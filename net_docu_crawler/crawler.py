# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Net-Docu-Crawler: Unified Multi-Vendor Network Infrastructure Discovery Engine.
Orchestrates zero-blast-radius discovery across Cisco, Juniper, Aruba, Palo Alto,
Arista, MikroTik, Fortinet, FRRouting, OPNsense, and OpenWrt environments.
Supports local broadcast domains and routed L3 subnets across firewalls and gateways.
"""

import argparse
import datetime
import ipaddress
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import oui_lookup
import report_generator
from net_docu_crawler.drivers import (
    AristaDriver,
    ArubaDriver,
    CiscoDriver,
    CiscoSMBDriver,
    FortinetDriver,
    FRRDriver,
    HPProCurveDriver,
    JuniperDriver,
    MikroTikDriver,
    OpenWrtDriver,
    OPNsenseDriver,
    PaloAltoDriver,
)
from net_docu_crawler.drivers.base import sanitize_raw_config
from net_docu_crawler.drivers.detector import (
    detect_vendor_range,
    get_arp_table_entries,
    get_mac_from_system_arp,
    probe_http_fingerprint,
    probe_snmp_sysinfo,
    scan_subnet_ports,
)
from net_docu_crawler.topology_resolver import DeviceRegistry

_VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "tailscale")


def detect_local_subnets() -> list[str]:
    """
    Auto-detect active local physical IPv4 subnets (e.g., 192.168.1.0/24),
    excluding loopback and virtual/container bridges. Falls back to 192.168.1.0/24.
    """
    subnets: list[str] = []
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or "inet" not in parts:
                    continue
                ifname = parts[1].rstrip(":")
                if ifname.startswith(_VIRTUAL_IFACE_PREFIXES):
                    continue
                inet_idx = parts.index("inet")
                if inet_idx + 1 >= len(parts):
                    continue
                cidr = parts[inet_idx + 1]
                try:
                    net = ipaddress.IPv4Interface(cidr).network
                    if 22 <= net.prefixlen <= 30 and str(net) not in subnets:
                        subnets.append(str(net))
                except ValueError:
                    continue
    except Exception:
        pass
    return subnets[:1] if subnets else ["192.168.1.0/24"]


DEFAULT_TARGETS = (
    [t.strip() for t in os.environ["NET_DOCU_TARGETS"].split(",") if t.strip()]
    if os.environ.get("NET_DOCU_TARGETS")
    else detect_local_subnets()
)

VENDOR_DRIVER_MAP = {
    "juniper": JuniperDriver,
    "aruba": ArubaDriver,
    "hpprocurve": HPProCurveDriver,
    "procurve": HPProCurveDriver,
    "hp": HPProCurveDriver,
    "cisco": CiscoDriver,
    "ciscosmb": CiscoSMBDriver,
    "cisco_s300": CiscoSMBDriver,
    "cbs": CiscoSMBDriver,
    "sg300": CiscoSMBDriver,
    "sg350": CiscoSMBDriver,
    "paloalto": PaloAltoDriver,
    "arista": AristaDriver,
    "mikrotik": MikroTikDriver,
    "fortinet": FortinetDriver,
    "frrouting": FRRDriver,
    "opnsense": OPNsenseDriver,
    "openwrt": OpenWrtDriver,
}


def expand_targets(targets: list[str], max_hosts_per_cidr: int = 256) -> list[str]:
    """
    Expands individual IP addresses, hostnames, and CIDR subnets (e.g., 172.16.1.0/24).
    Prevents accidental explosion of large network masks (/16 or /8).
    """
    expanded = []
    seen = set()

    for item in targets:
        item = item.strip()
        if not item:
            continue

        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                num_hosts = network.num_addresses
                if num_hosts > max_hosts_per_cidr + 2:
                    print(
                        f"[!] Warning: Subnet {item} has {num_hosts} addresses. "
                        f"Limiting expansion to first {max_hosts_per_cidr} hosts."
                    )
                count = 0
                for host in network.hosts():
                    if count >= max_hosts_per_cidr:
                        break
                    ip_str = str(host)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        expanded.append(ip_str)
                        count += 1
            except Exception as e:
                print(f"[!] Failed to parse CIDR {item}: {e}. Retaining as literal target.")
                if item not in seen:
                    seen.add(item)
                    expanded.append(item)
        else:
            if item not in seen:
                seen.add(item)
                expanded.append(item)

    return expanded


def load_credentials(path: str = "credentials.json") -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _log_event(log_path: str, msg: str):
    if not log_path:
        return
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def crawl_target(
    ip: str,
    credentials: list[dict],
    timeout: int = 8,
    session_log: str = "",
    log_file: str = "",
) -> dict | None:
    msg_probe = f"Probing target: {ip}..."
    print(f"\n[*] {msg_probe}")
    _log_event(log_file, msg_probe)

    # Tier 1 & 2: Pre-identification
    vendor_cand, banner = detect_vendor_range(ip, timeout=float(timeout))
    det_msg = f"Detection for {ip}: vendor='{vendor_cand}', banner={repr(banner[:40]) if banner else 'none'}"
    print(f"[+] {det_msg}")
    _log_event(log_file, det_msg)

    # Determine which drivers to attempt in order
    if vendor_cand in VENDOR_DRIVER_MAP:
        driver_classes = [VENDOR_DRIVER_MAP[vendor_cand]]
    elif ip.endswith(".253"):
        driver_classes = [AristaDriver, CiscoDriver]
    elif ip.endswith(".252"):
        driver_classes = [FortinetDriver, CiscoDriver]
    else:
        driver_classes = [CiscoDriver, AristaDriver, JuniperDriver, FortinetDriver]

    _log_event(log_file, f"Attempting drivers for {ip}: {[d.__name__ for d in driver_classes]}")

    # Prioritize matching credentials to avoid rapid-fire failed logins / AAA lockouts
    sorted_creds = list(credentials)
    if vendor_cand == "opnsense" or ip == "192.168.1.1":
        sorted_creds.sort(key=lambda c: 0 if "192.168.1.1" in c.get("name", "") and c.get("username") == "root" else 1)
    elif vendor_cand == "cisco" or ip.endswith(".250"):
        sorted_creds.sort(key=lambda c: 0 if c.get("username") == "Cisco" else 1)
    elif vendor_cand == "juniper" or ip.endswith(".3"):
        sorted_creds.sort(
            key=lambda c: 0 if c.get("username") == "root" else (1 if c.get("username") == "admin" else 2)
        )
    elif vendor_cand in ("frrouting", "openwrt") or ip.endswith(".254"):
        sorted_creds.sort(key=lambda c: 0 if c.get("username") == "root" else 1)
    else:
        sorted_creds.sort(key=lambda c: 0 if c.get("username") == "admin" else 1)

    for driver_cls in driver_classes:
        for cred in sorted_creds:
            user = cred.get("username", "")
            pwd = cred.get("password", "")
            secret = cred.get("secret", "")
            if not user or not pwd:
                continue

            _log_event(log_file, f"Connecting to {ip} with {driver_cls.__name__} (User: {user})...")
            try:
                driver = driver_cls(
                    ip=ip,
                    username=user,
                    password=pwd,
                    secret=secret,
                    timeout=timeout,
                    session_log=session_log,
                )
                conn = driver.connect()
                succ_msg = f"Successfully connected to {ip} with {driver_cls.__name__} (User: {user})"
                print(f"[+] {succ_msg}")
                _log_event(log_file, succ_msg)
                data = driver.crawl(conn)
                conn.disconnect()
                _log_event(log_file, f"Crawl completed successfully for {ip} (Hostname: {data.get('hostname')})")
                return data
            except Exception as e:
                err_msg = str(e).lower()
                _log_event(
                    log_file, f"Connection attempt failed on {ip} with {driver_cls.__name__} (User: {user}): {e}"
                )
                if "auth" in err_msg or "password" in err_msg:
                    continue
                else:
                    break

    fail_msg = f"Could not authenticate or connect to {ip}"
    print(f"[-] {fail_msg}")
    _log_event(log_file, fail_msg)
    return None


def parse_target_specs(
    targets: list[str],
    ssh_ports: list[int] | None = None,
    telnet_ports: list[int] | None = None,
) -> tuple[list[str], dict[str, list[tuple[int, str]]]]:
    """
    Parse target specifications supporting plain IPs, CIDRs, and `ip:port` syntax.
    Returns `(expanded_ips, explicit_ports_by_ip)`.
    """
    ssh_set = set(ssh_ports or [22])
    telnet_set = set(telnet_ports or [23])
    expanded_ips: list[str] = []
    seen_ips: set[str] = set()
    explicit_ports: dict[str, list[tuple[int, str]]] = {}

    for raw in targets:
        t = raw.strip()
        if not t:
            continue
        if ":" in t and "/" not in t:
            host, port_str = t.rsplit(":", 1)
            if port_str.isdigit():
                port = int(port_str)
                transport = "telnet" if (port in telnet_set or port == 23) and port not in ssh_set else "ssh"
                if host not in seen_ips:
                    seen_ips.add(host)
                    expanded_ips.append(host)
                explicit_ports.setdefault(host, [])
                if (port, transport) not in explicit_ports[host]:
                    explicit_ports[host].append((port, transport))
                continue
        for ip in expand_targets([t]):
            if ip not in seen_ips:
                seen_ips.add(ip)
                expanded_ips.append(ip)

    return expanded_ips, explicit_ports


def build_partial_device_record(
    ip: str,
    mac: str = "",
    vendor: str = "Unknown",
    banner: str = "",
    port: int = 22,
    transport: str = "ssh",
    status: str = "unauthenticated",
) -> dict:
    """
    Build a partial normalized `device_data` record for reachable hosts that
    could not be authenticated or lack a supported driver, so they appear in
    `asset_inventory.csv` and reports.
    """
    if transport == "arp":
        mgmt_method = "ARP/OUI"
    elif transport == "http":
        mgmt_method = "HTTP" if port == 80 else f"HTTP:{port}"
    elif transport == "https":
        mgmt_method = "HTTPS" if port == 443 else f"HTTPS:{port}"
    elif transport == "telnet":
        mgmt_method = "Telnet" if port == 23 else f"Telnet:{port}"
    else:
        mgmt_method = "SSH" if port == 22 else f"SSH:{port}"

    oui_vendor = oui_lookup.get_vendor(mac) if mac else ""
    if vendor and vendor.lower() != "unknown":
        resolved_vendor = vendor
    elif oui_vendor and oui_vendor.lower() != "unknown":
        resolved_vendor = oui_vendor
    else:
        resolved_vendor = "Unknown"

    clean_banner = banner.strip().replace("\r", " ").replace("\n", " ") if banner else ""
    if clean_banner:
        model = clean_banner[:60]
    elif resolved_vendor != "Unknown":
        model = f"{resolved_vendor} Device"
    else:
        model = "Unknown"

    return {
        "ip": ip,
        "status": status,
        "mgmt_method": mgmt_method,
        "vendor": resolved_vendor,
        "device_type": "unknown",
        "device_persona": "unknown",
        "hostname": ip,
        "model": model,
        "serial": "Unknown",
        "firmware": "Unknown",
        "mac_address": mac.lower() if mac else "",
        "l3_interfaces": [],
        "interfaces_detail": {},
        "neighbors": [],
        "routes": [],
        "arp_table": [],
        "mac_table": [],
        "vlans": {},
        "stp": {"enabled": False, "is_root": False, "vlans": {}},
        "services": {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []},
        "raw_config": "",
    }


def crawl_target_with_ports(
    ip: str,
    credentials: list[dict],
    timeout: int = 8,
    session_log: str = "",
    log_file: str = "",
    open_ports: list[tuple[int, str]] | None = None,
    mac: str = "",
) -> dict | None:
    """
    Probe a target across its discovered open `(port, transport)` pairs.
    Returns a full `device_data` dict on success, or a partial `unauthenticated`/
    `unsupported` record when a management port is open but login/driver fails.
    """
    ports_to_try = open_ports if open_ports else [(22, "ssh")]
    # Try SSH before Telnet
    ports_to_try = sorted(ports_to_try, key=lambda pt: (0 if pt[1] == "ssh" else 1, pt[0]))
    host_mac = mac or get_mac_from_system_arp(ip)

    last_vendor = "unknown"
    last_banner = ""
    last_port, last_transport = ports_to_try[0]
    saw_auth_failure = False

    for port, transport in ports_to_try:
        vendor_cand, banner = detect_vendor_range(
            ip,
            mac=host_mac,
            port=port,
            timeout=min(float(timeout), 3.0),
            transport=transport,
        )
        last_vendor, last_banner, last_port, last_transport = vendor_cand, banner, port, transport
        _log_event(
            log_file,
            f"Target {ip}:{port} ({transport}) -> vendor={vendor_cand}, banner={banner!r}",
        )

        if vendor_cand in VENDOR_DRIVER_MAP:
            driver_classes = [VENDOR_DRIVER_MAP[vendor_cand]]
        elif ip.endswith(".253"):
            driver_classes = [AristaDriver, CiscoDriver]
        elif ip.endswith(".252"):
            driver_classes = [FortinetDriver, CiscoDriver]
        else:
            driver_classes = [CiscoDriver, AristaDriver, JuniperDriver, FortinetDriver]

        sorted_creds = list(credentials)
        if vendor_cand == "opnsense" or ip == "192.168.1.1":
            sorted_creds.sort(
                key=lambda c: 0 if "192.168.1.1" in c.get("name", "") and c.get("username") == "root" else 1
            )
        elif vendor_cand == "cisco" or ip.endswith(".250"):
            sorted_creds.sort(key=lambda c: 0 if c.get("username") == "Cisco" else 1)
        elif vendor_cand == "juniper" or ip.endswith(".3"):
            sorted_creds.sort(
                key=lambda c: 0 if c.get("username") == "root" else (1 if c.get("username") == "admin" else 2)
            )
        elif vendor_cand in ("frrouting", "openwrt") or ip.endswith(".254"):
            sorted_creds.sort(key=lambda c: 0 if c.get("username") == "root" else 1)
        else:
            sorted_creds.sort(key=lambda c: 0 if c.get("username") == "admin" else 1)

        if vendor_cand and vendor_cand != "unknown":
            sorted_creds.sort(
                key=lambda c: (
                    0
                    if (not c.get("vendor") or c.get("vendor", "").lower() == vendor_cand.lower())
                    else 1
                )
            )

        for driver_cls in driver_classes:
            for cred in sorted_creds:
                user = cred.get("username", "")
                pwd = cred.get("password", "")
                secret = cred.get("secret", "")
                if not user:
                    continue

                _log_event(
                    log_file,
                    f"Connecting to {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user})...",
                )
                try:
                    driver = driver_cls(
                        ip=ip,
                        username=user,
                        password=pwd,
                        secret=secret,
                        timeout=timeout,
                        session_log=session_log,
                        port=port,
                        transport=transport,
                    )
                    conn = driver.connect()
                    succ_msg = (
                        f"Successfully connected to {ip}:{port} ({transport}) "
                        f"with {driver_cls.__name__} (User: {user})"
                    )
                    print(f"[+] {succ_msg}")
                    _log_event(log_file, succ_msg)
                    data = driver.crawl(conn)
                    conn.disconnect()
                    _log_event(log_file, f"Crawl completed successfully for {ip} (Hostname: {data.get('hostname')})")
                    return data
                except Exception as e:
                    err_msg = str(e).lower()
                    _log_event(
                        log_file,
                        f"Connection attempt failed on {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user}): {e}",
                    )
                    if any(
                        k in err_msg
                        for k in ("auth", "password", "login", "denied", "permission", "credential", "invalid")
                    ):
                        saw_auth_failure = True
                        continue
                    break

    status = "unauthenticated" if (last_vendor in VENDOR_DRIVER_MAP and saw_auth_failure) else "unsupported"
    fail_msg = f"Could not authenticate or connect to {ip} (recording partial inventory status={status})"
    print(f"[-] {fail_msg}")
    _log_event(log_file, fail_msg)
    return build_partial_device_record(
        ip=ip,
        mac=host_mac,
        vendor=last_vendor,
        banner=last_banner,
        port=last_port,
        transport=last_transport,
        status=status,
    )


def extract_followable_subnets(
    devices: list[dict],
    allow_cgnat: bool = False,
    allow_public: bool = False,
    min_prefix: int = 22,
    max_prefix: int = 30,
) -> list[str]:
    """
    Extract connected/routed IPv4 subnets from crawled devices (`l3_interfaces` and `routes`).
    Enforces a strict RFC 1918 boundary by default: skips 0.0.0.0/0, loopback, link-local,
    multicast, CGNAT (100.64.0.0/10 unless `allow_cgnat`), and public IPs (unless `allow_public`).
    """
    cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
    discovered: list[str] = []
    seen: set[str] = set()

    def _consider(raw_cidr: str):
        s = (raw_cidr or "").strip()
        if not s or s == "0.0.0.0/0":
            return
        if " " in s and "/" not in s:
            parts = s.split()
            if len(parts) == 2:
                s = f"{parts[0]}/{parts[1]}"
        if "/" not in s:
            return
        try:
            net = ipaddress.IPv4Interface(s).network
        except ValueError:
            return
        if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
            return
        if not (min_prefix <= net.prefixlen <= max_prefix):
            return
        is_cgnat = net.overlaps(cgnat_net)
        if is_cgnat:
            if not (allow_cgnat or allow_public):
                return
        elif not net.is_private and not allow_public:
            return
        key = str(net)
        if key not in seen:
            seen.add(key)
            discovered.append(key)

    for dev in devices:
        for iface in dev.get("l3_interfaces", []):
            _consider(iface.get("ip_address", ""))
        for route in dev.get("routes", []):
            _consider(route.get("subnet", ""))

    return discovered


def compute_organized_output_dir(
    targets: list[str],
    base_dir: str = "docs/reports",
    domain: str = "lan",
) -> str:
    """
    Computes a structured directory path: <base_dir>/<Subnet>_<TimeStamp>_<domain>/
    Example: docs/reports/192.168.1.0-24_20261107_221530_lan
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scope_slug = "multi_target"
    if targets:
        for t in targets:
            if "/" in t:
                scope_slug = t.strip().replace("/", "-").replace(":", "-")
                break
        if scope_slug == "multi_target" and targets:
            if any("192.168.1." in t for t in targets):
                scope_slug = "192.168.1.0-24"
            else:
                scope_slug = targets[0].strip().replace("/", "-").replace(":", "-")

    folder_name = f"{scope_slug}_{ts}_{domain}"
    return os.path.join(base_dir, folder_name)


def crawl_network(
    targets: list[str],
    credentials_path: str | list[str] = "credentials.json",
    output_dir: str = "",
    organize: bool = False,
    domain: str = "lan",
    sanitize_passwords: bool = False,
    timeout: int = 8,
    ssh_ports: list[int] | None = None,
    telnet_ports: list[int] | None = None,
    max_workers: int = 16,
    http_fingerprint: bool = True,
    snmp: bool = False,
    snmp_community: str = "public",
    follow_subnets: bool = False,
    max_hops: int = 1,
    allow_cgnat: bool = False,
    allow_public_subnets: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
) -> list[dict]:
    # Determine output destination (structured run folder vs legacy flat folder)
    if organize:
        base = output_dir if (output_dir and output_dir not in ("auto", "docs/net_docu_crawler")) else "docs/reports"
        run_output_dir = compute_organized_output_dir(targets, base_dir=base, domain=domain)
        is_organized = True
    elif not output_dir or output_dir == "auto":
        run_output_dir = compute_organized_output_dir(targets, domain=domain)
        is_organized = True
    else:
        run_output_dir = output_dir
        is_organized = False

    os.makedirs(run_output_dir, exist_ok=True)
    logs_dir = os.path.join(run_output_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    crawler_log = os.path.join(logs_dir, "crawler_execution.log")

    if isinstance(credentials_path, (list, tuple)):
        credentials = []
        for cred_file in credentials_path:
            credentials.extend(load_credentials(cred_file))
    else:
        credentials = load_credentials(credentials_path)
    print(f"[+] Loaded {len(credentials)} credential profiles from {credentials_path}")
    _log_event(crawler_log, f"Loaded {len(credentials)} credential profiles from {credentials_path}")

    # Expand any CIDR subnets and ip:port targets
    expanded_targets, explicit_ports = parse_target_specs(
        targets, ssh_ports=ssh_ports, telnet_ports=telnet_ports
    )
    eff_ssh_ports = ssh_ports if ssh_ports is not None else [22, 2222]
    eff_telnet_ports = telnet_ports if telnet_ports is not None else [23]

    raw_devices: list[dict] = []
    registry = DeviceRegistry()
    scanned_ip_set: set[str] = set()
    scanned_cidrs: set[str] = {t.strip() for t in targets if "/" in t}

    def _run_batch(batch_ips: list[str], batch_explicit: dict[str, list[tuple[int, str]]]):
        if not batch_ips:
            return
        scanned_ip_set.update(batch_ips)
        print(
            f"[+] Pre-scanning {len(batch_ips)} target(s) for SSH {eff_ssh_ports} / Telnet {eff_telnet_ports}..."
        )
        _log_event(crawler_log, f"Pre-scanning {len(batch_ips)} targets: {batch_ips}")

        scan_ips = [ip for ip in batch_ips if ip not in batch_explicit]
        open_ports_map = (
            scan_subnet_ports(
                scan_ips,
                ssh_ports=eff_ssh_ports,
                telnet_ports=eff_telnet_ports,
                timeout=min(float(timeout), 1.0),
                max_workers=max(max_workers, 32),
            )
            if scan_ips
            else {}
        )
        for ip, ports in batch_explicit.items():
            open_ports_map[ip] = ports

        reachable_targets = [ip for ip in batch_ips if open_ports_map.get(ip)]
        print(f"[+] Found {len(reachable_targets)} reachable host(s) with open management ports.")
        _log_event(crawler_log, f"Reachable targets ({len(reachable_targets)}): {reachable_targets}")

        targets_to_crawl = []
        for ip in reachable_targets:
            if not registry.start_crawl(ip):
                print(f"[*] Skipping {ip}: already registered as alias/SVI of a crawled device.")
                _log_event(crawler_log, f"Skipping {ip}: already registered as alias/SVI of a crawled device.")
                continue
            targets_to_crawl.append(ip)

        if not targets_to_crawl:
            return

        worker_count = max(1, min(max_workers, len(targets_to_crawl)))
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            future_to_ip = {
                pool.submit(
                    crawl_target_with_ports,
                    ip,
                    credentials,
                    timeout=timeout,
                    session_log=os.path.join(logs_dir, f"{ip.replace(':', '_')}_raw_session.log"),
                    log_file=crawler_log,
                    open_ports=open_ports_map.get(ip),
                ): ip
                for ip in targets_to_crawl
            }
            results_by_ip: dict[str, dict | None] = {}
            for fut in as_completed(future_to_ip):
                ip = future_to_ip[fut]
                try:
                    results_by_ip[ip] = fut.result()
                except Exception as exc:
                    _log_event(crawler_log, f"Unhandled worker exception for {ip}: {exc}")
                    results_by_ip[ip] = None

        for ip in targets_to_crawl:
            device_data = results_by_ip.get(ip)
            if device_data:
                registry.register_device(device_data)
                raw_devices.append(device_data)
            else:
                registry.release_crawl(ip)

    _run_batch(expanded_targets, explicit_ports)

    # Optional multi-hop routed subnet discovery (--follow-subnets)
    if follow_subnets and max_hops > 0:
        for hop in range(1, max_hops + 1):
            candidate_cidrs = extract_followable_subnets(
                raw_devices,
                allow_cgnat=allow_cgnat,
                allow_public=allow_public_subnets,
            )
            new_cidrs = [c for c in candidate_cidrs if c not in scanned_cidrs]
            if not new_cidrs:
                break
            scanned_cidrs.update(new_cidrs)
            hop_ips = [ip for ip in expand_targets(new_cidrs) if ip not in scanned_ip_set]
            if not hop_ips:
                break
            print(f"[+] Hop {hop}: following {len(new_cidrs)} routed subnet(s): {new_cidrs}")
            _log_event(crawler_log, f"Hop {hop} following subnets: {new_cidrs}")
            _run_batch(hop_ips, {})

    # ARP-only host inventory: include local ARP-visible hosts with no open SSH/Telnet ports
    arp_entries = get_arp_table_entries()
    for arp_ip, arp_mac in arp_entries.items():
        if scanned_ip_set and arp_ip not in scanned_ip_set:
            continue
        if not registry.start_crawl(arp_ip):
            continue
        arp_rec = build_partial_device_record(
            ip=arp_ip,
            mac=arp_mac,
            vendor="Unknown",
            banner="",
            port=0,
            transport="arp",
            status="discovered",
        )
        registry.register_device(arp_rec)
        raw_devices.append(arp_rec)

    # Enrich partial/ARP-discovered hosts via read-only HTTP/HTTPS banner & TLS cert fingerprinting
    partial_devs = [d for d in raw_devices if d.get("status") in ("discovered", "unauthenticated", "unsupported")]
    if http_fingerprint and partial_devs:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(partial_devs))) as pool:
            http_futs = {
                pool.submit(probe_http_fingerprint, d["ip"], timeout=min(float(timeout), 1.5)): d
                for d in partial_devs
            }
            for fut in as_completed(http_futs):
                dev = http_futs[fut]
                try:
                    fp = fut.result()
                except Exception:
                    fp = None
                if not fp:
                    continue
                label = fp.get("title") or fp.get("server") or fp.get("cert_cn") or ""
                if label and (dev.get("model") in ("Unknown", "") or dev.get("model", "").endswith(" Device")):
                    dev["model"] = label[:60]
                if dev.get("status") == "discovered":
                    scheme = fp["scheme"].upper()
                    port = fp["port"]
                    dev["mgmt_method"] = scheme if port in (80, 443) else f"{scheme}:{port}"
                    dev["status"] = "unsupported"

    # Optional SNMP sysDescr / sysName enrichment (--snmp)
    if snmp and partial_devs:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(partial_devs))) as pool:
            snmp_futs = {
                pool.submit(probe_snmp_sysinfo, d["ip"], community=snmp_community, timeout=min(float(timeout), 1.5)): d
                for d in partial_devs
            }
            for fut in as_completed(snmp_futs):
                dev = snmp_futs[fut]
                try:
                    info = fut.result()
                except Exception:
                    info = None
                if not info:
                    continue
                if info.get("sysName") and dev.get("hostname") == dev.get("ip"):
                    dev["hostname"] = info["sysName"]
                if info.get("sysDescr"):
                    dev["model"] = info["sysDescr"][:60]
                if dev.get("status") == "discovered":
                    dev["mgmt_method"] = "SNMP"
                    dev["status"] = "unsupported"

    # Cross-resolve neighbor IPs/personas from crawled devices & Global ARP, then stitch topology edges
    crawled_by_ip = {d["ip"]: d for d in raw_devices if d.get("ip")}
    crawled_by_host = {}
    for d in raw_devices:
        for h_key in (d.get("hostname", ""), d.get("canonical_hostname", "")):
            if h_key:
                crawled_by_host[h_key.lower()] = d
                crawled_by_host[h_key.split(".")[0].lower()] = d

    for device_data in raw_devices:
        local_host = device_data.get("hostname") or device_data.get("ip", "")
        for nbr in device_data.get("neighbors", []):
            if not nbr.get("remote_ip"):
                resolved_ip = registry.resolve_neighbor_ip(
                    neighbor_mac=nbr.get("remote_mac", ""),
                    neighbor_name=nbr.get("remote_device", ""),
                )
                if resolved_ip:
                    nbr["remote_ip"] = resolved_ip

            matched_dev = crawled_by_ip.get(nbr.get("remote_ip", ""))
            if not matched_dev and nbr.get("remote_device"):
                r_key = nbr["remote_device"].split(".")[0].lower()
                matched_dev = crawled_by_host.get(r_key)

            if matched_dev:
                if matched_dev.get("device_type"):
                    nbr["device_type"] = matched_dev["device_type"]
                if not nbr.get("platform"):
                    plat_label = f"{matched_dev.get('vendor', '')} {matched_dev.get('model', '')}".strip()
                    nbr["platform"] = plat_label
                    nbr["remote_platform"] = plat_label

            registry.add_bidirectional_link(
                local_node=local_host,
                local_port=nbr.get("local_port", ""),
                remote_node=nbr.get("remote_device", ""),
                remote_port=nbr.get("remote_port", ""),
            )

    confirmed_count = sum(1 for lk in registry.links if lk["status"] == "confirmed")
    print(f"\n[+] Successfully crawled {len(raw_devices)} network devices!")
    print(f"[+] Unique devices in registry: {len(registry.devices)}")
    print(f"[+] Discovered topology links: {len(registry.links)} ({confirmed_count} bidirectional confirmed)")

    # Optional security sanitization of secrets in configs
    if sanitize_passwords:
        print("[+] Sanitizing passwords and pre-shared keys in configuration backups...")
        for dev in raw_devices:
            if dev.get("raw_config"):
                dev["raw_config"] = sanitize_raw_config(dev["raw_config"])

    # Save consolidated raw crawl JSON
    json_path = os.path.join(run_output_dir, "net_docu_crawler_dataset.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(raw_devices, f, indent=2)
    print(f"[+] Saved crawl dataset to: {json_path}")

    # Generate Reports using canonical device records
    devices_dict = {dev["ip"]: dev for dev in registry.devices.values()}

    # Determine scope label
    scope_label = (
        targets[0]
        if len(targets) == 1
        else ("192.168.1.0/24" if any("192.168.1." in t for t in targets) else "Multi-Target Campus")
    )

    # 1. Master Migration Blueprint (Network_Analysis.md)
    blueprint_path = os.path.join(run_output_dir, "Network_Analysis.md")
    report_generator.generate_master_network_analysis_migration_blueprint(
        devices_dict, output_path=blueprint_path, scope=scope_label
    )
    print(f"[+] Generated master migration blueprint: {blueprint_path}")

    # 2. Automated Post-Cutover Validation Smoke Test Script (validate_cutover.sh)
    smoke_path = os.path.join(run_output_dir, "validate_cutover.sh")
    report_generator.generate_cutover_validation_script(devices_dict, output_path=smoke_path)
    print(f"[+] Generated cutover validation smoke script: {smoke_path}")

    # 3. Standard deliverables (L2/L3 Diagrams, Asset Inventory, Cabling Matrix, Protocol Translation, Live Report)
    rep_path = os.path.join(run_output_dir, "net_docu_crawler_live_report.md")
    report_generator.generate_network_analysis_report(devices_dict, output_path=rep_path)
    print(f"[+] Generated network analysis report: {rep_path}")

    inv_path = os.path.join(run_output_dir, "asset_inventory.csv")
    report_generator.generate_asset_inventory(devices_dict, output_path=inv_path)
    print(f"[+] Generated asset inventory CSV: {inv_path}")

    cable_path = os.path.join(run_output_dir, "migration_cabling_matrix.csv")
    report_generator.generate_cabling_matrix(devices_dict, output_path=cable_path)
    print(f"[+] Generated cabling matrix CSV: {cable_path}")

    endpoint_path = os.path.join(run_output_dir, "port_mac_endpoint_mapping.csv")
    report_generator.generate_port_endpoint_mapping(devices_dict, output_path=endpoint_path)
    print(f"[+] Generated port-to-endpoint mapping CSV: {endpoint_path}")

    l2_path = os.path.join(run_output_dir, "L2_network_diagrams.md")
    report_generator.generate_l2_diagram(devices_dict, output_path=l2_path)
    print(f"[+] Generated Layer 2 diagram: {l2_path}")

    l3_path = os.path.join(run_output_dir, "L3_network_diagrams.md")
    report_generator.generate_l3_diagram(devices_dict, output_path=l3_path)
    print(f"[+] Generated Layer 3 diagram: {l3_path}")

    trans_path = os.path.join(run_output_dir, "cisco_to_target_translation.md")
    report_generator.generate_protocol_translation(devices_dict, output_path=trans_path)
    print(f"[+] Generated configuration translation guide: {trans_path}")

    bom_path = os.path.join(run_output_dir, "bom_hardware_sizing.csv")
    report_generator.generate_bom_hardware_sizing(devices_dict, output_path=bom_path)
    print(f"[+] Generated BOM & hardware sizing CSV: {bom_path}")

    if target_vendor:
        target_cfg_path = os.path.join(run_output_dir, f"target_migration_{target_vendor.lower()}.md")
        report_generator.generate_target_migration_configs(
            devices_dict, target_vendor=target_vendor, output_path=target_cfg_path
        )
        print(f"[+] Generated target vendor migration configs ({target_vendor}): {target_cfg_path}")

    if save_baseline:
        report_generator.save_baseline_state(devices_dict, output_path=save_baseline)
        print(f"[+] Saved pre-cutover baseline state to: {save_baseline}")

    if compare_baseline:
        ver_path = os.path.join(run_output_dir, "migration_verification_report.md")
        report_generator.compare_baseline_state(devices_dict, baseline_path=compare_baseline, output_path=ver_path)
        print(f"[+] Generated post-cutover verification diff report: {ver_path}")

    # If organized run folder was created, update latest pointer and maintain legacy path compatibility
    if is_organized and run_output_dir.startswith("docs/reports"):
        latest_link = os.path.join(os.path.dirname(run_output_dir), "latest")
        try:
            if os.path.islink(latest_link) or os.path.exists(latest_link):
                if os.path.islink(latest_link):
                    os.unlink(latest_link)
                elif os.path.isdir(latest_link):
                    shutil.rmtree(latest_link)
                elif os.path.isfile(latest_link):
                    os.remove(latest_link)
            os.symlink(os.path.basename(run_output_dir), latest_link)
            print(f"[+] Updated symlink: {latest_link} -> {os.path.basename(run_output_dir)}")
        except OSError:
            # On Windows without SeCreateSymbolicLinkPrivilege, maintain pointer via latest.txt
            try:
                latest_txt = os.path.join(os.path.dirname(run_output_dir), "latest.txt")
                with open(latest_txt, "w", encoding="utf-8") as f:
                    f.write(os.path.basename(run_output_dir) + "\n")
                print(f"[+] Recorded latest run pointer: {latest_txt} -> {os.path.basename(run_output_dir)}")
            except Exception:
                pass

        # Mirror deliverables to docs/net_docu_crawler for backward compatibility
        legacy_dir = "docs/net_docu_crawler"
        os.makedirs(legacy_dir, exist_ok=True)
        for fname in os.listdir(run_output_dir):
            src_f = os.path.join(run_output_dir, fname)
            dst_f = os.path.join(legacy_dir, fname)
            if os.path.isfile(src_f):
                shutil.copy2(src_f, dst_f)
            elif os.path.isdir(src_f) and fname == "logs":
                os.makedirs(dst_f, exist_ok=True)
                for l_file in os.listdir(src_f):
                    l_src = os.path.join(src_f, l_file)
                    if os.path.isfile(l_src):
                        shutil.copy2(l_src, os.path.join(dst_f, l_file))

    return raw_devices


def main():
    parser = argparse.ArgumentParser(description="Net-Docu-Crawler Multi-Vendor Network Discovery")
    parser.add_argument(
        "--targets",
        nargs="+",
        default=DEFAULT_TARGETS,
        help="List of target IPs or CIDRs to crawl (e.g., 172.16.1.0/24)",
    )
    parser.add_argument(
        "--credentials",
        nargs="+",
        default=["credentials.json"],
        help="Path(s) to credentials JSON file(s) (tried in order)",
    )
    parser.add_argument(
        "--output-dir",
        default="docs/net_docu_crawler",
        help="Output directory for reports (or use --organize for Subnet_TimeStamp_domain)",
    )
    parser.add_argument(
        "--organize",
        action="store_true",
        help="Store deliverables in a structured folder: docs/reports/<Subnet>_<TimeStamp>_<domain>/",
    )
    parser.add_argument(
        "--domain",
        default="lan",
        help="Domain suffix for organized report folders (default: lan)",
    )
    parser.add_argument(
        "--sanitize-passwords",
        action="store_true",
        help="Redact passwords, pre-shared keys, and SNMP communities in configurations and exports",
    )
    parser.add_argument("--timeout", type=int, default=8, help="Connection timeout in seconds")
    parser.add_argument(
        "--ssh-ports",
        nargs="+",
        type=int,
        default=[22, 2222],
        help="SSH ports to probe during subnet discovery (default: 22 2222)",
    )
    parser.add_argument(
        "--telnet-ports",
        nargs="+",
        type=int,
        default=[23],
        help="Telnet ports to probe during subnet discovery (default: 23)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=16,
        help="Maximum concurrent device crawl workers (default: 16)",
    )
    parser.add_argument(
        "--no-http-fingerprint",
        action="store_true",
        help="Disable default HTTP/HTTPS banner and TLS certificate fingerprinting for unauthenticated/ARP hosts",
    )
    parser.add_argument(
        "--snmp",
        action="store_true",
        help="Enable opt-in read-only SNMPv2c sysDescr/sysName enrichment for unauthenticated/ARP hosts",
    )
    parser.add_argument(
        "--snmp-community",
        default="public",
        help="SNMPv2c community string when --snmp is enabled (default: public)",
    )
    parser.add_argument(
        "--follow-subnets",
        action="store_true",
        help="Follow connected/routed RFC 1918 subnets discovered from crawled routers/firewalls",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=1,
        help="Maximum L3 subnet hops when --follow-subnets is enabled (default: 1)",
    )
    parser.add_argument(
        "--allow-cgnat",
        action="store_true",
        help="Allow --follow-subnets to follow CGNAT (100.64.0.0/10) ranges (ISP/lab override)",
    )
    parser.add_argument(
        "--allow-public-subnets",
        action="store_true",
        help="Allow --follow-subnets to follow non-RFC1918 public subnets (explicit ISP override)",
    )
    parser.add_argument(
        "--target-vendor",
        default="",
        help="Generate staged target-vendor migration CLI configs (cisco, juniper, arista, hpprocurve)",
    )
    parser.add_argument(
        "--save-baseline",
        default="",
        help="Save pre-cutover baseline state JSON to the specified path",
    )
    parser.add_argument(
        "--compare-baseline",
        default="",
        help="Compare current crawl against a saved baseline JSON and generate migration_verification_report.md",
    )

    args = parser.parse_args()

    t_start = time.time()
    crawl_network(
        targets=args.targets,
        credentials_path=args.credentials,
        output_dir=args.output_dir,
        organize=args.organize,
        domain=args.domain,
        sanitize_passwords=args.sanitize_passwords,
        timeout=args.timeout,
        ssh_ports=args.ssh_ports,
        telnet_ports=args.telnet_ports,
        max_workers=args.workers,
        http_fingerprint=not args.no_http_fingerprint,
        snmp=args.snmp,
        snmp_community=args.snmp_community,
        follow_subnets=args.follow_subnets,
        max_hops=args.max_hops,
        allow_cgnat=args.allow_cgnat,
        allow_public_subnets=args.allow_public_subnets,
        target_vendor=args.target_vendor,
        save_baseline=args.save_baseline,
        compare_baseline=args.compare_baseline,
    )
    print(f"\n[+] Total crawl and documentation runtime: {time.time() - t_start:.2f} seconds")


if __name__ == "__main__":
    main()

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
import glob
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
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
    classify_non_network_appliance,
    detect_vendor_range,
    get_arp_table_entries,
    get_mac_from_system_arp,
    infer_vendor_from_http,
    probe_appliance_ports,
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
        if sys.platform == "win32":
            proc = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3, check=False)
            if proc.returncode == 0:
                cur_ip = ""
                for line in proc.stdout.splitlines():
                    m_ip = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if m_ip:
                        cur_ip = m_ip.group(1)
                        continue
                    m_mask = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if m_mask and cur_ip:
                        try:
                            net = ipaddress.IPv4Interface(f"{cur_ip}/{m_mask.group(1)}").network
                            if 22 <= net.prefixlen <= 30 and not net.is_loopback and str(net) not in subnets:
                                subnets.append(str(net))
                        except ValueError:
                            pass
                        cur_ip = ""
        else:
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


def validate_credentials(entries: object, source: str = "credentials.json") -> tuple[list[dict], list[str], list[str]]:
    """
    Validates parsed credential profiles and removes exact duplicates.
    Returns (valid_entries, warnings, errors).
    """
    warnings: list[str] = []
    errors: list[str] = []
    valid_entries: list[dict] = []

    if not isinstance(entries, list):
        errors.append(f"{source}: top-level JSON must be a list of credential objects, got {type(entries).__name__}.")
        return valid_entries, warnings, errors

    seen: dict[tuple[str, str, str, str], str] = {}
    for idx, item in enumerate(entries):
        label = f"{source}[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{label}: expected JSON object, got {type(item).__name__}.")
            continue

        name = item.get("name", label)
        if not isinstance(name, str) or not name.strip():
            name = label

        username = item.get("username")
        if not isinstance(username, str) or not username.strip():
            errors.append(f"{name}: missing or empty 'username' string.")
            continue

        password = item.get("password", "")
        if not isinstance(password, str):
            errors.append(f"{name}: 'password' must be a string, got {type(password).__name__}.")
            continue

        secret = item.get("secret", "")
        if secret is None:
            secret = ""
        if not isinstance(secret, str):
            errors.append(f"{name}: 'secret' must be a string, got {type(secret).__name__}.")
            continue

        vendor = item.get("vendor", "")
        if vendor is None:
            vendor = ""
        if not isinstance(vendor, str):
            errors.append(f"{name}: 'vendor' must be a string, got {type(vendor).__name__}.")
            continue
        vendor_norm = vendor.strip().lower()
        if vendor_norm and vendor_norm not in VENDOR_DRIVER_MAP:
            warnings.append(
                f"{name}: unknown vendor tag '{vendor}' (not in VENDOR_DRIVER_MAP; will not get vendor-priority sorting)."
            )

        dedup_key = (vendor_norm, username, password, secret)
        if dedup_key in seen:
            warnings.append(
                f"{name}: duplicate of '{seen[dedup_key]}' (vendor={vendor_norm or 'any'}, username={username!r}) — skipping."
            )
            continue
        seen[dedup_key] = name

        normalized = dict(item)
        normalized["username"] = username
        normalized["password"] = password
        if "secret" in item or secret:
            normalized["secret"] = secret
        if vendor_norm:
            normalized["vendor"] = vendor_norm
        valid_entries.append(normalized)

    return valid_entries, warnings, errors


def load_and_validate_credentials(
    credentials_path: str | list[str] | tuple[str, ...] = "credentials.json",
) -> tuple[list[dict], list[str], list[str]]:
    """
    Loads and validates one or more credential JSON files before a crawl starts.
    Returns (valid_entries, warnings, errors).
    """
    paths = list(credentials_path) if isinstance(credentials_path, (list, tuple)) else [credentials_path]
    all_raw: list[dict] = []
    warnings: list[str] = []
    errors: list[str] = []

    for path in paths:
        if not os.path.exists(path):
            errors.append(f"Credential file not found: {path}")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {path} (line {e.lineno}, col {e.colno}): {e.msg}")
            continue
        except OSError as e:
            errors.append(f"Failed to read {path}: {e}")
            continue

        valid, w, err = validate_credentials(data, source=path)
        all_raw.extend(valid)
        warnings.extend(w)
        errors.extend(err)

    # Cross-file deduplication if multiple credential files were supplied
    if len(paths) > 1 and all_raw:
        all_raw, w_cross, _ = validate_credentials(all_raw, source="merged_credentials")
        warnings.extend(w_cross)

    if not all_raw and not errors:
        errors.append("No valid credential profiles found.")

    return all_raw, warnings, errors


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
    """Compatibility wrapper delegating single-target SSH crawls to `crawl_target_with_ports()`."""
    res = crawl_target_with_ports(
        ip=ip,
        credentials=credentials,
        timeout=timeout,
        session_log=session_log,
        log_file=log_file,
        open_ports=[(22, "ssh")],
    )
    if res and res.get("status") == "success":
        return res
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
    device_type: str = "unknown",
    model_override: str = "",
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
    if device_type == "unknown":
        app_class = classify_non_network_appliance(vendor_oui=oui_vendor, banner=clean_banner)
        if app_class:
            device_type, auto_model = app_class
            if not model_override:
                model_override = auto_model

    if model_override:
        model = model_override
    elif clean_banner:
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
        "device_type": device_type,
        "device_persona": "appliance" if device_type in ("av_control", "camera", "display") else "unknown",
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


_GENERIC_HTTP_LABELS = frozenset(
    {
        "index",
        "index.html",
        "index.htm",
        "home",
        "login",
        "welcome",
        "webserver",
        "web server",
        "http",
        "https",
        "nginx",
        "apache",
        "lighttpd",
        "boa",
        "mini_httpd",
        "thttpd",
        "400 bad request",
        "401 unauthorized",
        "401 authorization required",
        "403 forbidden",
        "404 not found",
        "error",
        "redirect",
        "document moved",
    }
)


def _sanitize_http_model_label(fp: dict | None) -> str:
    """Extract a meaningful hardware/product label from an HTTP/TLS fingerprint, filtering generic web titles."""
    if not fp:
        return ""
    for candidate in (fp.get("title"), fp.get("server"), fp.get("cert_cn")):
        val = str(candidate or "").strip()
        if not val:
            continue
        low = val.lower()
        if low in _GENERIC_HTTP_LABELS:
            continue
        if low.startswith(("401 ", "403 ", "404 ", "500 ", "502 ", "503 ")):
            continue
        # Reject 16+ char pure hex hashes (e.g. session/CSRF/MD5 page titles)
        if len(val) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", val):
            continue
        return val[:60]
    return ""


def crawl_target_with_ports(
    ip: str,
    credentials: list[dict],
    timeout: int = 8,
    session_log: str = "",
    log_file: str = "",
    open_ports: list[tuple[int, str]] | None = None,
    mac: str = "",
    http_fingerprint: bool = True,
    vendor_hint: str = "",
    try_all_creds: bool = False,
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
    hint_norm = vendor_hint.strip().lower()

    last_vendor = "unknown"
    last_banner = ""
    last_port, last_transport = ports_to_try[0]
    last_app_class: tuple[str, str] | None = None
    cached_http_fp: dict | None = None
    http_probed = False
    saw_auth_failure = False

    for port, transport in ports_to_try:
        vendor_cand, banner = detect_vendor_range(
            ip,
            mac=host_mac,
            port=port,
            timeout=min(float(timeout), 3.0),
            transport=transport,
        )
        if vendor_cand == "unsupported_appliance":
            last_vendor, last_banner, last_port, last_transport = vendor_cand, banner, port, transport
            _log_event(
                log_file,
                f"Target {ip}:{port} ({transport}) -> non-network appliance ({banner!r}); skipping SSH/Telnet login.",
            )
            break
        if vendor_cand == "unknown" and hint_norm in VENDOR_DRIVER_MAP:
            vendor_cand = hint_norm
        elif vendor_cand == "unknown":
            if http_fingerprint and not http_probed:
                cached_http_fp = probe_http_fingerprint(ip, timeout=min(float(timeout), 1.5))
                http_probed = True
                if cached_http_fp:
                    _log_event(log_file, f"Target {ip}:{port} HTTP/TLS probe -> {cached_http_fp}")
            http_fp = cached_http_fp
            http_vendor = infer_vendor_from_http(http_fp)
            if http_vendor != "unknown":
                vendor_cand = http_vendor
                _log_event(
                    log_file,
                    f"Target {ip}:{port} HTTP/TLS fingerprint identified vendor={vendor_cand}",
                )
            else:
                app_ports = probe_appliance_ports(ip, timeout=min(float(timeout), 0.3))
                oui_v = oui_lookup.get_vendor(host_mac) if host_mac else ""
                app_class = classify_non_network_appliance(
                    vendor_oui=oui_v, banner=banner, http_fp=http_fp, open_app_ports=app_ports
                )
                if app_class:
                    last_vendor, last_banner, last_port, last_transport = (
                        "unsupported_appliance",
                        banner,
                        port,
                        transport,
                    )
                    last_app_class = app_class
                    _log_event(
                        log_file,
                        f"Target {ip}:{port} ({transport}) -> non-network appliance ({app_class[1]}, ports={app_ports}); skipping SSH/Telnet login.",
                    )
                    break
        if vendor_cand == "unknown" and last_vendor in VENDOR_DRIVER_MAP:
            vendor_cand = last_vendor
        last_vendor, last_banner, last_port, last_transport = vendor_cand, banner, port, transport
        _log_event(
            log_file,
            f"Target {ip}:{port} ({transport}) -> vendor={vendor_cand}, mac={host_mac or 'none'}, banner={banner!r}",
        )

        if vendor_cand in VENDOR_DRIVER_MAP:
            driver_classes = [VENDOR_DRIVER_MAP[vendor_cand]]
        else:
            driver_classes = [CiscoDriver, AristaDriver, JuniperDriver, FortinetDriver]

        sorted_creds = list(credentials)
        if vendor_cand == "opnsense":
            sorted_creds.sort(key=lambda c: 0 if c.get("username") == "root" else 1)
        elif vendor_cand == "cisco":
            sorted_creds.sort(key=lambda c: 0 if c.get("username") in ("Cisco", "admin") else 1)
        elif vendor_cand == "juniper":
            sorted_creds.sort(
                key=lambda c: 0 if c.get("username") == "root" else (1 if c.get("username") == "admin" else 2)
            )
        elif vendor_cand in ("frrouting", "openwrt"):
            sorted_creds.sort(key=lambda c: 0 if c.get("username") == "root" else 1)
        elif vendor_cand == "hpprocurve":
            sorted_creds.sort(
                key=lambda c: 0 if c.get("username") == "manager" else (1 if c.get("username") == "admin" else 2)
            )
        else:
            sorted_creds.sort(key=lambda c: 0 if c.get("username") == "admin" else 1)

        if vendor_cand and vendor_cand != "unknown":
            sorted_creds.sort(
                key=lambda c: 0 if (not c.get("vendor") or c.get("vendor", "").lower() == vendor_cand.lower()) else 1
            )
            if not try_all_creds:
                scoped_creds = [
                    c
                    for c in sorted_creds
                    if not c.get("vendor") or c.get("vendor", "").strip().lower() == vendor_cand.lower()
                ]
                if scoped_creds:
                    sorted_creds = scoped_creds
                else:
                    _log_event(
                        log_file,
                        f"No credentials tagged '{vendor_cand}' or untagged; falling back to all {len(sorted_creds)} profiles.",
                    )

        _driver_vendor_map = {
            CiscoDriver: "cisco",
            CiscoSMBDriver: "ciscosmb",
            AristaDriver: "arista",
            JuniperDriver: "juniper",
            FortinetDriver: "fortinet",
            ArubaDriver: "aruba",
            HPProCurveDriver: "hpprocurve",
            PaloAltoDriver: "paloalto",
            MikroTikDriver: "mikrotik",
            OPNsenseDriver: "opnsense",
            OpenWrtDriver: "openwrt",
            FRRDriver: "frrouting",
        }

        transport_failed = False
        for driver_cls in driver_classes:
            if transport_failed:
                break
            if transport == "telnet" and not getattr(driver_cls, "supports_telnet", True):
                continue
            driver_creds = sorted_creds
            if vendor_cand == "unknown" and not try_all_creds:
                drv_vendor = _driver_vendor_map.get(driver_cls, "")
                if drv_vendor:
                    filtered = [
                        c
                        for c in sorted_creds
                        if not c.get("vendor") or c.get("vendor", "").strip().lower() == drv_vendor
                    ]
                    if filtered:
                        driver_creds = filtered
            for cred in driver_creds:
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
                        f"Successfully connected to {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user})"
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
                    if any(
                        k in err_msg
                        for k in (
                            "incompatible",
                            "no acceptable host key",
                            "no acceptable kex",
                            "error reading ssh protocol banner",
                            "connection refused",
                            "timed out",
                            "tcp connection to device failed",
                        )
                    ):
                        transport_failed = True
                    break

    status = "unauthenticated" if (last_vendor in VENDOR_DRIVER_MAP and saw_auth_failure) else "unsupported"
    fail_msg = f"Could not authenticate or connect to {ip} (recording partial inventory status={status})"
    print(f"[-] {fail_msg}")
    _log_event(log_file, fail_msg)
    partial = build_partial_device_record(
        ip=ip,
        mac=host_mac,
        vendor=last_vendor,
        banner=last_banner,
        port=last_port,
        transport=last_transport,
        status=status,
        device_type=last_app_class[0] if last_app_class else "unknown",
        model_override=last_app_class[1] if last_app_class else "",
    )
    if http_probed:
        partial["_http_fp"] = cached_http_fp
    return partial


_MGMT_IFACE_RE = re.compile(
    r"(?:mgmt|manage|infra|switch|sw[_-]|core|dist|loopback|^lo0|p2p|transit|uplink|default_vlan|^vlan\.?1$)",
    re.IGNORECASE,
)

_NON_INFRA_OUI_KEYWORDS: tuple[str, ...] = (
    "apple",
    "dell",
    "lenovo",
    "intel",
    "samsung",
    "google",
    "sonos",
    "roku",
    "crestron",
    "extron",
    "hikvision",
    "axis",
    "brother",
    "canon",
    "epson",
    "xerox",
    "ricoh",
    "lexmark",
    "polycom",
    "yealink",
    "grandstream",
    "ring",
    "nest",
    "raspberry",
    "microsoft",
    "vmware",
)


def _parse_cidr_list(raw_cidrs: list[str] | None) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for raw in raw_cidrs or []:
        try:
            nets.append(ipaddress.IPv4Network(raw.strip(), strict=False))
        except ValueError:
            continue
    return nets


def extract_followable_subnets(
    devices: list[dict],
    allow_cgnat: bool = False,
    allow_public: bool = False,
    include_routes: bool = True,
    min_prefix: int = 22,
    max_prefix: int = 30,
    mgmt_only: bool = False,
    subnet_include: list[str] | None = None,
    subnet_exclude: list[str] | None = None,
) -> list[str]:
    """
    Extract connected IPv4 subnets from crawled devices (`l3_interfaces`, plus `routes` when `include_routes=True`).
    Enforces a strict RFC 1918 boundary by default: skips 0.0.0.0/0, loopback, link-local,
    multicast, CGNAT (100.64.0.0/10 unless `allow_cgnat`), and public IPs (unless `allow_public`).
    """
    cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
    include_nets = _parse_cidr_list(subnet_include)
    exclude_nets = _parse_cidr_list(subnet_exclude)
    discovered: list[str] = []
    seen: set[str] = set()

    def _consider(raw_cidr: str, iface_name: str = ""):
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
        if mgmt_only and net.prefixlen < 30 and not _MGMT_IFACE_RE.search(iface_name or ""):
            return
        if include_nets and not any(net.overlaps(inc) for inc in include_nets):
            return
        if exclude_nets and any(net.overlaps(exc) for exc in exclude_nets):
            return
        key = str(net)
        if key not in seen:
            seen.add(key)
            discovered.append(key)

    for dev in devices:
        for iface in dev.get("l3_interfaces", []):
            _consider(iface.get("ip_address", ""), iface.get("interface", ""))
        if include_routes:
            for route in dev.get("routes", []):
                _consider(route.get("subnet", ""), route.get("interface", ""))

    return discovered


def _select_hop_targets_for_cidrs(
    cidrs: list[str],
    registry: DeviceRegistry,
    scanned_ip_set: set[str],
    arp_only: bool = False,
) -> list[str]:
    """
    Use harvested ARP tables to target known-live hosts inside connected subnets
    instead of blindly scanning 250+ dead IPs per VLAN.
    When `arp_only=True`, never falls back to full CIDR sweeps and skips known
    non-infrastructure endpoint OUIs (Apple, printers, cameras, AV controllers).
    When `arp_only=False` and ARP tables exist, prunes empty `/24`–`/22` subnets
    while still allowing `/29`–`/30` transit links.
    """
    selected: list[str] = []
    seen: set[str] = set(scanned_ip_set)
    arp_ips = list(registry.global_arp.keys())
    has_global_arp = bool(arp_ips)

    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            continue
        arp_hits = [ip for ip in arp_ips if ipaddress.IPv4Address(ip) in net]
        if arp_hits:
            for ip in arp_hits:
                if ip in seen:
                    continue
                if arp_only:
                    arp_entry = registry.global_arp.get(ip)
                    if isinstance(arp_entry, dict):
                        oui_l = str(arp_entry.get("vendor") or "").lower()
                        if not oui_l or oui_l == "unknown":
                            mac = str(arp_entry.get("mac") or "")
                            oui_l = oui_lookup.lookup_oui(mac).lower() if mac else ""
                    elif isinstance(arp_entry, str) and arp_entry:
                        oui_l = oui_lookup.lookup_oui(arp_entry).lower()
                    else:
                        oui_l = ""
                    if oui_l and any(k in oui_l for k in _NON_INFRA_OUI_KEYWORDS):
                        continue
                seen.add(ip)
                selected.append(ip)
        elif arp_only:
            continue
        elif has_global_arp and net.prefixlen < 29:
            # Zero-ARP subnet pruning: avoid sweeping 254+ dead IPs on empty VLANs
            continue
        else:
            for ip in expand_targets([cidr]):
                if ip not in seen:
                    seen.add(ip)
                    selected.append(ip)
    return selected


def extract_neighbor_ips(
    devices: list[dict],
    registry: DeviceRegistry | None = None,
    allow_cgnat: bool = False,
    allow_public: bool = False,
) -> list[str]:
    """
    Extract unique management IPv4 addresses of CDP/LLDP infrastructure neighbors
    from crawled devices (using explicit `remote_ip` or `registry.resolve_neighbor_ip()`).
    Enforces RFC 1918 boundary unless `allow_cgnat` / `allow_public` is set.
    """
    cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
    discovered: list[str] = []
    seen: set[str] = set()

    for dev in devices:
        if dev.get("status", "success") != "success":
            continue
        for nbr in dev.get("neighbors", []):
            if str(nbr.get("device_type", "")).lower() == "ap":
                continue
            cand_ip = str(nbr.get("remote_ip", "")).strip()
            if not cand_ip and registry is not None:
                cand_ip = (
                    registry.resolve_neighbor_ip(
                        neighbor_mac=nbr.get("remote_mac", ""),
                        neighbor_name=nbr.get("remote_device", ""),
                    )
                    or ""
                )
            if not cand_ip or cand_ip in seen:
                continue
            try:
                addr = ipaddress.IPv4Address(cand_ip)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                continue
            if addr in cgnat_net:
                if not (allow_cgnat or allow_public):
                    continue
            elif not addr.is_private and not allow_public:
                continue
            seen.add(cand_ip)
            discovered.append(cand_ip)

    return discovered


def compute_organized_output_dir(
    targets: list[str],
    base_dir: str = "deliverables",
    domain: str = "lan",
) -> str:
    """
    Computes a structured directory path: <base_dir>/<Subnet>_<TimeStamp>_<domain>/
    Example: deliverables/192.168.1.0-24_20261107_221530_lan
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
    organize: bool = True,
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
    follow_arp_only: bool = False,
    mgmt_subnets_only: bool = False,
    subnet_include: list[str] | None = None,
    subnet_exclude: list[str] | None = None,
    follow_routes: bool = False,
    follow_neighbors: bool = True,
    max_hops: int = 1,
    allow_cgnat: bool = False,
    allow_public_subnets: bool = False,
    target_vendor: str = "",
    vendor_hint: str = "",
    try_all_creds: bool = False,
    save_baseline: str = "",
    compare_baseline: str = "",
    retry_failed: str = "",
) -> list[dict]:
    prior_success_devices: list[dict] = []
    if retry_failed:
        with open(retry_failed, encoding="utf-8") as f:
            failed_entries = json.load(f)
        retry_ips = []
        skipped_unsupported = 0
        for entry in failed_entries:
            if isinstance(entry, str):
                retry_ips.append(entry)
            elif isinstance(entry, dict) and entry.get("ip"):
                if entry.get("status") == "unsupported":
                    skipped_unsupported += 1
                    continue
                retry_ips.append(entry["ip"])
        if not retry_ips and isinstance(failed_entries, list):
            retry_ips = [e["ip"] for e in failed_entries if isinstance(e, dict) and e.get("ip")]
            skipped_unsupported = 0
        if skipped_unsupported:
            print(
                f"[+] Loaded {len(retry_ips)} retry target(s) from {retry_failed} (skipped {skipped_unsupported} unsupported)."
            )
        else:
            print(f"[+] Loaded {len(retry_ips)} retry target(s) from {retry_failed}.")
        targets = retry_ips
        if not targets:
            print("[!] No retryable hosts found in failed_hosts.json.")
            return []

        sibling_dataset = os.path.join(os.path.dirname(os.path.abspath(retry_failed)), "net_docu_crawler_dataset.json")
        if os.path.isfile(sibling_dataset):
            try:
                with open(sibling_dataset, encoding="utf-8") as df:
                    prior_data = json.load(df)
                retry_ip_set = set(retry_ips)
                if isinstance(prior_data, list):
                    prior_success_devices = [
                        d
                        for d in prior_data
                        if isinstance(d, dict)
                        and d.get("status", "success") == "success"
                        and d.get("ip") not in retry_ip_set
                    ]
                    if prior_success_devices:
                        print(
                            f"[+] Merging {len(prior_success_devices)} previously succeeded device(s) from {sibling_dataset}."
                        )
            except Exception as exc:
                print(f"[!] Could not load prior dataset {sibling_dataset} for merge: {exc}")

    credentials, cred_warnings, cred_errors = load_and_validate_credentials(credentials_path)
    for w in cred_warnings:
        print(f"[!] Credential warning: {w}")
    for err in cred_errors:
        print(f"[-] Credential error: {err}")
    if cred_errors:
        raise ValueError(
            f"Credential validation failed ({len(cred_errors)} error(s)). Fix {credentials_path} and retry."
        )

    # Determine output destination (structured run folder vs legacy flat folder)
    if organize:
        base = output_dir if (output_dir and output_dir not in ("auto", "docs/net_docu_crawler")) else "deliverables"
        run_output_dir = compute_organized_output_dir(targets, base_dir=base, domain=domain)
        is_organized = True
    elif not output_dir or output_dir == "auto":
        run_output_dir = "docs/net_docu_crawler"
        is_organized = False
    else:
        run_output_dir = output_dir
        is_organized = False

    os.makedirs(run_output_dir, exist_ok=True)
    logs_dir = os.path.join(run_output_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    crawler_log = os.path.join(logs_dir, "crawler_execution.log")

    print(f"[+] Validated and loaded {len(credentials)} credential profile(s) from {credentials_path}")
    _log_event(crawler_log, f"Validated and loaded {len(credentials)} credential profile(s) from {credentials_path}")
    for w in cred_warnings:
        _log_event(crawler_log, f"Credential warning: {w}")

    # Expand any CIDR subnets and ip:port targets
    expanded_targets, explicit_ports = parse_target_specs(targets, ssh_ports=ssh_ports, telnet_ports=telnet_ports)
    eff_ssh_ports = ssh_ports if ssh_ports is not None else [22]
    eff_telnet_ports = telnet_ports if telnet_ports is not None else [23]

    raw_devices: list[dict] = []
    registry = DeviceRegistry()
    scanned_ip_set: set[str] = set()
    scanned_cidrs: set[str] = {t.strip() for t in targets if "/" in t}

    for prior_dev in prior_success_devices:
        registry.register_device(prior_dev)
        raw_devices.append(prior_dev)
        if prior_dev.get("ip"):
            scanned_ip_set.add(prior_dev["ip"])

    def _run_batch(batch_ips: list[str], batch_explicit: dict[str, list[tuple[int, str]]]):
        if not batch_ips:
            return
        scanned_ip_set.update(batch_ips)
        print(f"[+] Pre-scanning {len(batch_ips)} target(s) for SSH {eff_ssh_ports} / Telnet {eff_telnet_ports}...")
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
                    mac=registry.get_arp_mac(ip),
                    http_fingerprint=http_fingerprint,
                    vendor_hint=vendor_hint,
                    try_all_creds=try_all_creds,
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

    # Neighbor-first discovery: crawl CDP/LLDP management IPs discovered on crawled infrastructure
    if follow_neighbors and not retry_failed:
        nbr_hops = max(1, max_hops)
        for hop in range(1, nbr_hops + 1):
            nbr_ips = [
                ip
                for ip in extract_neighbor_ips(
                    raw_devices,
                    registry=registry,
                    allow_cgnat=allow_cgnat,
                    allow_public=allow_public_subnets,
                )
                if ip not in scanned_ip_set
            ]
            if not nbr_ips:
                break
            print(f"[+] Neighbor Hop {hop}: queuing {len(nbr_ips)} CDP/LLDP neighbor IP(s): {nbr_ips}")
            _log_event(crawler_log, f"Neighbor Hop {hop} queuing IPs: {nbr_ips}")
            _run_batch(nbr_ips, {})

    # Optional multi-hop routed subnet discovery (--follow-subnets / --follow-arp-only)
    if (follow_subnets or follow_arp_only) and max_hops > 0:
        for hop in range(1, max_hops + 1):
            candidate_cidrs = extract_followable_subnets(
                raw_devices,
                allow_cgnat=allow_cgnat,
                allow_public=allow_public_subnets,
                include_routes=follow_routes,
                mgmt_only=mgmt_subnets_only,
                subnet_include=subnet_include,
                subnet_exclude=subnet_exclude,
            )
            new_cidrs = [c for c in candidate_cidrs if c not in scanned_cidrs]
            if not new_cidrs:
                break
            scanned_cidrs.update(new_cidrs)
            hop_ips = _select_hop_targets_for_cidrs(
                new_cidrs,
                registry,
                scanned_ip_set,
                arp_only=follow_arp_only,
            )
            if not hop_ips:
                break
            print(f"[+] Hop {hop}: following {len(new_cidrs)} subnet(s) ({len(hop_ips)} target IP(s)): {new_cidrs}")
            _log_event(crawler_log, f"Hop {hop} following subnets ({len(hop_ips)} IPs): {new_cidrs}")
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
        to_probe = [d for d in partial_devs if "_http_fp" not in d]
        probed_results: dict[int, dict | None] = {}
        if to_probe:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(to_probe))) as pool:
                http_futs = {
                    pool.submit(probe_http_fingerprint, d["ip"], timeout=min(float(timeout), 1.5)): d for d in to_probe
                }
                for fut in as_completed(http_futs):
                    dev = http_futs[fut]
                    try:
                        probed_results[id(dev)] = fut.result()
                    except Exception:
                        probed_results[id(dev)] = None

        for dev in partial_devs:
            fp = dev.pop("_http_fp", None) if "_http_fp" in dev else probed_results.get(id(dev))
            if not fp:
                continue
            label = _sanitize_http_model_label(fp)
            if label and (dev.get("model") in ("Unknown", "") or dev.get("model", "").endswith(" Device")):
                dev["model"] = label
            if dev.get("status") == "discovered":
                scheme = fp["scheme"].upper()
                port = fp["port"]
                dev["mgmt_method"] = scheme if port in (80, 443) else f"{scheme}:{port}"
                dev["status"] = "unsupported"
    else:
        for dev in partial_devs:
            dev.pop("_http_fp", None)

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

    return render_deliverables_from_dataset(
        raw_devices=raw_devices,
        registry=registry,
        run_output_dir=run_output_dir,
        targets=targets,
        is_organized=is_organized,
        sanitize_passwords=sanitize_passwords,
        target_vendor=target_vendor,
        save_baseline=save_baseline,
        compare_baseline=compare_baseline,
        logs_dir=logs_dir,
    )


def _sanitize_session_logs(logs_dir: str):
    """Redact credentials/secrets from raw Netmiko/Paramiko session transcripts when --sanitize-passwords is enabled."""
    if not logs_dir or not os.path.isdir(logs_dir):
        return
    for fname in os.listdir(logs_dir):
        if not fname.endswith("_raw_session.log"):
            continue
        fpath = os.path.join(logs_dir, fname)
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                raw_txt = f.read()
            cleaned = sanitize_raw_config(raw_txt)
            if cleaned != raw_txt:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(cleaned)
        except Exception:
            pass


def enrich_devices_from_dhcp_reservations(raw_devices: list[dict]) -> list[dict]:
    """
    Cross-reference discovered/unauthenticated/unsupported hosts against DHCP
    static reservations extracted from crawled firewalls/routers/switches so
    APs, WLCs, NVRs, and printers inherit their real reservation hostnames.
    """
    by_ip: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}
    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        dhcp = dev.get("dhcp") or {}
        for res in dhcp.get("reservations", []):
            hostname = str(res.get("hostname") or "").strip()
            if not hostname:
                continue
            ip_val = str(res.get("ip") or "").strip()
            mac_val = oui_lookup.normalize_mac(str(res.get("mac") or "")).lower()
            info = {"hostname": hostname, "pool": str(res.get("pool") or "").strip()}
            if ip_val and ip_val not in by_ip:
                by_ip[ip_val] = info
            if mac_val and mac_val not in by_mac:
                by_mac[mac_val] = info

    if not by_ip and not by_mac:
        return raw_devices

    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        status = str(dev.get("status") or "").lower()
        cur_host = str(dev.get("hostname") or "").strip()
        ip_val = str(dev.get("ip") or "").strip()
        mac_val = oui_lookup.normalize_mac(str(dev.get("mac_address") or "")).lower()
        needs_name = (
            status in ("discovered", "unauthenticated", "unsupported")
            or not cur_host
            or cur_host in ("Unknown", ip_val)
            or cur_host.startswith("ARP_")
        )
        if not needs_name:
            continue
        match = by_ip.get(ip_val) or (by_mac.get(mac_val) if mac_val else None)
        if not match:
            continue
        dev["hostname"] = match["hostname"]
        dev["canonical_hostname"] = match["hostname"]
        if not dev.get("model") or dev.get("model") in ("Unknown", "N/A"):
            pool = match.get("pool", "")
            dev["model"] = f"DHCP Reservation ({pool})" if pool else "DHCP Reservation"

    return raw_devices


def render_deliverables_from_dataset(
    raw_devices: list[dict],
    registry: DeviceRegistry | None = None,
    run_output_dir: str = "docs/net_docu_crawler",
    targets: list[str] | None = None,
    is_organized: bool = False,
    sanitize_passwords: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
    logs_dir: str = "",
) -> list[dict]:
    """
    Resolve topology links, optionally sanitize secrets (including raw session logs),
    export JSON/failed_hosts.json, and generate all Markdown/CSV/script deliverables.
    Can be called live after `crawl_network()` or offline via `--from-dataset`.
    """
    os.makedirs(run_output_dir, exist_ok=True)
    enrich_devices_from_dhcp_reservations(raw_devices)
    if registry is None:
        registry = DeviceRegistry()
        for dev in raw_devices:
            if isinstance(dev, dict):
                registry.register_device(dev)

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
    print(f"\n[+] Processed {len(raw_devices)} network devices!")
    print(f"[+] Unique devices in registry: {len(registry.devices)}")
    print(f"[+] Discovered topology links: {len(registry.links)} ({confirmed_count} bidirectional confirmed)")

    # Optional security sanitization of secrets in configs and raw session logs
    if sanitize_passwords:
        print("[+] Sanitizing passwords and pre-shared keys in configuration backups and session logs...")
        for dev in raw_devices:
            if dev.get("raw_config"):
                dev["raw_config"] = sanitize_raw_config(dev["raw_config"])
        _sanitize_session_logs(logs_dir or os.path.join(run_output_dir, "logs"))

    # Save consolidated raw crawl JSON
    json_path = os.path.join(run_output_dir, "net_docu_crawler_dataset.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(raw_devices, f, indent=2)
    print(f"[+] Saved crawl dataset to: {json_path}")

    # Export failed / unauthenticated / unsupported hosts for targeted --retry-failed follow-ups
    failed_hosts = [
        {
            "ip": dev.get("ip", ""),
            "status": dev.get("status", "unknown"),
            "vendor": dev.get("vendor", "Unknown"),
            "device_type": dev.get("device_type", "unknown"),
            "mgmt_method": dev.get("mgmt_method", ""),
            "model": dev.get("model", ""),
            "mac_address": dev.get("mac_address", ""),
        }
        for dev in raw_devices
        if dev.get("status") in ("unauthenticated", "unsupported")
    ]
    failed_path = os.path.join(run_output_dir, "failed_hosts.json")
    with open(failed_path, "w", encoding="utf-8") as f:
        json.dump(failed_hosts, f, indent=2)
    if failed_hosts:
        print(f"[+] Saved {len(failed_hosts)} failed/partial host(s) to: {failed_path}")

    # Generate Reports using canonical device records
    devices_dict = {dev["ip"]: dev for dev in registry.devices.values()}

    # Determine scope label
    t_list = targets or []
    scope_label = (
        t_list[0]
        if len(t_list) == 1
        else ("192.168.1.0/24" if any("192.168.1." in t for t in t_list) else "Multi-Target Campus")
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
    if is_organized:
        latest_link = os.path.join(os.path.dirname(run_output_dir), "latest")
        try:
            if os.path.islink(latest_link):
                os.unlink(latest_link)
            elif os.path.exists(latest_link):
                if os.path.isdir(latest_link):
                    try:
                        # On Windows, os.rmdir removes an NTFS junction without deleting target contents
                        os.rmdir(latest_link)
                    except OSError:
                        shutil.rmtree(latest_link)
                else:
                    os.remove(latest_link)
            os.symlink(os.path.basename(run_output_dir), latest_link, target_is_directory=True)
            print(f"[+] Updated symlink: {latest_link} -> {os.path.basename(run_output_dir)}")
        except OSError:
            # On Windows without SeCreateSymbolicLinkPrivilege, try an NTFS junction first, then latest.txt
            junction_created = False
            if os.name == "nt":
                try:
                    subprocess.run(
                        ["cmd", "/c", "mklink", "/J", os.path.abspath(latest_link), os.path.abspath(run_output_dir)],
                        check=True,
                        capture_output=True,
                    )
                    print(f"[+] Updated junction: {latest_link} -> {os.path.basename(run_output_dir)}")
                    junction_created = True
                except Exception:
                    junction_created = False
            if not junction_created:
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


def render_from_dataset_file(
    dataset_path: str,
    output_dir: str = "",
    sanitize_passwords: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
) -> list[dict]:
    """
    Offline mode (`--from-dataset`): load an existing `net_docu_crawler_dataset.json`
    and re-run topology resolution + all deliverable generators with zero network traffic.
    """
    with open(dataset_path, encoding="utf-8") as f:
        raw_devices = json.load(f)
    if not isinstance(raw_devices, list):
        raise ValueError(f"Expected JSON list in dataset {dataset_path}, got {type(raw_devices).__name__}")
    target_dir = (
        output_dir
        if (output_dir and output_dir not in ("auto", "docs/net_docu_crawler"))
        else os.path.dirname(os.path.abspath(dataset_path))
    )
    print(f"[+] Loaded {len(raw_devices)} device record(s) from {dataset_path} (offline render -> {target_dir})")
    return render_deliverables_from_dataset(
        raw_devices=raw_devices,
        run_output_dir=target_dir,
        sanitize_passwords=sanitize_passwords,
        target_vendor=target_vendor,
        save_baseline=save_baseline,
        compare_baseline=compare_baseline,
    )


class LogReplayConnection:
    """
    Offline Netmiko-compatible connection adapter that replays recorded CLI
    command outputs from `<ip>_raw_session.log` files without touching the network.
    """

    def __init__(self, log_text: str):
        self.commands: dict[str, str] = {}
        self.prompt: str = ""
        self._parse_log(log_text)

    def _parse_log(self, log_text: str) -> None:
        cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", log_text)
        cleaned = re.sub(r"\[(?:\?[0-9;]*[hl]|[0-9;]*[HJKr])", "", cleaned).replace("\r", "")
        lines = cleaned.splitlines()
        base_prompt = ""
        prompt_re = None
        # Identify the device prompt prefix from the first prompt+command line
        for ln in lines:
            m = re.match(r"^([A-Za-z0-9._@-]+)(?:\s*\([^)]+\))?\s*[#>$]\s*([a-zA-Z/].*)$", ln)
            if m:
                base_prompt = m.group(1)
                prompt_re = re.compile(rf"^{re.escape(base_prompt)}(?:\s*\([^)]+\))?\s*[#>$]\s*(.*)$")
                break
        if not prompt_re:
            return

        cur_cmd: str | None = None
        cur_buf: list[str] = []
        for ln in lines:
            m = prompt_re.match(ln)
            if m:
                if cur_cmd is not None:
                    while cur_buf and (
                        not cur_buf[-1].strip()
                        or re.match(r"^\{(?:master|backup|linecard):\d+\}$", cur_buf[-1].strip())
                    ):
                        cur_buf.pop()
                    self.commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
                cmd_part = m.group(1).strip()
                if not self.prompt and "(" not in ln.split("#", 1)[0].split(">", 1)[0]:
                    sep = "#" if "#" in ln else (">" if ">" in ln else "$")
                    self.prompt = ln.split(sep, 1)[0] + sep
                cur_cmd = cmd_part if cmd_part else None
                cur_buf = []
            elif cur_cmd is not None:
                cur_buf.append(ln)
        if cur_cmd is not None:
            while cur_buf and (
                not cur_buf[-1].strip() or re.match(r"^\{(?:master|backup|linecard):\d+\}$", cur_buf[-1].strip())
            ):
                cur_buf.pop()
            self.commands[cur_cmd] = "\n".join(cur_buf).strip("\n")

    def send_command(self, command_string: str, **kwargs) -> str:
        cmd = command_string.strip()
        if cmd in self.commands:
            return self.commands[cmd]
        # Fallback: case-insensitive or prefix match
        cmd_l = cmd.lower()
        for k, v in self.commands.items():
            if k.lower() == cmd_l:
                return v
        return ""

    def find_prompt(self) -> str:
        return self.prompt or "device#"

    def enable(self) -> None:
        return None

    def disconnect(self) -> None:
        return None


def _infer_vendor_from_log(log_text: str, existing_vendor: str = "") -> str:
    ev = (existing_vendor or "").lower()
    _alias = {
        "juniper_junos": "juniper",
        "juniper": "juniper",
        "cisco_ios": "cisco",
        "cisco_xe": "cisco",
        "cisco_nxos": "cisco",
        "cisco_xr": "cisco",
        "cisco": "cisco",
        "arista_eos": "arista",
        "arista": "arista",
        "mikrotik_routeros": "mikrotik",
        "mikrotik": "mikrotik",
        "fortinet": "fortinet",
        "opnsense": "opnsense",
        "openwrt": "openwrt",
        "hpprocurve": "hpprocurve",
        "aruba": "aruba",
        "paloalto": "paloalto",
        "frrouting": "frrouting",
    }
    low = log_text.lower()
    if "fortigate" in low or "fortios" in low or "get system status" in low or "config system interface" in low:
        return "fortinet"
    if "junos" in low or "show chassis hardware" in low:
        return "juniper"
    if "procurve" in low or "arubaos-s" in low or "show power-over-ethernet brief" in low or "hp j" in low:
        return "hpprocurve"
    if "arista" in low or "eos" in low:
        return "arista"
    if "mikrotik" in low or "/system identity" in low:
        return "mikrotik"
    if "opnsense" in low or "/conf/config.xml" in low:
        return "opnsense"
    if "openwrt" in low or "ubus call" in low:
        return "openwrt"
    if "cisco ios" in low or "show ip interface brief" in low or "show cdp neighbors detail" in low:
        return "cisco"
    if ev in _alias:
        return _alias[ev]
    if "juniper" in ev or "junos" in ev:
        return "juniper"
    if "procurve" in ev or "arubaos-s" in ev or "hp " in ev:
        return "hpprocurve"
    return "cisco"


def reparse_logs_dir(
    run_dir: str,
    output_dir: str = "",
    sanitize_passwords: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
) -> list[dict]:
    """
    Offline mode (`--reparse-logs`): replay `logs/*_raw_session.log` in `run_dir`
    through the latest vendor drivers and regenerate all deliverables with zero
    network traffic, preserving partial/ARP-discovered entries from any existing
    `net_docu_crawler_dataset.json`.
    """
    run_abs = os.path.abspath(run_dir)
    logs_dir = os.path.join(run_abs, "logs") if os.path.isdir(os.path.join(run_abs, "logs")) else run_abs
    dataset_path = os.path.join(run_abs, "net_docu_crawler_dataset.json")
    target_out = output_dir if (output_dir and output_dir not in ("auto", "docs/net_docu_crawler")) else run_abs

    existing_by_ip: dict[str, dict] = {}
    existing_order: list[str] = []
    if os.path.isfile(dataset_path):
        with open(dataset_path, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, list):
            for rec in loaded:
                if isinstance(rec, dict) and rec.get("ip"):
                    ip_k = str(rec["ip"])
                    existing_by_ip[ip_k] = rec
                    existing_order.append(ip_k)

    log_files = sorted(glob.glob(os.path.join(logs_dir, "*_raw_session.log")))
    if not log_files:
        raise FileNotFoundError(f"No *_raw_session.log files found in {logs_dir}")

    reparsed_by_ip: dict[str, dict] = {}
    for lf in log_files:
        ip = os.path.basename(lf).replace("_raw_session.log", "")
        with open(lf, encoding="utf-8", errors="ignore") as f:
            log_text = f.read()

        conn = LogReplayConnection(log_text)
        # Skip tiny auth-failed stubs with fewer than 2 recorded commands
        if len(conn.commands) < 2:
            prev = existing_by_ip.get(ip)
            if prev:
                # Fix legacy misclassified auth-failure stubs
                if prev.get("hostname") in ("authentication", "Password", "Login", "Username", ""):
                    prev["status"] = "unauthenticated"
                    prev["hostname"] = prev.get("ip", ip)
                reparsed_by_ip[ip] = prev
            continue

        prev = existing_by_ip.get(ip, {})
        vendor = _infer_vendor_from_log(log_text, prev.get("vendor", ""))
        driver_cls = VENDOR_DRIVER_MAP.get(vendor, CiscoDriver)
        driver = driver_cls(ip)
        print(f"[+] Re-parsing {ip} ({vendor}) from {os.path.basename(lf)} ({len(conn.commands)} commands)")
        dev = driver.crawl(conn)
        dev["ip"] = ip
        if not dev.get("mac_address") and prev.get("mac_address"):
            dev["mac_address"] = prev["mac_address"]
        for extra_k in ("http_title", "http_server", "ssh_banner", "open_ports", "discovery_source"):
            if prev.get(extra_k) and not dev.get(extra_k):
                dev[extra_k] = prev[extra_k]
        reparsed_by_ip[ip] = dev

    merged: list[dict] = []
    seen: set[str] = set()
    for ip in existing_order:
        if ip in reparsed_by_ip:
            merged.append(reparsed_by_ip[ip])
        else:
            merged.append(existing_by_ip[ip])
        seen.add(ip)
    for ip, dev in reparsed_by_ip.items():
        if ip not in seen:
            merged.append(dev)

    return render_deliverables_from_dataset(
        raw_devices=merged,
        run_output_dir=target_out,
        sanitize_passwords=sanitize_passwords,
        target_vendor=target_vendor,
        save_baseline=save_baseline,
        compare_baseline=compare_baseline,
        logs_dir=logs_dir if sanitize_passwords else "",
    )


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
        help="Flat output directory when --no-organize is used, or custom base directory when organized (default base: deliverables/)",
    )
    parser.add_argument(
        "--organize",
        action="store_true",
        help="(Default) Store deliverables in a structured folder: deliverables/<Subnet>_<TimeStamp>_<domain>/",
    )
    parser.add_argument(
        "--no-organize",
        action="store_true",
        help="Write flat output directly to --output-dir without creating a <Subnet>_<TimeStamp>_<domain> subfolder",
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
        default=[22],
        help="SSH ports to probe during subnet discovery (default: 22)",
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
        help="Follow directly connected RFC 1918 subnets discovered from crawled routers/firewalls (prunes empty /24+ subnets when ARP tables exist)",
    )
    parser.add_argument(
        "--follow-arp-only",
        action="store_true",
        help="Only follow live ARP-discovered infrastructure IPs inside connected subnets (never sweeps empty subnets; skips known endpoint OUIs)",
    )
    parser.add_argument(
        "--mgmt-subnets-only",
        action="store_true",
        help="When following subnets, restrict to management/infrastructure/transit SVIs and /30-/31 P2P links",
    )
    parser.add_argument(
        "--subnet-include",
        nargs="+",
        default=None,
        help="Only follow subnets overlapping these CIDRs (e.g. --subnet-include 10.250.0.0/16 172.31.0.0/16)",
    )
    parser.add_argument(
        "--subnet-exclude",
        nargs="+",
        default=None,
        help="Exclude subnets overlapping these CIDRs when following subnets",
    )
    parser.add_argument(
        "--follow-routes",
        action="store_true",
        help="When --follow-subnets is enabled, also follow non-connected routing-table subnets",
    )
    parser.add_argument(
        "--no-follow-neighbors",
        action="store_true",
        help="Disable automatic crawling of CDP/LLDP neighbor management IPs discovered on crawled devices",
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
        "--vendor-hint",
        default="",
        help="Fallback vendor driver hint when OUI/SSH banner is unknown (e.g., fortinet, ciscosmb, cisco)",
    )
    parser.add_argument(
        "--try-all-creds",
        action="store_true",
        help="Try all credential profiles even when a specific vendor is detected (not recommended for lockout-protected devices)",
    )
    parser.add_argument(
        "--no-online-oui",
        action="store_true",
        help="Disable online OUI lookup fallback for unseen MAC prefixes (air-gapped mode)",
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
    parser.add_argument(
        "--retry-failed",
        default="",
        help="Path to failed_hosts.json from a prior run to retry unauthenticated hosts only",
    )
    parser.add_argument(
        "--from-dataset",
        default="",
        help="Offline mode: regenerate all deliverables from an existing net_docu_crawler_dataset.json",
    )
    parser.add_argument(
        "--reparse-logs",
        default="",
        help="Offline mode: replay logs/*_raw_session.log in a run directory through the latest drivers and regenerate all deliverables",
    )
    parser.add_argument(
        "--validate-credentials",
        action="store_true",
        help="Validate --credentials JSON file(s) and exit without running a crawl",
    )

    args = parser.parse_args()

    if args.validate_credentials:
        creds, warnings, errors = load_and_validate_credentials(args.credentials)
        for w in warnings:
            print(f"[!] Credential warning: {w}")
        for err in errors:
            print(f"[-] Credential error: {err}")
        if errors:
            sys.exit(1)
        print(f"[+] Validated {len(creds)} credential profile(s) from {args.credentials}")
        return

    if args.no_online_oui:
        os.environ["NET_DOCU_OFFLINE_OUI"] = "1"

    t_start = time.time()
    try:
        if args.reparse_logs:
            reparse_logs_dir(
                run_dir=args.reparse_logs,
                output_dir=args.output_dir,
                sanitize_passwords=args.sanitize_passwords,
                target_vendor=args.target_vendor,
                save_baseline=args.save_baseline,
                compare_baseline=args.compare_baseline,
            )
            print(f"\n[+] Offline log re-parse completed in {time.time() - t_start:.2f} seconds")
            return

        if args.from_dataset:
            render_from_dataset_file(
                dataset_path=args.from_dataset,
                output_dir=args.output_dir,
                sanitize_passwords=args.sanitize_passwords,
                target_vendor=args.target_vendor,
                save_baseline=args.save_baseline,
                compare_baseline=args.compare_baseline,
            )
            print(f"\n[+] Offline deliverable regeneration completed in {time.time() - t_start:.2f} seconds")
            return

        crawl_network(
            targets=args.targets,
            credentials_path=args.credentials,
            output_dir=args.output_dir,
            organize=not args.no_organize,
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
            follow_arp_only=args.follow_arp_only,
            mgmt_subnets_only=args.mgmt_subnets_only,
            subnet_include=args.subnet_include,
            subnet_exclude=args.subnet_exclude,
            follow_routes=args.follow_routes,
            follow_neighbors=not args.no_follow_neighbors,
            max_hops=args.max_hops,
            allow_cgnat=args.allow_cgnat,
            allow_public_subnets=args.allow_public_subnets,
            target_vendor=args.target_vendor,
            vendor_hint=args.vendor_hint,
            try_all_creds=args.try_all_creds,
            save_baseline=args.save_baseline,
            compare_baseline=args.compare_baseline,
            retry_failed=args.retry_failed,
        )
    except ValueError:
        sys.exit(1)
    print(f"\n[+] Total crawl and documentation runtime: {time.time() - t_start:.2f} seconds")


if __name__ == "__main__":
    main()

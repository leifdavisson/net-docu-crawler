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
import time

import report_generator
from net_docu_crawler.drivers import (
    AristaDriver,
    ArubaDriver,
    CiscoDriver,
    FortinetDriver,
    FRRDriver,
    JuniperDriver,
    MikroTikDriver,
    OpenWrtDriver,
    OPNsenseDriver,
    PaloAltoDriver,
)
from net_docu_crawler.drivers.base import sanitize_raw_config
from net_docu_crawler.drivers.detector import detect_vendor_range
from net_docu_crawler.topology_resolver import DeviceRegistry

DEFAULT_TARGETS = [t.strip() for t in os.environ.get("NET_DOCU_TARGETS", "192.168.1.1").split(",") if t.strip()]

VENDOR_DRIVER_MAP = {
    "juniper": JuniperDriver,
    "aruba": ArubaDriver,
    "cisco": CiscoDriver,
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
    credentials_path: str = "credentials.json",
    output_dir: str = "",
    organize: bool = False,
    domain: str = "lan",
    sanitize_passwords: bool = False,
    timeout: int = 8,
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

    credentials = load_credentials(credentials_path)
    print(f"[+] Loaded {len(credentials)} credential profiles from {credentials_path}")
    _log_event(crawler_log, f"Loaded {len(credentials)} credential profiles from {credentials_path}")

    # Expand any CIDR subnets (e.g., 172.16.1.0/24 or 192.168.10.0/24)
    expanded_targets = expand_targets(targets)
    print(f"[+] Crawling {len(expanded_targets)} target(s) across multi-vendor testbed & gear...")
    _log_event(crawler_log, f"Crawling {len(expanded_targets)} targets: {expanded_targets}")

    raw_devices = []
    registry = DeviceRegistry()

    for ip in expanded_targets:
        if not registry.start_crawl(ip):
            print(f"[*] Skipping {ip}: already registered as alias/SVI of a crawled device.")
            _log_event(crawler_log, f"Skipping {ip}: already registered as alias/SVI of a crawled device.")
            continue

        raw_session_log = os.path.join(logs_dir, f"{ip.replace(':', '_')}_raw_session.log")
        device_data = crawl_target(
            ip,
            credentials,
            timeout=timeout,
            session_log=raw_session_log,
            log_file=crawler_log,
        )
        if device_data:
            registry.register_device(device_data)
            raw_devices.append(device_data)
        else:
            registry.release_crawl(ip)

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
    parser.add_argument("--credentials", default="credentials.json", help="Path to credentials JSON")
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
    )
    print(f"\n[+] Total crawl and documentation runtime: {time.time() - t_start:.2f} seconds")


if __name__ == "__main__":
    main()

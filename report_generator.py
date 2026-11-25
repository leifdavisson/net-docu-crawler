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

import csv
import datetime
import json
import logging
import os
import re
import shutil

from netaddr import AddrFormatError, IPNetwork

import oui_lookup

logger = logging.getLogger(__name__)


def _route_sort_key(rt: dict) -> tuple:
    """Sort default routes first, valid CIDR networks numerically, and unparseable strings last."""
    sub = rt["subnet"]
    if sub == "0.0.0.0/0" or sub.startswith("0.0.0.0"):
        return (0, "")
    try:
        ip_net = IPNetwork(sub)
        return (1, ip_net)
    except (AddrFormatError, ValueError, TypeError) as exc:
        logger.debug("Unable to parse route subnet %r for sorting: %s", sub, exc)
        return (2, sub)


def normalize_interface_name(name):
    if not name:
        return ""
    name = re.sub(r"\.0$", "", str(name).lower().strip().strip('"').strip("'"))
    # Order longest prefixes first to prevent partial prefix collisions (e.g. twentyfive vs two)
    replacements = (
        ("twentyfivegigabitethernet", "twe"),
        ("twentyfivegige", "twe"),
        ("twopointfivegigabitethernet", "tw"),
        ("hundredgigabitethernet", "hu"),
        ("hundredgige", "hu"),
        ("fortygigabitethernet", "fo"),
        ("fortygige", "fo"),
        ("tengigabitethernet", "te"),
        ("tengige", "te"),
        ("fivegigabitethernet", "fi"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("port-channel", "po"),
        ("bundle-ether", "be"),
        ("ethernet", "et"),
    )
    for full, short in replacements:
        if name.startswith(full):
            return short + name[len(full) :]
    return name


def _parse_interface_network_strict(ip_str, mask_hint=None):
    """
    Parse multi-vendor interface IP representations into (clean_ip, IPNetwork | None, mask_known: bool).
    Does NOT fabricate a /24 mask when no CIDR prefix or netmask was provided.
    """
    if not ip_str:
        return "", None, False
    raw = str(ip_str).strip()
    if raw.lower() in ("unassigned", "down", "up", "unset", "n/a", "none", "0.0.0.0"):
        return "", None, False

    clean_ip = raw.split("/")[0].split()[0].strip()
    net = None
    mask_known = False
    try:
        if "/" in raw:
            net = IPNetwork(raw.split()[0])
            mask_known = True
        elif " " in raw:
            parts = raw.split()
            net = IPNetwork(f"{parts[0]}/{parts[1]}")
            mask_known = True
        elif mask_hint:
            net = IPNetwork(f"{clean_ip}/{str(mask_hint).lstrip('/')}")
            mask_known = True
    except (AddrFormatError, ValueError, TypeError) as exc:
        logger.debug("Failed to parse interface network from %r (mask_hint=%r): %s", ip_str, mask_hint, exc)
        net = None
        mask_known = False

    return clean_ip, net, mask_known


def parse_interface_network(ip_str, mask_hint=None):
    """
    Parses multi-vendor interface IP representations into (clean_ip, IPNetwork | None).
    Supports:
      - CIDR notation: '192.168.1.1/24', '100.64.224.70/19'
      - Space-separated netmask: '192.168.1.252 255.255.255.0'
      - Bare IP + optional config mask hint: '192.168.1.3', mask_hint='255.255.255.0'
    """
    clean_ip, net, mask_known = _parse_interface_network_strict(ip_str, mask_hint=mask_hint)
    if clean_ip and not mask_known:
        try:
            net = IPNetwork(f"{clean_ip}/24")
        except (AddrFormatError, ValueError, TypeError) as exc:
            logger.debug("Failed fallback /24 network parse for %r: %s", ip_str, exc)
            net = None
    return clean_ip, net


def get_link_speed(local_port, interfaces_detail):
    norm_local = normalize_interface_name(local_port)
    raw_low = str(local_port or "").strip().lower()

    # 1. Try to find in interfaces_detail
    for name, stats in (interfaces_detail or {}).items():
        if normalize_interface_name(name) == norm_local:
            speed_str = str((stats or {}).get("speed", "")).lower()
            if speed_str:
                if "100g" in speed_str or "100000" in speed_str:
                    return "100G"
                if "40g" in speed_str or "40000" in speed_str:
                    return "40G"
                if "25g" in speed_str or "25000" in speed_str:
                    return "25G"
                if "10g" in speed_str or "10000" in speed_str:
                    return "10G"
                if "5g" in speed_str or "5000" in speed_str:
                    return "5G"
                if "2.5g" in speed_str or "2500" in speed_str:
                    return "2.5G"
                if "1000m" in speed_str or "1g" in speed_str or "1000" in speed_str:
                    return "1G"
                if "100m" in speed_str or "100" in speed_str:
                    return "100M"
                if "10m" in speed_str or re.search(r"\b10\b", speed_str):
                    return "10M"

    # 2. Fallback to anchored prefix inference (never bare substring checks)
    if re.match(r"^(?:hu|hundred|et-\d)", norm_local) or raw_low.startswith("et-"):
        return "100G"
    if re.match(r"^(?:fo|forty|qsfp)", norm_local):
        return "40G"
    if re.match(r"^(?:twe|twentyfive|25ge)", norm_local) or raw_low.startswith(("twe", "twentyfive", "25ge")):
        return "25G"
    if re.match(r"^(?:xe-|te(?:\d|$)|ten|10ge)", norm_local) or raw_low.startswith(("xe-", "tengig", "10ge")):
        return "10G"
    if re.match(r"^(?:fi\d|fivegig)", norm_local):
        return "5G"
    if re.match(r"^(?:tw\d|twopointfive)", norm_local):
        return "2.5G"
    if re.match(r"^(?:ge-|gi|gig|vtnet|ether|eth\d|et\d|port\d|swp)", norm_local):
        return "1G"
    if re.match(r"^(?:fe-|fa\d|fast)", norm_local):
        return "100M"

    return "1G"  # Default to 1G if unknown


def get_route_details(route):
    """
    Extracts subnet, protocol, next_hop, interface, and admin_distance from a route dict,
    handling different formats (e.g. parsed vs simulated).
    """
    # Subnet extraction
    subnet = route.get("subnet")
    if not subnet:
        network = route.get("network")
        mask = route.get("mask")
        if network:
            if mask:
                subnet = f"{network}/{mask}"
            else:
                subnet = network
        else:
            subnet = "Unknown"

    # Protocol extraction
    protocol = route.get("protocol", "Unknown")
    proto_map = {
        "C": "Connected",
        "L": "Local",
        "O": "OSPF",
        "D": "EIGRP",
        "B": "BGP",
        "R": "RIP",
        "S": "Static",
        "*": "Default",
    }
    if len(protocol) == 1 and protocol in proto_map:
        protocol = proto_map[protocol]

    # Next hop extraction
    next_hop = route.get("next_hop") or route.get("nexthop") or "Unknown"

    # Interface extraction
    interface = route.get("interface") or ""

    # Administrative distance / preference (None when not reported)
    admin_distance = route.get("admin_distance")
    if admin_distance is None or admin_distance == "":
        admin_distance = route.get("preference")
    if admin_distance is None or admin_distance == "":
        admin_distance = route.get("distance")

    return {
        "subnet": subnet,
        "protocol": protocol,
        "next_hop": next_hop,
        "interface": interface,
        "admin_distance": admin_distance,
    }


_PLACEHOLDER_SERIALS = frozenset(
    {
        "",
        "unknown",
        "not specified",
        "0",
        "default string",
        "none",
        "n/a",
        "to be filled by o.e.m.",
        "system serial number",
        "chassis serial number",
        "openwrt-virtual",
        "empty",
        "virtual",
    }
)
_GENERIC_DEFAULT_HOSTNAMES = frozenset(
    {
        "",
        "unknown",
        "openwrt",
        "mikrotik",
        "opnsense",
        "pfsense",
        "localhost",
        "router",
        "switch",
        "firewall",
        "frr",
        "debian",
        "ubuntu",
        "vyos",
        "arista",
        "cisco",
        "juniper",
        "fortigate",
        "procurve",
        "aruba",
    }
)


def get_unique_devices(devices):
    """
    De-duplicates devices based on Serial Number (primary) and Hostname (fallback only when
    no unique valid hardware serial is present and hostname is non-generic).
    If a device was discovered/crawled via multiple SVIs, it only keeps one primary instance.
    """
    if not devices:
        return {}

    unique_devices = {}
    seen_serials = set()
    seen_hostnames = set()

    def ip_sort_key_internal(ip):
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return [int(x) for x in ip.split(".")]
        return [0]

    sorted_ips = sorted(
        devices.keys(),
        key=lambda ip: (
            devices[ip].get("status") == "success",
            str(devices[ip].get("mgmt_method", "")).startswith("SSH"),
            ip_sort_key_internal(ip),
        ),
        reverse=True,
    )

    duplicates_info = []

    for ip in sorted_ips:
        dev = devices[ip]
        serial = str(dev.get("serial") or "").strip()
        hostname = str(dev.get("hostname") or "").strip()

        is_duplicate = False
        duplicate_reason = ""

        # Check Serial number uniqueness (ignoring placeholder VM/SMBIOS serials)
        has_valid_serial = bool(serial) and serial.lower() not in _PLACEHOLDER_SERIALS
        if has_valid_serial:
            serial_clean = serial.upper()
            if serial_clean in seen_serials:
                is_duplicate = True
                duplicate_reason = f"duplicate serial {serial_clean}"
            else:
                seen_serials.add(serial_clean)

        # Check Hostname uniqueness ONLY as fallback when serial is absent/placeholder and hostname is non-generic
        host_clean = hostname.lower()
        if (
            not is_duplicate
            and not has_valid_serial
            and host_clean
            and host_clean not in _GENERIC_DEFAULT_HOSTNAMES
            and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host_clean)
        ):
            if host_clean in seen_hostnames:
                is_duplicate = True
                duplicate_reason = f"duplicate hostname {host_clean}"
            else:
                seen_hostnames.add(host_clean)

        if not is_duplicate:
            unique_devices[ip] = dev
        else:
            duplicates_info.append(
                f"Discovered duplicate IP {ip} ({hostname}) via {duplicate_reason}. Excluding from deliverables."
            )

    if duplicates_info:
        print("\n--- Duplicate Device Detection (Multiple SVIs) ---")
        for info in duplicates_info:
            print(f"  [!] {info}")
        print(
            f"  [+] Retained {len(unique_devices)} unique physical devices out of {len(devices)} discovered SVI endpoints.\n"
        )

    def ip_sort_key(ip):
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return [int(x) for x in ip.split(".")]
        return [0]

    return {ip: unique_devices[ip] for ip in sorted(unique_devices.keys(), key=ip_sort_key)}


_INFRA_DEVICE_TYPES = frozenset({"switch", "router", "firewall", "ap", "wlc", "wireless", "gateway", "bridge"})


def _is_network_infra(dev: dict) -> bool:
    """Return True if a device record represents crawled network infrastructure rather than a passive endpoint."""
    status = str(dev.get("status", "success")).strip().lower()
    if status != "success":
        return False
    rc = str(dev.get("record_class") or "").strip().lower()
    if rc and rc != "crawled_infra":
        return False
    dtype = str(dev.get("device_type") or dev.get("device_persona") or "switch").strip().lower()
    return dtype in _INFRA_DEVICE_TYPES


def _device_section_status(dev: dict, section: str, fallback_section: str = "") -> str:
    """
    Return the explicit collection_status for `section` on `dev`, or '' for legacy records
    that predate Schema v2.1 collection_status tracking.
    """
    cs = dev.get("collection_status")
    if not isinstance(cs, dict) or not cs:
        return ""
    if section in cs:
        return str(cs[section]).strip().lower()
    if fallback_section and fallback_section in cs:
        return str(cs[fallback_section]).strip().lower()
    return ""


def _section_availability_summary(devices_dict: dict, section: str, fallback_section: str = "") -> dict:
    """
    Summarize Schema v2.1 collection_status counts across `devices_dict` for a report section.
    Never conflates `command_failed`, `parse_failed`, or `not_collected` with `ok`.
    """
    failed_hosts: list[str] = []
    not_collected_hosts: list[str] = []
    ok_hosts: list[str] = []
    na_hosts: list[str] = []
    legacy_hosts: list[str] = []

    for ip, dev in devices_dict.items():
        host = dev.get("hostname") or ip
        st = _device_section_status(dev, section, fallback_section=fallback_section)
        if st in ("command_failed", "parse_failed"):
            failed_hosts.append(f"{host} ({st})")
        elif st == "not_collected":
            not_collected_hosts.append(host)
        elif st in ("ok", "partial"):
            ok_hosts.append(host)
        elif st == "not_applicable":
            na_hosts.append(host)
        else:
            legacy_hosts.append(host)

    return {
        "total": len(devices_dict),
        "ok_hosts": ok_hosts,
        "failed_hosts": failed_hosts,
        "not_collected_hosts": not_collected_hosts,
        "na_hosts": na_hosts,
        "legacy_hosts": legacy_hosts,
        "has_failures": bool(failed_hosts),
        "has_gaps": bool(failed_hosts or not_collected_hosts),
    }


def generate_asset_inventory(devices, output_path="asset_inventory.csv", infra_only: bool = False):
    """
    Generates the authoritative Asset Inventory CSV.
    Fields: Hostname, IP Address, MAC Address, Device Type, Model + Firmware, Serial Number, Role, Mgmt Method
    """
    fields = [
        "Hostname",
        "IP Address",
        "MAC Address",
        "Device Type",
        "Model",
        "Firmware",
        "Serial Number",
        "Role",
        "Management Method",
    ]

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ip, dev in devices.items():
                if infra_only and (
                    dev.get("status") in ("unauthenticated", "unsupported", "discovered") or not _is_network_infra(dev)
                ):
                    continue
                model_lower = dev.get("model", "").lower()
                hostname_lower = dev.get("hostname", "").lower()
                custom_dev_type = dev.get("device_type", "").lower()

                # Determine role based on model/hostname/type
                role = "Access"
                if custom_dev_type == "ap" or "ap" in custom_dev_type:
                    role = "Wireless AP"
                elif custom_dev_type == "wlc":
                    role = "WLC"
                elif custom_dev_type == "firewall":
                    role = "Perimeter Security"
                elif (
                    "core" in hostname_lower
                    or "c9500" in model_lower
                    or "4500" in model_lower
                    or "5412" in model_lower
                    or "5406" in model_lower
                    or (
                        custom_dev_type in ("", "switch")
                        and (len(dev.get("l3_interfaces", [])) >= 5 or len(dev.get("routes", [])) >= 10)
                    )
                ):
                    role = "Core"
                elif "dist" in hostname_lower or "c3850" in model_lower or "c9300" in model_lower:
                    role = "Distribution"
                elif (
                    "edge" in hostname_lower
                    or "asr" in model_lower
                    or "isr" in model_lower
                    or custom_dev_type == "router"
                ):
                    role = "Edge/Router"

                # Determine device type
                dev_type = "Switch"
                if custom_dev_type == "ap" or "air-" in model_lower or "c91" in model_lower:
                    dev_type = "Access Point"
                elif custom_dev_type == "wlc":
                    dev_type = "Wireless Controller"
                elif custom_dev_type == "firewall":
                    dev_type = "Firewall"
                elif (
                    custom_dev_type == "router"
                    or "asr" in model_lower
                    or "isr" in model_lower
                    or "router" in hostname_lower
                ):
                    dev_type = "Router"
                elif custom_dev_type and custom_dev_type not in ("switch", "unknown"):
                    _custom_labels = {"av_control": "AV Control", "ups": "UPS", "nas": "NAS", "iot": "IoT"}
                    dev_type = _custom_labels.get(custom_dev_type, custom_dev_type.replace("_", " ").title())

                status = dev.get("status", "success")
                if status in ("unauthenticated", "unsupported", "discovered"):
                    role = (
                        "Unauthenticated"
                        if status == "unauthenticated"
                        else ("Unsupported" if status == "unsupported" else "ARP Discovered")
                    )
                    if not custom_dev_type or custom_dev_type == "unknown":
                        dev_type = "Unknown"

                writer.writerow(
                    _sanitize_csv_row(
                        {
                            "Hostname": dev.get("hostname") or "Unknown",
                            "IP Address": ip,
                            "MAC Address": dev.get("mac_address") or "Unknown",
                            "Device Type": dev_type,
                            "Model": dev.get("model") or "Unknown",
                            "Firmware": dev.get("firmware") or "Unknown",
                            "Serial Number": dev.get("serial") or "Unknown",
                            "Role": role,
                            "Management Method": dev.get("mgmt_method") or "SSH",
                        }
                    )
                )
        print(f"Asset inventory successfully written to {output_path}")
    except Exception as e:
        logger.error("Error generating asset inventory CSV at %s: %s", output_path, e, exc_info=True)
        print(f"Error generating asset inventory CSV: {e}")


_PHONE_OUI_HINTS = (
    "polycom",
    "yealink",
    "grandstream",
    "digium",
    "sangoma",
    "snom",
    "mitel",
    "avaya",
    "cisco-linksys",
    "audiocodes",
)
_AP_OUI_HINTS = ("ruckus", "aruba", "ubiquiti", "unifi", "aerohive", "meraki", "cambium", "mist")


def _is_non_infra_neighbor(remote_host: str, nbr: dict) -> bool:
    """Return True if an uncrawled LLDP/CDP neighbor is an endpoint (phone, camera, PC, printer) rather than network infra."""
    from net_docu_crawler.topology_renderer import classify_neighbor_node

    return classify_neighbor_node(remote_host, nbr) == "endpoint"


_CSV_NUMERIC_RE = re.compile(r"^-\d+(?:\.\d+)?$")
_MERMAID_RESERVED_SLUGS = frozenset(
    {
        "end",
        "subgraph",
        "class",
        "click",
        "style",
        "classdef",
        "linkstyle",
        "default",
        "graph",
        "flowchart",
        "direction",
    }
)


def _sanitize_csv_cell(val: object) -> object:
    """
    Collapse embedded newlines/carriage returns and neutralize spreadsheet formula injection
    (CWE-1236) on untrusted string cells while preserving numeric types and plain negative numbers.
    """
    if val is None:
        return ""
    if isinstance(val, (int, float, bool)):
        return val
    text = re.sub(r"[\r\n]+", " ", str(val))
    stripped = text.lstrip(" ")
    if stripped and stripped[0] in ("=", "+", "@", "\t"):
        return "'" + text
    if stripped.startswith("-") and stripped != "-" and not _CSV_NUMERIC_RE.match(stripped):
        return "'" + text
    return text


def _sanitize_csv_row(row: dict) -> dict:
    """Return a copy of `row` with every cell sanitized for single-line, formula-safe CSV export."""
    return {k: _sanitize_csv_cell(v) for k, v in row.items()}


def _escape_md_cell(val: object) -> str:
    """Escape pipe delimiters and collapse line breaks for safe GitHub-Flavored Markdown table cells."""
    text = re.sub(r"[\r\n]+", " ", str(val if val is not None else ""))
    return text.replace("|", "\\|").strip()


def _mermaid_safe_text(val: str, *, escape_brackets: bool = True) -> str:
    """
    Sanitize arbitrary device/config text for Mermaid 11 labels.
    Neutralizes quotes, trailing/embedded backslashes, pipes, semicolons, hashes,
    backticks, mid-line `%%` comments, stray HTML tags, and (by default) bracket/brace delimiters.
    """
    cleaned = str(val or "").replace("\r", " ").replace("\n", " ")
    # Temporarily preserve explicit <br/> / <br> breaks while neutralizing stray angle brackets
    token = "__BR_TAG__"
    cleaned = re.sub(r"<br\s*/?>", token, cleaned, flags=re.IGNORECASE)
    cleaned = (
        cleaned.replace("\\", "/")
        .replace('"', "'")
        .replace("`", "'")
        .replace("|", "/")
        .replace(";", ",")
        .replace("#", "No.")
        .replace("%%", "% %")
        .replace("<", "(")
        .replace(">", ")")
    )
    if escape_brackets:
        cleaned = cleaned.replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
    return cleaned.replace(token, "<br/>").strip()


def _mermaid_slug(val: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(val or "").lower()).strip("_") or "node"
    if slug in _MERMAID_RESERVED_SLUGS or slug[0].isdigit():
        slug = f"n_{slug}"
    return slug


def _mermaid_l2_classdefs() -> list[str]:
    """Return canonical Mermaid class definitions for all L2 topology node roles."""
    return [
        "  %% Style configurations",
        "  classDef core fill:#3399ff,stroke:#0066cc,stroke-width:2px,color:#fff;",
        "  classDef dist fill:#85c1e9,stroke:#2e86c1,stroke-width:2px,color:#0f172a;",
        "  classDef router fill:#aed6f1,stroke:#1b4f72,stroke-width:2px,color:#0f172a;",
        "  classDef access fill:#d5dbdb,stroke:#7f8c8d,stroke-width:1px,color:#0f172a;",
        "  classDef ap fill:#f9e79f,stroke:#f1c40f,stroke-width:1px,color:#000;",
        "  classDef firewall fill:#e74c3c,stroke:#c0392b,stroke-width:2px,color:#fff;",
        "  classDef root fill:#2ecc71,stroke:#27ae60,stroke-width:3px,color:#fff;",
        "  classDef isolated_root fill:#f59e0b,stroke:#b45309,stroke-width:2px,color:#000;",
        "  classDef uncrawled fill:#f8fafc,stroke:#64748b,stroke-width:1.5px,stroke-dasharray: 5 5,color:#1e293b;",
        "  classDef wan_cloud fill:#ccfbf1,stroke:#0d9488,stroke-width:2px,color:#134e4a;",
        "  classDef isp fill:#e2e8f0,stroke:#475569,stroke-width:2px,color:#0f172a;",
    ]


def _mermaid_l3_classdefs() -> list[str]:
    """Return canonical Mermaid class definitions for L3 logical routing diagrams."""
    return [
        "  %% Style configurations",
        "  classDef isp fill:#e2e8f0,stroke:#475569,stroke-width:2px,color:#0f172a;",
        "  classDef firewall fill:#fee2e2,stroke:#dc2626,stroke-width:2px,color:#991b1b;",
        "  classDef router fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px,color:#1e3a8a;",
        "  classDef core fill:#3399ff,stroke:#0066cc,stroke-width:2px,color:#fff;",
        "  classDef wan_cloud fill:#ccfbf1,stroke:#0d9488,stroke-width:2px,color:#134e4a;",
        "  classDef external_nexthop fill:#f1f5f9,stroke:#64748b,stroke-width:1.5px,stroke-dasharray: 5 5,color:#334155;",
        "  classDef device fill:#f5f5f5,stroke:#333,stroke-width:2px,color:#0f172a;",
        "  classDef subnet fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#0c4a6e;",
        "  classDef conflict fill:#fee2e2,stroke:#dc2626,stroke-width:2.5px,color:#991b1b;",
    ]


def _speed_thickness(speed_mbps: int) -> str:
    if speed_mbps >= 100000:
        return "11px"
    if speed_mbps >= 40000:
        return "9px"
    if speed_mbps >= 10000:
        return "7.5px"
    if speed_mbps >= 5000:
        return "6px"
    if speed_mbps >= 2500:
        return "5px"
    if speed_mbps >= 1000:
        return "3.5px"
    if speed_mbps >= 100:
        return "2px"
    return "1px"


def _format_l2_edge_mermaid(src_mid: str, dst_mid: str, edge: dict, link_idx: int) -> tuple[str, str]:
    """Format a canonical L2 graph edge and its distinct Mermaid ``linkStyle`` by transport type."""
    tt = str(edge.get("transport_type") or "direct_l2_uplink").lower()
    is_blk = bool(edge.get("is_blocked"))
    speed_mbps = int(edge.get("speed_mbps") or 1000)
    thickness = _speed_thickness(speed_mbps)
    raw_pairs = [
        _mermaid_safe_text(re.sub(r"^\s*↔\s*", "", str(p)).strip()) for p in (edge.get("port_pairs") or []) if p
    ]
    ports = ", ".join(raw_pairs)
    if not ports:
        if edge.get("transit_cidr"):
            ports = _mermaid_safe_text(str(edge["transit_cidr"]))
        elif edge.get("transit_vlan"):
            ports = f"VLAN {_mermaid_safe_text(str(edge['transit_vlan']))}"
        else:
            ports = _mermaid_safe_text(str(edge.get("speed_label") or ""))

    badge = _mermaid_safe_text(str(edge.get("display_badge") or "").strip())
    mm = _mermaid_safe_text(str(edge.get("mask_mismatch") or "").strip())

    if is_blk:
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#dc2626,stroke-width:{thickness},stroke-dasharray: 5 5;"
        suffix = "[Passthrough/Transit] [STP BLK]" if tt == "virtual_passthrough" else "[STP BLK]"
        label = f"{ports} {suffix}".strip()
    elif tt in ("metro_ethernet", "wan_carrier"):
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#0d9488,stroke-width:{thickness},stroke-dasharray: 5 5;"
        badge_txt = badge or ("Metro-E" if tt == "metro_ethernet" else "WAN")
        if mm:
            badge_txt = f"{badge_txt} - MASK MISMATCH {mm}"
        label = f"{ports} [{badge_txt}]".strip()
    elif tt in ("l3_egress", "l3_routed"):
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#6366f1,stroke-width:{thickness},stroke-dasharray: 2 4;"
        badge_txt = badge or ("L3 Egress" if tt == "l3_egress" else "L3 Route")
        label = f"{ports} [{badge_txt}]".strip()
    elif tt == "mac_inferred":
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#d97706,stroke-width:{thickness},stroke-dasharray: 5 5;"
        label = f"{ports} [MAC Inferred]".strip()
    elif tt == "virtual_passthrough":
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#9333ea,stroke-width:{thickness},stroke-dasharray: 5 5;"
        label = f"{ports} [Passthrough/Transit]".strip()
    else:
        arrow = "==>" if edge.get("evidence") == "confirmed_lldp" else "-->"
        style = f"  linkStyle {link_idx} stroke:#333,stroke-width:{thickness};"
        label = f"{ports} [{badge}]".strip() if badge else ports

    safe_lbl = _mermaid_safe_text(label or badge or tt, escape_brackets=False)
    return f'  {src_mid} {arrow}|"{safe_lbl}"| {dst_mid}', style


def _l2_node_def_and_class(node: dict, mid: str, include_ap_rollup: bool = True) -> tuple[str, str]:
    """Return ``(node_definition_line, css_class)`` for a canonical topology graph node."""
    host = _mermaid_safe_text(node.get("hostname") or node.get("id") or "Unknown")
    model_s = _mermaid_safe_text(node.get("model") or "")
    role = str(node.get("role") or "switch").lower()
    scope = str(node.get("stp_root_scope") or "not_applicable").lower()
    ap_cnt = int(node.get("attached_ap_count") or 0)

    if role == "wan_cloud":
        cmode = str(node.get("cloud_mode") or "hub-and-spoke").lower()
        mode_tag = f" · {cmode}" if cmode in ("dual-hub", "full-mesh") else ""
        return f'  {mid}(["{host}<br/>(Carrier WAN / Metro-E{mode_tag})"])', "wan_cloud"
    if role == "isp":
        sub = f"<br/>({model_s})" if model_s and model_s.lower() != host.lower() else ""
        return f'  {mid}(["{host}{sub}"])', "isp"

    ap_tag = f"<br/>+{ap_cnt} APs" if (include_ap_rollup and ap_cnt > 0 and role != "ap") else ""
    if node.get("is_crawled"):
        mod_line = f"<br/>({model_s})" if model_s else ""
    else:
        if model_s and "uncrawled" not in model_s.lower():
            mod_line = f"<br/>({model_s} · Uncrawled)"
        elif model_s:
            mod_line = f"<br/>({model_s})"
        else:
            mod_line = "<br/>(Uncrawled)"

    if scope == "campus_root":
        css_cls = "root"
    elif scope == "isolated_self_root":
        css_cls = "isolated_root"
    elif role == "ap":
        css_cls = "ap"
    elif role == "firewall":
        css_cls = "firewall"
    elif role == "router":
        css_cls = "router"
    elif role == "core":
        css_cls = "core"
    elif role == "dist":
        css_cls = "dist"
    elif not node.get("is_crawled"):
        css_cls = "uncrawled"
    else:
        css_cls = "access"

    return f'  {mid}["{host}{mod_line}{ap_tag}"]', css_cls


def _compact_mermaid_block_if_oversized(mermaid_lines: list[str], max_chars: int = 38000) -> list[str]:
    """
    Compact a Mermaid ``flowchart`` block when it exceeds ``max_chars`` (Mermaid's
    default ``maxTextSize`` is 50,000 chars) by omitting ``ext_*`` leaf nodes/edges
    and dropping ``linkStyle`` lines whose indices shift.
    """
    if len("\n".join(mermaid_lines)) <= max_chars:
        return mermaid_lines

    filtered: list[str] = []
    omitted_ext = 0
    for ln in mermaid_lines:
        if re.match(r"^\s+ext_[a-z0-9_]+(?:\[|\(\[)", ln):
            omitted_ext += 1
            continue
        if re.match(r"^\s+class\s+ext_[a-z0-9_]+\s+", ln):
            continue
        if re.match(r"^\s+\S+\s+[-=.]+>.*?\bext_[a-z0-9_]+\b", ln) or re.match(r"^\s+ext_[a-z0-9_]+\s+[-=.]+>", ln):
            continue
        if re.match(r"^\s+linkStyle\s+\d+", ln):
            continue
        filtered.append(ln)

    if omitted_ext > 0:
        for i, ln in enumerate(filtered):
            if ln.strip() == "```" and i > 0:
                filtered.insert(
                    i,
                    f'  ext_summary["+{omitted_ext} Uncrawled Leaf / Endpoint Nodes<br/>(See Site Topologies & Hierarchy Tree below)"]',
                )
                break
    return filtered


def _render_l2_collapsible_hierarchy_tree(
    model: dict,
) -> list[str]:
    """Render an expandable/collapsible Markdown hierarchy tree (Site -> Core -> Hop-1 -> Hop-2 -> Hop-3) from ``model``."""
    nodes_by_id = {n["id"]: n for n in model.get("nodes") or []}
    edges = [e for e in (model.get("edges") or []) if e.get("link_scope") != "wireless_ap"]
    edges_by_node: dict[str, list[dict]] = {}
    for e in edges:
        edges_by_node.setdefault(e["source"], []).append(e)
        edges_by_node.setdefault(e["target"], []).append(e)

    sites = model.get("sites") or []
    if not sites:
        return []

    lines: list[str] = [
        "## Collapsible Layer 2 Hierarchy Tree",
        "Expand a site or switch below to inspect hierarchical hop depth, sub-campus membership, and transport-tagged links without Mermaid diagram size limits:",
        "",
    ]

    for sc in sites:
        site_nodes = [n for n in (model.get("nodes") or []) if n.get("site") == sc and n.get("role") != "ap"]
        if not site_nodes:
            continue
        site_node_ids = {n["id"] for n in site_nodes}

        # Build parent -> children tree within this site using hop_depth
        children_of: dict[str, list[str]] = {nid: [] for nid in site_node_ids}
        has_parent: set[str] = set()
        for n in sorted(
            site_nodes, key=lambda x: (int(x.get("hop_depth") or 0), x.get("layer", 4), x["hostname"].lower())
        ):
            nid = n["id"]
            my_depth = int(n.get("hop_depth") or 0)
            if my_depth <= 0:
                continue
            cand_parents = []
            for e in edges_by_node.get(nid, []):
                pid = e["target"] if e["source"] == nid else e["source"]
                if pid in site_node_ids and pid != nid:
                    pnode = nodes_by_id[pid]
                    if int(pnode.get("hop_depth") or 0) < my_depth:
                        cand_parents.append(pnode)
            if cand_parents:
                best_parent = min(
                    cand_parents,
                    key=lambda p: (int(p.get("hop_depth") or 0), int(p.get("layer") or 4), p["hostname"].lower()),
                )
                children_of[best_parent["id"]].append(nid)
                has_parent.add(nid)

        roots = sorted(
            [n for n in site_nodes if n["id"] not in has_parent],
            key=lambda x: (int(x.get("hop_depth") or 0), int(x.get("layer") or 4), x["hostname"].lower()),
        )

        lines.append(
            f"<details><summary><strong>Site: {sc}</strong> ({len(site_nodes)} infrastructure node(s))</summary>"
        )
        lines.append("")

        def _format_node_badge(n: dict) -> str:
            ip_s = f" ({n['ip']})" if n.get("ip") else ""
            mod_s = f" [{n['model']}]" if n.get("model") else ""
            sub_s = f" `[Sub-site: {n['sub_site']}]`" if n.get("sub_site") else ""
            scope = n.get("stp_root_scope") or ""
            stp_s = (
                " `[STP Campus Root]`"
                if scope == "campus_root"
                else (" `[Isolated Self-Root]`" if scope == "isolated_self_root" else "")
            )
            ap_cnt = int(n.get("attached_ap_count") or 0)
            ap_s = f" (+{ap_cnt} APs)" if ap_cnt > 0 else ""
            uncr_s = " *(Uncrawled)*" if not n.get("is_crawled") else ""
            return f"**{n['hostname']}**{ip_s}{mod_s}{sub_s}{stp_s}{ap_s}{uncr_s}"

        def _emit_subtree(nid: str, indent_lvl: int, _children_of=children_of, _edges_by_node=edges_by_node) -> None:
            n = nodes_by_id[nid]
            n_edges = sorted(
                _edges_by_node.get(nid, []),
                key=lambda e: (
                    nodes_by_id.get(e["target"] if e["source"] == nid else e["source"], {}).get("hostname", "").lower()
                ),
            )
            kids = sorted(
                _children_of.get(nid, []),
                key=lambda cid: (int(nodes_by_id[cid].get("layer") or 4), nodes_by_id[cid]["hostname"].lower()),
            )
            pad = "  " * indent_lvl
            badge_lbl = _format_node_badge(n)
            hop_lbl = f"Hop-{int(n.get('hop_depth') or 0)}"
            if not n_edges and not kids:
                lines.append(f"{pad}- {badge_lbl} *({hop_lbl}, no infra uplinks)*")
                return

            lines.append(f"{pad}- {badge_lbl} *({hop_lbl}, {len(n_edges)} link(s))*")
            for e in n_edges:
                peer_id = e["target"] if e["source"] == nid else e["source"]
                peer = nodes_by_id.get(peer_id, {"hostname": peer_id})
                ports_s = ", ".join(re.sub(r"^\s*↔\s*", "", str(p)) for p in (e.get("port_pairs") or []) if p)
                if not ports_s:
                    ports_s = e.get("transit_cidr") or e.get("speed_label") or "uplink"
                dbadge = e.get("display_badge") or e.get("transport_type") or "LLDP"
                mm = f" ⚠️ MASK MISMATCH {e['mask_mismatch']}" if e.get("mask_mismatch") else ""
                lines.append(f"{pad}  - `{ports_s}` ↔ **{peer['hostname']}** `[{dbadge}]`{mm}")
            for cid in kids:
                _emit_subtree(cid, indent_lvl + 1, _children_of=_children_of, _edges_by_node=_edges_by_node)

        for rnode in roots:
            _emit_subtree(rnode["id"], 0)

        lines.append("")
        lines.append("</details>")
        lines.append("")
    return lines


def generate_l2_diagram(devices, output_path="L2_network_diagrams.md"):
    """
    Generates the L2/Physical Network Diagram using Mermaid.js.
    Consumes the canonical ``build_topology_graph_model(devices)`` graph so
    Markdown diagrams, Interactive HTML, Wireless Overlay, and STP scopes agree 100%.
    """
    from net_docu_crawler.diagram_validator import validate_mermaid_block
    from net_docu_crawler.topology_renderer import build_topology_graph_model

    infra_devices = {ip: dev for ip, dev in (devices or {}).items() if _is_network_infra(dev)}
    model = build_topology_graph_model(infra_devices)

    lines: list[str] = [
        "# Layer 2 & Physical Network Diagrams",
        "",
        "This file contains physical topologies, switch-to-switch uplinks, carrier WAN / Metro-E paths, L3 egress links, and wireless AP connections discovered via LLDP/CDP, ARP/routing, and MAC-table correlation.",
        "",
    ]

    nodes = model.get("nodes") or []
    edges = model.get("edges") or []
    sites = model.get("sites") or []
    non_ap_nodes = [n for n in nodes if n.get("role") != "ap"]
    is_small_single_site = len(sites) <= 1 and len(non_ap_nodes) <= 12

    def _emit_mermaid_graph(
        target_nodes: list[dict],
        target_edges: list[dict],
        id_map: dict[str, str],
        include_ap_rollup: bool = True,
        group_subsites: bool = False,
        empty_label: str = "No L2 Physical Links Discovered",
    ) -> list[str]:
        m_lines = ["```mermaid", "flowchart LR", *_mermaid_l2_classdefs(), ""]
        if not target_nodes:
            m_lines.append(f'  empty_node["{_mermaid_safe_text(empty_label)}"]')
            m_lines.append("```")
            return m_lines

        subsite_groups: dict[str, list[dict]] = {}
        plain_nodes: list[dict] = []
        for n in sorted(
            target_nodes,
            key=lambda x: (int(x.get("hop_depth") or 0), int(x.get("layer") or 4), x["hostname"].lower(), x["id"]),
        ):
            sub = str(n.get("sub_site") or "").strip()
            if group_subsites and sub:
                subsite_groups.setdefault(sub, []).append(n)
            else:
                plain_nodes.append(n)

        class_lines: list[str] = []
        for n in plain_nodes:
            mid = id_map[n["id"]]
            defn, css_cls = _l2_node_def_and_class(n, mid, include_ap_rollup=include_ap_rollup)
            m_lines.append(defn)
            class_lines.append(f"  class {mid} {css_cls};")

        for sub in sorted(subsite_groups.keys()):
            sub_id = f"{_mermaid_slug(sub).upper()}_SUB"
            m_lines.append(f'  subgraph {sub_id} ["{_mermaid_safe_text(sub)} Sub-Campus"]')
            for n in subsite_groups[sub]:
                mid = id_map[n["id"]]
                defn, css_cls = _l2_node_def_and_class(n, mid, include_ap_rollup=include_ap_rollup)
                m_lines.append(f"  {defn}")
                class_lines.append(f"  class {mid} {css_cls};")
            m_lines.append("  end")

        m_lines.extend(class_lines)
        m_lines.append("")
        m_lines.append("  %% Topology links")

        link_styles: list[str] = []
        link_idx = 0
        for e in target_edges:
            if e["source"] not in id_map or e["target"] not in id_map:
                continue
            eline, sln = _format_l2_edge_mermaid(id_map[e["source"]], id_map[e["target"]], e, link_idx)
            m_lines.append(eline)
            link_styles.append(sln)
            link_idx += 1

        if link_styles:
            m_lines.append("")
            m_lines.append("  %% Link Styles (transport type & link speed)")
            m_lines.extend(link_styles)
        m_lines.append("```")
        return _compact_mermaid_block_if_oversized(m_lines)

    def _semantic_mid(n: dict, used_ids: set[str]) -> str:
        role = str(n.get("role") or "").lower()
        slug = _mermaid_slug(n["id"])
        if role == "wan_cloud":
            cand = f"cloud_{slug}"
        elif role == "isp":
            cand = f"isp_{slug}"
        elif role == "firewall" and not n.get("is_crawled"):
            cand = f"fw_{slug}"
        elif role == "router" and not n.get("is_crawled"):
            cand = f"rtr_{slug}"
        elif not n.get("is_crawled"):
            cand = f"ext_{slug}"
        else:
            cand = f"sw_{slug}"
        base = cand
        seq = 1
        while cand in used_ids:
            seq += 1
            cand = f"{base}_{seq}"
        used_ids.add(cand)
        return cand

    standalone_nodes: list[dict] = []

    if is_small_single_site:
        # Small / Single-Site Mode: deterministic sw_0, sw_1, ... in infra_devices order
        id_map: dict[str, str] = {}
        used_ids: set[str] = set()
        crawled_by_ip = {n["ip"]: n for n in nodes if n.get("is_crawled") and n.get("ip")}
        crawled_by_host = {n["hostname"].lower(): n for n in nodes if n.get("is_crawled") and n.get("hostname")}
        sw_idx = 0
        for ip, dev in infra_devices.items():
            dev_ip = str(dev.get("ip") or ip).strip()
            hn = str(dev.get("hostname") or dev_ip).strip().lower()
            mnode = crawled_by_ip.get(dev_ip) or crawled_by_host.get(hn)
            if mnode and mnode["id"] not in id_map:
                mid = f"sw_{sw_idx}"
                id_map[mnode["id"]] = mid
                used_ids.add(mid)
                sw_idx += 1

        for n in nodes:
            if n["id"] not in id_map:
                if n.get("is_crawled"):
                    mid = f"sw_{sw_idx}"
                    id_map[n["id"]] = mid
                    used_ids.add(mid)
                    sw_idx += 1
                else:
                    id_map[n["id"]] = _semantic_mid(n, used_ids)

        uncrawled_aps = [ap for ap in (model.get("ap_nodes") or []) if not ap.get("is_crawled")]
        small_nodes = list(nodes)
        small_edges = list(edges)
        rollup_aps = len(uncrawled_aps) > 12

        if not rollup_aps and uncrawled_aps:
            for ap in uncrawled_aps:
                if ap["attached_to"] not in id_map:
                    continue
                ap_mid = f"ap_{len(used_ids)}_{_mermaid_slug(ap['hostname'])}"
                used_ids.add(ap_mid)
                id_map[ap["id"]] = ap_mid
                small_nodes.append(
                    {
                        "id": ap["id"],
                        "hostname": ap["hostname"],
                        "model": ap.get("model") or "Wireless AP",
                        "role": "ap",
                        "hop_depth": 5,
                        "layer": 5,
                        "stp_root_scope": "not_applicable",
                        "attached_ap_count": 0,
                        "is_crawled": False,
                    }
                )
                small_edges.append(
                    {
                        "source": ap["attached_to"],
                        "target": ap["id"],
                        "port_pairs": [
                            f"{ap['local_port']} ↔ {ap.get('remote_port') or 'eth0'}"
                            if ap.get("local_port")
                            else (ap.get("remote_port") or "eth0")
                        ],
                        "speed_label": ap.get("speed") or "1G",
                        "speed_mbps": 1000,
                        "transport_type": "direct_l2_uplink",
                        "evidence": "unidirectional_lldp",
                        "display_badge": f"LLDP {ap.get('speed') or '1G'}",
                        "is_blocked": False,
                    }
                )

        lines.append("## Physical Connectivity Diagram")
        lines.extend(
            _emit_mermaid_graph(
                small_nodes,
                small_edges,
                id_map,
                include_ap_rollup=rollup_aps,
                group_subsites=False,
            )
        )
        lines.append("")
    else:
        # Multi-Site / Campus Mode
        nodes_by_id = {n["id"]: n for n in nodes}
        non_ap_edges = [e for e in edges if e.get("link_scope") != "wireless_ap"]
        touched_any = {e["source"] for e in non_ap_edges} | {e["target"] for e in non_ap_edges}
        standalone_nodes = [n for n in non_ap_nodes if n.get("is_crawled") and n["id"] not in touched_any]

        # Section 1: Backbone, Perimeter & Inter-Site Physical Overview
        backbone_edges = [e for e in non_ap_edges if e.get("link_scope") == "backbone"]
        bb_node_ids = {e["source"] for e in backbone_edges} | {e["target"] for e in backbone_edges}
        if not bb_node_ids:
            bb_node_ids = {n["id"] for n in non_ap_nodes if int(n.get("layer") or 4) <= 2}
        bb_nodes = [nodes_by_id[nid] for nid in bb_node_ids if nid in nodes_by_id]
        bb_id_map: dict[str, str] = {}
        bb_used: set[str] = set()
        for n in sorted(bb_nodes, key=lambda x: (int(x.get("layer") or 4), x["site"], x["hostname"].lower())):
            bb_id_map[n["id"]] = _semantic_mid(n, bb_used)

        lines.append("## Backbone, Perimeter & Inter-Site Physical Overview")
        lines.extend(
            _emit_mermaid_graph(
                bb_nodes,
                backbone_edges,
                bb_id_map,
                include_ap_rollup=False,
                group_subsites=False,
                empty_label="No Backbone or Inter-Site Uplinks Discovered",
            )
        )
        lines.append("")

        # Section 2: Site-Scoped Layer 2 Topologies
        lines.append("## Site-Scoped Layer 2 Topologies")
        for sc in sites:
            sc_nodes_base = [n for n in non_ap_nodes if n.get("site") == sc]
            if not sc_nodes_base:
                continue
            sc_edges: list[dict] = []
            for e in non_ap_edges:
                src_n = nodes_by_id.get(e["source"])
                dst_n = nodes_by_id.get(e["target"])
                if not src_n or not dst_n:
                    continue
                s_in = src_n.get("site") == sc
                d_in = dst_n.get("site") == sc
                if s_in and d_in:
                    sc_edges.append(e)
                elif e.get("link_scope") == "backbone" and (s_in ^ d_in):
                    local_n = src_n if s_in else dst_n
                    if local_n.get("role") != "wan_cloud":
                        sc_edges.append(e)

            sc_node_ids = {n["id"] for n in sc_nodes_base}
            for e in sc_edges:
                sc_node_ids.add(e["source"])
                sc_node_ids.add(e["target"])
            sc_nodes = [nodes_by_id[nid] for nid in sc_node_ids if nid in nodes_by_id]

            sc_id_map: dict[str, str] = {}
            sc_used: set[str] = set()
            for n in sorted(sc_nodes, key=lambda x: (int(x.get("hop_depth") or 0), x["hostname"].lower(), x["id"])):
                sc_id_map[n["id"]] = _semantic_mid(n, sc_used)

            lines.append(f"### Site `{sc}` Layer 2 Topology")
            lines.extend(
                _emit_mermaid_graph(
                    sc_nodes,
                    sc_edges,
                    sc_id_map,
                    include_ap_rollup=True,
                    group_subsites=True,
                )
            )
            lines.append("")

    # Legend
    lines.extend(
        [
            "### Legend",
            "* **STP Campus Root (Green)**: Multi-switch corroborated Spanning Tree root bridge (`campus_root`).",
            "* **Isolated Self-Root (Amber)**: Switch claiming root with zero peer corroboration (`isolated_self_root` / island).",
            "* **Core / Distribution Switch (Blue)**: Campus/Site MDF or distribution switch.",
            "* **Access Switch (Grey)**: Edge access switch.",
            "* **Uncrawled Infra (Dashed)**: Uncrawled switch/infra peer discovered via LLDP/CDP/ARP.",
            "* **Metro-E Cloud (Teal)**: Carrier WAN / Metro-Ethernet multi-site transit cloud.",
            "* **Firewall (Red) / Router (Light Blue) / ISP NID (Slate)**: L3 perimeter gateways and carrier handoffs.",
            "* **Solid Dark Lines (`==>` / `-->`)**: Direct LLDP/CDP uplink (`==>` confirmed two-way, `-->` unidirectional; thickness scales by speed).",
            "* **Dashed Teal Lines**: Metro-E / Carrier WAN (`wan_carrier_arp_route`).",
            "* **Dotted Indigo Lines**: L3 Egress / Route (`0.0.0.0/0` or routed next-hop).",
            "* **Dashed Orange Lines**: MAC-table inferred link (LLDP/CDP unavailable on peer).",
            "* **Dashed Purple Lines**: Virtual / bridge passthrough or multi-neighbor transit link.",
            "* **Dashed Red Lines**: STP Blocking (`BLK`) link.",
            "",
        ]
    )

    lines.extend(_render_l2_collapsible_hierarchy_tree(model))

    # Wireless Overlay Layout
    wireless_aps = model.get("wireless_aps") or []
    ap_count = len(wireless_aps)
    lines.extend(
        [
            "## Wireless Overlay Layout",
            "Discovered Wireless Access Points connected to switches:",
        ]
    )
    if ap_count > 0:
        lines.append(f"\nTotal Discovered Access Points: **{ap_count}**\n")
        if ap_count > 15:
            by_site_aps: dict[str, list[dict]] = {}
            for ap in wireless_aps:
                by_site_aps.setdefault(ap.get("site") or "CORE", []).append(ap)
            lines.extend(
                [
                    "### Per-Site Wireless Summary",
                    "| Site | Access Points | Serving Switch(es) |",
                    "| :--- | :---: | :--- |",
                ]
            )
            for sc in sorted(by_site_aps.keys()):
                s_aps = by_site_aps[sc]
                sw_names = sorted({a.get("switch_hostname") or "Standalone" for a in s_aps})
                sw_preview = ", ".join(sw_names[:6]) + (f" (+{len(sw_names) - 6} more)" if len(sw_names) > 6 else "")
                lines.append(f"| **{sc}** | **{len(s_aps)}** | {sw_preview} |")
            lines.append("")

        lines.extend(
            [
                "| Switch Hostname | Local Port | AP Hostname/MAC | AP IP | AP Model |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for ap in wireless_aps:
            sw_hn = ap.get("switch_hostname") or "(Standalone / Crawled AP)"
            lp = ap.get("local_port") or "N/A"
            ap_id_lbl = ap.get("hostname") or ap.get("mac") or "Unknown AP"
            ap_ip = ap.get("ip") or "N/A"
            ap_mod = ap.get("model") or "Wireless AP"
            lines.append(f"| {sw_hn} | {lp} | {ap_id_lbl} | {ap_ip} | {ap_mod} |")
    else:
        lines.append("\nNo wireless access points were directly discovered via LLDP/CDP neighbor tables.")

    if standalone_nodes:
        lines.extend(
            [
                "",
                "## Standalone / Unlinked Infrastructure Switches",
                "Crawled switches with zero discovered infrastructure neighbor links:",
                "",
                "| Hostname | Management IP | Site | Model |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for sn in standalone_nodes:
            lines.append(
                f"| **{sn['hostname']}** | `{sn['ip']}` | `{sn.get('site', '')}` | `{sn.get('model', 'Unknown')}` |"
            )

    scope_labels = {
        "campus_root": "Campus Root",
        "isolated_self_root": "Isolated Self-Root",
        "non_root": "Non-Root",
        "disabled": "Disabled",
        "not_applicable": "N/A",
    }
    node_scope_by_ip = {
        n["ip"]: scope_labels.get(n.get("stp_root_scope", "not_applicable"), "N/A")
        for n in nodes
        if n.get("is_crawled")
    }
    node_scope_by_hn = {
        n["hostname"].lower(): scope_labels.get(n.get("stp_root_scope", "not_applicable"), "N/A")
        for n in nodes
        if n.get("is_crawled")
    }

    lines.extend(
        [
            "",
            "## L2 Discovery Coverage & Accuracy Audit",
            "Per-device LLDP/CDP operational status, STP root scope, and topology caveats (explains unlinked, MAC-inferred, Metro-E, or passthrough edges):",
            "",
            "| Hostname | IP | Persona | STP Scope | LLDP | CDP | Neighbors | Notes / Accuracy Caveats |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :--- |",
        ]
    )
    for ip, dev in infra_devices.items():
        hostname = dev.get("hostname") or ip
        persona = dev.get("device_persona") or dev.get("device_type") or "unknown"
        dp = dev.get("discovery_protocols") or {}
        lldp_st = dp.get("lldp", "unknown")
        cdp_st = dp.get("cdp", "unsupported")
        nbrs = dev.get("neighbors") or []
        stp_scope = node_scope_by_ip.get(str(dev.get("ip") or ip)) or node_scope_by_hn.get(hostname.lower(), "N/A")
        note_parts = [dp["notes"]] if dp.get("notes") else []
        acc_notes = sorted({n.get("l2_accuracy_note", "") for n in nbrs if n.get("l2_accuracy_note")})
        note_parts.extend(acc_notes)
        if any(n.get("l2_accuracy") == "wan_carrier_arp_route" for n in nbrs) and not any(
            "metro" in p.lower() or "carrier" in p.lower() or "lldp" in p.lower() for p in note_parts
        ):
            note_parts.append("Carrier Metro-E strips LLDP frames; uplink corroborated via ARP + L3 transit")
        if not nbrs and not note_parts:
            if persona == "router":
                note_parts.append("L3 router with no L2 LLDP/CDP neighbors learned")
            else:
                note_parts.append("No LLDP/CDP neighbors learned")
        notes_str = "; ".join(note_parts) if note_parts else "Direct LLDP/CDP visibility"
        lines.append(
            f"| **{_escape_md_cell(hostname)}** | `{_escape_md_cell(ip)}` | `{_escape_md_cell(persona)}` | "
            f"{_escape_md_cell(stp_scope)} | `{_escape_md_cell(lldp_st)}` | `{_escape_md_cell(cdp_st)}` | {len(nbrs)} | {_escape_md_cell(notes_str)} |"
        )

    try:
        full_md = "\n".join(lines)
        for m_blk in re.findall(r"```mermaid\n(.*?)```", full_md, re.DOTALL):
            errs = validate_mermaid_block(m_blk)
            if errs:
                logger.warning("Mermaid syntax warning in %s: %s", output_path, "; ".join(errs))
                print(f"[!] Mermaid syntax warning in {output_path}: {errs[0]}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_md)
        print(f"L2 Diagrams successfully written to {output_path}")
    except Exception as e:
        logger.error("Error generating L2 diagram file %s: %s", output_path, e, exc_info=True)
        print(f"Error generating L2 diagram file: {e}")


def _format_l3_link_mermaid(src_mid: str, dst_mid: str, lk: dict, link_idx: int) -> tuple[str, str]:
    """Format an L3 routed/transit edge and its distinct Mermaid ``linkStyle``."""
    tt = str(lk.get("transport_type") or "l3_routed").lower()
    cidr = str(lk.get("transit_cidr") or "").strip()
    vid = str(lk.get("vlan_id") or "").strip()
    mm = bool(lk.get("mask_mismatch"))
    mm_detail = str(lk.get("mask_mismatch_detail") or "").strip()
    rpfxs = lk.get("routed_prefixes") or []

    if tt == "metro_ethernet":
        t_badge = "Metro-E"
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#0d9488,stroke-width:2.5px,stroke-dasharray: 5 5;"
    elif tt == "wan_carrier":
        t_badge = "WAN Carrier"
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#0d9488,stroke-width:2.5px,stroke-dasharray: 5 5;"
    elif tt == "direct_l2_uplink":
        t_badge = "Direct Fiber LLDP"
        arrow = "-->"
        style = f"  linkStyle {link_idx} stroke:#333,stroke-width:2.5px;"
    elif tt == "l3_egress":
        t_badge = "L3 Egress"
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#6366f1,stroke-width:2.5px,stroke-dasharray: 2 4;"
    elif tt == "overlay_tunnel":
        otype = str(lk.get("overlay_type") or "tunnel").upper()
        t_badge = f"Overlay {otype}"
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#7c3aed,stroke-width:2.5px,stroke-dasharray: 6 3;"
    elif tt == "l3_unnumbered_p2p":
        t_badge = "Unnumbered P2P"
        arrow = "-->"
        style = f"  linkStyle {link_idx} stroke:#0284c7,stroke-width:2.5px;"
    elif tt == "vrf_leak":
        t_badge = "VRF Leak"
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#d97706,stroke-width:2.5px,stroke-dasharray: 4 4;"
    else:
        t_badge = "L3 Route"
        arrow = "-.->"
        style = f"  linkStyle {link_idx} stroke:#6366f1,stroke-width:2.5px,stroke-dasharray: 2 4;"

    badge_parts = [
        f"{t_badge} VLAN {_mermaid_safe_text(vid)}"
        if (vid and tt in ("metro_ethernet", "wan_carrier", "direct_l2_uplink"))
        else t_badge
    ]
    if mm:
        badge_parts.append(f"MASK MISMATCH {_mermaid_safe_text(mm_detail)}".strip())
    if tt == "l3_egress" and "0.0.0.0/0" in rpfxs:
        badge_txt = f"{t_badge} 0.0.0.0/0"
    else:
        badge_txt = " / ".join(badge_parts)

    pfx_note = ""
    non_def = [_mermaid_safe_text(p) for p in rpfxs if p != "0.0.0.0/0"]
    if len(non_def) > 3:
        pfx_note = f"<br/>+{len(non_def)} routed prefixes"
    elif non_def:
        pfx_note = f"<br/>{', '.join(non_def)}"

    hdr = f"{_mermaid_safe_text(cidr)} " if cidr else ""
    safe_lbl = _mermaid_safe_text(f"{hdr}[{badge_txt}]{pfx_note}".strip(), escape_brackets=False)
    return f'  {src_mid} {arrow}|"{safe_lbl}"| {dst_mid}', style


def _l3_node_def_and_class(l3n: dict, mid: str) -> tuple[str, str]:
    """Return ``(node_definition_line, css_class)`` for an ``l3_graph`` node."""
    host = _mermaid_safe_text(l3n.get("hostname") or l3n.get("id") or "Unknown")
    role = str(l3n.get("role") or "device").lower()
    sub_cnt = len(l3n.get("l3_subnets") or [])
    ip_s = str(l3n.get("ip") or "").strip()

    if role == "isp":
        return f'  {mid}(["{host}"])', "isp"
    if role == "wan_cloud":
        return f'  {mid}(["{host}<br/>(Carrier WAN)"])', "wan_cloud"
    if role == "external_nexthop":
        return f'  {mid}["{host}"]', "external_nexthop"

    meta = f"<br/>({sub_cnt} SVIs)" if sub_cnt > 1 else (f"<br/>({ip_s})" if ip_s else "")
    vrf = str(l3n.get("vrf") or "default").strip()
    vrf_tag = f"<br/>[VRF: {_mermaid_safe_text(vrf)}]" if vrf and vrf != "default" else ""
    css_cls = role if role in ("firewall", "router", "core") else "device"
    return f'  {mid}["{host}{vrf_tag}{meta}"]', css_cls


def generate_l3_diagram(devices, output_path="L3_network_diagrams.md"):
    """
    Generates L3 logical and routing topologies using Mermaid.js.
    Consumes ``build_topology_graph_model(devices)["l3_graph"]`` and
    ``correlator.build_l3_svi_table()`` for authoritative routing boundaries,
    functional VLAN groups, conflict detection, and SVI/VLAN joins.
    """
    from net_docu_crawler.correlator import build_l3_svi_table
    from net_docu_crawler.diagram_validator import validate_mermaid_block
    from net_docu_crawler.topology_renderer import build_topology_graph_model

    infra_devices = {ip: dev for ip, dev in (devices or {}).items() if _is_network_infra(dev)}
    model = build_topology_graph_model(infra_devices)
    l3_graph = model.get("l3_graph") or {}
    l3_nodes = l3_graph.get("l3_nodes") or []
    l3_links = l3_graph.get("l3_links") or []
    l3_conflicts = l3_graph.get("l3_conflicts") or []
    site_vlan_groups = l3_graph.get("site_vlan_groups") or {}
    dhcp_relay_targets = l3_graph.get("dhcp_relay_targets") or {}

    svi_rows = build_l3_svi_table(list(infra_devices.values()))
    svi_lookup: dict[tuple[str, str], dict] = {}
    for row in svi_rows:
        hn = row.get("source_device") or row.get("hostname", "")
        iname = str(row.get("svi_interface") or "").lower()
        svi_lookup[(hn, iname)] = row

    device_config_ips: dict[str, dict] = {}
    for ip, dev in infra_devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        device_config_ips[hostname] = parse_interface_ips_from_config(cfg) if cfg else {}

    non_ap_nodes = [n for n in (model.get("nodes") or []) if n.get("role") != "ap"]
    all_l3_subnets = model.get("l3_subnets") or []
    sites = model.get("sites") or []
    is_campus_l3 = len(non_ap_nodes) > 10 or (len(sites) >= 2 and len(all_l3_subnets) > 10)
    omitted_l2_mgmt = sum(1 for n in non_ap_nodes if n.get("is_crawled") and not n.get("is_l3_gateway"))

    lines: list[str] = [
        "# Layer 3 & Logical Network Diagrams",
        "",
        "This file documents Layer 3 boundaries, Switch Virtual Interfaces (SVIs), VLAN maps, routing conflicts, and routing domains/VRFs.",
        "",
        "## Logical Routing Boundary Diagram",
    ]

    # Section 1: Logical Routing Boundary Diagram
    m1 = ["```mermaid", "flowchart LR", *_mermaid_l3_classdefs(), ""]
    l3_id_map: dict[str, str] = {}
    used_l3_ids: set[str] = set()

    def _alloc_l3_mid(nid: str, prefix: str = "l3") -> str:
        if nid in l3_id_map:
            return l3_id_map[nid]
        cand = f"{prefix}_{_mermaid_slug(nid)}"
        base = cand
        seq = 1
        while cand in used_l3_ids:
            seq += 1
            cand = f"{base}_{seq}"
        used_l3_ids.add(cand)
        l3_id_map[nid] = cand
        return cand

    l3_nodes_by_id = {n["id"]: n for n in l3_nodes}
    l3_nodes_by_host = {str(n.get("hostname") or "").lower(): n["id"] for n in l3_nodes if n.get("hostname")}

    if not l3_nodes and not all_l3_subnets:
        m1.append('  root["No L3 Interfaces Discovered"]')
        m1.append("  class root device;")
    elif is_campus_l3:
        linked_ids = {lk["source"] for lk in l3_links} | {lk["target"] for lk in l3_links}
        active_l3_nodes = [
            n
            for n in l3_nodes
            if (
                n.get("role") != "wan_cloud" and (n["id"] in linked_ids or n.get("is_crawled") or n.get("has_conflict"))
            )
            or n["id"] in linked_ids
        ]
        cls_lines: list[str] = []
        for n in active_l3_nodes:
            mid = _alloc_l3_mid(n["id"])
            defn, css_cls = _l3_node_def_and_class(n, mid)
            m1.append(defn)
            cls_lines.append(f"  class {mid} {css_cls};")

        # Emit explicit red conflict warning nodes for duplicate gateway IP / overlapping site subnet
        conflict_links: list[tuple[str, str, str]] = []
        for cidx, conf in enumerate(l3_conflicts):
            ctype = conf.get("conflict_type") or ""
            if ctype not in ("duplicate_gateway_ip", "overlapping_site_subnet"):
                continue
            cid = f"conflict_{cidx}"
            used_l3_ids.add(cid)
            cidr_lbl = _mermaid_safe_text(conf.get("cidr") or "")
            title_lbl = "Duplicate Gateway IP" if ctype == "duplicate_gateway_ip" else "Overlapping Site Subnet"
            dup_ip = f" ({_mermaid_safe_text(conf['duplicate_ip'])})" if conf.get("duplicate_ip") else ""
            m1.append(f'  {cid}(["CONFLICT: {title_lbl}<br/>{cidr_lbl}{dup_ip}"])')
            cls_lines.append(f"  class {cid} conflict;")
            hub_tgt = _mermaid_safe_text(conf.get("active_hub_route_target") or "")
            edge_lbl = f"CONFLICT - Hub routes to {hub_tgt}" if hub_tgt else "CONFLICT - Overlapping Subnet"
            for dname in conf.get("devices") or []:
                dn_id = l3_nodes_by_host.get(str(dname).lower())
                if dn_id and dn_id in l3_id_map:
                    conflict_links.append((l3_id_map[dn_id], cid, edge_lbl))

        m1.extend(cls_lines)
        m1.append("")
        m1.append("  %% L3 Routing & Transit Links")
        link_styles: list[str] = []
        link_idx = 0
        for lk in l3_links:
            if lk["source"] not in l3_id_map or lk["target"] not in l3_id_map:
                continue
            eline, sln = _format_l3_link_mermaid(l3_id_map[lk["source"]], l3_id_map[lk["target"]], lk, link_idx)
            m1.append(eline)
            link_styles.append(sln)
            link_idx += 1
        for src_mid, cid, elbl in conflict_links:
            m1.append(f'  {src_mid} -.->|"{_mermaid_safe_text(elbl)}"| {cid}')
            link_styles.append(f"  linkStyle {link_idx} stroke:#dc2626,stroke-width:2.5px,stroke-dasharray: 5 5;")
            link_idx += 1
        if link_styles:
            m1.append("")
            m1.extend(link_styles)
    else:
        # Small Lab Mode: show L3 nodes + subnet ovals (with accurate CIDR masks) + L3 egress/route arrows
        cls_lines = []
        for n in l3_nodes:
            mid = _alloc_l3_mid(n["id"])
            defn, css_cls = _l3_node_def_and_class(n, mid)
            m1.append(defn)
            cls_lines.append(f"  class {mid} {css_cls};")

        # Collect authoritative CIDRs (supporting raw_config mask hints when l3_interfaces lacks CIDR)
        subnet_meta: dict[str, dict[str, set[str]]] = {}
        dev_to_sub_edges: list[tuple[str, str]] = []
        for ip, dev in infra_devices.items():
            hn = dev.get("hostname") or ip
            nid = l3_nodes_by_host.get(hn.lower())
            if not nid or nid not in l3_id_map:
                continue
            for intf in dev.get("l3_interfaces") or []:
                ip_addr = str(intf.get("ip_address") or "")
                intf_name = str(intf.get("interface") or "")
                norm_intf = normalize_interface_name(intf_name)
                _cfg_ip, cfg_mask = device_config_ips.get(hn, {}).get(norm_intf, (None, None))
                clean_ip, net = parse_interface_network(ip_addr, cfg_mask)
                if not net or clean_ip.startswith(("127.", "128.0.")):
                    continue
                cidr = f"{net.network}/{net.prefixlen}"
                svi_row = svi_lookup.get((hn, intf_name.lower()), {})
                vid = svi_row.get("vlan_id") or ""
                vname = svi_row.get("vlan_name") or ""
                entry = subnet_meta.setdefault(cidr, {"labels": set()})
                if vid or vname:
                    entry["labels"].add(f"VLAN {vid}: {vname}".strip(": ") if vid else vname)
                dev_to_sub_edges.append((l3_id_map[nid], cidr))

        sub_mid_map: dict[str, str] = {}
        for idx, cidr in enumerate(sorted(subnet_meta.keys())):
            smid = f"sub_{idx}"
            sub_mid_map[cidr] = smid
            lbls = sorted(subnet_meta[cidr]["labels"])
            vname_suffix = f"<br/>({'/'.join(lbls)})" if lbls else ""
            m1.append(f'  {smid}(["{_mermaid_safe_text(cidr + vname_suffix)}"])')
            cls_lines.append(f"  class {smid} subnet;")

        m1.extend(cls_lines)
        m1.append("")
        link_styles = []
        link_idx = 0
        seen_sub_edges: set[tuple[str, str]] = set()
        for dev_mid, cidr in sorted(dev_to_sub_edges):
            smid = sub_mid_map[cidr]
            if (dev_mid, smid) in seen_sub_edges:
                continue
            seen_sub_edges.add((dev_mid, smid))
            m1.append(f"  {dev_mid} --- {smid}")
            link_styles.append(f"  linkStyle {link_idx} stroke:#64748b,stroke-width:2px;")
            link_idx += 1

        for lk in l3_links:
            if lk["source"] not in l3_id_map or lk["target"] not in l3_id_map:
                continue
            eline, sln = _format_l3_link_mermaid(l3_id_map[lk["source"]], l3_id_map[lk["target"]], lk, link_idx)
            m1.append(eline)
            link_styles.append(sln)
            link_idx += 1

        if link_styles:
            m1.append("")
            m1.extend(link_styles)

    m1.append("```")
    lines.extend(_compact_mermaid_block_if_oversized(m1))
    lines.append("")

    if is_campus_l3 and omitted_l2_mgmt > 0:
        lines.extend(
            [
                f"> [!NOTE] Scoped to **{len(l3_nodes)}** L3 routing gateways, perimeter firewalls, and routed next-hops; **{omitted_l2_mgmt}** single-SVI L2 management switches omitted from the backbone Mermaid graph above (all SVIs remain listed in the table below).",
                "",
            ]
        )

    model_svi_desc_lookup: dict[tuple[str, str], str] = {}
    model_vid_desc_lookup: dict[tuple[str, str], str] = {}
    for mnode in model.get("nodes") or []:
        mhn = str(mnode.get("hostname") or "").lower()
        for sub in mnode.get("l3_subnets") or []:
            vdesc = str(sub.get("vlan_description") or "").strip('"')
            if not vdesc:
                continue
            if sub.get("interface"):
                model_svi_desc_lookup[(mhn, str(sub["interface"]).lower())] = vdesc
            if sub.get("vlan_id"):
                model_vid_desc_lookup[(mhn, str(sub["vlan_id"]))] = vdesc

    # Section 2: Site-Scoped Layer 3 Functional Architecture Diagrams
    if is_campus_l3:
        lines.extend(["## Site-Scoped Layer 3 Functional Architecture Diagrams", ""])
        for sc in sites:
            site_l3_nodes = [
                n for n in l3_nodes if n.get("site") == sc and n.get("role") not in ("wan_cloud", "external_nexthop")
            ]
            if not site_l3_nodes:
                continue
            site_l3_ids = {n["id"] for n in site_l3_nodes}
            site_subs = [sub for n in site_l3_nodes for sub in (n.get("l3_subnets") or [])]
            sc_groups = site_vlan_groups.get(sc) or {}
            sc_relays = dhcp_relay_targets.get(sc) or []
            if not site_subs and not sc_groups:
                continue

            site_links = [lk for lk in l3_links if lk["source"] in site_l3_ids or lk["target"] in site_l3_ids]

            s_m = ["```mermaid", "flowchart LR", *_mermaid_l3_classdefs(), ""]
            s_id_map: dict[str, str] = {}
            s_used: set[str] = set()
            s_cls: list[str] = []

            def _alloc_site_l3(nid: str, _s_id_map=s_id_map, _s_used=s_used) -> str:
                if nid in _s_id_map:
                    return _s_id_map[nid]
                cand = f"s_{_mermaid_slug(nid)}"
                base = cand
                seq = 1
                while cand in _s_used:
                    seq += 1
                    cand = f"{base}_{seq}"
                _s_used.add(cand)
                _s_id_map[nid] = cand
                return cand

            node_pool_ids = set(site_l3_ids)
            for lk in site_links:
                node_pool_ids.add(lk["source"])
                node_pool_ids.add(lk["target"])

            for nid in sorted(node_pool_ids):
                n_obj = l3_nodes_by_id.get(nid)
                if not n_obj:
                    continue
                mid = _alloc_site_l3(nid)
                defn, css_cls = _l3_node_def_and_class(n_obj, mid)
                s_m.append(defn)
                s_cls.append(f"  class {mid} {css_cls};")

            primary_site_gw_node = max(
                site_l3_nodes,
                key=lambda n: (
                    1 if n.get("is_crawled") else 0,
                    len(n.get("l3_subnets") or []),
                    -int(n.get("layer") or 4),
                ),
            )
            primary_site_mid = s_id_map[primary_site_gw_node["id"]]

            s_edges_lines: list[str] = []
            s_link_styles: list[str] = []
            s_lidx = 0

            for lk in site_links:
                if lk["source"] in s_id_map and lk["target"] in s_id_map:
                    eline, sln = _format_l3_link_mermaid(s_id_map[lk["source"]], s_id_map[lk["target"]], lk, s_lidx)
                    s_edges_lines.append(eline)
                    s_link_styles.append(sln)
                    s_lidx += 1

            if len(site_subs) > 10 and sc_groups:
                for gidx, (bname, bdata) in enumerate(sorted(sc_groups.items())):
                    gid = f"grp_{gidx}"
                    s_used.add(gid)
                    samples = []
                    for it in bdata.get("items") or []:
                        lbl = str(it.get("vlan_description") or it.get("vlan_name") or "").strip()
                        if lbl and lbl not in samples:
                            samples.append(lbl)
                        if len(samples) >= 2:
                            break
                    samp_str = f"<br/>e.g. {', '.join(samples)}" if samples else ""
                    g_lbl = _mermaid_safe_text(
                        f"{bname} ({bdata.get('count', 0)} SVIs)<br/>{bdata.get('cidr_summary', '')}{samp_str}"
                    )
                    s_m.append(f'  {gid}(["{g_lbl}"])')
                    s_cls.append(f"  class {gid} subnet;")
                    s_edges_lines.append(f"  {primary_site_mid} --> {gid}")
                    s_link_styles.append(f"  linkStyle {s_lidx} stroke:#0288d1,stroke-width:2px;")
                    s_lidx += 1
            else:
                for sidx, sub in enumerate(site_subs):
                    sid = f"sub_{sidx}"
                    s_used.add(sid)
                    vid = sub.get("vlan_id") or ""
                    vname = sub.get("vlan_name") or ""
                    vdesc = sub.get("vlan_description") or ""
                    meta_p = f"VLAN {vid}: {vname}".strip(": ") if (vid or vname) else ""
                    desc_p = f" — {vdesc}" if vdesc else ""
                    cidr_p = str(sub.get("cidr") or "").strip()
                    detail_p = f"{meta_p}{desc_p}".strip()
                    raw_sub_lbl = f"{cidr_p}<br/>{detail_p}" if (cidr_p and detail_p) else (cidr_p or detail_p)
                    lbl = _mermaid_safe_text(raw_sub_lbl)
                    s_m.append(f'  {sid}(["{lbl}"])')
                    s_cls.append(f"  class {sid} subnet;")
                    s_edges_lines.append(f"  {primary_site_mid} --- {sid}")
                    s_link_styles.append(f"  linkStyle {s_lidx} stroke:#64748b,stroke-width:2px;")
                    s_lidx += 1

            if sc_relays:
                did = f"dhcp_{_mermaid_slug(sc)}"
                s_used.add(did)
                relay_txt = _mermaid_safe_text(", ".join(sc_relays))
                s_m.append(f'  {did}["DHCP Relays<br/>{relay_txt}"]')
                s_cls.append(f"  class {did} router;")
                s_edges_lines.append(f'  {primary_site_mid} -.->|"DHCP Helper"| {did}')
                s_link_styles.append(f"  linkStyle {s_lidx} stroke:#6366f1,stroke-width:2px,stroke-dasharray: 2 4;")
                s_lidx += 1

            s_m.extend(s_cls)
            s_m.append("")
            s_m.extend(s_edges_lines)
            if s_link_styles:
                s_m.append("")
                s_m.extend(s_link_styles)
            s_m.append("```")
            s_m = _compact_mermaid_block_if_oversized(s_m)
            lines.extend([f"### Site `{sc}` Layer 3 Architecture", *s_m, ""])

    # Section 3: L3 Routing Conflicts, Mask Mismatches & Collapsible Subnet Tree
    lines.extend(["### Detected L3 Conflicts & Mask Mismatches", ""])
    if l3_conflicts:
        lines.extend(
            [
                "| Conflict Type | CIDR / Subnet | Affected Devices | Active Hub Route Target | Impact Summary |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for c in l3_conflicts:
            ctype = str(c.get("conflict_type") or "").replace("_", " ").title()
            cidr_c = c.get("cidr") or ""
            devs_c = ", ".join(c.get("devices") or [])
            tgt_c = c.get("active_hub_route_target") or "-"
            imp_c = c.get("impact_summary") or ""
            lines.append(f"| **{ctype}** | `{cidr_c}` | {devs_c} | {tgt_c} | {imp_c} |")
        lines.append("")
    else:
        lines.extend(["✓ No duplicate gateway IPs, overlapping site subnets, or transit mask mismatches detected.", ""])

    if infra_devices:
        lines.extend(
            [
                "## Collapsible Layer 3 Hierarchy Tree",
                "Expand a site or device below to inspect all routed/SVI subnets, VLAN IDs, names, and descriptions at full size:",
                "",
            ]
        )
        site_by_host = {
            n["hostname"].lower(): n["site"]
            for n in (model.get("nodes") or [])
            if n.get("is_crawled") and n.get("hostname")
        }
        site_by_ip = {n["ip"]: n["site"] for n in (model.get("nodes") or []) if n.get("is_crawled") and n.get("ip")}
        by_site_l3: dict[str, list[tuple[str, list[dict]]]] = {}
        for ip, dev in infra_devices.items():
            hn = dev.get("hostname") or ip
            l3_items = []
            for intf in dev.get("l3_interfaces") or []:
                ip_addr = str(intf.get("ip_address") or "")
                intf_name = str(intf.get("interface") or "")
                norm_intf = normalize_interface_name(intf_name)
                _cfg_ip, cfg_mask = device_config_ips.get(hn, {}).get(norm_intf, (None, None))
                clean_ip, net = parse_interface_network(ip_addr, cfg_mask)
                if not clean_ip or clean_ip.startswith(("127.", "128.0.")):
                    continue
                cidr = f"{net.network}/{net.prefixlen}" if net else clean_ip
                svi_row = svi_lookup.get((hn, intf_name.lower()), {})
                vid = svi_row.get("vlan_id") or ""
                if not vid:
                    vm = re.search(r"(?:vlan\.?|vl|irb\.)0*(\d+)", intf_name, re.IGNORECASE)
                    if vm:
                        vid = vm.group(1)
                vinfo = (dev.get("vlans") or {}).get(vid, {}) if vid else {}
                vname = svi_row.get("vlan_name") or (vinfo.get("name", "") if isinstance(vinfo, dict) else "")
                vdesc = (
                    svi_row.get("vlan_description")
                    or (vinfo.get("description", "") if isinstance(vinfo, dict) else "")
                    or model_svi_desc_lookup.get((hn.lower(), intf_name.lower()), "")
                    or model_vid_desc_lookup.get((hn.lower(), str(vid)), "")
                )
                l3_items.append(
                    {
                        "cidr": cidr,
                        "vid": vid,
                        "vname": str(vname).strip('"'),
                        "vdesc": str(vdesc).strip('"'),
                        "intf": intf_name,
                        "ip": ip_addr,
                    }
                )
            if l3_items:
                sc = (
                    site_by_ip.get(str(dev.get("ip") or ip))
                    or site_by_host.get(hn.lower())
                    or dev.get("site_code")
                    or "CORE"
                )
                by_site_l3.setdefault(sc, []).append((hn, l3_items))

        for sc in sorted(by_site_l3.keys()):
            dev_entries = sorted(by_site_l3[sc], key=lambda x: x[0].lower())
            lines.append(f"<details><summary><strong>Site: {sc}</strong> ({len(dev_entries)} L3 node(s))</summary>")
            lines.append("")
            for hn, items in dev_entries:
                lines.append(f"<details><summary><strong>{hn}</strong> — {len(items)} subnet(s)</summary>")
                lines.append("")
                for it in sorted(items, key=lambda x: (x["cidr"], x["intf"])):
                    vid_s = f"VLAN {it['vid']}" if it["vid"] else "N/A"
                    vn_s = it["vname"] or "N/A"
                    vd_s = it["vdesc"] or "N/A"
                    lines.append(f"  - `{it['cidr']}` — {vid_s} | `{vn_s}` | {vd_s} (`{it['intf']}`: `{it['ip']}`)")
                lines.append("")
                lines.append("</details>")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    # Section 4: Authoritative VLAN, Subnet & SVI Map (preserve 8 columns across ALL infra devices)
    lines.extend(
        [
            "## Authoritative VLAN, Subnet & SVI Map",
            "",
            "| Switch Hostname | Interface / SVI | VLAN ID | VLAN Name | Description | SVI IP Address | Subnet Range | Interface Status |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for ip, dev in infra_devices.items():
        hostname = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", [])
        ints_detail = dev.get("interfaces_detail", {})
        for intf in l3_ints:
            intf_name = intf.get("interface")
            ip_addr = intf.get("ip_address")
            status = intf.get("status")

            desc = ""
            norm_name = normalize_interface_name(intf_name)
            for name, stats in ints_detail.items():
                if normalize_interface_name(name) == norm_name:
                    desc = stats.get("description", "")
                    break

            svi_row = svi_lookup.get((hostname, str(intf_name or "").lower()), {})
            vlan_id_str = svi_row.get("vlan_id") or ""
            vlan_name = svi_row.get("vlan_name") or ""
            if not vlan_id_str:
                vlan_match = re.search(r"(?:vlan\.?|vl|irb\.)0*(\d+)", str(intf_name or ""), re.IGNORECASE)
                if vlan_match:
                    vlan_id_str = vlan_match.group(1)
            v_entry = (dev.get("vlans") or {}).get(vlan_id_str, {}) if vlan_id_str else {}
            if not vlan_name and isinstance(v_entry, dict):
                vlan_name = v_entry.get("name", "")
            vlan_desc = (
                svi_row.get("vlan_description")
                or (str(v_entry.get("description", "")).strip('"') if isinstance(v_entry, dict) else "")
                or model_svi_desc_lookup.get((hostname.lower(), str(intf_name or "").lower()), "")
                or model_vid_desc_lookup.get((hostname.lower(), str(vlan_id_str)), "")
            )

            _cfg_ip, cfg_mask = device_config_ips.get(hostname, {}).get(norm_name, (None, None))
            clean_ip, net = parse_interface_network(ip_addr, cfg_mask)
            if clean_ip.startswith(("127.", "128.0.")):
                continue
            parsed_subnet = f"{net.network}/{net.prefixlen}" if net else ""
            if parsed_subnet and net.prefixlen < 32:
                subnet_range = parsed_subnet
            else:
                subnet_range = svi_row.get("prefix_cidr") or svi_row.get("subnet") or parsed_subnet or "N/A"
            lines.append(
                f"| {hostname} | {intf_name} | {vlan_id_str or 'N/A'} | {vlan_name or 'N/A'} | {desc or vlan_desc or 'N/A'} | {ip_addr} | {subnet_range} | {status} |"
            )

    lines.extend(
        [
            "",
            "## VRF Routing Instances & Boundaries",
            "Discovered VRF routing instances and their associated interfaces:",
        ]
    )

    from net_docu_crawler.migration_parsers import extract_vrfs_and_acls

    vrf_found = False
    for ip, dev in infra_devices.items():
        hostname = dev.get("hostname") or ip
        vrf_entries: dict[str, dict] = {}
        for item in dev.get("vrfs") or []:
            if isinstance(item, dict):
                vname = str(item.get("name") or "").strip()
                if vname:
                    vrf_entries[vname] = {
                        "name": vname,
                        "type": str(item.get("type") or "vrf"),
                        "rd": str(item.get("rd") or ""),
                        "interfaces": list(item.get("interfaces") or []),
                    }
            elif isinstance(item, str) and item.strip():
                vname = item.strip()
                vrf_entries.setdefault(vname, {"name": vname, "type": "vrf", "rd": "", "interfaces": []})

        cfg = dev.get("raw_config", "")
        if cfg:
            parsed_vrfs, _ = extract_vrfs_and_acls(cfg, vendor=dev.get("vendor", ""))
            for pv in parsed_vrfs:
                vname = str(pv.get("name") or "").strip()
                if not vname:
                    continue
                existing = vrf_entries.setdefault(
                    vname,
                    {"name": vname, "type": str(pv.get("type") or "vrf"), "rd": "", "interfaces": []},
                )
                if not existing["rd"] and pv.get("rd"):
                    existing["rd"] = str(pv["rd"])
                for pif in pv.get("interfaces") or []:
                    if pif not in existing["interfaces"]:
                        existing["interfaces"].append(pif)

        if vrf_entries:
            vrf_found = True
            lines.append(f"\n### {hostname} VRF Instances:")
            for vname in sorted(vrf_entries.keys()):
                vinfo = vrf_entries[vname]
                details = []
                if vinfo.get("type") and vinfo["type"] != "vrf":
                    details.append(f"Type: `{vinfo['type']}`")
                if vinfo.get("rd"):
                    details.append(f"RD: `{vinfo['rd']}`")
                if vinfo.get("interfaces"):
                    if_str = ", ".join(f"`{i}`" for i in sorted(vinfo["interfaces"]))
                    details.append(f"Interfaces: {if_str}")
                suffix = f" ({'; '.join(details)})" if details else ""
                lines.append(f"* **VRF Name:** `{vname}`{suffix}")

    if not vrf_found:
        vrf_avail = _section_availability_summary(infra_devices, "vrfs", fallback_section="running_config")
        if vrf_avail["has_gaps"]:
            gap_hosts = vrf_avail["failed_hosts"] + vrf_avail["not_collected_hosts"]
            lines.append(
                f"\n⚠️ **VRF Data Not Collected / Collection Failed** on {len(gap_hosts)}/{vrf_avail['total']} device(s) "
                f"({', '.join(gap_hosts[:8])}); cannot verify whether VRFs are configured."
            )
        else:
            lines.append(
                "\nNo virtual routing and forwarding (VRF) instances were detected in active device configurations (standard global table only)."
            )

    # Complete Routing Tables (summarizing /32 Access-internal / Local / Host routes per (protocol, interface))
    lines.extend(
        [
            "",
            "## Discovered Routing Tables",
            "The following table lists the active routing entries parsed from each device's routing table:",
        ]
    )

    has_routes = False
    for ip, dev in infra_devices.items():
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        if routes:
            if not has_routes:
                lines.append("")
                lines.append(
                    "| Switch Hostname | Route Prefix / Subnet | Protocol | Next Hop IP | Outgoing Interface |"
                )
                lines.append("| --- | --- | --- | --- | --- |")
                has_routes = True

            sorted_routes = sorted((get_route_details(r) for r in routes), key=_route_sort_key)

            collapsed_host_routes: dict[tuple[str, str], int] = {}
            for rt in sorted_routes:
                sub = str(rt["subnet"] or "")
                proto = str(rt["protocol"] or "")
                proto_l = proto.lower()
                iface = rt["interface"] or "N/A"
                if sub.endswith("/32") and proto_l in ("local", "access-internal", "access", "host"):
                    collapsed_host_routes[(proto, iface)] = collapsed_host_routes.get((proto, iface), 0) + 1
                    continue
                lines.append(f"| {hostname} | `{sub}` | {proto} | {rt['next_hop']} | {iface} |")
            for (proto_d, iface_d), cnt in sorted(collapsed_host_routes.items()):
                lines.append(
                    f"| {hostname} | *({cnt} `/32` {proto_d} host/subscriber routes summarized)* | {proto_d} | - | {iface_d} |"
                )

    if not has_routes:
        lines.append("\nNo routing table entries were parsed or simulated for the scanned devices.")

    try:
        full_md = "\n".join(lines)
        for m_blk in re.findall(r"```mermaid\n(.*?)```", full_md, re.DOTALL):
            errs = validate_mermaid_block(m_blk)
            if errs:
                logger.warning("Mermaid syntax warning in %s: %s", output_path, "; ".join(errs))
                print(f"[!] Mermaid syntax warning in {output_path}: {errs[0]}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_md)
        print(f"L3 Diagrams successfully written to {output_path}")
    except Exception as e:
        logger.error("Error generating L3 diagram file %s: %s", output_path, e, exc_info=True)
        print(f"Error generating L3 diagram file: {e}")


def parse_interface_ips_from_config(raw_config):
    """
    Parses interface IP addresses and subnet masks from Cisco IOS/XE/XR running-config.
    Returns a dict mapping normalized interface name -> (ip_address, subnet_mask_or_prefix)
    """
    if not raw_config:
        return {}

    intf_ips = {}
    current_intf = None

    for line in raw_config.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Match interface line
        intf_match = re.match(r"^interface\s+(\S+)", line_stripped, re.IGNORECASE)
        if intf_match:
            current_intf = normalize_interface_name(intf_match.group(1))
            continue

        if current_intf:
            # Check for end of interface block (e.g. '!' or exit)
            if line_stripped == "!" or line_stripped.lower().startswith("exit"):
                current_intf = None
                continue

            # Match ip address/ipv4 address
            ip_match = re.match(
                r"^(?:ipv4|ip)\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|/(\d+))",
                line_stripped,
                re.IGNORECASE,
            )
            if ip_match:
                ip = ip_match.group(1)
                mask_or_prefix = ip_match.group(2) or ip_match.group(3)
                intf_ips[current_intf] = (ip, mask_or_prefix)

    return intf_ips


def _render_l1_l2_cabling_and_errors_section(devices: dict) -> list[str]:
    """Render Layer 1/2 cabling speed/duplex mismatches and interface error counters."""
    lines = ["### Cabling Issues & Speed/Duplex Mismatches"]
    mismatches = []
    errors_found = []

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        for name, stats in dev.get("interfaces_detail", {}).items():
            if "up" not in str(stats.get("status", "")).lower():
                continue
            desc = stats.get("description", "")
            speed = str(stats.get("speed", ""))
            duplex = str(stats.get("duplex", ""))
            in_err = stats.get("input_errors", 0)
            crc = stats.get("crc", 0)
            out_err = stats.get("output_errors", 0)
            drops = stats.get("drops", 0)

            if duplex and "half" in duplex.lower():
                mismatches.append(
                    f"* **{hostname}** Interface `{name}` (`{desc}`): Operating at **{duplex}** / **{speed}** (Potential mismatch)."
                )

            is_gig_port = "gigabit" in name.lower() or name.lower().startswith(("gi", "ge-", "xe-", "te", "et-"))
            if speed and ("10Mb/s" in speed or (is_gig_port and "100Mb/s" in speed)):
                mismatches.append(f"* **{hostname}** Interface `{name}` (`{desc}`): Speed restricted to **{speed}**.")

            if in_err > 0 or crc > 0 or out_err > 0 or drops > 0:
                desc_str = f" (`{desc}`)" if desc else ""
                drop_str = f", Drops: `{drops}`" if drops > 0 else ""
                errors_found.append(
                    f"* **{hostname}** Interface `{name}`{desc_str}: Input Errors: `{in_err}`, CRCs: `{crc}`, Output Errors: `{out_err}`{drop_str}."
                )

    lines.extend(
        mismatches if mismatches else ["  * No active speed/duplex mismatches or half-duplex anomalies detected."]
    )
    lines.append("\n### Interface Packet & CRC Errors")
    if errors_found:
        lines.extend(errors_found)
    else:
        lines.append(
            "  * No packet errors or CRC checksum failures detected on active interfaces (clean physical paths)."
        )
    return lines


def _render_port_utilization_section(devices: dict) -> list[str]:
    """Render interface port utilization summary table across succeeded infrastructure devices."""
    rows = []
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        ints_detail = dev.get("interfaces_detail", {})
        total = len(ints_detail)
        if total == 0:
            continue
        hostname = dev.get("hostname") or ip
        connected = sum(1 for stats in ints_detail.values() if str((stats or {}).get("status", "")).lower() == "up")
        pct = (connected / total * 100) if total > 0 else 0
        rows.append(f"| {hostname} | {connected} | {total} | {pct:.1f}% |")

    lines = ["\n### Interface Port Utilization Summary"]
    if rows:
        lines.extend(
            [
                "| Switch Hostname | Connected Ports | Total Ports | Utilization % |",
                "| --- | --- | --- | --- |",
                *rows,
            ]
        )
    else:
        lines.append("  * No physical interface telemetry was collected for port utilization calculation.")
    return lines


def _render_stp_audit_section(devices: dict) -> list[str]:
    """Render Spanning Tree Protocol loop-risk and blocked-port audit."""
    lines = ["\n### Loop Risks & Spanning Tree (STP) Audit"]
    stp_issues = []
    stp_blocked_lines = []
    stp_unverified = []
    audited_switches = 0

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        stp = dev.get("stp", {}) or {}
        dev_type = str(dev.get("device_type") or dev.get("device_persona") or "switch").lower()
        stp_cs = _device_section_status(dev, "stp")

        if stp_cs in ("command_failed", "parse_failed", "not_collected"):
            if dev_type == "switch":
                stp_unverified.append(
                    f"* **{hostname}**: **STP telemetry unavailable** (`collection_status={stp_cs}`) — verify Spanning Tree state manually."
                )
            continue

        if not stp.get("enabled"):
            if dev_type == "switch":
                audited_switches += 1
                stp_issues.append(
                    f"* **{hostname}**: **Spanning Tree is DISABLED** (Extreme loop risk if redundant links exist)."
                )
            continue

        audited_switches += 1
        blocked_ports = [
            f"`{port_name}` (VLAN {vlan_id})"
            for vlan_id, ports in stp.get("vlans", {}).items()
            for port_name, state_dict in ports.items()
            if state_dict.get("state") == "BLK"
        ]
        if blocked_ports:
            stp_blocked_lines.append(
                f"* **{hostname}**: Currently blocking loops on {len(set(blocked_ports))} ports: {', '.join(sorted(set(blocked_ports)))}"
            )

    if stp_blocked_lines:
        lines.extend(stp_blocked_lines)
    if stp_issues:
        lines.extend(stp_issues)
    if stp_unverified:
        lines.extend(stp_unverified)
    if not stp_blocked_lines and not stp_issues and not stp_unverified:
        lines.append(
            f"  * Spanning Tree is active on all {audited_switches} Layer 2 switch(es) with zero loop-blocked ports "
            "(Layer 3 routers, firewalls, and wireless APs excluded from L2 STP requirement)."
        )
    return lines


def _render_interface_descriptions_section(devices: dict) -> list[str]:
    """Render configured interface descriptions and port naming tables."""
    lines = ["\n### Configured Interface Descriptions & Port Naming"]
    desc_found = False
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        device_lines = []
        has_local_desc = False
        for name, stats in dev.get("interfaces_detail", {}).items():
            desc = stats.get("description", "")
            if not desc:
                continue
            if not has_local_desc:
                device_lines.append(f"\n#### {hostname} Port Naming Mappings:")
                device_lines.append("| Port Interface | Speed | Status | Configured Description / Name |")
                device_lines.append("| --- | --- | --- | --- |")
                has_local_desc = True
                desc_found = True
            status = stats.get("status", "unknown")
            speed = stats.get("speed", "unknown")
            device_lines.append(f"| `{name}` | {speed} | {status} | {desc} |")
        if has_local_desc:
            lines.extend(device_lines)

    if not desc_found:
        lines.append("  * No interface descriptions or port names were found configured on scanned devices.")
    return lines


def _render_subnet_overlap_section(devices: dict) -> list[str]:
    """Render overlapping subnets and duplicate IP address space conflict warnings (VRF- and mask-aware)."""
    lines = ["### Overlapping Subnets & IP Space Conflicts"]
    ip_subnets = []
    fhrp_vips: set[str] = set()

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        for f_item in dev.get("fhrp") or []:
            vip = str(f_item.get("vip") or "").split("/")[0].strip()
            if vip:
                fhrp_vips.add(vip)
        hostname = dev.get("hostname") or ip
        raw_config = dev.get("raw_config", "")
        config_ips = parse_interface_ips_from_config(raw_config) if raw_config else {}
        iface_vrf_map: dict[str, str] = {}
        for vrec in dev.get("vrfs") or []:
            if isinstance(vrec, dict):
                vname = str(vrec.get("name") or "").strip().lower()
                for vif in vrec.get("interfaces") or []:
                    iface_vrf_map[normalize_interface_name(vif)] = vname
        for intf in dev.get("l3_interfaces", []):
            intf_name = intf.get("interface")
            intf_ip = intf.get("ip_address")
            if intf_ip and intf_ip not in ["unassigned", "down", "up", "unset"]:
                norm_name = normalize_interface_name(intf_name)
                _ip_from_cfg, mask_from_cfg = config_ips.get(norm_name, (None, None))
                clean_ip, net, mask_known = _parse_interface_network_strict(intf_ip, mask_from_cfg)
                if clean_ip and not clean_ip.startswith(("127.", "128.0.")):
                    vrf_name = str(intf.get("vrf") or iface_vrf_map.get(norm_name) or "default").strip().lower()
                    ip_subnets.append((hostname, intf_name, clean_ip, net, mask_known, vrf_name))

    ip_conflicts = []
    subnet_overlaps = []
    for i in range(len(ip_subnets)):
        for j in range(i + 1, len(ip_subnets)):
            h1, int1, ip1, net1, mk1, vrf1 = ip_subnets[i]
            h2, int2, ip2, net2, mk2, vrf2 = ip_subnets[j]
            if vrf1 != vrf2:
                continue
            if ip1 == ip2 and (h1 != h2 or int1 != int2):
                if ip1 not in fhrp_vips:
                    ip_conflicts.append((h1, int1, ip1, h2, int2, ip2))
            elif mk1 and mk2 and net1 is not None and net2 is not None:
                if h1 == h2 and int1 != int2 and (net1.cidr in net2.cidr or net2.cidr in net1.cidr):
                    subnet_overlaps.append((h1, int1, net1, h2, int2, net2))
                elif h1 != h2 and net1.cidr != net2.cidr and (net1.cidr in net2.cidr or net2.cidr in net1.cidr):
                    subnet_overlaps.append((h1, int1, net1, h2, int2, net2))

    overlap_found = False
    if ip_conflicts:
        overlap_found = True
        lines.append("#### Critical IP Address Conflicts")
        for h1, int1, ip1, h2, int2, _ip2 in ip_conflicts:
            lines.append(
                f"* **CRITICAL IP CONFLICT:** IP address `{ip1}` is configured on **{h1}** (`{int1}`) and **{h2}** (`{int2}`)."
            )
        lines.append("")

    if subnet_overlaps:
        overlap_found = True
        lines.append("#### Subnet Address Space Overlaps")
        for h1, int1, net1, h2, int2, net2 in subnet_overlaps:
            lines.append(
                f"* **Overlap Warning:** Overlapping CIDR boundaries `{net1.cidr}` on **{h1}** (`{int1}`) "
                f"and `{net2.cidr}` on **{h2}** (`{int2}`)."
            )
        lines.append("")

    if not overlap_found:
        lines.append("  * No overlapping subnets or IP address space collisions detected.")
    return lines


def _render_routing_protocols_and_tables_section(devices: dict) -> list[str]:
    """Render active routing protocols and complete per-device routing tables."""
    lines = ["\n### Active Routing Protocols"]
    routes_summary = {}
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        protocols = list({get_route_details(r)["protocol"] for r in dev.get("routes", [])})
        protocols = [p for p in protocols if p and p != "Unknown"]
        if protocols:
            routes_summary[hostname] = protocols

    if routes_summary:
        for host, protos in routes_summary.items():
            lines.append(f"* **{host}**: Running routing protocols: {', '.join(protos)}")
    else:
        lines.append("  * Devices are operating entirely on Static routing or directly connected Layer 3 boundaries.")

    lines.append("\n### Complete Routing Tables")
    has_routes_any = False
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        routes = dev.get("routes", [])
        if not routes:
            continue
        has_routes_any = True
        lines.append(f"\n#### {hostname} Routing Table:")
        lines.append("| Route Prefix | Protocol | Next Hop / Gateway | Outgoing Interface |")
        lines.append("| --- | --- | --- | --- |")
        sorted_routes = sorted((get_route_details(r) for r in routes), key=_route_sort_key)
        collapsed_host_routes: dict[tuple[str, str], int] = {}
        for rt in sorted_routes:
            sub = str(rt["subnet"] or "")
            proto = str(rt["protocol"] or "")
            proto_l = proto.lower()
            iface = rt["interface"] or "N/A"
            if sub.endswith("/32") and proto_l in ("local", "access-internal", "access", "host"):
                collapsed_host_routes[(proto, iface)] = collapsed_host_routes.get((proto, iface), 0) + 1
                continue
            lines.append(f"| `{sub}` | {proto} | {rt['next_hop']} | {iface} |")
        for (proto_d, iface_d), cnt in sorted(collapsed_host_routes.items()):
            lines.append(f"| *({cnt} `/32` {proto_d} subscriber/host routes summarized)* | {proto_d} | - | {iface_d} |")

    if not has_routes_any:
        lines.append("  * No routing table entries were parsed or simulated for the scanned devices.")
    return lines


def _render_l4_l7_services_and_gaps_section(devices: dict) -> list[str]:
    """Render Layer 4-7 infrastructure services consistency and visibility/security gaps."""
    lines = [
        "",
        "## 3. Layer 4-7 (Services & Security) Analysis",
        "",
        "### Infrastructure Services Consistency (NTP, DNS, AAA)",
        "| Switch Hostname | DNS Servers | NTP Servers | RADIUS/TACACS Servers | Management Protocol |",
        "| --- | --- | --- | --- | --- |",
    ]
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})
        dns = ", ".join(services.get("dns_servers", [])) or "None"
        ntp = ", ".join(services.get("ntp_servers", [])) or "None"
        aaa = []
        if services.get("radius_servers"):
            aaa.append(f"RADIUS({len(services['radius_servers'])})")
        if services.get("tacacs_servers"):
            aaa.append(f"TACACS({len(services['tacacs_servers'])})")
        aaa_str = ", ".join(aaa) or "None"
        mgmt = dev.get("mgmt_method", "SSH")
        lines.append(f"| {hostname} | {dns} | {ntp} | {aaa_str} | {mgmt} |")

    lines.append("\n### Visibility & Security Gaps")
    gaps = []
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        status_l = str(dev.get("status", "success")).strip().lower()
        mgmt = str(dev.get("mgmt_method", "SSH"))
        is_infra = _is_network_infra(dev)
        # Flag unencrypted Telnet on crawled infra and unauthenticated targets (not passive/unsupported servers)
        if (is_infra or status_l == "unauthenticated") and "telnet" in mgmt.lower():
            gaps.append(f"* **{hostname}** is using unencrypted **Telnet** for management interface (Security risk).")
        if not is_infra:
            continue
        serv_cs = _device_section_status(dev, "services", fallback_section="running_config")
        if serv_cs in ("command_failed", "parse_failed", "not_collected"):
            gaps.append(
                f"* **{hostname}** services configuration was not collected (`{serv_cs}`) — unable to verify NTP/DNS/AAA."
            )
            continue
        services = dev.get("services", {}) or {}
        if not services.get("ntp_servers"):
            gaps.append(f"* **{hostname}** has **no NTP servers** configured (Log timestamps may be out of sync).")
        if not services.get("dns_servers"):
            gaps.append(f"* **{hostname}** has **no DNS name-servers** configured (Unable to resolve hostnames).")
        if not services.get("radius_servers") and not services.get("tacacs_servers"):
            gaps.append(f"* **{hostname}** does not use central AAA authentication (Using local fallback users).")

    if gaps:
        lines.extend(gaps)
    else:
        lines.append(
            "  * No primary visibility or security gaps found. Central AAA, NTP synchronization, and secure SSH management are properly configured."
        )
    return lines


def _render_poe_and_control_plane_section(devices: dict) -> list[str]:
    """Render PoE power budget summary, dynamic routing peers, and FHRP groups."""
    lines = [
        "\n## 5. Migration Intent, Control-Plane, & Hardware Sizing",
        "\n### PoE Power Budget & Optical Transceiver Summary",
    ]
    poe_rows = []
    peer_rows = []
    fhrp_rows = []
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        poe = dev.get("poe", {}) or {}
        tot_w = float(poe.get("total_power_watts", 0.0) or 0.0)
        used_w = float(poe.get("used_power_watts", 0.0) or 0.0)
        poe_ports = len(poe.get("ports", {}) or {})
        optics_cnt = len(dev.get("optics", []) or [])
        if tot_w > 0 or used_w > 0 or poe_ports > 0 or optics_cnt > 0:
            poe_rows.append(f"| {hostname} | {ip} | {tot_w:.1f} | {used_w:.1f} | {poe_ports} | {optics_cnt} |")
        for p in dev.get("routing_peers", []) or []:
            peer_rows.append(
                f"| {hostname} | {p.get('protocol', '').upper()} | {p.get('neighbor_ip', '')} | "
                f"{p.get('remote_as') or p.get('area') or '-'} | {p.get('state', '')} |"
            )
        for f_item in dev.get("fhrp", []) or []:
            fhrp_rows.append(
                f"| {hostname} | {f_item.get('protocol', '').upper()} | {f_item.get('group', '')} | "
                f"{f_item.get('interface', '')} | {f_item.get('vip', '')} | {f_item.get('priority', '')} |"
            )

    if poe_rows:
        lines.extend(
            [
                "| Device | IP | PoE Budget (W) | PoE Used (W) | PoE Active Ports | Optics Count |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
                *poe_rows,
            ]
        )
    else:
        lines.append("  * No PoE power budgets or optical transceivers reported on crawled infrastructure.")

    if peer_rows:
        lines.append("\n### Dynamic Routing Peers (BGP / OSPF)")
        lines.append("| Device | Protocol | Neighbor / Network | AS / Area | State |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        lines.extend(peer_rows)
    if fhrp_rows:
        lines.append("\n### First-Hop Redundancy (HSRP / VRRP / CARP)")
        lines.append("| Device | Protocol | Group | Interface | VIP | Priority |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        lines.extend(fhrp_rows)
    return lines


def _render_dhcp_and_port_intent_section(devices: dict) -> list[str]:
    """Render DHCP scopes/relays and per-port L2 switching intent summary."""
    lines = []
    dhcp_pool_rows = []
    dhcp_res_count = 0
    dhcp_relay_rows = []
    port_summary_rows = []

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        dhcp = dev.get("dhcp", {}) or {}
        for pool in dhcp.get("pools", []) or []:
            dhcp_pool_rows.append(
                f"| {hostname} | {pool.get('name', '')} | {pool.get('network') or pool.get('range', '')} | "
                f"{pool.get('gateway', '')} | {pool.get('dns', '')} |"
            )
        dhcp_res_count += len(dhcp.get("reservations", []) or [])
        for rel in dhcp.get("relays", []) or []:
            dhcp_relay_rows.append(f"| {hostname} | {rel.get('interface', '')} | {rel.get('helper_ip', '')} |")

        pp = dev.get("port_profiles", {}) or {}
        if pp:
            acc = sum(1 for v in pp.values() if v.get("mode") == "access")
            trk = sum(1 for v in pp.values() if v.get("mode") == "trunk")
            rtd = sum(1 for v in pp.values() if v.get("mode") == "routed")
            lags = len({v.get("lag_group") for v in pp.values() if v.get("lag_group")})
            port_summary_rows.append(f"| {hostname} | {len(pp)} | {acc} | {trk} | {rtd} | {lags} |")

    if dhcp_pool_rows or dhcp_relay_rows or dhcp_res_count:
        lines.append(f"\n### DHCP Services (Static Reservations Discovered: **{dhcp_res_count}**)")
        if dhcp_pool_rows:
            lines.append("| Device | Pool | Network / Range | Gateway | DNS |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            lines.extend(dhcp_pool_rows)
        if dhcp_relay_rows:
            lines.append("\n| Device | Relay Interface | Helper IP |")
            lines.append("| :--- | :--- | :--- |")
            lines.extend(dhcp_relay_rows)

    if port_summary_rows:
        lines.append("\n### Per-Port L2 Switching Intent")
        lines.append("| Device | Profiled Ports | Access | Trunk | Routed | LAG Bundles |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        lines.extend(port_summary_rows)
    return lines


def generate_network_analysis_report(devices, output_path="network_analysis_report.md", dns_domain: str = ""):
    """
    Generates a structured Layer 1-7 network analysis report.
    Details cabling errors, speed mismatches, STP loop risks, subnets, and L4-L7 services.
    """
    lines = [
        "# Layered Network Analysis Report (OSI-Oriented)",
        "",
        "This report evaluates network behavior, health indicators, configuration consistency, and security gaps parsed from active switch running-states.",
    ]
    if dns_domain:
        lines.extend(["", f"**Detected DNS Domain**: `{dns_domain}`"])
    lines.extend(["", "## 1. Layer 1/2 (Physical & Data Link) Analysis", ""])
    lines.extend(_render_l1_l2_cabling_and_errors_section(devices))
    lines.extend(_render_port_utilization_section(devices))
    lines.extend(_render_stp_audit_section(devices))
    lines.extend(_build_trunk_audit_markdown_section(devices, heading="### Trunk VLAN Mismatch & L2 Symmetry Audit"))
    lines.extend(_render_interface_descriptions_section(devices))
    lines.extend(["", "## 2. Layer 3 (Routing) Analysis", ""])
    lines.extend(_render_subnet_overlap_section(devices))
    lines.extend(_render_routing_protocols_and_tables_section(devices))
    lines.extend(_render_l4_l7_services_and_gaps_section(devices))
    lines.extend(_render_poe_and_control_plane_section(devices))
    lines.extend(_render_dhcp_and_port_intent_section(devices))

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Network analysis report successfully written to {output_path}")
    except Exception as e:
        logger.debug("Error generating network analysis report at %s: %s", output_path, e, exc_info=True)
        print(f"Error generating network analysis report: {e}")


def generate_best_practices_report(devices, output_path="Cisco Best Practices.md"):
    """
    Generates a Cisco Security and Compatibility Best Practices checklist report.
    Checks running configurations and state parameters against Cisco best practices
    and flags service-impacting remediations.
    """
    lines = [
        "# Cisco Switch Best Practices & Security Audit Report",
        "",
        "This report compares active switch configurations against Cisco Security Hardening and Compatibility Guidelines.",
        "",
        "### ⚠️ Critical Warning on Service Impact Levels",
        "* **Low Impact**: Configuration changes that do not affect active data traffic (e.g. disabling unused protocols).",
        "* **Medium Impact**: Admin session drops or localized traffic shifts (e.g. switching from Telnet to SSH, changing AAA).",
        "* **High / Service Disruptive**: Potential network-wide downtime, routing adjacency drops, or port closures (e.g. Port Security, Spanning Tree changes, LACP mode updates).",
        "",
    ]

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        mgmt_method = dev.get("mgmt_method", "SSH")
        services = dev.get("services", {})

        # Audits
        # 1. SSH vs Telnet
        ssh_ok = str(mgmt_method).startswith("SSH")

        # 2. Central AAA
        aaa_ok = bool(services.get("radius_servers") or services.get("tacacs_servers"))

        # 3. SNMP v3
        snmp_v3 = False
        snmp_v1_2 = False
        if cfg:
            if re.search(r"snmp-server group|snmp-server user", cfg, re.IGNORECASE):
                snmp_v3 = True
            if re.search(r"snmp-server community", cfg, re.IGNORECASE):
                snmp_v1_2 = True
        snmp_ok = snmp_v3 and not snmp_v1_2

        # 4. DHCP Snooping
        dhcp_snoop = False
        if cfg and re.search(r"ip dhcp snooping(?!\s+information)", cfg, re.IGNORECASE):
            dhcp_snoop = True

        # 5. BPDU Guard
        bpdu_guard = False
        if cfg and re.search(r"bpduguard enable|bpduguard default", cfg, re.IGNORECASE):
            bpdu_guard = True

        # 6. Port Security
        port_sec = False
        if cfg and re.search(r"port-security", cfg, re.IGNORECASE):
            port_sec = True

        # 7. Static LACP ("mode on") loops
        lacp_static = False
        if cfg and re.search(r"channel-group\s+\d+\s+mode\s+on", cfg, re.IGNORECASE):
            lacp_static = True

        # 8. Control Plane Policing (CoPP)
        copp_ok = False
        if cfg and re.search(r"control-plane", cfg, re.IGNORECASE):
            copp_ok = True

        lines.extend(
            [
                f"## Device: {hostname} ({ip})",
                "",
                "| Best Practice Rule | Current Status | Cisco Recommendation | Service Impact of Fix |",
                "| --- | --- | --- | --- |",
                f"| **Secure Management (SSH)** | {'[✓] Compliant' if ssh_ok else '[✗] Non-Compliant'} | Disable Telnet, use SSHv2 only | **Medium**: Will drop current active Telnet sessions. |",
                f"| **Centralized AAA** | {'[✓] Compliant' if aaa_ok else '[✗] Non-Compliant'} | Use RADIUS/TACACS+ instead of local users | **Medium**: Potential admin lockout if AAA servers are unreachable. |",
                f"| **Secure SNMP (v3)** | {'[✓] Compliant' if snmp_ok else '[✗] Non-Compliant'} | Disable SNMP v1/v2c, use encrypted SNMPv3 | **Low**: Requires NMS credential updates. |",
                f"| **DHCP Snooping** | {'[✓] Compliant' if dhcp_snoop else '[✗] Non-Compliant'} | Enable globally and trust uplinks to block rogue servers | **High**: Incorrect trust port configuration blocks valid DHCP leases. |",
                f"| **STP BPDU Guard** | {'[✓] Compliant' if bpdu_guard else '[✗] Non-Compliant'} | Enable on access-ports to shut down rogue switches | **High**: Shuts down ports if rogue STP packets are received. |",
                f"| **Port Security** | {'[✓] Compliant' if port_sec else '[✗] Non-Compliant'} | Limit MACs per access-port to block MAC flooding | **High**: Shuts down port if users connect unapproved hubs/switches. |",
                f"| **Static EtherChannel** | {'[✓] Compliant' if not lacp_static else '[✗] Non-Compliant'} | Avoid static 'mode on'; use dynamic LACP | **Service Disruptive**: Changing mode drops bundle interfaces; incorrect configuration creates loops. |",
                f"| **Control Plane Policing (CoPP)** | {'[✓] Compliant' if copp_ok else '[✗] Non-Compliant'} | Enable CoPP to protect CPU from Denial of Service | **Medium**: Can drop valid protocol packets if rate-limits are too strict. |",
                "",
            ]
        )

    lines.extend(
        [
            "## Detailed Remediation Guide & Risk Mitigations",
            "",
            "### 1. Static EtherChannel to LACP Active Mode",
            "* **Risk**: **Service Disruptive**",
            "* **Impact**: Changing a port-channel group configuration tears down the virtual interface. If traffic is flowing over the port-channel, a temporary outage occurs.",
            "* **Mitigation**: Perform during a maintenance window. Enable LACP on the remote end first (passive or active), then switch the local Cisco switch to `mode active`. Avoid using `mode on` (static) as it cannot detect cabling loops.",
            "",
            "### 2. DHCP Snooping & Dynamic ARP Inspection (DAI)",
            "* **Risk**: **High**",
            "* **Impact**: If you enable DHCP Snooping without marking the uplink ports to the DHCP server as `trusted`, the switch will discard all incoming DHCP Server packets, entirely blocking DHCP addressing.",
            "* **Mitigation**: Always configure interface trust states first: `ip dhcp snooping trust` on uplink interfaces BEFORE enabling DHCP snooping globally.",
            "",
            "### 3. Port Security & MAC Address Limits",
            "* **Risk**: **High**",
            "* **Impact**: If a user plugs in a small unmanaged desktop switch or a device changes its MAC address, the port is put into `err-disabled` (shut down), causing local user outages.",
            "* **Mitigation**: Set a reasonable MAC count limit (e.g. `switchport port-security maximum 3`) and configure violation mode to `restrict` instead of `shutdown` to alert syslog without disabling the interface.",
            "",
            "### 4. AAA Authentication (RADIUS/TACACS+)",
            "* **Risk**: **Medium**",
            "* **Impact**: If centralized servers are unreachable and no local fallback is configured, administrators will be completely locked out of the switch console.",
            "* **Mitigation**: Always ensure a local fallback is defined in the method list: `aaa authentication login default group tacacs+ local` and verify console fallback access before logging out.",
        ]
    )

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Best practices report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating best practices report: {e}")


def generate_cabling_matrix(devices, output_path="migration_cabling_matrix.csv"):
    """
    Generates the Physical & Cabling Patching Matrix (Cutover Sheet).
    """
    fields = [
        "Source Hostname",
        "Source Port",
        "Description",
        "Status",
        "Admin Status",
        "Mode",
        "VLAN",
        "Access VLAN",
        "Voice VLAN",
        "Native VLAN",
        "Allowed VLANs",
        "LAG Group",
        "LACP Mode",
        "Speed",
        "Duplex",
        "PoE Draw (W)",
        "Edge MAC Count",
        "Hygiene Disposition",
        "Neighbor Hostname",
        "Neighbor Port",
        "Neighbor Platform",
        "Target Hostname (Placeholder)",
        "Target Port (Placeholder)",
        "Target Patch Panel (Placeholder)",
    ]

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()

            for ip, dev in devices.items():
                if not _is_network_infra(dev) or str(dev.get("record_class") or "").strip().lower() not in (
                    "",
                    "crawled_infra",
                ):
                    continue
                hostname = dev.get("hostname") or ip
                ints_detail = dev.get("interfaces_detail", {})
                port_profiles = dev.get("port_profiles", {}) or {}
                neighbors = dev.get("neighbors", [])

                # Pre-map port_profiles by normalized interface name
                norm_profiles = {normalize_interface_name(p_name): p_data for p_name, p_data in port_profiles.items()}

                # Pre-map neighbors by local interface name (normalized)
                neighbor_map = {}
                for n in neighbors:
                    lp = n.get("local_port", "")
                    if lp:
                        neighbor_map[normalize_interface_name(lp)] = n

                for name, stats in ints_detail.items():
                    if str(name).strip().lower() in ("irb", "vlan", "lo", "lo0"):
                        continue
                    desc = stats.get("description", "")
                    status = stats.get("status", "down")
                    speed = stats.get("speed", "")
                    duplex = stats.get("duplex", "")

                    norm_name = normalize_interface_name(name)
                    profile = port_profiles.get(name) or norm_profiles.get(norm_name) or {}
                    cport = (dev.get("ports") or {}).get(name) or {}

                    admin_status = cport.get("admin_state") or stats.get("admin_status") or "unknown"
                    mode = cport.get("mode") or profile.get("mode") or ""
                    access_vlan = str(cport.get("access_vlan") or profile.get("access_vlan") or "").strip()
                    voice_vlan = str(cport.get("voice_vlan") or profile.get("voice_vlan") or "").strip()
                    native_vlan = str(cport.get("native_vlan") or profile.get("native_vlan") or "").strip()
                    if native_vlan == "unknown":
                        native_vlan = ""
                    allowed_raw = (
                        cport.get("allowed_vlans")
                        or profile.get("allowed_vlans")
                        or profile.get("trunk_allowed_vlans")
                        or []
                    )
                    if isinstance(allowed_raw, list):
                        allowed_vlans = ",".join(str(v) for v in allowed_raw if str(v).strip())
                    else:
                        allowed_vlans = str(allowed_raw).strip()
                    lag_group = str(cport.get("lag_id") or profile.get("lag_group") or "").strip()
                    if lag_group in ("none", "unknown"):
                        lag_group = ""
                    lacp_mode = str(cport.get("lacp_mode") or profile.get("lacp_mode") or "").strip()
                    if lacp_mode in ("none", "unknown"):
                        lacp_mode = ""
                    poe_draw = cport.get("poe_draw_watts", "")
                    edge_macs = cport.get("edge_mac_count", "")
                    hygiene = cport.get("hygiene_disposition", "")

                    vlan = str(stats.get("vlan") or "").strip()
                    if not vlan:
                        if mode == "trunk" and allowed_vlans:
                            vlan = f"Trunk ({allowed_vlans})"
                        elif mode == "trunk" and native_vlan:
                            vlan = f"Trunk (native {native_vlan})"
                        elif access_vlan:
                            vlan = access_vlan
                        elif allowed_vlans:
                            vlan = allowed_vlans

                    # Look up neighbor
                    neighbor = neighbor_map.get(norm_name)

                    neigh_host = ""
                    neigh_port = ""
                    neigh_plat = ""
                    if neighbor:
                        neigh_host = neighbor.get("remote_device", "")
                        neigh_port = neighbor.get("remote_port", "")
                        neigh_plat = neighbor.get("platform") or neighbor.get("remote_platform", "")

                    writer.writerow(
                        _sanitize_csv_row(
                            {
                                "Source Hostname": hostname,
                                "Source Port": name,
                                "Description": desc,
                                "Status": status,
                                "Admin Status": admin_status,
                                "Mode": mode,
                                "VLAN": vlan,
                                "Access VLAN": access_vlan,
                                "Voice VLAN": voice_vlan,
                                "Native VLAN": native_vlan,
                                "Allowed VLANs": allowed_vlans,
                                "LAG Group": lag_group,
                                "LACP Mode": lacp_mode,
                                "Speed": speed,
                                "Duplex": duplex,
                                "PoE Draw (W)": poe_draw,
                                "Edge MAC Count": edge_macs,
                                "Hygiene Disposition": hygiene,
                                "Neighbor Hostname": neigh_host,
                                "Neighbor Port": neigh_port,
                                "Neighbor Platform": neigh_plat,
                                "Target Hostname (Placeholder)": "",
                                "Target Port (Placeholder)": "",
                                "Target Patch Panel (Placeholder)": "",
                            }
                        )
                    )
        print(f"Cabling patching matrix successfully written to {output_path}")
    except Exception as e:
        logger.error("Error generating cabling matrix CSV at %s: %s", output_path, e, exc_info=True)
        print(f"Error generating cabling matrix CSV: {e}")


def generate_port_endpoint_mapping(devices, output_path="port_mac_endpoint_mapping.csv"):
    """
    Generates the Layer 2 Port-to-MAC Endpoint Mapping matrix (Cutover Endpoint Sheet).
    Links switch access ports to connected workstations, APs, and servers with OUI resolution.
    """
    fields = [
        "Switch Hostname",
        "Switch IP",
        "Port",
        "VLAN",
        "MAC Address",
        "OUI Vendor",
        "Entry Type",
        "Resolved IP",
        "Resolved Hostname / Identity",
        "Device Persona / Role",
        "Resolution Confidence",
    ]

    mac_to_ip = {}
    mac_to_host = {}
    mac_to_role = {}
    dhcp_macs = set()

    for ip, dev in devices.items():
        dev_host = dev.get("hostname") or ip
        dev_persona = dev.get("device_persona") or dev.get("device_type", "switch")
        dev_mac = (dev.get("mac_address") or "").lower()
        if dev_mac:
            mac_to_ip[dev_mac] = ip
            mac_to_host[dev_mac] = dev_host
            mac_to_role[dev_mac] = dev_persona

        for arp in dev.get("arp_table", []):
            a_ip = arp.get("ip")
            a_mac = (arp.get("mac") or "").lower()
            if a_ip and a_mac:
                mac_to_ip[a_mac] = a_ip

        for res in (dev.get("dhcp") or {}).get("reservations", []) or []:
            r_mac = (res.get("mac") or "").lower()
            if r_mac:
                dhcp_macs.add(r_mac)
                if res.get("ip") and r_mac not in mac_to_ip:
                    mac_to_ip[r_mac] = res["ip"]
                if res.get("hostname") and r_mac not in mac_to_host:
                    mac_to_host[r_mac] = res["hostname"]

        for nbr in dev.get("neighbors", []):
            r_mac = (nbr.get("remote_mac") or "").lower()
            r_host = nbr.get("remote_device") or ""
            r_type = nbr.get("device_type") or ""
            if r_mac:
                if r_host:
                    mac_to_host[r_mac] = r_host
                if r_type:
                    mac_to_role[r_mac] = r_type

    rows = []
    seen_port_mac = set()

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        mac_table = dev.get("mac_table", [])
        dev_ports = dev.get("ports") or {}
        ports_ci = {str(k).lower(): v for k, v in dev_ports.items()}
        profs_ci = {str(k).lower(): v for k, v in (dev.get("port_profiles") or {}).items()}
        norm_dev_ports = {normalize_interface_name(k).lower(): v for k, v in dev_ports.items()}
        for entry in mac_table:
            port = entry.get("interface") or entry.get("port") or ""
            norm_p = normalize_interface_name(port).lower()
            cport = (
                dev_ports.get(port)
                or ports_ci.get(port.lower())
                or norm_dev_ports.get(norm_p)
                or profs_ci.get(port.lower())
                or {}
            )
            if (
                cport.get("mode") == "trunk"
                or cport.get("neighbor_type") in ("switch", "router", "firewall")
                or port.lower().startswith(("ae", "po", "trk"))
            ):
                continue
            vlan = str(entry.get("vlan", "1"))
            mac = (entry.get("mac") or "").lower()
            mtype = entry.get("type", "dynamic")
            vendor = entry.get("vendor") or (oui_lookup.lookup_oui(mac) if mac else "Unknown")

            res_ip = mac_to_ip.get(mac, "")
            res_host = mac_to_host.get(mac, "")
            res_role = mac_to_role.get(mac, "")

            if not res_role:
                v_lower = vendor.lower()
                if any(ap in v_lower for ap in ["aruba", "ubiquiti", "ruckus", "cisco", "mist", "meraki"]):
                    res_role = "Access Point"
                elif any(
                    srv in v_lower for srv in ["vmware", "dell", "hp", "hewlett", "supermicro", "qemu", "proxmox"]
                ):
                    res_role = "Server / Hypervisor"
                elif any(cli in v_lower for cli in ["apple", "intel", "samsung", "lenovo"]):
                    res_role = "Workstation / Client"
                else:
                    res_role = "Network Endpoint"

            res_conf = (
                "CORRELATED_DHCP"
                if mac in dhcp_macs
                else (
                    "CORRELATED_ARP" if res_ip else ("INFERRED_OUI" if vendor and vendor != "Unknown" else "UNRESOLVED")
                )
            )
            seen_port_mac.add((hostname, port, mac))
            rows.append(
                {
                    "Switch Hostname": hostname,
                    "Switch IP": ip,
                    "Port": port,
                    "VLAN": vlan,
                    "MAC Address": mac,
                    "OUI Vendor": vendor,
                    "Entry Type": mtype,
                    "Resolved IP": res_ip or "N/A (DHCP / Unrouted)",
                    "Resolved Hostname / Identity": res_host or "N/A",
                    "Device Persona / Role": res_role,
                    "Resolution Confidence": res_conf,
                }
            )

        # Enrich with learned ARP endpoints on interfaces
        for arp in dev.get("arp_table", []):
            a_ip = arp.get("ip", "")
            a_mac = (arp.get("mac") or "").lower()
            a_intf = arp.get("interface", "")
            if not a_mac or not a_intf or a_ip == ip or a_mac == "incomplete":
                continue
            a_norm = normalize_interface_name(a_intf).lower()
            a_cport = (
                dev_ports.get(a_intf)
                or ports_ci.get(a_intf.lower())
                or norm_dev_ports.get(a_norm)
                or profs_ci.get(a_intf.lower())
                or {}
            )
            if (
                a_cport.get("mode") == "trunk"
                or a_cport.get("neighbor_type") in ("switch", "router", "firewall")
                or a_intf.lower().startswith(("ae", "po", "trk"))
            ):
                continue
            if (hostname, a_intf, a_mac) in seen_port_mac:
                continue
            seen_port_mac.add((hostname, a_intf, a_mac))
            vendor = arp.get("vendor") or (oui_lookup.lookup_oui(a_mac) if a_mac else "Unknown")
            res_host = mac_to_host.get(a_mac, "")
            res_role = mac_to_role.get(a_mac, "")

            if not res_role:
                v_lower = vendor.lower()
                if any(ap in v_lower for ap in ["aruba", "ubiquiti", "ruckus", "cisco", "mist", "meraki"]):
                    res_role = "Access Point"
                elif any(
                    srv in v_lower for srv in ["vmware", "dell", "hp", "hewlett", "supermicro", "qemu", "proxmox"]
                ):
                    res_role = "Server / Hypervisor"
                elif any(cli in v_lower for cli in ["apple", "intel", "samsung", "lenovo"]):
                    res_role = "Workstation / Client"
                else:
                    res_role = "Network Endpoint"

            rows.append(
                {
                    "Switch Hostname": hostname,
                    "Switch IP": ip,
                    "Port": a_intf,
                    "VLAN": "Routed / SVI",
                    "MAC Address": a_mac,
                    "OUI Vendor": vendor,
                    "Entry Type": "arp-learned",
                    "Resolved IP": a_ip,
                    "Resolved Hostname / Identity": res_host or "N/A",
                    "Device Persona / Role": res_role,
                    "Resolution Confidence": "CORRELATED_ARP",
                }
            )

    try:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for r in rows:
                writer.writerow(_sanitize_csv_row(r))
        print(f"Port-to-MAC endpoint mapping successfully written to {output_path}")
    except Exception as e:
        logger.error("Error generating port-to-endpoint CSV at %s: %s", output_path, e, exc_info=True)
        print(f"Error generating port-to-endpoint CSV: {e}")


def generate_protocol_translation(devices, output_path="cisco_to_target_translation.md"):
    """
    Generates Cisco-to-Target Feature Mapping & Protocol Translation Matrix.
    """
    lines = [
        "# Cross-Vendor Protocol Translation & Mapping Matrix",
        "",
        "This report outlines proprietary or vendor-specific protocols detected on your network switches, and provides the standard target equivalent features required during migration.",
        "",
    ]

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")

        lines.append(f"## Switch: {hostname} ({ip}) — {dev.get('vendor', 'Unknown')}")
        lines.append(
            "| Source Construct | Source Evidence (Ports / VLANs / IPs) | Target Standard Equivalent | Validation Gate |"
        )
        lines.append("| --- | --- | --- | --- |")

        features_found = 0
        vendor_l = str(dev.get("vendor") or "").lower()
        ports_map = dev.get("ports") or {}
        acc_ports = [p for p, d in ports_map.items() if d.get("mode") == "access"]
        trk_ports = [p for p, d in ports_map.items() if d.get("mode") == "trunk"]
        voice_vlans = sorted({str(d.get("voice_vlan")) for d in ports_map.values() if d.get("voice_vlan")})
        relays = (dev.get("dhcp") or {}).get("relays") or []
        stp = dev.get("stp") or {}

        if "procurve" in vendor_l or "hp" in vendor_l or "aruba" in vendor_l:
            if acc_ports or trk_ports:
                lines.append(
                    f"| **HP/Aruba `untagged` / `tagged` VLANs** | {len(acc_ports)} access, {len(trk_ports)} trunk ports | Target Access / Trunk Port Profiles | Per-VLAN MAC learning |"
                )
                features_found += 1
            if voice_vlans:
                lines.append(
                    f"| **HP/Aruba `voice` VLAN** | VLAN(s): {', '.join(voice_vlans)} | Target Voice VLAN + LLDP-MED | Phone DHCP & voice VLAN check |"
                )
                features_found += 1
            if relays:
                lines.append(
                    f"| **HP/Aruba `ip helper-address`** | {len(relays)} relay binding(s) | Target SVI DHCP Relay | Client DHCP lease test |"
                )
                features_found += 1
            if stp.get("enabled") is False:
                lines.append(
                    "| **⚠️ STP Disabled on Source Switch** | `STP Enabled: No` | Enable RSTP (802.1w) / MSTP (802.1s) on target | Loop-free topology check |"
                )
                features_found += 1
        elif "juniper" in vendor_l:
            all_trks = [p for p, d in ports_map.items() if d.get("allowed_vlans_raw") == "all"]
            if acc_ports or trk_ports:
                ev = f"{len(acc_ports)} access, {len(trk_ports)} trunk" + (
                    f" ({len(all_trks)} using `all`)" if all_trks else ""
                )
                lines.append(
                    f"| **Junos `family ethernet-switching`** | {ev} | Target Access / Trunk Port Profiles (explicit VLANs) | Compare source vs target port objects |"
                )
                features_found += 1
            if voice_vlans:
                lines.append(
                    f"| **Junos `switch-options voip`** | Voice VLAN(s): {', '.join(voice_vlans)} | Target Voice VLAN + LLDP-MED | Phone DHCP & voice VLAN check |"
                )
                features_found += 1
            if relays:
                lines.append(
                    f"| **Junos `irb.*` + `dhcp-relay`** | {len(relays)} relay binding(s) | Target SVI + DHCP Relay | Gateway & DHCP lease test |"
                )
                features_found += 1
            if stp.get("root_scope") == "isolated_self_root":
                lines.append(
                    f"| **⚠️ Junos `isolated_self_root` RSTP** | Root `{stp.get('root_bridge', '')}` | Deterministic RSTP/MSTP root priority | Root/secondary-root check |"
                )
                features_found += 1
        elif cfg:
            # Spanning tree
            if re.search(r"spanning-tree mode\s+(?:pvst|rapid-pvst)", cfg, re.IGNORECASE):
                lines.append(
                    "| **Rapid-PVST+ / PVST+** | Configured in `spanning-tree mode` | `MSTP (802.1s)` or `RSTP (802.1w)` | Root/secondary-root check |"
                )
                features_found += 1
            # HSRP
            if re.search(r"standby\s+\d+\s+ip", cfg, re.IGNORECASE):
                lines.append(
                    "| **HSRP (Hot Standby Router Protocol)** | Configured in `standby ip` | `VRRPv3 (RFC 5798)` | Gateway failover test |"
                )
                features_found += 1
            # CDP
            if re.search(r"cdp run|cdp enable", cfg, re.IGNORECASE):
                lines.append(
                    "| **CDP (Cisco Discovery Protocol)** | Configured in `cdp` | `LLDP (802.1AB)` | Neighbor adjacency check |"
                )
                features_found += 1
            # VTP
            if re.search(r"vtp mode|vtp domain", cfg, re.IGNORECASE):
                lines.append(
                    "| **VTP (VLAN Trunking Protocol)** | Configured in `vtp` | `Manual Config` or `MVRP (802.1ak)` | VLAN database parity |"
                )
                features_found += 1
            # Static EtherChannel
            if re.search(r"channel-group\s+\d+\s+mode\s+on", cfg, re.IGNORECASE):
                lines.append(
                    "| **Static EtherChannel** | `channel-group mode on` | `LACP (802.3ad) Active` | All LAG members forwarding |"
                )
                features_found += 1
            # Stackwise
            if dev.get("model") and ("c9300" in dev.get("model").lower() or "c3850" in dev.get("model").lower()):
                lines.append(
                    "| **StackWise / StackWise-Virtual** | Hardware model | `VPC / MLAG` or Target Virtual Chassis | Redundant uplink check |"
                )
                features_found += 1

        if features_found == 0:
            lines.append(
                "| *No vendor-specific constructs extracted* | Verify `ports` / `raw_config` | Standard Target Profile | Manual config review |"
            )

        lines.append("")

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Protocol translation report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating protocol translation report: {e}")


def generate_config_variables(devices, output_path="migration_config_variables.json"):
    """
    Generates configuration variables JSON sheet for Jinja2/Ansible templates.
    """
    from net_docu_crawler.migration_parsers import extract_vlans

    variables = {}

    # Pre-parse VLAN names for all devices (preferring structured dev["vlans"] + multi-vendor config fallback)
    device_vlan_maps = {}
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        vlan_names: dict[str, str] = {}
        for vid, vinfo in (dev.get("vlans") or {}).items():
            vid_s = str(vid).strip()
            if vid_s.isdigit() and 1 <= int(vid_s) <= 4094:
                vname = (vinfo.get("name") if isinstance(vinfo, dict) else str(vinfo)) or f"VLAN_{vid_s}"
                vlan_names[vid_s] = str(vname).strip().strip('"').strip("'")
        cfg = dev.get("raw_config", "")
        if cfg:
            for vid, vinfo in extract_vlans(cfg, vendor=dev.get("vendor", "")).items():
                vlan_names.setdefault(str(vid), str(vinfo.get("name") or f"VLAN_{vid}"))
        device_vlan_maps[hostname] = vlan_names

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})

        # Build VLAN list
        vlans_list = []
        vlan_names = device_vlan_maps.get(hostname, {})
        for vid in sorted(vlan_names.keys(), key=lambda x: int(x) if x.isdigit() else 99999):
            vlans_list.append({"id": vid, "name": vlan_names[vid]})

        # Build SVI list
        l3_ints = dev.get("l3_interfaces", [])
        ints_detail = dev.get("interfaces_detail", {})
        config_ips = parse_interface_ips_from_config(dev.get("raw_config", "")) if dev.get("raw_config") else {}
        svis_list = []
        for intf in l3_ints:
            intf_name = intf.get("interface")
            ip_addr = intf.get("ip_address")
            status = intf.get("status")

            desc = ""
            norm_name = normalize_interface_name(intf_name)
            for name, stats in ints_detail.items():
                if normalize_interface_name(name) == norm_name:
                    desc = stats.get("description", "")
                    break

            _ip_cfg, mask_cfg = config_ips.get(norm_name, (None, None))
            _clean_ip, net, mask_known = _parse_interface_network_strict(ip_addr, mask_hint=mask_cfg)
            subnet_range = str(net.cidr) if (mask_known and net is not None) else "Unknown"
            svis_list.append(
                {
                    "interface": intf_name,
                    "ip_address": ip_addr,
                    "subnet": subnet_range,
                    "status": status,
                    "description": desc,
                }
            )

        # Build physical interfaces list
        interfaces_list = []
        for name, stats in ints_detail.items():
            # Skip SVIs in the physical list
            if "vlan" in name.lower() or "loopback" in name.lower():
                continue
            interfaces_list.append(
                {
                    "interface": name,
                    "description": stats.get("description", ""),
                    "status": stats.get("status", "down"),
                    "vlan": stats.get("vlan", ""),
                    "speed": stats.get("speed", ""),
                    "duplex": stats.get("duplex", ""),
                }
            )

        variables[hostname] = {
            "management_ip": ip,
            "model": dev.get("model", "Unknown"),
            "firmware": dev.get("firmware", "Unknown"),
            "serial": dev.get("serial", "Unknown"),
            "dns_servers": services.get("dns_servers", []),
            "ntp_servers": services.get("ntp_servers", []),
            "radius_servers": services.get("radius_servers", []),
            "tacacs_servers": services.get("tacacs_servers", []),
            "vlans": vlans_list,
            "l3_interfaces": svis_list,
            "interfaces": interfaces_list,
            "routes": [get_route_details(r) for r in dev.get("routes", [])],
        }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(variables, f, indent=4)
        print(f"Configuration variables successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating config variables JSON: {e}")


def save_baseline_state(devices, output_path):
    """
    Saves the key operational state parameters (MACs, routes, neighbors, up interfaces)
    as a baseline JSON file for future comparison.
    """
    baseline = {}
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip

        # Up physical interfaces
        up_ints = []
        for name, stats in dev.get("interfaces_detail", {}).items():
            if stats.get("status") == "up":
                up_ints.append(name)

        # Neighbor connections
        neighbors = []
        for n in dev.get("neighbors", []):
            neighbors.append(
                {
                    "local_port": n.get("local_port", ""),
                    "remote_device": n.get("remote_device", ""),
                    "remote_port": n.get("remote_port", ""),
                }
            )

        # Route prefixes
        routes = []
        for r in dev.get("routes", []):
            details = get_route_details(r)
            if details["subnet"] and details["subnet"] != "Unknown":
                routes.append(details["subnet"])

        # SVI / L3 Interface states
        svis = {}
        for intf in dev.get("l3_interfaces", []):
            svis[intf.get("interface")] = {"ip": intf.get("ip_address"), "status": intf.get("status")}

        baseline[hostname] = {
            "management_ip": ip,
            "up_interfaces": up_ints,
            "neighbors": neighbors,
            "routes": routes,
            "svis": svis,
        }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=4)
        print(f"\n[+] Baseline state successfully saved to {output_path}")
    except Exception as e:
        print(f"Error saving baseline state: {e}")


def compare_baseline_state(devices, baseline_path, output_path="migration_verification_report.md"):
    """
    Compares the current network state against a baseline JSON file.
    Generates a verification report detailing missing elements or state mismatches.
    """
    if not os.path.exists(baseline_path):
        print(f"Error: Baseline file {baseline_path} does not exist.")
        return

    try:
        with open(baseline_path, encoding="utf-8") as f:
            baseline = json.load(f)
    except Exception as e:
        print(f"Error reading baseline file: {e}")
        return

    # Support full dataset JSON (`list[dict]` or `dict[ip, device_dict]`) in addition to legacy baseline summaries
    if isinstance(baseline, list) or (
        isinstance(baseline, dict)
        and baseline
        and any(isinstance(v, dict) and ("interfaces_detail" in v or "ports" in v) for v in baseline.values())
    ):
        raw_list = baseline if isinstance(baseline, list) else list(baseline.values())
        normalized_baseline = {}
        for bd in raw_list:
            if not isinstance(bd, dict) or bd.get("status", "success") != "success":
                continue
            bhost = bd.get("hostname") or bd.get("ip", "")
            if not bhost:
                continue
            b_ints = bd.get("interfaces_detail") or {}
            b_up = [n for n, st in b_ints.items() if st.get("status") == "up"]
            b_svis = {
                i.get("interface", ""): {"ip": i.get("ip_address", ""), "status": i.get("status", "")}
                for i in (bd.get("l3_interfaces") or [])
                if i.get("interface")
            }
            normalized_baseline[bhost] = {
                "management_ip": bd.get("ip", ""),
                "up_interfaces": b_up,
                "svis": b_svis,
                "neighbors": bd.get("neighbors") or [],
                "routes": bd.get("routes") or [],
            }
        baseline = normalized_baseline

    lines = [
        "# Post-Migration Verification & Validation Report",
        "",
        f"This report compares the current network state against the baseline file: `{os.path.basename(baseline_path)}`.",
        "",
    ]

    total_failures = 0

    for host_base, base_state in baseline.items():
        # Find matching device in current devices by IP or hostname
        current_dev = None
        base_ip = base_state.get("management_ip")

        for ip, dev in devices.items():
            if ip == base_ip or (dev.get("hostname") and dev.get("hostname").lower() == host_base.lower()):
                current_dev = dev
                break

        lines.append(f"## Device: {host_base}")
        if not current_dev:
            lines.append("❌ **CRITICAL: Switch is UNREACHABLE or missing in current scan!**")
            lines.append("")
            total_failures += 1
            continue

        device_failures = 0

        # 1. Compare UP physical interfaces
        base_up = base_state.get("up_interfaces", [])
        curr_ints = current_dev.get("interfaces_detail", {})
        curr_up = [name for name, stats in curr_ints.items() if stats.get("status") == "up"]

        missing_ints = [name for name in base_up if name not in curr_up]
        if missing_ints:
            lines.append(
                f"❌ **Interface Status Mismatch**: {len(missing_ints)} interfaces that were UP are now DOWN or missing:"
            )
            for name in missing_ints:
                desc = curr_ints.get(name, {}).get("description", "No Description")
                lines.append(f"  * `{name}` (Description: `{desc}`)")
            device_failures += 1
        else:
            lines.append("✓ **Interface Status**: All baseline UP interfaces are currently UP.")

        # 2. Compare SVI / L3 Interface states
        base_svis = base_state.get("svis", {})
        curr_svis = {intf.get("interface"): intf for intf in current_dev.get("l3_interfaces", [])}

        svi_mismatches = []
        for name, base_svi in base_svis.items():
            curr_svi = curr_svis.get(name)
            if not curr_svi:
                svi_mismatches.append(f"Interface `{name}` is missing entirely.")
            elif curr_svi.get("status") != base_svi.get("status"):
                svi_mismatches.append(
                    f"Interface `{name}` status is `{curr_svi.get('status')}` (Expected: `{base_svi.get('status')}`)."
                )
            elif curr_svi.get("ip_address") != base_svi.get("ip"):
                svi_mismatches.append(
                    f"Interface `{name}` IP is `{curr_svi.get('ip_address')}` (Expected: `{base_svi.get('ip')}`)."
                )

        if svi_mismatches:
            lines.append("❌ **SVI/L3 Mismatches**:")
            for mismatch in svi_mismatches:
                lines.append(f"  * {mismatch}")
            device_failures += 1
        else:
            lines.append("✓ **SVI/L3 Interfaces**: All baseline L3 interfaces and IPs match.")

        # 3. Compare Neighbors (CDP/LLDP)
        base_neighbors = base_state.get("neighbors", [])
        curr_neighbors = current_dev.get("neighbors", [])

        missing_neighbors = []
        for bn in base_neighbors:
            match_found = False
            b_remote = bn.get("remote_device", "").split(".")[0].lower()
            b_local_port = normalize_interface_name(bn.get("local_port", ""))

            for cn in curr_neighbors:
                c_remote = cn.get("remote_device", "").split(".")[0].lower()
                c_local_port = normalize_interface_name(cn.get("local_port", ""))
                if b_remote == c_remote and b_local_port == c_local_port:
                    match_found = True
                    break
            if not match_found:
                missing_neighbors.append(
                    f"Port `{bn.get('local_port')}` has lost connection to `{bn.get('remote_device')}` (Port: `{bn.get('remote_port')}`)."
                )

        if missing_neighbors:
            lines.append(
                f"❌ **Neighbor/Uplink Mismatches**: Lost neighbor adjacencies on {len(missing_neighbors)} ports:"
            )
            for mismatch in missing_neighbors:
                lines.append(f"  * {mismatch}")
            device_failures += 1
        else:
            lines.append("✓ **CDP/LLDP Neighbor Adjacencies**: All baseline neighbors are present.")

        # 4. Compare Routing table prefixes
        base_routes = set(base_state.get("routes", []))
        curr_routes = set()
        for r in current_dev.get("routes", []):
            details = get_route_details(r)
            if details["subnet"] and details["subnet"] != "Unknown":
                curr_routes.add(details["subnet"])

        missing_routes = base_routes - curr_routes
        if missing_routes:
            lines.append(
                f"❌ **Routing Prefix Mismatches**: {len(missing_routes)} routes present in the baseline are missing:"
            )
            for r in sorted(list(missing_routes)):
                lines.append(f"  * Prefix: `{r}`")
            device_failures += 1
        else:
            lines.append("✓ **Routing Table**: All baseline route prefixes are learned.")

        if device_failures > 0:
            lines.append(
                f"\n⚠️ **Verification Summary**: {device_failures} state verification checks failed for switch **{host_base}**."
            )
            total_failures += 1
        else:
            lines.append(f"\n✓ **Verification Summary**: Switch **{host_base}** passed all state verification checks.")
        lines.append("")

    lines.append("---")
    if total_failures > 0:
        lines.append(f"# ❌ Verification Verdict: FAILED ({total_failures} switches failed validation checks)")
    else:
        lines.append("# ✓ Verification Verdict: PASSED (All switches match their baseline states)")

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"\n[+] Post-Migration Verification Report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating verification report: {e}")


def _render_blueprint_header_and_toc(scope: str, dns_domain: str, timestamp: str, total_nodes: int) -> list[str]:
    """Render the blueprint title, scope metadata table, and table of contents."""
    lines = [
        "# Network Migration Analysis Blueprint & Engineering Cutover Dossier",
        "",
        "> **Executive Overview**: High-level discovery readiness, cutover risk scorecard, hardware/L2/L3 summaries, "
        "and clickable links to all breakout reports and CSV matrices compiled from strictly read-only telemetry.",
        "",
        "| Attribute | Migration Scope Value |",
        "| :--- | :--- |",
        f"| **Migration Target Scope** | `{scope}` |",
    ]
    if dns_domain:
        lines.append(f"| **Detected DNS Domain** | `{dns_domain}` |")
    lines.extend(
        [
            f"| **Discovery Execution Timestamp** | `{timestamp}` |",
            f"| **Total Discovered Infrastructure Nodes** | `{total_nodes}` |",
            "| **Read-Only Discovery Invariant** | Strictly Enforced (Zero Control-Plane Blast Radius) |",
            "",
            "---",
            "",
            "## Table of Contents",
            "1. [Executive Summary & Current Hardware Estate](#1-executive-summary--current-hardware-estate)",
            "2. [Physical Layer 1/2 Cabling, Optics & MTU Matrix](#2-physical-layer-12-cabling-optics--mtu-matrix)",
            "3. [Power over Ethernet (PoE) Budget & Power Supply Sizing](#3-power-over-ethernet-poe-budget--power-supply-sizing)",
            "4. [Layer 2 VLANs, 802.1Q Trunks & Native VLAN Map](#4-layer-2-vlans-8021q-trunks--native-vlan-map)",
            "5. [DHCP Relay & IP Helper Addresses (Migration Critical)](#5-dhcp-relay--ip-helper-addresses-migration-critical)",
            "6. [Spanning Tree (STP) & Loop Prevention Plan](#6-spanning-tree-stp--loop-prevention-plan)",
            "7. [First-Hop Redundancy Protocols (FHRP) & Gateway Migration](#7-first-hop-redundancy-protocols-fhrp--gateway-migration)",
            "8. [Layer 3 Subnets, Routing Boundaries & WAN Egress](#8-layer-3-subnets-routing-boundaries--wan-egress)",
            "9. [Security, Access Control Lists & NAT Policies](#9-security-access-control-lists--nat-policies)",
            "10. [Infrastructure Services (DNS, NTP, Syslog, SNMP, AAA)](#10-infrastructure-services-dns-ntp-syslog-snmp-aaa)",
            "11. [Proprietary Feature De-risking & Protocol Translation](#11-proprietary-feature-de-risking--protocol-translation)",
            "12. [Maintenance Window Cutover Runbook & Rollback Plan](#12-maintenance-window-cutover-runbook--rollback-plan)",
        ]
    )
    return lines


def _collect_discovery_readiness_metrics(
    unique_devs: dict,
    failed_hosts_count: int = 0,
    non_infra_failed_count: int = 0,
) -> dict:
    """Compute discovery confidence, L2 link accuracy, and SPOF/blocker flags from crawled devices."""
    lldp_enabled = 0
    lldp_unknown = 0
    lldp_missing: list[tuple[str, str, str]] = []
    cdp_enabled = 0
    total_nbrs = 0
    direct_nbrs = 0
    mac_inferred_nbrs = 0
    passthrough_nbrs = 0
    l3_wan_inferred_nbrs = 0
    passthrough_notes: list[str] = []
    high_poe: list[str] = []
    gw_devs: list[str] = []
    fhrp_total = 0
    total_ports = 0
    up_ports = 0

    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        persona = (dev.get("device_persona") or dev.get("device_type") or "").lower()
        dp = dev.get("discovery_protocols") or {}
        lldp_st = str(dp.get("lldp", "unknown") or "unknown").strip().lower()
        cdp_st = str(dp.get("cdp", "unsupported") or "unsupported").strip().lower()
        nbrs = dev.get("neighbors") or []
        if lldp_st == "enabled":
            lldp_enabled += 1
        elif lldp_st in ("disabled", "not_installed") or (lldp_st == "unknown" and not nbrs and cdp_st != "enabled"):
            reason = dp.get("notes") or (
                "No LLDP/CDP neighbors learned and protocol status unknown" if lldp_st == "unknown" else ""
            )
            lldp_missing.append((hostname, lldp_st, reason))
        else:
            # lldp_st == "unknown" with neighbors present or CDP-only — never silently treat as confirmed LLDP-enabled
            lldp_unknown += 1
        if cdp_st == "enabled":
            cdp_enabled += 1

        total_nbrs += len(nbrs)
        for n in nbrs:
            acc = str(n.get("l2_accuracy") or "").strip().lower()
            if acc == "mac_inferred":
                mac_inferred_nbrs += 1
            elif acc in ("virtual_passthrough", "multi_neighbor_port"):
                passthrough_nbrs += 1
                note = f"**{hostname}** (`{n.get('local_port', '')}` ↔ **{n.get('remote_device', '')}**): {n.get('l2_accuracy_note', acc)}"
                if note not in passthrough_notes:
                    passthrough_notes.append(note)
            elif acc in ("wan_carrier_arp_route", "l3_next_hop_egress"):
                l3_wan_inferred_nbrs += 1
            else:
                direct_nbrs += 1

        poe = dev.get("poe") or {}
        tot_w = float(poe.get("total_power_watts") or 0.0)
        used_w = float(poe.get("used_power_watts") or 0.0)
        if tot_w > 0 and (used_w / tot_w) > 0.80:
            high_poe.append(f"**{hostname}** ({used_w:.1f}W / {tot_w:.1f}W, {used_w / tot_w * 100:.1f}%)")

        if persona in ("firewall", "router"):
            gw_devs.append(hostname)
        fhrp_total += len(dev.get("fhrp") or [])

        ints_detail = dev.get("interfaces_detail") or {}
        total_ports += len(ints_detail)
        up_ports += sum(1 for s in ints_detail.values() if str((s or {}).get("status", "")).lower() == "up")

    single_gw_spof = len(gw_devs) == 1 and fhrp_total == 0
    if failed_hosts_count > 0:
        gate = "BLOCKED"
    elif lldp_missing or lldp_unknown or mac_inferred_nbrs or passthrough_nbrs or high_poe or single_gw_spof:
        gate = "READY WITH CAVEATS"
    else:
        gate = "READY"

    return {
        "gate": gate,
        "failed_hosts_count": failed_hosts_count,
        "non_infra_failed_count": non_infra_failed_count,
        "lldp_enabled": lldp_enabled,
        "lldp_unknown": lldp_unknown,
        "lldp_missing": lldp_missing,
        "cdp_enabled": cdp_enabled,
        "total_nbrs": total_nbrs,
        "direct_nbrs": direct_nbrs,
        "mac_inferred_nbrs": mac_inferred_nbrs,
        "passthrough_nbrs": passthrough_nbrs,
        "l3_wan_inferred_nbrs": l3_wan_inferred_nbrs,
        "passthrough_notes": passthrough_notes,
        "high_poe": high_poe,
        "gw_devs": gw_devs,
        "single_gw_spof": single_gw_spof,
        "total_ports": total_ports,
        "up_ports": up_ports,
    }


def _render_blueprint_executive_summary_section(
    unique_devs: dict,
    failed_hosts_count: int = 0,
    non_infra_failed_count: int = 0,
) -> list[str]:
    """Render Section 1: Executive Summary, Deliverables Index, Risks & Hardware Estate."""
    metrics = _collect_discovery_readiness_metrics(
        unique_devs,
        failed_hosts_count=failed_hosts_count,
        non_infra_failed_count=non_infra_failed_count,
    )
    total_nodes = len(unique_devs)
    gate_badge = (
        f"❌ **{metrics['gate']}**"
        if metrics["gate"] == "BLOCKED"
        else (f"⚠️ **{metrics['gate']}**" if metrics["gate"] == "READY WITH CAVEATS" else "✅ **READY**")
    )

    if total_nodes > 0 and metrics["lldp_enabled"] == total_nodes and not metrics["lldp_missing"]:
        lldp_assess = "✓ Full protocol coverage"
    elif metrics["lldp_missing"] and metrics["lldp_unknown"]:
        lldp_assess = (
            f"⚠ {len(metrics['lldp_missing'])} device(s) lack LLDP; "
            f"{metrics['lldp_unknown']} device(s) LLDP status unknown"
        )
    elif metrics["lldp_missing"]:
        lldp_assess = f"⚠ {len(metrics['lldp_missing'])} device(s) lack LLDP"
    elif metrics["lldp_unknown"]:
        lldp_assess = f"⚠ {metrics['lldp_unknown']} device(s) LLDP status unknown (neighbors inferred or CDP-only)"
    else:
        lldp_assess = "⚠ No crawled devices to evaluate"

    wan_l3_frag = f" / `{metrics['l3_wan_inferred_nbrs']}` WAN/L3-egress" if metrics["l3_wan_inferred_nbrs"] else ""
    if metrics["mac_inferred_nbrs"] or metrics["passthrough_nbrs"] or metrics["l3_wan_inferred_nbrs"]:
        adj_assess = "⚠ Verify dashed/inferred links in L2 diagram"
    elif metrics["direct_nbrs"] > 0:
        adj_assess = "✓ Direct cabling verified"
    else:
        adj_assess = "⚠ No L2 neighbor adjacencies observed"
    non_infra_note = (
        f" (`{non_infra_failed_count}` passive/unsupported non-infra hosts)" if non_infra_failed_count > 0 else ""
    )
    if metrics["failed_hosts_count"] == 0:
        scope_assess = (
            f"✓ Complete infra scope ({non_infra_failed_count} passive/unsupported non-infra hosts in failed_hosts.json)"
            if non_infra_failed_count > 0
            else "✓ Complete scope"
        )
    else:
        scope_assess = f"⚠ Review {metrics['failed_hosts_count']} infra target(s) in failed_hosts.json"

    lines = [
        "",
        "---",
        "",
        "## 1. Executive Summary & Current Hardware Estate",
        "",
        "### 1.1 Discovery Confidence & Cutover Readiness Scorecard",
        "",
        "| Readiness Indicator | Observed Value | Assessment |",
        "| :--- | :--- | :--- |",
        f"| **Cutover Readiness Gate** | {gate_badge} | Based on crawl coverage, L2 visibility & SPOF checks |",
        f"| **Crawled Infrastructure Nodes** | `{total_nodes}` succeeded / `{metrics['failed_hosts_count']}` infra failed{non_infra_note} | {scope_assess} |",
        f"| **L2 Protocol Visibility (LLDP / CDP)** | `{metrics['lldp_enabled']}/{total_nodes}` LLDP enabled (`{metrics['cdp_enabled']}` CDP) | {lldp_assess} |",
        f"| **L2 Adjacency Confidence** | `{metrics['direct_nbrs']}` direct / `{metrics['mac_inferred_nbrs']}` MAC-inferred / `{metrics['passthrough_nbrs']}` passthrough{wan_l3_frag} | {adj_assess} |",
        f"| **Total Interface Footprint** | `{metrics['up_ports']}` up / `{metrics['total_ports']}` total interfaces | See `migration_cabling_matrix.csv` |",
        "",
        "### 1.2 Deliverables & Breakout Reports Index",
        "",
        "| Deliverable | Purpose | Audience |",
        "| :--- | :--- | :--- |",
        "| [L2_network_diagrams.md](./L2_network_diagrams.md) | Physical L2 Mermaid graph, wireless AP overlay & per-device LLDP/CDP audit | Managers & Engineers |",
        "| [L3_network_diagrams.md](./L3_network_diagrams.md) | Layer 3 routed topology, subnets & CIDR conflict audit | Managers & Engineers |",
        "| [topology_interactive.html](./topology_interactive.html) | Interactive offline HTML topology viewer (collapsible tree, search, site filter & port inspector) | Managers & Engineers |",
        "| [manual_followup_report.md](./manual_followup_report.md) | Consolidated manual follow-up checklist (unauth, command mismatches, unmanaged switches, PoE, non-AP trunks) | Field & Network Engineers |",
        "| [cutover_runbook.md](./cutover_runbook.md) | Standalone maintenance-window execution sequence, T-minus checklist & rollback plan | Cutover Lead |",
        "| [trunk_vlan_audit.md](./trunk_vlan_audit.md) | 802.1Q trunk symmetry & native VLAN mismatch audit | Switching Engineer |",
        "| [net_docu_crawler_live_report.md](./net_docu_crawler_live_report.md) | Full per-device interface telemetry, errors & operational state | Engineers |",
        "| [cisco_to_target_translation.md](./cisco_to_target_translation.md) | Protocol & CLI migration translation reference | Engineers |",
        "| [asset_inventory.csv](./asset_inventory.csv) / [bom_hardware_sizing.csv](./bom_hardware_sizing.csv) | Hardware serials, firmware & vendor-neutral port/PoE sizing BOM | Procurement & PM |",
        "| [migration_cabling_matrix.csv](./migration_cabling_matrix.csv) / [port_mac_endpoint_mapping.csv](./port_mac_endpoint_mapping.csv) | Complete port-by-port patch matrix & learned endpoint MAC mapping | Field Cabling Techs |",
        "| [validate_cutover.sh](./validate_cutover.sh) / [validate_cutover.ps1](./validate_cutover.ps1) | Automated pre/post-cutover reachability & DNS smoke tests | Cutover Lead |",
        "| [net_docu_crawler_dataset.json](./net_docu_crawler_dataset.json) / [failed_hosts.json](./failed_hosts.json) | Canonical raw JSON dataset & failed target retry list | Automation / Audit |",
        "",
        "### 1.3 Cutover Risks, Blind Spots & Single Points of Failure (SPOF)",
        "",
    ]

    risks: list[str] = []
    if metrics["failed_hosts_count"] > 0:
        risks.append(
            f"- ❌ **Unreachable / Failed Targets ({metrics['failed_hosts_count']})**: Retry failed devices in [failed_hosts.json](./failed_hosts.json) before freezing BOM or cabling."
        )
    for host, st, note in metrics["lldp_missing"]:
        detail = f" ({note})" if note else ""
        risks.append(f"- ⚠️ **Missing L2 Discovery on `{host}`** (`lldp={st}`){detail}")
    for pnote in metrics["passthrough_notes"]:
        risks.append(f"- ⚠️ **L2 Passthrough / Multi-Neighbor Port**: {pnote}")
    if metrics["single_gw_spof"]:
        risks.append(
            f"- ⚠️ **Single Gateway / Firewall SPOF**: Only `{metrics['gw_devs'][0]}` discovered with zero FHRP (HSRP/VRRP/CARP) redundancy."
        )
    for hpoe in metrics["high_poe"]:
        risks.append(f"- ⚠️ **High PoE Utilization (>80%)**: {hpoe}")

    if risks:
        lines.extend(risks)
    else:
        lines.append("✓ **No critical cutover blockers, failed hosts, or L2 discovery blind spots detected.**")

    lines.extend(
        [
            "",
            "### 1.4 Current Hardware Estate & Port Capacity",
            "",
            "| Hostname | Management IP | Vendor | Model | Serial Number | Firmware OS | Persona | Port Capacity | Role / Guidance |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        vendor = dev.get("vendor", "Unknown")
        model = dev.get("model", "Unknown")
        serial = dev.get("serial", "Unknown")
        firmware = dev.get("firmware", "Unknown")
        persona = dev.get("device_persona", dev.get("device_type", "switch"))
        ints = dev.get("interfaces_detail") or {}
        up_cnt = sum(1 for s in ints.values() if str((s or {}).get("status", "")).lower() == "up")
        port_cap = f"{up_cnt}/{len(ints)} up" if ints else "N/A"

        if persona == "firewall":
            target_rec = "Security Gateway / Perimeter Firewall"
        elif persona == "router":
            target_rec = "L3 Router / Transit Gateway"
        elif persona == "ap":
            target_rec = "Wireless Access Point"
        else:
            target_rec = f"Managed L2/L3 Switch ({len(ints)} ports)"

        lines.append(
            f"| **{hostname}** | `{ip}` | {vendor} | `{model}` | `{serial}` | `{firmware}` | `{persona}` | `{port_cap}` | {target_rec} |"
        )
    return lines


def _collect_blueprint_cabling_and_mtu(unique_devs: dict) -> tuple[list[str], list[tuple], int]:
    """Collect cabling matrix rows and detect cross-device MTU mismatches without fabricating defaults."""
    mtu_mismatches = []
    cabling_rows = []
    verified_mtu_pairs = 0

    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        ints_detail = dev.get("interfaces_detail", {})
        cfg = dev.get("raw_config", "")

        channel_map = {}
        if cfg:
            for cg_m in re.finditer(r"interface\s+(\S+)[\s\S]*?channel-group\s+(\d+)", cfg, re.IGNORECASE):
                channel_map[normalize_interface_name(cg_m.group(1))] = f"Po{cg_m.group(2)}"

        neighbor_map = {
            normalize_interface_name(nbr.get("local_port", "")): nbr
            for nbr in dev.get("neighbors", [])
            if normalize_interface_name(nbr.get("local_port", ""))
        }

        for port_name, stats in sorted(ints_detail.items()):
            norm_port = normalize_interface_name(port_name)
            cport = (dev.get("ports") or {}).get(port_name) or {}
            status = stats.get("status", "down")
            speed = stats.get("speed") or "Unknown"
            duplex = stats.get("duplex") or "Unknown"
            raw_mtu = stats.get("mtu") if stats.get("mtu") is not None else cport.get("mtu")
            mtu = int(raw_mtu) if str(raw_mtu or "").isdigit() else None

            if cport.get("optic_part_number"):
                media = f"{cport.get('media') or 'SFP'} ({cport['optic_part_number']})"
            elif cport.get("media"):
                media = cport["media"]
            elif any(p in norm_port.lower() for p in ["xe-", "te", "eth1/", "et-", "mgmt", "10ge"]):
                media = "10GBASE-SR (SFP+ LC)"
            else:
                media = "1000BASE-T (RJ45)"

            nbr = neighbor_map.get(norm_port)
            nbr_host = cport.get("neighbor_hostname") or (
                (nbr.get("remote_device") or "").strip().strip('"').strip("'") if nbr else "Unconnected"
            )
            nbr_port = cport.get("neighbor_port") or (
                normalize_interface_name(nbr.get("remote_port", "")) if nbr else "N/A"
            )
            lag_val = cport.get("lag_id") or channel_map.get(norm_port, "")
            lag_group = lag_val if lag_val and lag_val not in ("none", "unknown") else "None (Standalone)"

            cabling_rows.append(
                f"| **{hostname}** | `{norm_port}` | {media} | {speed} / {duplex} | `{status}` | **{nbr_host}** | `{nbr_port}` | `{lag_group}` |"
            )

            if nbr and nbr_host != "Unconnected" and mtu is not None:
                for _rip, rdev in unique_devs.items():
                    if (rdev.get("hostname") or "").lower().split(".")[0] == nbr_host.lower().split(".")[0]:
                        r_ints = rdev.get("interfaces_detail", {})
                        r_stats = r_ints.get(nbr_port) or r_ints.get(nbr.get("remote_port", ""))
                        if r_stats:
                            r_raw_mtu = r_stats.get("mtu")
                            r_mtu = int(r_raw_mtu) if str(r_raw_mtu or "").isdigit() else None
                            if r_mtu is not None:
                                verified_mtu_pairs += 1
                                if mtu != r_mtu:
                                    mtu_mismatches.append((hostname, norm_port, mtu, nbr_host, nbr_port, r_mtu))

    return cabling_rows, mtu_mismatches, verified_mtu_pairs


def _render_blueprint_cabling_and_mtu_section(unique_devs: dict) -> list[str]:
    """Render Sections 2.1 (Neighbor/Uplink Cabling Summary) and 2.2 (MTU Discrepancy Guard)."""
    cabling_rows, mtu_mismatches, verified_mtu_pairs = _collect_blueprint_cabling_and_mtu(unique_devs)
    connected_rows = [r for r in cabling_rows if "**Unconnected**" not in r]
    up_rows = [r for r in cabling_rows if "| `up` |" in r]
    display_rows = connected_rows if connected_rows else up_rows[:15]

    lines = [
        "",
        "---",
        "",
        "## 2. Physical Layer 1/2 Cabling, Optics & MTU Matrix",
        "",
        "### 2.1 Patch Cabling, Port-Channels & Media Types",
        f"Discovered **{len(cabling_rows)}** total ports (**{len(up_rows)}** `up`, **{len(connected_rows)}** with L2 neighbor links). "
        "Full port-by-port patching is exported in [migration_cabling_matrix.csv](./migration_cabling_matrix.csv); "
        "active neighbor uplinks are summarized below:",
        "",
        "| Source Switch | Source Port | Media / Form Factor | Speed / Duplex | Status | Connected Neighbor | Neighbor Port | LAG / Port-Channel |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if display_rows:
        lines.extend(display_rows[:30])
        if len(display_rows) > 30:
            lines.append(
                f"| ... and {len(display_rows) - 30} additional links in [migration_cabling_matrix.csv](./migration_cabling_matrix.csv) | | | | | | | |"
            )
    else:
        lines.append("| *None* | `N/A` | `N/A` | `N/A` | `N/A` | *No active ports* | `N/A` | `N/A` |")

    lines.extend(["", "### 2.2 MTU Discrepancy & Jumbo Frame Guard"])
    if mtu_mismatches:
        lines.append("> [!WARNING]")
        lines.append("> **CRITICAL MTU MISMATCH DETECTED ACROSS UPLINKS:**")
        for h1, p1, m1, h2, p2, m2 in mtu_mismatches:
            lines.append(
                f"> * **{h1}** (`{p1}`, MTU {m1}) <==> **{h2}** (`{p2}`, MTU {m2}). Mismatched MTUs will cause silent OSPF packet drops or jumbo-frame truncation!"
            )
    elif verified_mtu_pairs > 0:
        lines.append(
            f"✓ **No MTU Mismatches Detected**: Verified consistent MTU across **{verified_mtu_pairs}** inter-device uplink pair(s)."
        )
    else:
        lines.append(
            "⚠️ **MTU Parity Unverified**: No inter-device uplink pair reported explicit MTU telemetry on both ends — verify MTU parity before cutover."
        )
    return lines


def _render_blueprint_optics_section(unique_devs: dict) -> list[str]:
    """Render Section 2.3: Optical Transceiver & Digital Optical Monitoring (DOM) Telemetry."""
    lines = [
        "",
        "### 2.3 Optical Transceiver & Digital Optical Monitoring (DOM) Telemetry",
        "Detailed physical telemetry for pluggable fiber/copper SFP, SFP+, and QSFP transceivers:",
        "",
    ]
    optics_rows = []
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        for opt in dev.get("optics", []):
            port = opt.get("port", "")
            part = opt.get("part_number", "SFP-DOM")
            serial = opt.get("serial", "Unknown")
            form = opt.get("type", "SFP+")
            tx = f"{opt['tx_power_dbm']:.2f} dBm" if opt.get("tx_power_dbm") is not None else "N/A"
            rx = f"{opt['rx_power_dbm']:.2f} dBm" if opt.get("rx_power_dbm") is not None else "N/A"
            temp = f"{opt['temperature_c']:.1f} °C" if opt.get("temperature_c") is not None else "N/A"
            volt = f"{opt['voltage_v']:.2f} V" if opt.get("voltage_v") is not None else "N/A"

            rx_val = opt.get("rx_power_dbm")
            if rx_val is not None:
                if rx_val < -15.0:
                    health = "⚠ High Attenuation (Check Fiber)"
                elif rx_val > -1.0:
                    health = "⚠ Optical Saturation (High RX)"
                else:
                    health = "✓ Optimal Optical Link"
            else:
                health = "DOM Unavailable / Unmonitored"

            optics_rows.append(
                f"| **{hostname}** | `{port}` | `{part}` | `{serial}` | `{form}` | {tx} | {rx} | {temp} | {volt} | {health} |"
            )

    if optics_rows:
        lines.extend(
            [
                "| Switch Hostname | Port | Transceiver Model / Part | Serial Number | Form Factor | TX Power (dBm) | RX Power (dBm) | Temperature (°C) | Voltage (V) | Optical Health Status |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                *optics_rows,
            ]
        )
    else:
        opt_avail = _section_availability_summary(unique_devs, "optics")
        if opt_avail["has_gaps"]:
            gap_hosts = opt_avail["failed_hosts"] + opt_avail["not_collected_hosts"]
            lines.append(
                f"> ⚠️ **Optics / DOM Telemetry Not Collected or Failed** on {len(gap_hosts)}/{opt_avail['total']} device(s) "
                f"({', '.join(gap_hosts[:8])}); cannot verify pluggable SFP/QSFP inventory."
            )
        else:
            lines.append(
                "> No pluggable SFP/SFP+/QSFP optical transceivers or DOM readings were reported on crawled devices (verify copper/fixed PHY manually if uplinks are fiber)."
            )
    return lines


def _render_blueprint_mac_mapping_section(unique_devs: dict) -> list[str]:
    """Render Section 2.4: Port-to-Endpoint MAC Address Mapping & Access Layer Topology."""
    priority_rows = []
    other_rows = []
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        for entry in dev.get("mac_table", []):
            port = entry.get("interface", "")
            vlan = str(entry.get("vlan", "1"))
            mac = entry.get("mac", "")
            vendor = entry.get("vendor", "Unknown")
            v_lower = vendor.lower()
            if any(ap in v_lower for ap in ["aruba", "ubiquiti", "ruckus", "cisco", "mist"]):
                role = "Access Point"
                priority_rows.append(f"| **{hostname}** | `{port}` | `VLAN {vlan}` | `{mac}` | {vendor} | {role} |")
            elif any(srv in v_lower for srv in ["vmware", "dell", "hp", "supermicro", "qemu", "proxmox"]):
                role = "Server / Hypervisor"
                priority_rows.append(f"| **{hostname}** | `{port}` | `VLAN {vlan}` | `{mac}` | {vendor} | {role} |")
            else:
                role = "Workstation / Client"
                other_rows.append(f"| **{hostname}** | `{port}` | `VLAN {vlan}` | `{mac}` | {vendor} | {role} |")

    mac_rows = priority_rows + other_rows
    lines = [
        "",
        "### 2.4 Port-to-Endpoint MAC Address Mapping & Access Layer Topology",
        f"Discovered **{len(mac_rows)}** learned MAC forwarding entries across switches "
        "(complete table exported to [port_mac_endpoint_mapping.csv](./port_mac_endpoint_mapping.csv)). "
        "Infrastructure/AP/Server sample below:",
        "",
        "| Switch Hostname | Port | VLAN | MAC Address | OUI Vendor | Resolved Device Role |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if mac_rows:
        lines.extend(mac_rows[:10])
        if len(mac_rows) > 10:
            lines.append(
                f"| ... and {len(mac_rows) - 10} additional learned MAC endpoints in [port_mac_endpoint_mapping.csv](./port_mac_endpoint_mapping.csv) | | | | | |"
            )
    else:
        lines.append("| *None* | `N/A` | `N/A` | *No MAC forwarding entries learned* | `N/A` | `N/A` |")
    return lines


def _render_blueprint_poe_section(unique_devs: dict) -> list[str]:
    """Render Section 3: Power over Ethernet (PoE) Budget & Power Supply Sizing."""
    lines = [
        "",
        "---",
        "",
        "## 3. Power over Ethernet (PoE) Budget & Power Supply Sizing",
        "",
        "When replacing access switches, new power supplies must support the concurrent wattage demanded by APs, IP phones, and cameras:",
        "",
    ]
    poe_rows = []
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        poe = dev.get("poe", {}) or {}
        tot = float(poe.get("total_power_watts", 0.0) or 0.0)
        used = float(poe.get("used_power_watts", 0.0) or 0.0)
        rem = float(poe.get("available_power_watts", 0.0) or 0.0)
        persona = str(dev.get("device_persona") or dev.get("device_type") or "").lower()
        poe_cs = _device_section_status(dev, "poe")

        if not (persona == "switch" or tot > 0 or used > 0):
            continue
        if poe_cs in ("command_failed", "parse_failed", "not_collected") and tot == 0.0 and used == 0.0:
            poe_rows.append(
                f"| **{hostname}** | Collection Failed (`{poe_cs}`) | Unknown | Unknown | N/A | ⚠️ Verify PoE Telemetry Manually |"
            )
        elif poe.get("poe_supported") is False and tot == 0.0 and used == 0.0:
            poe_rows.append(f"| **{hostname}** | Non-PoE Switch | 0.0W | N/A | N/A | Non-PoE Core / Fiber SKU |")
        elif poe.get("budget_unreported") and used > 0.0:
            deliv_cnt = poe.get("poe_delivering_ports", 0)
            poe_rows.append(
                f"| **{hostname}** | Unreported by CLI | {used:.1f}W ({deliv_cnt} active) | Unknown | N/A | Verify Chassis PSU Budget (Draw: {used:.1f}W) |"
            )
        elif tot == 0.0 and used == 0.0:
            poe_rows.append(
                f"| **{hostname}** | Unknown | Unknown | Unknown | N/A | Unknown (Verify PSU / PoE Budget) |"
            )
        elif tot == 0.0 and used > 0.0:
            poe_rows.append(
                f"| **{hostname}** | 0.0W | {used:.1f}W | N/A | N/A | ⚠️ Conflict: 0W budget with active draw |"
            )
        else:
            pct = (used / tot * 100.0) if tot > 0 else 0.0
            req_w = max(tot, used * 1.25)
            psu_rec = f"{rem:.1f}W headroom ({100.0 - pct:.1f}% free); size replacement PSU >= {int(req_w)}W"
            poe_rows.append(f"| **{hostname}** | {tot:.1f}W | {used:.1f}W | {rem:.1f}W | {pct:.1f}% | {psu_rec} |")

    if poe_rows:
        lines.extend(
            [
                "| Switch Hostname | Total PoE Capacity (W) | Consumed PoE Wattage (W) | Remaining Budget (W) | PoE Utilization | PSU Sizing Recommendation |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
                *poe_rows,
            ]
        )
    else:
        lines.append(
            "> No Layer 2 PoE-capable switches or active PoE draw were discovered in the crawled dataset (not applicable to Layer 3-only nodes)."
        )
    return lines


def _extract_valid_vlan_id_from_iface(iface_name: str, dev_vlans: dict) -> tuple[str, str]:
    """Resolve a valid 802.1Q VLAN ID (1..4094) and name from an interface name or dev['vlans']."""
    if_clean = str(iface_name or "").strip()
    if_low = if_clean.lower()
    # 1. Explicit match in dev["vlans"] by svi_interface or VLAN name
    for vid_k, vinfo in (dev_vlans or {}).items():
        vid_s = str(vid_k).strip()
        if not (vid_s.isdigit() and 1 <= int(vid_s) <= 4094):
            continue
        if isinstance(vinfo, dict):
            svi = str(vinfo.get("svi_interface") or "").strip().lower()
            vname = str(vinfo.get("name") or "").strip()
            if (svi and svi == if_low) or (vname and vname.lower() == if_low):
                return vid_s, vname
    # 2. Interface syntax patterns (Vlan10, vlan.10, vtnet0_vlan10, eth0.10, Gi0/0.10, bvi10, irb.10)
    m_v = re.search(r"(?:^|[_.\-])(?:vlan|vl|irb|bvi)[_.\-\s]*0*(\d+)$", if_low)
    if not m_v:
        m_v = re.search(r"\.0*(\d+)$", if_low)
    if m_v:
        cand = int(m_v.group(1))
        if 1 <= cand <= 4094:
            vid_s = str(cand)
            vinfo = (dev_vlans or {}).get(vid_s)
            vname = str(vinfo.get("name") or "") if isinstance(vinfo, dict) else ""
            return vid_s, vname
    return "", ""


def _render_blueprint_vlan_and_trunk_section(unique_devs: dict) -> list[str]:
    """Render Section 4: Layer 2 VLANs, 802.1Q Trunks & Native VLAN Map (both L3 SVIs & L2-only VLANs)."""
    from net_docu_crawler.correlator import build_l3_svi_table

    lines = [
        "",
        "---",
        "",
        "## 4. Layer 2 VLANs, 802.1Q Trunks & Native VLAN Map",
        "",
        "This authoritative map defines every VLAN ID, broadcast domain, gateway IP, and trunk path across the campus:",
        "",
        "| Site | Source Device | VLAN ID | VLAN Name | SVI / IRB | Gateway IP | Subnet / CIDR Prefix | DHCP Relays |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    dev_by_host = {(d.get("hostname") or ip): d for ip, d in unique_devs.items()}
    svi_rows = build_l3_svi_table(list(unique_devs.values()))
    vlan_rows = []
    seen_dev_vlans: set[tuple[str, str]] = set()

    for sr in svi_rows:
        src_host = sr.get("source_device") or ""
        primary_ip = str(sr.get("primary_ip") or "").strip()
        if primary_ip.startswith(("127.", "128.0.")):
            continue
        dev = dev_by_host.get(src_host) or {}
        dev_vlans = dev.get("vlans") or {}
        svi_if = str(sr.get("svi_interface") or "")

        vid = str(sr.get("vlan_id") or "").strip()
        vname = str(sr.get("vlan_name") or "").strip()
        if not vid or vid == "0" or (vid.isdigit() and not (1 <= int(vid) <= 4094)):
            vid, resolved_name = _extract_valid_vlan_id_from_iface(svi_if, dev_vlans)
            if not vname and resolved_name:
                vname = resolved_name
        elif not vname and vid in dev_vlans and isinstance(dev_vlans[vid], dict):
            vname = str(dev_vlans[vid].get("name") or "")

        prefix_cidr = str(sr.get("prefix_cidr") or "").strip()
        # Prevent bare management IPs (e.g. Aruba AP br0 without mask) from displaying fabricated /32
        if prefix_cidr.endswith("/32"):
            for l3i in dev.get("l3_interfaces") or []:
                if str(l3i.get("interface") or "") == svi_if:
                    raw_ip_s = str(l3i.get("ip_address") or "").strip()
                    if "/" not in raw_ip_s and " " not in raw_ip_s:
                        prefix_cidr = "Unknown"
                    break

        if vid:
            seen_dev_vlans.add((src_host, vid))

        site_lbl = sr.get("site_code") or dev.get("site_code") or "-"
        vid_lbl = f"**{vid}**" if vid else "-"
        vname_lbl = f"`{vname}`" if vname else "-"
        rel_lbl = ", ".join(f"`{r}`" for r in (sr.get("dhcp_relays") or [])) or "None"
        vlan_rows.append(
            f"| {site_lbl} | **{src_host}** | {vid_lbl} | {vname_lbl} | `{svi_if}` | "
            f"`{primary_ip}` | `{prefix_cidr or 'Unknown'}` | {rel_lbl} |"
        )

    # Append L2-only VLANs from dev["vlans"] not already represented in an L3 SVI row
    for ip, dev in unique_devs.items():
        host = dev.get("hostname") or ip
        site_lbl = dev.get("site_code") or "-"
        for vid_k in sorted((dev.get("vlans") or {}).keys(), key=lambda x: int(x) if str(x).isdigit() else 99999):
            vid_s = str(vid_k).strip()
            if not (vid_s.isdigit() and 1 <= int(vid_s) <= 4094):
                continue
            if (host, vid_s) in seen_dev_vlans:
                continue
            vinfo = dev["vlans"][vid_k]
            vname = str(vinfo.get("name") if isinstance(vinfo, dict) else vinfo or "").strip()
            vname_lbl = f"`{vname}`" if vname else "-"
            vlan_rows.append(
                f"| {site_lbl} | **{host}** | **{vid_s}** | {vname_lbl} | *(L2 Only)* | `-` | `-` | None |"
            )
            seen_dev_vlans.add((host, vid_s))

    if not vlan_rows:
        v_avail = _section_availability_summary(unique_devs, "vlans", fallback_section="interfaces")
        if v_avail["has_gaps"]:
            gap_hosts = v_avail["failed_hosts"] + v_avail["not_collected_hosts"]
            vlan_rows.append(
                f"| - | *Collection Failed* | - | *⚠️ VLAN/SVI data not collected or failed on {len(gap_hosts)}/{v_avail['total']} device(s)* | - | `N/A` | `N/A` | - |"
            )
        else:
            vlan_rows.append("| - | *None* | - | *No L2 VLAN or L3 SVI mappings parsed* | - | `N/A` | `N/A` | - |")

    lines.extend(vlan_rows)
    lines.extend(
        _build_trunk_audit_markdown_section(unique_devs, heading="### 4.1 Trunk VLAN Mismatch & L2 Symmetry Audit")
    )
    return lines


def _render_blueprint_dhcp_relay_section(unique_devs: dict) -> list[str]:
    """Render Section 5: DHCP Relay & IP Helper Addresses (Migration Critical)."""
    lines = [
        "",
        "---",
        "",
        "## 5. DHCP Relay & IP Helper Addresses (Migration Critical)",
        "",
        "> [!IMPORTANT]",
        "> **CRITICAL PRE-CUTOVER GATEWAY CHECK**: Missing `ip helper-address` / DHCP relay configurations on newly deployed SVIs "
        "is the primary cause of post-cutover outages. Ensure every relay IP below is provisioned on target replacement gateways:",
        "",
        "| Source Device | Interface / VLAN | Configured DHCP Relay / Helper IP | Target DHCP Server / Scope | Audit Status |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    has_relays = False
    local_pool_hosts: list[str] = []
    total_local_pools = 0
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        dhcp_d = dev.get("dhcp") or {}
        pools = dhcp_d.get("pools", []) or []
        if pools:
            total_local_pools += len(pools)
            local_pool_hosts.append(f"{hostname} ({len(pools)})")
        relays = dhcp_d.get("relays", []) or []
        if relays:
            has_relays = True
            for rel in relays:
                r_intf = rel.get("interface") or "Unknown"
                r_ip = rel.get("helper_ip") or ""
                if r_ip:
                    lines.append(f"| **{hostname}** | `{r_intf}` | `{r_ip}` | Discovered DHCP Relay | ✓ Provisioned |")
        else:
            for r_ip in (dev.get("services") or {}).get("dhcp_relays", []) or []:
                has_relays = True
                lines.append(
                    f"| **{hostname}** | `Unknown (Config Services)` | `{r_ip}` | Discovered DHCP Relay | ✓ Provisioned |"
                )

    dhcp_avail = _section_availability_summary(unique_devs, "dhcp", fallback_section="running_config")
    if not has_relays:
        if dhcp_avail["has_gaps"]:
            gap_hosts = dhcp_avail["failed_hosts"] + dhcp_avail["not_collected_hosts"]
            lines.append(
                f"| *Incomplete* | *DHCP data not collected / failed on {len(gap_hosts)}/{dhcp_avail['total']} device(s)* | "
                f"`N/A` | `{', '.join(gap_hosts[:5])}` | ⚠️ Data Not Collected / Collection Failed |"
            )
        elif total_local_pools > 0:
            lines.append(
                f"| *Local DHCP* | *0 relays; {total_local_pools} local DHCP pool(s) discovered* | "
                f"`N/A` | {', '.join(local_pool_hosts[:5])} | ℹ️ Local DHCP Server Active |"
            )
        else:
            lines.append(
                "| *None* | *No DHCP relay / ip helper-address entries discovered* | `N/A` | `N/A` | None Configured |"
            )
    elif dhcp_avail["has_gaps"]:
        gap_hosts = dhcp_avail["failed_hosts"] + dhcp_avail["not_collected_hosts"]
        lines.append(
            f"| *Partial* | *DHCP config missing on {len(gap_hosts)}/{dhcp_avail['total']} device(s)* | "
            f"`N/A` | `{', '.join(gap_hosts[:5])}` | ⚠️ Verify Uncollected Devices |"
        )
    return lines


def _render_blueprint_stp_section(unique_devs: dict) -> list[str]:
    """Render Section 6: Spanning Tree (STP) & Loop Prevention Plan."""
    lines = [
        "",
        "---",
        "",
        "## 6. Spanning Tree (STP) & Loop Prevention Plan",
        "",
    ]
    stp_rows = []
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        stp = dev.get("stp", {}) or {}
        is_root = bool(stp.get("is_root", False))
        persona = str(dev.get("device_persona") or dev.get("device_type") or "").lower()
        if not (persona == "switch" or stp.get("enabled")):
            continue

        stp_cs = _device_section_status(dev, "stp")
        proto = stp.get("protocol") or "Unknown"
        prio = stp.get("bridge_priority") or "Unknown"
        if stp_cs in ("command_failed", "parse_failed", "not_collected") and not stp.get("enabled"):
            root_label = f"⚠️ Collection Failed / Not Collected (`{stp_cs}`)"
        elif not stp.get("enabled"):
            root_label = "Disabled (STP Off)"
        elif stp.get("is_verified_campus_root"):
            root_label = f"👑 **VERIFIED CAMPUS ROOT** ({stp.get('root_bridge', '')})"
        elif stp.get("root_scope") == "isolated_self_root":
            root_label = f"⚠️ Isolated Self-Root ({stp.get('root_bridge', '')})"
        elif is_root and (stp.get("root_bridge") or stp.get("vlans")):
            root_label = "👑 **ROOT BRIDGE**"
        elif is_root:
            root_label = "⚠️ Unverified Root (Missing Bridge ID)"
        else:
            rb = stp.get("root_bridge") or "Unknown"
            rp = stp.get("root_port") or "N/A"
            root_label = f"Non-Root (Root: {rb}, Port: {rp})"

        # Merge edge & BPDU guard counts across both port_profiles (bool) and correlated ports ("enabled")
        edge_ports: set[str] = set()
        bpdu_ports: set[str] = set()
        for pname, v in (dev.get("port_profiles") or {}).items():
            if not isinstance(v, dict):
                continue
            np = normalize_interface_name(pname)
            if v.get("stp_edge") is True or str(v.get("stp_edge") or "").lower() == "enabled":
                edge_ports.add(np)
            if v.get("bpdu_guard") is True or str(v.get("bpdu_guard") or "").lower() == "enabled":
                bpdu_ports.add(np)
        for pname, v in (dev.get("ports") or {}).items():
            if not isinstance(v, dict):
                continue
            np = normalize_interface_name(pname)
            if v.get("stp_edge") is True or str(v.get("stp_edge") or "").lower() == "enabled":
                edge_ports.add(np)
            if v.get("bpdu_guard") is True or str(v.get("bpdu_guard") or "").lower() == "enabled":
                bpdu_ports.add(np)

        edge_label = f"{len(edge_ports)} edge ports" if edge_ports else "Unknown"
        bpdu_label = f"{len(bpdu_ports)} protected ports" if bpdu_ports else "Unknown"

        stp_rows.append(
            f"| **{hostname}** | `{proto}` | {root_label} | `{prio}` | {edge_label} | {bpdu_label} | Standard IEEE 802.1w / 802.1s |"
        )

    if stp_rows:
        lines.extend(
            [
                "| Switch Hostname | STP Protocol Detected | Root Bridge Status | Bridge Priority | PortFast / Edge Ports | BPDU Guard Status | Migration Target Standard |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                *stp_rows,
            ]
        )
    else:
        lines.append(
            "> No Layer 2 switches or active Spanning Tree instances were discovered in the crawled dataset (not applicable to Layer 3-only routers/firewalls)."
        )
    lines.extend(
        [
            "",
            "### 6.1 Loop Protection & BPDU Guard Best-Practice Matrix (By Link Type)",
            "",
            "| Link / Port Type | STP Edge / PortFast | BPDU Guard / Block | Loop Protection (`loop-protect`) | Additional Guardrails (Often Missed) |",
            "| :--- | :---: | :---: | :---: | :--- |",
            "| **User Access (PC / Printer / Wall Jack)** | **Yes** | **Yes** | **Yes** | Enable Storm Control + auto-recovery timer (`errdisable recovery`) so transient user loops recover after unplugging. |",
            "| **VoIP Phone + PC Daisy-Chain** | **Yes** | **Yes** | **Yes** | Configure Voice VLAN + LLDP-MED and allow MAC limit >= 2–3 (phone + PC) so port security does not trip. |",
            "| **Wireless Access Point (AP)** | **Yes** | **Yes** *(off if mesh)* | **Yes** | Disable BPDU Guard if APs run wired-to-wireless mesh; keep Loop Protection on to catch dual-cable/injector loops. |",
            "| **Inter-Switch Trunk (Access ↔ Dist)** | **No** | **No** | **No** | Enable **STP Root Guard** on Distribution ports facing Access switches, plus **STP Loop Guard** / **UDLD** on fiber uplinks. |",
            "| **Spine / Core-to-Core / LAG** | **No** | **No** | **No** | Prefer **L3 routed P2P (`/30`/`/31`)** links where possible; on L2 trunks/LAGs use **LACP (`802.3ad`)** + **Loop Guard** + **UDLD**. |",
            "| **Firewall / Router / Hypervisor** | **Yes** *(if L3)* | **Yes** *(vSwitch/L3)* | **Yes** *(vSwitch)* | Keep BPDU Guard **off** on transparent/bridged firewalls; enable on Proxmox/ESXi uplinks to catch `vmbr`/vSwitch loops. |",
        ]
    )
    return lines


def _render_blueprint_fhrp_and_routing_section(unique_devs: dict) -> list[str]:
    """Render Sections 7 (FHRP) and 8 (Layer 3 Subnets & Default Routes)."""
    lines = [
        "",
        "---",
        "",
        "## 7. First-Hop Redundancy Protocols (FHRP) & Gateway Migration",
        "",
    ]
    # Group FHRP entries across fleet by (protocol, group, vip) so Active Primary and Standby Secondary map cleanly
    fhrp_groups: dict[tuple[str, str, str], list[tuple[str, dict]]] = {}
    for ip, dev in unique_devs.items():
        host = dev.get("hostname") or ip
        for f_item in dev.get("fhrp", []) or []:
            proto = str(f_item.get("protocol") or "Unknown").upper()
            grp = str(f_item.get("group") or "")
            vip = str(f_item.get("vip") or "Unknown")
            fhrp_groups.setdefault((proto, grp, vip), []).append((host, f_item))

    fhrp_migration_rows = []
    for (proto, grp, vip), members in fhrp_groups.items():
        primaries: list[str] = []
        standbys: list[str] = []
        others: list[tuple[int, str]] = []
        preempt_vals: list[bool] = []
        group_intf = members[0][1].get("interface", "N/A")

        for host, f_item in members:
            st_raw = str(f_item.get("state") or "Unknown").strip()
            st_l = st_raw.lower()
            pri = int(f_item.get("priority") or 0)
            intf = f_item.get("interface") or "N/A"
            label = f"`{host}` ({intf}, pri {pri})"
            if st_l in ("active", "master", "primary", "active-active"):
                primaries.append(label)
            elif st_l in ("standby", "backup", "secondary", "listen", "speak"):
                standbys.append(label)
            else:
                others.append((pri, f"`{host}` ({intf}, {st_raw}, pri {pri})"))
            pval = f_item.get("preempt")
            if isinstance(pval, bool):
                preempt_vals.append(pval)
            elif isinstance(pval, str) and pval.strip().lower() in ("true", "enabled", "yes"):
                preempt_vals.append(True)
            elif isinstance(pval, str) and pval.strip().lower() in ("false", "disabled", "no"):
                preempt_vals.append(False)

        if not primaries and others:
            others.sort(key=lambda x: x[0], reverse=True)
            primaries.append(others[0][1])
            standbys.extend(item[1] for item in others[1:])
        elif others:
            standbys.extend(item[1] for item in others)

        primary_col = ", ".join(primaries) if primaries else "Unknown"
        standby_col = ", ".join(standbys) if standbys else "Single Node Observed (No Peer Discovered)"
        if any(preempt_vals):
            preempt_col = "Enabled"
        elif preempt_vals:
            preempt_col = "Disabled"
        else:
            preempt_col = "Unknown"
        grp_lbl = f"Group `{grp}` ({group_intf})" if grp else f"({group_intf})"

        fhrp_migration_rows.append(
            f"| **{grp_lbl}** | `{proto}` | `{vip}` | {primary_col} | {standby_col} | {preempt_col} | Standard VRRPv3 (RFC 5798) |"
        )

    fhrp_avail = _section_availability_summary(unique_devs, "fhrp", fallback_section="running_config")
    if fhrp_migration_rows:
        lines.extend(
            [
                "| Redundancy Group | Protocol Type | Virtual IP Address | Active Primary Node | Standby Secondary Node | Preemption | Target Migration Standard |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                *fhrp_migration_rows,
            ]
        )
        if fhrp_avail["has_gaps"]:
            gap_hosts = fhrp_avail["failed_hosts"] + fhrp_avail["not_collected_hosts"]
            lines.append(
                f"\n> ⚠️ **Partial FHRP Visibility**: Data not collected / failed on {len(gap_hosts)}/{fhrp_avail['total']} device(s) ({', '.join(gap_hosts[:8])})."
            )
    else:
        if fhrp_avail["has_gaps"]:
            gap_hosts = fhrp_avail["failed_hosts"] + fhrp_avail["not_collected_hosts"]
            lines.append(
                f"> ⚠️ **FHRP Data Not Collected / Collection Failed** on {len(gap_hosts)}/{fhrp_avail['total']} device(s) "
                f"({', '.join(gap_hosts[:8])}); cannot confirm absence of HSRP/VRRP/CARP groups."
            )
        else:
            lines.append("> No FHRP (HSRP / VRRP / CARP) groups were discovered in the crawled dataset.")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 8. Layer 3 Subnets, Routing Boundaries & WAN Egress",
            "",
            "### 8.1 Discovered Default Routes & Gateways of Last Resort",
        ]
    )
    def_route_rows = []
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        for r in dev.get("routes", []):
            rd = get_route_details(r)
            sub_norm = str(rd.get("subnet") or "").strip().lower()
            if sub_norm in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "default", "::/0"):
                ad_val = rd.get("admin_distance")
                ad_str = (
                    f"{ad_val} ({rd.get('protocol')})"
                    if ad_val is not None and str(ad_val).strip() != ""
                    else "Unknown (Not Reported)"
                )
                nh_lbl = f"`{rd.get('next_hop')}`" + (f" (`{rd.get('subnet')}`)" if sub_norm == "::/0" else "")
                def_route_rows.append(
                    f"| **{hostname}** | {nh_lbl} | `{rd.get('interface') or 'N/A'}` | `{rd.get('protocol')}` | {ad_str} |"
                )

    if def_route_rows:
        lines.extend(
            [
                "| Device Hostname | Default Route (`0.0.0.0/0` / `::/0`) Next-Hop | Exit Interface | Protocol Type | Administrative Distance |",
                "| :--- | :--- | :--- | :--- | :--- |",
                *def_route_rows,
            ]
        )
    else:
        rt_avail = _section_availability_summary(unique_devs, "routes")
        if rt_avail["has_gaps"]:
            gap_hosts = rt_avail["failed_hosts"] + rt_avail["not_collected_hosts"]
            lines.append(
                f"> ⚠️ **Route Data Not Collected / Collection Failed** on {len(gap_hosts)}/{rt_avail['total']} device(s) ({', '.join(gap_hosts[:8])})."
            )
        else:
            lines.append("> No default routes (`0.0.0.0/0` or `::/0`) were discovered in crawled routing tables.")

    from net_docu_crawler.topology_renderer import build_topology_graph_model

    model = build_topology_graph_model(unique_devs)
    l3_graph = model.get("l3_graph") or {}
    l3_nodes_by_id = {n["id"]: n for n in (l3_graph.get("l3_nodes") or [])}
    l3_links = l3_graph.get("l3_links") or []
    l3_conflicts = l3_graph.get("l3_conflicts") or []

    lines.extend(["", "### 8.2 L3 Backbone, WAN Egress & Conflict Summary", ""])
    if l3_links:
        lines.extend(
            [
                "| Source Node | Target Node | Transit CIDR | Transport Type | Routing Mechanism | Routed Prefixes / Warnings |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        tt_labels = {
            "metro_ethernet": "Metro-E (ARP+L3)",
            "wan_carrier": "WAN Carrier",
            "direct_l2_uplink": "Direct Fiber LLDP",
            "l3_egress": "L3 Egress",
            "l3_routed": "L3 Route",
        }
        for lk in l3_links:
            src_hn = (l3_nodes_by_id.get(lk["source"]) or {}).get("hostname") or lk["source"]
            dst_hn = (l3_nodes_by_id.get(lk["target"]) or {}).get("hostname") or lk["target"]
            tcidr = lk.get("transit_cidr") or "-"
            tt_lbl = tt_labels.get(lk.get("transport_type") or "", lk.get("transport_type") or "L3 Route")
            mech = lk.get("routing_mechanism") or "-"
            notes = []
            if lk.get("mask_mismatch"):
                notes.append(f"⚠️ MASK MISMATCH ({lk.get('mask_mismatch_detail') or 'prefix mismatch'})")
            if lk.get("routed_prefixes_summary"):
                notes.append(lk["routed_prefixes_summary"])
            note_s = "; ".join(notes) or "-"
            lines.append(f"| **{src_hn}** | **{dst_hn}** | `{tcidr}` | {tt_lbl} | `{mech}` | {note_s} |")
        lines.append("")
    else:
        lines.extend(["> No multi-node L3 routed transit or WAN egress adjacencies detected.", ""])

    if l3_conflicts:
        lines.extend(
            [
                "#### Detected L3 Routing Conflicts & Mask Mismatches",
                "| Conflict Type | CIDR | Affected Devices | Active Hub Route Target | Impact Summary |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for c in l3_conflicts:
            ctype = str(c.get("conflict_type") or "").replace("_", " ").title()
            devs_s = ", ".join(c.get("devices") or [])
            tgt_s = c.get("active_hub_route_target") or "-"
            lines.append(
                f"| **{ctype}** | `{c.get('cidr') or ''}` | {devs_s} | {tgt_s} | {c.get('impact_summary') or ''} |"
            )
        lines.append("")
    else:
        lines.append(
            "✓ **No L3 duplicate gateway IPs, overlapping site subnets, or transit mask mismatches detected.**"
        )
    return lines


def _render_blueprint_security_and_services_section(unique_devs: dict) -> list[str]:
    """Render Sections 9 (Security/ACLs/NAT) and 10 (Infrastructure Services) with truthful audits."""
    lines = [
        "",
        "---",
        "",
        "## 9. Security, Access Control Lists & NAT Policies",
        "",
        "| Device Hostname | Insecure Protocols (Telnet/HTTP) | Secure Transport (SSH/HTTPS) | Ingress/Egress Filter Rules | NAT Overload (PAT) Status |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        persona = str(dev.get("device_persona") or dev.get("device_type") or "").lower()
        mgmt = str(dev.get("mgmt_method") or "Unknown")
        cfg = str(dev.get("raw_config") or "")
        sec_pol = dev.get("security_policy") or {}
        fw_cnt = len(sec_pol.get("firewall_rules") or [])
        nat_cnt = len(sec_pol.get("nat_rules") or [])
        sec_cs = _device_section_status(dev, "security_policy", fallback_section="running_config")

        # Count port-level ACL bindings from both correlated `ports` and `port_profiles`
        port_acls: set[str] = set()
        for src_map in (dev.get("ports") or {}, dev.get("port_profiles") or {}):
            for p_entry in src_map.values():
                if not isinstance(p_entry, dict):
                    continue
                for akey in ("acl_in", "acl_out"):
                    aval = str(p_entry.get(akey) or "").strip()
                    if aval:
                        port_acls.add(aval)

        # Detect insecure management exposure from both mgmt_method and running-config
        insecure_flags: list[str] = []
        if "telnet" in mgmt.lower() or re.search(
            r"(?im)^\s*(?:transport\s+input\b[^\r\n]*\btelnet\b|telnet-server\b|set\s+system\s+services\s+telnet\b)",
            cfg,
        ):
            insecure_flags.append("Telnet")
        if re.search(r"(?im)^\s*ip\s+http\s+server\b", cfg) and not re.search(
            r"(?im)^\s*no\s+ip\s+http\s+server\b", cfg
        ):
            insecure_flags.append("HTTP")

        if insecure_flags:
            insecure_col = f"⚠️ {' + '.join(insecure_flags)} Enabled"
        elif mgmt == "Unknown" and not cfg:
            insecure_col = "Unknown"
        else:
            insecure_col = "None Detected (SSH/API)"

        secure_col = mgmt if mgmt != "Unknown" else "Unknown"

        if fw_cnt > 0 and port_acls:
            acl_col = f"{fw_cnt} policy rules + {len(port_acls)} port ACL(s) ({', '.join(sorted(port_acls)[:3])})"
        elif fw_cnt > 0:
            acl_col = f"{fw_cnt} parsed rules"
        elif port_acls:
            acl_col = f"{len(port_acls)} port ACL(s): {', '.join(sorted(port_acls)[:4])}"
        elif sec_cs in ("command_failed", "parse_failed", "not_collected"):
            acl_col = f"⚠️ Data Not Collected (`{sec_cs}`)"
        else:
            acl_col = "None Parsed (Verify Manually)"

        if nat_cnt > 0:
            nat_status = f"Enabled ({nat_cnt} rules)"
        elif sec_cs in ("command_failed", "parse_failed", "not_collected"):
            nat_status = f"⚠️ Data Not Collected (`{sec_cs}`)"
        elif persona == "switch":
            nat_status = "N/A (L2/L3 Switch)"
        else:
            nat_status = "None Detected (Verify NAT Policy)"

        lines.append(f"| **{hostname}** | {insecure_col} | {secure_col} | {acl_col} | {nat_status} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "## 10. Infrastructure Services (DNS, NTP, Syslog, SNMP, AAA)",
            "",
            "| Service Category | Discovered Server Endpoint(s) | Operational Protocol | Migration Consistency Audit |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )

    total_devs = len(unique_devs)
    serv_avail = _section_availability_summary(unique_devs, "services", fallback_section="running_config")

    def _audit_fleet_service(
        key_names: tuple[str, ...],
        *,
        empty_label: str,
        ok_consistent_label: str,
        label_prefix_map: dict[str, str] | None = None,
    ) -> tuple[str, str]:
        all_endpoints: set[str] = set()
        per_dev_sets: list[frozenset[str]] = []
        covered = 0
        for dev in unique_devs.values():
            serv = dev.get("services") or {}
            dev_eps: set[str] = set()
            for k in key_names:
                pfx = (label_prefix_map or {}).get(k, "")
                for item in serv.get(k) or []:
                    s_val = str(item).strip()
                    if s_val:
                        formatted = f"{pfx}{s_val}" if pfx else s_val
                        dev_eps.add(formatted)
                        all_endpoints.add(formatted)
            if dev_eps:
                covered += 1
                per_dev_sets.append(frozenset(dev_eps))

        ep_str = ", ".join(f"`{s}`" for s in sorted(all_endpoints)) or empty_label

        if serv_avail["has_gaps"]:
            gap_cnt = len(serv_avail["failed_hosts"]) + len(serv_avail["not_collected_hosts"])
            if not all_endpoints:
                audit_str = f"⚠️ Data Not Collected / Collection Failed ({gap_cnt}/{total_devs} device(s))"
            else:
                audit_str = f"⚠️ Incomplete ({covered}/{total_devs} configured; {gap_cnt} device(s) collection failed/not collected)"
        elif not all_endpoints or total_devs == 0:
            audit_str = "⚠️ Not Discovered (Verify Configuration)"
        elif covered == total_devs and len(set(per_dev_sets)) == 1:
            audit_str = f"{ok_consistent_label} ({covered}/{total_devs} devices)"
        else:
            distinct_cnt = len(set(per_dev_sets))
            audit_str = f"⚠️ Partial / Divergent ({covered}/{total_devs} devices; {distinct_cnt} distinct config set(s))"
        return ep_str, audit_str

    dns_str, dns_audit = _audit_fleet_service(
        ("dns_servers",),
        empty_label="Unknown (Not Discovered)",
        ok_consistent_label="✓ Consistent Across Fleet",
    )
    ntp_str, ntp_audit = _audit_fleet_service(
        ("ntp_servers",),
        empty_label="Unknown (Not Discovered)",
        ok_consistent_label="✓ Clock Synchronized",
    )
    sys_str, sys_audit = _audit_fleet_service(
        ("syslog_servers",),
        empty_label="Unknown (Not Discovered)",
        ok_consistent_label="✓ Audit Trail Maintained",
    )
    snmp_str, snmp_audit = _audit_fleet_service(
        ("snmp_servers",),
        empty_label="Unknown (Not Discovered)",
        ok_consistent_label="✓ SNMP Monitoring Configured",
    )
    aaa_str, aaa_audit = _audit_fleet_service(
        ("radius_servers", "tacacs_servers"),
        empty_label="Unknown / Local RBAC",
        ok_consistent_label="✓ Central AAA Consistent",
        label_prefix_map={"radius_servers": "RADIUS:", "tacacs_servers": "TACACS+:"},
    )

    lines.append(f"| **DNS Resolvers** | {dns_str} | DNS UDP/TCP 53 | {dns_audit} |")
    lines.append(f"| **NTP Strata** | {ntp_str} | NTP UDP 123 | {ntp_audit} |")
    lines.append(f"| **Syslog Logging** | {sys_str} | Syslog UDP 514 | {sys_audit} |")
    lines.append(f"| **SNMP Monitoring** | {snmp_str} | SNMP UDP 161/162 | {snmp_audit} |")
    lines.append(f"| **AAA Authentication** | {aaa_str} | RADIUS UDP 1812 / TACACS+ TCP 49 | {aaa_audit} |")
    return lines


def _render_blueprint_translation_and_runbook_section(unique_devs: dict) -> list[str]:
    """Render Sections 11 (Protocol Translation) and 12 (Cutover Runbook Summary & Link)."""
    lines = [
        "",
        "---",
        "",
        "## 11. Proprietary Feature De-risking & Protocol Translation",
        "",
        "| Source Vendor / Construct | Standard Target Feature | Technical Migration Action | Risk Level |",
        "| :--- | :--- | :--- | :--- |",
    ]
    vendors_present = {str(d.get("vendor") or "").lower() for d in unique_devs.values()}
    added_rows = 0
    if any("cisco" in v for v in vendors_present):
        added_rows += 1
        lines.extend(
            [
                "| **Cisco PVST+ / Rapid-PVST+** | `MSTP (802.1s)` or `RSTP (802.1w)` | Map multi-instance VLAN STPs to IEEE standard MSTP region. | Medium |",
                "| **Cisco HSRP** | `VRRPv3 (RFC 5798)` | Convert virtual router IP groups and priority preemption to VRRP. | Low |",
                "| **Cisco Discovery Protocol (CDP)** | `LLDP (802.1AB)` | Enable LLDP globally and transmit/receive TLVs on all switchports. | Low |",
                "| **Static EtherChannel (`mode on`)** | `LACP Active (802.3ad)` | Eliminate unnegotiated channel bonds; enforce LACP control packet verification. | High |",
                "| **Cisco StackWise** | Target `MLAG / Virtual Chassis` | Eliminate proprietary backplane stacking; transition to multi-chassis LAG. | Medium |",
            ]
        )
    if any("juniper" in v for v in vendors_present):
        added_rows += 1
        lines.extend(
            [
                "| **Junos `family ethernet-switching`** | Target Access / Trunk Port Profile | Map `interface-mode` + `vlan members` (expanding `all`) and `native-vlan-id`. | Medium |",
                "| **Junos `irb.<vid>` + `dhcp-relay`** | Target SVI / Routed VLAN Interface | Preserve IP/prefix, VRF, and `active-server-group` relay bindings. | Medium |",
                "| **Junos `switch-options voip`** | Target Voice VLAN / LLDP-MED | Map `voip interface` VLAN bindings to target voice-VLAN + LLDP-MED policy. | Low |",
            ]
        )
    if any("procurve" in v or "hp" in v or "aruba" in v for v in vendors_present):
        added_rows += 1
        lines.extend(
            [
                "| **HP/Aruba `untagged` / `tagged` VLANs** | Target Access / Trunk Port Profile | Convert `untagged` on trunks to native VLAN and `tagged` sets to allowed VLANs. | Medium |",
                "| **HP/Aruba `Trk*` + `ip helper-address`** | Target LACP LAG + SVI Relay | Map `Trk*` bundles to LACP active LAGs and per-VLAN `ip helper-address`. | Medium |",
            ]
        )
    if any("opnsense" in v for v in vendors_present):
        added_rows += 1
        lines.append(
            "| **OPNsense `vtnet*_vlan*` / `CARP`** | Standard 802.1Q Subinterfaces / VRRPv3 | Preserve VLAN tags, DHCP/Dnsmasq/Kea scopes, and firewall/NAT rules. | Medium |"
        )
    if any("fortinet" in v or "fortigate" in v for v in vendors_present):
        added_rows += 1
        lines.append(
            "| **FortiOS Zones / Policy Objects** | Standard Interface Zones / ACLs | Translate FortiOS zone members, VIP/IPPool NAT objects, and enable LLDP TX/RX. | Medium |"
        )
    if any("mikrotik" in v for v in vendors_present):
        added_rows += 1
        lines.append(
            "| **MikroTik `MNDP` / Bridge VLAN Filtering** | `LLDP (802.1AB)` / IEEE 802.1Q | Convert RouterOS bridge PVID/tagged lists and verify LLDP vs MNDP visibility. | Low |"
        )
    if any("frr" in v for v in vendors_present):
        added_rows += 1
        lines.append(
            "| **FRRouting (`vtysh`) L3 Control Plane** | Standard BGP / OSPF / Static Routing | Preserve ASN/area/redistribute policies; install `lldpd` if L2 adjacency is desired. | Low |"
        )
    if added_rows == 0:
        lines.append(
            "| *Discovered Estate* | Standard IEEE 802.1Q / 802.1AB / L3 Routing | No vendor-proprietary L2/L3 lock-in protocols detected. | Low |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 12. Maintenance Window Cutover Runbook & Rollback Plan",
            "",
            "The complete step-by-step T-minus pre-flight checklist, cutover execution sequence, and rollback decision gate "
            "are maintained in the standalone runbook: **[cutover_runbook.md](./cutover_runbook.md)**.",
            "",
            "- **Pre-Cutover**: Backup dataset ([net_docu_crawler_dataset.json](./net_docu_crawler_dataset.json)), stage optics/cabling per [migration_cabling_matrix.csv](./migration_cabling_matrix.csv), and verify `./validate_cutover.sh`.",
            "- **Execution**: Silence NMS alerts -> repatch per [migration_cabling_matrix.csv](./migration_cabling_matrix.csv) -> power on target gear -> run [validate_cutover.sh](./validate_cutover.sh).",
            "- **Rollback**: If core gateways or client DHCP fail beyond the 45-minute abort gate, restore legacy patching and re-verify baseline via [validate_cutover.sh](./validate_cutover.sh).",
            "",
            "---",
            "*Automated Executive Overview compiled by Net-Docu-Crawler Engine.*",
        ]
    )
    return lines


def generate_cutover_runbook(
    devices: dict,
    output_path: str = "cutover_runbook.md",
    scope: str = "Discovered Network",
    timestamp: str = "",
) -> None:
    """
    Generate the standalone Maintenance Window Cutover Runbook & Rollback Plan (cutover_runbook.md).
    """
    from net_docu_crawler.topology_renderer import build_topology_graph_model

    if not timestamp:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    unique_devs = get_unique_devices({ip: dev for ip, dev in devices.items() if _is_network_infra(dev)})
    model = build_topology_graph_model(unique_devs)
    gateways: list[tuple[str, str, str, str]] = []
    relays: list[tuple[str, str, str]] = []
    lldp_gaps: list[tuple[str, str]] = []

    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        for r in dev.get("routes", []):
            rd = get_route_details(r)
            if rd.get("subnet") in ("0.0.0.0/0", "default"):
                gateways.append(
                    (
                        hostname,
                        str(rd.get("next_hop") or ""),
                        str(rd.get("interface") or ""),
                        str(rd.get("protocol") or ""),
                    )
                )
        dev_relays = (dev.get("dhcp") or {}).get("relays", []) or []
        if dev_relays:
            for rel in dev_relays:
                if rel.get("helper_ip"):
                    relays.append((hostname, str(rel.get("interface", "") or "-"), str(rel["helper_ip"])))
        else:
            for r_ip in (dev.get("services") or {}).get("dhcp_relays", []) or []:
                relays.append((hostname, "Config Services", str(r_ip)))
        dp = dev.get("discovery_protocols") or {}
        lldp_st = dp.get("lldp", "unknown")
        if lldp_st in ("disabled", "not_installed") or (
            lldp_st == "unknown" and not (dev.get("neighbors") or []) and dp.get("cdp") != "enabled"
        ):
            lldp_gaps.append((hostname, lldp_st))

    campus_roots = [n for n in (model.get("nodes") or []) if n.get("stp_root_scope") == "campus_root"]
    isolated_roots = [n for n in (model.get("nodes") or []) if n.get("stp_root_scope") == "isolated_self_root"]

    def _fmt_inline_or_count(items: list, inline_fn, empty_msg: str, noun: str) -> str:
        if not items:
            return empty_msg
        if len(items) <= 4:
            return ", ".join(inline_fn(it) for it in items)
        return f"**{len(items)}** {noun} verified (expand reference table below)."

    gw_summary = _fmt_inline_or_count(
        gateways,
        lambda g: f"`{g[0]}` -> `{g[1]}` via `{g[2]}`",
        "Verify default routes on target L3 gateways.",
        "default gateways",
    )
    if campus_roots:
        cr_part = _fmt_inline_or_count(
            campus_roots,
            lambda n: f"`{n['hostname']}` (`{n.get('stp_root_bridge_mac') or 'Root'}`)",
            "",
            "verified campus STP root(s)",
        )
        iso_part = (
            f" (⚠️ **{len(isolated_roots)}** isolated self-root island(s) also detected — see below)"
            if isolated_roots
            else ""
        )
        stp_summary = f"Verified campus root(s): {cr_part}{iso_part}"
    elif isolated_roots:
        stp_summary = (
            f"⚠️ **0** multi-switch verified campus roots; **{len(isolated_roots)}** isolated self-root switch(es) flagged "
            "(confirm intended STP root bridge priority on target core; see details below)."
        )
    else:
        stp_summary = "Confirm intended STP root bridge priority on target core."

    relay_summary = _fmt_inline_or_count(
        relays,
        lambda r: f"`{r[0]}` `{r[1]}` -> `{r[2]}`",
        "No centralized DHCP relays detected; verify local gateway DHCP scopes if applicable.",
        "DHCP relay bindings",
    )
    if not lldp_gaps:
        lldp_summary = "All infrastructure nodes have LLDP/CDP visibility."
    elif len(lldp_gaps) <= 4:
        lldp_summary = "Manually trace physical cabling for: " + ", ".join(
            f"`{h}` (`lldp={st}`)" for h, st in lldp_gaps
        )
    else:
        lldp_summary = f"**{len(lldp_gaps)}** nodes lack LLDP/CDP visibility (expand table below)."

    lines = [
        "# Maintenance Window Cutover Runbook & Rollback Plan",
        "",
        f"> **Scope**: `{scope}` | **Generated**: `{timestamp}` | **Nodes**: `{len(unique_devs)}`",
        "> **Reference Overview**: [Network_Analysis.md](./Network_Analysis.md) | "
        "**Cabling**: [migration_cabling_matrix.csv](./migration_cabling_matrix.csv) | "
        "**Smoke Test**: [validate_cutover.sh](./validate_cutover.sh)",
        "",
        "---",
        "",
        "## 1. Pre-Cutover T-Minus Checklist (24 Hours Prior)",
        "- [ ] **Configuration & Dataset Backup**: Confirm [net_docu_crawler_dataset.json](./net_docu_crawler_dataset.json) and raw device backups are archived.",
        "- [ ] **Cabling & Optics Staging**: Stage patch cords and transceivers per [migration_cabling_matrix.csv](./migration_cabling_matrix.csv).",
        f"- [ ] **Default Gateways Verified**: {gw_summary}",
        f"- [ ] **STP Root Placement Verified**: {stp_summary}",
        f"- [ ] **DHCP Relays Provisioned**: {relay_summary}",
        f"- [ ] **L2 Blind-Spot Physical Trace**: {lldp_summary}",
        "- [ ] **Validation Script Ready**: Confirm `./validate_cutover.sh` (or `validate_cutover.ps1`) executes cleanly against baseline.",
        "",
    ]

    detail_blocks: list[str] = []
    if len(gateways) > 4:
        detail_blocks.extend(
            [
                f"<details><summary><strong>Default Gateways ({len(gateways)})</strong></summary>",
                "",
                "| Hostname | Next Hop | Exit Interface | Protocol |",
                "| :--- | :--- | :--- | :--- |",
                *[f"| **{h}** | `{nh}` | `{iface}` | `{proto}` |" for h, nh, iface, proto in gateways],
                "",
                "</details>",
                "",
            ]
        )
    if len(campus_roots) > 4 or isolated_roots:
        detail_blocks.extend(
            [
                f"<details><summary><strong>STP Root Scope Breakdown ({len(campus_roots)} verified campus root(s), {len(isolated_roots)} isolated self-root(s))</strong></summary>",
                "",
                "| Hostname | Site | STP Scope | Root Bridge ID |",
                "| :--- | :--- | :--- | :--- |",
                *[
                    f"| **{n['hostname']}** | `{n.get('site', '')}` | Verified Campus Root | `{n.get('stp_root_bridge_mac') or 'Root'}` |"
                    for n in campus_roots
                ],
                *[
                    f"| **{n['hostname']}** | `{n.get('site', '')}` | ⚠️ Isolated Self-Root | `{n.get('stp_root_bridge_mac') or 'Self'}` |"
                    for n in isolated_roots
                ],
                "",
                "</details>",
                "",
            ]
        )
    if len(relays) > 4:
        detail_blocks.extend(
            [
                f"<details><summary><strong>DHCP Relay Bindings ({len(relays)})</strong></summary>",
                "",
                "| Hostname | Interface | Helper IP |",
                "| :--- | :--- | :--- |",
                *[f"| **{h}** | `{iface}` | `{hip}` |" for h, iface, hip in relays],
                "",
                "</details>",
                "",
            ]
        )
    if len(lldp_gaps) > 4:
        detail_blocks.extend(
            [
                f"<details><summary><strong>L2 Blind-Spot Nodes ({len(lldp_gaps)})</strong></summary>",
                "",
                "| Hostname | LLDP Status |",
                "| :--- | :--- |",
                *[f"| **{h}** | `{st}` |" for h, st in lldp_gaps],
                "",
                "</details>",
                "",
            ]
        )
    if detail_blocks:
        lines.extend(["### 1.1 Pre-Cutover Reference Tables", "", *detail_blocks])

    lines.extend(
        [
            "---",
            "",
            "## 2. Cutover Window Execution Sequence (T-0 to T+30m)",
            "1. **T-0:00 - Silence Monitoring Alerts**: Place target switches, routers, and firewalls in maintenance mode in SIEM/NMS.",
            "2. **T-0:05 - Physical Cable Transfer**: Move patch cables in sequence per [migration_cabling_matrix.csv](./migration_cabling_matrix.csv).",
            "3. **T-0:15 - Power-On & Link Verification**: Power up replacement hardware; verify uplinks, LACP/LAG bundles, and STP convergence.",
            "4. **T-0:20 - Automated Reachability Smoke Tests**: Run `./validate_cutover.sh` from management jumphost to verify gateway and DNS reachability.",
            "5. **T-0:25 - Client & Wireless Verification**: Verify DHCP leases, inter-VLAN routing, and AP associations across all VLANs.",
            "",
            "---",
            "",
            "## 3. Rollback Plan & Hard Abort Gate",
            "> [!CAUTION]",
            "> **HARD ABORT CRITERIA**: If core gateway reachability, WAN egress, or client DHCP fails and cannot be resolved within 45 minutes of maintenance window start, trigger immediate rollback:",
            "1. Power down or isolate replacement hardware.",
            "2. Re-seat original patch cables into legacy ports using [migration_cabling_matrix.csv](./migration_cabling_matrix.csv) as source of truth.",
            "3. Power on legacy switches/gateways and run `./validate_cutover.sh` to verify 100% baseline restoration.",
            "",
        ]
    )

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] Cutover runbook written to: {output_path}")
    except Exception as e:
        logger.debug("Error writing cutover runbook to %s: %s", output_path, e, exc_info=True)
        print(f"[-] Error writing cutover runbook: {e}")


_PROBABLE_NETWORK_VENDOR_HINTS = (
    "cisco",
    "juniper",
    "aruba",
    "hewlett",
    "procurve",
    "netgear",
    "tp-link",
    "tplink",
    "ubiquiti",
    "unifi",
    "d-link",
    "dlink",
    "brocade",
    "extreme",
    "arista",
    "mikrotik",
    "zyxel",
    "allied",
    "trendnet",
    "ruckus",
    "fortinet",
    "palo",
    "opnsense",
    "pfsense",
    "frrouting",
    "edgecore",
    "mellanox",
    "huawei",
    "h3c",
    "hp inc",
)


def _is_infra_failed_host(fh: dict) -> bool:
    """Return True if a failed_hosts.json entry represents infrastructure rather than a passive/unsupported endpoint."""
    if not isinstance(fh, dict):
        return False
    rc = str(fh.get("record_class") or "").strip().lower()
    if rc == "unauthenticated_infra":
        return True
    if rc in ("passive_endpoint", "unsupported_appliance"):
        return False
    st = str(fh.get("status") or "").strip().lower()
    dtype = str(fh.get("device_type") or "").strip().lower()
    if dtype in ("ap", "phone", "voip", "camera", "printer", "display", "av_control", "ups", "nas", "iot", "server"):
        return False
    if st == "unauthenticated":
        return True
    if dtype in ("switch", "router", "firewall", "wlc"):
        return True
    vend_l = str(fh.get("vendor") or "").strip().lower()
    mod_l = str(fh.get("model") or "").strip().lower()
    hay = f"{vend_l} {mod_l}"
    infra_hints = tuple(h for h in _PROBABLE_NETWORK_VENDOR_HINTS if h not in ("ruckus", "hp inc"))
    return any(h in hay for h in infra_hints)


def _render_blueprint_manual_verification_section(devices: dict, unique_devs: dict) -> list[str]:
    """Render Section 1.5: manual verification checklist for suspected unmanaged switches, failed/unsupported hosts, and bridges."""
    from net_docu_crawler.topology_renderer import classify_neighbor_node

    lines: list[str] = [
        "",
        "### 1.5 Manual Verification & Suspected Unmanaged / Unverified Switches",
        "",
        "Items below were flagged from MAC forwarding tables, LLDP/CDP gaps, SSH/TLS probes, and non-infrastructure host crawls and require physical or administrative verification:",
        "",
    ]

    crawled_hosts_lc: set[str] = set()
    crawled_ips: set[str] = set()
    crawled_macs: set[str] = set()
    for ip, d in unique_devs.items():
        hn = str(d.get("hostname") or ip).strip()
        if hn:
            crawled_hosts_lc.add(hn.lower())
            crawled_hosts_lc.add(hn.split(".")[0].lower())
        crawled_ips.add(str(ip).strip())
        if d.get("ip"):
            crawled_ips.add(str(d["ip"]).strip())
        for l3 in d.get("l3_interfaces") or []:
            cip = str((l3 or {}).get("ip_address") or "").split("/")[0].split()[0].strip()
            if cip and not cip.startswith(("127.", "128.0.")):
                crawled_ips.add(cip)
        bmac = oui_lookup.normalize_mac(str(d.get("mac_address") or "")).lower().strip()
        if bmac and bmac != "00:00:00:00:00:00":
            crawled_macs.add(bmac)

    suspected_l2_rows: list[str] = []
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        nbrs = dev.get("neighbors") or []
        direct_nbr_ports = {
            normalize_interface_name(n.get("local_port", "")).lower()
            for n in nbrs
            if n.get("local_port") and n.get("l2_accuracy", "") != "mac_inferred"
        }
        carrier_or_egress_ports = {
            normalize_interface_name(n.get("local_port", "")).lower()
            for n in nbrs
            if n.get("local_port") and n.get("l2_accuracy", "") in ("wan_carrier_arp_route", "l3_next_hop_egress")
        }

        macs_by_port: dict[str, set[str]] = {}
        for entry in dev.get("mac_table") or []:
            port = (entry.get("interface") or entry.get("port") or "").strip()
            mac = (entry.get("mac") or "").strip().lower()
            if not port or not mac or port.lower() in ("cpu", "self", "router", "switch"):
                continue
            macs_by_port.setdefault(port, set()).add(mac)

        for port, macs in sorted(macs_by_port.items()):
            norm_p = normalize_interface_name(port).lower()
            if len(macs) >= 2 and norm_p not in direct_nbr_ports and norm_p not in carrier_or_egress_ports:
                suspected_l2_rows.append(
                    f"| **{hostname}** | `{port}` | `{len(macs)} MACs` (no direct LLDP/CDP) | Verify unmanaged switch, hypervisor vSwitch/bridge, or L2 aggregation hop |"
                )

        for n in nbrs:
            if n.get("l2_accuracy") in ("virtual_passthrough", "multi_neighbor_port"):
                suspected_l2_rows.append(
                    f"| **{hostname}** | `{n.get('local_port', '')}` | Multi-neighbor transit (`{n.get('remote_device', '')}`) | Verify unmanaged switch or passthrough bridge on uplink |"
                )
            remote_raw = str(n.get("remote_device") or "").strip().strip('"').strip("'")
            if not remote_raw:
                continue
            cls = classify_neighbor_node(
                remote_raw,
                n,
                crawled_hosts_lc=crawled_hosts_lc,
                crawled_ips=crawled_ips,
                crawled_macs=crawled_macs,
            )
            if cls in ("uncrawled_switch", "firewall", "router", "isp"):
                plat = n.get("platform") or n.get("remote_platform") or n.get("device_type") or "Unknown"
                suspected_l2_rows.append(
                    f"| **{hostname}** | `{n.get('local_port', '')}` | Uncrawled neighbor `{remote_raw}` (`{plat}`) | Verify management IP/credentials or confirm unmanaged/external peer |"
                )

    if suspected_l2_rows:
        lines.extend(
            [
                "#### Suspected Unmanaged Switches, Multi-MAC Ports & Uncrawled Neighbors",
                "",
                "| Switch Hostname | Port | Evidence | Manual Verification Action |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        lines.extend(suspected_l2_rows[:25])
        if len(suspected_l2_rows) > 25:
            lines.append(
                f"| *...* | *...* | *{len(suspected_l2_rows) - 25} additional L2 verification item(s) omitted* | Review `port_mac_endpoint_mapping.csv` & `L2_network_diagrams.md` |"
            )
        lines.append("")

    # 2. Unauthenticated / Unsupported / Discovered hosts (highlighting probable switches)
    unverified_rows: list[tuple[bool, str]] = []
    for ip, dev in devices.items():
        st = str(dev.get("status", "")).strip().lower()
        if st not in ("unauthenticated", "unsupported", "discovered"):
            continue
        hostname = dev.get("hostname") or ip
        mac = dev.get("mac_address") or "N/A"
        vendor = dev.get("vendor") or "Unknown"
        model = dev.get("model") or ""
        haystack = f"{vendor} {model} {hostname}".lower()
        is_probable_sw = any(h in haystack for h in _PROBABLE_NETWORK_VENDOR_HINTS)
        role_label = "Probable Switch / Network Appliance" if is_probable_sw else "Server / Endpoint / Unknown"
        if st == "unsupported" and model.lower().startswith("ssh-"):
            action = f"Legacy/unsupported SSH (`{model}`); verify via console, SNMP, or Web UI"
        elif st == "unauthenticated":
            action = "SSH reachable but auth failed; verify credentials or confirm non-network host"
        else:
            action = "Discovered via ARP/OUI only; verify if managed/unmanaged switch or endpoint"
        row = f"| `{ip}` | **{hostname}** | `{mac}` | {vendor} | `{st}` | {role_label} | {action} |"
        unverified_rows.append((is_probable_sw, row))

    if unverified_rows:
        unverified_rows.sort(key=lambda x: (not x[0], x[1]))
        lines.extend(
            [
                "#### Unauthenticated, Unsupported & Discovered Targets Requiring Verification",
                "",
                "| IP Address | Hostname | MAC Address | Vendor / OUI | Status | Suspected Role | Verification Action |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for _, row in unverified_rows[:25]:
            lines.append(row)
        if len(unverified_rows) > 25:
            lines.append(
                f"| *...* | *...* | *...* | *...* | *...* | *...* | *{len(unverified_rows) - 25} additional host(s) in `failed_hosts.json`* |"
            )
        lines.append("")

    # 3. Non-infra crawled hosts (hypervisors, Linux bridges, monitoring servers) & shared MACs
    non_infra_notes: list[str] = []
    for ip, dev in devices.items():
        if str(dev.get("status", "")).strip().lower() != "success" or _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        ints = dev.get("interfaces_detail") or {}
        has_bridge = any(k.lower().startswith(("vmbr", "virbr", "br")) for k in ints) or "pve" in hostname.lower()
        note = (
            "Hypervisor / Linux L2 bridge host (verify virtual switch uplinks to physical switches)"
            if has_bridge
            else "Non-network server/appliance excluded from network BOM"
        )
        non_infra_notes.append(f"- **{hostname}** (`{ip}`, `{dev.get('device_type', 'server')}`): {note}")

    mac_to_ips: dict[str, list[str]] = {}
    for ip, dev in devices.items():
        mac = str(dev.get("mac_address") or "").strip().lower()
        if mac:
            mac_to_ips.setdefault(mac, []).append(
                f"`{ip}` ({dev.get('hostname') or ip}, `{dev.get('status', 'unknown')}`)"
            )
    for mac, entries in sorted(mac_to_ips.items()):
        if len(entries) > 1:
            non_infra_notes.append(
                f"- **Shared MAC `{mac}`** observed on multiple IPs: {', '.join(entries)} — verify VIP/secondary interface or virtual controller IP."
            )

    if non_infra_notes:
        lines.append("#### Hypervisors, Non-Infrastructure Hosts & Shared MACs")
        lines.append("")
        lines.extend(non_infra_notes)
        lines.append("")

    if not suspected_l2_rows and not unverified_rows and not non_infra_notes:
        lines.append("✓ **No suspected unmanaged switches, unverified targets, or bridge anomalies detected.**")
        lines.append("")

    return lines


def generate_master_network_analysis_migration_blueprint(
    devices: dict,
    output_path: str = "Network_Analysis.md",
    scope: str = "Discovered Network",
    timestamp: str = "",
    dns_domain: str = "",
    failed_hosts_count: int | None = None,
) -> None:
    """
    Generates the Executive & Cutover Readiness Overview (Network_Analysis.md)
    linking to all breakout deliverables and compiled from live operational telemetry.
    """
    if not timestamp:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    non_infra_failed_count = 0
    if failed_hosts_count is None:
        failed_hosts_count = 0
        failed_path = os.path.join(os.path.dirname(os.path.abspath(output_path)), "failed_hosts.json")
        if os.path.isfile(failed_path):
            try:
                with open(failed_path, encoding="utf-8") as fh:
                    failed_data = json.load(fh)
                if isinstance(failed_data, list):
                    for item in failed_data:
                        if _is_infra_failed_host(item):
                            failed_hosts_count += 1
                        else:
                            non_infra_failed_count += 1
            except (OSError, ValueError):
                failed_hosts_count = 0

    unique_devs = get_unique_devices({ip: dev for ip, dev in devices.items() if _is_network_infra(dev)})
    lines = _render_blueprint_header_and_toc(scope, dns_domain, timestamp, len(unique_devs))
    lines.extend(
        _render_blueprint_executive_summary_section(
            unique_devs,
            failed_hosts_count=failed_hosts_count,
            non_infra_failed_count=non_infra_failed_count,
        )
    )
    lines.extend(_render_blueprint_manual_verification_section(devices, unique_devs))
    lines.extend(_render_blueprint_cabling_and_mtu_section(unique_devs))
    lines.extend(_render_blueprint_optics_section(unique_devs))
    lines.extend(_render_blueprint_mac_mapping_section(unique_devs))
    lines.extend(_render_blueprint_poe_section(unique_devs))
    lines.extend(_render_blueprint_vlan_and_trunk_section(unique_devs))
    lines.extend(_render_blueprint_dhcp_relay_section(unique_devs))
    lines.extend(_render_blueprint_stp_section(unique_devs))
    lines.extend(_render_blueprint_fhrp_and_routing_section(unique_devs))
    lines.extend(_render_blueprint_security_and_services_section(unique_devs))
    lines.extend(_render_blueprint_translation_and_runbook_section(unique_devs))

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] Master Network Analysis Migration Blueprint written to: {output_path}")
    except Exception as e:
        logger.debug("Error writing master migration blueprint to %s: %s", output_path, e, exc_info=True)
        print(f"[-] Error writing master migration blueprint: {e}")


def generate_cutover_validation_script(
    devices: dict,
    output_path: str = "validate_cutover.sh",
) -> None:
    """
    Generates a standalone, executable Bash smoke-test validation script
    that verifies gateway reachability, DNS resolution, and core switch ports post-cutover.
    """
    import os

    gateways = set()
    dns_servers = set()
    for dev in devices.values():
        for intf in dev.get("l3_interfaces", []):
            ip_val = intf.get("ip_address", "").split("/")[0].split()[0]
            if (
                ip_val
                and not ip_val.startswith(("127.", "128.0.", "0.0.0.0"))
                and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_val)
            ):
                gateways.add(ip_val)
        for d in dev.get("services", {}).get("dns_servers", []):
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
                dns_servers.add(d)

    lines = [
        "#!/usr/bin/env bash",
        "# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>",
        "# SPDX-License-Identifier: AGPL-3.0-or-later",
        "# Auto-generated Post-Cutover Validation Smoke Test Script",
        "",
        "set -u",
        "",
        'GREEN="\\033[0;32m"',
        'RED="\\033[0;31m"',
        'YELLOW="\\033[1;33m"',
        'BOLD="\\033[1m"',
        'NC="\\033[0m"',
        "",
        'echo -e "${BOLD}================================================================${NC}"',
        'echo -e "${BOLD} Net-Docu-Crawler: Automated Post-Cutover Network Smoke Test    ${NC}"',
        'echo -e "${BOLD}================================================================${NC}"',
        "",
        "TOTAL_CHECKS=0",
        "PASSED_CHECKS=0",
        "FAILED_CHECKS=0",
        "",
        "check_ping() {",
        "    local ip=$1",
        "    local label=$2",
        "    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))",
        '    if ping -c 2 -W 2 "$ip" > /dev/null 2>&1; then',
        '        echo -e "  [${GREEN}PASS${NC}] Ping reachability: $label ($ip)"',
        "        PASSED_CHECKS=$((PASSED_CHECKS + 1))",
        "    else",
        '        echo -e "  [${RED}FAIL${NC}] Ping reachability: $label ($ip) UNREACHABLE!"',
        "        FAILED_CHECKS=$((FAILED_CHECKS + 1))",
        "    fi",
        "}",
        "",
        "check_port() {",
        "    local ip=$1",
        "    local port=$2",
        "    local label=$3",
        "    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))",
        '    if nc -z -w 2 "$ip" "$port" > /dev/null 2>&1; then',
        '        echo -e "  [${GREEN}PASS${NC}] TCP Service: $label ($ip:$port)"',
        "        PASSED_CHECKS=$((PASSED_CHECKS + 1))",
        "    else",
        '        echo -e "  [${YELLOW}WARN${NC}] TCP Service: $label ($ip:$port) closed or firewalled."',
        "    fi",
        "}",
        "",
        'echo -e "\\n${BOLD}[*] Phase 1: Verifying Layer 3 Gateway & SVI Reachability...${NC}"',
    ]

    _safe_target_re = re.compile(r"^[A-Za-z0-9._:-]+$")

    def _is_safe_target_addr(val: object) -> bool:
        s = str(val or "").strip()
        return bool(s) and bool(_safe_target_re.match(s))

    def _escape_bash_dq(val: object) -> str:
        s = re.sub(r"[\r\n\x00]+", " ", str(val or "")).strip()
        s = s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`").replace("!", "\\!")
        return s

    def _escape_ps_dq(val: object) -> str:
        s = re.sub(r"[\r\n\x00]+", " ", str(val or "")).strip()
        s = s.replace("`", "``").replace('"', '`"').replace("$", "`$")
        return s

    for gw in sorted(gateways):
        if _is_safe_target_addr(gw):
            lines.append(f'check_ping "{gw}" "Gateway / SVI"')

    lines.extend(
        [
            "",
            'echo -e "\\n${BOLD}[*] Phase 2: Verifying Core DNS Resolvers...${NC}"',
        ]
    )
    for dns in sorted(dns_servers):
        if _is_safe_target_addr(dns):
            lines.append(f'check_ping "{dns}" "DNS Resolver"')
            lines.append(f'check_port "{dns}" 53 "DNS Port 53"')

    lines.extend(
        [
            "",
            'echo -e "\\n${BOLD}[*] Phase 3: Verifying Management Services (SSH Port 22)...${NC}"',
        ]
    )
    for dev in devices.values():
        if not _is_network_infra(dev) or str(dev.get("record_class") or "").strip().lower() not in (
            "",
            "crawled_infra",
        ):
            continue
        dev_ip = dev.get("ip")
        dev_host = dev.get("hostname") or dev_ip
        if _is_safe_target_addr(dev_ip):
            safe_host_sh = _escape_bash_dq(dev_host)
            lines.append(f'check_port "{dev_ip}" 22 "{safe_host_sh} SSH"')

    lines.extend(
        [
            "",
            'echo -e "\\n${BOLD}================================================================${NC}"',
            'echo -e "${BOLD} Validation Summary: $PASSED_CHECKS / $TOTAL_CHECKS Checks Passed${NC}"',
            'echo -e "${BOLD}================================================================${NC}"',
            "",
            'if [ "$FAILED_CHECKS" -eq 0 ]; then',
            '    echo -e "${GREEN}${BOLD}✓ CUTOVER SMOKE TEST SUCCESSFUL: All critical gateways online.${NC}\\n"',
            "    exit 0",
            "else",
            '    echo -e "${RED}${BOLD}❌ CUTOVER VERIFICATION WARNING: $FAILED_CHECKS check(s) failed.${NC}\\n"',
            "    exit 1",
            "fi",
        ]
    )

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        try:
            os.chmod(output_path, 0o755)
        except OSError as exc:
            logger.debug("Could not set executable permissions on %s: %s", output_path, exc)
        print(f"[+] Cutover validation smoke test script written to: {output_path}")

        # Also generate cross-platform PowerShell smoke script for Windows environments
        ps1_path = os.path.splitext(output_path)[0] + ".ps1"
        ps1_lines = [
            "# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>",
            "# SPDX-License-Identifier: AGPL-3.0-or-later",
            "# Auto-generated Post-Cutover Validation Smoke Test Script (PowerShell for Windows)",
            "",
            "$TotalChecks = 0",
            "$PassedChecks = 0",
            "$FailedChecks = 0",
            "",
            'Write-Host "================================================================" -ForegroundColor Cyan',
            'Write-Host " Net-Docu-Crawler: Automated Post-Cutover Network Smoke Test    " -ForegroundColor Cyan',
            'Write-Host "================================================================" -ForegroundColor Cyan',
            "",
            "function Test-PingReachability($ip, $label) {",
            "    $script:TotalChecks++",
            "    if (Test-Connection -ComputerName $ip -Count 2 -Quiet -ErrorAction SilentlyContinue) {",
            '        Write-Host "  [PASS] Ping reachability: $label ($ip)" -ForegroundColor Green',
            "        $script:PassedChecks++",
            "    } else {",
            '        Write-Host "  [FAIL] Ping reachability: $label ($ip) UNREACHABLE!" -ForegroundColor Red',
            "        $script:FailedChecks++",
            "    }",
            "}",
            "",
            "function Test-TcpPort($ip, $port, $label) {",
            "    $script:TotalChecks++",
            "    $client = New-Object System.Net.Sockets.TcpClient",
            "    try {",
            "        $async = $client.BeginConnect($ip, $port, $null, $null)",
            "        $wait = $async.AsyncWaitHandle.WaitOne(2000, $false)",
            "        if ($wait -and $client.Connected) {",
            "            $client.EndConnect($async)",
            '            Write-Host "  [PASS] TCP Service: $label ($ip:$port)" -ForegroundColor Green',
            "            $script:PassedChecks++",
            "        } else {",
            '            Write-Host "  [WARN] TCP Service: $label ($ip:$port) closed or firewalled." -ForegroundColor Yellow',
            "        }",
            "    } catch {",
            '        Write-Host "  [WARN] TCP Service: $label ($ip:$port) closed or firewalled." -ForegroundColor Yellow',
            "    } finally {",
            "        $client.Close()",
            "    }",
            "}",
            "",
            'Write-Host "`n[*] Phase 1: Verifying Layer 3 Gateway & SVI Reachability..." -ForegroundColor Cyan',
        ]
        for gw in sorted(gateways):
            if _is_safe_target_addr(gw):
                ps1_lines.append(f'Test-PingReachability -ip "{gw}" -label "Gateway / SVI"')

        ps1_lines.extend(
            [
                "",
                'Write-Host "`n[*] Phase 2: Verifying Core DNS Resolvers..." -ForegroundColor Cyan',
            ]
        )
        for dns in sorted(dns_servers):
            if _is_safe_target_addr(dns):
                ps1_lines.append(f'Test-PingReachability -ip "{dns}" -label "DNS Resolver"')
                ps1_lines.append(f'Test-TcpPort -ip "{dns}" -port 53 -label "DNS Port 53"')

        ps1_lines.extend(
            [
                "",
                'Write-Host "`n[*] Phase 3: Verifying Management Services (SSH Port 22)..." -ForegroundColor Cyan',
            ]
        )
        for dev in devices.values():
            if not _is_network_infra(dev) or str(dev.get("record_class") or "").strip().lower() not in (
                "",
                "crawled_infra",
            ):
                continue
            dev_ip = dev.get("ip")
            dev_host = dev.get("hostname") or dev_ip
            if _is_safe_target_addr(dev_ip):
                safe_host_ps = _escape_ps_dq(dev_host)
                ps1_lines.append(f'Test-TcpPort -ip "{dev_ip}" -port 22 -label "{safe_host_ps} SSH"')

        ps1_lines.extend(
            [
                "",
                'Write-Host "`n================================================================" -ForegroundColor Cyan',
                'Write-Host " Validation Summary: $PassedChecks / $TotalChecks Checks Passed" -ForegroundColor Cyan',
                'Write-Host "================================================================" -ForegroundColor Cyan',
                "",
                "if ($FailedChecks -eq 0) {",
                '    Write-Host "`n[OK] CUTOVER SMOKE TEST SUCCESSFUL: All critical gateways online.`n" -ForegroundColor Green',
                "    exit 0",
                "} else {",
                '    Write-Host "`n[WARN] CUTOVER VERIFICATION WARNING: $FailedChecks check(s) failed.`n" -ForegroundColor Red',
                "    exit 1",
                "}",
            ]
        )
        with open(ps1_path, "w", encoding="utf-8") as f:
            f.write("\r\n".join(ps1_lines) + "\r\n")
        print(f"[+] Cross-platform PowerShell cutover script written to: {ps1_path}")
    except Exception as e:
        print(f"[-] Error writing cutover validation script: {e}")


def _recommend_replacement_sku(dev: dict, total_ports: int, poe_budget_w: float, target_vendor: str = "juniper") -> str:
    """Recommend a replacement hardware SKU for the target vendor (defaults to Juniper)."""
    tv = (target_vendor or "juniper").strip().lower()
    dtype = (dev.get("device_type") or "switch").lower()
    model_l = (dev.get("model") or "").lower()
    host_l = (dev.get("hostname") or "").lower()
    has_poe = poe_budget_w > 0 or bool((dev.get("poe") or {}).get("ports"))
    is_core = (
        "core" in host_l
        or "5412" in model_l
        or "5406" in model_l
        or "ex4600" in model_l
        or len(dev.get("l3_interfaces", []) or []) >= 5
        or len(dev.get("routes", []) or []) >= 10
    )

    if tv in ("cisco", "cisco_ios", "cisco_xe"):
        if dtype == "firewall":
            return "FPR-1120"
        if dtype == "router":
            return "C8300-1N1S-4T2X"
        if is_core:
            return "C9500-48Y4C" if not has_poe else "C9300-48P"
        if total_ports <= 28:
            return "C9200L-24P-4X" if has_poe else "C9200L-24T-4X"
        return "C9200L-48P-4X" if has_poe else "C9200L-48T-4X"

    if tv in ("arista", "arista_eos"):
        if is_core:
            return "DCS-7050SX3-48YC8"
        if total_ports <= 28:
            return "CCS-720XP-24ZY4" if has_poe else "CCS-720XP-24Y6"
        return "CCS-720XP-48ZC2" if has_poe else "CCS-720XP-48Y6"

    if tv in ("hpprocurve", "procurve", "hp", "aruba"):
        if is_core:
            return "Aruba CX 6300M 48G PoE+" if has_poe else "Aruba CX 8325-48Y8C"
        if total_ports <= 28:
            return "Aruba CX 6200F 24G PoE+" if has_poe else "Aruba CX 6200F 24G"
        return "Aruba CX 6200F 48G PoE+" if has_poe else "Aruba CX 6200F 48G"

    # Default: Juniper Networks
    if dtype == "firewall":
        return "SRX345" if total_ports <= 16 else "SRX1500"
    if dtype == "router":
        return "MX204"
    if is_core:
        if "ex4600" in model_l or (not has_poe and len(dev.get("optics", []) or []) >= 8):
            return "EX4600-40F"
        return "EX4400-48P" if has_poe else "EX4650-48Y"
    if total_ports <= 12:
        return "EX2300-C-12P" if has_poe else "EX2300-C-12T"
    if total_ports <= 28:
        return "EX3400-24P" if has_poe else "EX3400-24T"
    return "EX3400-48P" if has_poe else "EX3400-48T"


def generate_bom_hardware_sizing(devices, output_path="bom_hardware_sizing.csv", target_vendor="juniper"):
    """
    Generate a hardware sizing & Bill-of-Materials (BOM) CSV aggregating per-device
    port counts, PoE wattage budgets/draw, SFP/SFP+/QSFP transceiver totals, and
    recommended replacement SKUs (defaulting to Juniper).
    """
    fields = [
        "Hostname",
        "IP Address",
        "Vendor",
        "Model",
        "Device Type",
        "Total Ports",
        "Active Ports",
        "PoE Budget (W)",
        "PoE Used (W)",
        "PoE Active Ports",
        "Optics Count",
        "Optics Breakdown",
        "Recommended SKU",
    ]
    try:
        infra_devices = {ip: dev for ip, dev in devices.items() if _is_network_infra(dev)}
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for ip, dev in infra_devices.items():
                ints_detail = dev.get("interfaces_detail", {}) or {}
                total_ports = len(ints_detail)
                active_ports = sum(1 for d in ints_detail.values() if str(d.get("status", "")).lower() == "up")
                poe = dev.get("poe", {}) or {}
                tot_w = float(poe.get("total_power_watts", 0.0) or 0.0)
                used_w = float(poe.get("used_power_watts", 0.0) or 0.0)
                poe_ports = poe.get("poe_delivering_ports")
                if poe_ports is None:
                    poe_ports = len(poe.get("ports", {}) or {})
                optics = dev.get("optics", []) or []
                opt_counts: dict[str, int] = {}
                for opt in optics:
                    otype = str(opt.get("type") or opt.get("part_number") or "SFP").strip()
                    opt_counts[otype] = opt_counts.get(otype, 0) + 1
                opt_str = "; ".join(f"{k}:{v}" for k, v in sorted(opt_counts.items())) or "None"
                rec_sku = _recommend_replacement_sku(dev, total_ports, tot_w, target_vendor=target_vendor)
                writer.writerow(
                    _sanitize_csv_row(
                        {
                            "Hostname": dev.get("hostname") or ip,
                            "IP Address": ip,
                            "Vendor": dev.get("vendor") or "Unknown",
                            "Model": dev.get("model") or "Unknown",
                            "Device Type": dev.get("device_type") or "unknown",
                            "Total Ports": total_ports,
                            "Active Ports": active_ports,
                            "PoE Budget (W)": f"{tot_w:.1f}",
                            "PoE Used (W)": f"{used_w:.1f}",
                            "PoE Active Ports": poe_ports,
                            "Optics Count": len(optics),
                            "Optics Breakdown": opt_str,
                            "Recommended SKU": rec_sku,
                        }
                    )
                )
        print(f"BOM & hardware sizing CSV successfully written to {output_path}")
    except Exception as e:
        logger.error("Error generating BOM hardware sizing CSV at %s: %s", output_path, e, exc_info=True)
        print(f"Error generating BOM hardware sizing CSV: {e}")


def generate_target_migration_configs(
    devices,
    target_vendor="juniper",
    output_path="target_migration_configs.md",
):
    """
    Generate vendor-neutral staged CLI configuration snippets for migrating
    mixed-vendor devices onto a single target vendor (`juniper`, `cisco`, `arista`, `hpprocurve`).
    """
    from net_docu_crawler.target_adapters import render_device_target_config

    tv = (target_vendor or "juniper").strip().lower()
    lines = [
        f"# Target Vendor Migration Configs (`{tv}`)",
        "",
        "Generated from normalized device intent (`ports`, `l3_interfaces`, `port_profiles`, `routes`, `services`, `dhcp`).",
        "",
    ]
    for ip, dev in devices.items():
        if dev.get("status") != "success":
            continue
        hostname = dev.get("hostname") or ip
        lines.append(f"## {hostname} ({dev.get('vendor', 'Unknown')} `{dev.get('model', '')}` -> `{tv}`)")
        lines.append("```json" if tv == "meraki" else "```text")
        if dev.get("ports") and tv in ("juniper", "meraki", "aruba", "arista", "cisco"):
            rendered = render_device_target_config(dev, tv)
            if isinstance(rendered, list):
                lines.extend(rendered)
            else:
                lines.append(str(rendered))
            lines.append("```")
            lines.append("")
            continue
        services = dev.get("services", {}) or {}
        port_profiles = dev.get("port_profiles", {}) or {}
        l3_ints = dev.get("l3_interfaces", []) or []

        if tv in ("cisco", "arista"):
            lines.append(f"hostname {hostname}")
            for ntp in services.get("ntp_servers", []):
                lines.append(f"ntp server {ntp}")
            for dns in services.get("dns_servers", []):
                lines.append(f"ip name-server {dns}")
            for intf in l3_ints[:20]:
                iname = intf.get("interface", "")
                ip_str = intf.get("ip_address", "")
                if iname and ip_str:
                    lines.append(f"! Source L3: {iname} -> {ip_str}")
            for port, prof in list(port_profiles.items())[:48]:
                lines.append(f"interface {port}")
                if prof.get("mode") == "access" and prof.get("access_vlan"):
                    lines.append(" switchport mode access")
                    lines.append(f" switchport access vlan {prof['access_vlan']}")
                    if prof.get("voice_vlan"):
                        lines.append(f" switchport voice vlan {prof['voice_vlan']}")
                elif prof.get("mode") == "trunk":
                    lines.append(" switchport mode trunk")
                    if prof.get("trunk_allowed_vlans"):
                        lines.append(f" switchport trunk allowed vlan {prof['trunk_allowed_vlans']}")
        elif tv == "juniper":
            lines.append(f"set system host-name {hostname}")
            for ntp in services.get("ntp_servers", []):
                lines.append(f"set system ntp server {ntp}")
            for dns in services.get("dns_servers", []):
                lines.append(f"set system name-server {dns}")
            for port, prof in list(port_profiles.items())[:48]:
                if prof.get("mode") == "access" and prof.get("access_vlan"):
                    lines.append(f"set interfaces {port} unit 0 family ethernet-switching interface-mode access")
                    lines.append(
                        f"set interfaces {port} unit 0 family ethernet-switching vlan members {prof['access_vlan']}"
                    )
                elif prof.get("mode") == "trunk":
                    lines.append(f"set interfaces {port} unit 0 family ethernet-switching interface-mode trunk")
                    if prof.get("trunk_allowed_vlans"):
                        lines.append(
                            f"set interfaces {port} unit 0 family ethernet-switching vlan members [{prof['trunk_allowed_vlans'].replace(',', ' ')}]"
                        )
        elif tv in ("hpprocurve", "procurve", "hp"):
            lines.append(f'hostname "{hostname}"')
            for ntp in services.get("ntp_servers", []):
                lines.append(f"sntp server priority 1 {ntp}")
            for dns in services.get("dns_servers", []):
                lines.append(f"ip dns server-address priority 1 {dns}")
            for port, prof in list(port_profiles.items())[:48]:
                if prof.get("mode") == "access" and prof.get("access_vlan"):
                    lines.append(f"vlan {prof['access_vlan']} untagged {port}")
                elif prof.get("mode") == "trunk" and prof.get("trunk_allowed_vlans"):
                    for vid in prof["trunk_allowed_vlans"].split(","):
                        if vid.strip().isdigit():
                            lines.append(f"vlan {vid.strip()} tagged {port}")
        else:
            lines.append(f"# Unsupported target_vendor={tv}")
        lines.append("```")
        lines.append("")

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Target migration configs written to {output_path}")
    except Exception as e:
        print(f"Error generating target migration configs: {e}")


def _export_failures_csv(raw_devices: list[dict], manifest_dir: str) -> None:
    """Write 00_manifest/failures.csv for unauthenticated, unsupported, or discovered hosts."""
    fail_fields = [
        "ip",
        "status",
        "record_class",
        "vendor",
        "device_type",
        "mgmt_method",
        "model",
        "mac_address",
        "capture_time",
    ]
    fail_rows = [
        {
            "ip": d.get("ip", ""),
            "status": d.get("status", ""),
            "record_class": d.get("record_class", ""),
            "vendor": d.get("vendor", "Unknown"),
            "device_type": d.get("device_type", "unknown"),
            "mgmt_method": d.get("mgmt_method", ""),
            "model": d.get("model", ""),
            "mac_address": d.get("mac_address", ""),
            "capture_time": d.get("capture_time", ""),
        }
        for d in raw_devices
        if d.get("status") in ("unauthenticated", "unsupported", "discovered")
    ]
    with open(os.path.join(manifest_dir, "failures.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fail_fields)
        w.writeheader()
        w.writerows(_sanitize_csv_row(r) for r in fail_rows)


def _export_interfaces_csv(infra: list[dict], norm_dir: str, corr_dir: str) -> None:
    """Write 02_normalized/interfaces.csv and 03_correlated/unused_ports.csv."""
    iface_fields = [
        "hostname",
        "interface",
        "admin_state",
        "oper_state",
        "mode",
        "access_vlan",
        "voice_vlan",
        "native_vlan",
        "allowed_vlans",
        "lag_id",
        "lacp_mode",
        "speed",
        "duplex",
        "media",
        "neighbor_hostname",
        "neighbor_port",
        "stp_edge",
        "bpdu_guard",
        "storm_control",
        "poe_draw_watts",
        "edge_mac_count",
        "hygiene_disposition",
        "hygiene_reason",
    ]
    iface_rows = []
    unused_rows = []
    for d in infra:
        for p_rec in (d.get("ports") or {}).values():
            raw_allowed = p_rec.get("allowed_vlans") or []
            allowed_str = (
                ",".join(str(v).strip() for v in raw_allowed if str(v).strip())
                if isinstance(raw_allowed, (list, tuple, set))
                else str(raw_allowed).strip()
            )
            row = {
                "hostname": p_rec.get("hostname", ""),
                "interface": p_rec.get("interface", ""),
                "admin_state": p_rec.get("admin_state", ""),
                "oper_state": p_rec.get("oper_state", ""),
                "mode": p_rec.get("mode", ""),
                "access_vlan": p_rec.get("access_vlan", ""),
                "voice_vlan": p_rec.get("voice_vlan", ""),
                "native_vlan": p_rec.get("native_vlan", ""),
                "allowed_vlans": allowed_str,
                "lag_id": p_rec.get("lag_id", ""),
                "lacp_mode": p_rec.get("lacp_mode", ""),
                "speed": p_rec.get("speed_operational", ""),
                "duplex": p_rec.get("duplex", ""),
                "media": p_rec.get("media", ""),
                "neighbor_hostname": p_rec.get("neighbor_hostname", ""),
                "neighbor_port": p_rec.get("neighbor_port", ""),
                "stp_edge": p_rec.get("stp_edge", ""),
                "bpdu_guard": p_rec.get("bpdu_guard", ""),
                "storm_control": p_rec.get("storm_control", ""),
                "poe_draw_watts": p_rec.get("poe_draw_watts", 0.0),
                "edge_mac_count": p_rec.get("edge_mac_count", 0),
                "hygiene_disposition": p_rec.get("hygiene_disposition", ""),
                "hygiene_reason": p_rec.get("hygiene_reason", ""),
            }
            sanitized = _sanitize_csv_row(row)
            iface_rows.append(sanitized)
            if row["hygiene_disposition"] in ("SHUTDOWN", "QUARANTINE", "REVIEW"):
                unused_rows.append(sanitized)

    with open(os.path.join(norm_dir, "interfaces.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=iface_fields)
        w.writeheader()
        w.writerows(iface_rows)
    with open(os.path.join(corr_dir, "unused_ports.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=iface_fields)
        w.writeheader()
        w.writerows(unused_rows)


def _export_vlans_and_svi_csvs(infra: list[dict], norm_dir: str) -> list[dict]:
    """Write 02_normalized/vlans.csv and 02_normalized/svi_routes.csv; return correlated SVI rows."""
    from net_docu_crawler.correlator import build_l3_svi_table

    vlan_rows = [
        _sanitize_csv_row(
            {
                "hostname": d.get("hostname") or d.get("ip", ""),
                "site_code": d.get("site_code", ""),
                "vlan_id": vid,
                "vlan_name": vinfo.get("name", ""),
                "svi_interface": vinfo.get("svi_interface", ""),
                "voice": vinfo.get("voice", False),
            }
        )
        for d in infra
        for vid, vinfo in (d.get("vlans") or {}).items()
    ]
    with open(os.path.join(norm_dir, "vlans.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["hostname", "site_code", "vlan_id", "vlan_name", "svi_interface", "voice"])
        w.writeheader()
        w.writerows(vlan_rows)

    svi_rows = build_l3_svi_table(infra)
    svi_fields = [
        "site_code",
        "source_device",
        "vlan_id",
        "vlan_name",
        "vlan_description",
        "svi_interface",
        "primary_ip",
        "prefix_cidr",
        "dhcp_relays",
        "confidence",
    ]
    with open(os.path.join(norm_dir, "svi_routes.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=svi_fields, extrasaction="ignore")
        w.writeheader()
        for sr in svi_rows:
            row = dict(sr)
            row.setdefault("vlan_description", "")
            raw_relays = sr.get("dhcp_relays") or []
            row["dhcp_relays"] = (
                ",".join(str(r).strip() for r in raw_relays if str(r).strip())
                if isinstance(raw_relays, (list, tuple, set))
                else str(raw_relays).strip()
            )
            w.writerow(_sanitize_csv_row(row))
    return svi_rows


def _export_poe_csv(infra: list[dict], norm_dir: str) -> None:
    """Write 02_normalized/poe.csv with per-device PoE budget and draw."""
    poe_fields = [
        "hostname",
        "ip",
        "poe_supported",
        "total_power_watts",
        "used_power_watts",
        "allocated_power_watts",
        "poe_capable_ports",
        "poe_delivering_ports",
        "psu_redundancy",
    ]
    with open(os.path.join(norm_dir, "poe.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=poe_fields)
        w.writeheader()
        for d in infra:
            poe = d.get("poe") or {}
            w.writerow(
                _sanitize_csv_row(
                    {
                        "hostname": d.get("hostname") or d.get("ip", ""),
                        "ip": d.get("ip", ""),
                        "poe_supported": poe.get("poe_supported", False),
                        "total_power_watts": poe.get("total_power_watts", 0.0),
                        "used_power_watts": poe.get("used_power_watts", 0.0),
                        "allocated_power_watts": poe.get("allocated_power_watts", 0.0),
                        "poe_capable_ports": poe.get("poe_capable_ports", 0),
                        "poe_delivering_ports": poe.get("poe_delivering_ports", 0),
                        "psu_redundancy": poe.get("psu_redundancy", "unknown"),
                    }
                )
            )


def _export_neighbors_csv(infra: list[dict], norm_dir: str) -> None:
    """Write 02_normalized/neighbors.csv with normalized LLDP/CDP adjacencies."""
    nbr_fields = [
        "source_device",
        "site_code",
        "local_port",
        "remote_device",
        "remote_port",
        "remote_ip",
        "remote_mac",
        "platform",
        "device_type",
        "link_confidence",
        "capture_time",
    ]
    with open(os.path.join(norm_dir, "neighbors.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=nbr_fields)
        w.writeheader()
        for d in infra:
            host = d.get("hostname") or d.get("ip", "")
            sc = d.get("site_code", "")
            ct = d.get("capture_time", "")
            for nbr in d.get("neighbors") or []:
                w.writerow(
                    _sanitize_csv_row(
                        {
                            "source_device": host,
                            "site_code": sc,
                            "local_port": nbr.get("local_port", ""),
                            "remote_device": nbr.get("remote_device", ""),
                            "remote_port": nbr.get("remote_port", ""),
                            "remote_ip": nbr.get("remote_ip", ""),
                            "remote_mac": nbr.get("remote_mac", ""),
                            "platform": nbr.get("platform", ""),
                            "device_type": nbr.get("device_type", ""),
                            "link_confidence": nbr.get("link_confidence", ""),
                            "capture_time": ct,
                        }
                    )
                )


def _export_raw_device_artifacts(infra: list[dict], raw_dir: str, run_output_dir: str, source_logs_dir: str) -> None:
    """Write 01_raw/*_running_config.txt and copy raw session logs if present."""
    cand_dirs = [d_c for d_c in (source_logs_dir, run_output_dir, os.path.join(run_output_dir, "logs")) if d_c]
    for d in infra:
        host = re.sub(r"[^A-Za-z0-9._-]+", "_", str(d.get("hostname") or d.get("ip") or "device"))
        ip_safe = str(d.get("ip") or "").replace(":", "_")
        prefix = f"{host}__{ip_safe}" if ip_safe else host
        raw_cfg = d.get("raw_config") or ""
        if raw_cfg:
            with open(os.path.join(raw_dir, f"{prefix}_running_config.txt"), "w", encoding="utf-8") as f:
                f.write(raw_cfg)
        if ip_safe:
            for cand_dir in cand_dirs:
                src_log = os.path.join(cand_dir, f"{ip_safe}_raw_session.log")
                if os.path.isfile(src_log):
                    shutil.copy2(src_log, os.path.join(raw_dir, f"{prefix}_raw_session.log"))
                    break


def _export_physical_links_and_endpoints_csvs(registry, corr_dir: str, run_output_dir: str) -> None:
    """Write 03_correlated/physical_links.csv and copy endpoint_bindings.csv if present."""
    with open(os.path.join(corr_dir, "physical_links.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "node_a",
                "port_a",
                "node_b",
                "port_b",
                "status",
                "type",
                "link_class",
                "transport_type",
                "evidence",
            ],
            extrasaction="ignore",
        )
        w.writeheader()
        for lk in getattr(registry, "links", []) or []:
            row = dict(lk)
            row.setdefault("link_class", "infra_uplink")
            row.setdefault("transport_type", "")
            row.setdefault("evidence", "")
            w.writerow(_sanitize_csv_row(row))

    ep_src = os.path.join(run_output_dir, "port_mac_endpoint_mapping.csv")
    if os.path.isfile(ep_src):
        shutil.copy2(ep_src, os.path.join(corr_dir, "endpoint_bindings.csv"))


def _export_vlan_propagation_csv(infra: list[dict], svi_rows: list[dict], corr_dir: str) -> None:
    """Write 03_correlated/vlan_propagation.csv summarizing campus VLAN/trunk reach."""
    svi_by_site_vid = {(sr.get("site_code", ""), str(sr.get("vlan_id", ""))): sr for sr in svi_rows}
    vlan_prop: dict[tuple[str, str], dict] = {}
    for d in infra:
        host = d.get("hostname") or d.get("ip", "")
        sc = d.get("site_code", "")
        for vid, vinfo in (d.get("vlans") or {}).items():
            key = (sc, str(vid))
            entry = vlan_prop.setdefault(
                key,
                {
                    "site_code": sc,
                    "vlan_id": str(vid),
                    "vlan_name": vinfo.get("name", ""),
                    "switches": set(),
                    "trunk_ports": set(),
                },
            )
            entry["switches"].add(host)
        for p_rec in (d.get("ports") or {}).values():
            if p_rec.get("mode") == "trunk":
                for vid in p_rec.get("allowed_vlans") or []:
                    key = (sc, str(vid))
                    if key in vlan_prop:
                        vlan_prop[key]["trunk_ports"].add(f"{host}:{p_rec.get('interface', '')}")

    prop_fields = [
        "site_code",
        "vlan_id",
        "vlan_name",
        "svi_device",
        "gateway_ip",
        "subnet",
        "switch_count",
        "trunk_port_count",
        "trunk_ports",
    ]
    with open(os.path.join(corr_dir, "vlan_propagation.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=prop_fields)
        w.writeheader()
        for key in sorted(vlan_prop.keys(), key=lambda x: (x[0], int(x[1]) if x[1].isdigit() else 99999)):
            vp = vlan_prop[key]
            sr = svi_by_site_vid.get(key, {})
            tports = sorted(vp["trunk_ports"])
            w.writerow(
                _sanitize_csv_row(
                    {
                        "site_code": vp["site_code"],
                        "vlan_id": vp["vlan_id"],
                        "vlan_name": sr.get("vlan_name") or vp["vlan_name"],
                        "svi_device": sr.get("source_device", ""),
                        "gateway_ip": sr.get("primary_ip", ""),
                        "subnet": sr.get("prefix_cidr", ""),
                        "switch_count": len(vp["switches"]),
                        "trunk_port_count": len(tports),
                        "trunk_ports": ";".join(tports[:25]),
                    }
                )
            )


def _export_trunk_audit_artifacts(
    raw_devices: list[dict], trunk_audit: dict | None, corr_dir: str, rep_dir: str
) -> None:
    """Write trunk_audit.json, trunk_mismatches.csv, and 05_reports/trunk_vlan_audit.md."""
    resolved_audit = trunk_audit if trunk_audit is not None else _resolve_trunk_audit(raw_devices)
    with open(os.path.join(corr_dir, "trunk_audit.json"), "w", encoding="utf-8") as f:
        json.dump(resolved_audit, f, indent=2, default=list)

    trunk_csv_rows = _normalize_trunk_csv_rows(resolved_audit)
    with open(os.path.join(corr_dir, "trunk_mismatches.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TRUNK_MISMATCH_CSV_FIELDS)
        w.writeheader()
        w.writerows(_sanitize_csv_row(r) for r in trunk_csv_rows)

    layered_trunk_md = os.path.join(rep_dir, "trunk_vlan_audit.md")
    if not os.path.isfile(layered_trunk_md):
        generate_trunk_audit_report(resolved_audit, output_path=layered_trunk_md)


def export_layered_csvs(
    raw_devices: list[dict],
    registry,
    run_output_dir: str,
    source_logs_dir: str = "",
    trunk_audit: dict | None = None,
) -> None:
    """
    Export normalized and correlated machine-readable CSVs into the layered
    `00_manifest/`, `01_raw/`, `02_normalized/`, and `03_correlated/` subdirectories.
    """
    m_dir = os.path.join(run_output_dir, "00_manifest")
    r_dir = os.path.join(run_output_dir, "01_raw")
    n_dir = os.path.join(run_output_dir, "02_normalized")
    c_dir = os.path.join(run_output_dir, "03_correlated")
    rep_dir = os.path.join(run_output_dir, "05_reports")
    for d in (m_dir, r_dir, n_dir, c_dir, rep_dir):
        os.makedirs(d, exist_ok=True)

    _export_failures_csv(raw_devices, m_dir)
    infra = [
        d
        for d in raw_devices
        if _is_network_infra(d) and str(d.get("record_class") or "").strip().lower() in ("", "crawled_infra")
    ]
    _export_interfaces_csv(infra, n_dir, c_dir)
    svi_rows = _export_vlans_and_svi_csvs(infra, n_dir)
    _export_poe_csv(infra, n_dir)
    _export_physical_links_and_endpoints_csvs(registry, c_dir, run_output_dir)
    _export_raw_device_artifacts(infra, r_dir, run_output_dir, source_logs_dir)
    _export_neighbors_csv(infra, n_dir)
    _export_vlan_propagation_csv(infra, svi_rows, c_dir)
    _export_trunk_audit_artifacts(raw_devices, trunk_audit, c_dir, rep_dir)


TRUNK_MISMATCH_CSV_FIELDS = [
    "Edge_ID",
    "Side_A_Host",
    "Side_A_Port",
    "Side_B_Host",
    "Side_B_Port",
    "Rule_ID",
    "Severity",
    "Side_A_Only_VLANs",
    "Side_B_Only_VLANs",
    "Remediation_Hint",
]


def _resolve_trunk_audit(devices_or_audit) -> dict:
    """Resolve `devices_or_audit` into a canonical `evaluate_trunk_mismatches` result dict."""
    from net_docu_crawler.trunk_audit import evaluate_trunk_mismatches

    if isinstance(devices_or_audit, dict):
        if "summary" in devices_or_audit and ("findings" in devices_or_audit or "csv_rows" in devices_or_audit):
            return devices_or_audit
        return evaluate_trunk_mismatches(list(devices_or_audit.values()))
    if isinstance(devices_or_audit, list):
        return evaluate_trunk_mismatches(devices_or_audit)
    return evaluate_trunk_mismatches([])


def _format_vlan_cell(val) -> str:
    if val is None:
        return ""
    if isinstance(val, (list, set, tuple)):
        return ",".join(str(v) for v in sorted(val, key=lambda x: int(str(x)) if str(x).isdigit() else 99999))
    return str(val).strip()


def _normalize_trunk_csv_rows(trunk_audit: dict) -> list[dict]:
    """Normalize trunk audit findings/csv_rows to match TRUNK_MISMATCH_CSV_FIELDS."""
    raw_rows = (trunk_audit or {}).get("csv_rows")
    if isinstance(raw_rows, list) and raw_rows:
        norm_rows = []
        for r in raw_rows:
            if not isinstance(r, dict):
                continue
            norm_rows.append(
                {
                    "Edge_ID": str(r.get("Edge_ID", r.get("edge_id", "")) or ""),
                    "Side_A_Host": str(r.get("Side_A_Host", r.get("side_a_host", "")) or ""),
                    "Side_A_Port": str(r.get("Side_A_Port", r.get("side_a_port", "")) or ""),
                    "Side_B_Host": str(r.get("Side_B_Host", r.get("side_b_host", "")) or ""),
                    "Side_B_Port": str(r.get("Side_B_Port", r.get("side_b_port", "")) or ""),
                    "Rule_ID": str(r.get("Rule_ID", r.get("rule_id", "")) or ""),
                    "Severity": str(r.get("Severity", r.get("severity", "")) or ""),
                    "Side_A_Only_VLANs": _format_vlan_cell(r.get("Side_A_Only_VLANs", r.get("side_a_only_vlans", ""))),
                    "Side_B_Only_VLANs": _format_vlan_cell(r.get("Side_B_Only_VLANs", r.get("side_b_only_vlans", ""))),
                    "Remediation_Hint": str(
                        r.get("Remediation_Hint", r.get("remediation_hint", r.get("remediation", ""))) or ""
                    ),
                }
            )
        return norm_rows

    findings = (trunk_audit or {}).get("findings") or []
    norm_rows = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        side_a = f.get("side_a") or {}
        side_b = f.get("side_b") or {}
        norm_rows.append(
            {
                "Edge_ID": str(f.get("Edge_ID", f.get("edge_id", "")) or ""),
                "Side_A_Host": str(
                    f.get(
                        "Side_A_Host",
                        f.get("side_a_host", side_a.get("device_hostname", side_a.get("hostname", ""))),
                    )
                    or ""
                ),
                "Side_A_Port": str(
                    f.get("Side_A_Port", f.get("side_a_port", side_a.get("interface_name", side_a.get("port", ""))))
                    or ""
                ),
                "Side_B_Host": str(
                    f.get(
                        "Side_B_Host",
                        f.get("side_b_host", side_b.get("device_hostname", side_b.get("hostname", ""))),
                    )
                    or ""
                ),
                "Side_B_Port": str(
                    f.get("Side_B_Port", f.get("side_b_port", side_b.get("interface_name", side_b.get("port", ""))))
                    or ""
                ),
                "Rule_ID": str(f.get("Rule_ID", f.get("rule_id", "")) or ""),
                "Severity": str(f.get("Severity", f.get("severity", "")) or ""),
                "Side_A_Only_VLANs": _format_vlan_cell(f.get("Side_A_Only_VLANs", f.get("side_a_only_vlans", ""))),
                "Side_B_Only_VLANs": _format_vlan_cell(f.get("Side_B_Only_VLANs", f.get("side_b_only_vlans", ""))),
                "Remediation_Hint": str(
                    f.get("Remediation_Hint", f.get("remediation_hint", f.get("remediation", f.get("detail", ""))))
                    or ""
                ),
            }
        )
    return norm_rows


def _extract_mac_from_hostname(host: str) -> str:
    """Extract a 12-hex MAC embedded in hostnames like ``d65-000fd30aae2f``."""
    m = re.search(r"([0-9a-fA-F]{12})$", (host or "").strip())
    if not m:
        return ""
    raw = m.group(1).lower()
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def _classify_oui_role(vendor_oui: str, dtype: str = "", platform: str = "") -> str:
    """Classify a peer's OUI + type into a concise role label such as ``[AP]`` or ``[Phone]``."""
    hay = f"{vendor_oui} {dtype} {platform}".lower()
    if dtype.lower() == "ap" or any(h in hay for h in _AP_OUI_HINTS):
        return f"{vendor_oui or 'Wireless'} [AP]"
    if (
        dtype.lower() in ("phone", "voip")
        or any(h in hay for h in _PHONE_OUI_HINTS)
        or re.match(r"^(?:d\d+|p\d+)-[0-9a-f]{12}$", platform.lower())
    ):
        return f"{vendor_oui or 'VoIP'} [Phone]"
    if dtype.lower() in ("switch", "router", "firewall"):
        return f"{vendor_oui or dtype.title()} [{dtype.title()}]"
    return vendor_oui or "Unknown"


def _build_host_oui_role_lookup(devices: dict | None) -> dict[str, str]:
    """Build a lowercase hostname/IP -> OUI/role lookup table from crawled devices and LLDP neighbors."""
    lookup: dict[str, str] = {}
    if not isinstance(devices, dict):
        return lookup
    for ip, dev in devices.items():
        if not isinstance(dev, dict):
            continue
        hn = str(dev.get("hostname") or ip).strip().lower()
        dtype = str(dev.get("device_type") or dev.get("device_persona") or "").strip()
        mac = str(dev.get("mac_address") or "").strip()
        oui_v = oui_lookup.lookup_oui(mac) if mac else ""
        if not oui_v or oui_v == "Unknown":
            oui_v = str(dev.get("vendor") or "")
        role = _classify_oui_role(oui_v, dtype=dtype, platform=str(dev.get("model") or ""))
        for key in {str(ip).lower(), hn, hn.split(".")[0]}:
            if key:
                lookup[key] = role
        for nbr in dev.get("neighbors") or []:
            rh = str(nbr.get("remote_device") or "").strip().lower()
            rip = str(nbr.get("remote_ip") or "").strip().lower()
            rmac = str(nbr.get("remote_mac") or "").strip()
            rplat = str(nbr.get("platform") or nbr.get("remote_platform") or "")
            rdtype = str(nbr.get("device_type") or "")
            if not rmac and rh:
                rmac = _extract_mac_from_hostname(rh)
            roui = oui_lookup.lookup_oui(rmac) if rmac else ""
            if not roui or roui == "Unknown":
                roui = rplat
            n_role = _classify_oui_role(roui, dtype=rdtype, platform=rh or rplat)
            for key in {rh, rh.split(".")[0], rip}:
                if key and (key not in lookup or lookup[key] == "Unknown"):
                    lookup[key] = n_role
    return lookup


def _resolve_trunk_peer_oui_role(host_a: str, host_b: str, lookup: dict[str, str]) -> str:
    """Resolve the most informative peer OUI/role for a trunk discrepancy row."""
    for h in (host_a, host_b):
        hl = (h or "").strip().lower()
        if not hl:
            continue
        if hl in lookup and lookup[hl] != "Unknown":
            val = lookup[hl]
            if "[AP]" in val or "[Phone]" in val:
                return val
        mac_h = _extract_mac_from_hostname(hl)
        if mac_h:
            oui_v = oui_lookup.lookup_oui(mac_h)
            if oui_v and oui_v != "Unknown":
                return _classify_oui_role(oui_v, platform=hl)
    for h in (host_a, host_b):
        hl = (h or "").strip().lower()
        if hl in lookup and lookup[hl] != "Unknown":
            return lookup[hl]
    return "Unknown"


def _build_trunk_audit_markdown_section(
    devices_or_audit,
    heading: str = "### Trunk VLAN Mismatch & L2 Symmetry Audit",
    peer_lookup: dict[str, str] | None = None,
) -> list[str]:
    """Build a concise Markdown summary table for trunk VLAN mismatch & L2 symmetry findings."""
    audit = _resolve_trunk_audit(devices_or_audit)
    summary = (audit or {}).get("summary") or {}
    rows = _normalize_trunk_csv_rows(audit)
    if peer_lookup is None and isinstance(devices_or_audit, dict) and "findings" not in devices_or_audit:
        peer_lookup = _build_host_oui_role_lookup(devices_or_audit)
    peer_lookup = peer_lookup or {}

    ap_phone_cnt = 0
    for r in rows:
        role_str = _resolve_trunk_peer_oui_role(r["Side_A_Host"], r["Side_B_Host"], peer_lookup)
        r["Peer_OUI_Role"] = role_str
        if "[AP]" in role_str or "[Phone]" in role_str:
            ap_phone_cnt += 1

    edges_eval = int(
        summary.get(
            "total_trunk_edges_evaluated",
            summary.get("edges_evaluated", summary.get("total_edges", 0)),
        )
        or 0
    )
    crit_cnt = int(summary.get("critical_count", 0) or 0)
    high_cnt = int(summary.get("high_count", 0) or 0)
    med_cnt = int(summary.get("medium_count", 0) or 0)
    low_cnt = int(summary.get("low_count", 0) or 0)
    info_cnt = int(summary.get("info_count", 0) or 0)
    total_cnt = int(summary.get("total_findings", len(rows)) or 0)

    sec_lines = [
        "",
        heading,
        (
            f"Evaluated Trunk Links: **{edges_eval}** | Total Findings: **{total_cnt}** "
            f"(CRITICAL: **{crit_cnt}**, HIGH: **{high_cnt}**, MEDIUM: **{med_cnt}**, "
            f"LOW: **{low_cnt}**, INFO: **{info_cnt}**) | "
            f"AP/Phone Edge Findings (Safe to Ignore): **{ap_phone_cnt}**"
        ),
        "",
        "| Edge_ID | Side_A_Host | Side_A_Port | Side_B_Host | Side_B_Port | Peer_OUI_Role | Rule_ID | Severity | Side_A_Only_VLANs | Side_B_Only_VLANs | Remediation_Hint |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if rows:
        for r in rows[:50]:
            sec_lines.append(
                f"| `{r['Edge_ID']}` | **{r['Side_A_Host']}** | `{r['Side_A_Port']}` | "
                f"**{r['Side_B_Host'] or 'N/A'}** | `{r['Side_B_Port'] or 'N/A'}` | "
                f"{r.get('Peer_OUI_Role', 'Unknown')} | `{r['Rule_ID']}` | **{r['Severity']}** | `{r['Side_A_Only_VLANs'] or '-'}` | "
                f"`{r['Side_B_Only_VLANs'] or '-'}` | {r['Remediation_Hint']} |"
            )
        if len(rows) > 50:
            sec_lines.append(
                f"| *... and {len(rows) - 50} additional trunk findings recorded in `trunk_vlan_audit.md` and `03_correlated/trunk_mismatches.csv`* | | | | | | | | | | |"
            )
    else:
        if edges_eval == 0:
            sec_lines.append(
                "| *No Trunks Evaluated* | `-` | `-` | `-` | `-` | `-` | `NOT_EVALUATED` | **NOT_EVALUATED** | `-` | `-` | No inter-switch 802.1Q trunk links were evaluated in this crawl scope. |"
            )
        else:
            sec_lines.append(
                "| *All Evaluated Trunks* | *Symmetric* | `-` | *Symmetric* | `-` | `-` | `PASS` | **PASS** | `-` | `-` | ✓ Zero 802.1Q trunk VLAN, native PVID, or mode mismatches detected. |"
            )
    return sec_lines


def generate_trunk_audit_report(
    devices_or_audit, output_path: str = "trunk_vlan_audit.md", devices: dict | None = None
) -> dict:
    """
    Generate the dedicated Trunk VLAN Mismatch & L2 Symmetry Audit Report (`trunk_vlan_audit.md`)
    with GNU AGPLv3 notice, summary counts, discrepancy table, and multi-vendor remediation guidance.
    """
    audit = _resolve_trunk_audit(devices_or_audit)
    summary = (audit or {}).get("summary") or {}
    rows = _normalize_trunk_csv_rows(audit)

    edges_eval = int(
        summary.get(
            "total_trunk_edges_evaluated",
            summary.get("edges_evaluated", summary.get("total_edges", 0)),
        )
        or 0
    )
    crit_cnt = int(summary.get("critical_count", 0) or 0)
    high_cnt = int(summary.get("high_count", 0) or 0)
    med_cnt = int(summary.get("medium_count", 0) or 0)
    low_cnt = int(summary.get("low_count", 0) or 0)
    info_cnt = int(summary.get("info_count", 0) or 0)
    total_cnt = int(summary.get("total_findings", len(rows)) or 0)

    lines = [
        "<!--",
        "Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>",
        "SPDX-License-Identifier: AGPL-3.0-or-later",
        "-->",
        "",
        "# Trunk VLAN Mismatch & Layer 2 Symmetry Audit Report",
        "",
        "> **License Notice**: This deliverable is generated by `Net-Docu-Crawler` and distributed under the "
        "**GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`)** (<https://www.gnu.org/licenses/agpl-3.0.html>).",
        "",
        "This report audits bidirectional Layer 2 802.1Q trunk links, Port-Channel / LAG bundles, native/PVID tagging, "
        "active VLAN forwarding state, and IEEE 802.1ad QinQ boundaries across multi-vendor switching domains.",
        "",
        "## 1. Executive Summary & Audit Metrics",
        "",
        "| Metric | Count | Status |",
        "| :--- | :--- | :--- |",
        f"| **Evaluated Trunk / Uplink Edges** | `{edges_eval}` | {'Audited' if edges_eval > 0 else 'Not Evaluated'} |",
        f"| **Total Discrepancy Findings** | `{total_cnt}` | {'WARN' if (crit_cnt + high_cnt) > 0 else ('PASS' if edges_eval > 0 else 'NOT_EVALUATED')} |",
        f"| **CRITICAL Findings (`TRK-001`, `TRK-002`)** | `{crit_cnt}` | {'⚠️ Action Required' if crit_cnt > 0 else ('✓ Clean' if edges_eval > 0 else 'Not Evaluated')} |",
        f"| **HIGH Findings (`TRK-003`, `TRK-004`)** | `{high_cnt}` | {'⚠️ Action Required' if high_cnt > 0 else ('✓ Clean' if edges_eval > 0 else 'Not Evaluated')} |",
        f"| **MEDIUM Findings (`TRK-005`, `TRK-006`, Boundary)** | `{med_cnt}` | {'Review Recommended' if med_cnt > 0 else ('✓ Clean' if edges_eval > 0 else 'Not Evaluated')} |",
        f"| **LOW Findings (`TRK-007`)** | `{low_cnt}` | {'Hardening Opportunity' if low_cnt > 0 else ('✓ Clean' if edges_eval > 0 else 'Not Evaluated')} |",
        f"| **INFO Findings (`INFO_QINQ_BOUNDARY`)** | `{info_cnt}` | Informational |",
    ]

    peer_src = (
        devices
        if devices is not None
        else (devices_or_audit if isinstance(devices_or_audit, dict) and "findings" not in devices_or_audit else None)
    )
    peer_lookup = _build_host_oui_role_lookup(peer_src)

    lines.extend(
        _build_trunk_audit_markdown_section(
            audit,
            heading="## 2. Trunk VLAN Mismatch & L2 Symmetry Discrepancy Table",
            peer_lookup=peer_lookup,
        )
    )

    lines.extend(
        [
            "",
            "## 3. Rule Reference & Multi-Vendor Remediation Guidance",
            "",
            "| Rule ID | Severity | Condition Audited | Operational Impact & Remediation Guidance |",
            "| :--- | :--- | :--- | :--- |",
            "| `TRK-001` | **CRITICAL** | Operational mode mismatch (`oper_mode_a != oper_mode_b`) | One side operates as an 802.1Q trunk while the peer operates as access or down. Configure explicit trunk mode on both peers. |",
            "| `TRK-002` | **CRITICAL** | Native / untagged PVID mismatch (`native_vlan_a != native_vlan_b`) | Causes untagged frame leaking between VLANs and Spanning Tree PVID inconsistency blocks. Align native VLAN IDs on both sides. |",
            "| `TRK-003` | **HIGH** | Asymmetric native VLAN tagging (`native_vlan_tagged` mismatch) | One switch tags the native VLAN (`vlan dot1q tag native` / Junos pure tagged trunk) while the peer expects untagged frames. |",
            "| `TRK-004` | **HIGH** | Allowed VLAN set asymmetry (`allowed_vlans_a ^ allowed_vlans_b`) | Traffic for asymmetric VLANs is silently blackholed at the peer trunk port. Synchronize the allowed VLAN list across both ends. |",
            "| `TRK-005` | **MEDIUM** | Active / operational VLAN database drift | A VLAN is permitted on the trunk configuration but missing or suspended in the local switch VLAN database or blocked by STP. |",
            "| `TRK-006` | **MEDIUM** | Default VLAN 1 permitted on trunk | Security hardening recommendation: prune default VLAN 1 from inter-switch trunks where unused. |",
            "| `TRK-007` | **LOW** | Dynamic Trunking Protocol (`dynamic_auto` / `dynamic_desirable`) | Disable DTP negotiation (`switchport mode trunk` + `switchport nonegotiate`) to prevent trunk spoofing. |",
            "| `ERR_UNCRAWLED_NEIGHBOR` | **MEDIUM** | Trunk neighbor not in crawled dataset | Include the remote neighbor management IP in the crawl scope or verify SSH/AAA credentials. |",
            "| `WARN_ASYMMETRIC_DISCOVERY` | **MEDIUM** | One-way LLDP/CDP neighbor visibility | Enable bidirectional LLDP (`lldp run` / `set protocols lldp interface all`) on both switches. |",
            "| `INFO_QINQ_BOUNDARY` | **INFO** | IEEE 802.1ad QinQ (`dot1q-tunnel`) edge | Customer-to-provider tunnel boundary detected; customer C-VLAN lists intentionally differ from provider S-VLANs. |",
            "",
            "### Official Vendor CLI Documentation & Remediation References",
            "- **Cisco IOS / IOS-XE / NX-OS**: [Cisco IOS & NX-OS Configuration Guides](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html) (`switchport mode trunk`, `switchport trunk native vlan <id>`, `switchport trunk allowed vlan <list>`)",
            "- **Juniper Networks Junos OS**: [Juniper Junos OS Documentation](https://www.juniper.net/documentation/product/us/en/junos-os/) (`set interfaces <port> unit 0 family ethernet-switching interface-mode trunk vlan members [...]`, `native-vlan-id <id>`)",
            "- **HPE Aruba Networking AOS-CX**: [HPE Aruba AOS-CX Documentation](https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm) (`vlan trunk native <id>`, `vlan trunk allowed <list>`)",
            "- **HPE ProCurve / ArubaOS-S**: [HPE ArubaOS-S Management and Configuration Guide](https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm) (`vlan <id> tagged <ports>`, `vlan <id> untagged <ports>`)",
            "- **Arista EOS**: [Arista EOS User Manual](https://www.arista.com/en/um-eos) (`switchport mode trunk`, `switchport trunk native vlan <id>`, `switchport trunk allowed vlan <list>`)",
            "",
        ]
    )

    try:
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Trunk VLAN audit report successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating trunk VLAN audit report: {e}")

    return audit


def generate_manual_followup_report(
    devices: dict,
    output_path: str = "manual_followup_report.md",
    trunk_audit: dict | None = None,
    quality_report: dict | None = None,
) -> None:
    """
    Generate a single consolidated manual follow-up checklist (`manual_followup_report.md`)
    pulling actionable items from quality gates, failed/unauthenticated targets,
    suspected unmanaged switches, PoE warnings, and switch-to-switch trunk mismatches
    (filtering out AP/Phone edges).
    """
    unique_devs = get_unique_devices({ip: dev for ip, dev in devices.items() if _is_network_infra(dev)})
    peer_lookup = _build_host_oui_role_lookup(devices)

    lines: list[str] = [
        "<!--",
        "Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>",
        "SPDX-License-Identifier: AGPL-3.0-or-later",
        "-->",
        "",
        "# Manual Follow-Up & Field Verification Report",
        "",
        "> **Purpose**: Consolidated engineer action list across all crawl deliverables—unauthenticated targets, command/header parse mismatches, suspected unmanaged switches, PoE anomalies, and switch-to-switch trunk mismatches (with AP/Phone edges separated).",
        "",
    ]

    # 1. Unauthenticated & Command/Header Mismatch Devices
    unauth = (quality_report or {}).get("unauthenticated_devices")
    mismatches = (quality_report or {}).get("command_header_mismatches")
    if unauth is None:
        unauth = [
            {
                "ip": ip,
                "hostname": d.get("hostname") or ip,
                "vendor": d.get("vendor") or "Unknown",
                "mac_address": d.get("mac_address") or "",
                "model": d.get("model") or "",
            }
            for ip, d in devices.items()
            if str(d.get("status", "")).lower() == "unauthenticated"
        ]
    if mismatches is None:
        mismatches = []
        for ip, d in devices.items():
            if str(d.get("status", "")).lower() != "success":
                continue
            hn = str(d.get("hostname") or ip).strip()
            reasons = []
            if not hn or hn == ip or hn.lower() == "unknown":
                reasons.append("hostname unresolved (header/version parse mismatch)")
            if not (d.get("interfaces_detail") or {}):
                reasons.append("0 interfaces parsed (command/driver mismatch)")
            if reasons:
                mismatches.append(
                    {
                        "ip": ip,
                        "hostname": hn or ip,
                        "vendor": d.get("vendor") or "Unknown",
                        "reasons": "; ".join(reasons),
                    }
                )

    lines.extend(["## 1. Unauthenticated & Command/Header Mismatch Devices", ""])
    if unauth:
        lines.extend(
            [
                f"### Unauthenticated Targets ({len(unauth)})",
                "| IP Address | Hostname | Vendor / OUI | MAC Address | Banner / Model |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for u in unauth:
            lines.append(
                f"| `{u['ip']}` | **{u['hostname']}** | {u['vendor']} | `{u['mac_address'] or 'N/A'}` | `{u['model'] or 'N/A'}` |"
            )
        lines.append("")
    if mismatches:
        lines.extend(
            [
                f"### Crawled Command / Header Mismatches ({len(mismatches)})",
                "| IP Address | Hostname | Vendor | Mismatch Detail |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for m in mismatches:
            lines.append(f"| `{m['ip']}` | **{m['hostname']}** | {m['vendor']} | {m['reasons']} |")
        lines.append("")
    if not unauth and not mismatches:
        lines.extend(["✓ No unauthenticated targets or command/header parse mismatches detected.", ""])

    # 2. Suspected Unmanaged Switches, Multi-MAC Ports & Unverified Targets
    lines.extend(_render_blueprint_manual_verification_section(devices, unique_devs))

    # 3. Switch-to-Switch Critical/High Trunk Mismatches (excluding AP/Phone edges)
    audit = _resolve_trunk_audit(trunk_audit if trunk_audit is not None else unique_devs)
    rows = _normalize_trunk_csv_rows(audit)
    sw_crit_high = []
    ignored_ap_phone = 0
    for r in rows:
        role_str = _resolve_trunk_peer_oui_role(r["Side_A_Host"], r["Side_B_Host"], peer_lookup)
        if "[AP]" in role_str or "[Phone]" in role_str:
            ignored_ap_phone += 1
            continue
        if r["Severity"] in ("CRITICAL", "HIGH"):
            sw_crit_high.append((r, role_str))

    lines.extend(["## 2. Switch-to-Switch Critical/High Trunk Mismatches (APs/Phones Filtered Out)", ""])
    lines.append(
        f"> Filtered out **{ignored_ap_phone}** AP/Phone edge finding(s); showing **{len(sw_crit_high)}** switch-to-switch CRITICAL/HIGH trunk mismatch(es)."
    )
    lines.append("")
    if sw_crit_high:
        lines.extend(
            [
                "| Edge_ID | Side_A_Host | Side_A_Port | Side_B_Host | Side_B_Port | Peer_OUI_Role | Rule_ID | Severity | Remediation_Hint |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for r, role_str in sw_crit_high[:50]:
            lines.append(
                f"| `{r['Edge_ID']}` | **{r['Side_A_Host']}** | `{r['Side_A_Port']}` | **{r['Side_B_Host'] or 'N/A'}** | `{r['Side_B_Port'] or 'N/A'}` | {role_str} | `{r['Rule_ID']}` | **{r['Severity']}** | {r['Remediation_Hint']} |"
            )
        lines.append("")
    else:
        lines.extend(["✓ No switch-to-switch CRITICAL/HIGH trunk mismatches remaining.", ""])

    # 4. PoE Budget Contradictions & High Utilization
    lines.extend(["## 3. PoE Budget Contradictions & High Utilization (>80%)", ""])
    poe_items = []
    for ip, dev in unique_devs.items():
        hn = dev.get("hostname") or ip
        poe = dev.get("poe") or {}
        tot_w = float(poe.get("total_power_watts") or 0.0)
        used_w = float(poe.get("used_power_watts") or 0.0)
        ints = dev.get("interfaces_detail") or {}
        up_cnt = sum(1 for s in ints.values() if str((s or {}).get("status", "")).lower() == "up")
        poe_ports = poe.get("ports") or {}
        poe_vals = poe_ports.values() if isinstance(poe_ports, dict) else poe_ports
        active_poe_ports = sum(1 for p in poe_vals if isinstance(p, dict) and float(p.get("power_watts") or 0.0) > 0)
        if active_poe_ports > up_cnt and tot_w > 0:
            poe_items.append(
                f"- ❌ **{hn}**: PoE contradiction (`active_poe_ports={active_poe_ports}` > `up_ports={up_cnt}`, budget={tot_w:.1f}W) — verify missing physical ports or stack members."
            )
        elif tot_w > 0 and (used_w / tot_w) > 0.80:
            poe_items.append(
                f"- ⚠️ **{hn}**: High PoE utilization ({used_w:.1f}W / {tot_w:.1f}W, {used_w / tot_w * 100:.1f}%)."
            )
    if poe_items:
        lines.extend(poe_items)
    else:
        lines.append("✓ No PoE contradictions or >80% PoE utilization warnings detected.")
    lines.append("")

    try:
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] Manual follow-up report written to: {output_path}")
    except Exception as e:
        print(f"Error generating manual follow-up report: {e}")


def generate_interactive_topology_html(
    devices: dict,
    output_path: str = "topology_interactive.html",
    trunk_audit: dict | None = None,
) -> str:
    """Generate the self-contained interactive topology viewer via ``topology_renderer``."""
    from net_docu_crawler.topology_renderer import build_topology_graph_model, get_topology_renderer

    model = build_topology_graph_model(devices, trunk_audit=trunk_audit)
    renderer = get_topology_renderer("interactive_html")
    written = renderer.render(model, output_path)
    print(f"[+] Interactive topology viewer written to: {written}")
    return written

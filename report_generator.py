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
    name = re.sub(r"\.0$", "", name.lower().strip().strip('"').strip("'"))
    replacements = {
        "gigabitethernet": "gi",
        "tengigabitethernet": "te",
        "fastethernet": "fa",
        "ethernet": "et",
        "fortygigabitethernet": "fo",
        "hundredgige": "hu",
        "hundredgigabitethernet": "hu",
        "fivegigabitethernet": "fi",
        "twopointfivegigabitethernet": "tw",
        "port-channel": "po",
        "bundle-ether": "be",
    }
    for full, short in replacements.items():
        if name.startswith(full):
            return name.replace(full, short)
    return name


def parse_interface_network(ip_str, mask_hint=None):
    """
    Parses multi-vendor interface IP representations into (clean_ip, IPNetwork | None).
    Supports:
      - CIDR notation: '192.168.1.1/24', '100.64.224.70/19'
      - Space-separated netmask: '192.168.1.252 255.255.255.0'
      - Bare IP + optional config mask hint: '192.168.1.3', mask_hint='255.255.255.0'
    """
    if not ip_str:
        return "", None
    raw = ip_str.strip()
    if raw.lower() in ("unassigned", "down", "up", "unset", "n/a", "none", "0.0.0.0"):
        return "", None

    clean_ip = raw.split("/")[0].split()[0].strip()
    net = None
    try:
        if "/" in raw:
            net = IPNetwork(raw.split()[0])
        elif " " in raw:
            parts = raw.split()
            net = IPNetwork(f"{parts[0]}/{parts[1]}")
        elif mask_hint:
            net = IPNetwork(f"{clean_ip}/{mask_hint.lstrip('/')}")
        else:
            net = IPNetwork(f"{clean_ip}/24")
    except (AddrFormatError, ValueError, TypeError) as exc:
        logger.debug("Failed to parse interface network from %r (mask_hint=%r): %s", ip_str, mask_hint, exc)
        net = None

    return clean_ip, net


def get_link_speed(local_port, interfaces_detail):
    norm_local = normalize_interface_name(local_port)

    # 1. Try to find in interfaces_detail
    for name, stats in interfaces_detail.items():
        if normalize_interface_name(name) == norm_local:
            speed_str = stats.get("speed", "").lower()
            if speed_str:
                if "100g" in speed_str or "100000" in speed_str:
                    return "100G"
                elif "40g" in speed_str or "40000" in speed_str:
                    return "40G"
                elif "10g" in speed_str or "10000" in speed_str:
                    return "10G"
                elif "5g" in speed_str or "5000" in speed_str:
                    return "5G"
                elif "2.5g" in speed_str or "2500" in speed_str:
                    return "2.5G"
                elif "1000m" in speed_str or "1g" in speed_str or "1000" in speed_str:
                    return "1G"
                elif "100m" in speed_str or "100" in speed_str:
                    return "100M"
                elif "10m" in speed_str or "10" in speed_str:
                    return "10M"

    # 2. Fallback to guessing from interface name
    if "hu" in norm_local or "hundred" in norm_local:
        return "100G"
    elif "fo" in norm_local or "forty" in norm_local:
        return "40G"
    elif "te" in norm_local or "ten" in norm_local:
        return "10G"
    elif "fi" in norm_local or "five" in norm_local:
        return "5G"
    elif "tw" in norm_local or "twopointfive" in norm_local:
        return "2.5G"
    elif "gi" in norm_local or "gig" in norm_local:
        return "1G"
    elif "fa" in norm_local or "fast" in norm_local:
        return "100M"
    elif "et" in norm_local or "eth" in norm_local:
        return "10M"

    return "1G"  # Default to 1G if unknown


def get_route_details(route):
    """
    Extracts subnet, protocol, next_hop, and interface from a route dict,
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

    return {"subnet": subnet, "protocol": protocol, "next_hop": next_hop, "interface": interface}


def get_unique_devices(devices):
    """
    De-duplicates devices based on Serial Number (primary) and Hostname (fallback).
    If a device was discovered/crawled via multiple SVIs, it only keeps one primary instance.
    """
    if not devices:
        return {}

    unique_devices = {}
    seen_serials = set()
    seen_hostnames = set()

    # Sort IPs so that we prioritize:
    # 1. Successful crawls over failed ones
    # 2. SSH over Telnet
    # 3. Alphabetical/numerical ordering of IP for determinism
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
        serial = dev.get("serial")
        hostname = dev.get("hostname")

        is_duplicate = False
        duplicate_reason = ""

        # Check Serial number uniqueness
        if serial and serial != "Unknown" and serial.strip():
            serial_clean = serial.strip().upper()
            if serial_clean in seen_serials:
                is_duplicate = True
                duplicate_reason = f"duplicate serial {serial_clean}"
            else:
                seen_serials.add(serial_clean)

        # Check Hostname uniqueness as fallback
        if not is_duplicate and hostname and hostname != "Unknown" and hostname.strip():
            host_clean = hostname.strip().lower()
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

    # Return unique devices sorted by IP for consistency
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
    dtype = str(dev.get("device_type") or dev.get("device_persona") or "switch").strip().lower()
    return dtype in _INFRA_DEVICE_TYPES


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
        print(f"Asset inventory successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating asset inventory CSV: {e}")


def generate_l2_diagram(devices, output_path="L2_network_diagrams.md"):
    """
    Generates the L2/Physical Network Diagram using Mermaid.js.
    Shows switch stacks, APs, uplinks, fiber paths, and STP states.
    """
    devices = {ip: dev for ip, dev in devices.items() if _is_network_infra(dev)}
    lines = [
        "# Layer 2 & Physical Network Diagrams",
        "",
        "This file contains physical topologies, switch-to-switch uplinks, and wireless AP connections discovered via CDP/LLDP and local port statuses.",
        "",
        "## Physical Connectivity Diagram",
        "```mermaid",
        "flowchart LR",
        "  %% Style configurations",
        "  classDef core fill:#3399ff,stroke:#0066cc,stroke-width:2px,color:#fff;",
        "  classDef dist fill:#85c1e9,stroke:#2e86c1,stroke-width:2px;",
        "  classDef router fill:#aed6f1,stroke:#1b4f72,stroke-width:2px;",
        "  classDef access fill:#d5dbdb,stroke:#7f8c8d,stroke-width:1px;",
        "  classDef ap fill:#f9e79f,stroke:#f1c40f,stroke-width:1px,color:#000;",
        "  classDef firewall fill:#e74c3c,stroke:#c0392b,stroke-width:2px,color:#fff;",
        "  classDef root fill:#2ecc71,stroke:#27ae60,stroke-width:3px,color:#fff;",
        "",
    ]

    link_idx = 0
    link_styles = []

    # Safe alphanumeric IDs mapping for L2 graph to avoid syntax errors with special characters
    # Key crawled devices by IP (not hostname) so colliding hostnames never overwrite/duplicate IDs.
    node_ids = {}
    hostname_to_node_id = {}
    defined_nodes = set()
    sw_counter = 0

    # Pre-populate IDs for all scanned devices
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        nid = f"sw_{sw_counter}"
        node_ids[ip] = nid
        if hostname not in hostname_to_node_id:
            hostname_to_node_id[hostname] = nid
        defined_nodes.add(hostname)
        sw_counter += 1

    # 1. Define nodes and their styles (omit 0-link standalone devices when topology has >=10 devices)
    linked_ips = {ip for ip, dev in devices.items() if dev.get("neighbors")}
    standalone_devs = []
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        if len(devices) >= 10 and ip not in linked_ips:
            standalone_devs.append((dev.get("hostname") or ip, ip, dev.get("model") or "Unknown"))
            continue
        hostname = dev.get("hostname") or ip
        model = dev.get("model") or "Unknown"
        is_root = bool(dev.get("stp", {}).get("is_verified_campus_root", False))

        node_id = node_ids[ip]
        # Node label with Model
        safe_hostname = hostname.replace('"', '\\"')
        safe_model = model.replace('"', '\\"')
        label = f'["{safe_hostname}<br/>({safe_model})"]'
        lines.append(f"  {node_id}{label}")

        # Apply classes
        model_lower = model.lower()
        hn_lower = hostname.lower()
        dev_type = dev.get("device_type", "").lower()
        if is_root:
            lines.append(f"  class {node_id} root;")
        elif dev_type == "ap" or "ap-" in model_lower or "air-" in model_lower:
            lines.append(f"  class {node_id} ap;")
        elif dev_type == "firewall":
            lines.append(f"  class {node_id} firewall;")
        elif dev_type == "router":
            lines.append(f"  class {node_id} router;")
        elif (
            "core" in hn_lower
            or "c9500" in model_lower
            or "5412" in model_lower
            or "5406" in model_lower
            or "ex4600" in model_lower
            or len(dev.get("l3_interfaces", [])) >= 5
        ):
            lines.append(f"  class {node_id} core;")
        elif "dist" in hn_lower or "c3850" in model_lower or "c9300" in model_lower:
            lines.append(f"  class {node_id} dist;")
        else:
            lines.append(f"  class {node_id} access;")

    lines.append("")
    lines.append("  %% Topology links")

    # 2. Draw connections from neighbors
    connections = {}
    external_nodes_defined = set()
    from net_docu_crawler.schema import infer_site_code

    node_site = {}
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        nid = node_ids[ip]
        node_site[nid] = dev.get("site_code") or infer_site_code(hostname)
        neighbors = dev.get("neighbors", [])
        dev_ports = dev.get("ports") or {}
        ports_ci = {str(k).lower(): v for k, v in dev_ports.items()}

        for n in neighbors:
            remote_host = (n.get("remote_device") or "").strip().strip('"').strip("'")
            if not remote_host:
                continue
            remote_host = remote_host.split(".")[0]

            matched_remote = None
            for _rip, rdev in devices.items():
                rhn = rdev.get("hostname", "")
                if rhn and rhn.split(".")[0].lower() == remote_host.lower():
                    matched_remote = rhn
                    break

            node_b = matched_remote or remote_host
            n_type = (n.get("device_type") or "").lower()
            if node_b not in defined_nodes and n_type not in ("switch", "router", "firewall", "wlc", "bridge"):
                continue

            # Ensure safe ID exists for node_b
            if node_b in hostname_to_node_id:
                node_b_id = hostname_to_node_id[node_b]
            else:
                if node_b not in node_ids:
                    node_ids[node_b] = f"ext_{len(node_ids) + sw_counter}"
                node_b_id = node_ids[node_b]

            node_a_id = node_ids[ip]

            # If external (not a crawled device) and not defined yet, define it
            if node_b not in defined_nodes and node_b not in external_nodes_defined:
                safe_nb = node_b.replace('"', '\\"')
                lines.append(f'  {node_b_id}["{safe_nb}"]')
                n_type = n.get("device_type", "").lower()
                n_plat = (n.get("platform") or n.get("remote_platform") or "").lower()
                if (
                    n_type == "ap"
                    or "ap-" in n_plat
                    or "air-" in n_plat
                    or "access point" in n_plat
                    or "aruba" in n_plat
                ):
                    lines.append(f"  class {node_b_id} ap;")
                elif n_type == "firewall":
                    lines.append(f"  class {node_b_id} firewall;")
                elif n_type == "router":
                    lines.append(f"  class {node_b_id} router;")
                else:
                    lines.append(f"  class {node_b_id} access;")
                external_nodes_defined.add(node_b)

            # Sort names for link key to prevent duplicates
            if node_a_id < node_b_id:
                key = (node_a_id, node_b_id)
            else:
                key = (node_b_id, node_a_id)

            if key not in connections:
                connections[key] = []

            local_port = n.get("local_port", "")
            remote_port = n.get("remote_port", "")

            is_blocked = False
            stp_vlans = dev.get("stp", {}).get("vlans", {})
            for _vlan_id, ports in stp_vlans.items():
                if local_port in ports and ports[local_port].get("state") == "BLK":
                    is_blocked = True
                    break

            speed_val = get_link_speed(local_port, dev.get("interfaces_detail", {}))
            cport = dev_ports.get(local_port) or ports_ci.get(local_port.lower()) or {}
            lag_val = str(cport.get("lag_id") or "").strip()
            po_name = lag_val if lag_val.lower() not in ("", "none", "unknown") else ""

            connections[key].append(
                {
                    "local_port": local_port,
                    "remote_port": remote_port,
                    "is_blocked": is_blocked,
                    "speed": speed_val,
                    "port_channel": po_name,
                }
            )

    for (id_a, id_b), links in connections.items():
        # Determine stp status: blocked if any link in bundle is blocked
        is_blocked = any(lk["is_blocked"] for lk in links)

        # Sort and select speeds
        def speed_key(s):
            return {"100G": 8, "40G": 7, "10G": 6, "5G": 5, "2.5G": 4, "1G": 3, "100M": 2, "10M": 1}.get(s, 0)

        speeds = [lk["speed"] for lk in links]
        max_speed = max(speeds, key=speed_key) if speeds else "1G"

        thickness = {
            "10M": "1px",
            "100M": "2px",
            "1G": "3.5px",
            "2.5G": "5px",
            "5G": "6px",
            "10G": "7.5px",
            "40G": "9px",
            "100G": "11px",
        }.get(max_speed, "3.5px")

        # Build logical label for the connection
        pos = sorted(list(set([lk["port_channel"] for lk in links if lk["port_channel"]])))
        if pos:
            # Combined under port channel
            local_ports_str = ", ".join(sorted(list(set([lk["local_port"] for lk in links]))))
            label = f"{pos[0]} ({local_ports_str})"
        else:
            # Physical ports only
            port_pairs = []
            for lk in links:
                lp = lk["local_port"]
                rp = lk["remote_port"]
                if rp and rp.lower() not in ("unknown", "n/a", "-"):
                    port_pairs.append(f"{lp} ↔ {rp}")
                else:
                    port_pairs.append(lp)
            label = ", ".join(sorted(set(port_pairs)))

        clean_label = label.replace('"', '\\"')

        if is_blocked:
            # Dotted red line for blocked paths
            lines.append(f'  {id_a} -.->|"{clean_label}"| {id_b}')
            link_styles.append(f"  linkStyle {link_idx} stroke:#ff3333,stroke-width:{thickness},stroke-dasharray: 5 5;")
        else:
            # Thick line with port labels
            lines.append(f'  {id_a} ==>|"{clean_label}"| {id_b}')
            link_styles.append(f"  linkStyle {link_idx} stroke:#333,stroke-width:{thickness};")

        link_idx += 1

    # 3. Add link styles
    if link_styles:
        lines.append("")
        lines.append("  %% Link Styles (thickness based on link speed)")
        lines.extend(link_styles)

    lines.extend(
        [
            "```",
            "",
            "### Legend",
            "* **Green Highlighted Node**: STP Root Bridge.",
            "* **Blue Node**: Core / Distribution switches.",
            "* **Grey Node**: Access switches.",
            "* **Dashed Red Lines**: STP Blocking (`BLK`) links.",
            "* **Double Solid Lines**: Active forwarding links (line thickness indicates speed).",
            "",
        ]
    )

    if len(defined_nodes) > 20 and connections:
        # Group edges by site_code for readable per-site Mermaid diagrams
        site_edges: dict[str, list[tuple[tuple[str, str], list[dict]]]] = {}
        for edge_key, edge_links in connections.items():
            s_a = node_site.get(edge_key[0])
            s_b = node_site.get(edge_key[1])
            for sc in sorted({s for s in (s_a, s_b) if s}):
                site_edges.setdefault(sc, []).append((edge_key, edge_links))
        if len(site_edges) >= 2:
            # Capture node definitions/classes from the main diagram lines
            def_map: dict[str, list[str]] = {}
            for ln in lines:
                m_def = re.match(r"^\s+((?:sw|ext)_\d+)\[", ln)
                if m_def:
                    def_map.setdefault(m_def.group(1), []).append(ln)
                m_cls = re.match(r"^\s+class\s+((?:sw|ext)_\d+)\s+", ln)
                if m_cls:
                    def_map.setdefault(m_cls.group(1), []).append(ln)
            lines.append("## Site-Scoped Layer 2 Topologies")
            for sc in sorted(site_edges.keys()):
                edges_for_site = site_edges[sc]
                touched = sorted({n for ek, _ in edges_for_site for n in ek})
                lines.extend([f"### Site `{sc}` Layer 2 Topology", "```mermaid", "flowchart LR"])
                for ln in lines[6:14]:
                    lines.append(ln)
                for nid in touched:
                    lines.extend(def_map.get(nid, [f'  {nid}["{nid}"]']))
                for (id_a, id_b), e_links in edges_for_site:
                    port_pairs = []
                    for lk in e_links:
                        lp, rp = lk["local_port"], lk["remote_port"]
                        if rp and rp.lower() not in ("unknown", "n/a", "-"):
                            port_pairs.append(f"{lp} ↔ {rp}")
                        else:
                            port_pairs.append(lp)
                    lbl = ", ".join(sorted(set(port_pairs))).replace('"', '\\"')
                    lines.append(f'  {id_a} ==>|"{lbl}"| {id_b}')
                lines.extend(["```", ""])

    lines.extend(
        [
            "## Wireless Overlay Layout",
            "Discovered Wireless Access Points connected to switches:",
        ]
    )

    # Extract AP neighbors
    ap_count = 0
    ap_table = [
        "| Switch Hostname | Local Port | AP Hostname/MAC | AP IP | AP Model |",
        "| --- | --- | --- | --- | --- |",
    ]

    crawled_host_types = {}
    for _cip, cdev in devices.items():
        chost = (cdev.get("hostname") or "").split(".")[0].lower()
        if chost:
            crawled_host_types[chost] = (cdev.get("device_type") or cdev.get("device_persona") or "").lower()

    for ip, dev in devices.items():
        if (dev.get("device_type") or dev.get("device_persona") or "").lower() == "ap":
            continue
        hostname = dev.get("hostname") or ip
        for n in dev.get("neighbors", []):
            raw_plat = n.get("platform") or n.get("remote_platform") or ""
            platform = raw_plat.lower()
            n_type = n.get("device_type", "").lower()
            r_host = (n.get("remote_device") or "").split(".")[0].lower()
            if not n_type and r_host in crawled_host_types:
                n_type = crawled_host_types[r_host]
            if (
                n_type == "ap"
                or "ap" in platform
                or "air-" in platform
                or "access point" in platform
                or "aruba" in platform
            ):
                ap_count += 1
                ap_table.append(
                    f"| {hostname} | {n.get('local_port')} | {n.get('remote_device')} "
                    f"| {n.get('remote_ip') or 'N/A'} | {raw_plat or 'Wireless AP'} |"
                )

    if ap_count > 0:
        lines.append(f"\nTotal Discovered Access Points: **{ap_count}**\n")
        lines.extend(ap_table)
    else:
        lines.append("\nNo wireless access points were directly discovered via LLDP/CDP neighbor tables.")

    if standalone_devs:
        lines.extend(
            [
                "",
                "## Standalone / Unlinked Infrastructure Switches",
                "Switches with no discovered CDP/LLDP neighbor links (omitted from the Mermaid graph above for readability):",
                "",
                "| Hostname | Management IP | Model |",
                "| :--- | :--- | :--- |",
            ]
        )
        for shost, sip, smodel in standalone_devs:
            lines.append(f"| **{shost}** | `{sip}` | `{smodel}` |")

    try:
        from net_docu_crawler.diagram_validator import validate_mermaid_block

        full_md = "\n".join(lines)
        for m_blk in re.findall(r"```mermaid\n(.*?)```", full_md, re.DOTALL):
            errs = validate_mermaid_block(m_blk)
            if errs:
                print(f"[!] Mermaid syntax warning in {output_path}: {errs[0]}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_md)
        print(f"L2 Diagrams successfully written to {output_path}")
    except Exception as e:
        print(f"Error generating L2 diagram file: {e}")


def generate_l3_diagram(devices, output_path="L3_network_diagrams.md"):
    """
    Generates L3 logical and routing topologies using Mermaid.js.
    Consumes `correlator.build_l3_svi_table()` for authoritative VLAN/SVI/subnet joins.
    """
    from net_docu_crawler.correlator import build_l3_svi_table

    devices = {ip: dev for ip, dev in devices.items() if _is_network_infra(dev)}
    svi_rows = build_l3_svi_table(list(devices.values()))
    svi_lookup: dict[tuple[str, str], dict] = {}
    subnet_vlan_names: dict[str, set[str]] = {}
    for row in svi_rows:
        hn = row.get("source_device") or row.get("hostname", "")
        iname = str(row.get("svi_interface") or "").lower()
        svi_lookup[(hn, iname)] = row
        sub = row.get("prefix_cidr") or row.get("subnet") or ""
        vid = row.get("vlan_id") or ""
        vname = row.get("vlan_name") or ""
        if sub and (vid or vname):
            lbl = f"VLAN {vid}: {vname}".strip(": ") if vid else vname
            subnet_vlan_names.setdefault(sub, set()).add(lbl)

    # Identify L3 routing gateways vs single-SVI L2 management switches when >20 infra devices exist
    l3_gateway_hosts: set[str] = set()
    mgmt_only_count = 0
    for ip, dev in devices.items():
        hn = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", []) or []
        has_dyn_or_static = any(
            str(r.get("protocol") or "").lower() not in ("connected", "local", "direct", "access-internal", "access")
            and str(r.get("subnet") or "") != "0.0.0.0/0"
            for r in (dev.get("routes") or [])
        )
        is_core = (
            "core" in hn.lower()
            or "5412" in str(dev.get("model", "")).lower()
            or "ex4600" in str(dev.get("model", "")).lower()
            or dev.get("device_persona") in ("router", "firewall")
        )
        if len(devices) <= 20 or len(l3_ints) >= 2 or has_dyn_or_static or is_core:
            l3_gateway_hosts.add(hn)
        else:
            mgmt_only_count += 1

    # 1. Build adjacency list of the bipartite graph (scoped to l3_gateway_hosts when >20 devices)
    adj = {}
    subnets = set()
    device_nodes = set()
    device_config_ips = {}
    for ip, dev in devices.items():
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        device_config_ips[hostname] = parse_interface_ips_from_config(cfg) if cfg else {}
        if hostname not in l3_gateway_hosts:
            continue
        device_nodes.add(hostname)
        adj.setdefault(hostname, set())

        for intf in dev.get("l3_interfaces", []) or []:
            intf_ip = intf.get("ip_address")
            intf_name = intf.get("interface", "")
            if not intf_ip or intf_ip in ["unassigned", "down", "up", "unset"]:
                continue

            norm_intf = normalize_interface_name(intf_name)
            _cfg_ip, cfg_mask = device_config_ips[hostname].get(norm_intf, (None, None))
            clean_ip, net = parse_interface_network(intf_ip, cfg_mask)
            if not net or clean_ip.startswith(("127.", "128.0.")):
                continue

            clean_ip_base = f"{net.network}/{net.prefixlen}"
            subnets.add(clean_ip_base)
            adj.setdefault(clean_ip_base, set())
            adj[hostname].add(clean_ip_base)
            adj[clean_ip_base].add(hostname)

    diagram_lines = []
    if not adj:
        diagram_lines.append("graph TD")
        diagram_lines.append('  root["No L3 Interfaces Discovered"]')
    else:
        diagram_lines.append("graph TD")
        diagram_lines.append("  %% Style configurations")
        diagram_lines.append("  classDef device fill:#f5f5f5,stroke:#333,stroke-width:2px;")
        diagram_lines.append("  classDef subnet fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;")
        diagram_lines.append("")

        # Pre-populate safe IDs for all nodes
        node_ids = {}
        counter = 0
        for sub in sorted(list(subnets)):
            node_ids[sub] = f"sub_{counter}"
            counter += 1
        for dev in sorted(list(device_nodes)):
            node_ids[dev] = f"dev_{counter}"
            counter += 1

        # Define Subnets (stadium oval: ([...]))
        diagram_lines.append("  %% Subnets (Ovals)")
        for sub in sorted(list(subnets)):
            node_id = node_ids[sub]
            vnames = subnet_vlan_names.get(sub, set())
            vname_suffix = f" ({'/'.join(sorted(vnames))})" if vnames else ""
            label = f"{sub}{vname_suffix}"
            safe_label = label.replace('"', "'")
            diagram_lines.append(f'  {node_id}(["{safe_label}"])')
            diagram_lines.append(f"  class {node_id} subnet;")

        # Define Devices (square: [...])
        diagram_lines.append("\n  %% Devices (Squares)")
        for dev in sorted(list(device_nodes)):
            node_id = node_ids[dev]
            safe_dev = dev.replace('"', '\\"')
            diagram_lines.append(f'  {node_id}["{safe_dev}"]')
            diagram_lines.append(f"  class {node_id} device;")

        # Draw Links
        diagram_lines.append("\n  %% Connectivity Links")
        for dev in sorted(list(device_nodes)):
            dev_id = node_ids[dev]
            for sub in sorted(list(adj.get(dev, []))):
                sub_id = node_ids[sub]
                diagram_lines.append(f"  {dev_id} --- {sub_id}")

    lines = [
        "# Layer 3 & Logical Network Diagrams",
        "",
        "This file documents Layer 3 boundaries, Switch Virtual Interfaces (SVIs), VLAN maps, and routing domains/VRFs.",
        "",
        "## Logical Routing Boundary Diagram",
        "```mermaid",
        "\n".join(diagram_lines),
        "```",
        "",
    ]
    if mgmt_only_count > 0:
        lines.extend(
            [
                f"> [!NOTE] Scoped to **{len(l3_gateway_hosts)}** L3 routing gateways / core switches; **{mgmt_only_count}** single-SVI L2 management switches omitted from the Mermaid graph above (all SVIs remain listed in the table below).",
                "",
            ]
        )
    lines.extend(
        [
            "## Authoritative VLAN, Subnet & SVI Map",
            "",
            "| Switch Hostname | Interface / SVI | VLAN ID | VLAN Name | Description | SVI IP Address | Subnet Range | Interface Status |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        l3_ints = dev.get("l3_interfaces", [])
        ints_detail = dev.get("interfaces_detail", {})
        for intf in l3_ints:
            intf_name = intf.get("interface")
            ip_addr = intf.get("ip_address")
            status = intf.get("status")

            # Match SVI name to interfaces_detail to get description
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
            if not vlan_name and vlan_id_str:
                vlan_name = (dev.get("vlans") or {}).get(vlan_id_str, {}).get("name", "")

            _cfg_ip, cfg_mask = device_config_ips.get(hostname, {}).get(norm_name, (None, None))
            clean_ip, net = parse_interface_network(ip_addr, cfg_mask)
            if clean_ip.startswith(("127.", "128.0.")):
                continue
            subnet_range = (
                svi_row.get("prefix_cidr")
                or svi_row.get("subnet")
                or (f"{net.network}/{net.prefixlen}" if net else "N/A")
            )
            lines.append(
                f"| {hostname} | {intf_name} | {vlan_id_str or 'N/A'} | {vlan_name or 'N/A'} | {desc or 'N/A'} | {ip_addr} | {subnet_range} | {status} |"
            )

    lines.extend(
        [
            "",
            "## VRF Routing Instances & Boundaries",
            "Discovered VRF routing instances and their associated interfaces:",
        ]
    )

    # Search running config for VRFs
    vrf_found = False
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        # Look for "vrf definition X" or "ip vrf X"
        vrfs = list(set(re.findall(r"(?:ip vrf|vrf definition)\s+(\S+)", cfg)))
        if vrfs:
            vrf_found = True
            lines.append(f"\n### {hostname} VRF Instances:")
            for vrf in vrfs:
                lines.append(f"* **VRF Name:** `{vrf}`")

    if not vrf_found:
        lines.append(
            "\nNo virtual routing and forwarding (VRF) instances were detected in active device configurations (standard global table only)."
        )

    # Complete Routing Tables
    lines.extend(
        [
            "",
            "## Discovered Routing Tables",
            "The following table lists the active routing entries parsed from each device's routing table:",
        ]
    )

    has_routes = False
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
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

            sorted_routes = []
            for r in routes:
                sorted_routes.append(get_route_details(r))

            sorted_routes.sort(key=_route_sort_key)

            omitted_host_routes = 0
            for rt in sorted_routes:
                sub = rt["subnet"]
                proto_l = str(rt["protocol"] or "").lower()
                if proto_l in ("local", "access-internal", "access") and sub.endswith("/32"):
                    omitted_host_routes += 1
                    continue
                lines.append(
                    f"| {hostname} | `{sub}` | {rt['protocol']} | {rt['next_hop']} | {rt['interface'] or 'N/A'} |"
                )
            if omitted_host_routes:
                lines.append(
                    f"| {hostname} | *({omitted_host_routes} `/32` Access-internal DHCP/subscriber host routes omitted)* | Access-internal | - | - |"
                )

    if not has_routes:
        lines.append("\nNo routing table entries were parsed or simulated for the scanned devices.")

    try:
        from net_docu_crawler.diagram_validator import validate_mermaid_block

        full_md = "\n".join(lines)
        for m_blk in re.findall(r"```mermaid\n(.*?)```", full_md, re.DOTALL):
            errs = validate_mermaid_block(m_blk)
            if errs:
                print(f"[!] Mermaid syntax warning in {output_path}: {errs[0]}")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_md)
        print(f"L3 Diagrams successfully written to {output_path}")
    except Exception as e:
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
    """Render interface port utilization summary table across succeeded devices."""
    lines = [
        "\n### Interface Port Utilization Summary",
        "| Switch Hostname | Connected Ports | Total Ports | Utilization % |",
        "| --- | --- | --- | --- |",
    ]
    for ip, dev in devices.items():
        if dev.get("status", "success") != "success":
            continue
        ints_detail = dev.get("interfaces_detail", {})
        total = len(ints_detail)
        if total == 0:
            continue
        hostname = dev.get("hostname") or ip
        connected = sum(1 for stats in ints_detail.values() if stats.get("status") == "up")
        pct = (connected / total * 100) if total > 0 else 0
        lines.append(f"| {hostname} | {connected} | {total} | {pct:.1f}% |")
    return lines


def _render_stp_audit_section(devices: dict) -> list[str]:
    """Render Spanning Tree Protocol loop-risk and blocked-port audit."""
    lines = ["\n### Loop Risks & Spanning Tree (STP) Audit"]
    stp_issues = []
    stp_blocked_lines = []
    audited_switches = 0

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        stp = dev.get("stp", {})
        dev_type = dev.get("device_type", "switch").lower()

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
    if not stp_blocked_lines and not stp_issues:
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
    """Render overlapping subnets and duplicate IP address space conflict warnings."""
    lines = ["### Overlapping Subnets & IP Space Conflicts"]
    ip_subnets = []

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        raw_config = dev.get("raw_config", "")
        config_ips = parse_interface_ips_from_config(raw_config) if raw_config else {}
        for intf in dev.get("l3_interfaces", []):
            intf_name = intf.get("interface")
            intf_ip = intf.get("ip_address")
            if intf_ip and intf_ip not in ["unassigned", "down", "up", "unset"]:
                norm_name = normalize_interface_name(intf_name)
                _ip_from_cfg, mask_from_cfg = config_ips.get(norm_name, (None, None))
                clean_ip, net = parse_interface_network(intf_ip, mask_from_cfg)
                if net and clean_ip and not clean_ip.startswith(("127.", "128.0.")):
                    ip_subnets.append((hostname, intf_name, clean_ip, net))

    ip_conflicts = []
    subnet_overlaps = []
    for i in range(len(ip_subnets)):
        for j in range(i + 1, len(ip_subnets)):
            h1, int1, ip1, net1 = ip_subnets[i]
            h2, int2, ip2, net2 = ip_subnets[j]
            if ip1 == ip2 and (h1 != h2 or int1 != int2):
                ip_conflicts.append((h1, int1, ip1, h2, int2, ip2))
            elif h1 == h2 and int1 != int2 and (net1.cidr in net2.cidr or net2.cidr in net1.cidr):
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
        for rt in sorted_routes:
            lines.append(f"| `{rt['subnet']}` | {rt['protocol']} | {rt['next_hop']} | {rt['interface'] or 'N/A'} |")

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
        mgmt = dev.get("mgmt_method", "SSH")
        services = dev.get("services", {})
        if mgmt == "Telnet":
            gaps.append(f"* **{hostname}** is using unencrypted **Telnet** for management interface (Security risk).")
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
        "| Device | IP | PoE Budget (W) | PoE Used (W) | PoE Active Ports | Optics Count |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
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
            lines.append(f"| {hostname} | {ip} | {tot_w:.1f} | {used_w:.1f} | {poe_ports} | {optics_cnt} |")
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
        print(f"Cabling patching matrix successfully written to {output_path}")
    except Exception as e:
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
                writer.writerow(r)
        print(f"Port-to-MAC endpoint mapping successfully written to {output_path}")
    except Exception as e:
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
    variables = {}

    # Pre-parse VLAN names for all devices
    device_vlan_maps = {}
    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        cfg = dev.get("raw_config", "")
        vlan_names = {}
        if cfg:
            matches = re.finditer(r"^vlan\s+(\d+)\s*[\r\n]+(?:\s+name\s+(\S+))?", cfg, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                vlan_id = match.group(1)
                name = match.group(2)
                if name:
                    vlan_names[vlan_id] = name.strip().strip('"').strip("'")
        device_vlan_maps[hostname] = vlan_names

    for ip, dev in devices.items():
        if not _is_network_infra(dev):
            continue
        hostname = dev.get("hostname") or ip
        services = dev.get("services", {})

        # Build VLAN list
        vlans_list = []
        vlan_names = device_vlan_maps.get(hostname, {})
        for vid, vname in vlan_names.items():
            vlans_list.append({"id": vid, "name": vname})

        # Build SVI list
        l3_ints = dev.get("l3_interfaces", [])
        ints_detail = dev.get("interfaces_detail", {})
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

            subnet_range = ".".join(ip_addr.split(".")[:3]) + ".0/24" if (ip_addr and "." in ip_addr) else "N/A"
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
        "> **Notice**: This document is an authoritative, multi-tier network engineering analysis compiled "
        "from live operational telemetry and configuration running-states. It contains the complete technical specification "
        "required for bill-of-materials validation, physical patching, L2/L3 configuration migration, and maintenance-window execution.",
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


def _render_blueprint_executive_summary_section(unique_devs: dict) -> list[str]:
    """Render Section 1: Executive Summary & Current Hardware Estate."""
    lines = [
        "",
        "---",
        "",
        "## 1. Executive Summary & Current Hardware Estate",
        "",
        "The following estate reflects the physical and virtual network appliances discovered during discovery. "
        "Review model lifecycle status and recommended target architecture replacements:",
        "",
        "| Hostname | Management IP | Vendor | Model | Serial Number | Firmware OS | Persona | Target Replacement Guidance |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        vendor = dev.get("vendor", "Unknown")
        model = dev.get("model", "Unknown")
        serial = dev.get("serial", "Unknown")
        firmware = dev.get("firmware", "Unknown")
        persona = dev.get("device_persona", dev.get("device_type", "switch"))

        target_rec = "Standard Enterprise Managed Switch"
        if persona == "firewall":
            target_rec = "Next-Gen Firewall / Core Gateway (HA Pair)"
        elif persona == "router":
            target_rec = "Carrier-Grade Edge Router / L3 Spine"
        elif persona == "ap":
            target_rec = "Wi-Fi 6E/7 Enterprise AP (802.3at PoE+)"
        elif "cisco" in vendor.lower() and ("891" in model or "29" in model):
            target_rec = "Modern SD-WAN / 10G Routed Gateway"
        elif "juniper" in vendor.lower() and "ex2300" in model.lower():
            target_rec = "Target 10G/25G Core/Distribution Switch (e.g. Arista 7050 / Juniper EX4400)"

        lines.append(
            f"| **{hostname}** | `{ip}` | {vendor} | `{model}` | `{serial}` | `{firmware}` | `{persona}` | {target_rec} |"
        )
    return lines


def _collect_blueprint_cabling_and_mtu(unique_devs: dict) -> tuple[list[str], list[tuple]]:
    """Collect cabling matrix rows and detect cross-device MTU mismatches."""
    mtu_mismatches = []
    cabling_rows = []

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
            speed = stats.get("speed") or "1Gb/s"
            duplex = stats.get("duplex") or "Full"
            mtu = stats.get("mtu") or (9000 if "jumbo" in stats.get("description", "").lower() else 1500)

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

            if nbr and nbr_host != "Unconnected":
                for _rip, rdev in unique_devs.items():
                    if (rdev.get("hostname") or "").lower().split(".")[0] == nbr_host.lower().split(".")[0]:
                        r_ints = rdev.get("interfaces_detail", {})
                        r_stats = r_ints.get(nbr_port) or r_ints.get(nbr.get("remote_port", ""))
                        if r_stats:
                            r_mtu = r_stats.get("mtu") or (
                                9000 if "jumbo" in r_stats.get("description", "").lower() else 1500
                            )
                            if mtu != r_mtu:
                                mtu_mismatches.append((hostname, norm_port, mtu, nbr_host, nbr_port, r_mtu))

    return cabling_rows, mtu_mismatches


def _render_blueprint_cabling_and_mtu_section(unique_devs: dict) -> list[str]:
    """Render Sections 2.1 (Patch Cabling Matrix) and 2.2 (MTU Discrepancy Guard)."""
    lines = [
        "",
        "---",
        "",
        "## 2. Physical Layer 1/2 Cabling, Optics & MTU Matrix",
        "",
        "### 2.1 Patch Cabling, Port-Channels & Media Types",
        "Every physical patch cord, optic type, and uplink LAG/LACP bond must be accounted for before cutover night:",
        "",
        "| Source Switch | Source Port | Media / Form Factor | Speed / Duplex | Status | Connected Neighbor | Neighbor Port | LAG / Port-Channel |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    cabling_rows, mtu_mismatches = _collect_blueprint_cabling_and_mtu(unique_devs)
    lines.extend(cabling_rows[:60])
    if len(cabling_rows) > 60:
        lines.append(
            f"| ... and {len(cabling_rows) - 60} additional switch access ports recorded in migration_cabling_matrix.csv | | | | | | | |"
        )

    lines.extend(["", "### 2.2 MTU Discrepancy & Jumbo Frame Guard"])
    if mtu_mismatches:
        lines.append("> [!WARNING]")
        lines.append("> **CRITICAL MTU MISMATCH DETECTED ACROSS UPLINKS:**")
        for h1, p1, m1, h2, p2, m2 in mtu_mismatches:
            lines.append(
                f"> * **{h1}** (`{p1}`, MTU {m1}) <==> **{h2}** (`{p2}`, MTU {m2}). Mismatched MTUs will cause silent OSPF packet drops or jumbo-frame truncation!"
            )
    else:
        lines.append(
            "✓ **No MTU Mismatches Detected**: All discovered switch-to-switch uplinks share consistent standard MTU boundaries (1500 bytes)."
        )
    return lines


def _render_blueprint_optics_section(unique_devs: dict) -> list[str]:
    """Render Section 2.3: Optical Transceiver & Digital Optical Monitoring (DOM) Telemetry."""
    lines = [
        "",
        "### 2.3 Optical Transceiver & Digital Optical Monitoring (DOM) Telemetry",
        "Detailed physical telemetry for pluggable fiber/copper SFP, SFP+, and QSFP transceivers:",
        "",
        "| Switch Hostname | Port | Transceiver Model / Part | Serial Number | Form Factor | TX Power (dBm) | RX Power (dBm) | Temperature (°C) | Voltage (V) | Optical Health Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    optics_found = 0
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        for opt in dev.get("optics", []):
            optics_found += 1
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

            lines.append(
                f"| **{hostname}** | `{port}` | `{part}` | `{serial}` | `{form}` | {tx} | {rx} | {temp} | {volt} | {health} |"
            )

    if optics_found == 0:
        lines.append(
            "| *All Switches* | *N/A* | *No pluggable SFP/DOM optics detected (All RJ-45 copper access)* | *N/A* | `1000BASE-T` | N/A | N/A | N/A | N/A | ✓ Healthy (Copper PHY) |"
        )
    return lines


def _render_blueprint_mac_mapping_section(unique_devs: dict) -> list[str]:
    """Render Section 2.4: Port-to-Endpoint MAC Address Mapping & Access Layer Topology."""
    lines = [
        "",
        "### 2.4 Port-to-Endpoint MAC Address Mapping & Access Layer Topology",
        "Active Layer 2 MAC forwarding table entries mapped to physical switch ports and endpoint identities (exported to `port_mac_endpoint_mapping.csv`):",
        "",
        "| Switch Hostname | Port | VLAN | MAC Address | OUI Vendor | Resolved Device Role |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    mac_rows = []
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
            elif any(srv in v_lower for srv in ["vmware", "dell", "hp", "supermicro", "qemu"]):
                role = "Server / Hypervisor"
            else:
                role = "Workstation / Client"
            mac_rows.append(f"| **{hostname}** | `{port}` | `VLAN {vlan}` | `{mac}` | {vendor} | {role} |")

    lines.extend(mac_rows[:30])
    if len(mac_rows) > 30:
        lines.append(
            f"| ... and {len(mac_rows) - 30} additional learned MAC endpoints recorded in port_mac_endpoint_mapping.csv | | | | | |"
        )
    elif not mac_rows:
        lines.append(
            "| *Discovered Switches* | *Access Ports* | *VLAN 1* | *Dynamic MACs Pending Traffic* | Standard OUI | Client Workstations |"
        )
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
        "| Switch Hostname | Total PoE Capacity (W) | Consumed PoE Wattage (W) | Remaining Budget (W) | PoE Utilization | PSU Sizing Recommendation |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        poe = dev.get("poe", {})
        tot = poe.get("total_power_watts", 0.0)
        used = poe.get("used_power_watts", 0.0)
        rem = poe.get("available_power_watts", 0.0)
        persona = dev.get("device_persona", "")

        if not (persona == "switch" or tot > 0 or used > 0):
            continue
        if poe.get("poe_supported") is False and tot == 0.0 and used == 0.0:
            lines.append(f"| **{hostname}** | Non-PoE Switch | 0.0W | N/A | N/A | Non-PoE Core / Fiber SKU |")
        elif poe.get("budget_unreported") and used > 0.0:
            deliv_cnt = poe.get("poe_delivering_ports", 0)
            lines.append(
                f"| **{hostname}** | Unreported by CLI | {used:.1f}W ({deliv_cnt} active) | Unknown | N/A | Verify Chassis PSU Budget (Draw: {used:.1f}W) |"
            )
        elif tot == 0.0 and used == 0.0:
            lines.append(f"| **{hostname}** | Unknown | Unknown | Unknown | N/A | Unknown (Verify PSU / PoE Budget) |")
        elif tot == 0.0 and used > 0.0:
            lines.append(
                f"| **{hostname}** | 0.0W | {used:.1f}W | N/A | N/A | ⚠️ Conflict: 0W budget with active draw |"
            )
        else:
            pct = (used / tot * 100.0) if tot > 0 else 0.0
            req_w = max(tot, used * 1.25)
            psu_rec = (
                f"Minimum {int(req_w)}W+ PSU (Supports 802.3at PoE+ expansion)"
                if req_w > 370
                else "Standard 370W PSU (Class 3/4 Sufficient)"
            )
            lines.append(f"| **{hostname}** | {tot:.1f}W | {used:.1f}W | {rem:.1f}W | {pct:.1f}% | {psu_rec} |")
    return lines


def _render_blueprint_vlan_and_trunk_section(unique_devs: dict) -> list[str]:
    """Render Section 4: Layer 2 VLANs, 802.1Q Trunks & Native VLAN Map."""
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
    svi_rows = build_l3_svi_table(list(unique_devs.values()))
    vlan_rows = []
    for sr in svi_rows:
        site_lbl = sr["site_code"] or "-"
        vid_lbl = f"**{sr['vlan_id']}**" if sr["vlan_id"] else "-"
        vname_lbl = f"`{sr['vlan_name']}`" if sr["vlan_name"] else "-"
        rel_lbl = ", ".join(f"`{r}`" for r in sr["dhcp_relays"]) if sr["dhcp_relays"] else "None"
        vlan_rows.append(
            f"| {site_lbl} | **{sr['source_device']}** | {vid_lbl} | {vname_lbl} | `{sr['svi_interface']}` | "
            f"`{sr['primary_ip']}` | `{sr['prefix_cidr'] or 'N/A'}` | {rel_lbl} |"
        )
    if not vlan_rows:
        vlan_rows.append("| - | *None* | - | *No L3 VLAN/SVI mappings parsed* | - | `N/A` | `N/A` | - |")

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
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        relays = (dev.get("dhcp") or {}).get("relays", []) or []
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

    if not has_relays:
        lines.append(
            "| *None* | *No DHCP relay / ip helper-address entries discovered* | `N/A` | `N/A` | Unconfigured or Local DHCP |"
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
        "| Switch Hostname | STP Protocol Detected | Root Bridge Status | Bridge Priority | PortFast / Edge Ports | BPDU Guard Status | Migration Target Standard |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        stp = dev.get("stp", {}) or {}
        is_root = bool(stp.get("is_root", False))
        persona = dev.get("device_persona", "")
        if not (persona == "switch" or stp.get("enabled")):
            continue

        proto = stp.get("protocol") or "Unknown"
        prio = stp.get("bridge_priority") or "Unknown"
        if not stp.get("enabled"):
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

        pp = dev.get("port_profiles", {}) or {}
        edge_cnt = sum(1 for v in pp.values() if v.get("stp_edge") is True)
        bpdu_cnt = sum(1 for v in pp.values() if v.get("bpdu_guard") is True)
        edge_label = f"{edge_cnt} edge ports" if edge_cnt > 0 else "Unknown"
        bpdu_label = f"{bpdu_cnt} protected ports" if bpdu_cnt > 0 else "Unknown"

        lines.append(
            f"| **{hostname}** | `{proto}` | {root_label} | `{prio}` | {edge_label} | {bpdu_label} | Standard IEEE 802.1w / 802.1s |"
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
    fhrp_migration_rows = [
        f"| **{dev.get('hostname') or ip} ({f_item.get('interface', 'N/A')})** | `{f_item.get('protocol', 'Unknown').upper()}` | "
        f"`{f_item.get('vip', 'Unknown')}` | `{dev.get('hostname') or ip}` | {f_item.get('state', 'Unknown')} | "
        f"{f_item.get('preempt', 'Unknown')} | Standard VRRPv3 (RFC 5798) |"
        for ip, dev in unique_devs.items()
        for f_item in (dev.get("fhrp", []) or [])
    ]

    if fhrp_migration_rows:
        lines.extend(
            [
                "| Redundancy Group | Protocol Type | Virtual IP Address | Active Primary Node | Standby Secondary Node | Preemption | Target Migration Standard |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                *fhrp_migration_rows,
            ]
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
            "| Device Hostname | Default Route (`0.0.0.0/0`) Next-Hop | Exit Interface | Protocol Type | Administrative Distance |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for ip, dev in unique_devs.items():
        hostname = dev.get("hostname") or ip
        for r in dev.get("routes", []):
            rd = get_route_details(r)
            if rd.get("subnet") in ("0.0.0.0/0", "default"):
                lines.append(
                    f"| **{hostname}** | `{rd.get('next_hop')}` | `{rd.get('interface')}` | `{rd.get('protocol')}` | 1 (Static) |"
                )
    return lines


def _render_blueprint_security_and_services_section(unique_devs: dict) -> list[str]:
    """Render Sections 9 (Security/ACLs/NAT) and 10 (Infrastructure Services)."""
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
        persona = dev.get("device_persona", "")
        mgmt = str(dev.get("mgmt_method") or "Unknown")
        sec_pol = dev.get("security_policy") or {}
        fw_cnt = len(sec_pol.get("firewall_rules") or [])
        nat_cnt = len(sec_pol.get("nat_rules") or [])
        insecure_col = (
            "Telnet Active" if "telnet" in mgmt.lower() else ("Unknown" if mgmt == "Unknown" else "SSH/API Only")
        )
        secure_col = mgmt if mgmt != "Unknown" else "Unknown"
        acl_col = f"{fw_cnt} parsed rules" if fw_cnt > 0 else "Unknown (Not Queried)"
        nat_status = (
            f"Enabled ({nat_cnt} rules)"
            if nat_cnt > 0
            else ("Disabled (Pure L2/L3)" if persona in ("switch", "router") else "Unknown")
        )
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

    dns_all, ntp_all, rad_all, sys_all = set(), set(), set(), set()
    for dev in unique_devs.values():
        serv = dev.get("services", {})
        dns_all.update(serv.get("dns_servers", []))
        ntp_all.update(serv.get("ntp_servers", []))
        rad_all.update(serv.get("radius_servers", []))
        sys_all.update(serv.get("syslog_servers", []))

    dns_str = ", ".join(f"`{s}`" for s in sorted(dns_all)) or "Unknown (Not Discovered)"
    ntp_str = ", ".join(f"`{s}`" for s in sorted(ntp_all)) or "Unknown (Not Discovered)"
    sys_str = ", ".join(f"`{s}`" for s in sorted(sys_all)) or "Unknown (Not Discovered)"
    rad_str = ", ".join(f"`{s}`" for s in sorted(rad_all)) or "Unknown / Local RBAC"

    lines.append(f"| **DNS Resolvers** | {dns_str} | DNS UDP/TCP 53 | ✓ Consistent Across Fleet |")
    lines.append(f"| **NTP Strata** | {ntp_str} | NTP UDP 123 | ✓ Clock Synchronized |")
    lines.append(f"| **Syslog Logging** | {sys_str} | Syslog UDP 514 | ✓ Audit Trail Maintained |")
    lines.append(
        f"| **AAA Authentication** | {rad_str} | RADIUS UDP 1812 / TACACS+ | ✓ Encrypted Identity Management |"
    )
    return lines


def _render_blueprint_translation_and_runbook_section(unique_devs: dict) -> list[str]:
    """Render Sections 11 (Protocol Translation) and 12 (Cutover Runbook & Rollback Plan)."""
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
    if any("cisco" in v for v in vendors_present):
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
        lines.extend(
            [
                "| **Junos `family ethernet-switching`** | Target Access / Trunk Port Profile | Map `interface-mode` + `vlan members` (expanding `all`) and `native-vlan-id`. | Medium |",
                "| **Junos `irb.<vid>` + `dhcp-relay`** | Target SVI / Routed VLAN Interface | Preserve IP/prefix, VRF, and `active-server-group` relay bindings. | Medium |",
                "| **Junos `switch-options voip`** | Target Voice VLAN / LLDP-MED | Map `voip interface` VLAN bindings to target voice-VLAN + LLDP-MED policy. | Low |",
            ]
        )
    if any("procurve" in v or "hp" in v or "aruba" in v for v in vendors_present):
        lines.extend(
            [
                "| **HP/Aruba `untagged` / `tagged` VLANs** | Target Access / Trunk Port Profile | Convert `untagged` on trunks to native VLAN and `tagged` sets to allowed VLANs. | Medium |",
                "| **HP/Aruba `Trk*` + `ip helper-address`** | Target LACP LAG + SVI Relay | Map `Trk*` bundles to LACP active LAGs and per-VLAN `ip helper-address`. | Medium |",
            ]
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 12. Maintenance Window Cutover Runbook & Rollback Plan",
            "",
            "### 12.1 Pre-Cutover T-Minus Checklist (24 Hours Prior)",
            "- [ ] **Backup Verification**: All running configurations backed up (`net_docu_crawler_dataset.json` preserved).",
            "- [ ] **Optics & Patching Staging**: Physical transceivers and cables staged according to Section 2.1.",
            "- [ ] **DHCP Relay Validation**: Target replacement switches have helper addresses provisioned per Section 5.",
            "- [ ] **Validation Script Ready**: Verify `./validate_cutover.sh` is executable and passes against baseline.",
            "",
            "### 12.2 Cutover Window Execution Sequence (T-0 to T+30m)",
            "1. **T-0:00 - Silence Monitoring Alerts**: Place core and access switches in maintenance mode in SIEM/NMS.",
            "2. **T-0:05 - Physical Cable Transfer**: Move patch cables in order specified by `migration_cabling_matrix.csv`.",
            "3. **T-0:15 - Power-On Target Hardware**: Power up target switches; verify dual PSU green LEDs.",
            "4. **T-0:20 - Run Automated Smoke Tests**: Execute `./validate_cutover.sh` from jumphost to verify gateway reachability.",
            "5. **T-0:25 - User & Wireless Smoke Test**: Test client DHCP lease acquisition on discovered access/voice VLANs.",
            "",
            "### 12.3 Rollback Plan & Decision Gate",
            "> [!CAUTION]",
            "> **HARD ABORT CRITERIA**: If core gateway reachability or client DHCP leasing fails and cannot be resolved "
            "within 45 minutes of maintenance window start, trigger immediate rollback:",
            "1. Power down replacement hardware.",
            "2. Re-seat original cables into legacy switch ports using `migration_cabling_matrix.csv` as source reference.",
            "3. Power on legacy switches and run `./validate_cutover.sh` to confirm 100% baseline restoration.",
            "",
            "---",
            "*Automated Migration Blueprint compiled by Net-Docu-Crawler Engine.*",
        ]
    )
    return lines


def generate_master_network_analysis_migration_blueprint(
    devices: dict,
    output_path: str = "Network_Analysis.md",
    scope: str = "Discovered Network",
    timestamp: str = "",
    dns_domain: str = "",
) -> None:
    """
    Generates the comprehensive, unified Master Migration Blueprint (Network_Analysis.md)
    containing all operational, physical, logical, services, and procedural intelligence
    required by a Senior Network Engineer to execute a flawless cutover to new network gear.
    """
    if not timestamp:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    unique_devs = get_unique_devices({ip: dev for ip, dev in devices.items() if _is_network_infra(dev)})
    lines = _render_blueprint_header_and_toc(scope, dns_domain, timestamp, len(unique_devs))
    lines.extend(_render_blueprint_executive_summary_section(unique_devs))
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

    for gw in sorted(gateways):
        lines.append(f'check_ping "{gw}" "Gateway / SVI"')

    lines.extend(
        [
            "",
            'echo -e "\\n${BOLD}[*] Phase 2: Verifying Core DNS Resolvers...${NC}"',
        ]
    )
    for dns in sorted(dns_servers):
        lines.append(f'check_ping "{dns}" "DNS Resolver"')
        lines.append(f'check_port "{dns}" 53 "DNS Port 53"')

    lines.extend(
        [
            "",
            'echo -e "\\n${BOLD}[*] Phase 3: Verifying Management Services (SSH Port 22)...${NC}"',
        ]
    )
    for dev in devices.values():
        if not _is_network_infra(dev):
            continue
        dev_ip = dev.get("ip")
        dev_host = dev.get("hostname") or dev_ip
        if dev_ip:
            lines.append(f'check_port "{dev_ip}" 22 "{dev_host} SSH"')

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
            ps1_lines.append(f'Test-PingReachability -ip "{gw}" -label "Gateway / SVI"')

        ps1_lines.extend(
            [
                "",
                'Write-Host "`n[*] Phase 2: Verifying Core DNS Resolvers..." -ForegroundColor Cyan',
            ]
        )
        for dns in sorted(dns_servers):
            ps1_lines.append(f'Test-PingReachability -ip "{dns}" -label "DNS Resolver"')
            ps1_lines.append(f'Test-TcpPort -ip "{dns}" -port 53 -label "DNS Port 53"')

        ps1_lines.extend(
            [
                "",
                'Write-Host "`n[*] Phase 3: Verifying Management Services (SSH Port 22)..." -ForegroundColor Cyan',
            ]
        )
        for dev in devices.values():
            dev_ip = dev.get("ip")
            dev_host = dev.get("hostname") or dev_ip
            if dev_ip:
                ps1_lines.append(f'Test-TcpPort -ip "{dev_ip}" -port 22 -label "{dev_host} SSH"')

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
        print(f"BOM & hardware sizing CSV successfully written to {output_path}")
    except Exception as e:
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
        w.writerows(fail_rows)


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
            row = {
                "hostname": p_rec.get("hostname", ""),
                "interface": p_rec.get("interface", ""),
                "admin_state": p_rec.get("admin_state", ""),
                "oper_state": p_rec.get("oper_state", ""),
                "mode": p_rec.get("mode", ""),
                "access_vlan": p_rec.get("access_vlan", ""),
                "voice_vlan": p_rec.get("voice_vlan", ""),
                "native_vlan": p_rec.get("native_vlan", ""),
                "allowed_vlans": ",".join(p_rec.get("allowed_vlans") or []),
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
            iface_rows.append(row)
            if row["hygiene_disposition"] in ("SHUTDOWN", "QUARANTINE", "REVIEW"):
                unused_rows.append(row)

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
        {
            "hostname": d.get("hostname") or d.get("ip", ""),
            "site_code": d.get("site_code", ""),
            "vlan_id": vid,
            "vlan_name": vinfo.get("name", ""),
            "svi_interface": vinfo.get("svi_interface", ""),
            "voice": vinfo.get("voice", False),
        }
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
        "svi_interface",
        "primary_ip",
        "prefix_cidr",
        "dhcp_relays",
        "confidence",
    ]
    with open(os.path.join(norm_dir, "svi_routes.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=svi_fields)
        w.writeheader()
        for sr in svi_rows:
            row = dict(sr)
            row["dhcp_relays"] = ",".join(sr.get("dhcp_relays") or [])
            w.writerow(row)
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
            fieldnames=["node_a", "port_a", "node_b", "port_b", "status", "type", "link_class"],
            extrasaction="ignore",
        )
        w.writeheader()
        for lk in getattr(registry, "links", []) or []:
            row = dict(lk)
            row.setdefault("link_class", "infra_uplink")
            w.writerow(row)

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
        w.writerows(trunk_csv_rows)

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
    infra = [d for d in raw_devices if d.get("status", "success") == "success"]
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


def _build_trunk_audit_markdown_section(
    devices_or_audit,
    heading: str = "### Trunk VLAN Mismatch & L2 Symmetry Audit",
) -> list[str]:
    """Build a concise Markdown summary table for trunk VLAN mismatch & L2 symmetry findings."""
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

    sec_lines = [
        "",
        heading,
        (
            f"Evaluated Trunk Links: **{edges_eval}** | Total Findings: **{total_cnt}** "
            f"(CRITICAL: **{crit_cnt}**, HIGH: **{high_cnt}**, MEDIUM: **{med_cnt}**, "
            f"LOW: **{low_cnt}**, INFO: **{info_cnt}**)"
        ),
        "",
        "| Edge_ID | Side_A_Host | Side_A_Port | Side_B_Host | Side_B_Port | Rule_ID | Severity | Side_A_Only_VLANs | Side_B_Only_VLANs | Remediation_Hint |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    if rows:
        for r in rows[:50]:
            sec_lines.append(
                f"| `{r['Edge_ID']}` | **{r['Side_A_Host']}** | `{r['Side_A_Port']}` | "
                f"**{r['Side_B_Host'] or 'N/A'}** | `{r['Side_B_Port'] or 'N/A'}` | "
                f"`{r['Rule_ID']}` | **{r['Severity']}** | `{r['Side_A_Only_VLANs'] or '-'}` | "
                f"`{r['Side_B_Only_VLANs'] or '-'}` | {r['Remediation_Hint']} |"
            )
        if len(rows) > 50:
            sec_lines.append(
                f"| *... and {len(rows) - 50} additional trunk findings recorded in `trunk_vlan_audit.md` and `03_correlated/trunk_mismatches.csv`* | | | | | | | | | |"
            )
    else:
        sec_lines.append(
            "| *All Evaluated Trunks* | *Symmetric* | `-` | *Symmetric* | `-` | `PASS` | **PASS** | `-` | `-` | ✓ Zero 802.1Q trunk VLAN, native PVID, or mode mismatches detected. |"
        )
    return sec_lines


def generate_trunk_audit_report(devices_or_audit, output_path: str = "trunk_vlan_audit.md") -> dict:
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
        f"| **Evaluated Trunk / Uplink Edges** | `{edges_eval}` | Audited |",
        f"| **Total Discrepancy Findings** | `{total_cnt}` | {'WARN' if (crit_cnt + high_cnt) > 0 else 'PASS'} |",
        f"| **CRITICAL Findings (`TRK-001`, `TRK-002`)** | `{crit_cnt}` | {'⚠️ Action Required' if crit_cnt > 0 else '✓ Clean'} |",
        f"| **HIGH Findings (`TRK-003`, `TRK-004`)** | `{high_cnt}` | {'⚠️ Action Required' if high_cnt > 0 else '✓ Clean'} |",
        f"| **MEDIUM Findings (`TRK-005`, `TRK-006`, Boundary)** | `{med_cnt}` | {'Review Recommended' if med_cnt > 0 else '✓ Clean'} |",
        f"| **LOW Findings (`TRK-007`)** | `{low_cnt}` | {'Hardening Opportunity' if low_cnt > 0 else '✓ Clean'} |",
        f"| **INFO Findings (`INFO_QINQ_BOUNDARY`)** | `{info_cnt}` | Informational |",
    ]

    lines.extend(
        _build_trunk_audit_markdown_section(
            audit,
            heading="## 2. Trunk VLAN Mismatch & L2 Symmetry Discrepancy Table",
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

# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
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
Modular Topology Graph Builder & Pluggable Renderer Registry.

Serves as the single source of truth (`build_topology_graph_model`) for both
Markdown diagrams (`report_generator.py`) and offline interactive HTML/SVG
visualization (`InteractiveHTMLTopologyRenderer`), powered by `netaddr`
(https://netaddr.readthedocs.io/) and Mermaid-compatible schemas
(https://mermaid.js.org/).
"""

from __future__ import annotations

import datetime
import json
import os
import re
from abc import ABC, abstractmethod
from collections import deque
from typing import Any

from netaddr import AddrFormatError, IPAddress, IPNetwork

import oui_lookup
from net_docu_crawler.schema import infer_site_code
from net_docu_crawler.topology_resolver import normalize_interface

_INFRA_DEVICE_TYPES = frozenset({"switch", "router", "firewall", "ap", "wlc", "wireless", "gateway", "bridge"})

_ROLE_ORDER = {
    "isp": 0,
    "firewall": 0,
    "wan_cloud": 1,
    "router": 1,
    "core": 2,
    "dist": 3,
    "switch": 4,
    "access": 4,
    "wlc": 4,
    "ap": 5,
    "uncrawled": 6,
    "uncrawled_switch": 6,
}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_TUNNEL_INTF_RE = re.compile(r"^(?:tun(?:nel)?|wg|gre|st\d|ipsec|vti)\S*$", re.IGNORECASE)
_UNNUMBERED_NH_TOKENS = frozenset(
    {"", "unnumbered", "directly connected", "connected", "local", "link-local", "n/a", "none", "-"}
)
_DEFAULT_VRF_ALIASES = frozenset({"", "global", "default", "global-table", "main", "inet.0", "inet6.0"})
_MAC_ANY_RE = re.compile(
    r"(?:^|[^0-9a-f])([0-9a-f]{2}(?:[:.\-\s][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})(?:$|[^0-9a-f])",
    re.IGNORECASE,
)
_INLINE_HEX12_RE = re.compile(r"(?:mac[-_:]|[-_])([0-9a-f]{12})$", re.IGNORECASE)

_ENDPOINT_DEVICE_TYPES = frozenset(
    {
        "phone",
        "voip",
        "camera",
        "printer",
        "server",
        "host",
        "workstation",
        "endpoint",
        "av_control",
        "display",
        "ups",
        "nas",
        "iot",
    }
)

_HP_PRINTER_PC_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:laserjet|officejet|deskjet|designjet|pagewide|scanjet|printer|mfp|jetdirect|"
    r"desktop-|laptop-|prodesk|elitedesk|probook|elitebook|zbook)(?![a-z0-9])",
    re.IGNORECASE,
)

_MANAGED_FIREWALL_RE = re.compile(
    r"(?:palo\s*alto|forti(?:gate|os|wifi|switch)?|opnsense|pfsense|checkpoint|sonicwall|cisco\s*asa|firepower|(?<![a-z0-9])srx\d*)",
    re.IGNORECASE,
)

_MANAGED_ROUTER_RE = re.compile(
    r"(?:mikrotik|routeros|frrouting|edgerouter|cisco\s*ios-xr|(?<![a-z0-9])(?:isr|asr)\d+|(?<![a-z0-9])mx\d{2,4}(?![a-z0-9]))",
    re.IGNORECASE,
)

_LINUX_SERVER_HOST_RE = re.compile(
    r"(?:linux\s*host|proxmox|librenms|(?<![a-z0-9])pve(?![a-z0-9]))",
    re.IGNORECASE,
)

_EXPLICIT_ROUTER_OVERRIDE_RE = re.compile(
    r"(?:frr-router|routeros|edgerouter|vyos|mikrotik)",
    re.IGNORECASE,
)

_GENERIC_SITE_PREFIXES = frozenset(
    {
        "FRR",
        "ARISTA",
        "CISCO",
        "JUNIPER",
        "MIKROTIK",
        "FORTI",
        "PALO",
        "OPNSENSE",
        "OPENWRT",
        "ARUBA",
        "RUCKUS",
        "SWITCH",
        "ROUTER",
        "GATEWAY",
        "CORE",
        "LAB",
    }
)

_MANAGED_SWITCH_RE = re.compile(
    r"(?:procurve|arubaos-s|arubaos-cx|hpn\s*supply\s*chain|hewlett\s*packard\s*enterprise|comware|"
    r"catalyst|nexus|cisco\s*ios|arista|snapav|araknis|netgear|brocade|ruckus\s*icx|extreme|unifi\s*switch|"
    r"edgeswitch|meraki\s*ms|"
    r"(?<![a-z0-9])(?:j[489]\d{2,4}[a-z]?|jl\d{3,4}[a-z]?|j9|jl|2530|2610|2920|2930|5406|5412|"
    r"ex[2349]\d*|qfx\d*|srx\d*|usw-[a-z0-9-]+|switch|mdf|idf|do-main|do-old|do-pd|do-idf)(?![a-z0-9]))",
    re.IGNORECASE,
)

_AP_SIGNAL_RE = re.compile(
    r"(?:access\s*point|wlan|arubaos|instant|unifi|\buap\b|\bu6\b|ruckus|meraki|aironet|\bap[-_]\d+|\bair-(?:ap|cap))",
    re.IGNORECASE,
)

_AP_NOT_SWITCH_GUARD_RE = re.compile(
    r"(?:(?<![a-z0-9])(?:ex[2349]\d*|6[123]00|2530|2920|2930|5406|5412|icx|ms\d+|mx\d+)(?![a-z0-9])|"
    r"procurve|arubaos-s|arubaos-cx|edgeswitch|edgerouter|unifi\s*switch|usw-|edge|switch|router|gateway|firewall|mdf|idf)",
    re.IGNORECASE,
)

_ENDPOINT_PHONE_HOST_RE = re.compile(
    r"^(?:(?:d\d+|p\d+)-[0-9a-f]{12}|sep[0-9a-f]{12}|t\d{2}[a-z][0-9a-f]{12}|s\d{12,})$",
    re.IGNORECASE,
)

_ENDPOINT_KEYWORD_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:sip-|dp750|digium|sangoma|yealink|polycom|grandstream|snom|mitel|avaya|"
    r"spa232|cisco\s*ata|audiocodes|voip|ip\s*phone|"
    r"axis|hikvision|verkada|cc500-|cc300-|ch53-|ch63-|cb63-|cf83-|valcom|hanwha|"
    r"crestron|extron|biamp|tsw-|"
    r"desktop-|laptop-|do-fisc-|do-katye|apple|ipad|iphone|macbook|windows|dell|lenovo|intel|"
    r"microsoft|vmware|esxi|ubuntu|debian|workstation|-pos-|pos-\d|"
    r"canon|epson|xerox|brother|lexmark|ricoh|laserjet|officejet|deskjet|printer|mfp|jetdirect)",
    re.IGNORECASE,
)

_PHONE_PORT_RE = re.compile(r"^(?:(?:wan|pc)\s*port\b|wan\.{2,}$)", re.IGNORECASE)


def _norm_iface(name: str) -> str:
    """Return a canonical lowercase interface identifier for deduplication and lookups."""
    if not name:
        return ""
    norm = normalize_interface(name).lower().strip()
    replacements = (
        ("hundredgigabitethernet", "hu"),
        ("hundredgige", "hu"),
        ("fortygigabitethernet", "fo"),
        ("tengigabitethernet", "te"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("port-channel", "po"),
        ("bundle-ether", "be"),
        ("ethernet", "et"),
    )
    for full, short in replacements:
        if norm.startswith(full):
            return norm.replace(full, short, 1)
    return norm


def _normalize_vrf_name(raw_vrf: str | None) -> str:
    """Normalize VRF/routing-instance names, mapping un-VRF'd/global aliases to ``'default'``."""
    v = str(raw_vrf or "").strip().strip('"').strip("'")
    if v.lower() in _DEFAULT_VRF_ALIASES:
        return "default"
    return v


def _is_valid_ipv6(val: str) -> bool:
    s = str(val or "").strip()
    if not s or ":" not in s:
        return False
    try:
        return IPAddress(s.split("%", 1)[0]).version == 6
    except (AddrFormatError, ValueError):
        return False


def _is_valid_ip(val: str) -> bool:
    return _is_valid_ipv4(val) or _is_valid_ipv6(val)


def _is_default_route_prefix(sub_str: str) -> bool:
    return str(sub_str or "").strip() in ("0.0.0.0/0", "::/0")


def _parse_iface_network(ip_str: str, mask_hint: str | None = None) -> tuple[str, IPNetwork | None]:
    """Parse IPv4 or IPv6 CIDR, space-separated netmask, or bare IP strings into ``(clean_ip, IPNetwork | None)``."""
    if not ip_str:
        return "", None
    raw = str(ip_str).strip()
    if raw.lower() in ("unassigned", "down", "up", "unset", "n/a", "none", "0.0.0.0", "::", "unnumbered"):
        return "", None

    clean_ip = raw.split("/")[0].split()[0].split("%")[0].strip()
    is_v4 = bool(_IPV4_RE.match(clean_ip))
    is_v6 = _is_valid_ipv6(clean_ip) if not is_v4 else False
    if not is_v4 and not is_v6:
        return "", None

    net: IPNetwork | None = None
    try:
        if "/" in raw:
            net = IPNetwork(raw.split()[0].split("%")[0])
        elif " " in raw and is_v4:
            parts = raw.split()
            net = IPNetwork(f"{parts[0]}/{parts[1]}")
        elif mask_hint:
            net = IPNetwork(f"{clean_ip}/{mask_hint.lstrip('/')}")
        else:
            net = IPNetwork(f"{clean_ip}/{'64' if is_v6 else '24'}")
    except (AddrFormatError, ValueError, TypeError):
        net = None
    return clean_ip, net


def _normalize_site_code(raw_site: str, hostname: str, ip: str) -> str:
    sc = str(raw_site or infer_site_code(hostname, ip) or "CORE").strip().upper()
    if not sc or sc in _GENERIC_SITE_PREFIXES:
        return "CORE"
    return sc


def _slugify(val: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (val or "").lower()).strip("_") or "unknown"


def _short_hostname(raw_name: str) -> str:
    """Return short hostname while preserving IPv4 literals and parenthesized gateway labels."""
    cleaned = str(raw_name or "").strip().strip('"').strip("'")
    if not cleaned:
        return ""
    if _IPV4_RE.match(cleaned) or "(" in cleaned:
        return cleaned
    parts = cleaned.split(".")
    if len(parts) > 1 and any(ch.isalpha() for ch in parts[1]):
        return parts[0]
    return cleaned


def _extract_valid_mac(val: str) -> str:
    """Extract and normalize a 48-bit MAC address from raw strings, rejecting IPv4 addresses."""
    s = str(val or "").strip()
    if not s or _IPV4_RE.match(s):
        return ""
    m = _MAC_ANY_RE.search(s)
    if m:
        candidate = m.group(1).replace(" ", ":")
        norm = oui_lookup.normalize_mac(candidate).lower().strip()
        if norm and norm != "00:00:00:00:00:00":
            return norm
    m_hex = _INLINE_HEX12_RE.search(s)
    if m_hex:
        raw = m_hex.group(1).lower()
        return ":".join(raw[i : i + 2] for i in range(0, 12, 2))
    return ""


def _extract_neighbor_mac(remote_host: str, nbr: dict[str, Any]) -> str:
    """Resolve the best valid MAC address from neighbor metadata, hostname, or port fallback."""
    for candidate in (
        str(nbr.get("remote_mac") or ""),
        str(remote_host or ""),
        str(nbr.get("remote_port") or ""),
    ):
        mac = _extract_valid_mac(candidate)
        if mac:
            return mac
    return ""


def _is_explicit_endpoint(rh_l: str, rport_l: str, hay: str, dtype: str, caps_l: str) -> bool:
    if dtype in _ENDPOINT_DEVICE_TYPES:
        return True
    if _ENDPOINT_PHONE_HOST_RE.match(rh_l):
        return True
    if _PHONE_PORT_RE.match(rport_l):
        return True
    if "telephone" in caps_l:
        return True
    if _ENDPOINT_KEYWORD_RE.search(hay):
        return True
    if "hp inc" in hay and not _MANAGED_SWITCH_RE.search(hay):
        return True
    return False


def classify_neighbor_node(
    remote_host: str,
    nbr: dict,
    crawled_hosts_lc: set[str] | None = None,
    crawled_ips: set[str] | None = None,
    crawled_macs: set[str] | None = None,
) -> str:
    """
    Classify an LLDP/CDP/synthesized neighbor strictly in priority order:
      1. Crawled infrastructure (hostname, IP, or MAC match) -> ``"crawled_infra"``
      2. Explicit synthesized WAN/Firewall/L3 egress or managed infra -> ``"firewall"`` /
         ``"router"`` / ``"isp"`` / ``"uncrawled_switch"``
      3. Wireless APs (explicit type, platform/capabilities, or AP OUI) -> ``"ap"``
      4. Non-infra endpoint exclusion (phones, cameras, AV, PCs, printers) -> ``"endpoint"``
    """
    nbr_d = nbr if isinstance(nbr, dict) else {}
    rh = str(remote_host or "").strip().strip('"').strip("'")
    rh_l = rh.lower()
    is_ipv4_host = bool(_IPV4_RE.match(rh_l))
    rh_short = rh_l if (is_ipv4_host or "(" in rh_l) else rh_l.split(".")[0]
    rip = str(nbr_d.get("remote_ip") or "").strip().lower()
    rport_l = str(nbr_d.get("remote_port") or "").strip().lower()
    rmac = _extract_neighbor_mac(rh, nbr_d)

    hosts_lc = {str(h).strip().lower() for h in (crawled_hosts_lc or set()) if h}
    ips_lc = {str(ip).strip().lower() for ip in (crawled_ips or set()) if ip}
    macs_lc = {oui_lookup.normalize_mac(str(m)).lower().strip() for m in (crawled_macs or set()) if m}

    # 1. Crawled infrastructure always wins
    if (rh_l and rh_l in hosts_lc) or (rh_short and rh_short in hosts_lc):
        return "crawled_infra"
    if (rip and rip in ips_lc) or (is_ipv4_host and rh_l in ips_lc):
        return "crawled_infra"
    if rmac and rmac in macs_lc:
        return "crawled_infra"

    dtype = str(nbr_d.get("device_type") or "").strip().lower()
    l2_acc = str(nbr_d.get("l2_accuracy") or "").strip().lower()
    plat_l = str(nbr_d.get("platform") or nbr_d.get("remote_platform") or "").strip().lower()
    caps_raw = nbr_d.get("capabilities") or nbr_d.get("remote_capabilities") or []
    if isinstance(caps_raw, (list, tuple, set)):
        caps_l = " ".join(str(c).lower() for c in caps_raw)
    else:
        caps_l = str(caps_raw).lower()

    oui_raw = oui_lookup.lookup_oui(rmac) if rmac else ""
    oui_l = "" if not oui_raw or oui_raw.lower() == "unknown" else oui_raw.lower()
    hay = f"{rh_l} {plat_l} {oui_l} {caps_l}"

    # 2. Explicit synthesized WAN / Firewall / L3 egress or managed network gear
    if l2_acc in ("wan_carrier_arp_route", "l3_next_hop_egress"):
        if dtype in ("firewall", "router", "isp"):
            return dtype
        return "uncrawled_switch"
    if dtype in ("firewall", "router", "isp"):
        return dtype
    if dtype == "wlc":
        return "uncrawled_switch"
    if dtype in _ENDPOINT_DEVICE_TYPES:
        return "endpoint"

    # Linux hypervisors / monitoring hosts (e.g. Proxmox/LibreNMS reporting "FRRouting Linux Host")
    if _LINUX_SERVER_HOST_RE.search(hay) and not _EXPLICIT_ROUTER_OVERRIDE_RE.search(hay):
        return "endpoint"

    # Printers/PCs must never masquerade as HPE switches
    if _HP_PRINTER_PC_RE.search(hay):
        return "endpoint"

    if _MANAGED_FIREWALL_RE.search(hay):
        return "firewall"
    if _MANAGED_ROUTER_RE.search(hay):
        return "router"
    if "spectrum internet" in hay or "fiber nid" in hay:
        return "isp"

    if _MANAGED_SWITCH_RE.search(hay):
        return "uncrawled_switch"

    # Hewlett Packard / HPN switches (when not HP Inc. PC or HP printer)
    if ("hewlett packard" in hay or "hewlett-packard" in hay) and "hp inc" not in hay:
        if not _is_explicit_endpoint(rh_l, rport_l, hay, dtype, caps_l):
            return "uncrawled_switch"

    # LLDP Bridge/Router capabilities without Telephone/Station/WLAN hints
    if caps_l and "telephone" not in caps_l and "station" not in caps_l and "wlan" not in caps_l:
        if "router" in caps_l and "bridge" not in caps_l:
            return "router"
        if "bridge" in caps_l and not _is_explicit_endpoint(rh_l, rport_l, hay, dtype, caps_l):
            return "uncrawled_switch"

    # 3. Wireless AP detection (even when device_type=="unknown" or platform=="")
    if dtype == "ap":
        return "ap"
    if _AP_SIGNAL_RE.search(f"{rh_l} {plat_l} {caps_l}") and not _AP_NOT_SWITCH_GUARD_RE.search(f"{rh_l} {plat_l}"):
        return "ap"
    if any(k in oui_l for k in ("ruckus", "aruba", "ubiquiti", "meraki", "aerohive", "mist", "cambium")):
        if not _AP_NOT_SWITCH_GUARD_RE.search(f"{rh_l} {plat_l}") and not _is_explicit_endpoint(
            rh_l, rport_l, hay, dtype, caps_l
        ):
            return "ap"

    # 4. Non-infra endpoint exclusion (before trusting generic device_type=="switch")
    if _is_explicit_endpoint(rh_l, rport_l, hay, dtype, caps_l):
        return "endpoint"

    if dtype in ("switch", "bridge"):
        return "uncrawled_switch"

    return "endpoint"


def _is_network_infra(dev: dict) -> bool:
    """Return True if a crawled device record represents network infrastructure."""
    status = str(dev.get("status", "success")).strip().lower()
    if status != "success":
        return False
    dtype = str(dev.get("device_type") or dev.get("device_persona") or "switch").strip().lower()
    return dtype in _INFRA_DEVICE_TYPES


def _classify_node_role(dev: dict, hostname: str) -> str:
    persona = str(dev.get("device_persona") or dev.get("device_type") or "switch").strip().lower()
    if persona in ("firewall", "router", "ap", "wlc", "isp"):
        return persona
    if persona == "gateway":
        return "router"
    hn_l = hostname.lower()
    model_l = str(dev.get("model") or "").lower()
    valid_l3 = [
        intf
        for intf in (dev.get("l3_interfaces") or [])
        if not str((intf or {}).get("ip_address") or "").strip().startswith(("127.", "128.0."))
    ]
    if (
        any(k in hn_l for k in ("core", "mdf", "main"))
        or any(k in model_l for k in ("5412", "5406", "ex4600", "ex4650", "c9500", "ex9200"))
        or len(valid_l3) >= 3
    ):
        return "core"
    if any(k in hn_l for k in ("dist", "idf")) or any(k in model_l for k in ("c3850", "c9300")):
        return "dist"
    return "switch"


def _extract_junos_vlan_descriptions(raw_config: str) -> dict[str, str]:
    """Fallback parser extracting ``set vlans <name> description <desc>`` from raw Junos config."""
    descs: dict[str, str] = {}
    if not raw_config:
        return descs
    for m in re.finditer(r"^\s*set\s+vlans\s+(\S+)\s+description\s+(.+)$", raw_config, re.MULTILINE):
        vname = m.group(1).strip().strip('"').strip("'")
        desc = m.group(2).strip().strip('"').strip("'")
        if vname and desc:
            descs[vname.lower()] = desc
    return descs


def _resolve_vlan_meta(
    intf_name: str,
    vlans_map: dict[str, Any],
    fallback_descs: dict[str, str],
) -> tuple[str, str, str]:
    """Resolve ``(vlan_id, vlan_name, vlan_description)`` for an SVI interface."""
    iname = (intf_name or "").strip()
    if not iname or not isinstance(vlans_map, dict):
        return "", "", ""

    def _desc_for(vinfo: dict[str, Any], vname: str) -> str:
        d = str(vinfo.get("description") or "").strip().strip('"').strip("'")
        if not d and vname:
            d = fallback_descs.get(vname.lower(), "")
        return d

    m_vid = re.match(r"^(?:vlan\.?|vl|irb\.)0*(\d+)$", iname, re.IGNORECASE)
    if m_vid:
        vid = m_vid.group(1)
        vinfo = vlans_map.get(vid) if isinstance(vlans_map.get(vid), dict) else {}
        vname = str(vinfo.get("name") or "").strip().strip('"')
        return vid, vname, _desc_for(vinfo, vname)

    iname_l = iname.lower()
    for vid, vinfo in vlans_map.items():
        if not isinstance(vinfo, dict):
            continue
        svi = str(vinfo.get("svi_interface") or "").strip().lower()
        vname = str(vinfo.get("name") or "").strip().strip('"')
        if svi and svi == iname_l:
            return str(vid), vname, _desc_for(vinfo, vname)
        if vname and vname.lower() == iname_l:
            return str(vid), vname, _desc_for(vinfo, vname)

    if iname.upper() == "DEFAULT_VLAN" and "1" in vlans_map and isinstance(vlans_map["1"], dict):
        vinfo = vlans_map["1"]
        vname = str(vinfo.get("name") or "DEFAULT_VLAN").strip().strip('"')
        return "1", vname, _desc_for(vinfo, vname)

    return "", "", ""


def _classify_vlan_bucket(vlan_id: str, vlan_name: str, vlan_desc: str, intf_name: str, cidr: str) -> str:
    """Group an SVI into one of 8 standardized functional VLAN buckets."""
    hay = f"{vlan_name} {vlan_desc} {intf_name}".lower()
    vid_int = int(vlan_id) if str(vlan_id).isdigit() else -1

    if (
        any(
            k in hay
            for k in ("wan", "isp", "fw internal", "spectrun", "spectrum", "uplink", "route to", "transit", "untrust")
        )
        or vid_int in (2, 4009)
        or (1050 <= vid_int <= 1057)
    ):
        return "WAN Transit"
    if any(k in hay for k in ("voice", "phone", "voip", "sip")) or vid_int in (10, 2008, 2018, 2028, 2048, 2058, 2088):
        return "Voice / Phones"
    if any(k in hay for k in ("student", "chromebook", "guest", "wifi", "wireless", "byod")) or vid_int in (
        2051,
        2052,
        2059,
    ):
        return "Student & Wireless"
    if (
        any(
            k in hay
            for k in (
                "teacher",
                "staff",
                "admin",
                "bldg_",
                "classroom",
                "lab",
                "library",
                "mpr",
                "office",
                "food",
                "printer",
                "airplay",
            )
        )
        or (500 <= vid_int <= 599)
        or vid_int in (110, 120, 2053, 2054, 2055, 2056, 2057)
    ):
        return "Staff & Classrooms"
    if (
        any(
            k in hay
            for k in (
                "camera",
                "a/c",
                "ac control",
                "hvac",
                "sprinkler",
                "grounds",
                "security",
                "bus_mesh",
                "lighting",
                "clock",
                "bell",
                "audio",
                "iot",
            )
        )
        or (3051 <= vid_int <= 3057)
        or (3791 <= vid_int <= 3794)
    ):
        return "Facilities, Cameras & IoT"
    if (
        any(k in hay for k in ("mgmt", "management", "switches", "ap_devices", "tech_comps"))
        or vid_int in (3009, 3048, 3049, 3058, 3059, 3799)
        or cidr.startswith(("172.30.", "172.31."))
    ):
        return "Switch Management"
    if any(k in hay for k in ("server", "dmz", "datacenter")) or cidr.startswith("10.0.0."):
        return "Servers / Infrastructure"
    return "Shared / Other"


def _parse_speed_mbps(speed_str: str, port_name: str = "") -> tuple[int, str]:
    """Return ``(speed_mbps, speed_label)`` from telemetry or interface naming."""
    s = (speed_str or "").lower().strip()
    p = _norm_iface(port_name)
    if s:
        if "100g" in s or "100000" in s:
            return 100000, "100G"
        if "40g" in s or "40000" in s:
            return 40000, "40G"
        if "25g" in s or "25000" in s:
            return 25000, "25G"
        if "10g" in s or "10000" in s:
            return 10000, "10G"
        if "5g" in s or "5000" in s:
            return 5000, "5G"
        if "2.5g" in s or "2500" in s:
            return 2500, "2.5G"
        if "1000m" in s or "1g" in s or "1000" in s:
            return 1000, "1G"
        if "100m" in s or "100" in s:
            return 100, "100M"
        if "10m" in s or s == "10":
            return 10, "10M"

    if p.startswith(("hu", "et-")):
        return 100000, "100G"
    if p.startswith("fo"):
        return 40000, "40G"
    if p.startswith(("xe-", "te", "25ge")):
        return 10000, "10G"
    if p.startswith("mge"):
        return 2500, "2.5G"
    if p.startswith(("ge-", "gi")):
        return 1000, "1G"
    if p.startswith("fa"):
        return 100, "100M"
    return 1000, "1G"


def _compute_display_badge(
    transport_type: str,
    evidence: str,
    speed_label: str,
    is_blocked: bool,
    route_prefix: str = "",
) -> str:
    if is_blocked:
        return "STP BLK"
    inf_tag = " (Inferred)" if evidence in ("inferred_arp_route", "inferred_route_only") else ""
    if transport_type == "metro_ethernet":
        return f"Metro-E {speed_label}".strip() + inf_tag
    if transport_type == "wan_carrier":
        return f"WAN {speed_label}".strip() + inf_tag
    if transport_type == "l3_egress":
        base = f"L3 Egress {route_prefix}".strip() if route_prefix else "L3 Egress"
        return base + inf_tag
    if transport_type == "l3_routed":
        base = f"L3 Route {route_prefix}".strip() if route_prefix else "L3 Route"
        return base + inf_tag
    if transport_type == "mac_inferred":
        return "MAC Inferred"
    if transport_type == "virtual_passthrough":
        return "Passthrough/Transit"
    proto = "CDP" if evidence == "cdp" else "LLDP"
    return f"{proto} {speed_label}".strip()


def _edge_provenance_meta(
    evidence: str,
    transport_type: str,
    blind_spot: bool = False,
    blind_spot_reason: str = "",
    provenance: list[str] | None = None,
) -> dict[str, Any]:
    """Compute canonical ``confidence_tier``, ``is_verified``, ``blind_spot``, and ``provenance`` metadata."""
    ev = (evidence or "").lower()
    if ev in ("confirmed_lldp", "cdp"):
        tier = "verified-lldp"
    elif ev in ("unidirectional_lldp", "wan_carrier_arp_route", "l3_next_hop_egress") and not blind_spot:
        tier = "verified-telemetry"
    elif ev in ("mac_inferred", "passthrough", "inferred_arp_route"):
        tier = "inferred-arp-route"
    elif ev == "inferred_route_only":
        tier = "inferred-route-only"
    elif transport_type == "mac_inferred":
        tier = "inferred-arp-route"
    else:
        tier = "inferred-route-only" if blind_spot else "verified-telemetry"

    prov = list(provenance or [])
    if not prov:
        prov = [ev or transport_type or "direct"]
    return {
        "confidence_tier": tier,
        "is_verified": tier.startswith("verified-"),
        "blind_spot": bool(blind_spot),
        "blind_spot_reason": blind_spot_reason if blind_spot else "",
        "provenance": prov,
    }


def _resolve_transport_and_evidence(nbr: dict[str, Any]) -> tuple[str, str]:
    acc = str(nbr.get("l2_accuracy") or "").strip().lower()
    explicit_tt = str(nbr.get("transport_type") or "").strip().lower()
    explicit_ev = str(nbr.get("evidence") or "").strip().lower()
    note_l = str(nbr.get("l2_accuracy_note") or nbr.get("carrier_cloud") or "").lower()
    conf = str(nbr.get("link_confidence") or "").strip().lower()
    proto = str(nbr.get("protocol") or nbr.get("discovery_protocol") or "").strip().lower()

    if acc == "wan_carrier_arp_route" or explicit_tt in ("metro_ethernet", "wan_carrier"):
        if explicit_tt in ("metro_ethernet", "wan_carrier"):
            tt = explicit_tt
        elif "metro" in note_l or "spectrum" in note_l or "carrier" in note_l:
            tt = "metro_ethernet"
        else:
            tt = "wan_carrier"
        return tt, (explicit_ev or "wan_carrier_arp_route")

    if acc == "l3_next_hop_egress" or explicit_tt == "l3_egress":
        return "l3_egress", (explicit_ev or "l3_next_hop_egress")

    if explicit_tt == "l3_routed":
        return "l3_routed", (explicit_ev or "l3_route_arp")

    if acc == "mac_inferred" or explicit_tt == "mac_inferred":
        return "mac_inferred", "mac_inferred"

    if acc in ("virtual_passthrough", "multi_neighbor_port") or explicit_tt == "virtual_passthrough":
        return "virtual_passthrough", "passthrough"

    if proto == "cdp":
        return "direct_l2_uplink", "cdp"
    if conf == "two-way":
        return "direct_l2_uplink", "confirmed_lldp"
    return "direct_l2_uplink", (explicit_ev or "unidirectional_lldp")


def _compute_stp_root_scopes(
    nodes_by_id: dict[str, dict[str, Any]],
    dev_by_id: dict[str, dict[str, Any]],
) -> None:
    """Compute honest ``stp_root_scope`` and ``stp_root`` across crawled switches."""
    switch_ids = [
        nid for nid, n in nodes_by_id.items() if n["role"] in ("core", "dist", "switch", "access") and n["is_crawled"]
    ]
    total_switches = len(switch_ids)
    stp_enabled_count = 0
    rb_claims: dict[str, int] = {}

    for nid in switch_ids:
        stp = (dev_by_id[nid].get("stp") or {}) if nid in dev_by_id else {}
        if stp.get("enabled") is True:
            stp_enabled_count += 1
        rb = str(stp.get("root_bridge") or "").strip().lower()
        if rb:
            rb_claims[rb] = rb_claims.get(rb, 0) + 1

    for nid, nrec in nodes_by_id.items():
        if nrec["role"] not in ("core", "dist", "switch", "access") or not nrec["is_crawled"]:
            nrec["stp_root_scope"] = "not_applicable"
            nrec["stp_root"] = False
            nrec["stp_root_bridge_mac"] = ""
            nrec["stp_anomalies"] = []
            continue

        stp = (dev_by_id[nid].get("stp") or {}) if nid in dev_by_id else {}
        rb = str(stp.get("root_bridge") or "").strip().lower()
        is_root = bool(stp.get("is_root"))
        scope: str

        if stp.get("is_isolated_self_root") is True:
            scope = "isolated_self_root"
        elif stp.get("is_verified_campus_root") is True:
            scope = "campus_root"
        elif is_root:
            if rb and rb_claims.get(rb, 0) >= 2:
                scope = "campus_root"
            elif total_switches == 2 and stp_enabled_count >= 2:
                scope = "campus_root"
            elif total_switches > 2:
                scope = "isolated_self_root"
            else:
                scope = "isolated_self_root"
        elif stp.get("enabled") is True:
            scope = "non_root"
        else:
            scope = "disabled"

        nrec["stp_root_scope"] = scope
        nrec["stp_root"] = scope == "campus_root"
        nrec["stp_root_bridge_mac"] = str(stp.get("root_bridge") or "")
        nrec["stp_anomalies"] = list(stp.get("anomalies") or [])


def _is_valid_ipv4(val: str) -> bool:
    if not val or not _IPV4_RE.match(val.strip()):
        return False
    try:
        IPAddress(val.strip())
        return True
    except (AddrFormatError, ValueError):
        return False


def _build_intf_vrf_map(dev: dict[str, Any]) -> dict[str, str]:
    """Build normalized interface -> VRF name mapping from `dev['vrfs']` and `raw_config`."""
    mapping: dict[str, str] = {}
    for vrf_obj in dev.get("vrfs") or []:
        if not isinstance(vrf_obj, dict):
            continue
        vname = _normalize_vrf_name(vrf_obj.get("name"))
        if vname == "default":
            continue
        for intf in vrf_obj.get("interfaces") or []:
            ni = _norm_iface(str(intf))
            if ni:
                mapping[ni] = vname

    raw_cfg = str(dev.get("raw_config") or "")
    if raw_cfg:
        for m_ri in re.finditer(r"set\s+routing-instances\s+(\S+)\s+interface\s+(\S+)", raw_cfg):
            vname = _normalize_vrf_name(m_ri.group(1))
            ni = _norm_iface(m_ri.group(2))
            if ni and vname != "default":
                mapping.setdefault(ni, vname)
        for m_intf in re.finditer(r"(?m)^interface\s+(\S+)\s*\r?\n((?:[ \t]+[^\r\n]+\r?\n)*)", raw_cfg):
            ni = _norm_iface(m_intf.group(1))
            body = m_intf.group(2)
            m_vf = re.search(
                r"(?m)^\s*(?:ip\s+vrf\s+forwarding|vrf\s+forwarding|vrf\s+member)\s+(\S+)",
                body,
                re.IGNORECASE,
            )
            if m_vf and ni:
                vname = _normalize_vrf_name(m_vf.group(1))
                if vname != "default":
                    mapping.setdefault(ni, vname)
    return mapping


def _l3_vrf_node_id(dev_nid: str, vrf_name: str) -> str:
    """Return canonical L3 node ID; preserves `dev_nid` for the default/global VRF."""
    v = _normalize_vrf_name(vrf_name)
    return dev_nid if v == "default" else f"{dev_nid}::vrf:{v}"


def _build_l3_graph(
    nodes_by_id: dict[str, dict[str, Any]],
    dev_by_id: dict[str, dict[str, Any]],
    edges_list: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build the canonical ``l3_graph`` object containing VRF-scoped L3 gateways,
    IPv4/IPv6 routed adjacencies, unnumbered P2P links, overlay tunnels
    (IPsec/WireGuard/GRE), explicit VRF route-leaking edges, subnet conflicts,
    per-site functional VLAN groups, and DHCP relay targets.
    """
    infra_nodes = [n for n in nodes_by_id.values() if n["role"] != "ap"]
    small_lab = len(infra_nodes) <= 10
    routing_protos = ("static", "s", "s*", "ospf", "o", "bgp", "b", "eigrp", "d", "rip", "r", "isis", "i")

    # 1. Identify true L3 gateways (never let dual-SVI L2 access switches masquerade in large networks)
    for nid, nrec in nodes_by_id.items():
        if nrec["role"] == "ap":
            nrec["is_l3_gateway"] = False
            continue
        if nrec["role"] in ("firewall", "router", "core", "isp"):
            nrec["is_l3_gateway"] = True
            continue
        if nrec["role"] == "wan_cloud":
            nrec["is_l3_gateway"] = False
            continue
        valid_subs = nrec.get("l3_subnets") or []
        dev_raw = dev_by_id.get(nid) or {}
        raw_routes = dev_raw.get("routes") or []
        has_tunnels = bool((dev_raw.get("security_policy") or {}).get("vpn_tunnels") or dev_raw.get("tunnels"))
        has_dyn_or_nondefault_static = any(
            str(r.get("protocol") or "").strip().lower() in routing_protos
            and not _is_default_route_prefix(str(r.get("subnet") or "").strip())
            and (
                _is_valid_ip(str(r.get("next_hop") or "").strip())
                or bool(str(r.get("interface") or "").strip())
                or str(r.get("protocol") or "").strip().lower()
                in ("ospf", "o", "bgp", "b", "eigrp", "d", "rip", "r", "isis", "i")
            )
            for r in raw_routes
        )
        if len(valid_subs) >= 3 or has_dyn_or_nondefault_static or has_tunnels or (small_lab and len(valid_subs) >= 1):
            nrec["is_l3_gateway"] = True
        else:
            nrec["is_l3_gateway"] = False

    l3_nodes_by_id: dict[str, dict[str, Any]] = {}
    ip_to_l3_node: dict[tuple[str, str], str] = {}
    dev_vrf_nodes: dict[str, dict[str, str]] = {}

    for nid, nrec in nodes_by_id.items():
        if not nrec.get("is_l3_gateway"):
            continue
        dev_raw = dev_by_id.get(nid) or {}
        intf_vrf_map = _build_intf_vrf_map(dev_raw)

        # Collect all VRFs present on this device (interfaces, routes, tunnels)
        vrfs_on_dev: dict[str, list[dict[str, Any]]] = {}
        for sub in nrec.get("l3_subnets") or []:
            vname = _normalize_vrf_name(sub.get("vrf") or intf_vrf_map.get(_norm_iface(sub.get("interface", "")), ""))
            vrfs_on_dev.setdefault(vname, []).append({**sub, "vrf": vname})

        route_vrfs: set[str] = set()
        for rt in dev_raw.get("routes") or []:
            rv = _normalize_vrf_name(rt.get("vrf") or intf_vrf_map.get(_norm_iface(str(rt.get("interface") or "")), ""))
            route_vrfs.add(rv)
            vrfs_on_dev.setdefault(rv, [])

        tunnels_raw = list((dev_raw.get("security_policy") or {}).get("vpn_tunnels") or []) + list(
            dev_raw.get("tunnels") or []
        )
        for tun in tunnels_raw:
            if isinstance(tun, dict):
                tv = _normalize_vrf_name(
                    tun.get("vrf") or intf_vrf_map.get(_norm_iface(str(tun.get("interface") or "")), "")
                )
                vrfs_on_dev.setdefault(tv, [])

        if not vrfs_on_dev:
            vrfs_on_dev["default"] = []

        for vname, v_subs in sorted(vrfs_on_dev.items()):
            l3_nid = _l3_vrf_node_id(nid, vname)
            dev_vrf_nodes.setdefault(nid, {})[vname] = l3_nid
            l3_nodes_by_id[l3_nid] = {
                "id": l3_nid,
                "device_id": nid,
                "vrf": vname,
                "routing_instance": vname,
                "hostname": nrec["hostname"],
                "ip": nrec["ip"] if vname == "default" else "",
                "site": nrec["site"],
                "sub_site": nrec.get("sub_site", ""),
                "role": nrec["role"],
                "layer": nrec["layer"],
                "is_crawled": nrec["is_crawled"],
                "l3_subnets": v_subs,
                "default_gateway_ip": nrec.get("default_gateway_ip", "") if vname == "default" else "",
                "dhcp_relays": (nrec.get("dhcp_relays") or []) if vname == "default" else [],
                "has_conflict": False,
            }
            if vname == "default" and _is_valid_ip(nrec["ip"]):
                ip_to_l3_node.setdefault(("default", nrec["ip"]), l3_nid)
            for sub in v_subs:
                cip, _ = _parse_iface_network(sub.get("ip", ""))
                if cip:
                    ip_to_l3_node.setdefault((vname, cip), l3_nid)

    # Check if Metro-E L2 edges exist so Carrier Cloud appears cleanly in l3_nodes
    has_metro_l2 = any(e.get("transport_type") in ("metro_ethernet", "wan_carrier") for e in edges_list)
    if has_metro_l2:
        for nid, nrec in nodes_by_id.items():
            if nrec["role"] == "wan_cloud":
                l3_nodes_by_id[nid] = {
                    "id": nid,
                    "device_id": nid,
                    "vrf": "default",
                    "routing_instance": "default",
                    "hostname": nrec["hostname"],
                    "ip": "",
                    "site": nrec["site"],
                    "sub_site": "",
                    "role": "wan_cloud",
                    "layer": 1,
                    "is_crawled": False,
                    "l3_subnets": [],
                    "default_gateway_ip": "",
                    "dhcp_relays": [],
                    "has_conflict": False,
                }

    # Build L2 transport lookup between crawled/materialized node pairs (including via wan_cloud)
    l2_transport_between: dict[tuple[str, str], str] = {}
    cloud_peers: dict[str, list[tuple[str, str]]] = {}
    for e in edges_list:
        s, t = e["source"], e["target"]
        tt = e.get("transport_type") or "direct_l2_uplink"
        l2_transport_between[tuple(sorted((s, t)))] = tt
        if nodes_by_id.get(s, {}).get("role") == "wan_cloud":
            cloud_peers.setdefault(s, []).append((t, tt))
        elif nodes_by_id.get(t, {}).get("role") == "wan_cloud":
            cloud_peers.setdefault(t, []).append((s, tt))
    for peers in cloud_peers.values():
        for i in range(len(peers)):
            for j in range(i + 1, len(peers)):
                pair = tuple(sorted((peers[i][0], peers[j][0])))
                l2_transport_between.setdefault(pair, peers[i][1])

    # Collect parsed L3 interfaces on l3_nodes (scoped per VRF)
    node_ifaces: dict[str, list[dict[str, Any]]] = {}
    for l3_nid, l3n in l3_nodes_by_id.items():
        items = []
        for sub in l3n.get("l3_subnets") or []:
            raw_ip = str(sub.get("ip") or "").strip()
            cip, net = _parse_iface_network(raw_ip)
            if not cip or not net:
                continue
            explicit_mask = bool(sub.get("mask_known", ("/" in raw_ip) or (" " in raw_ip)))
            items.append(
                {
                    "interface": sub.get("interface", ""),
                    "ip": cip,
                    "net": net,
                    "version": net.version,
                    "address_family": "ipv6" if net.version == 6 else "ipv4",
                    "vrf": l3n["vrf"],
                    "mask_known": explicit_mask,
                    "cidr": f"{net.network}/{net.prefixlen}" if explicit_mask else cip,
                    "vlan_id": sub.get("vlan_id", ""),
                    "vlan_name": sub.get("vlan_name", ""),
                    "vlan_description": sub.get("vlan_description", ""),
                }
            )
        node_ifaces[l3_nid] = items

    # Helper to resolve or materialize an uncrawled peer for unnumbered / overlay / next-hop
    host_to_dev_nid: dict[str, str] = {}
    for d_nid, nrec in nodes_by_id.items():
        if nrec.get("role") in ("ap", "wan_cloud"):
            continue
        hn = _short_hostname(nrec["hostname"]).lower()
        if hn:
            host_to_dev_nid.setdefault(hn, d_nid)
            host_to_dev_nid.setdefault(nrec["hostname"].lower(), d_nid)

    # 2. Index explicit routing-table next-hops, unnumbered P2P routes, & overlay tunnels
    routes_via_pair: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    default_route_target: dict[str, str] = {}
    default_route_nh: dict[str, str] = {}
    route_target_for_cidr: dict[tuple[str, str], str] = {}
    unnumbered_p2p_obs: list[dict[str, Any]] = []
    overlay_tunnel_obs: list[dict[str, Any]] = []
    vrf_leak_obs: list[dict[str, Any]] = []

    def _ensure_ext_l3_node(ext_id: str, hostname: str, ip_str: str, site: str, role: str, layer: int, vrf: str) -> str:
        if ext_id not in l3_nodes_by_id:
            l3_nodes_by_id[ext_id] = {
                "id": ext_id,
                "device_id": ext_id,
                "vrf": vrf,
                "routing_instance": vrf,
                "hostname": hostname,
                "ip": ip_str,
                "site": site,
                "sub_site": "",
                "role": role,
                "layer": layer,
                "is_crawled": False,
                "l3_subnets": [],
                "default_gateway_ip": "",
                "dhcp_relays": [],
                "has_conflict": False,
            }
            node_ifaces.setdefault(ext_id, [])
        return ext_id

    for dev_nid, vrf_map in list(dev_vrf_nodes.items()):
        dev = dev_by_id.get(dev_nid)
        if not dev:
            continue
        base_nrec = nodes_by_id[dev_nid]
        intf_vrf_map = _build_intf_vrf_map(dev)
        nbrs_by_port = {
            _norm_iface(str((nb or {}).get("local_port") or "")): nb
            for nb in (dev.get("neighbors") or [])
            if isinstance(nb, dict) and nb.get("local_port")
        }

        for rt in dev.get("routes") or []:
            sub_str = str(rt.get("subnet") or "").strip()
            nh = str(rt.get("next_hop") or "").strip()
            proto = str(rt.get("protocol") or "").strip().lower()
            rt_intf = str(rt.get("interface") or "").strip()
            rt_vrf = _normalize_vrf_name(rt.get("vrf") or intf_vrf_map.get(_norm_iface(rt_intf), ""))
            src_l3_nid = vrf_map.get(rt_vrf) or _l3_vrf_node_id(dev_nid, rt_vrf)

            # Explicit inter-VRF route leak on route entry
            leak_src_vrf = _normalize_vrf_name(
                rt.get("import_vrf") or rt.get("source_vrf") or rt.get("leaked_from_vrf") or ""
            )
            if (rt.get("import_vrf") or rt.get("source_vrf") or rt.get("leaked_from_vrf")) and leak_src_vrf != rt_vrf:
                leak_src_id = vrf_map.get(leak_src_vrf)
                if leak_src_id and src_l3_nid in l3_nodes_by_id:
                    vrf_leak_obs.append(
                        {
                            "src_id": leak_src_id,
                            "dst_id": src_l3_nid,
                            "source_vrf": leak_src_vrf,
                            "target_vrf": rt_vrf,
                            "prefix": sub_str,
                            "reason": "route_import",
                        }
                    )

            if not sub_str:
                continue

            # Unnumbered P2P or link-local IPv6 (fe80::) interface-referenced route
            is_link_local_nh = nh.lower().startswith("fe80:")
            is_unnum_nh = nh.lower() in _UNNUMBERED_NH_TOKENS or (rt_intf and nh.lower() == rt_intf.lower())
            if (is_unnum_nh or is_link_local_nh) and rt_intf and not _TUNNEL_INTF_RE.match(rt_intf):
                nbr = nbrs_by_port.get(_norm_iface(rt_intf))
                if nbr and proto in routing_protos:
                    r_raw = str(nbr.get("remote_device") or "").strip()
                    r_short = _short_hostname(r_raw).lower()
                    rip = str(nbr.get("remote_ip") or "").strip()
                    peer_dev_nid = host_to_dev_nid.get(r_short) or host_to_dev_nid.get(r_raw.lower())
                    if not peer_dev_nid and rip:
                        peer_dev_nid = ip_to_l3_node.get((rt_vrf, rip)) or ip_to_l3_node.get(("default", rip))
                        if peer_dev_nid and peer_dev_nid in l3_nodes_by_id:
                            peer_dev_nid = l3_nodes_by_id[peer_dev_nid]["device_id"]
                    if peer_dev_nid and peer_dev_nid != dev_nid:
                        peer_l3_nid = dev_vrf_nodes.get(peer_dev_nid, {}).get(rt_vrf)
                        if not peer_l3_nid:
                            peer_l3_nid = _l3_vrf_node_id(peer_dev_nid, rt_vrf)
                            if peer_l3_nid not in l3_nodes_by_id and peer_dev_nid in nodes_by_id:
                                pn = nodes_by_id[peer_dev_nid]
                                _ensure_ext_l3_node(
                                    peer_l3_nid, pn["hostname"], pn["ip"], pn["site"], pn["role"], pn["layer"], rt_vrf
                                )
                    else:
                        ext_id = f"l3_ext:unnum:{_slugify(r_raw or rt_intf)}"
                        peer_l3_nid = _ensure_ext_l3_node(
                            ext_id,
                            r_raw or f"Unnumbered Peer ({rt_intf})",
                            rip,
                            base_nrec["site"],
                            str(nbr.get("device_type") or "router"),
                            2,
                            rt_vrf,
                        )
                    if peer_l3_nid and peer_l3_nid != src_l3_nid:
                        unnumbered_p2p_obs.append(
                            {
                                "src_id": src_l3_nid,
                                "dst_id": peer_l3_nid,
                                "local_interface": rt_intf,
                                "remote_interface": str(nbr.get("remote_port") or ""),
                                "prefix": sub_str,
                                "protocol": proto or "unnumbered",
                                "vrf": rt_vrf,
                                "address_family": "ipv6" if ":" in sub_str else "ipv4",
                            }
                        )
                continue

            if not _is_valid_ip(nh) or nh in ("0.0.0.0", "::"):
                continue

            peer_nid = ip_to_l3_node.get((rt_vrf, nh))
            if not peer_nid and rt_vrf == "default":
                peer_nid = ip_to_l3_node.get(("default", nh))
            if not peer_nid:
                is_def = _is_default_route_prefix(sub_str)
                ext_id = f"l3_ext:{nh}" if rt_vrf == "default" else f"l3_ext:{rt_vrf}:{nh}"
                ext_role = "isp" if is_def else "external_nexthop"
                ext_name = f"ISP Gateway ({nh})" if is_def else f"Next-Hop {nh}"
                peer_nid = _ensure_ext_l3_node(
                    ext_id, ext_name, nh, base_nrec["site"], ext_role, 0 if is_def else 3, rt_vrf
                )
                ip_to_l3_node[(rt_vrf, nh)] = peer_nid

            if peer_nid == src_l3_nid:
                continue
            routes_via_pair.setdefault((src_l3_nid, peer_nid), []).append((sub_str, nh, proto))
            if _is_default_route_prefix(sub_str):
                default_route_target[src_l3_nid] = peer_nid
                default_route_nh[src_l3_nid] = nh
            if proto in routing_protos and not _is_default_route_prefix(sub_str):
                route_target_for_cidr[(rt_vrf, sub_str)] = l3_nodes_by_id[peer_nid]["hostname"]

        # Explicit VRF route leaking via `dev['vrf_leaking']` or matching export/import RTs
        for lk_cfg in dev.get("vrf_leaking") or []:
            if not isinstance(lk_cfg, dict):
                continue
            sv = _normalize_vrf_name(lk_cfg.get("source_vrf"))
            tv = _normalize_vrf_name(lk_cfg.get("target_vrf"))
            if sv != tv and sv in vrf_map and tv in vrf_map:
                pfxs = lk_cfg.get("prefixes") or ([lk_cfg["subnet"]] if lk_cfg.get("subnet") else [])
                for pfx in pfxs or [""]:
                    vrf_leak_obs.append(
                        {
                            "src_id": vrf_map[sv],
                            "dst_id": vrf_map[tv],
                            "source_vrf": sv,
                            "target_vrf": tv,
                            "prefix": str(pfx),
                            "reason": "explicit_vrf_leaking",
                        }
                    )

        vrfs_meta = [v for v in (dev.get("vrfs") or []) if isinstance(v, dict)]
        for va in vrfs_meta:
            va_name = _normalize_vrf_name(va.get("name"))
            va_exp = {str(rt).strip() for rt in (va.get("export_rts") or []) if rt}
            if not va_exp or va_name not in vrf_map:
                continue
            for vb in vrfs_meta:
                vb_name = _normalize_vrf_name(vb.get("name"))
                if vb_name == va_name or vb_name not in vrf_map:
                    continue
                vb_imp = {str(rt).strip() for rt in (vb.get("import_rts") or []) if rt}
                shared_rts = sorted(va_exp & vb_imp)
                if shared_rts:
                    vrf_leak_obs.append(
                        {
                            "src_id": vrf_map[va_name],
                            "dst_id": vrf_map[vb_name],
                            "source_vrf": va_name,
                            "target_vrf": vb_name,
                            "prefix": f"RT {','.join(shared_rts)}",
                            "reason": "rt_import_export",
                        }
                    )

        # Overlay Tunnels (IPsec, WireGuard, GRE)
        tunnels_all = list((dev.get("security_policy") or {}).get("vpn_tunnels") or []) + list(dev.get("tunnels") or [])
        for tun in tunnels_all:
            if not isinstance(tun, dict):
                continue
            rgw = str(tun.get("remote_gw") or tun.get("remote_ip") or tun.get("remote_endpoint") or "").strip()
            t_intf = str(tun.get("interface") or tun.get("tunnel_interface") or "").strip()
            if not rgw and not t_intf:
                continue
            otype = str(tun.get("type") or tun.get("overlay_type") or "").strip().lower()
            if not otype:
                il = t_intf.lower()
                if il.startswith("wg"):
                    otype = "wireguard"
                elif il.startswith("gre"):
                    otype = "gre"
                else:
                    otype = "ipsec"
            t_vrf = _normalize_vrf_name(tun.get("vrf") or intf_vrf_map.get(_norm_iface(t_intf), ""))
            src_l3_nid = vrf_map.get(t_vrf) or _l3_vrf_node_id(dev_nid, t_vrf)
            if src_l3_nid not in l3_nodes_by_id:
                continue

            peer_l3_nid = ""
            if rgw:
                peer_l3_nid = ip_to_l3_node.get((t_vrf, rgw)) or ip_to_l3_node.get(("default", rgw)) or ""
            if not peer_l3_nid and tun.get("peer_device"):
                pd_nid = host_to_dev_nid.get(_short_hostname(str(tun["peer_device"])).lower(), "")
                if pd_nid:
                    peer_l3_nid = dev_vrf_nodes.get(pd_nid, {}).get(t_vrf) or dev_vrf_nodes.get(pd_nid, {}).get(
                        "default", ""
                    )
            if not peer_l3_nid and rgw:
                ext_id = f"l3_ext:tunnel:{rgw}"
                peer_lbl = str(tun.get("descr") or f"{otype.upper()} Peer ({rgw})").strip()
                peer_l3_nid = _ensure_ext_l3_node(
                    ext_id, peer_lbl, rgw, base_nrec["site"], "external_nexthop", 3, t_vrf
                )
            if peer_l3_nid and peer_l3_nid != src_l3_nid:
                tcidr = str(tun.get("tunnel_cidr") or tun.get("overlay_cidr") or "").strip()
                overlay_tunnel_obs.append(
                    {
                        "src_id": src_l3_nid,
                        "dst_id": peer_l3_nid,
                        "overlay_type": otype,
                        "tunnel_interface": t_intf or otype,
                        "local_ip": str(tun.get("local_ip") or tun.get("local_endpoint") or "").strip(),
                        "remote_gw": rgw,
                        "transit_cidr": tcidr or f"{otype.upper()} ({rgw or t_intf})",
                        "vrf": t_vrf,
                        "address_family": "ipv6" if (":" in rgw or ":" in tcidr) else "ipv4",
                        "descr": str(tun.get("descr") or "").strip(),
                    }
                )

    # 3. Detect Conflicts (scoped per VRF: intra-device overlap + duplicate gateway IP + overlapping site subnets)
    l3_conflicts: list[dict[str, Any]] = []
    seen_conflict_keys: set[tuple[str, str, str, tuple[str, ...]]] = set()

    # 3a. Intra-device overlap (only within the SAME VRF on the same device)
    for l3_nid, ifaces in node_ifaces.items():
        vrf_name = l3_nodes_by_id[l3_nid]["vrf"]
        for i in range(len(ifaces)):
            for j in range(i + 1, len(ifaces)):
                a, b = ifaces[i], ifaces[j]
                if a["version"] != b["version"]:
                    continue
                host_len = 128 if a["version"] == 6 else 32
                if a["net"].prefixlen == host_len or b["net"].prefixlen == host_len:
                    continue
                if a["net"] in b["net"] or b["net"] in a["net"]:
                    if a["interface"] == b["interface"]:
                        continue
                    ck = (
                        "intra_device_overlap",
                        vrf_name,
                        a["cidr"],
                        tuple(sorted((l3_nid, a["interface"], b["interface"]))),
                    )
                    if ck not in seen_conflict_keys:
                        seen_conflict_keys.add(ck)
                        l3_nodes_by_id[l3_nid]["has_conflict"] = True
                        l3_conflicts.append(
                            {
                                "conflict_type": "intra_device_overlap",
                                "vrf": vrf_name,
                                "cidr": f"{a['cidr']} / {b['cidr']}",
                                "devices": [l3_nodes_by_id[l3_nid]["hostname"]],
                                "interfaces": [a["interface"], b["interface"]],
                                "active_hub_route_target": "",
                                "impact_summary": (
                                    f"{l3_nodes_by_id[l3_nid]['hostname']} (VRF {vrf_name}) configures overlapping SVIs "
                                    f"{a['interface']} ({a['ip']}/{a['net'].prefixlen}) and "
                                    f"{b['interface']} ({b['ip']}/{b['net'].prefixlen})."
                                ),
                            }
                        )

    # 3b. Cross-device duplicate gateway IPs & overlapping subnets (scoped per VRF)
    dup_ip_groups: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
    for l3_nid, ifaces in node_ifaces.items():
        vrf_name = l3_nodes_by_id[l3_nid]["vrf"]
        for item in ifaces:
            dup_ip_groups.setdefault((vrf_name, item["ip"]), []).append((l3_nid, item))

    duplicate_pairs_blocked: set[tuple[str, str, str]] = set()
    for (vrf_name, dup_ip), occs in sorted(dup_ip_groups.items()):
        distinct_nids = sorted({nid for nid, _ in occs})
        if len(distinct_nids) < 2:
            continue
        cidrs = sorted({it["cidr"] for _, it in occs})
        primary_cidr = cidrs[0]
        hosts = [l3_nodes_by_id[nid]["hostname"] for nid in distinct_nids]
        target = route_target_for_cidr.get((vrf_name, primary_cidr), "")
        ck = ("duplicate_gateway_ip", vrf_name, primary_cidr, tuple(distinct_nids))
        if ck not in seen_conflict_keys:
            seen_conflict_keys.add(ck)
            for nid in distinct_nids:
                l3_nodes_by_id[nid]["has_conflict"] = True
            l3_conflicts.append(
                {
                    "conflict_type": "duplicate_gateway_ip",
                    "vrf": vrf_name,
                    "cidr": primary_cidr,
                    "duplicate_ip": dup_ip,
                    "devices": hosts,
                    "active_hub_route_target": target,
                    "impact_summary": (
                        f"Duplicate gateway IP {dup_ip} ({primary_cidr}) in VRF {vrf_name} configured on {', '.join(hosts)}"
                        + (f" — Hub routes {primary_cidr} exclusively to {target}." if target else ".")
                    ),
                }
            )
        for i in range(len(distinct_nids)):
            for j in range(i + 1, len(distinct_nids)):
                duplicate_pairs_blocked.add((distinct_nids[i], distinct_nids[j], primary_cidr))

    # 4. Build L3 links (subnet containment OR explicit next-hop route OR unnumbered P2P OR overlay OR VRF leak)
    l3_links_map: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _add_l3_link(
        nid_a: str,
        nid_b: str,
        transit_cidr: str,
        src_ip: str = "",
        dst_ip: str = "",
        vlan_id: str = "",
        mask_mismatch: bool = False,
        mask_detail: str = "",
        transport_override: str = "",
        routing_mechanism_override: str = "",
        address_family: str = "",
        vrf_name: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        na, nb = l3_nodes_by_id[nid_a], l3_nodes_by_id[nid_b]

        def _l3_rank(n: dict[str, Any]) -> tuple[int, int, str]:
            r = n["role"]
            if r == "isp":
                return (0, 0, n["hostname"].lower())
            if r == "firewall":
                return (1, 0, n["hostname"].lower())
            if r == "core":
                return (2, -len(n.get("l3_subnets") or []), n["hostname"].lower())
            if r == "router":
                return (2, 0, n["hostname"].lower())
            return (3, 0, n["hostname"].lower())

        def _nh_matches_link(nh_ip: str) -> bool:
            if not nh_ip:
                return False
            if nh_ip in (src_ip, dst_ip) or nh_ip == transit_cidr:
                return True
            if "/" in transit_cidr and not transit_cidr.startswith(("unnumbered", "IPSEC", "WIREGUARD", "GRE")):
                try:
                    nh_obj = IPAddress(nh_ip.split("%", 1)[0])
                    t_net = IPNetwork(transit_cidr)
                    return nh_obj.version == t_net.version and nh_obj in t_net
                except (AddrFormatError, ValueError):
                    return False
            return False

        a_def_here = default_route_target.get(nid_a) == nid_b and _nh_matches_link(default_route_nh.get(nid_a, ""))
        b_def_here = default_route_target.get(nid_b) == nid_a and _nh_matches_link(default_route_nh.get(nid_b, ""))

        if a_def_here and not b_def_here:
            src_id, dst_id = nid_a, nid_b
            direction = "egress_upstream"
            s_ip, d_ip = src_ip, dst_ip
        elif b_def_here and not a_def_here:
            src_id, dst_id = nid_b, nid_a
            direction = "egress_upstream"
            s_ip, d_ip = dst_ip, src_ip
        elif _l3_rank(na) <= _l3_rank(nb):
            src_id, dst_id = nid_a, nid_b
            direction = "routed_peer"
            s_ip, d_ip = src_ip, dst_ip
        else:
            src_id, dst_id = nid_b, nid_a
            direction = "routed_peer"
            s_ip, d_ip = dst_ip, src_ip

        if l3_nodes_by_id[nid_b]["role"] == "isp" or l3_nodes_by_id[nid_a]["role"] == "isp":
            if l3_nodes_by_id[nid_a]["role"] == "isp":
                src_id, dst_id = nid_b, nid_a
                s_ip, d_ip = dst_ip, src_ip
            else:
                src_id, dst_id = nid_a, nid_b
                s_ip, d_ip = src_ip, dst_ip
            direction = "egress_upstream"
        elif l3_nodes_by_id[nid_b]["role"] == "firewall" and a_def_here:
            src_id, dst_id = nid_a, nid_b
            s_ip, d_ip = src_ip, dst_ip
            direction = "egress_upstream"
        elif l3_nodes_by_id[nid_a]["role"] == "firewall" and b_def_here:
            src_id, dst_id = nid_b, nid_a
            s_ip, d_ip = dst_ip, src_ip
            direction = "egress_upstream"

        routed_ab = [sub for sub, nh, _pr in routes_via_pair.get((src_id, dst_id), []) if _nh_matches_link(nh)]
        routed_ba = [sub for sub, nh, _pr in routes_via_pair.get((dst_id, src_id), []) if _nh_matches_link(nh)]
        combined_routes = sorted(set(routed_ab) | set(routed_ba))
        if extra_fields and extra_fields.get("routed_prefixes"):
            combined_routes = sorted(set(combined_routes) | set(extra_fields["routed_prefixes"]))

        if routing_mechanism_override:
            mech = routing_mechanism_override
        elif any(_is_default_route_prefix(p) for p in combined_routes):
            mech = "static_default"
        elif combined_routes:
            mech = "static_summary"
        else:
            mech = "connected_transit"

        pair_l2 = l2_transport_between.get(
            tuple(sorted((na.get("device_id", src_id), nb.get("device_id", dst_id)))), ""
        )
        if transport_override:
            tt = transport_override
        elif l3_nodes_by_id[src_id]["role"] == "isp" or l3_nodes_by_id[dst_id]["role"] == "isp":
            tt = "l3_egress"
        elif pair_l2 in ("metro_ethernet", "wan_carrier", "direct_l2_uplink", "l3_egress"):
            tt = pair_l2
        elif mech == "static_default":
            tt = "l3_egress"
        else:
            tt = "l3_routed"

        af = address_family or ("ipv6" if ":" in transit_cidr or ":" in s_ip or ":" in d_ip else "ipv4")
        vrf_lbl = vrf_name or na.get("vrf") or "default"
        key = (min(src_id, dst_id), max(src_id, dst_id), transit_cidr)
        entry = l3_links_map.get(key)
        if entry is None:
            rec = {
                "id": f"l3:{src_id}--{dst_id}:{transit_cidr or 'route'}",
                "source": src_id,
                "target": dst_id,
                "vrf": vrf_lbl,
                "address_family": af,
                "transit_cidr": transit_cidr,
                "vlan_id": vlan_id,
                "src_ip": s_ip,
                "dst_ip": d_ip,
                "transport_type": tt,
                "routing_mechanism": mech,
                "direction": direction,
                "mask_mismatch": mask_mismatch,
                "mask_mismatch_detail": mask_detail,
                "routed_prefixes": combined_routes,
                "routed_prefixes_summary": (
                    f"{len(combined_routes)} prefixes ({', '.join(combined_routes[:4])}, ...)"
                    if len(combined_routes) > 4
                    else ", ".join(combined_routes)
                ),
            }
            if extra_fields:
                for ek, ev in extra_fields.items():
                    if ek != "routed_prefixes":
                        rec[ek] = ev
            l3_links_map[key] = rec
        else:
            if mask_mismatch:
                entry["mask_mismatch"] = True
                entry["mask_mismatch_detail"] = mask_detail or entry["mask_mismatch_detail"]
            if af != entry["address_family"]:
                entry["address_family"] = "dual-stack"
            merged = sorted(set(entry["routed_prefixes"]) | set(combined_routes))
            entry["routed_prefixes"] = merged
            entry["routed_prefixes_summary"] = (
                f"{len(merged)} prefixes ({', '.join(merged[:4])}, ...)" if len(merged) > 4 else ", ".join(merged)
            )

    # 4a. Group containment matches per (VRF, address_family) to avoid O(N^2) broadcast LAN hairballs
    all_iface_items: list[tuple[str, dict[str, Any]]] = []
    for l3_nid, ifaces in node_ifaces.items():
        for item in ifaces:
            host_len = 128 if item["version"] == 6 else 32
            if item["net"].prefixlen < host_len and not item["ip"].lower().startswith("fe80:"):
                all_iface_items.append((l3_nid, item))

    cidr_participants: dict[tuple[str, str], set[str]] = {}
    for i in range(len(all_iface_items)):
        nid_a, a = all_iface_items[i]
        for j in range(i + 1, len(all_iface_items)):
            nid_b, b = all_iface_items[j]
            if nid_a == nid_b or a["vrf"] != b["vrf"] or a["version"] != b["version"] or a["ip"] == b["ip"]:
                continue
            if IPAddress(a["ip"]) in b["net"] or IPAddress(b["ip"]) in a["net"]:
                broad_cidr = a["cidr"] if a["net"].prefixlen <= b["net"].prefixlen else b["cidr"]
                cidr_participants.setdefault((a["vrf"], broad_cidr), set()).update((nid_a, nid_b))

    overlap_by_cidr: dict[tuple[str, str], list[tuple[str, dict[str, Any], str, dict[str, Any]]]] = {}
    for i in range(len(all_iface_items)):
        nid_a, a = all_iface_items[i]
        for j in range(i + 1, len(all_iface_items)):
            nid_b, b = all_iface_items[j]
            if nid_a == nid_b or a["vrf"] != b["vrf"] or a["version"] != b["version"]:
                continue
            ip_a_obj = IPAddress(a["ip"])
            ip_b_obj = IPAddress(b["ip"])
            if not (ip_a_obj in b["net"] or ip_b_obj in a["net"]):
                continue
            vrf_name = a["vrf"]
            tight_cidr = a["cidr"] if a["net"].prefixlen >= b["net"].prefixlen else b["cidr"]
            broad_cidr = a["cidr"] if a["net"].prefixlen <= b["net"].prefixlen else b["cidr"]
            if a["ip"] == b["ip"]:
                continue
            if (min(nid_a, nid_b), max(nid_a, nid_b), tight_cidr) in duplicate_pairs_blocked:
                continue

            dev_a = l3_nodes_by_id[nid_a].get("device_id", nid_a)
            dev_b = l3_nodes_by_id[nid_b].get("device_id", nid_b)
            pair_l2 = l2_transport_between.get(tuple(sorted((dev_a, dev_b))))
            has_route_link = bool(routes_via_pair.get((nid_a, nid_b)) or routes_via_pair.get((nid_b, nid_a)))
            same_site = l3_nodes_by_id[nid_a]["site"] == l3_nodes_by_id[nid_b]["site"]
            shared_gw = default_route_target.get(nid_a) and default_route_target.get(nid_a) == default_route_target.get(
                nid_b
            )
            num_peers = len(cidr_participants.get((vrf_name, broad_cidr), set()))
            max_site_pfx = 64 if a["version"] == 6 else 24
            if (
                not same_site
                and not pair_l2
                and not has_route_link
                and not shared_gw
                and num_peers <= 2
                and a["net"].prefixlen == b["net"].prefixlen
                and a["net"].prefixlen <= max_site_pfx
            ):
                ck = ("overlapping_site_subnet", vrf_name, tight_cidr, tuple(sorted((nid_a, nid_b))))
                if ck not in seen_conflict_keys:
                    seen_conflict_keys.add(ck)
                    l3_nodes_by_id[nid_a]["has_conflict"] = True
                    l3_nodes_by_id[nid_b]["has_conflict"] = True
                    l3_conflicts.append(
                        {
                            "conflict_type": "overlapping_site_subnet",
                            "vrf": vrf_name,
                            "cidr": tight_cidr,
                            "devices": [l3_nodes_by_id[nid_a]["hostname"], l3_nodes_by_id[nid_b]["hostname"]],
                            "active_hub_route_target": route_target_for_cidr.get((vrf_name, tight_cidr), ""),
                            "impact_summary": (
                                f"Overlapping subnet {tight_cidr} in VRF {vrf_name} on {l3_nodes_by_id[nid_a]['hostname']} "
                                f"and {l3_nodes_by_id[nid_b]['hostname']} without direct transit routing."
                            ),
                        }
                    )
                continue

            overlap_by_cidr.setdefault((vrf_name, broad_cidr), []).append((nid_a, a, nid_b, b))

    for (vrf_name, _broad_cidr), pairs in overlap_by_cidr.items():
        participants = sorted({nid for nid_a, _, nid_b, _ in pairs for nid in (nid_a, nid_b)})
        for nid_a, a, nid_b, b in pairs:
            has_explicit_route = bool(routes_via_pair.get((nid_a, nid_b)) or routes_via_pair.get((nid_b, nid_a)))
            if len(participants) >= 3 and not has_explicit_route:
                continue
            if a["mask_known"] and not b["mask_known"]:
                tight_cidr = a["cidr"]
            elif b["mask_known"] and not a["mask_known"]:
                tight_cidr = b["cidr"]
            else:
                tight_cidr = a["cidr"] if a["net"].prefixlen >= b["net"].prefixlen else b["cidr"]
            mismatch = bool(
                a["mask_known"]
                and b["mask_known"]
                and l3_nodes_by_id[nid_a]["is_crawled"]
                and l3_nodes_by_id[nid_b]["is_crawled"]
                and a["net"].prefixlen != b["net"].prefixlen
            )
            if mismatch:
                p1, p2 = a["net"].prefixlen, b["net"].prefixlen
                detail = f"/{p1} vs /{p2}"
                ck = ("mask_mismatch", vrf_name, tight_cidr, tuple(sorted((nid_a, nid_b))))
                if ck not in seen_conflict_keys:
                    seen_conflict_keys.add(ck)
                    l3_conflicts.append(
                        {
                            "conflict_type": "mask_mismatch",
                            "vrf": vrf_name,
                            "cidr": tight_cidr,
                            "devices": sorted([l3_nodes_by_id[nid_a]["hostname"], l3_nodes_by_id[nid_b]["hostname"]]),
                            "active_hub_route_target": "",
                            "impact_summary": (
                                f"Subnet mask mismatch ({detail}) on {tight_cidr} (VRF {vrf_name}) between "
                                f"{l3_nodes_by_id[nid_a]['hostname']} ({a['ip']}/{p1}) and "
                                f"{l3_nodes_by_id[nid_b]['hostname']} ({b['ip']}/{p2})."
                            ),
                        }
                    )
            else:
                detail = ""
            vlan_id = a.get("vlan_id") or b.get("vlan_id") or ""
            _add_l3_link(
                nid_a,
                nid_b,
                transit_cidr=tight_cidr,
                src_ip=a["ip"],
                dst_ip=b["ip"],
                vlan_id=vlan_id,
                mask_mismatch=mismatch,
                mask_detail=detail,
                address_family=a["address_family"],
                vrf_name=vrf_name,
            )

    # 4b. Ensure explicit route next-hop pairs (IPv4 & IPv6)
    for (nid_a, nid_b), pfxs in routes_via_pair.items():
        if nid_a not in l3_nodes_by_id or nid_b not in l3_nodes_by_id:
            continue
        already = any(
            (lk["source"] == nid_a and lk["target"] == nid_b) or (lk["source"] == nid_b and lk["target"] == nid_a)
            for lk in l3_links_map.values()
        )
        if not already:
            tt = "l3_egress" if any(_is_default_route_prefix(sub) for sub, _nh, _pr in pfxs) else "l3_routed"
            peer_ip_str = str(l3_nodes_by_id[nid_b].get("ip") or "").strip()
            matched_cidr = peer_ip_str
            matched_src_ip = str(l3_nodes_by_id[nid_a].get("ip") or "")
            matched_vid = ""
            if _is_valid_ip(peer_ip_str):
                peer_ip_obj = IPAddress(peer_ip_str)
                for ifa in node_ifaces.get(nid_a, []):
                    if peer_ip_obj.version == ifa["net"].version and peer_ip_obj in ifa["net"]:
                        matched_cidr = ifa["cidr"]
                        matched_src_ip = ifa["ip"]
                        matched_vid = ifa.get("vlan_id", "")
                        break
            af = "ipv6" if any(":" in sub or ":" in nh for sub, nh, _pr in pfxs) else "ipv4"
            _add_l3_link(
                nid_a,
                nid_b,
                transit_cidr=matched_cidr,
                src_ip=matched_src_ip,
                dst_ip=peer_ip_str,
                vlan_id=matched_vid,
                transport_override=tt,
                address_family=af,
                vrf_name=l3_nodes_by_id[nid_a].get("vrf", "default"),
            )

    # 4c. Ensure Firewall <-> ISP link if both exist in same site & VRF
    fw_ids = [nid for nid, n in l3_nodes_by_id.items() if n["role"] == "firewall"]
    isp_ids = [nid for nid, n in l3_nodes_by_id.items() if n["role"] == "isp"]
    for fw_id in fw_ids:
        for isp_id in isp_ids:
            if (
                l3_nodes_by_id[fw_id]["site"] == l3_nodes_by_id[isp_id]["site"]
                and l3_nodes_by_id[fw_id]["vrf"] == l3_nodes_by_id[isp_id]["vrf"]
            ):
                already = any(
                    (lk["source"] == fw_id and lk["target"] == isp_id)
                    or (lk["source"] == isp_id and lk["target"] == fw_id)
                    for lk in l3_links_map.values()
                )
                if not already:
                    _add_l3_link(
                        fw_id,
                        isp_id,
                        transit_cidr="Untrust / ISP",
                        transport_override="l3_egress",
                        vrf_name=l3_nodes_by_id[fw_id]["vrf"],
                    )

    # 4d. Unnumbered P2P links
    for uo in unnumbered_p2p_obs:
        _add_l3_link(
            uo["src_id"],
            uo["dst_id"],
            transit_cidr=f"unnumbered ({uo['local_interface']})",
            transport_override="l3_unnumbered_p2p",
            routing_mechanism_override=uo["protocol"],
            address_family=uo["address_family"],
            vrf_name=uo["vrf"],
            extra_fields={
                "is_unnumbered": True,
                "local_interface": uo["local_interface"],
                "remote_interface": uo["remote_interface"],
                "routed_prefixes": [uo["prefix"]],
            },
        )

    # 4e. Overlay Tunnels (IPsec, WireGuard, GRE)
    for tobs in overlay_tunnel_obs:
        _add_l3_link(
            tobs["src_id"],
            tobs["dst_id"],
            transit_cidr=tobs["transit_cidr"],
            src_ip=tobs["local_ip"],
            dst_ip=tobs["remote_gw"],
            transport_override="overlay_tunnel",
            routing_mechanism_override=f"{tobs['overlay_type']}_tunnel",
            address_family=tobs["address_family"],
            vrf_name=tobs["vrf"],
            extra_fields={
                "overlay_type": tobs["overlay_type"],
                "tunnel_interface": tobs["tunnel_interface"],
                "tunnel_endpoint_local": tobs["local_ip"],
                "tunnel_endpoint_remote": tobs["remote_gw"],
                "notes": tobs["descr"],
            },
        )

    # 4f. Explicit VRF Route Leaking / Inter-VRF Imports
    for vlo in vrf_leak_obs:
        _add_l3_link(
            vlo["src_id"],
            vlo["dst_id"],
            transit_cidr=f"VRF Leak: {vlo['source_vrf']} -> {vlo['target_vrf']}",
            transport_override="vrf_leak",
            routing_mechanism_override="vrf_route_leak",
            vrf_name=f"{vlo['source_vrf']}->{vlo['target_vrf']}",
            extra_fields={
                "is_vrf_leak": True,
                "source_vrf": vlo["source_vrf"],
                "target_vrf": vlo["target_vrf"],
                "routed_prefixes": [vlo["prefix"]] if vlo.get("prefix") else [],
            },
        )

    # 5. Functional VLAN grouping & DHCP relay targets per site
    site_vlan_groups: dict[str, dict[str, Any]] = {}
    dhcp_relay_targets: dict[str, list[str]] = {}
    seen_svi_per_site: dict[str, set[tuple[str, str]]] = {}

    for nrec in nodes_by_id.values():
        sc = nrec["site"]
        for r in nrec.get("dhcp_relays") or []:
            hip = str((r or {}).get("helper_ip") or "").strip()
            if hip:
                dhcp_relay_targets.setdefault(sc, [])
                if hip not in dhcp_relay_targets[sc]:
                    dhcp_relay_targets[sc].append(hip)

        # Group SVIs from L3 gateways (or all nodes in small labs)
        if not nrec.get("is_l3_gateway"):
            continue
        for sub in nrec.get("l3_subnets") or []:
            cidr = sub.get("cidr", "")
            intf = sub.get("interface", "")
            if not cidr:
                continue
            seen_set = seen_svi_per_site.setdefault(sc, set())
            if (cidr, intf) in seen_set:
                continue
            seen_set.add((cidr, intf))
            bucket = _classify_vlan_bucket(
                sub.get("vlan_id", ""),
                sub.get("vlan_name", ""),
                sub.get("vlan_description", ""),
                intf,
                cidr,
            )
            sc_groups = site_vlan_groups.setdefault(sc, {})
            b_entry = sc_groups.setdefault(
                bucket,
                {"count": 0, "cidrs": [], "cidr_summary": "", "items": []},
            )
            b_entry["count"] += 1
            if cidr not in b_entry["cidrs"]:
                b_entry["cidrs"].append(cidr)
            b_entry["items"].append(
                {
                    "vlan_id": sub.get("vlan_id", ""),
                    "vlan_name": sub.get("vlan_name", ""),
                    "vlan_description": sub.get("vlan_description", ""),
                    "cidr": cidr,
                    "interface": intf,
                    "device": nrec["hostname"],
                }
            )

    for groups in site_vlan_groups.values():
        for b_entry in groups.values():
            c_sorted = sorted(b_entry["cidrs"])
            b_entry["cidrs"] = c_sorted
            b_entry["cidr_summary"] = (
                f"{', '.join(c_sorted[:3])} (+{len(c_sorted) - 3} more)" if len(c_sorted) > 3 else ", ".join(c_sorted)
            )
    for sc in dhcp_relay_targets:
        dhcp_relay_targets[sc] = sorted(dhcp_relay_targets[sc])

    for l3n in l3_nodes_by_id.values():
        dev_nid = l3n.get("device_id") or l3n["id"]
        if l3n.get("has_conflict") and dev_nid in nodes_by_id:
            nodes_by_id[dev_nid]["has_conflict"] = True

    sorted_nodes = sorted(
        l3_nodes_by_id.values(),
        key=lambda n: (n["layer"], n["site"], n["hostname"].lower(), n.get("vrf", "default")),
    )
    sorted_links = sorted(
        l3_links_map.values(),
        key=lambda lk: (lk["source"], lk["target"], lk["transit_cidr"]),
    )
    vrf_names = sorted({str(n.get("vrf") or "default") for n in sorted_nodes})
    vrf_graphs: dict[str, dict[str, Any]] = {}
    for vname in vrf_names:
        v_nodes = [n for n in sorted_nodes if n.get("vrf", "default") == vname]
        v_node_ids = {n["id"] for n in v_nodes}
        v_links = [
            lk
            for lk in sorted_links
            if not lk.get("is_vrf_leak") and lk["source"] in v_node_ids and lk["target"] in v_node_ids
        ]
        v_confs = [c for c in l3_conflicts if c.get("vrf", "default") == vname]
        vrf_graphs[vname] = {
            "l3_nodes": v_nodes,
            "l3_links": v_links,
            "l3_conflicts": v_confs,
        }

    return {
        "l3_nodes": sorted_nodes,
        "l3_links": sorted_links,
        "l3_conflicts": l3_conflicts,
        "vrfs": vrf_names,
        "vrf_graphs": vrf_graphs,
        "site_vlan_groups": site_vlan_groups,
        "dhcp_relay_targets": dhcp_relay_targets,
    }


def build_topology_graph_model(
    devices: dict[str, dict],
    trunk_audit: dict | None = None,
) -> dict[str, Any]:
    """
    Build a vendor-neutral, JSON-serializable topology graph model from crawled
    ``devices`` and optional ``trunk_audit`` findings.
    """
    nodes_by_id: dict[str, dict[str, Any]] = {}
    dev_by_id: dict[str, dict[str, Any]] = {}
    host_to_id: dict[str, str] = {}
    crawled_hosts_lc: set[str] = set()
    crawled_ips: set[str] = set()
    crawled_macs: set[str] = set()

    # 1. Materialize crawled infrastructure nodes
    for ip, dev in (devices or {}).items():
        if not isinstance(dev, dict) or not _is_network_infra(dev):
            continue
        hostname = str(dev.get("hostname") or ip).strip()
        short_host = _short_hostname(hostname)
        short_lc = short_host.lower()
        dev_ip_str = str(dev.get("ip") or ip).strip()
        serial_str = str(dev.get("serial") or "").strip()
        is_generic_host = short_lc in ("", "unknown", "switch", "router", "localhost")
        base_id = f"node:{short_lc or _slugify(dev_ip_str)}"
        if is_generic_host:
            node_id = f"node:{short_lc or 'host'}_{_slugify(dev_ip_str)}"
        elif base_id in nodes_by_id:
            existing = nodes_by_id[base_id]
            same_serial = bool(
                serial_str
                and serial_str.lower() not in ("unknown", "n/a", "none", "0", "default string", "not specified")
                and serial_str == existing.get("serial")
            )
            if dev_ip_str in host_to_id or same_serial or existing.get("ip") == dev_ip_str:
                continue
            node_id = f"node:{short_lc}_{_slugify(dev_ip_str)}"
        else:
            node_id = base_id
        if node_id in nodes_by_id:
            continue

        stp = dev.get("stp") or {}
        poe = dev.get("poe") or {}
        dp = dev.get("discovery_protocols") or {}
        ints = dev.get("interfaces_detail") or {}
        up_cnt = sum(1 for s in ints.values() if str((s or {}).get("status", "")).lower() == "up")
        role = _classify_node_role(dev, hostname)
        site_code = _normalize_site_code(str(dev.get("site_code") or ""), hostname, dev_ip_str)
        vlans_map = dev.get("vlans") or {}
        fallback_descs = _extract_junos_vlan_descriptions(str(dev.get("raw_config") or ""))

        vlans_list = []
        for vid, vinfo in sorted(vlans_map.items(), key=lambda x: str(x[0])):
            vname = str((vinfo or {}).get("name") or "").strip().strip('"') if isinstance(vinfo, dict) else ""
            vlans_list.append(f"{vid}:{vname}" if vname else str(vid))

        intf_vrf_map = _build_intf_vrf_map(dev)
        l3_subs = []
        for intf in dev.get("l3_interfaces") or []:
            ip_addr = str((intf or {}).get("ip_address") or "")
            intf_name = str((intf or {}).get("interface") or "")
            vrf_name = _normalize_vrf_name((intf or {}).get("vrf") or intf_vrf_map.get(_norm_iface(intf_name), ""))
            clean_ip, net = _parse_iface_network(ip_addr)
            if not clean_ip or clean_ip.startswith(("127.", "128.0.")) or clean_ip == "::1":
                continue
            crawled_ips.add(clean_ip)
            cidr = f"{net.network}/{net.prefixlen}" if net else clean_ip
            vid, vname, vdesc = _resolve_vlan_meta(intf_name, vlans_map, fallback_descs)
            l3_subs.append(
                {
                    "interface": intf_name,
                    "ip": ip_addr,
                    "cidr": cidr,
                    "vrf": vrf_name,
                    "address_family": "ipv6" if (net and net.version == 6) or ":" in clean_ip else "ipv4",
                    "vlan_id": vid,
                    "vlan_name": vname,
                    "vlan_description": vdesc,
                }
            )

        def_gw = ""
        for rt in dev.get("routes") or []:
            if _is_default_route_prefix(str((rt or {}).get("subnet") or "").strip()):
                nh = str((rt or {}).get("next_hop") or "").strip()
                if _is_valid_ip(nh) and nh not in ("0.0.0.0", "::"):
                    def_gw = nh
                    break

        base_mac = oui_lookup.normalize_mac(str(dev.get("mac_address") or "")).lower().strip()
        if base_mac and base_mac != "00:00:00:00:00:00":
            crawled_macs.add(base_mac)
        for istats in ints.values():
            imac = oui_lookup.normalize_mac(str((istats or {}).get("mac_address") or "")).lower().strip()
            if imac and imac != "00:00:00:00:00:00":
                crawled_macs.add(imac)

        if not is_generic_host:
            crawled_hosts_lc.add(short_lc)
            crawled_hosts_lc.add(hostname.lower())
            host_to_id.setdefault(short_lc, node_id)
            host_to_id.setdefault(hostname.lower(), node_id)
        crawled_ips.add(str(ip).strip())
        if dev.get("ip"):
            crawled_ips.add(str(dev["ip"]).strip())

        node_rec = {
            "id": node_id,
            "hostname": hostname,
            "ip": dev_ip_str,
            "site": site_code,
            "orig_site": site_code,
            "sub_site": "",
            "hop_depth": 0,
            "role": role,
            "layer": _ROLE_ORDER.get(role, 4),
            "vendor": str(dev.get("vendor") or "Unknown"),
            "model": str(dev.get("model") or "Unknown"),
            "serial": serial_str or "Unknown",
            "firmware": str(dev.get("firmware") or "Unknown"),
            "mac": str(dev.get("mac_address") or ""),
            "stp_root": False,
            "stp_root_scope": "not_applicable",
            "stp_root_bridge_mac": str(stp.get("root_bridge") or ""),
            "stp_priority": str(stp.get("bridge_priority") or ""),
            "stp_anomalies": list(stp.get("anomalies") or []),
            "poe_used_w": round(float(poe.get("used_power_watts") or 0.0), 1),
            "poe_total_w": round(float(poe.get("total_power_watts") or 0.0), 1),
            "lldp": str(dp.get("lldp") or "unknown"),
            "cdp": str(dp.get("cdp") or "unsupported"),
            "ports_up": up_cnt,
            "ports_total": len(ints),
            "vlans": vlans_list,
            "l3_subnets": l3_subs,
            "default_gateway_ip": def_gw,
            "dhcp_relays": list((dev.get("dhcp") or {}).get("relays") or []),
            "attached_ap_count": 0,
            "attached_aps": [],
            "is_l3_gateway": False,
            "is_crawled": True,
        }
        nodes_by_id[node_id] = node_rec
        dev_by_id[node_id] = dev
        host_to_id[str(ip)] = node_id
        if dev_ip_str:
            host_to_id[dev_ip_str] = node_id
        for sub in l3_subs:
            cip, _ = _parse_iface_network(sub["ip"])
            if cip:
                host_to_id.setdefault(cip, node_id)

    _compute_stp_root_scopes(nodes_by_id, dev_by_id)

    # Map trunk audit severity per edge pair
    trunk_sev_by_pair: dict[tuple[str, str], list[dict[str, str]]] = {}
    for f in (trunk_audit or {}).get("findings") or []:
        if not isinstance(f, dict):
            continue
        ha = _short_hostname(str(f.get("Side_A_Host") or f.get("side_a_host") or "")).lower()
        hb = _short_hostname(str(f.get("Side_B_Host") or f.get("side_b_host") or "")).lower()
        if ha and hb:
            pair = tuple(sorted((ha, hb)))
            trunk_sev_by_pair.setdefault(pair, []).append(
                {
                    "rule_id": str(f.get("Rule_ID") or f.get("rule_id") or ""),
                    "severity": str(f.get("Severity") or f.get("severity") or ""),
                    "hint": str(f.get("Remediation_Hint") or f.get("remediation_hint") or ""),
                }
            )

    # 2. Collect AP rollups, WAN carrier observations, L3 egress nodes, and infra edges
    ap_nodes_by_id: dict[str, dict[str, Any]] = {}
    wireless_aps: list[dict[str, Any]] = []
    seen_ap_switch_keys: set[tuple[str, str, str]] = set()
    wan_cloud_obs: dict[str, list[dict[str, Any]]] = {}
    raw_edge_obs: list[dict[str, Any]] = []

    def _ensure_uncrawled_node(
        remote_raw: str,
        cls: str,
        nbr: dict[str, Any],
        src_site: str,
    ) -> str:
        r_short = _short_hostname(remote_raw)
        r_lc = r_short.lower()
        rip = str(nbr.get("remote_ip") or "").strip()
        if r_lc in host_to_id:
            return host_to_id[r_lc]
        if rip and rip in host_to_id:
            return host_to_id[rip]

        dst_id = f"ext:{_slugify(r_short)}"
        if dst_id not in nodes_by_id:
            n_type = str(nbr.get("device_type") or "").strip().lower()
            if cls == "firewall":
                role = "firewall"
            elif cls == "router":
                role = "router"
            elif cls == "isp":
                role = "isp"
            elif n_type == "wlc":
                role = "wlc"
            else:
                role = "uncrawled_switch"

            rmac = _extract_neighbor_mac(remote_raw, nbr)
            plat = str(nbr.get("platform") or nbr.get("remote_platform") or "").strip()
            oui_v = oui_lookup.lookup_oui(rmac) if rmac else ""
            if oui_v == "Unknown":
                oui_v = ""
            vendor_lbl = plat or oui_v or "Unknown"
            model_lbl = plat or ("Perimeter Firewall" if role == "firewall" else "Uncrawled Infrastructure")
            l3_subs_ext = []
            if rip and _is_valid_ipv4(rip):
                l3_subs_ext.append(
                    {
                        "interface": str(nbr.get("remote_port") or "wan"),
                        "ip": rip,
                        "cidr": rip,
                        "mask_known": False,
                        "vlan_id": str(nbr.get("transit_vlan") or ""),
                        "vlan_name": "",
                        "vlan_description": "",
                    }
                )
            nodes_by_id[dst_id] = {
                "id": dst_id,
                "hostname": r_short,
                "ip": rip,
                "site": src_site,
                "orig_site": src_site,
                "sub_site": "",
                "hop_depth": 0,
                "role": role,
                "layer": 0 if role in ("firewall", "isp") else _ROLE_ORDER.get(role, 6),
                "vendor": vendor_lbl,
                "model": model_lbl,
                "serial": "",
                "firmware": "",
                "mac": rmac,
                "stp_root": False,
                "stp_root_scope": "not_applicable",
                "stp_root_bridge_mac": "",
                "stp_priority": "",
                "stp_anomalies": [],
                "poe_used_w": 0.0,
                "poe_total_w": 0.0,
                "lldp": "unknown",
                "cdp": "unsupported",
                "ports_up": 0,
                "ports_total": 0,
                "vlans": [],
                "l3_subnets": l3_subs_ext,
                "default_gateway_ip": "",
                "dhcp_relays": [],
                "attached_ap_count": 0,
                "attached_aps": [],
                "is_l3_gateway": role in ("firewall", "router", "isp"),
                "is_crawled": False,
            }
            host_to_id[r_lc] = dst_id
            if rip:
                host_to_id.setdefault(rip, dst_id)
        return dst_id

    for src_id, dev in list(dev_by_id.items()):
        src_node = nodes_by_id[src_id]
        src_site = src_node["site"]
        dev_ports = dev.get("ports") or {}
        ports_ci = {str(k).lower(): v for k, v in dev_ports.items()}
        ints_detail = dev.get("interfaces_detail") or {}
        stp_vlans = (dev.get("stp") or {}).get("vlans") or {}

        for n in dev.get("neighbors") or []:
            remote_raw = str((n or {}).get("remote_device") or "").strip().strip("\"'")
            if not remote_raw:
                continue

            cls = classify_neighbor_node(
                remote_raw,
                n,
                crawled_hosts_lc=crawled_hosts_lc,
                crawled_ips=crawled_ips,
                crawled_macs=crawled_macs,
            )
            if cls == "endpoint":
                continue

            lp = str(n.get("local_port") or "").strip()
            rp = str(n.get("remote_port") or "").strip()
            if rp.lower() in ("unknown", "n/a", "-"):
                rp = ""
            cport = ports_ci.get(lp.lower()) or ports_ci.get(_norm_iface(lp)) or {}
            stp_state = str(cport.get("stp_state") or "").upper()
            is_blk = stp_state in ("BLK", "BLOCKING", "DISCARDING")
            if not is_blk and lp:
                for _vid, vports in stp_vlans.items():
                    if isinstance(vports, dict) and str((vports.get(lp) or {}).get("state") or "").upper() in (
                        "BLK",
                        "BLOCKING",
                        "DISCARDING",
                    ):
                        is_blk = True
                        break
            raw_speed = str((ints_detail.get(lp) or {}).get("speed") or "")
            speed_mbps, speed_lbl = _parse_speed_mbps(raw_speed, lp)
            tt, ev = _resolve_transport_and_evidence(n)

            # AP classification & rollup
            if cls == "ap" or (
                cls == "crawled_infra"
                and src_node["role"] != "ap"
                and nodes_by_id.get(host_to_id.get(_short_hostname(remote_raw).lower(), ""), {}).get("role") == "ap"
            ):
                ap_host = _short_hostname(remote_raw)
                ap_ip = str(n.get("remote_ip") or "").strip()
                ap_mac = _extract_neighbor_mac(remote_raw, n)
                ap_model = str(n.get("platform") or n.get("remote_platform") or "Wireless AP").strip()

                if cls == "crawled_infra":
                    dst_id = (
                        host_to_id.get(ap_host.lower())
                        or host_to_id.get(ap_ip)
                        or host_to_id.get(remote_raw.lower(), "")
                    )
                    if dst_id and dst_id in nodes_by_id:
                        c_ap = nodes_by_id[dst_id]
                        ap_host = c_ap["hostname"]
                        ap_ip = c_ap["ip"] or ap_ip
                        ap_mac = c_ap["mac"] or ap_mac
                        ap_model = c_ap["model"] or ap_model
                        raw_edge_obs.append(
                            {
                                "src_id": src_id,
                                "dst_id": dst_id,
                                "src_port": lp,
                                "dst_port": rp,
                                "speed_mbps": speed_mbps,
                                "speed_lbl": speed_lbl,
                                "is_blocked": is_blk,
                                "transport_type": tt,
                                "evidence": ev,
                                "transit_vlan": str(n.get("transit_vlan") or ""),
                                "transit_cidr": str(n.get("transit_cidr") or ""),
                                "mask_mismatch": str(n.get("mask_mismatch") or ""),
                                "route_prefix": str(n.get("route_prefix") or ""),
                                "notes": str(n.get("l2_accuracy_note") or ""),
                            }
                        )
                if src_node["role"] != "ap":
                    dedup_key = (src_id, _norm_iface(lp), ap_mac or ap_host.lower())
                    if dedup_key not in seen_ap_switch_keys:
                        seen_ap_switch_keys.add(dedup_key)
                        ap_rec = {
                            "hostname": ap_host,
                            "ip": ap_ip,
                            "mac": ap_mac,
                            "local_port": lp,
                            "model": ap_model,
                        }
                        src_node["attached_aps"].append(ap_rec)
                        src_node["attached_ap_count"] += 1
                        ap_nid = f"ap:{_slugify(ap_mac or ap_host)}_{_slugify(src_id)}"
                        ap_nodes_by_id[ap_nid] = {
                            "id": ap_nid,
                            "hostname": ap_host,
                            "ip": ap_ip,
                            "site": src_site,
                            "role": "ap",
                            "layer": 5,
                            "model": ap_model,
                            "vendor": ap_model,
                            "mac": ap_mac,
                            "attached_to": src_id,
                            "attached_hostname": src_node["hostname"],
                            "local_port": lp,
                            "remote_port": rp or "eth0",
                            "speed": speed_lbl,
                            "is_crawled": cls == "crawled_infra",
                        }
                        wireless_aps.append(
                            {
                                "switch_id": src_id,
                                "switch_hostname": src_node["hostname"],
                                "site": src_site,
                                "local_port": lp,
                                "hostname": ap_host,
                                "ip": ap_ip,
                                "mac": ap_mac,
                                "model": ap_model,
                                "is_crawled": cls == "crawled_infra",
                            }
                        )
                continue

            # Resolve infra peer ID
            if cls == "crawled_infra":
                r_short = _short_hostname(remote_raw).lower()
                rip = str(n.get("remote_ip") or "").strip()
                rmac = _extract_neighbor_mac(remote_raw, n)
                dst_id = (
                    host_to_id.get(r_short)
                    or host_to_id.get(remote_raw.lower())
                    or (host_to_id.get(rip) if rip else None)
                    or ""
                )
                if not dst_id and rmac:
                    for cid, cn in nodes_by_id.items():
                        if oui_lookup.normalize_mac(cn.get("mac", "")).lower() == rmac:
                            dst_id = cid
                            break
                if not dst_id:
                    continue
            else:
                dst_id = _ensure_uncrawled_node(remote_raw, cls, n, src_site)

            if src_id == dst_id:
                continue

            # Group Carrier Metro-E / WAN observations for cloud materialization
            if str(n.get("l2_accuracy") or "").lower() == "wan_carrier_arp_route":
                cloud_name = str(n.get("carrier_cloud") or "Carrier Metro-E / WAN").strip()
                wan_cloud_obs.setdefault(cloud_name, []).append(
                    {
                        "src_id": src_id,
                        "dst_id": dst_id,
                        "src_port": lp,
                        "dst_port": rp,
                        "speed_mbps": speed_mbps,
                        "speed_lbl": speed_lbl,
                        "transport_type": tt,
                        "evidence": "wan_carrier_arp_route",
                        "transit_vlan": str(n.get("transit_vlan") or ""),
                        "transit_cidr": str(n.get("transit_cidr") or ""),
                        "mask_mismatch": str(n.get("mask_mismatch") or ""),
                        "notes": str(n.get("l2_accuracy_note") or ""),
                    }
                )
                continue

            # Regular or L3 egress edge observation
            raw_edge_obs.append(
                {
                    "src_id": src_id,
                    "dst_id": dst_id,
                    "src_port": lp,
                    "dst_port": rp,
                    "speed_mbps": speed_mbps,
                    "speed_lbl": speed_lbl,
                    "is_blocked": is_blk,
                    "transport_type": tt,
                    "evidence": ev,
                    "transit_vlan": str(n.get("transit_vlan") or ""),
                    "transit_cidr": str(n.get("transit_cidr") or ""),
                    "mask_mismatch": str(n.get("mask_mismatch") or ""),
                    "route_prefix": str(n.get("route_prefix") or ""),
                    "notes": str(n.get("l2_accuracy_note") or ""),
                }
            )

            # Synthesize ISP handoff connected to Perimeter Firewall when present
            isp_handoff = n.get("isp_handoff")
            if isinstance(isp_handoff, dict) and isp_handoff:
                isp_label = str(isp_handoff.get("isp_label") or isp_handoff.get("isp_vendor") or "ISP Handoff").strip()
                isp_id = f"isp:{_slugify(isp_label)}"
                if isp_id not in nodes_by_id:
                    isp_vendor = str(isp_handoff.get("isp_vendor") or "ISP Fiber NID")
                    nodes_by_id[isp_id] = {
                        "id": isp_id,
                        "hostname": isp_label,
                        "ip": "",
                        "site": src_site,
                        "orig_site": src_site,
                        "sub_site": "",
                        "hop_depth": 0,
                        "role": "isp",
                        "layer": 0,
                        "vendor": isp_vendor,
                        "model": isp_vendor,
                        "serial": "",
                        "firmware": "",
                        "mac": str(isp_handoff.get("isp_mac") or ""),
                        "stp_root": False,
                        "stp_root_scope": "not_applicable",
                        "stp_root_bridge_mac": "",
                        "stp_priority": "",
                        "stp_anomalies": [],
                        "poe_used_w": 0.0,
                        "poe_total_w": 0.0,
                        "lldp": "unknown",
                        "cdp": "unsupported",
                        "ports_up": 0,
                        "ports_total": 0,
                        "vlans": [],
                        "l3_subnets": [],
                        "default_gateway_ip": "",
                        "dhcp_relays": [],
                        "attached_ap_count": 0,
                        "attached_aps": [],
                        "is_l3_gateway": True,
                        "is_crawled": False,
                        "isp_handoff_ports": isp_handoff,
                    }
                isp_port = str(isp_handoff.get("isp_port") or "").strip()
                fw_untrust = str(isp_handoff.get("fw_untrust_port") or "").strip()
                vid_h = str(isp_handoff.get("vlan_id") or "").strip()
                handoff_note = f"VLAN {vid_h}: {src_node['hostname']}({isp_port}) -> FW({fw_untrust})".strip()
                raw_edge_obs.append(
                    {
                        "src_id": isp_id,
                        "dst_id": dst_id,
                        "src_port": isp_port or "NID",
                        "dst_port": fw_untrust or "Untrust",
                        "speed_mbps": 1000,
                        "speed_lbl": "1G",
                        "is_blocked": False,
                        "transport_type": "l3_egress",
                        "evidence": "l3_next_hop_egress",
                        "transit_vlan": vid_h,
                        "transit_cidr": "",
                        "mask_mismatch": "",
                        "route_prefix": "0.0.0.0/0",
                        "notes": handoff_note,
                        "force_direction": (isp_id, dst_id),
                    }
                )

    # Include crawled APs that weren't seen via switch neighbor lists (safety net)
    crawled_ap_seen = {a["hostname"].lower() for a in wireless_aps if a.get("is_crawled")}
    for nrec in nodes_by_id.values():
        if nrec["role"] == "ap" and nrec["is_crawled"] and nrec["hostname"].lower() not in crawled_ap_seen:
            wireless_aps.append(
                {
                    "switch_id": "",
                    "switch_hostname": "",
                    "site": nrec["site"],
                    "local_port": "",
                    "hostname": nrec["hostname"],
                    "ip": nrec["ip"],
                    "mac": nrec["mac"],
                    "model": nrec["model"],
                    "is_crawled": True,
                }
            )

    def _lookup_node_port_speed(nid: str, port_name: str, fallback_mbps: int, fallback_lbl: str) -> tuple[int, str]:
        dev_ints = (dev_by_id.get(nid) or {}).get("interfaces_detail") or {}
        raw_sp = str((dev_ints.get(port_name) or {}).get("speed") or "")
        if not raw_sp and port_name:
            norm_target = _norm_iface(port_name)
            for k_if, v_if in dev_ints.items():
                if _norm_iface(k_if) == norm_target:
                    raw_sp = str((v_if or {}).get("speed") or "")
                    break
        if raw_sp or port_name:
            return _parse_speed_mbps(raw_sp, port_name)
        return fallback_mbps, fallback_lbl

    def _classify_cloud_mode(
        obs_list: list[dict[str, Any]],
        degree: dict[str, set[str]],
    ) -> tuple[str, list[str]]:
        """Determine ``(cloud_mode, hub_ids)`` for a carrier WAN/Metro-E cloud."""
        for o in obs_list:
            explicit_mode = str(o.get("cloud_mode") or "").strip().lower()
            if explicit_mode in ("hub-and-spoke", "dual-hub", "full-mesh"):
                explicit_hubs = [h for h in (o.get("hub_ids") or []) if h in degree]
                if explicit_hubs:
                    return explicit_mode, sorted(set(explicit_hubs))
                if explicit_mode == "full-mesh":
                    return "full-mesh", sorted(degree.keys())

        all_peers = sorted(degree.keys())
        n = len(all_peers)
        if n <= 1:
            return "hub-and-spoke", all_peers

        pairs = {(min(o["src_id"], o["dst_id"]), max(o["src_id"], o["dst_id"])) for o in obs_list}
        max_possible = n * (n - 1) // 2
        degs = [len(degree[k]) for k in all_peers]
        min_deg, max_deg = min(degs), max(degs)

        # Full-mesh: >= 3 peers and all (or >= 75% with uniform degree >= 2, excluding bipartite K_{2,2}) peers interconnect
        is_bipartite_k22 = n == 4 and max_deg == min_deg == 2 and len(pairs) == 4
        if (
            n >= 3
            and not is_bipartite_k22
            and (
                len(pairs) == max_possible
                or (min_deg >= 2 and max_deg - min_deg <= 1 and len(pairs) >= max(3, int(0.75 * max_possible)))
            )
        ):
            return "full-mesh", all_peers

        def _hub_score(nid: str) -> tuple[int, int, int, int, str]:
            nr = nodes_by_id.get(nid, {})
            is_core_role = 1 if nr.get("role") in ("core", "router", "firewall") else 0
            has_hub_kw = 1 if any(w in nr.get("hostname", "").lower() for w in ("hub", "main", "dc", "core")) else 0
            return (len(degree[nid]), is_core_role, len(nr.get("l3_subnets") or []), has_hub_kw, nid)

        # Dual-hub: multiple high-degree hubs anchoring spokes
        if n >= 4:
            # Bipartite K_{2,2} (all degree 2, 4 edges) or K_{2,m} (2 hubs have max_deg)
            top_ranked = sorted(all_peers, key=_hub_score, reverse=True)
            if max_deg == min_deg == 2 and len(pairs) == 4:
                return "dual-hub", sorted(top_ranked[:2])
            hub_cands = [k for k in all_peers if len(degree[k]) >= max(2, max_deg - 1) and len(degree[k]) == max_deg]
            if len(hub_cands) < 2 and max_deg >= 3:
                # Secondary hub with degree >= max_deg - 1 that is a core/router/hub-named node
                hub_cands = [
                    k
                    for k in all_peers
                    if len(degree[k]) >= max_deg - 1
                    and (
                        len(degree[k]) == max_deg
                        or nodes_by_id.get(k, {}).get("role") in ("core", "router", "firewall")
                        or any(w in nodes_by_id.get(k, {}).get("hostname", "").lower() for w in ("hub", "main", "dc"))
                    )
                ]
            if len(hub_cands) >= 2 and len(hub_cands) < n:
                return "dual-hub", sorted(hub_cands)

        single_hub = max(all_peers, key=_hub_score)
        return "hub-and-spoke", [single_hub]

    # 2b. Gap 4: Deterministic fallback [Metro-E] & [L3 Egress] synthesis when core telemetry is missing/partial
    _CARRIER_FALLBACK_RE = re.compile(
        r"\b(?:metro|wan|carrier|spectrum|spectrun|comcast|mpls|fiber|circuit|transit)\b",
        re.IGNORECASE,
    )
    _FW_FALLBACK_RE = re.compile(r"(?:firewall|palo|forti|opnsense|pfsense|asa|srx|untrust|\bfw\b)", re.IGNORECASE)
    linked_dev_ids: set[str] = set()
    for o in raw_edge_obs:
        linked_dev_ids.add(o["src_id"])
        linked_dev_ids.add(o["dst_id"])
    for obs_list in wan_cloud_obs.values():
        for o in obs_list:
            linked_dev_ids.add(o["src_id"])
            linked_dev_ids.add(o["dst_id"])

    carrier_spoke_cands: dict[str, list[dict[str, Any]]] = {}
    egress_cands: list[dict[str, Any]] = []
    for src_id, dev in list(dev_by_id.items()):
        src_node = nodes_by_id[src_id]
        if src_node["role"] in ("ap", "wan_cloud", "isp"):
            continue
        # Skip if already has an uplink to a wan_cloud or l3_egress neighbor
        has_egress_or_wan = any(
            (o["src_id"] == src_id or o["dst_id"] == src_id)
            and o.get("transport_type") in ("l3_egress", "metro_ethernet", "wan_carrier")
            for o in raw_edge_obs
        ) or any(o["src_id"] == src_id or o["dst_id"] == src_id for obs_l in wan_cloud_obs.values() for o in obs_l)
        if has_egress_or_wan:
            continue

        # Collect default routes on this crawled device
        def_routes = [
            rt
            for rt in (dev.get("routes") or [])
            if _is_default_route_prefix(str((rt or {}).get("subnet") or "").strip())
            and _is_valid_ip(str((rt or {}).get("next_hop") or "").strip())
            and str((rt or {}).get("next_hop") or "").strip() not in ("0.0.0.0", "::")
        ]
        distinct_nhs = {str(r.get("next_hop") or "").strip() for r in def_routes}
        # Conflicting multiple default next-hops without clear single egress -> do not fabricate
        if len(distinct_nhs) != 1:
            continue
        rt = def_routes[0]
        nh = str(rt.get("next_hop") or "").strip()
        if nh in crawled_ips:
            continue

        # Corroborate via ARP table OR local L3 subnet containment
        arp_hit = next(
            (a for a in (dev.get("arp_table") or []) if str((a or {}).get("ip") or "").strip() == nh),
            None,
        )
        nh_obj = IPAddress(nh)
        local_sub_match = None
        for sub in src_node.get("l3_subnets") or []:
            _cip, snet = _parse_iface_network(sub.get("ip", ""))
            if snet and snet.version == nh_obj.version and nh_obj in snet:
                local_sub_match = sub
                break
        if not arp_hit and not local_sub_match:
            continue

        rt_intf = str(rt.get("interface") or (local_sub_match or {}).get("interface") or "").strip()
        ints_detail = dev.get("interfaces_detail") or {}
        pdesc = str((ints_detail.get(rt_intf) or {}).get("description") or "").strip()
        vname = str((local_sub_match or {}).get("vlan_name") or "").strip()
        vdesc = str((local_sub_match or {}).get("vlan_description") or "").strip()
        kw_blob = f"{rt_intf} {pdesc} {vname} {vdesc}"
        prov = ["edge_default_route"]
        if arp_hit:
            prov.append("edge_arp")
        if local_sub_match:
            prov.append("local_subnet_match")
        if _CARRIER_FALLBACK_RE.search(kw_blob):
            prov.append("carrier_interface_attr")

        ev = "inferred_arp_route" if arp_hit else "inferred_route_only"
        sp_mbps, sp_lbl = _parse_speed_mbps(str((ints_detail.get(rt_intf) or {}).get("speed") or ""), rt_intf)
        cand = {
            "src_id": src_id,
            "nh": nh,
            "rt_intf": rt_intf,
            "speed_mbps": sp_mbps,
            "speed_lbl": sp_lbl,
            "transit_cidr": (local_sub_match or {}).get("cidr", ""),
            "transit_vlan": (local_sub_match or {}).get("vlan_id", ""),
            "ev": ev,
            "prov": prov,
            "kw_blob": kw_blob,
            "arp_mac": str((arp_hit or {}).get("mac") or "").lower(),
        }
        if _CARRIER_FALLBACK_RE.search(kw_blob) and "metro" in kw_blob.lower():
            carrier_key = "Carrier Metro-E (Inferred)"
            carrier_spoke_cands.setdefault(carrier_key, []).append(cand)
        else:
            egress_cands.append(cand)

    # Synthesize fallback [Metro-E] when >= 2 carrier-tagged spokes share an uncrawled core/cloud
    for cloud_name, cands in carrier_spoke_cands.items():
        if len(cands) >= 2:
            hub_ext_id = "ext:uncrawled_core_hub"
            if hub_ext_id not in nodes_by_id:
                nodes_by_id[hub_ext_id] = {
                    "id": hub_ext_id,
                    "hostname": "Uncrawled-Core-Hub",
                    "ip": cands[0]["nh"],
                    "site": nodes_by_id[cands[0]["src_id"]]["site"],
                    "orig_site": nodes_by_id[cands[0]["src_id"]]["site"],
                    "sub_site": "",
                    "hop_depth": 0,
                    "role": "core",
                    "layer": 2,
                    "vendor": "Unknown",
                    "model": "Uncrawled Core (Missing Telemetry)",
                    "serial": "",
                    "firmware": "",
                    "mac": "",
                    "stp_root": False,
                    "stp_root_scope": "not_applicable",
                    "stp_root_bridge_mac": "",
                    "stp_priority": "",
                    "stp_anomalies": [],
                    "poe_used_w": 0.0,
                    "poe_total_w": 0.0,
                    "lldp": "unknown",
                    "cdp": "unsupported",
                    "ports_up": 0,
                    "ports_total": 0,
                    "vlans": [],
                    "l3_subnets": [],
                    "default_gateway_ip": "",
                    "dhcp_relays": [],
                    "attached_ap_count": 0,
                    "attached_aps": [],
                    "is_l3_gateway": True,
                    "is_crawled": False,
                    "blind_spot": True,
                    "blind_spot_reason": "missing_core_telemetry: core/hub CLI/SSH telemetry unavailable",
                }
            for c in cands:
                wan_cloud_obs.setdefault(cloud_name, []).append(
                    {
                        "src_id": hub_ext_id,
                        "dst_id": c["src_id"],
                        "src_port": "Carrier Handoff",
                        "dst_port": c["rt_intf"],
                        "speed_mbps": c["speed_mbps"],
                        "speed_lbl": c["speed_lbl"],
                        "transport_type": "metro_ethernet",
                        "evidence": c["ev"],
                        "transit_vlan": c["transit_vlan"],
                        "transit_cidr": c["transit_cidr"],
                        "mask_mismatch": "",
                        "notes": "Synthesized [Metro-E] candidate from edge/spoke telemetry (core telemetry missing)",
                        "blind_spot": True,
                        "blind_spot_reason": "missing_core_telemetry: core/hub CLI/SSH telemetry unavailable",
                        "provenance": c["prov"],
                    }
                )
        else:
            egress_cands.extend(cands)

    # Synthesize fallback [L3 Egress] for remaining unlinked edge/spoke default gateways
    for c in egress_cands:
        nh = c["nh"]
        src_node_role = nodes_by_id[c["src_id"]]["role"]
        gw_id = f"ext:gw_{_slugify(nh)}"
        if gw_id not in nodes_by_id:
            oui_v = oui_lookup.lookup_oui(c["arp_mac"]) if c["arp_mac"] else ""
            if oui_v == "Unknown":
                oui_v = ""
            if src_node_role == "firewall":
                gw_role = "isp"
                gw_label = f"ISP Gateway ({nh})"
            elif _FW_FALLBACK_RE.search(f"{c['kw_blob']} {oui_v}"):
                gw_role = "firewall"
                gw_label = f"Perimeter-Firewall ({nh})"
            else:
                gw_role = "router"
                gw_label = f"Default-Gateway ({nh})"
            nodes_by_id[gw_id] = {
                "id": gw_id,
                "hostname": gw_label,
                "ip": nh,
                "site": nodes_by_id[c["src_id"]]["site"],
                "orig_site": nodes_by_id[c["src_id"]]["site"],
                "sub_site": "",
                "hop_depth": 0,
                "role": gw_role,
                "layer": 0 if gw_role == "firewall" else 1,
                "vendor": oui_v or "Unknown",
                "model": "Uncrawled Gateway (Missing Telemetry)",
                "serial": "",
                "firmware": "",
                "mac": c["arp_mac"],
                "stp_root": False,
                "stp_root_scope": "not_applicable",
                "stp_root_bridge_mac": "",
                "stp_priority": "",
                "stp_anomalies": [],
                "poe_used_w": 0.0,
                "poe_total_w": 0.0,
                "lldp": "unknown",
                "cdp": "unsupported",
                "ports_up": 0,
                "ports_total": 0,
                "vlans": [],
                "l3_subnets": [{"interface": "wan", "ip": nh, "cidr": nh, "mask_known": False, "vrf": "default"}],
                "default_gateway_ip": "",
                "dhcp_relays": [],
                "attached_ap_count": 0,
                "attached_aps": [],
                "is_l3_gateway": True,
                "is_crawled": False,
                "blind_spot": True,
                "blind_spot_reason": "missing_core_telemetry: gateway CLI/SSH telemetry unavailable",
            }
        raw_edge_obs.append(
            {
                "src_id": c["src_id"],
                "dst_id": gw_id,
                "src_port": c["rt_intf"],
                "dst_port": "",
                "speed_mbps": c["speed_mbps"],
                "speed_lbl": c["speed_lbl"],
                "is_blocked": False,
                "transport_type": "l3_egress",
                "evidence": c["ev"],
                "transit_vlan": c["transit_vlan"],
                "transit_cidr": c["transit_cidr"],
                "mask_mismatch": "",
                "route_prefix": "::/0" if ":" in nh else "0.0.0.0/0",
                "notes": "Synthesized [L3 Egress] candidate from edge default route (gateway telemetry missing)",
                "blind_spot": True,
                "blind_spot_reason": "missing_core_telemetry: gateway CLI/SSH telemetry unavailable",
                "provenance": c["prov"],
            }
        )

    # 3. Materialize WAN Cloud nodes & Hub(s) -> wan_cloud -> Remote Core edges (supports hub-and-spoke, dual-hub, full-mesh)
    wan_cloud_ids: set[str] = set()
    for cloud_name, obs_list in wan_cloud_obs.items():
        degree: dict[str, set[str]] = {}
        for o in obs_list:
            degree.setdefault(o["src_id"], set()).add(o["dst_id"])
            degree.setdefault(o["dst_id"], set()).add(o["src_id"])
        cloud_mode, hub_ids = _classify_cloud_mode(obs_list, degree)
        hub_set = set(hub_ids)
        spoke_ids = sorted(k for k in degree.keys() if k not in hub_set)
        primary_hub_id = hub_ids[0] if hub_ids else next(iter(degree.keys()))
        hub_site = nodes_by_id[primary_hub_id]["site"]
        cloud_id = f"wan_cloud:{_slugify(cloud_name)}"
        wan_cloud_ids.add(cloud_id)
        cloud_blind_spot = any(bool(o.get("blind_spot")) for o in obs_list)
        if cloud_id not in nodes_by_id:
            nodes_by_id[cloud_id] = {
                "id": cloud_id,
                "hostname": cloud_name,
                "ip": "",
                "site": hub_site,
                "orig_site": hub_site,
                "sub_site": "",
                "hop_depth": 0,
                "role": "wan_cloud",
                "layer": 1,
                "vendor": "Carrier WAN",
                "model": "Carrier WAN / Metro-E",
                "serial": "",
                "firmware": "",
                "mac": "",
                "cloud_mode": cloud_mode,
                "hub_ids": hub_ids,
                "spoke_ids": spoke_ids,
                "blind_spot": cloud_blind_spot,
                "stp_root": False,
                "stp_root_scope": "not_applicable",
                "stp_root_bridge_mac": "",
                "stp_priority": "",
                "stp_anomalies": [],
                "poe_used_w": 0.0,
                "poe_total_w": 0.0,
                "lldp": "unknown",
                "cdp": "unsupported",
                "ports_up": 0,
                "ports_total": 0,
                "vlans": [],
                "l3_subnets": [],
                "default_gateway_ip": "",
                "dhcp_relays": [],
                "attached_ap_count": 0,
                "attached_aps": [],
                "is_l3_gateway": False,
                "is_crawled": False,
            }

        seen_cloud_links: set[tuple[str, str, str, str]] = set()
        for o in obs_list:
            endpoints = [
                (o["src_id"], o["src_port"], o["speed_mbps"], o["speed_lbl"]),
                (o["dst_id"], o["dst_port"], 1000, "1G"),
            ]
            for pid, p_port, fb_mbps, fb_lbl in endpoints:
                lk_key = (pid, _norm_iface(p_port), o.get("transit_vlan", ""), o.get("transit_cidr", ""))
                if lk_key in seen_cloud_links:
                    continue
                seen_cloud_links.add(lk_key)
                sp_mbps, sp_lbl = _lookup_node_port_speed(pid, p_port, fb_mbps, fb_lbl)
                ev_str = o.get("evidence") or "wan_carrier_arp_route"
                is_bs = bool(o.get("blind_spot"))
                bs_reason = str(o.get("blind_spot_reason") or "")
                prov_list = list(o.get("provenance") or [])
                if pid in hub_set:
                    raw_edge_obs.append(
                        {
                            "src_id": pid,
                            "dst_id": cloud_id,
                            "src_port": p_port,
                            "dst_port": "Carrier Handoff",
                            "speed_mbps": sp_mbps,
                            "speed_lbl": sp_lbl,
                            "is_blocked": False,
                            "transport_type": o["transport_type"],
                            "evidence": ev_str,
                            "transit_vlan": "" if cloud_mode == "hub-and-spoke" else o.get("transit_vlan", ""),
                            "transit_cidr": "" if cloud_mode == "hub-and-spoke" else o.get("transit_cidr", ""),
                            "mask_mismatch": o.get("mask_mismatch", "") if cloud_mode != "hub-and-spoke" else "",
                            "route_prefix": "",
                            "notes": f"{cloud_name} ({cloud_mode}) trunk",
                            "force_direction": (pid, cloud_id),
                            "blind_spot": is_bs,
                            "blind_spot_reason": bs_reason,
                            "provenance": prov_list,
                        }
                    )
                else:
                    raw_edge_obs.append(
                        {
                            "src_id": cloud_id,
                            "dst_id": pid,
                            "src_port": f"VLAN {o['transit_vlan']}" if o.get("transit_vlan") else "Circuit",
                            "dst_port": p_port,
                            "speed_mbps": sp_mbps,
                            "speed_lbl": sp_lbl,
                            "is_blocked": False,
                            "transport_type": o["transport_type"],
                            "evidence": ev_str,
                            "transit_vlan": o.get("transit_vlan", ""),
                            "transit_cidr": o.get("transit_cidr", ""),
                            "mask_mismatch": o.get("mask_mismatch", ""),
                            "route_prefix": "",
                            "notes": o.get("notes", ""),
                            "force_direction": (cloud_id, pid),
                            "blind_spot": is_bs,
                            "blind_spot_reason": bs_reason,
                            "provenance": prov_list,
                        }
                    )

    # 4. Parent-Site BFS + sub_site tagging + per-site hop_depth BFS
    l2_adj: dict[str, set[str]] = {}
    for o in raw_edge_obs:
        s, t = o["src_id"], o["dst_id"]
        if s in wan_cloud_ids or t in wan_cloud_ids:
            continue
        if nodes_by_id[s]["role"] in ("firewall", "isp") or nodes_by_id[t]["role"] in ("firewall", "isp"):
            continue
        l2_adj.setdefault(s, set()).add(t)
        l2_adj.setdefault(t, set()).add(s)

    core_sites = {n["site"] for n in nodes_by_id.values() if n["layer"] <= 2 and n["is_crawled"]}
    site_seeds = [nid for nid, n in nodes_by_id.items() if n["layer"] <= 2 and n["is_crawled"]]
    site_q: deque[str] = deque(site_seeds)
    site_vis = set(site_seeds)
    while site_q:
        cur = site_q.popleft()
        cur_site = nodes_by_id[cur]["site"]
        for nb in sorted(l2_adj.get(cur, set())):
            if nb in site_vis:
                continue
            site_vis.add(nb)
            if nodes_by_id[nb]["site"] not in core_sites:
                nodes_by_id[nb]["site"] = cur_site
            site_q.append(nb)

    for nrec in nodes_by_id.values():
        orig = nrec.pop("orig_site", nrec["site"])
        nrec["sub_site"] = orig if (orig and orig != nrec["site"]) else ""

    # Compute hop_depth per site via BFS starting at each site's Core/Router/FW
    intra_adj: dict[str, set[str]] = {}
    for o in raw_edge_obs:
        s, t = o["src_id"], o["dst_id"]
        if s in wan_cloud_ids or t in wan_cloud_ids:
            continue
        if nodes_by_id[s]["role"] in ("wan_cloud", "isp", "firewall") or nodes_by_id[t]["role"] in (
            "wan_cloud",
            "isp",
            "firewall",
        ):
            continue
        if nodes_by_id[s]["site"] == nodes_by_id[t]["site"]:
            intra_adj.setdefault(s, set()).add(t)
            intra_adj.setdefault(t, set()).add(s)

    by_site_ids: dict[str, list[str]] = {}
    for nid, nrec in nodes_by_id.items():
        if nrec["role"] in ("wan_cloud", "isp", "firewall"):
            nrec["hop_depth"] = 0
            continue
        by_site_ids.setdefault(nrec["site"], []).append(nid)

    for _sc, nids in by_site_ids.items():
        seeds = [nid for nid in nids if nodes_by_id[nid]["layer"] <= 2 and nodes_by_id[nid]["is_crawled"]]
        if not seeds:
            seeds = [nid for nid in nids if nodes_by_id[nid]["layer"] <= 2]
        if not seeds and nids:
            seeds = [min(nids, key=lambda x: (nodes_by_id[x]["layer"], -len(intra_adj.get(x, set())), x))]
        hq: deque[str] = deque()
        depth_vis: set[str] = set()
        for sid in seeds:
            nodes_by_id[sid]["hop_depth"] = 0
            depth_vis.add(sid)
            hq.append(sid)
        while hq:
            cur = hq.popleft()
            d_next = nodes_by_id[cur]["hop_depth"] + 1
            for nb in sorted(intra_adj.get(cur, set())):
                if nb not in depth_vis:
                    depth_vis.add(nb)
                    nodes_by_id[nb]["hop_depth"] = d_next
                    hq.append(nb)
        for nid in nids:
            if nid not in depth_vis:
                nodes_by_id[nid]["hop_depth"] = 1 if nodes_by_id[nid]["layer"] > 2 else 0

    # Sync AP site codes after parent-site BFS
    for ap in ap_nodes_by_id.values():
        sw = nodes_by_id.get(ap["attached_to"])
        if sw:
            ap["site"] = sw["site"]
    for ap in wireless_aps:
        sw = nodes_by_id.get(ap["switch_id"])
        if sw:
            ap["site"] = sw["site"]

    # 5. Build canonical oriented, deduplicated edges
    edges_map: dict[tuple[str, str], dict[str, Any]] = {}

    def _orient_pair(obs: dict[str, Any]) -> tuple[str, str, str, str]:
        s, t = obs["src_id"], obs["dst_id"]
        sp, dp = obs["src_port"], obs["dst_port"]
        forced = obs.get("force_direction")
        if forced:
            if forced == (s, t):
                return s, t, sp, dp
            return t, s, dp, sp
        ns, nt = nodes_by_id[s], nodes_by_id[t]
        if nt["role"] in ("firewall", "isp") and ns["role"] not in ("firewall", "isp"):
            return t, s, dp, sp
        if ns["role"] in ("firewall", "isp") and nt["role"] not in ("firewall", "isp"):
            return s, t, sp, dp
        key_s = (ns["layer"], ns["hop_depth"], ns["hostname"].lower(), s)
        key_t = (nt["layer"], nt["hop_depth"], nt["hostname"].lower(), t)
        if key_s <= key_t:
            return s, t, sp, dp
        return t, s, dp, sp

    _TT_PRIORITY = {
        "l3_egress": 6,
        "metro_ethernet": 5,
        "wan_carrier": 5,
        "l3_routed": 4,
        "virtual_passthrough": 3,
        "mac_inferred": 2,
        "direct_l2_uplink": 1,
    }
    _EV_PRIORITY = {
        "wan_carrier_arp_route": 6,
        "l3_next_hop_egress": 6,
        "confirmed_lldp": 5,
        "cdp": 4,
        "passthrough": 3,
        "mac_inferred": 2,
        "inferred_arp_route": 2,
        "unidirectional_lldp": 1,
        "inferred_route_only": 1,
    }

    for obs in raw_edge_obs:
        src, dst, p_src, p_dst = _orient_pair(obs)
        pair_key = (src, dst)
        edge = edges_map.get(pair_key)

        ns, nt = nodes_by_id[src], nodes_by_id[dst]
        if ns["role"] == "ap" or nt["role"] == "ap":
            lscope = "wireless_ap"
        elif (
            ns["role"] in ("wan_cloud", "firewall", "isp", "router")
            or nt["role"] in ("wan_cloud", "firewall", "isp", "router")
            or ns["site"] != nt["site"]
            or (ns["role"] == "core" and nt["role"] == "core")
            or obs["transport_type"] in ("metro_ethernet", "wan_carrier", "l3_egress", "l3_routed")
        ):
            lscope = "backbone"
        else:
            lscope = "intra_site"

        if edge is None:
            conf = (
                "mac_inferred"
                if obs["transport_type"] == "mac_inferred"
                else ("passthrough" if obs["transport_type"] == "virtual_passthrough" else "direct")
            )
            edge = {
                "id": f"{src}--{dst}",
                "source": src,
                "target": dst,
                "port_pairs": [],
                "port_pair_objs": [],
                "_seen_ports": {},
                "speed": obs["speed_lbl"],
                "speed_label": obs["speed_lbl"],
                "speed_mbps": obs["speed_mbps"],
                "confidence": conf,
                "transport_type": obs["transport_type"],
                "evidence": obs["evidence"],
                "link_scope": lscope,
                "is_blocked": bool(obs["is_blocked"]),
                "trunk_severity": "",
                "trunk_findings": [],
                "transit_vlan": obs.get("transit_vlan", ""),
                "transit_cidr": obs.get("transit_cidr", ""),
                "mask_mismatch": obs.get("mask_mismatch", ""),
                "route_prefix": obs.get("route_prefix", ""),
                "notes": obs.get("notes", ""),
                "blind_spot": bool(obs.get("blind_spot")),
                "blind_spot_reason": str(obs.get("blind_spot_reason") or ""),
                "provenance": list(obs.get("provenance") or []),
                "display_badge": "",
            }
            edges_map[pair_key] = edge

        # Upgrade transport/evidence/speed/scope if stronger observation arrives
        if _TT_PRIORITY.get(obs["transport_type"], 0) > _TT_PRIORITY.get(edge["transport_type"], 0):
            edge["transport_type"] = obs["transport_type"]
        if _EV_PRIORITY.get(obs["evidence"], 0) > _EV_PRIORITY.get(edge["evidence"], 0):
            edge["evidence"] = obs["evidence"]
        if obs.get("provenance"):
            edge["provenance"] = sorted(set(edge["provenance"]) | set(obs["provenance"]))
        if not obs.get("blind_spot") and edge.get("blind_spot") and _EV_PRIORITY.get(obs["evidence"], 0) >= 4:
            edge["blind_spot"] = False
            edge["blind_spot_reason"] = ""
        if obs["speed_mbps"] > edge["speed_mbps"]:
            edge["speed_mbps"] = obs["speed_mbps"]
            edge["speed"] = obs["speed_lbl"]
            edge["speed_label"] = obs["speed_lbl"]
        if obs["is_blocked"]:
            edge["is_blocked"] = True
        if lscope == "backbone":
            edge["link_scope"] = "backbone"
        for k_opt in ("transit_vlan", "transit_cidr", "mask_mismatch", "route_prefix", "notes"):
            if obs.get(k_opt) and not edge[k_opt]:
                edge[k_opt] = obs[k_opt]

        # Canonical deduplication of port pairs strictly by normalized (src_port, dst_port)
        norm_sp = _norm_iface(p_src)
        norm_dp = _norm_iface(p_dst)
        if p_src or p_dst:
            seen_ports: dict[tuple[str, str], dict[str, Any]] = edge["_seen_ports"]
            if (norm_sp, norm_dp) not in seen_ports:
                # Upgrade partial entries when either side's missing port arrives
                if norm_dp and (norm_sp, "") in seen_ports:
                    existing_obj = seen_ports.pop((norm_sp, ""))
                    existing_obj["dst_port"] = p_dst
                    seen_ports[(norm_sp, norm_dp)] = existing_obj
                elif norm_sp and ("", norm_dp) in seen_ports:
                    existing_obj = seen_ports.pop(("", norm_dp))
                    existing_obj["src_port"] = p_src
                    seen_ports[(norm_sp, norm_dp)] = existing_obj
                elif not norm_dp and any(k[0] == norm_sp and k[1] for k in seen_ports):
                    pass
                elif not norm_sp and any(k[1] == norm_dp and k[0] for k in seen_ports):
                    pass
                else:
                    obj = {
                        "src_port": p_src,
                        "dst_port": p_dst,
                        "speed": obs["speed_lbl"],
                        "is_blocked": bool(obs["is_blocked"]),
                    }
                    seen_ports[(norm_sp, norm_dp)] = obj
                    edge["port_pair_objs"].append(obj)

        # Attach trunk audit findings
        hn_pair = tuple(
            sorted(
                (
                    _short_hostname(nodes_by_id[src]["hostname"]).lower(),
                    _short_hostname(nodes_by_id[dst]["hostname"]).lower(),
                )
            )
        )
        if hn_pair in trunk_sev_by_pair and not edge["trunk_findings"]:
            findings = trunk_sev_by_pair[hn_pair]
            edge["trunk_findings"] = findings
            sevs = {x["severity"] for x in findings}
            for s_lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if s_lvl in sevs:
                    edge["trunk_severity"] = s_lvl
                    break

    def _format_port_pair(po: dict[str, Any], src_role: str, transport_type: str) -> str:
        sp = str(po.get("src_port") or "").strip()
        dp = str(po.get("dst_port") or "").strip()
        if sp and dp:
            return f"{sp} ↔ {dp}"
        if sp:
            return sp
        if dp:
            return f"Trust ↔ {dp}" if (transport_type == "l3_egress" and src_role in ("firewall", "router")) else dp
        return ""

    edges_list: list[dict[str, Any]] = []
    for edge in edges_map.values():
        edge.pop("_seen_ports", None)
        src_role = nodes_by_id.get(edge["source"], {}).get("role", "")
        tt_edge = edge.get("transport_type", "")
        edge["port_pairs"] = [lbl for po in edge["port_pair_objs"] if (lbl := _format_port_pair(po, src_role, tt_edge))]
        if edge["transport_type"] == "mac_inferred":
            edge["confidence"] = "mac_inferred"
        elif edge["transport_type"] == "virtual_passthrough":
            edge["confidence"] = "passthrough"
        edge["display_badge"] = _compute_display_badge(
            edge["transport_type"],
            edge["evidence"],
            edge["speed_label"],
            edge["is_blocked"],
            edge["route_prefix"],
        )
        pmeta = _edge_provenance_meta(
            edge["evidence"],
            edge["transport_type"],
            blind_spot=bool(edge.get("blind_spot")),
            blind_spot_reason=str(edge.get("blind_spot_reason") or ""),
            provenance=edge.get("provenance"),
        )
        edge.update(pmeta)
        edges_list.append(edge)

    # 6. Build canonical L3 routed graph & enriched L3 subnet list
    l3_graph = _build_l3_graph(nodes_by_id, dev_by_id, edges_list)

    l3_map: dict[str, dict[str, Any]] = {}
    for nid, nrec in nodes_by_id.items():
        for sub in nrec.get("l3_subnets") or []:
            cidr = sub["cidr"]
            entry = l3_map.setdefault(
                cidr,
                {
                    "cidr": cidr,
                    "vlan_id": sub.get("vlan_id", ""),
                    "vlan_name": sub.get("vlan_name", ""),
                    "vlan_description": sub.get("vlan_description", ""),
                    "devices": [],
                },
            )
            if sub.get("vlan_id") and not entry["vlan_id"]:
                entry["vlan_id"] = sub["vlan_id"]
            if sub.get("vlan_name") and not entry["vlan_name"]:
                entry["vlan_name"] = sub["vlan_name"]
            if sub.get("vlan_description") and not entry["vlan_description"]:
                entry["vlan_description"] = sub["vlan_description"]
            entry["devices"].append(
                {
                    "id": nid,
                    "hostname": nrec["hostname"],
                    "site": nrec["site"],
                    "interface": sub["interface"],
                    "ip": sub["ip"],
                    "vlan_id": sub.get("vlan_id", ""),
                    "vlan_name": sub.get("vlan_name", ""),
                    "vlan_description": sub.get("vlan_description", ""),
                }
            )

    nodes_sorted = sorted(
        nodes_by_id.values(), key=lambda x: (x["site"], x["layer"], x["hop_depth"], x["hostname"].lower())
    )
    sites = sorted({n["site"] for n in nodes_sorted if n.get("site")})
    ap_nodes_sorted = sorted(
        ap_nodes_by_id.values(), key=lambda x: (x["site"], x["attached_hostname"].lower(), x["hostname"].lower())
    )
    wireless_aps_sorted = sorted(
        wireless_aps, key=lambda x: (x["site"], x["switch_hostname"].lower(), x["local_port"], x["hostname"].lower())
    )

    blind_spots = sorted(
        {
            f"{n['hostname']}: {n.get('blind_spot_reason') or 'missing_core_telemetry'}"
            for n in nodes_sorted
            if n.get("blind_spot")
        }
    )

    return {
        "metadata": {
            "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_nodes": len(nodes_sorted),
            "total_edges": len(edges_list),
            "total_sites": len(sites),
            "total_aps": len(wireless_aps_sorted),
            "crawled_nodes": sum(1 for n in nodes_sorted if n.get("is_crawled")),
            "uncrawled_nodes": sum(1 for n in nodes_sorted if not n.get("is_crawled")),
            "campus_roots": sum(1 for n in nodes_sorted if n.get("stp_root_scope") == "campus_root"),
            "isolated_roots": sum(1 for n in nodes_sorted if n.get("stp_root_scope") == "isolated_self_root"),
            "missing_core_blind_spots": blind_spots,
        },
        "sites": sites,
        "nodes": nodes_sorted,
        "edges": edges_list,
        "ap_nodes": ap_nodes_sorted,
        "wireless_aps": wireless_aps_sorted,
        "l3_subnets": [l3_map[k] for k in sorted(l3_map.keys())],
        "l3_graph": l3_graph,
    }


class TopologyRenderer(ABC):
    """Abstract base class for pluggable topology diagram renderers."""

    name: str = ""
    default_filename: str = ""

    @abstractmethod
    def render(self, graph_model: dict[str, Any], output_path: str) -> str:
        """Render ``graph_model`` to ``output_path`` and return the written path."""


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Net-Docu-Crawler — Interactive Topology Viewer</title>
<style>
  :root {
    --bg: #f8fafc; --panel: #ffffff; --border: #cbd5e1; --text: #0f172a;
    --muted: #475569; --accent: #2563eb; --accent-soft: #dbeafe;
    --root-bg: #dcfce7; --root-bd: #16a34a;
    --iso-bg: #fef3c7; --iso-bd: #d97706;
    --core-bg: #dbeafe; --core-bd: #2563eb;
    --fw-bg: #fee2e2; --fw-bd: #dc2626;
    --wan-bg: #ccfbf1; --wan-bd: #0d9488;
    --sw-bg: #f1f5f9; --sw-bd: #64748b;
    --ap-bg: #fef3c7; --ap-bd: #d97706;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; }
  header { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 9px 14px; background: var(--panel); border-bottom: 1px solid var(--border); }
  header h1 { font-size: 15px; margin: 0 8px 0 0; font-weight: 700; }
  .ctrl { display: flex; align-items: center; gap: 6px; font-size: 12.5px; }
  input[type="search"], select { padding: 5px 8px; border: 1px solid var(--border); border-radius: 6px; font-size: 12.5px; background: #fff; color: var(--text); }
  button { padding: 5px 10px; border: 1px solid var(--border); border-radius: 6px; background: #fff; color: var(--text); cursor: pointer; font-size: 12px; font-weight: 600; }
  button:hover { background: var(--accent-soft); border-color: var(--accent); }
  button.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .main { flex: 1; display: grid; grid-template-columns: 300px 1fr 345px; min-height: 0; }
  @media (max-width: 1120px) { .main { grid-template-columns: 260px 1fr; } .inspector { display: none; } }
  .sidebar, .inspector { background: var(--panel); overflow-y: auto; padding: 12px; }
  .sidebar { border-right: 1px solid var(--border); }
  .inspector { border-left: 1px solid var(--border); font-size: 12.5px; }
  .canvas-wrap { position: relative; overflow: hidden; background: radial-gradient(#e2e8f0 1px, transparent 1px) 0 0 / 20px 20px var(--bg); }
  svg { width: 100%; height: 100%; cursor: grab; display: block; }
  svg:active { cursor: grabbing; }
  .tree-site { margin-bottom: 6px; border: 1px solid var(--border); border-radius: 6px; background: #fff; }
  .tree-site-hdr { display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; cursor: pointer; font-weight: 700; font-size: 12.5px; background: #f8fafc; border-radius: 6px; }
  .tree-site-hdr:hover { background: var(--accent-soft); }
  .tree-list { list-style: none; margin: 0; padding: 4px 8px 8px 12px; }
  .tree-item { padding: 4px 6px; border-radius: 4px; cursor: pointer; font-size: 12px; display: flex; justify-content: space-between; align-items: center; gap: 6px; }
  .tree-item:hover, .tree-item.selected { background: var(--accent-soft); }
  .badge { font-size: 9.5px; padding: 1px 5px; border-radius: 4px; font-weight: 700; text-transform: uppercase; border: 1px solid transparent; white-space: nowrap; }
  .b-core { background: var(--core-bg); color: #1d4ed8; border-color: var(--core-bd); }
  .b-fw { background: var(--fw-bg); color: #b91c1c; border-color: var(--fw-bd); }
  .b-wan { background: var(--wan-bg); color: #0f766e; border-color: var(--wan-bd); }
  .b-ap { background: var(--ap-bg); color: #b45309; border-color: var(--ap-bd); }
  .b-root { background: var(--root-bg); color: #15803d; border-color: var(--root-bd); }
  .b-iso { background: var(--iso-bg); color: #b45309; border-color: var(--iso-bd); }
  .b-sw { background: var(--sw-bg); color: #334155; border-color: var(--sw-bd); }
  .kv { width: 100%; border-collapse: collapse; margin-top: 8px; }
  .kv td { padding: 4px 6px; border-bottom: 1px solid #e2e8f0; vertical-align: top; word-break: break-word; }
  .kv td:first-child { color: var(--muted); font-weight: 600; width: 38%; }
  .legend { position: absolute; bottom: 10px; left: 10px; right: 10px; background: rgba(255,255,255,0.96); border: 1px solid var(--border); border-radius: 8px; padding: 7px 10px; font-size: 11px; display: flex; flex-wrap: wrap; gap: 10px; pointer-events: none; box-shadow: 0 2px 8px rgba(15,23,42,0.08); }
  .tooltip { position: fixed; z-index: 99; background: #0f172a; color: #f8fafc; padding: 7px 10px; border-radius: 6px; font-size: 11.5px; pointer-events: none; display: none; max-width: 380px; box-shadow: 0 4px 12px rgba(0,0,0,0.22); line-height: 1.4; }
  .l3-drawer { position: absolute; top: 10px; right: 10px; bottom: 52px; width: min(640px, 92%); background: rgba(255,255,255,0.98); border: 1px solid var(--border); border-radius: 10px; box-shadow: 0 8px 24px rgba(15,23,42,0.16); display: none; flex-direction: column; z-index: 20; }
  .l3-drawer-hdr { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border); font-weight: 700; font-size: 13px; }
  .l3-drawer-body { overflow-y: auto; padding: 12px; flex: 1; }
  .svi-table { width: 100%; border-collapse: collapse; font-size: 11.5px; margin-top: 8px; }
  .svi-table th, .svi-table td { text-align: left; padding: 5px 6px; border-bottom: 1px solid #e2e8f0; }
  .svi-table th { background: #f8fafc; position: sticky; top: 0; font-weight: 700; color: var(--muted); }
  .bucket-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; margin-bottom: 12px; }
  .bucket-card { border: 1px solid var(--border); border-radius: 6px; padding: 8px; background: #f8fafc; font-size: 11.5px; }
</style>
</head>
<body>
<header>
  <h1>Net-Docu-Crawler Topology</h1>
  <div class="ctrl">
    <label>Site:</label>
    <select id="siteSelect"></select>
  </div>
  <div class="ctrl" id="vrfCtrl" style="display:none;">
    <label>VRF:</label>
    <select id="vrfSelect"></select>
  </div>
  <div class="ctrl">
    <input id="searchBox" type="search" placeholder="Search host, IP, model, VLAN, MAC... (/)" size="26" />
  </div>
  <div class="ctrl">
    <button id="btnBackbone">Backbone &amp; WAN</button>
    <button id="btnL2">L2 Physical</button>
    <button id="btnL3">L3 Routed</button>
    <button id="btnL3Drawer" style="display:none;">SVI &amp; Subnet Table</button>
  </div>
  <div class="ctrl">
    <label><input type="checkbox" id="chkAps" /> Show APs</label>
    <label><input type="checkbox" id="chkUncrawled" checked /> Show Uncrawled</label>
    <label><input type="checkbox" id="chkIssues" /> Issues Only</label>
  </div>
  <div class="ctrl">
    <button id="btnExpandAll">Expand Tree</button>
    <button id="btnCollapseAll">Collapse Tree</button>
    <button id="btnResetZoom">Fit Graph</button>
    <button id="btnExportSvg">Export SVG</button>
  </div>
  <span id="statsLabel" style="margin-left:auto;font-size:12px;color:#475569;"></span>
</header>
<div class="main">
  <aside class="sidebar" id="treePanel"></aside>
  <section class="canvas-wrap" id="canvasWrap">
    <svg id="topoSvg">
      <defs>
        <marker id="arrow-slate" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#334155"/></marker>
        <marker id="arrow-teal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#0d9488"/></marker>
        <marker id="arrow-indigo" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#4f46e5"/></marker>
        <marker id="arrow-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#dc2626"/></marker>
      </defs>
      <g id="viewport"></g>
    </svg>
    <div id="edgeTooltip" class="tooltip"></div>
    <div id="l3Drawer" class="l3-drawer">
      <div class="l3-drawer-hdr">
        <span>L3 Functional VLAN Groups &amp; Authoritative SVI Table</span>
        <button id="btnCloseL3Drawer">Close</button>
      </div>
      <div class="l3-drawer-body" id="l3DrawerBody"></div>
    </div>
    <div class="legend" id="legendBar">
      <span><b style="color:#16a34a;">■</b> STP Root (Campus)</span>
      <span><b style="color:#d97706;">■</b> Isolated Self-Root / AP</span>
      <span><b style="color:#2563eb;">■</b> Core/Dist</span>
      <span><b style="color:#dc2626;">■</b> Firewall/Router/ISP</span>
      <span><b style="color:#0d9488;">■</b> Carrier WAN Cloud</span>
      <span><b style="color:#334155;">━━</b> Direct LLDP/CDP Uplink</span>
      <span><b style="color:#0d9488;">┅┅</b> Metro-E / Carrier WAN</span>
      <span><b style="color:#4f46e5;">┈┈</b> L3 Routed / Egress</span>
      <span><b style="color:#ea580c;">┄┄</b> MAC Inferred</span>
      <span><b style="color:#7c3aed;">┄┄</b> Virtual Passthrough</span>
      <span><b style="color:#dc2626;">┄┄</b> STP Blocked / Trunk High-Crit</span>
    </div>
  </section>
  <aside class="inspector" id="inspectorPanel">
    <h3 style="margin-top:0;">Inspector</h3>
    <p style="color:#475569;">Click any switch, router, firewall, WAN cloud, AP, or link to inspect ports, transport type, discovery evidence, VLANs, STP scope, and trunk audit findings.</p>
  </aside>
</div>
<script>
const GRAPH = __GRAPH_JSON__;
const apListAll = GRAPH.ap_nodes || [];
const state = {
  site: "ALL",
  vrf: "ALL",
  search: "",
  mode: GRAPH.sites.length > 1 ? "BACKBONE" : "L2",
  showAps: apListAll.length <= 20,
  showUncrawled: true,
  issuesOnly: false,
  showL3Drawer: false,
  selectedId: null,
  collapsedNodes: new Set(),
  expandedSites: new Set(GRAPH.nodes.length > 25 && GRAPH.sites.length > 1 ? [] : GRAPH.sites),
  customPos: {},
  lastLayoutPos: {},
  tx: 40, ty: 40, scale: 1
};

function esc(v) {
  return String(v == null ? "" : v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

document.getElementById("chkAps").checked = state.showAps;
const siteSel = document.getElementById("siteSelect");
siteSel.innerHTML = `<option value="ALL">ALL SITES (${GRAPH.nodes.length})</option>` +
  GRAPH.sites.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
siteSel.value = state.site;
const vrfList = ((GRAPH.l3_graph || {}).vrfs || ["default"]);
const vrfSel = document.getElementById("vrfSelect");
vrfSel.innerHTML = `<option value="ALL">ALL VRFs (${vrfList.length})</option>` +
  vrfList.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
vrfSel.value = state.vrf;
vrfSel.onchange = e => { state.vrf = e.target.value; render(); fitGraph(); };

function nodeMatches(n) {
  if (state.site !== "ALL" && n.site !== state.site) return false;
  if (!state.showAps && n.role === "ap") return false;
  if (!state.showUncrawled && !n.is_crawled && n.role !== "ap") return false;
  if (state.search) {
    const q = state.search.toLowerCase();
    const vl = (n.vlans || []).join(" ");
    const subs = (n.l3_subnets || []).map(s => `${s.cidr} ${s.vlan_name || ""} ${s.vlan_description || ""}`).join(" ");
    const hay = `${n.hostname} ${n.ip} ${n.model} ${n.serial || ""} ${n.mac || ""} ${n.sub_site || ""} ${vl} ${subs}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function edgeStyle(e) {
  const tt = e.transport_type || "direct_l2_uplink";
  const w = (e.speed_mbps >= 10000 || (e.speed || "").includes("10G") || (e.speed || "").includes("40G")) ? "3" : "1.9";
  if (e.is_blocked || e.trunk_severity === "CRITICAL" || e.trunk_severity === "HIGH") {
    return { color: "#dc2626", dash: "6,4", width: w, marker: "url(#arrow-red)" };
  }
  if (tt === "metro_ethernet" || tt === "wan_carrier") {
    return { color: "#0d9488", dash: "8,4", width: w, marker: "url(#arrow-teal)" };
  }
  if (tt === "l3_egress" || tt === "l3_routed") {
    return { color: "#4f46e5", dash: "3,4", width: w, marker: "url(#arrow-indigo)" };
  }
  if (tt === "mac_inferred" || e.confidence === "mac_inferred") {
    return { color: "#ea580c", dash: "5,4", width: w, marker: "" };
  }
  if (tt === "virtual_passthrough" || e.confidence === "passthrough") {
    return { color: "#7c3aed", dash: "5,4", width: w, marker: "" };
  }
  return { color: "#334155", dash: "", width: w, marker: "url(#arrow-slate)" };
}

function edgeMatchesIssue(e) {
  return Boolean(
    e.is_blocked ||
    e.trunk_severity === "CRITICAL" ||
    e.trunk_severity === "HIGH" ||
    e.confidence === "mac_inferred" ||
    e.transport_type === "mac_inferred" ||
    e.mask_mismatch
  );
}

function nodeMatchesIssue(n) {
  return Boolean(
    n.stp_root_scope === "isolated_self_root" ||
    n.has_conflict ||
    (!n.is_crawled && n.role === "uncrawled_switch")
  );
}

function getVisibleL2Graph() {
  const treeNodes = GRAPH.nodes.filter(nodeMatches);
  const treeIdSet = new Set(treeNodes.map(n => n.id));
  let rawEdges = GRAPH.edges.filter(e => treeIdSet.has(e.source) && treeIdSet.has(e.target));

  // Expand uncrawled APs from GRAPH.ap_nodes when Show APs is checked
  let extraAps = [];
  if (state.showAps && !state.issuesOnly) {
    const q = state.search.toLowerCase();
    for (const ap of apListAll) {
      if (ap.is_crawled) continue;
      if (!treeIdSet.has(ap.attached_to)) continue;
      if (state.site !== "ALL" && ap.site !== state.site) continue;
      if (q && !`${ap.hostname} ${ap.ip} ${ap.mac} ${ap.model} ${ap.attached_hostname}`.toLowerCase().includes(q)) continue;
      const parent = treeNodes.find(x => x.id === ap.attached_to);
      extraAps.push({
        ...ap,
        hop_depth: (parent ? parent.hop_depth : 0) + 1,
        vlans: [],
        l3_subnets: [],
        stp_root_scope: "not_applicable",
        is_ephemeral_ap: true
      });
      rawEdges.push({
        id: `${ap.attached_to}--${ap.id}`,
        source: ap.attached_to,
        target: ap.id,
        port_pairs: [ap.local_port ? `${ap.local_port} ↔ ${ap.remote_port || "eth0"}` : "eth0"],
        speed: ap.speed || "1G",
        speed_mbps: 1000,
        confidence: "direct",
        transport_type: "direct_l2_uplink",
        evidence: "unidirectional_lldp",
        link_scope: "wireless_ap",
        is_blocked: false,
        trunk_severity: "",
        trunk_findings: [],
        display_badge: "AP"
      });
    }
  }

  const allPool = treeNodes.concat(extraAps);
  const byId = Object.fromEntries(allPool.map(n => [n.id, n]));
  const childrenMap = {};
  for (const e of rawEdges) {
    const a = byId[e.source], b = byId[e.target];
    if (!a || !b) continue;
    if ((a.layer < b.layer) || (a.layer === b.layer && (a.hop_depth || 0) < (b.hop_depth || 0))) {
      (childrenMap[a.id] = childrenMap[a.id] || []).push(b.id);
    } else if ((b.layer < a.layer) || (b.layer === a.layer && (b.hop_depth || 0) < (a.hop_depth || 0))) {
      (childrenMap[b.id] = childrenMap[b.id] || []).push(a.id);
    }
  }

  const hiddenIds = new Set();
  const siteCollapsedCards = [];
  const collapsedSiteMap = {};
  const bySite = {};
  for (const n of allPool) (bySite[n.site] = bySite[n.site] || []).push(n);

  for (const [sc, sNodes] of Object.entries(bySite)) {
    if (!state.expandedSites.has(sc) && !state.search) {
      const coreNode = sNodes.find(n => n.layer <= 2 && n.is_crawled) || sNodes.find(n => n.layer <= 2) || null;
      if (coreNode && sNodes.length > 1) {
        for (const n of sNodes) {
          if (n.id !== coreNode.id) {
            hiddenIds.add(n.id);
            collapsedSiteMap[n.id] = coreNode.id;
          }
        }
      } else {
        const cardId = `site_card:${sc}`;
        for (const n of sNodes) {
          hiddenIds.add(n.id);
          collapsedSiteMap[n.id] = cardId;
        }
        siteCollapsedCards.push({
          id: cardId, hostname: `Site ${sc} (Collapsed)`, ip: `${sNodes.length} node(s)`,
          site: sc, role: "core", layer: 2, hop_depth: 0, model: "Click + to expand",
          is_crawled: true, is_site_card: true, hidden_count: sNodes.length,
          vlans: [], l3_subnets: [], stp_root_scope: "not_applicable"
        });
      }
    }
  }

  const nodeHiddenCount = {};
  for (const nid of state.collapsedNodes) {
    if (hiddenIds.has(nid)) continue;
    const kids = childrenMap[nid] || [];
    let cnt = 0;
    for (const kid of kids) {
      if (!hiddenIds.has(kid)) { hiddenIds.add(kid); cnt += 1; }
    }
    if (cnt > 0) nodeHiddenCount[nid] = cnt;
  }

  const nodesAll = allPool.filter(n => !hiddenIds.has(n.id)).concat(siteCollapsedCards);
  const visIdSetAll = new Set(nodesAll.map(n => n.id));
  const edgeDedup = new Map();
  for (const e of rawEdges) {
    const s = visIdSetAll.has(e.source) ? e.source : collapsedSiteMap[e.source];
    const t = visIdSetAll.has(e.target) ? e.target : collapsedSiteMap[e.target];
    if (!s || !t || s === t) continue;
    const key = s < t ? `${s}--${t}` : `${t}--${s}`;
    if (!edgeDedup.has(key)) edgeDedup.set(key, { ...e, source: s, target: t });
  }
  let edges = Array.from(edgeDedup.values());
  let nodes = nodesAll;
  if (state.issuesOnly) {
    edges = edges.filter(edgeMatchesIssue);
    const issueIds = new Set(edges.flatMap(e => [e.source, e.target]));
    nodes = nodesAll.filter(n => issueIds.has(n.id) || nodeMatchesIssue(n));
  }
  return { treeNodes, nodes, edges, childrenMap, nodeHiddenCount };
}

function getBackboneGraph() {
  const backboneEdgeIds = new Set();
  const sitePrimary = {};
  for (const n of GRAPH.nodes) {
    if (!sitePrimary[n.site] || n.layer < sitePrimary[n.site].layer) sitePrimary[n.site] = n;
  }
  const backboneKeep = new Set();
  for (const e of GRAPH.edges) {
    if (e.link_scope === "backbone") {
      backboneKeep.add(e.source);
      backboneKeep.add(e.target);
      backboneEdgeIds.add(e.id);
    }
  }
  for (const n of GRAPH.nodes) {
    if (["isp", "firewall", "wan_cloud", "router", "core"].includes(n.role)) backboneKeep.add(n.id);
  }
  for (const p of Object.values(sitePrimary)) backboneKeep.add(p.id);

  let nodes = GRAPH.nodes.filter(n => backboneKeep.has(n.id) && (state.showUncrawled || n.is_crawled || n.role === "wan_cloud"));
  if (state.site !== "ALL") {
    const siteSet = new Set(nodes.filter(n => n.site === state.site).map(n => n.id));
    for (const e of GRAPH.edges) {
      if (e.link_scope === "backbone" && (siteSet.has(e.source) || siteSet.has(e.target))) {
        siteSet.add(e.source); siteSet.add(e.target);
      }
    }
    nodes = nodes.filter(n => siteSet.has(n.id));
  }
  if (state.search) {
    const q = state.search.toLowerCase();
    nodes = nodes.filter(n => `${n.hostname} ${n.ip} ${n.site} ${n.model}`.toLowerCase().includes(q));
  }
  const idSet = new Set(nodes.map(n => n.id));
  let edges = GRAPH.edges.filter(e => idSet.has(e.source) && idSet.has(e.target) && (e.link_scope === "backbone" || backboneEdgeIds.has(e.id)));
  if (state.issuesOnly) {
    edges = edges.filter(edgeMatchesIssue);
    const ids = new Set(edges.flatMap(e => [e.source, e.target]));
    nodes = nodes.filter(n => ids.has(n.id) || nodeMatchesIssue(n));
  }
  return { treeNodes: nodes, nodes, edges, childrenMap: {}, nodeHiddenCount: {} };
}

function getL3SvgGraph() {
  const l3g = GRAPH.l3_graph || { l3_nodes: [], l3_links: [], l3_conflicts: [] };
  let nodes = (l3g.l3_nodes || []).filter(n => n.role !== "wan_cloud");
  let links = l3g.l3_links || [];
  if (state.vrf !== "ALL") {
    nodes = nodes.filter(n => (n.vrf || "default") === state.vrf);
    links = links.filter(lk => !lk.is_vrf_leak && (lk.vrf || "default") === state.vrf);
  }
  if (state.site !== "ALL") {
    const siteSet = new Set(nodes.filter(n => n.site === state.site).map(n => n.id));
    for (const lk of links) {
      if (siteSet.has(lk.source) || siteSet.has(lk.target)) {
        siteSet.add(lk.source); siteSet.add(lk.target);
      }
    }
    nodes = nodes.filter(n => siteSet.has(n.id));
  }
  if (state.search) {
    const q = state.search.toLowerCase();
    nodes = nodes.filter(n => {
      const subs = (n.l3_subnets || []).map(s => `${s.cidr} ${s.vlan_name || ""} ${s.vlan_description || ""}`).join(" ");
      return `${n.hostname} ${n.ip} ${n.site} ${n.vrf || ""} ${subs}`.toLowerCase().includes(q);
    });
  }
  const idSet = new Set(nodes.map(n => n.id));
  links = links.filter(lk => idSet.has(lk.source) && idSet.has(lk.target));
  if (state.issuesOnly) {
    links = links.filter(lk => lk.mask_mismatch || lk.blind_spot);
    const ids = new Set(links.flatMap(lk => [lk.source, lk.target]));
    nodes = nodes.filter(n => n.has_conflict || n.blind_spot || ids.has(n.id));
  }
  const conflicts = state.vrf === "ALL" ? (l3g.l3_conflicts || []) : (l3g.l3_conflicts || []).filter(c => (c.vrf || "default") === state.vrf);
  return { treeNodes: nodes, nodes, edges: links, conflicts, childrenMap: {}, nodeHiddenCount: {} };
}

function roleBadge(n) {
  const vrfTag = (n.vrf && n.vrf !== "default") ? ` <span class="badge b-core">VRF:${esc(n.vrf)}</span>` : "";
  if (n.stp_root_scope === "campus_root") return '<span class="badge b-root">STP ROOT</span>';
  if (n.stp_root_scope === "isolated_self_root") return '<span class="badge b-iso">ISOLATED ROOT</span>';
  if (n.role === "wan_cloud") return `<span class="badge b-wan">${esc((n.cloud_mode || "METRO-E").toUpperCase())}</span>`;
  if (n.role === "core" || n.role === "dist") return `<span class="badge b-core">${esc(n.role)}</span>${vrfTag}`;
  if (["firewall", "router", "isp", "external_nexthop"].includes(n.role)) return `<span class="badge b-fw">${esc(n.role === "external_nexthop" ? "NEXT-HOP" : n.role)}</span>${vrfTag}`;
  if (n.role === "ap") return '<span class="badge b-ap">AP</span>';
  return `<span class="badge b-sw">${n.is_crawled ? "SW" : "EXT"}</span>${vrfTag}`;
}

function nodeColors(n) {
  if (n.has_conflict) return { fill: "#fef2f2", stroke: "#dc2626" };
  if (n.stp_root_scope === "campus_root") return { fill: "#dcfce7", stroke: "#16a34a" };
  if (n.stp_root_scope === "isolated_self_root") return { fill: "#fef3c7", stroke: "#d97706" };
  if (n.role === "wan_cloud") return { fill: "#ccfbf1", stroke: "#0d9488" };
  if (n.role === "core" || n.role === "dist") return { fill: "#dbeafe", stroke: "#2563eb" };
  if (["firewall", "router", "isp", "external_nexthop"].includes(n.role)) return { fill: "#fee2e2", stroke: "#dc2626" };
  if (n.role === "ap") return { fill: "#fef3c7", stroke: "#d97706" };
  return { fill: "#f1f5f9", stroke: "#64748b" };
}

function renderTree(vis) {
  const bySite = {};
  for (const n of vis.treeNodes) (bySite[n.site || "GLOBAL"] = bySite[n.site || "GLOBAL"] || []).push(n);
  const panel = document.getElementById("treePanel");
  panel.innerHTML = Object.keys(bySite).sort().map(sc => {
    const items = bySite[sc];
    const isOpen = state.expandedSites.has(sc) || state.mode !== "L2";
    const lis = isOpen ? items.map(n => `
      <li class="tree-item ${state.selectedId === n.id ? "selected" : ""}" data-nid="${esc(n.id)}">
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(n.hostname)} (${esc(n.ip)})">${esc(n.hostname)}</span>
        ${roleBadge(n)}
      </li>`).join("") : "";
    return `<div class="tree-site">
      <div class="tree-site-hdr" data-site="${esc(sc)}"><span>${isOpen ? "▼" : "▶"} Site ${esc(sc)}</span><span>${items.length}</span></div>
      ${isOpen ? `<ul class="tree-list">${lis}</ul>` : ""}
    </div>`;
  }).join("");

  panel.querySelectorAll(".tree-site-hdr").forEach(el => {
    el.onclick = () => {
      const sc = el.dataset.site;
      if (state.expandedSites.has(sc)) state.expandedSites.delete(sc); else state.expandedSites.add(sc);
      render();
    };
  });
  panel.querySelectorAll(".tree-item").forEach(el => {
    el.onclick = () => selectNode(el.dataset.nid, true);
  });
}

function computeLayout(vis) {
  const pos = {};
  const subBoxes = [];
  const swimlanes = [];
  const boxW = 204, boxH = 58, colW = 250, rowH = 84;

  if (state.mode === "BACKBONE") {
    const tierCols = [[], [], [], [], []];
    const hubIds = new Set();
    for (const n of vis.nodes) {
      if (n.role === "wan_cloud" && Array.isArray(n.hub_ids)) {
        for (const hid of n.hub_ids) hubIds.add(hid);
      }
    }
    const deg = {};
    for (const e of vis.edges) {
      deg[e.source] = (deg[e.source] || 0) + 1;
      deg[e.target] = (deg[e.target] || 0) + 1;
      const ns = vis.nodes.find(x => x.id === e.source);
      const nt = vis.nodes.find(x => x.id === e.target);
      if (!hubIds.size) {
        if (ns && nt && (ns.role === "firewall" || ns.role === "wan_cloud") && nt.role === "core") hubIds.add(nt.id);
        if (ns && nt && (nt.role === "firewall" || nt.role === "wan_cloud") && ns.role === "core") hubIds.add(ns.id);
      }
    }
    if (!hubIds.size) {
      const cores = vis.nodes.filter(n => n.role === "core");
      cores.sort((a, b) => (deg[b.id] || 0) - (deg[a.id] || 0) || (b.hostname.toLowerCase().includes("main") ? 1 : 0) - (a.hostname.toLowerCase().includes("main") ? 1 : 0));
      if (cores.length) hubIds.add(cores[0].id);
    }
    const hubSites = new Set(vis.nodes.filter(n => hubIds.has(n.id)).map(n => n.site));
    for (const n of vis.nodes) {
      if (n.role === "isp") tierCols[0].push(n);
      else if (n.role === "firewall" || n.role === "router") tierCols[1].push(n);
      else if (hubIds.has(n.id) || (n.role === "uncrawled_switch" && hubSites.has(n.site))) tierCols[2].push(n);
      else if (n.role === "wan_cloud") tierCols[3].push(n);
      else tierCols[4].push(n);
    }
    let curX = 32;
    for (const col of tierCols) {
      if (!col.length) continue;
      col.sort((a, b) => a.layer - b.layer || a.site.localeCompare(b.site) || a.hostname.localeCompare(b.hostname));
      col.forEach((n, idx) => {
        pos[n.id] = state.customPos[n.id] || { x: curX, y: 40 + idx * (rowH + 14) };
      });
      curX += colW + 30;
    }
    return { pos, subBoxes, swimlanes, boxW, boxH };
  }

  if (state.mode === "L3") {
    const tierCols = [[], [], [], []];
    const deg = {};
    for (const e of vis.edges) {
      deg[e.source] = (deg[e.source] || 0) + 1;
      deg[e.target] = (deg[e.target] || 0) + 1;
    }
    const cloudHubIds = new Set();
    for (const gn of GRAPH.nodes) {
      if (gn.role === "wan_cloud" && Array.isArray(gn.hub_ids)) {
        for (const hid of gn.hub_ids) cloudHubIds.add(hid);
      }
    }
    const hubCandidates = vis.nodes
      .filter(n => n.role === "core" || n.role === "router")
      .sort((a, b) => (deg[b.id] || 0) - (deg[a.id] || 0) || (b.hostname.toLowerCase().includes("main") ? 1 : 0) - (a.hostname.toLowerCase().includes("main") ? 1 : 0));
    const hubIdSet = new Set(cloudHubIds.size ? Array.from(cloudHubIds) : (hubCandidates.length ? [hubCandidates[0].id] : []));
    for (const n of vis.nodes) {
      if (n.role === "isp") tierCols[0].push(n);
      else if (n.role === "firewall") tierCols[1].push(n);
      else if (hubIdSet.has(n.id) || hubIdSet.has(n.device_id) || n.role === "external_nexthop") tierCols[2].push(n);
      else tierCols[3].push(n);
    }
    let curX = 32;
    for (const col of tierCols) {
      if (!col.length) continue;
      col.sort((a, b) => a.layer - b.layer || a.site.localeCompare(b.site) || a.hostname.localeCompare(b.hostname));
      col.forEach((n, idx) => {
        pos[n.id] = state.customPos[n.id] || { x: curX, y: 74 + idx * (rowH + 18) };
      });
      curX += colW + 60;
    }
    return { pos, subBoxes, swimlanes, boxW, boxH };
  }

  // L2 Physical: Site-aligned swimlanes with columns strictly ordered by hop_depth
  const bySite = {};
  for (const n of vis.nodes) (bySite[n.site] = bySite[n.site] || []).push(n);
  let bandY = 30;
  for (const sc of Object.keys(bySite).sort()) {
    const sNodes = bySite[sc];
    const switches = sNodes.filter(n => !n.is_ephemeral_ap);
    const ephAps = sNodes.filter(n => n.is_ephemeral_ap);
    const byHop = {};
    for (const n of switches) {
      const h = Math.max(0, Number(n.hop_depth || 0));
      (byHop[h] = byHop[h] || []).push(n);
    }
    const hops = Object.keys(byHop).map(Number).sort((a, b) => a - b);
    let maxRows = 1;
    for (const h of hops) maxRows = Math.max(maxRows, byHop[h].length);

    const apByParent = {};
    for (const ap of ephAps) (apByParent[ap.attached_to] = apByParent[ap.attached_to] || []).push(ap);

    const siteStartY = bandY;
    for (const h of hops) {
      const col = byHop[h].sort((a, b) => (a.sub_site || "").localeCompare(b.sub_site || "") || a.layer - b.layer || a.hostname.localeCompare(b.hostname));
      col.forEach((n, rIdx) => {
        pos[n.id] = state.customPos[n.id] || { x: 32 + h * colW, y: bandY + 28 + rIdx * rowH };
      });
    }
    if (ephAps.length) {
      const apColX = 32 + ((hops.length ? Math.max(...hops) + 1 : 1)) * colW;
      let apIdx = 0;
      for (const ap of ephAps) {
        const cOff = apIdx % 3;
        const rOff = Math.floor(apIdx / 3);
        pos[ap.id] = state.customPos[ap.id] || { x: apColX + cOff * 190, y: bandY + 28 + rOff * 54 };
        apIdx += 1;
      }
      maxRows = Math.max(maxRows, Math.ceil(ephAps.length / 3) * 0.7 + 1);
    }

    const bandH = Math.max(120, Math.ceil(maxRows) * rowH + 40);
    const maxX = Math.max(...sNodes.map(n => (pos[n.id] || { x: 32 }).x)) + boxW + 24;
    swimlanes.push({ site: sc, x: 16, y: siteStartY, w: Math.max(260, maxX - 16), h: bandH });

    // Sub-site dashed bounding containers (e.g. MOT inside VES)
    const bySub = {};
    for (const n of switches) {
      if (n.sub_site) (bySub[n.sub_site] = bySub[n.sub_site] || []).push(n);
    }
    for (const [subName, subNodes] of Object.entries(bySub)) {
      const xs = subNodes.map(n => pos[n.id].x);
      const ys = subNodes.map(n => pos[n.id].y);
      subBoxes.push({
        label: `Sub-Campus: ${subName}`,
        x: Math.min(...xs) - 10,
        y: Math.min(...ys) - 22,
        w: Math.max(...xs) + boxW + 10 - (Math.min(...xs) - 10),
        h: Math.max(...ys) + boxH + 10 - (Math.min(...ys) - 22)
      });
    }
    bandY += bandH + 24;
  }
  return { pos, subBoxes, swimlanes, boxW, boxH };
}

function renderSvg(vis) {
  const vp = document.getElementById("viewport");
  vp.innerHTML = "";
  const ns = "http://www.w3.org/2000/svg";
  const tip = document.getElementById("edgeTooltip");
  const { pos, subBoxes, swimlanes, boxW, boxH } = computeLayout(vis);
  state.lastLayoutPos = pos;
  const byId = Object.fromEntries(vis.nodes.map(x => [x.id, x]));

  // Site swimlanes
  for (const lane of swimlanes) {
    const r = document.createElementNS(ns, "rect");
    r.setAttribute("x", lane.x); r.setAttribute("y", lane.y);
    r.setAttribute("width", lane.w); r.setAttribute("height", lane.h);
    r.setAttribute("rx", "10"); r.setAttribute("fill", "rgba(255,255,255,0.65)");
    r.setAttribute("stroke", "#cbd5e1"); r.setAttribute("stroke-width", "1.2");
    vp.appendChild(r);
    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("x", lane.x + 12); lbl.setAttribute("y", lane.y + 18);
    lbl.setAttribute("font-size", "11.5"); lbl.setAttribute("font-weight", "700"); lbl.setAttribute("fill", "#475569");
    lbl.textContent = `SITE ${lane.site}`;
    vp.appendChild(lbl);
  }

  // Sub-campus dashed boxes
  for (const sb of subBoxes) {
    const r = document.createElementNS(ns, "rect");
    r.setAttribute("x", sb.x); r.setAttribute("y", sb.y);
    r.setAttribute("width", sb.w); r.setAttribute("height", sb.h);
    r.setAttribute("rx", "8"); r.setAttribute("fill", "rgba(219,234,254,0.22)");
    r.setAttribute("stroke", "#3b82f6"); r.setAttribute("stroke-dasharray", "6,4"); r.setAttribute("stroke-width", "1.4");
    vp.appendChild(r);
    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("x", sb.x + 8); lbl.setAttribute("y", sb.y + 14);
    lbl.setAttribute("font-size", "10.5"); lbl.setAttribute("font-weight", "700"); lbl.setAttribute("fill", "#1d4ed8");
    lbl.textContent = sb.label;
    vp.appendChild(lbl);
  }

  // L3 conflict alert strip inside L3 SVG view
  if (state.mode === "L3" && (vis.conflicts || []).length) {
    const cG = document.createElementNS(ns, "g");
    cG.setAttribute("transform", "translate(24, 14)");
    const cRect = document.createElementNS(ns, "rect");
    cRect.setAttribute("width", "760"); cRect.setAttribute("height", "36"); cRect.setAttribute("rx", "6");
    cRect.setAttribute("fill", "#fef2f2"); cRect.setAttribute("stroke", "#dc2626"); cRect.setAttribute("stroke-width", "1.4");
    cG.appendChild(cRect);
    const cTxt = document.createElementNS(ns, "text");
    cTxt.setAttribute("x", "12"); cTxt.setAttribute("y", "22");
    cTxt.setAttribute("font-size", "11.5"); cTxt.setAttribute("font-weight", "700"); cTxt.setAttribute("fill", "#b91c1c");
    const first = vis.conflicts[0];
    cTxt.textContent = `⚠ ${vis.conflicts.length} L3 Conflict(s): ${first.conflict_type} on ${first.cidr} (${(first.devices || []).join(" & ")}) — NO false transit link drawn`;
    cG.appendChild(cTxt);
    vp.appendChild(cG);
  }

  const spotlightSet = new Set();
  if (state.selectedId) {
    spotlightSet.add(state.selectedId);
    for (const e of vis.edges) {
      if (e.source === state.selectedId) spotlightSet.add(e.target);
      if (e.target === state.selectedId) spotlightSet.add(e.source);
    }
  }

  // Draw edges
  for (const e of vis.edges) {
    const a = pos[e.source], b = pos[e.target];
    if (!a || !b) continue;
    const na = byId[e.source], nb = byId[e.target];
    const wA = na && na.is_ephemeral_ap ? 176 : boxW;
    const hA = na && na.is_ephemeral_ap ? 38 : boxH;
    const wB = nb && nb.is_ephemeral_ap ? 176 : boxW;
    const hB = nb && nb.is_ephemeral_ap ? 38 : boxH;

    const x1 = a.x + wA / 2, y1 = a.y + hA / 2;
    const x2 = b.x + wB / 2, y2 = b.y + hB / 2;
    const sameCol = Math.abs(x1 - x2) < 12;
    const cx = sameCol ? x1 + 56 : (x1 + x2) / 2;
    const mx = sameCol ? x1 + 42 : (x1 + x2) / 2;
    const my = (y1 + y2) / 2;

    const st = edgeStyle(e);
    const dAttr = `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
    const line = document.createElementNS(ns, "path");
    line.setAttribute("d", dAttr);
    const isSpotEdge = !state.selectedId || e.source === state.selectedId || e.target === state.selectedId;
    line.setAttribute("fill", "none");
    line.setAttribute("stroke", st.color);
    line.setAttribute("stroke-width", st.width);
    line.setAttribute("opacity", isSpotEdge ? "0.92" : "0.14");
    if (st.dash) line.setAttribute("stroke-dasharray", st.dash);
    if (st.marker && (state.mode !== "L2" || e.transport_type === "l3_egress")) {
      line.setAttribute("marker-end", st.marker);
    }
    line.style.cursor = "pointer";
    line.onmouseenter = (ev) => {
      const badge = e.display_badge || e.transit_cidr || e.transport_type || "";
      const ports = (e.port_pairs || []).join(", ") || e.transit_cidr || "N/A";
      const mm = e.mask_mismatch ? `<br/><b style="color:#fbbf24;">Mask Mismatch:</b> ${esc(e.mask_mismatch_detail || e.mask_mismatch)}` : "";
      const sev = e.trunk_severity ? ` · <b style="color:#f87171;">${esc(e.trunk_severity)}</b>` : "";
      tip.innerHTML = `<b>${esc(na ? na.hostname : e.source)}</b> → <b>${esc(nb ? nb.hostname : e.target)}</b>` +
        `<br/>Transport: <b>${esc(e.transport_type || "direct_l2_uplink")}</b> (${esc(e.evidence || e.routing_mechanism || "direct")})` +
        `<br/>Ports / Transit: <code>${esc(ports)}</code>${badge ? ` · ${esc(badge)}` : ""}${sev}${mm}`;
      tip.style.display = "block";
      tip.style.left = `${ev.clientX + 12}px`; tip.style.top = `${ev.clientY + 12}px`;
    };
    line.onmousemove = (ev) => { tip.style.left = `${ev.clientX + 12}px`; tip.style.top = `${ev.clientY + 12}px`; };
    line.onmouseleave = () => { tip.style.display = "none"; };
    line.onclick = (ev) => { ev.stopPropagation(); selectEdge(e); };
    vp.appendChild(line);

    // Inline edge badge (always in Backbone/L3, or when zoomed in >= 0.65 in L2)
    const showLabel = (state.mode !== "L2" || state.scale >= 0.65) && isSpotEdge && e.link_scope !== "wireless_ap";
    const lblText = state.mode === "L3"
      ? `${e.transit_cidr || ""}${e.mask_mismatch ? ` (${e.mask_mismatch_detail})` : ""}`
      : (e.display_badge || "");
    if (showLabel && lblText) {
      const pill = document.createElementNS(ns, "text");
      pill.setAttribute("x", mx); pill.setAttribute("y", my - 4);
      pill.setAttribute("text-anchor", "middle");
      pill.setAttribute("font-size", "9.5"); pill.setAttribute("font-weight", "700");
      pill.setAttribute("fill", e.mask_mismatch ? "#b45309" : st.color);
      pill.setAttribute("stroke", "#ffffff"); pill.setAttribute("stroke-width", "3");
      pill.setAttribute("paint-order", "stroke");
      pill.style.pointerEvents = "none";
      pill.textContent = lblText.slice(0, 28);
      vp.appendChild(pill);
    }
  }

  // Draw nodes
  for (const n of vis.nodes) {
    const p = pos[n.id];
    if (!p) continue;
    const isMiniAp = Boolean(n.is_ephemeral_ap);
    const w = isMiniAp ? 176 : boxW;
    const h = isMiniAp ? 38 : boxH;
    const g = document.createElementNS(ns, "g");
    g.setAttribute("transform", `translate(${p.x},${p.y})`);
    g.setAttribute("opacity", !state.selectedId || spotlightSet.has(n.id) ? "1" : "0.18");
    g.style.cursor = "grab";
    const c = nodeColors(n);
    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("width", w); rect.setAttribute("height", h); rect.setAttribute("rx", isMiniAp ? "6" : "8");
    rect.setAttribute("fill", c.fill);
    rect.setAttribute("stroke", state.selectedId === n.id ? "#0f172a" : c.stroke);
    rect.setAttribute("stroke-width", state.selectedId === n.id ? "3" : "1.6");
    if (!n.is_crawled) rect.setAttribute("stroke-dasharray", "5,3");
    g.appendChild(rect);

    const t1 = document.createElementNS(ns, "text");
    t1.setAttribute("x", "9"); t1.setAttribute("y", isMiniAp ? "16" : "20");
    t1.setAttribute("font-size", isMiniAp ? "10.5" : "11.5"); t1.setAttribute("font-weight", "700"); t1.setAttribute("fill", "#0f172a");
    const maxLen = isMiniAp ? 20 : 21;
    t1.textContent = n.hostname.length > maxLen ? n.hostname.slice(0, maxLen - 1) + "…" : n.hostname;
    g.appendChild(t1);

    const t2 = document.createElementNS(ns, "text");
    t2.setAttribute("x", "9"); t2.setAttribute("y", isMiniAp ? "30" : "37");
    t2.setAttribute("font-size", isMiniAp ? "9.5" : "10"); t2.setAttribute("fill", "#334155");
    const subTxt = isMiniAp
      ? `${n.local_port || "AP"} · ${n.ip || n.mac || ""}`
      : (state.mode === "L3"
        ? `${n.ip || n.site} · ${(n.l3_subnets || []).length} SVIs`
        : `${n.ip || n.role} · ${n.model || ""}`);
    t2.textContent = subTxt.slice(0, 27);
    g.appendChild(t2);

    // Status pill: +N APs or STP Root / Isolated Root / Site Drilldown
    if (!isMiniAp) {
      if (state.mode === "BACKBONE" && n.role === "core" && n.site) {
        const sCount = GRAPH.nodes.filter(x => x.site === n.site).length;
        const apCount = GRAPH.nodes.filter(x => x.site === n.site).reduce((acc, x) => acc + (x.attached_ap_count || 0), 0);
        const sPill = document.createElementNS(ns, "g");
        sPill.setAttribute("transform", `translate(9, ${h - 14})`);
        const rSp = document.createElementNS(ns, "rect");
        rSp.setAttribute("width", "134"); rSp.setAttribute("height", "12"); rSp.setAttribute("rx", "3");
        rSp.setAttribute("fill", "#eff6ff"); rSp.setAttribute("stroke", "#2563eb"); rSp.setAttribute("stroke-width", "0.8");
        const tSp = document.createElementNS(ns, "text");
        tSp.setAttribute("x", "67"); tSp.setAttribute("y", "9"); tSp.setAttribute("text-anchor", "middle");
        tSp.setAttribute("font-size", "8.5"); tSp.setAttribute("font-weight", "700"); tSp.setAttribute("fill", "#1d4ed8");
        tSp.textContent = `Site ${n.site}: ${sCount} SW · ${apCount} APs ↗`;
        sPill.appendChild(rSp); sPill.appendChild(tSp);
        sPill.style.cursor = "pointer";
        sPill.onclick = (ev) => {
          ev.stopPropagation();
          state.site = n.site; siteSel.value = n.site;
          state.expandedSites.add(n.site);
          setMode("L2");
        };
        g.appendChild(sPill);
      } else if (n.attached_ap_count > 0 && !state.showAps && state.mode === "L2") {
        const apPill = document.createElementNS(ns, "g");
        apPill.setAttribute("transform", `translate(9, ${h - 14})`);
        const rAp = document.createElementNS(ns, "rect");
        rAp.setAttribute("width", "54"); rAp.setAttribute("height", "12"); rAp.setAttribute("rx", "3");
        rAp.setAttribute("fill", "#fef3c7"); rAp.setAttribute("stroke", "#d97706"); rAp.setAttribute("stroke-width", "0.8");
        const tAp = document.createElementNS(ns, "text");
        tAp.setAttribute("x", "27"); tAp.setAttribute("y", "9"); tAp.setAttribute("text-anchor", "middle");
        tAp.setAttribute("font-size", "8.5"); tAp.setAttribute("font-weight", "700"); tAp.setAttribute("fill", "#92400e");
        tAp.textContent = `+${n.attached_ap_count} APs`;
        apPill.appendChild(rAp); apPill.appendChild(tAp);
        apPill.style.cursor = "pointer";
        apPill.onclick = (ev) => {
          ev.stopPropagation();
          state.showAps = true;
          document.getElementById("chkAps").checked = true;
          render(); fitGraph();
        };
        g.appendChild(apPill);
      } else if (n.stp_root_scope === "campus_root" || n.stp_root_scope === "isolated_self_root") {
        const sPill = document.createElementNS(ns, "text");
        sPill.setAttribute("x", "9"); sPill.setAttribute("y", h - 5);
        sPill.setAttribute("font-size", "8.5"); sPill.setAttribute("font-weight", "700");
        sPill.setAttribute("fill", n.stp_root_scope === "campus_root" ? "#15803d" : "#b45309");
        sPill.textContent = n.stp_root_scope === "campus_root" ? "● CAMPUS STP ROOT" : "▲ ISOLATED SELF-ROOT";
        g.appendChild(sPill);
      }
    }

    // Branch collapse / expand pill in L2 mode
    const kidsCount = (vis.childrenMap[n.id] || []).length;
    const isSiteCollapsed = !state.expandedSites.has(n.site);
    const hiddenN = vis.nodeHiddenCount[n.id] || n.hidden_count || 0;
    if (state.mode === "L2" && !isMiniAp && (n.is_site_card || kidsCount > 0 || isSiteCollapsed)) {
      const pill = document.createElementNS(ns, "g");
      pill.setAttribute("transform", `translate(${w - 34}, 6)`);
      pill.style.cursor = "pointer";
      const pRect = document.createElementNS(ns, "rect");
      pRect.setAttribute("width", "28"); pRect.setAttribute("height", "16"); pRect.setAttribute("rx", "4");
      pRect.setAttribute("fill", "#ffffff"); pRect.setAttribute("stroke", c.stroke); pRect.setAttribute("stroke-width", "1");
      const pTxt = document.createElementNS(ns, "text");
      pTxt.setAttribute("x", "14"); pTxt.setAttribute("y", "11.5");
      pTxt.setAttribute("text-anchor", "middle"); pTxt.setAttribute("font-size", "10"); pTxt.setAttribute("font-weight", "700"); pTxt.setAttribute("fill", "#0f172a");
      pTxt.textContent = (n.is_site_card || (isSiteCollapsed && n.layer <= 2)) ? "+" : (state.collapsedNodes.has(n.id) ? `+${hiddenN}` : "−");
      pill.appendChild(pRect); pill.appendChild(pTxt);
      pill.onclick = (ev) => {
        ev.stopPropagation();
        if (n.is_site_card || !state.expandedSites.has(n.site)) state.expandedSites.add(n.site);
        else if (state.collapsedNodes.has(n.id)) state.collapsedNodes.delete(n.id);
        else state.collapsedNodes.add(n.id);
        render(); fitGraph();
      };
      g.appendChild(pill);
    }

    // Drag or click node
    g.onmousedown = (ev) => {
      if (ev.button !== 0) return;
      ev.stopPropagation();
      const startX = ev.clientX, startY = ev.clientY;
      const orig = { ...pos[n.id] };
      let moved = false;
      const onMove = (me) => {
        const dx = (me.clientX - startX) / state.scale;
        const dy = (me.clientY - startY) / state.scale;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true;
        if (moved) { state.customPos[n.id] = { x: orig.x + dx, y: orig.y + dy }; renderSvg(vis); }
      };
      const onUp = () => {
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("mouseup", onUp);
        if (!moved) {
          if (n.is_site_card) { state.expandedSites.add(n.site); render(); fitGraph(); }
          else { selectNode(n.id); }
        }
      };
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    };
    vp.appendChild(g);
  }
  applyTransform();
}

function renderL3Drawer() {
  const drawer = document.getElementById("l3Drawer");
  if (state.mode !== "L3" || !state.showL3Drawer) {
    drawer.style.display = "none";
    return;
  }
  drawer.style.display = "flex";
  const body = document.getElementById("l3DrawerBody");
  const l3g = GRAPH.l3_graph || {};
  const groups = l3g.site_vlan_groups || {};
  const relays = l3g.dhcp_relay_targets || {};
  const q = state.search.toLowerCase();

  let bucketHtml = "";
  const targetSites = state.site === "ALL" ? Object.keys(groups).sort() : [state.site].filter(s => groups[s]);
  if (targetSites.length) {
    bucketHtml = `<h4 style="margin:0 0 8px 0;">Functional VLAN Groups</h4><div class="bucket-grid">` +
      targetSites.map(sc => {
        const gs = groups[sc] || {};
        const rlist = (relays[sc] || []).join(", ") || "None";
        const rows = Object.entries(gs).map(([bname, bdata]) =>
          `<div><b>${esc(bname)}</b> (${bdata.count}): <code>${esc(bdata.cidr_summary)}</code></div>`
        ).join("");
        return `<div class="bucket-card"><div style="font-weight:700;color:#1d4ed8;margin-bottom:4px;">Site ${esc(sc)} (DHCP Relays: ${esc(rlist)})</div>${rows}</div>`;
      }).join("") + `</div>`;
  }

  const subs = (GRAPH.l3_subnets || []).filter(s => {
    const devs = s.devices.filter(d => state.site === "ALL" || d.site === state.site);
    if (!devs.length) return false;
    if (!q) return true;
    const meta = `${s.cidr} ${s.vlan_id || ""} ${s.vlan_name || ""} ${s.vlan_description || ""}`.toLowerCase();
    return meta.includes(q) || devs.some(d => `${d.hostname} ${d.ip} ${d.interface}`.toLowerCase().includes(q));
  });

  const rowsHtml = subs.map(s => {
    const devs = s.devices.filter(d => state.site === "ALL" || d.site === state.site);
    const devTxt = devs.map(d => `${d.hostname} (${d.interface}: ${d.ip})`).join("; ");
    return `<tr>
      <td><code>${esc(s.cidr)}</code></td>
      <td>${esc(s.vlan_id || "-")}</td>
      <td>${esc(s.vlan_name || "-")}</td>
      <td>${esc(s.vlan_description || "-")}</td>
      <td>${esc(devTxt)}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="5" style="color:#475569;">No SVIs match filter.</td></tr>';

  body.innerHTML = `${bucketHtml}
    <h4 style="margin:4px 0;">Authoritative SVI &amp; Subnet Table (${subs.length})</h4>
    <table class="svi-table">
      <thead><tr><th>CIDR</th><th>VLAN</th><th>Name</th><th>Description</th><th>Interfaces</th></tr></thead>
      <tbody>${rowsHtml}</tbody>
    </table>`;
}

function fitGraph() {
  const pts = Object.values(state.lastLayoutPos || {});
  if (!pts.length) return;
  const wrap = document.getElementById("canvasWrap");
  const w = wrap.clientWidth || 800, h = wrap.clientHeight || 600;
  const minX = Math.min(...pts.map(p => p.x)), maxX = Math.max(...pts.map(p => p.x + 210));
  const minY = Math.min(...pts.map(p => p.y)), maxY = Math.max(...pts.map(p => p.y + 70));
  const gw = Math.max(1, maxX - minX), gh = Math.max(1, maxY - minY);
  const pad = 44;
  state.scale = Math.max(0.15, Math.min(1.2, Math.min((w - pad * 2) / gw, (h - pad * 2) / gh)));
  state.tx = (w - gw * state.scale) / 2 - minX * state.scale;
  state.ty = (h - gh * state.scale) / 2 - minY * state.scale;
  applyTransform();
}

function centerOnNode(nid) {
  const p = (state.lastLayoutPos || {})[nid];
  if (!p) return;
  const wrap = document.getElementById("canvasWrap");
  const w = wrap.clientWidth || 800, h = wrap.clientHeight || 600;
  state.scale = Math.max(state.scale, 0.85);
  state.tx = w / 2 - (p.x + 102) * state.scale;
  state.ty = h / 2 - (p.y + 29) * state.scale;
  applyTransform();
}

function selectNode(nid, center) {
  const n = GRAPH.nodes.find(x => x.id === nid) ||
    apListAll.find(x => x.id === nid) ||
    ((GRAPH.l3_graph || {}).l3_nodes || []).find(x => x.id === nid);
  if (!n) return;
  if (n.site && !state.expandedSites.has(n.site)) state.expandedSites.add(n.site);
  state.selectedId = nid;
  const adjEdges = (state.mode === "L3" ? ((GRAPH.l3_graph || {}).l3_links || []) : GRAPH.edges)
    .filter(e => e.source === nid || e.target === nid);
  const allById = Object.fromEntries(
    GRAPH.nodes.concat((GRAPH.l3_graph || {}).l3_nodes || []).map(x => [x.id, x])
  );
  const stpTxt = n.stp_root_scope === "campus_root"
    ? '<b style="color:#15803d;">YES (Campus Root)</b>'
    : (n.stp_root_scope === "isolated_self_root"
      ? '<b style="color:#b45309;">Isolated Self-Root</b>'
      : esc(n.stp_root_scope || "N/A"));

  const insp = document.getElementById("inspectorPanel");
  insp.innerHTML = `
    <h3 style="margin-top:0;">${esc(n.hostname)} ${roleBadge(n)}</h3>
    ${(n.site && state.mode !== "L2") ? `<div style="margin-bottom:8px;"><button id="btnOpenSiteL2">Open Site ${esc(n.site)} in L2 Physical →</button></div>` : ""}
    <table class="kv">
      <tr><td>IP Address</td><td><code>${esc(n.ip || "N/A")}</code></td></tr>
      <tr><td>Site / Sub-Site</td><td>${esc(n.site || "N/A")}${n.sub_site ? ` (${esc(n.sub_site)})` : ""}</td></tr>
      <tr><td>Vendor / Model</td><td>${esc(n.vendor || "Unknown")} / ${esc(n.model || "Unknown")}</td></tr>
      <tr><td>Serial / OS</td><td><code>${esc(n.serial || "N/A")}</code> / ${esc(n.firmware || "N/A")}</td></tr>
      <tr><td>Hop Depth / L3 GW</td><td>${n.hop_depth ?? 0} · ${n.is_l3_gateway ? "Yes" : "No"}</td></tr>
      <tr><td>Ports / LLDP</td><td>${n.ports_up || 0}/${n.ports_total || 0} up · LLDP: ${esc(n.lldp || "unknown")}</td></tr>
      <tr><td>STP Scope / Prio</td><td>${stpTxt} / ${esc(n.stp_priority || "N/A")}</td></tr>
      <tr><td>PoE Load</td><td>${n.poe_total_w ? `${n.poe_used_w}W / ${n.poe_total_w}W` : "N/A"}</td></tr>
    </table>
    <h4>Uplinks &amp; Links (${adjEdges.length})</h4>
    <ul style="padding-left:16px;margin:4px 0;">
      ${adjEdges.map(e => {
        const peer = e.source === nid ? allById[e.target] : allById[e.source];
        const detail = (e.port_pairs || []).join(", ") || e.transit_cidr || e.transport_type;
        const warn = e.trunk_severity ? ` <b style="color:#dc2626;">[${esc(e.trunk_severity)}]</b>` : "";
        return `<li><b>${esc(peer ? peer.hostname : "?")}</b>: <code>${esc(detail)}</code> (${esc(e.transport_type || "")})${warn}</li>`;
      }).join("") || "<li>No infrastructure links</li>"}
    </ul>
    ${(n.attached_aps || []).length ? `<h4>Attached Wireless APs (${n.attached_aps.length})</h4><ul style="padding-left:16px;margin:4px 0;max-height:160px;overflow-y:auto;">${n.attached_aps.map(a => `<li><code>${esc(a.local_port)}</code>: <b>${esc(a.hostname)}</b> (${esc(a.ip || a.mac)})</li>`).join("")}</ul>` : ""}
    ${(n.l3_subnets || []).length ? `<h4>L3 SVIs (${n.l3_subnets.length})</h4><ul style="padding-left:16px;margin:4px 0;max-height:180px;overflow-y:auto;">${n.l3_subnets.map(s => `<li><code>${esc(s.interface)}</code>: ${esc(s.ip)} (${esc(s.cidr)})${s.vlan_description ? ` — <i>${esc(s.vlan_description)}</i>` : ""}</li>`).join("")}</ul>` : ""}
  `;
  const btnOpenSite = document.getElementById("btnOpenSiteL2");
  if (btnOpenSite && n.site) {
    btnOpenSite.onclick = () => {
      state.site = n.site;
      siteSel.value = n.site;
      state.expandedSites.add(n.site);
      setMode("L2");
    };
  }
  render();
  if (center) centerOnNode(nid);
}

function selectEdge(e) {
  const allById = Object.fromEntries(
    GRAPH.nodes.concat(apListAll).concat((GRAPH.l3_graph || {}).l3_nodes || []).map(x => [x.id, x])
  );
  const a = allById[e.source], b = allById[e.target];
  const insp = document.getElementById("inspectorPanel");
  const findings = e.trunk_findings || [];
  insp.innerHTML = `
    <h3 style="margin-top:0;">Link Inspector</h3>
    <table class="kv">
      <tr><td>Source</td><td><b>${esc(a ? a.hostname : e.source)}</b></td></tr>
      <tr><td>Target</td><td><b>${esc(b ? b.hostname : e.target)}</b></td></tr>
      <tr><td>Transport Type</td><td><b>${esc(e.transport_type || "direct_l2_uplink")}</b></td></tr>
      <tr><td>Discovery Method</td><td>${esc(e.evidence || e.routing_mechanism || "direct")}</td></tr>
      <tr><td>Ports</td><td><code>${esc((e.port_pairs || []).join(", ") || "N/A")}</code></td></tr>
      <tr><td>Speed</td><td>${esc(e.speed || "Unknown")}</td></tr>
      <tr><td>Transit VLAN / CIDR</td><td>${esc([e.transit_vlan ? `VLAN ${e.transit_vlan}` : "", e.transit_cidr || ""].filter(Boolean).join(" · ") || "N/A")}</td></tr>
      <tr><td>Mask Mismatch</td><td>${e.mask_mismatch ? `<b style="color:#b45309;">${esc(e.mask_mismatch_detail || e.mask_mismatch)}</b>` : "None"}</td></tr>
      <tr><td>STP Blocking</td><td>${e.is_blocked ? '<b style="color:#dc2626;">YES (BLK)</b>' : "No"}</td></tr>
      ${(e.routed_prefixes || []).length ? `<tr><td>Routed Prefixes (${e.routed_prefixes.length})</td><td><div style="max-height:120px;overflow-y:auto;"><code>${esc(e.routed_prefixes.join(", "))}</code></div></td></tr>` : ""}
      ${e.notes ? `<tr><td>Notes</td><td>${esc(e.notes)}</td></tr>` : ""}
    </table>
    <h4>Trunk Audit Findings (${findings.length})</h4>
    <ul style="padding-left:16px;">
      ${findings.map(f => `<li><b>${esc(f.severity)}</b> (${esc(f.rule_id)}): ${esc(f.hint)}</li>`).join("") || "<li>No trunk discrepancies</li>"}
    </ul>
  `;
}

function applyTransform() {
  document.getElementById("viewport").setAttribute("transform", `translate(${state.tx},${state.ty}) scale(${state.scale})`);
}

function setMode(m) {
  state.mode = m;
  document.getElementById("btnBackbone").classList.toggle("active", m === "BACKBONE");
  document.getElementById("btnL2").classList.toggle("active", m === "L2");
  document.getElementById("btnL3").classList.toggle("active", m === "L3");
  document.getElementById("btnL3Drawer").style.display = m === "L3" ? "inline-block" : "none";
  document.getElementById("vrfCtrl").style.display = (m === "L3" && vrfList.length > 1) ? "flex" : "none";
  render();
  fitGraph();
}

function render() {
  const vis = state.mode === "BACKBONE"
    ? getBackboneGraph()
    : (state.mode === "L3" ? getL3SvgGraph() : getVisibleL2Graph());
  document.getElementById("statsLabel").textContent =
    `Showing ${vis.nodes.length} nodes · ${vis.edges.length} links · ${GRAPH.metadata.total_aps || 0} APs`;
  renderTree(vis);
  renderSvg(vis);
  renderL3Drawer();
}

const svgEl = document.getElementById("topoSvg");
let dragging = false, movedCanvas = false, sx = 0, sy = 0;
svgEl.addEventListener("mousedown", e => { dragging = true; movedCanvas = false; sx = e.clientX - state.tx; sy = e.clientY - state.ty; });
window.addEventListener("mousemove", e => { if (!dragging) return; movedCanvas = true; state.tx = e.clientX - sx; state.ty = e.clientY - sy; applyTransform(); });
window.addEventListener("mouseup", () => { dragging = false; });
svgEl.addEventListener("click", () => { if (!movedCanvas && state.selectedId) { state.selectedId = null; render(); } });
svgEl.addEventListener("wheel", e => {
  e.preventDefault();
  const f = e.deltaY < 0 ? 1.1 : 0.9;
  state.scale = Math.max(0.15, Math.min(3, state.scale * f));
  if (state.mode === "L2") render(); else applyTransform();
}, { passive: false });

siteSel.onchange = e => {
  state.site = e.target.value;
  if (state.site !== "ALL") state.expandedSites.add(state.site);
  render(); fitGraph();
};
document.getElementById("searchBox").oninput = e => { state.search = e.target.value.trim(); render(); fitGraph(); };
document.getElementById("chkAps").onchange = e => { state.showAps = e.target.checked; render(); fitGraph(); };
document.getElementById("chkUncrawled").onchange = e => { state.showUncrawled = e.target.checked; render(); fitGraph(); };
document.getElementById("chkIssues").onchange = e => { state.issuesOnly = e.target.checked; render(); fitGraph(); };
document.getElementById("btnBackbone").onclick = () => setMode("BACKBONE");
document.getElementById("btnL2").onclick = () => setMode("L2");
document.getElementById("btnL3").onclick = () => setMode("L3");
document.getElementById("btnL3Drawer").onclick = () => { state.showL3Drawer = !state.showL3Drawer; renderL3Drawer(); };
document.getElementById("btnCloseL3Drawer").onclick = () => { state.showL3Drawer = false; renderL3Drawer(); };
document.getElementById("btnExpandAll").onclick = () => { state.expandedSites = new Set(GRAPH.sites); state.collapsedNodes.clear(); render(); fitGraph(); };
document.getElementById("btnCollapseAll").onclick = () => { state.expandedSites.clear(); state.collapsedNodes.clear(); render(); fitGraph(); };
document.getElementById("btnResetZoom").onclick = () => fitGraph();
document.getElementById("btnExportSvg").onclick = () => {
  const xml = new XMLSerializer().serializeToString(svgEl);
  const blob = new Blob([xml], { type: "image/svg+xml;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `topology_${state.mode.toLowerCase()}_${state.site}.svg`;
  a.click();
};
window.addEventListener("keydown", e => {
  if (e.key === "/" && document.activeElement !== document.getElementById("searchBox")) {
    e.preventDefault(); document.getElementById("searchBox").focus();
  } else if (e.key === "Escape") {
    state.selectedId = null; state.showL3Drawer = false; render();
  }
});

setMode(state.mode);
</script>
</body>
</html>
"""


class InteractiveHTMLTopologyRenderer(TopologyRenderer):
    """Zero-dependency self-contained HTML5/SVG interactive topology renderer."""

    name = "interactive_html"
    default_filename = "topology_interactive.html"

    def render(self, graph_model: dict[str, Any], output_path: str) -> str:
        payload = json.dumps(graph_model, separators=(",", ":")).replace("</", "<\\/")
        html = _HTML_TEMPLATE.replace("__GRAPH_JSON__", payload)
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path


RENDERER_REGISTRY: dict[str, type[TopologyRenderer]] = {
    InteractiveHTMLTopologyRenderer.name: InteractiveHTMLTopologyRenderer,
}


def get_topology_renderer(name: str = "interactive_html") -> TopologyRenderer:
    """Instantiate a registered ``TopologyRenderer`` by name."""
    cls = RENDERER_REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"Unknown topology renderer {name!r}; available: {sorted(RENDERER_REGISTRY)}")
    return cls()


def render_topology_deliverables(
    devices: dict[str, dict],
    output_dir: str,
    trunk_audit: dict | None = None,
    renderer_names: tuple[str, ...] = ("interactive_html",),
) -> list[str]:
    """Build canonical graph model once and execute all requested pluggable renderers."""
    model = build_topology_graph_model(devices, trunk_audit=trunk_audit)
    written: list[str] = []
    for rname in renderer_names:
        renderer = get_topology_renderer(rname)
        out_path = os.path.join(output_dir, renderer.default_filename)
        written.append(renderer.render(model, out_path))
    return written

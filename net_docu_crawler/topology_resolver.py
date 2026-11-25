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
Topology Resolver & Device Registry for Net-Docu-Crawler.
Handles:
  1. Single physical device deduplication via Serial Number & Base MAC
  2. Safe disambiguation of cloned VMs, LXC containers, and multi-IP Layer 3 switches/routers
  3. Neighbor IP cross-referencing via ARP cache (e.g., Junos MAC-only LLDP)
  4. Capability-based non-network device filtering (skipping VoIP phones, printers, workstations)
  5. Canonical hostname normalization with FQDN tracking
  6. Interface alias normalization (e.g., GigabitEthernet1/0/1 -> Gi1/0/1, ge-0/0/1.0 -> ge-0/0/1)
  7. Confirmed bidirectional graph edge stitching
"""

import re
import threading

import netaddr

import oui_lookup

_CLEAN_IF_RE = re.compile(
    r"^(?:(?:ge|mge|xe|et|fe|ae|reth)-?\d+(?:/\d+)*(?::\d+)?|ae\d+|reth\d+"
    r"|(?:Gi|Gig|Te|Ten|TenGigE|Fa|Fast|Eth|Et|Ethernet|Twe|Tw|Fi|Fo|FortyGigE|Hu|Hun"
    r"|25GE|GigabitEthernet|TenGigabitEthernet|FastEthernet|TwentyFiveGigE|TwentyFiveGigabitEthernet"
    r"|TwoPointFiveGigabitEthernet|TwoPointFiveGigE|FiveGigabitEthernet|FiveGigE"
    r"|FortyGigabitEthernet|HundredGigE|HundredGigabitEthernet"
    r"|Po|Port-channel|BE|Bundle-Ether|Management|Mgmt|port|lag)\s*\d+(?:/\d+)*"
    r"|swp\d+|sfp\S*|ether\d+|vtnet\d+|Trk\d+|[A-L]\d+|\d{1,2}|\d+/\d+(?:/\d+)?)$",
    re.IGNORECASE,
)
_KNOWN_IF_WORD_RE = re.compile(
    r"^(?:port|lan|wan|mgmt|management|bridge|br[-_]?|vlan|irb|trk|lag|po|eth|em|enp|ens|eno|vtnet|sfp|swp|ether)[A-Za-z0-9_./:-]*$",
    re.IGNORECASE,
)
_MAC_PORT_RE = re.compile(
    r"^(?:[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|(?:[0-9a-f]{2}\s+){5}[0-9a-f]{2}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12})$",
    re.IGNORECASE,
)
_CARRIER_KW_RE = re.compile(
    r"\b(?:metro|wan|carrier|isp|spectrum|spectrun|comcast|att|at&t|mpls|fiber|circuit|transit)\b",
    re.IGNORECASE,
)
_FW_KW_RE = re.compile(
    r"(?:firewall|palo|forti|opnsense|pfsense|checkpoint|sonicwall|asa|srx|untrust|trust|\bfw\b)",
    re.IGNORECASE,
)
_INFRA_DEV_TYPES = frozenset({"switch", "router", "firewall", "wlc"})
_NON_INFRA_DEV_TYPES = frozenset(
    {"server", "host", "workstation", "printer", "phone", "camera", "endpoint", "av_control", "nas", "ups", "iot"}
)
_PRESERVED_L2_ACCURACY = frozenset({"mac_inferred", "wan_carrier_arp_route", "l3_next_hop_egress"})


def _is_non_infra_device(dev: dict) -> bool:
    """Return True if `dev` is a server/host/endpoint rather than network infrastructure."""
    dtype = str(dev.get("device_type") or "").strip().lower()
    dpers = str(dev.get("device_persona") or "").strip().lower()
    return dtype in _NON_INFRA_DEV_TYPES or dpers in _NON_INFRA_DEV_TYPES


def is_clean_interface_token(token: str) -> bool:
    """Return True if `token` is a genuine switch/router port identifier (not prose or >=3-digit ifIndex)."""
    if not token:
        return False
    cleaned = re.sub(r"\.0$", "", token.strip())
    return bool(_CLEAN_IF_RE.match(cleaned))


def _is_numeric_ifindex(val: str) -> bool:
    s = (val or "").strip()
    return s.isdigit() and len(s) >= 3


def _is_mac_port(val: str) -> bool:
    return bool(val and _MAC_PORT_RE.fullmatch(val.strip()))


def pick_clean_remote_port(port_id: str = "", port_info: str = "", port_desc: str = "") -> tuple[str, str]:
    """
    Select the cleanest interface token from `(port_id, port_info, port_desc)` and
    preserve any human prose description as `raw_description`.
    """
    pid = (port_id or "").strip()
    pinfo = (port_info or "").strip()
    pdesc = (port_desc or "").strip()

    clean_port = ""
    for cand in (pid, pinfo, pdesc):
        if is_clean_interface_token(cand):
            clean_port = re.sub(r"\.0$", "", cand.strip())
            break
    if not clean_port:
        for cand in (pid, pinfo, pdesc):
            if cand and not _is_numeric_ifindex(cand) and not _is_mac_port(cand):
                clean_port = cand
                break
    if not clean_port:
        for cand in (pid, pinfo, pdesc):
            if cand and not _is_numeric_ifindex(cand):
                clean_port = cand
                break
    if not clean_port:
        clean_port = pid or pinfo or pdesc

    raw_desc = ""
    if pdesc and (
        re.sub(r"\.0$", "", pdesc).lower() != clean_port.lower()
        or (not is_clean_interface_token(pdesc) and not _is_mac_port(pdesc) and not _is_numeric_ifindex(pdesc))
    ):
        raw_desc = pdesc
    elif (
        pinfo
        and re.sub(r"\.0$", "", pinfo).lower() != clean_port.lower()
        and not is_clean_interface_token(pinfo)
        and not _is_numeric_ifindex(pinfo)
        and not _is_mac_port(pinfo)
    ):
        raw_desc = pinfo
    return clean_port, raw_desc


def _parse_ip_net(ip_str: str) -> tuple[netaddr.IPAddress | None, netaddr.IPNetwork | None]:
    raw = str(ip_str or "").strip()
    if not raw or raw in ("N/A", "unassigned", "down", "up", "unset"):
        return None, None
    token = raw.replace(" ", "/")
    if "/" not in token:
        return None, None
    try:
        ip_obj = netaddr.IPAddress(token.split("/", 1)[0])
        net_obj = netaddr.IPNetwork(token)
    except (netaddr.AddrFormatError, ValueError):
        return None, None
    if ip_obj.version != 4 or ip_obj.is_loopback() or str(ip_obj).startswith("128.0.") or str(ip_obj) == "0.0.0.0":
        return None, None
    return ip_obj, net_obj


# Common non-infrastructure OUIs to filter from crawl queues
NON_INFRA_VENDORS = {
    "polycom",
    "yealink",
    "mitel",
    "avaya",
    "grandstream",
    "canon",
    "epson",
    "xerox",
    "brother",
    "lexmark",
    "ricoh",
    "apple",
    "samsung",
    "intel",
    "dell",
    "lenovo",
    "realtek",
}

# Non-unique placeholder serials emitted by hypervisors, containers, or unpopulated SMBIOS tables
PLACEHOLDER_SERIALS = {
    "",
    "unknown",
    "n/a",
    "none",
    "0",
    "default string",
    "not specified",
    "to be filled by o.e.m.",
    "system serial number",
    "lxc-virtual",
    "openwrt-virtual",
    "freebsd-virtual",
}

# Factory-default hostnames that must not collide across unconfigured devices
GENERIC_DEFAULT_HOSTNAMES = {
    "",
    "unknown",
    "default",
    "openwrt",
    "opnsense",
    "pfsense",
    "mikrotik",
    "router",
    "switch",
    "localhost",
    "frr",
    "frr-router",
    "fortigate",
    "fortigate-vm64",
    "fortigate-vm64-kvm",
    "firewall",
    "vyos",
    "amnesiac",
    "edgeos",
    "ubnt",
    "arista",
    "veos",
}

_FHRP_VIRTUAL_MAC_PREFIXES: tuple[str, ...] = (
    "00:00:5e:00:01:",  # VRRPv2/v3 IPv4 (RFC 5798) & FreeBSD/OPNsense CARP
    "00:00:5e:00:02:",  # VRRPv3 IPv6 (RFC 5798)
    "00:00:0c:07:ac:",  # Cisco HSRPv1
    "00:07:b4:00:",  # Cisco GLBP
    "00:09:0f:09:",  # Fortinet FGCP HA virtual MAC
    "e0:23:ff:fc:",  # Fortinet FGCP secondary virtual MAC block
    "00:1b:17:00:",  # Palo Alto HA virtual MAC
    "00:23:04:ee:be:",  # Cisco Nexus vPC system MAC
)

_HSRPV2_MAC_RE = re.compile(r"^00:00:0c:9f:f[0-9a-f]:[0-9a-f]{2}$")
_TEXT_MAC_RE = re.compile(
    r"(?:^|[^0-9a-f])([0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|(?:mac[-_:]?)([0-9a-f]{12}))(?:$|[^0-9a-f])",
    re.IGNORECASE,
)
_SVI_VLAN_PREFIX_RE = re.compile(r"^(?:vlan[._\-\s]?|vl|irb\.|bvi[._\-\s]?)0*(\d+)$", re.IGNORECASE)
_FREEBSD_VLAN_SUBIF_RE = re.compile(r"^[a-zA-Z0-9/_-]+_vlan0*([1-9]\d{0,3})$", re.IGNORECASE)
_DOT1Q_SUBIF_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9/_-]*\d+\.0*([1-9]\d{0,3})$")
_STP_BRIDGE_ID_RE = re.compile(
    r"^(?:(\d+)[.\-:/\s]+)?([0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12})$",
    re.IGNORECASE,
)

_CANONICAL_IF_SHORT_RULES: tuple[tuple[str, str], ...] = (
    (r"^(?:twentyfivegigabitethernet|twentyfivegige|twe|25ge)\s*(?=\d)", "Twe"),
    (r"^(?:twopointfivegigabitethernet|twopointfivegige|tw)\s*(?=\d)", "Tw"),
    (r"^(?:hundredgigabitethernet|hundredgige|hun|hu)\s*(?=\d)", "Hu"),
    (r"^(?:fortygigabitethernet|fortygige|fo)\s*(?=\d)", "Fo"),
    (r"^(?:tengigabitethernet|tengige|ten|te)\s*(?=\d)", "Te"),
    (r"^(?:fivegigabitethernet|fivegige|fi)\s*(?=\d)", "Fi"),
    (r"^(?:gigabitethernet|gig|gi)\s*(?=\d)", "Gi"),
    (r"^(?:fastethernet|fast|fa)\s*(?=\d)", "Fa"),
    (r"^(?:port-channel|po)\s*(?=\d)", "Po"),
    (r"^(?:bundle-ether|be)\s*(?=\d)", "BE"),
    (r"^(?:ethernet|eth|et)\s*(?=\d)", "Eth"),
)


def is_placeholder_serial(serial: str) -> bool:
    """Return True if `serial` is empty or a known non-unique virtual/SMBIOS placeholder."""
    return str(serial or "").strip().lower() in PLACEHOLDER_SERIALS


def is_generic_hostname(hostname: str) -> bool:
    """Return True if `hostname` (short form) is empty or a factory-default generic name."""
    short, _ = normalize_hostname(str(hostname or ""))
    return short.lower() in GENERIC_DEFAULT_HOSTNAMES


def is_multicast_or_zero_mac(mac: str) -> bool:
    """Return True for empty, malformed, all-zero, broadcast, or IEEE multicast MACs."""
    norm = oui_lookup.normalize_mac(str(mac or "")).lower().strip()
    if len(norm) != 17 or norm in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return True
    try:
        first_octet = int(norm.split(":", 1)[0], 16)
    except ValueError:
        return True
    return bool(first_octet & 0x01)


def is_fhrp_virtual_mac(mac: str) -> bool:
    """Return True if `mac` belongs to a shared FHRP / HA virtual MAC range (VRRP/CARP/HSRP/GLBP/HA)."""
    norm = oui_lookup.normalize_mac(str(mac or "")).lower().strip()
    if len(norm) != 17:
        return False
    if norm.startswith(_FHRP_VIRTUAL_MAC_PREFIXES):
        return True
    return bool(_HSRPV2_MAC_RE.match(norm))


def is_locally_administered_mac(mac: str) -> bool:
    """Return True if `mac` is a unicast locally administered address (LAA, IEEE bit 1 set)."""
    norm = oui_lookup.normalize_mac(str(mac or "")).lower().strip()
    if len(norm) != 17:
        return False
    try:
        first_octet = int(norm.split(":", 1)[0], 16)
    except ValueError:
        return False
    return (first_octet & 0x03) == 0x02


def is_shared_or_virtual_mac(mac: str) -> bool:
    """Return True if `mac` must never be used as a unique physical chassis identity."""
    return is_multicast_or_zero_mac(mac) or is_fhrp_virtual_mac(mac)


def normalize_hostname(raw_hostname: str) -> tuple[str, str]:
    """
    Normalizes a hostname by stripping quotes, serial suffixes, and domain suffixes.
    Returns: (short_canonical_name, full_fqdn)
    Example: 'switch-core.lan.example.internal' -> ('switch-core', 'switch-core.lan.example.internal')
    """
    if not raw_hostname:
        return "", ""
    cleaned = raw_hostname.strip().strip('"').strip("'")
    # Strip serial in parenthesis if present e.g. switch01(FOC12345)
    cleaned = re.sub(r"\(.*?\)", "", cleaned).strip()
    fqdn = cleaned

    # Extract short hostname before first dot (unless raw_hostname is an IPv4 address)
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", cleaned):
        return cleaned, cleaned

    short_name = cleaned.split(".")[0].strip()
    return short_name, fqdn


def normalize_interface(intf: str) -> str:
    """
    Standardizes interface nomenclature across multiple vendor naming conventions.
    Example:
      'GigabitEthernet1/0/1' -> 'Gi1/0/1'
      'TenGigabitEthernet1/0/48' -> 'Te1/0/48'
      'ge-0/0/1.0' -> 'ge-0/0/1'
      'Ethernet1/1' / 'Eth1/1' / 'Et1/1' -> 'Eth1/1'
      'Port-channel1' / 'Po1' -> 'Po1'
      'Bundle-Ether10' / 'BE10' -> 'BE10'
      'eth0' (Linux/appliance NIC) -> 'eth0'
    """
    if not intf:
        return ""
    name = intf.strip().strip('"').strip("'")
    if not name:
        return ""

    # Strip trailing Junos/router unit .0 suffix (preserve non-zero VLAN subinterfaces e.g. .10)
    name = re.sub(r"\.0$", "", name)

    # Preserve Junos interface prefixes before Ethernet short-form rules (protects et-0/0/0 100G)
    m_junos = re.match(r"^(ge-|mge-|xe-|et-|fe-|ae(?=\d)|reth(?=\d))(.*)$", name, flags=re.IGNORECASE)
    if m_junos:
        return f"{m_junos.group(1).lower()}{m_junos.group(2)}"

    # Preserve exact lowercase Linux/appliance ethN[.V] NICs without rewriting to Cisco/Arista EthN
    if re.fullmatch(r"eth\d+(?:\.\d+)?", name):
        return name

    for pattern, short_prefix in _CANONICAL_IF_SHORT_RULES:
        if re.match(pattern, name, flags=re.IGNORECASE):
            return re.sub(pattern, short_prefix, name, count=1, flags=re.IGNORECASE)

    return name


def normalize_interface_key(intf: str) -> str:
    """Return a canonical lowercase lookup key for interface matching across modules."""
    return normalize_interface(intf).lower().strip()


def infer_interface_speed(speed_str: str = "", port_name: str = "") -> tuple[int, str]:
    """
    Return `(speed_mbps, speed_label)` from operational speed telemetry or vendor port naming.
    Uses strict prefix matching on canonicalized port names so `et-0/0/0` (100G), `Twe` (25G),
    `Tw` (2.5G), `vtnet0`, and `ether1` never collide with legacy 10M/2.5G/5G rules.
    """
    s = (speed_str or "").lower().strip()
    if s:
        if "400g" in s or "400000" in s:
            return 400000, "400G"
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

    p = normalize_interface_key(port_name)
    if p.startswith(("hu", "et-")):
        return 100000, "100G"
    if p.startswith("fo"):
        return 40000, "40G"
    if p.startswith(("twe", "25ge")):
        return 25000, "25G"
    if p.startswith(("xe-", "te")):
        return 10000, "10G"
    if p.startswith("fi"):
        return 5000, "5G"
    if p.startswith(("mge", "tw")):
        return 2500, "2.5G"
    if p.startswith(("ge-", "gi")):
        return 1000, "1G"
    if p.startswith("fa"):
        return 100, "100M"
    return 1000, "1G"


def _extract_device_fhrp_vips(device_data: dict) -> set[str]:
    """Return all FHRP (HSRP/VRRP/CARP/GLBP) virtual IP addresses configured on `device_data`."""
    vips: set[str] = set()
    for entry in device_data.get("fhrp") or []:
        if not isinstance(entry, dict):
            continue
        vip = str(entry.get("vip") or entry.get("virtual_ip") or "").split("/", 1)[0].strip()
        if vip:
            vips.add(vip)
    return vips


def _extract_owned_ips(device_data: dict, exclude_fhrp_vips: bool = True) -> set[str]:
    """Return non-loopback, non-fabric IPv4/IPv6 addresses owned by `device_data`."""
    fhrp_vips = _extract_device_fhrp_vips(device_data) if exclude_fhrp_vips else set()
    ips: set[str] = set()
    primary_ip = str(device_data.get("ip") or "").strip()
    if primary_ip and not primary_ip.startswith(("127.", "128.0.")) and primary_ip != "::1":
        ips.add(primary_ip)
    for intf in device_data.get("l3_interfaces") or []:
        if not isinstance(intf, dict):
            continue
        ip_raw = str(intf.get("ip_address") or "")
        ip_clean = ip_raw.split("/")[0].split()[0].split("%")[0].strip()
        if (
            ip_clean
            and ip_clean not in ("N/A", "unassigned", "0.0.0.0", "::")
            and not ip_clean.startswith(("127.", "128.0."))
            and ip_clean != "::1"
            and ip_clean not in fhrp_vips
        ):
            ips.add(ip_clean)
    return ips


def _extract_hw_macs(device_data: dict) -> set[str]:
    """Return normalized non-virtual, non-hypervisor, non-LAA hardware MAC addresses on `device_data`."""
    from net_docu_crawler.drivers.detector import is_hypervisor_mac

    macs: set[str] = set()
    raw_candidates = [device_data.get("mac_address", "")]
    for stats in (device_data.get("interfaces_detail") or {}).values():
        if isinstance(stats, dict):
            raw_candidates.append(stats.get("mac_address", ""))
    for raw_m in raw_candidates:
        m = oui_lookup.normalize_mac(str(raw_m or "")).lower().strip()
        if m and not is_shared_or_virtual_mac(m) and not is_hypervisor_mac(m) and not is_locally_administered_mac(m):
            macs.add(m)
    return macs


def dedupe_devices(devices: dict[str, dict]) -> dict[str, dict]:
    """
    Canonical multi-SVI chassis deduplicator shared across registry and reporting.

    Preserves distinct cloned VMs, hypervisor guests, FHRP HA pairs, and factory-default
    appliances by rejecting placeholder serials, FHRP/virtual MACs, and generic hostnames,
    and only falling back to hostname matching when neither peer has a valid hardware serial.
    """
    if not devices:
        return {}

    def _ip_sort_key(ip: str) -> list[int]:
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return [int(x) for x in ip.split(".")]
        return [0]

    sorted_ips = sorted(
        devices.keys(),
        key=lambda ip: (
            devices[ip].get("status") == "success",
            str(devices[ip].get("mgmt_method", "")).startswith("SSH"),
            _ip_sort_key(ip),
        ),
        reverse=True,
    )

    unique_devices: dict[str, dict] = {}
    seen_serials: dict[str, str] = {}
    seen_owned_ips: dict[str, str] = {}
    seen_hw_macs: dict[str, str] = {}
    seen_hostnames: dict[str, tuple[str, bool, set[str]]] = {}

    for ip in sorted_ips:
        dev = devices[ip]
        if not isinstance(dev, dict):
            continue
        serial = str(dev.get("serial") or "").strip()
        has_valid_serial = not is_placeholder_serial(serial)
        serial_key = serial.upper() if has_valid_serial else ""
        short_host, _ = normalize_hostname(str(dev.get("hostname") or ""))
        has_unique_host = not is_generic_hostname(short_host)
        host_key = short_host.lower() if has_unique_host else ""
        owned_ips = _extract_owned_ips(dev, exclude_fhrp_vips=True)
        owned_ips.add(ip)
        hw_macs = _extract_hw_macs(dev)

        is_dup = False
        if has_valid_serial and serial_key in seen_serials:
            is_dup = True
        elif any(oip in seen_owned_ips for oip in owned_ips):
            matched_ip = next(seen_owned_ips[oip] for oip in owned_ips if oip in seen_owned_ips)
            existing_ser = str(unique_devices[matched_ip].get("serial") or "").strip()
            if not (
                has_valid_serial and not is_placeholder_serial(existing_ser) and existing_ser.upper() != serial_key
            ):
                is_dup = True
        elif any(m in seen_hw_macs for m in hw_macs):
            matched_ip = next(seen_hw_macs[m] for m in hw_macs if m in seen_hw_macs)
            existing_ser = str(unique_devices[matched_ip].get("serial") or "").strip()
            if not (
                has_valid_serial and not is_placeholder_serial(existing_ser) and existing_ser.upper() != serial_key
            ):
                is_dup = True
        elif not has_valid_serial and has_unique_host and host_key in seen_hostnames:
            _prev_ip, prev_has_serial, prev_hw_macs = seen_hostnames[host_key]
            # Fallback hostname dedupe only when neither device has a verified serial or distinct hardware MACs
            if not prev_has_serial and not (hw_macs and prev_hw_macs and hw_macs.isdisjoint(prev_hw_macs)):
                is_dup = True

        if not is_dup:
            unique_devices[ip] = dev
            if has_valid_serial:
                seen_serials[serial_key] = ip
            for oip in owned_ips:
                seen_owned_ips.setdefault(oip, ip)
            for m in hw_macs:
                seen_hw_macs.setdefault(m, ip)
            if has_unique_host:
                seen_hostnames.setdefault(host_key, (ip, has_valid_serial, hw_macs))

    return {ip: unique_devices[ip] for ip in sorted(unique_devices.keys(), key=_ip_sort_key)}


def is_crawlable_network_device(capabilities: list[str], device_type: str = "", vendor_or_model: str = "") -> bool:
    """
    Evaluates whether a neighbor is a true network infrastructure device
    (Switch, Router, Bridge, Access Point, Firewall) or a non-crawlable peripheral (VoIP Phone, Host, Printer).
    """
    caps_lower = [c.lower() for c in capabilities]
    type_lower = device_type.lower()
    vm_lower = vendor_or_model.lower()

    # Explicit phone detection
    if "phone" in type_lower or "telephone" in type_lower or "phone" in caps_lower or "telephone" in caps_lower:
        return False
    if any(p in vm_lower for p in ["cp-78", "cp-88", "voip", "ip phone", "polycom", "yealink"]):
        return False

    # Host/Printer exclusion unless it also has bridge/router capabilities
    if "host" in type_lower or "station" in type_lower or "printer" in type_lower:
        return False

    # Must possess networking capabilities: Bridge, Switch, Router, or WLAN
    network_caps = {"bridge", "switch", "router", "wlan", "ap", "b", "r", "w"}
    if any(c in network_caps for c in caps_lower):
        return True

    # If capabilities are unspecified but device_type is switch/router/firewall/ap, accept
    if type_lower in ("switch", "router", "firewall", "ap", "wlc"):
        return True

    # Default to True for unknown infrastructure to avoid missing unmanaged switches
    return True


def _extract_mac_from_text(val: str) -> str:
    """Extract and normalize a 48-bit MAC address from a raw token, `MAC-<hex>`, or port string."""
    text = str(val or "").strip()
    if not text:
        return ""
    direct = oui_lookup.normalize_mac(text).lower().strip()
    if len(direct) == 17 and direct.count(":") == 5:
        return direct
    m = _TEXT_MAC_RE.search(text)
    if not m:
        return ""
    raw_hex = m.group(2) or m.group(1)
    norm = oui_lookup.normalize_mac(raw_hex).lower().strip()
    return norm if len(norm) == 17 and norm.count(":") == 5 else ""


def _extract_unicast_ip(val: str) -> str:
    """Return canonical unicast IPv4/IPv6 string if `val` is a valid non-multicast/non-loopback IP, else ''."""
    tok = str(val or "").strip().split("/", 1)[0].split("%", 1)[0].strip()
    if not tok or (":" not in tok and tok.count(".") != 3):
        return ""
    try:
        ip_obj = netaddr.IPAddress(tok)
    except (netaddr.AddrFormatError, ValueError):
        return ""
    ip_s = str(ip_obj)
    if (
        ip_obj.is_multicast()
        or ip_obj.is_loopback()
        or ip_s in ("0.0.0.0", "::", "::1")
        or ip_s.startswith(("127.", "128.0."))
    ):
        return ""
    return ip_s


def extract_vlan_id_from_interface(
    intf_name: str,
    intf_meta: dict | None = None,
    interfaces_detail: dict | None = None,
) -> str:
    """
    Extract a valid IEEE 802.1Q VLAN ID (`"1"`..`"4094"`) from multi-vendor SVI/subinterface names
    or explicit interface metadata (rejecting VLAN 0 such as unmapped `irb.0`).
    """
    for src in (intf_meta, (interfaces_detail or {}).get(intf_name) if interfaces_detail else None):
        if isinstance(src, dict):
            raw_v = str(src.get("vlan_id") or src.get("vlan") or "").strip()
            if raw_v.isdigit() and 1 <= int(raw_v) <= 4094:
                return str(int(raw_v))

    iname = str(intf_name or "").strip()
    if not iname:
        return ""

    m_svi = _SVI_VLAN_PREFIX_RE.match(iname)
    if m_svi:
        vid_int = int(m_svi.group(1))
        return str(vid_int) if 1 <= vid_int <= 4094 else ""

    m_bsd = _FREEBSD_VLAN_SUBIF_RE.match(iname)
    if m_bsd:
        vid_int = int(m_bsd.group(1))
        return str(vid_int) if 1 <= vid_int <= 4094 else ""

    m_dot1q = _DOT1Q_SUBIF_RE.match(iname)
    if m_dot1q:
        vid_int = int(m_dot1q.group(1))
        return str(vid_int) if 1 <= vid_int <= 4094 else ""

    return ""


def normalize_stp_bridge_id(raw_bridge_id: str) -> str:
    """
    Canonicalize STP root/bridge IDs across vendors (`32768.20d8.0b8f.adde`, `32768.20:d8:0b:8f:ad:de`,
    `32768-20:d8:0b:8f:ad:de`) to `<priority>.<aa:bb:cc:dd:ee:ff>` (or lowercase colon MAC if no priority).
    """
    val = str(raw_bridge_id or "").strip().lower()
    if not val:
        return ""
    m = _STP_BRIDGE_ID_RE.match(val)
    if not m:
        return val
    prio, mac_part = m.group(1), m.group(2)
    mac_norm = oui_lookup.normalize_mac(mac_part).lower().strip()
    if len(mac_norm) != 17:
        return val
    return f"{prio}.{mac_norm}" if prio else mac_norm


def detect_cidr_overlaps(devices: dict[str, dict] | list[dict]) -> dict[str, list[dict]]:
    """
    Canonical VRF-scoped, `netaddr`-backed CIDR & IP conflict detector for reports and topology graphs.

    Flags only genuine L3 defects (never normal multi-device shared broadcast LAN peers):
      1. `duplicate_gateway_ip`: identical IP on >=2 distinct devices in the same VRF (exempting declared FHRP VIPs).
      2. `intra_device_overlap`: overlapping subnets across two distinct normalized interfaces on the same device & VRF.
      3. `mask_mismatch`: unequal overlapping prefix lengths across distinct devices in the same VRF (2 or >=3 peers).
    """
    if isinstance(devices, dict):
        dev_list = list(dedupe_devices(devices).values())
    else:
        dev_list = list(devices or [])

    active_devs = [
        d
        for d in dev_list
        if isinstance(d, dict) and d.get("status", "success") == "success" and not _is_non_infra_device(d)
    ]

    entries: list[dict] = []
    fhrp_vips_by_dev: dict[int, set[str]] = {}
    for dev_idx, dev in enumerate(active_devs):
        host = str(dev.get("hostname") or dev.get("ip") or f"dev-{dev_idx}").strip()
        fhrp_vips_by_dev[dev_idx] = _extract_device_fhrp_vips(dev)

        intf_vrf: dict[str, str] = {}
        for vobj in dev.get("vrfs") or []:
            if isinstance(vobj, dict):
                vn = str(vobj.get("name") or "default").strip() or "default"
                for inf in vobj.get("interfaces") or []:
                    k = normalize_interface_key(str(inf))
                    if k:
                        intf_vrf[k] = vn

        for intf in dev.get("l3_interfaces") or []:
            if not isinstance(intf, dict):
                continue
            iname = str(intf.get("interface") or "").strip()
            raw_ip = str(intf.get("ip_address") or "").strip()
            if not raw_ip or raw_ip.lower() in ("unassigned", "down", "up", "unset", "n/a"):
                continue
            collapsed = re.sub(r"\s+", " ", raw_ip)
            mask_known = ("/" in collapsed) or (" " in collapsed)
            try:
                net = netaddr.IPNetwork(collapsed.replace(" ", "/"))
                ip_obj = netaddr.IPAddress(collapsed.split("/", 1)[0].split(" ", 1)[0])
            except (netaddr.AddrFormatError, ValueError):
                continue
            ip_s = str(ip_obj)
            if (
                ip_obj.is_loopback()
                or ip_s in ("0.0.0.0", "::", "::1")
                or ip_s.startswith(("127.", "128.0."))
                or ip_s.lower().startswith("fe80:")
            ):
                continue
            vrf_raw = str(
                intf.get("vrf") or intf_vrf.get(normalize_interface_key(iname), "default") or "default"
            ).strip()
            vrf = (
                "default"
                if vrf_raw.lower() in ("", "global", "default", "global-table", "main", "inet.0", "inet6.0")
                else vrf_raw
            )
            entries.append(
                {
                    "dev_idx": dev_idx,
                    "hostname": host,
                    "interface": iname,
                    "iface_key": normalize_interface_key(iname),
                    "vrf": vrf,
                    "ip": ip_s,
                    "ip_obj": ip_obj,
                    "net": net,
                    "cidr": f"{net.network}/{net.prefixlen}" if mask_known else ip_s,
                    "version": net.version,
                    "mask_known": mask_known,
                }
            )

    duplicate_ips: list[dict] = []
    intra_device_overlaps: list[dict] = []
    mask_mismatches: list[dict] = []
    seen_keys: set[tuple] = set()

    # 1. Intra-device overlapping subnets (same device, same VRF, distinct normalized interfaces, explicit masks)
    by_dev_vrf: dict[tuple[int, str], list[dict]] = {}
    for e in entries:
        by_dev_vrf.setdefault((e["dev_idx"], e["vrf"]), []).append(e)

    for (dev_idx, vrf), items in by_dev_vrf.items():
        for i in range(len(items)):
            for j in range(i + 1, len(items)):
                a, b = items[i], items[j]
                if a["version"] != b["version"] or not (a["mask_known"] and b["mask_known"]):
                    continue
                if a["iface_key"] == b["iface_key"]:
                    continue
                host_len = 128 if a["version"] == 6 else 32
                if a["net"].prefixlen == host_len or b["net"].prefixlen == host_len:
                    continue
                if a["net"] in b["net"] or b["net"] in a["net"]:
                    ck = ("intra", dev_idx, vrf, tuple(sorted((a["iface_key"], b["iface_key"]))), a["cidr"], b["cidr"])
                    if ck in seen_keys:
                        continue
                    seen_keys.add(ck)
                    intra_device_overlaps.append(
                        {
                            "conflict_type": "intra_device_overlap",
                            "vrf": vrf,
                            "cidr": f"{a['cidr']} / {b['cidr']}",
                            "devices": [a["hostname"]],
                            "interfaces": [a["interface"], b["interface"]],
                            "impact_summary": (
                                f"{a['hostname']} (VRF {vrf}) configures overlapping interfaces "
                                f"{a['interface']} ({a['ip']}/{a['net'].prefixlen}) and "
                                f"{b['interface']} ({b['ip']}/{b['net'].prefixlen})."
                            ),
                        }
                    )

    # 2. Cross-device duplicate IPs (same VRF, exempting declared shared FHRP VIPs)
    by_vrf_ip: dict[tuple[str, str], list[dict]] = {}
    for e in entries:
        by_vrf_ip.setdefault((e["vrf"], e["ip"]), []).append(e)

    for (vrf, dup_ip), occs in sorted(by_vrf_ip.items()):
        dev_indices = sorted({o["dev_idx"] for o in occs})
        if len(dev_indices) < 2:
            continue
        if all(dup_ip in fhrp_vips_by_dev.get(idx, set()) for idx in dev_indices):
            continue
        hosts = sorted({o["hostname"] for o in occs})
        cidrs = sorted({o["cidr"] for o in occs})
        duplicate_ips.append(
            {
                "conflict_type": "duplicate_gateway_ip",
                "vrf": vrf,
                "cidr": cidrs[0],
                "duplicate_ip": dup_ip,
                "devices": hosts,
                "impact_summary": f"Duplicate IP {dup_ip} ({cidrs[0]}) in VRF {vrf} configured on {', '.join(hosts)}.",
            }
        )

    # 3. Cross-device unequal overlapping subnet masks (works for both 2-peer and >=3-peer LANs)
    for i in range(len(entries)):
        a = entries[i]
        if not a["mask_known"]:
            continue
        host_len = 128 if a["version"] == 6 else 32
        if a["net"].prefixlen == host_len:
            continue
        for j in range(i + 1, len(entries)):
            b = entries[j]
            if (
                a["dev_idx"] == b["dev_idx"]
                or a["vrf"] != b["vrf"]
                or a["version"] != b["version"]
                or not b["mask_known"]
                or b["net"].prefixlen == host_len
                or a["ip"] == b["ip"]
                or a["net"].prefixlen == b["net"].prefixlen
            ):
                continue
            if a["ip_obj"] in b["net"] or b["ip_obj"] in a["net"]:
                tight_cidr = a["cidr"] if a["net"].prefixlen >= b["net"].prefixlen else b["cidr"]
                ck = ("mask", a["vrf"], tight_cidr, tuple(sorted((a["dev_idx"], b["dev_idx"]))))
                if ck in seen_keys:
                    continue
                seen_keys.add(ck)
                p1, p2 = a["net"].prefixlen, b["net"].prefixlen
                mask_mismatches.append(
                    {
                        "conflict_type": "mask_mismatch",
                        "vrf": a["vrf"],
                        "cidr": tight_cidr,
                        "devices": sorted([a["hostname"], b["hostname"]]),
                        "mask_detail": f"/{p1} vs /{p2}",
                        "impact_summary": (
                            f"Subnet mask mismatch (/{p1} vs /{p2}) on {tight_cidr} (VRF {a['vrf']}) between "
                            f"{a['hostname']} ({a['ip']}/{p1}) and {b['hostname']} ({b['ip']}/{p2})."
                        ),
                    }
                )

    return {
        "conflicts": intra_device_overlaps + duplicate_ips + mask_mismatches,
        "duplicate_ips": duplicate_ips,
        "intra_device_overlaps": intra_device_overlaps,
        "mask_mismatches": mask_mismatches,
    }


class DeviceRegistry:
    """
    Thread-safe Central Device & Topology Registry.
    Tracks devices by verified hardware Serial Number and Base MAC to avoid duplicate crawls
    when switches have multiple SVIs, loopbacks, or VRF interfaces, while preventing false
    collisions across cloned VMs, LXC containers, or factory-default routers.
    """

    def __init__(self):
        self._lock = threading.RLock()
        # Canonical device records keyed by primary device_id (serial or base_mac or short_name or ip)
        self.devices: dict[str, dict] = {}
        # Mapping: alias_ip -> canonical_device_id
        self.ip_to_device_id: dict[str, str] = {}
        # Mapping: mac_address -> canonical_device_id
        self.mac_to_device_id: dict[str, str] = {}
        # Mapping: short_hostname -> full FQDN
        self.fqdn_table: dict[str, str] = {}
        # Set of IPs currently being crawled by worker threads
        self.in_progress_ips: set[str] = set()
        # Harvested Global ARP Cache: ip -> {"mac": mac, "vendor": vendor, "discovered_on": ip}
        self.global_arp: dict[str, dict] = {}
        # Canonical topology links: list of {"node_a", "port_a", "node_b", "port_b", "status", "type"}
        self.links: list[dict] = []
        # Internal observed direct-observation directions per link id(lk): {"a->b", "b->a"}
        self._link_directions: dict[int, set[str]] = {}

    def start_crawl(self, ip: str) -> bool:
        """
        Attempts to claim an IP for crawling.
        Returns False if IP or its device is already crawled or in-progress.
        """
        with self._lock:
            if ip in self.in_progress_ips:
                return False
            if ip in self.ip_to_device_id:
                # Device already crawled under another SVI
                return False
            self.in_progress_ips.add(ip)
            return True

    def release_crawl(self, ip: str):
        """Releases the in-progress lock for an IP."""
        with self._lock:
            self.in_progress_ips.discard(ip)

    def _find_existing_svi_device_id(
        self,
        owned_ips: set[str],
        hw_macs: set[str],
        serial: str,
        has_valid_serial: bool,
    ) -> str:
        """Return an existing canonical device_id when `owned_ips` or `hw_macs` match a previously registered chassis."""
        for candidate_id in [self.ip_to_device_id[ip] for ip in owned_ips if ip in self.ip_to_device_id] + [
            self.mac_to_device_id[m] for m in hw_macs if m in self.mac_to_device_id
        ]:
            existing = self.devices.get(candidate_id)
            if not existing:
                continue
            existing_serial = str(existing.get("serial") or "").strip()
            existing_has_serial = not is_placeholder_serial(existing_serial)
            if has_valid_serial and existing_has_serial and existing_serial.upper() != serial.upper():
                continue
            return candidate_id
        return ""

    def register_device(self, device_data: dict) -> str:
        """
        Registers a crawled device, linking all its SVIs, MACs, and hostnames to a single canonical entity.
        Rejects placeholder virtual serials, shared FHRP virtual MACs, and factory-default hostnames so
        cloned VMs/containers and HA pairs never collide, while merging multi-SVI crawls of the same chassis.
        Returns the canonical device_id.
        """
        from net_docu_crawler.drivers.detector import is_hypervisor_mac

        with self._lock:
            short_host, fqdn = normalize_hostname(device_data.get("hostname", ""))
            serial = str(device_data.get("serial") or "").strip()
            base_mac = oui_lookup.normalize_mac(str(device_data.get("mac_address") or "")).lower().strip()
            primary_ip = str(device_data.get("ip") or "").strip()

            has_valid_serial = not is_placeholder_serial(serial)
            has_unique_host = not is_generic_hostname(short_host)
            owned_ips = _extract_owned_ips(device_data, exclude_fhrp_vips=True)
            hw_macs = _extract_hw_macs(device_data)
            usable_base_mac = bool(base_mac) and not is_shared_or_virtual_mac(base_mac)

            # Determine primary unique key: Verified Serial > Multi-SVI Existing Match > Usable Base MAC > Unique Hostname > IP
            device_id = ""
            if has_valid_serial:
                device_id = f"SER_{serial}"
            else:
                device_id = self._find_existing_svi_device_id(owned_ips, hw_macs, serial, has_valid_serial)

            if not device_id:
                if usable_base_mac:
                    mac_hex = base_mac.replace(":", "").replace(".", "")
                    cand_id = f"MAC_{mac_hex}"
                    existing = self.devices.get(cand_id)
                    if existing and (is_hypervisor_mac(base_mac) or is_locally_administered_mac(base_mac)):
                        existing_ips = _extract_owned_ips(existing, exclude_fhrp_vips=True)
                        if owned_ips and existing_ips and owned_ips.isdisjoint(existing_ips):
                            device_id = f"MAC_{mac_hex}_{primary_ip}" if primary_ip else f"IP_{primary_ip}"
                        else:
                            device_id = cand_id
                    else:
                        device_id = cand_id
                elif has_unique_host:
                    cand_id = f"HOST_{short_host}"
                    existing = self.devices.get(cand_id)
                    if existing and existing.get("ip") != primary_ip:
                        existing_ips = _extract_owned_ips(existing, exclude_fhrp_vips=True)
                        if owned_ips and existing_ips and not owned_ips.isdisjoint(existing_ips):
                            device_id = cand_id
                        else:
                            device_id = f"HOST_{short_host}_{primary_ip}"
                    else:
                        device_id = cand_id
                else:
                    device_id = f"IP_{primary_ip}"

            # Store FQDN mapping (only for non-generic hostnames)
            if has_unique_host and fqdn:
                self.fqdn_table[short_host] = fqdn

            # Register all owned L3 interfaces (excluding FHRP VIPs, loopbacks, internal fabric) to this device_id
            for ip_clean in owned_ips:
                self.ip_to_device_id[ip_clean] = device_id

            # Register non-virtual base MAC and per-interface MACs (never index FHRP/multicast MACs,
            # and never clobber a different device's shared hypervisor/LAA MAC)
            candidate_macs = [base_mac] if usable_base_mac else []
            for stats in (device_data.get("interfaces_detail") or {}).values():
                if not isinstance(stats, dict):
                    continue
                imac = oui_lookup.normalize_mac(str(stats.get("mac_address") or "")).lower().strip()
                if imac and not is_shared_or_virtual_mac(imac):
                    candidate_macs.append(imac)
            for m in candidate_macs:
                if (is_hypervisor_mac(m) or is_locally_administered_mac(m)) and m in self.mac_to_device_id:
                    if self.mac_to_device_id[m] != device_id:
                        continue
                self.mac_to_device_id[m] = device_id

            # Ingest device ARP entries into global ARP table
            for arp in device_data.get("arp_table", []):
                a_ip = arp.get("ip", "")
                a_mac = oui_lookup.normalize_mac(arp.get("mac", "")).lower().strip()
                if a_ip and a_mac and not is_multicast_or_zero_mac(a_mac):
                    self.global_arp[a_ip] = {
                        "mac": a_mac,
                        "vendor": arp.get("vendor") or oui_lookup.lookup_oui(a_mac),
                        "discovered_on": primary_ip,
                    }

            # Store or update the canonical record (do not let a non-success stub overwrite a crawled success record)
            device_data["canonical_id"] = device_id
            device_data["canonical_hostname"] = short_host
            device_data["fqdn"] = fqdn
            existing_rec = self.devices.get(device_id)
            if not (
                existing_rec
                and existing_rec.get("status", "success") == "success"
                and device_data.get("status", "success") != "success"
            ):
                self.devices[device_id] = device_data
            self.in_progress_ips.discard(primary_ip)

            return device_id

    def get_arp_mac(self, ip: str) -> str:
        """Return a previously harvested ARP MAC address for `ip`, or '' if unknown."""
        with self._lock:
            entry = self.global_arp.get(ip)
            return entry.get("mac", "") if entry else ""

    def resolve_neighbor_ip(
        self,
        neighbor_mac: str = "",
        neighbor_name: str = "",
        remote_port: str = "",
    ) -> str | None:
        """
        Resolve a neighbor's management/IP address across all LLDP chassis-ID subtypes
        (MAC, network address, local serial, or system name) and MAC-valued `remote_port`s.
        Prefers crawled `DeviceRegistry` management IPs over secondary ARP entries and
        rejects multicast IPs, FHRP virtual MACs, and generic factory-default hostnames.
        """
        with self._lock:
            # 1. Network-address chassis-ID subtype (unicast IPv4/IPv6 in neighbor_mac or neighbor_name)
            for raw_tok in (neighbor_mac, neighbor_name):
                uip = _extract_unicast_ip(raw_tok)
                if uip:
                    if uip in self.ip_to_device_id:
                        dev = self.devices.get(self.ip_to_device_id[uip])
                        if dev and dev.get("ip"):
                            return dev["ip"]
                    return uip

            # 2. Collect non-virtual MAC candidates from chassis-id, remote_port, and remote_device text
            candidate_macs: list[str] = []
            for raw_src in (neighbor_mac, remote_port, neighbor_name):
                m_cand = _extract_mac_from_text(raw_src)
                if m_cand and not is_shared_or_virtual_mac(m_cand) and m_cand not in candidate_macs:
                    candidate_macs.append(m_cand)

            # 3. Prefer crawled DeviceRegistry management IP by MAC (prevents secondary VC/SVI ARP shadowing)
            for m_cand in candidate_macs:
                if m_cand in self.mac_to_device_id:
                    dev = self.devices.get(self.mac_to_device_id[m_cand])
                    if dev and dev.get("ip"):
                        return dev["ip"]

            # 4. Fallback to Global ARP table by MAC
            for m_cand in candidate_macs:
                for ip, entry in self.global_arp.items():
                    if entry.get("mac") == m_cand and _extract_unicast_ip(ip):
                        return ip

            # 5. Local serial chassis-ID subtype (non-MAC, non-IP, non-placeholder serial)
            for raw_ser in (neighbor_mac, neighbor_name):
                s_clean = str(raw_ser or "").strip()
                if not s_clean or _extract_mac_from_text(s_clean) or _extract_unicast_ip(s_clean):
                    continue
                if is_placeholder_serial(s_clean):
                    continue
                ser_key = f"SER_{s_clean}"
                if ser_key in self.devices and self.devices[ser_key].get("ip"):
                    return self.devices[ser_key]["ip"]
                for dev in self.devices.values():
                    d_ser = str(dev.get("serial") or "").strip()
                    if d_ser and not is_placeholder_serial(d_ser) and d_ser.lower() == s_clean.lower():
                        if dev.get("ip"):
                            return dev["ip"]

            # 6. Short hostname lookup (guarded against generic defaults) + unique >=12-char prefix match
            if neighbor_name:
                short, _ = normalize_hostname(neighbor_name)
                if short and not is_generic_hostname(short):
                    low = short.lower()
                    for dev in self.devices.values():
                        ch = (dev.get("canonical_hostname") or dev.get("hostname") or "").strip()
                        if ch and ch.lower() == low and dev.get("ip"):
                            return dev["ip"]
                    if len(low) >= 12:
                        pfx_ips = [
                            dev["ip"]
                            for dev in self.devices.values()
                            if dev.get("ip")
                            and (dev.get("canonical_hostname") or dev.get("hostname") or "")
                            .strip()
                            .lower()
                            .startswith(low)
                        ]
                        if len(pfx_ips) == 1:
                            return pfx_ips[0]

            return None

    def add_bidirectional_link(
        self,
        local_node: str,
        local_port: str,
        remote_node: str,
        remote_port: str,
        link_type: str = "physical",
        link_class: str = "infra_uplink",
        transport_type: str = "",
        evidence: str = "",
        is_inferred: bool = False,
    ):
        """
        Stitches a connection between two nodes. Tracks observed directions (`a->b` vs `b->a`)
        so ONLY true reciprocal direct observations promote a link to `"confirmed"` / `"confirmed_lldp"`.
        """
        with self._lock:
            node_a, _ = normalize_hostname(local_node)
            node_b, _ = normalize_hostname(remote_node)
            port_a = normalize_interface(local_port)
            port_b = normalize_interface(remote_port)
            if port_a.lower() in ("unknown", "n/a", "-"):
                port_a = ""
            if port_b.lower() in ("unknown", "n/a", "-"):
                port_b = ""

            if not node_a or not node_b:
                return

            inferred = bool(
                is_inferred
                or link_type in ("mac_inferred", "l3_egress", "wan_carrier")
                or transport_type in ("mac_inferred", "l3_egress", "metro_ethernet", "wan_carrier")
                or evidence in ("mac_inferred", "l3_next_hop_egress", "wan_carrier_arp_route", "inferred")
            )

            # Canonical order (case-insensitive hostname comparison) for deduplication
            end_1 = (node_a.lower(), port_a.lower())
            end_2 = (node_b.lower(), port_b.lower())

            if end_1 > end_2:
                c_node_a, c_port_a, c_node_b, c_port_b = node_b, port_b, node_a, port_a
                obs_dir = "b->a"
            else:
                c_node_a, c_port_a, c_node_b, c_port_b = node_a, port_a, node_b, port_b
                obs_dir = "a->b"

            for existing in self.links:
                same_nodes = (
                    existing["node_a"].lower() == c_node_a.lower() and existing["node_b"].lower() == c_node_b.lower()
                )
                if not same_nodes:
                    continue

                ports_match = (
                    existing["port_a"].lower() == c_port_a.lower() and existing["port_b"].lower() == c_port_b.lower()
                )
                b_compatible = (
                    not existing["port_b"]
                    or not c_port_b
                    or (_is_mac_port(existing["port_b"]) != _is_mac_port(c_port_b))
                )
                a_compatible = (
                    not existing["port_a"]
                    or not c_port_a
                    or (_is_mac_port(existing["port_a"]) != _is_mac_port(c_port_a))
                )
                partial_port_match = (
                    bool(existing["port_a"]) and existing["port_a"].lower() == c_port_a.lower() and b_compatible
                ) or (bool(existing["port_b"]) and existing["port_b"].lower() == c_port_b.lower() and a_compatible)
                if ports_match or partial_port_match:
                    if (
                        (not existing["port_a"] or _is_mac_port(existing["port_a"]))
                        and c_port_a
                        and not _is_mac_port(c_port_a)
                    ):
                        existing["port_a"] = c_port_a
                    elif not existing["port_a"] and c_port_a:
                        existing["port_a"] = c_port_a
                    if (
                        (not existing["port_b"] or _is_mac_port(existing["port_b"]))
                        and c_port_b
                        and not _is_mac_port(c_port_b)
                    ):
                        existing["port_b"] = c_port_b
                    elif not existing["port_b"] and c_port_b:
                        existing["port_b"] = c_port_b

                    dirs = self._link_directions.setdefault(id(existing), set())
                    if not inferred:
                        dirs.add(obs_dir)

                    if len(dirs) >= 2:
                        existing["status"] = "confirmed"
                    elif not inferred and existing.get("status") == "inferred":
                        existing["status"] = "unidirectional"

                    if link_class == "infra_uplink":
                        existing["link_class"] = "infra_uplink"
                    if transport_type:
                        if not existing.get("transport_type") or (
                            transport_type == "direct_l2_uplink" and existing.get("transport_type") == "mac_inferred"
                        ):
                            existing["transport_type"] = transport_type

                    if (
                        len(dirs) >= 2
                        and existing.get("evidence") in ("", "unidirectional_lldp")
                        and evidence
                        in (
                            "",
                            "unidirectional_lldp",
                            "confirmed_lldp",
                        )
                    ):
                        if existing.get("evidence") == "unidirectional_lldp" or evidence in (
                            "unidirectional_lldp",
                            "confirmed_lldp",
                        ):
                            existing["evidence"] = "confirmed_lldp"
                    elif evidence and not existing.get("evidence"):
                        existing["evidence"] = evidence
                    return

            new_link = {
                "node_a": c_node_a,
                "port_a": c_port_a,
                "node_b": c_node_b,
                "port_b": c_port_b,
                "status": "inferred" if inferred else "unidirectional",
                "type": link_type,
                "link_class": link_class,
                "transport_type": transport_type,
                "evidence": evidence,
            }
            self.links.append(new_link)
            self._link_directions[id(new_link)] = set() if inferred else {obs_dir}

    def resolve_canonical_hostname(
        self,
        raw_name: str,
        remote_mac: str = "",
        remote_ip: str = "",
        remote_port: str = "",
    ) -> str:
        """
        Resolve a potentially truncated, FQDN, IP, MAC, or serial neighbor identifier
        to a registered device's canonical hostname. Thread-safe via re-entrant `self._lock`.
        """
        with self._lock:
            short, _ = normalize_hostname(raw_name)
            for ip_src in (remote_ip, remote_mac, raw_name):
                uip = _extract_unicast_ip(ip_src)
                if uip and uip in self.ip_to_device_id:
                    dev = self.devices.get(self.ip_to_device_id[uip])
                    if dev and dev.get("hostname"):
                        return dev["hostname"]
            for mac_src in (remote_mac, remote_port, raw_name):
                m_clean = _extract_mac_from_text(mac_src)
                if m_clean and not is_shared_or_virtual_mac(m_clean) and m_clean in self.mac_to_device_id:
                    dev = self.devices.get(self.mac_to_device_id[m_clean])
                    if dev and dev.get("hostname"):
                        return dev["hostname"]
            for ser_src in (remote_mac, raw_name):
                s_clean = str(ser_src or "").strip()
                if s_clean and not _extract_mac_from_text(s_clean) and not _extract_unicast_ip(s_clean):
                    if not is_placeholder_serial(s_clean):
                        ser_dev = self.devices.get(f"SER_{s_clean}")
                        if ser_dev and ser_dev.get("hostname"):
                            return ser_dev["hostname"]
            if short:
                low = short.lower()
                if not is_generic_hostname(short):
                    for dev in self.devices.values():
                        ch = (dev.get("canonical_hostname") or dev.get("hostname") or "").strip()
                        if ch and ch.lower() == low:
                            return ch
                    if len(low) >= 12:
                        prefix_matches = [
                            (dev.get("canonical_hostname") or dev.get("hostname") or "").strip()
                            for dev in self.devices.values()
                            if (dev.get("canonical_hostname") or dev.get("hostname") or "")
                            .strip()
                            .lower()
                            .startswith(low)
                        ]
                        if len(prefix_matches) == 1:
                            return prefix_matches[0]
            return short or raw_name

    @staticmethod
    def _needs_remote_port_resolution(r_port: str, r_host: str) -> bool:
        if not r_port:
            return True
        if _is_mac_port(r_port) or _is_numeric_ifindex(r_port):
            return True
        if r_host and (r_port.lower() == r_host.lower() or normalize_hostname(r_port)[0].lower() == r_host.lower()):
            return True
        if " " in r_port:
            return True
        return not is_clean_interface_token(r_port) and not _KNOWN_IF_WORD_RE.match(r_port)

    def _resolve_peer_port_from_telemetry(
        self, peer_dev: dict, local_host: str, l_port: str, nbr: dict, r_port: str, r_host: str
    ) -> tuple[str, bool]:
        """Resolve an opaque/prose/ifIndex `remote_port` against `peer_dev`'s LLDP neighbors and port descriptions."""
        # (a) Reciprocal LLDP neighbor pointing back to (local_host, l_port)
        reciprocal_candidates: list[dict] = []
        for pn in peer_dev.get("neighbors", []) or []:
            pn_canon = self.resolve_canonical_hostname(
                pn.get("remote_device", ""),
                remote_mac=pn.get("remote_mac", ""),
                remote_ip=pn.get("remote_ip", ""),
            )
            pn_host, _ = normalize_hostname(pn_canon or pn.get("remote_device", ""))
            if pn_host.lower() == local_host.lower():
                reciprocal_candidates.append(pn)

        for pn in reciprocal_candidates:
            if l_port and normalize_interface(pn.get("remote_port", "")).lower() == l_port.lower():
                cand_lp = normalize_interface(pn.get("local_port", ""))
                if cand_lp:
                    return cand_lp, True
        if len(reciprocal_candidates) == 1:
            cand_lp = normalize_interface(reciprocal_candidates[0].get("local_port", ""))
            if cand_lp:
                return cand_lp, True

        # (b) Description match against peer_dev["interfaces_detail"][p]["description"]
        ints_detail = peer_dev.get("interfaces_detail") or {}
        for raw_cand in (r_port, str(nbr.get("remote_port_description") or "").strip()):
            cand = (raw_cand or "").strip()
            if (
                not cand
                or len(cand) < 3
                or cand.lower() in ("unknown", "n/a", "-", r_host.lower())
                or _is_numeric_ifindex(cand)
            ):
                continue
            exact_matches: list[str] = []
            prefix_matches: list[str] = []
            cand_prefix = cand.rstrip(".").strip().lower()
            for pname, pinfo in ints_detail.items():
                pdesc = str((pinfo or {}).get("description") or "").strip()
                if not pdesc:
                    continue
                if pdesc.lower() == cand.lower():
                    exact_matches.append(normalize_interface(pname))
                elif len(cand_prefix) >= 10 and pdesc.lower().startswith(cand_prefix):
                    prefix_matches.append(normalize_interface(pname))
            if len(exact_matches) == 1:
                return exact_matches[0], bool(reciprocal_candidates)
            if len(prefix_matches) == 1:
                return prefix_matches[0], bool(reciprocal_candidates)

        return "", bool(reciprocal_candidates)

    def reconcile_reciprocal_neighbors(self, raw_devices: list[dict]) -> None:
        """
        Write resolved reciprocal `remote_port`, canonical `remote_device`, and
        `link_confidence` ('two-way' | 'one-way' | 'INFERRED') back into each device's `neighbors` list.
        """
        by_host = {}
        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            h, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
            if h:
                by_host[h.lower()] = dev

        pending_synth: list[tuple[dict, dict]] = []
        pending_synth_keys: set[tuple[int, str]] = set()

        with self._lock:
            for dev in raw_devices:
                local_host, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
                for nbr in list(dev.get("neighbors", [])):
                    if nbr.get("l2_accuracy") != "l3_next_hop_egress":
                        canon_r = self.resolve_canonical_hostname(
                            nbr.get("remote_device", ""),
                            remote_mac=nbr.get("remote_mac", ""),
                            remote_ip=nbr.get("remote_ip", ""),
                            remote_port=nbr.get("remote_port", ""),
                        )
                        if canon_r:
                            nbr["remote_device"] = canon_r
                    l_port = normalize_interface(nbr.get("local_port", ""))
                    r_host, _ = normalize_hostname(nbr.get("remote_device", ""))
                    r_port = normalize_interface(nbr.get("remote_port", ""))
                    if r_port.lower() in ("unknown", "n/a", "-"):
                        r_port = ""

                    peer_dev = by_host.get(r_host.lower())
                    has_reciprocal = False
                    if peer_dev and self._needs_remote_port_resolution(r_port, r_host):
                        resolved_peer_port, has_reciprocal = self._resolve_peer_port_from_telemetry(
                            peer_dev, local_host, l_port, nbr, r_port, r_host
                        )
                        if resolved_peer_port:
                            nbr["remote_port"] = resolved_peer_port
                            r_port = resolved_peer_port

                    matched_link = None
                    for lk in self.links:
                        a_match = lk["node_a"].lower() == local_host.lower() and lk["node_b"].lower() == r_host.lower()
                        b_match = lk["node_b"].lower() == local_host.lower() and lk["node_a"].lower() == r_host.lower()
                        if a_match and lk["port_a"].lower() == l_port.lower():
                            matched_link = (lk, lk["port_b"])
                            break
                        if b_match and lk["port_b"].lower() == l_port.lower():
                            matched_link = (lk, lk["port_a"])
                            break

                    is_already_inferred = (
                        str(nbr.get("link_confidence") or "").upper() == "INFERRED"
                        or nbr.get("l2_accuracy") in _PRESERVED_L2_ACCURACY
                    )

                    if matched_link:
                        lk, resolved_remote_port = matched_link
                        if self._needs_remote_port_resolution(r_port, r_host) and resolved_remote_port:
                            if not self._needs_remote_port_resolution(resolved_remote_port, r_host):
                                nbr["remote_port"] = resolved_remote_port
                                r_port = resolved_remote_port
                        if not is_already_inferred:
                            if lk["status"] == "confirmed" or has_reciprocal:
                                nbr["link_confidence"] = "two-way"
                            else:
                                nbr["link_confidence"] = "one-way"
                    elif not is_already_inferred:
                        nbr["link_confidence"] = "two-way" if has_reciprocal else nbr.get("link_confidence", "one-way")

                    # Defer synthesis of reverse neighbor on peer until after loop so INFERRED is never overwritten
                    if peer_dev and r_port and l_port and not is_already_inferred:
                        peer_ints = {
                            normalize_interface(k).lower(): k for k in (peer_dev.get("interfaces_detail") or {})
                        }
                        if r_port.lower() in peer_ints:
                            peer_port_exact = peer_ints[r_port.lower()]
                            already = any(
                                normalize_interface(pn.get("local_port", "")).lower() == r_port.lower()
                                for pn in peer_dev.get("neighbors", [])
                            )
                            synth_key = (id(peer_dev), r_port.lower())
                            if not already and synth_key not in pending_synth_keys:
                                pending_synth_keys.add(synth_key)
                                synth = {
                                    "local_port": peer_port_exact,
                                    "remote_device": local_host,
                                    "remote_port": l_port,
                                    "remote_ip": dev.get("ip", ""),
                                    "remote_mac": dev.get("mac_address", ""),
                                    "platform": f"{dev.get('vendor', '')} {dev.get('model', '')}".strip(),
                                    "remote_platform": f"{dev.get('vendor', '')} {dev.get('model', '')}".strip(),
                                    "device_type": dev.get("device_type", "switch"),
                                    "link_confidence": "INFERRED",
                                }
                                if nbr.get("transport_type"):
                                    synth["transport_type"] = nbr["transport_type"]
                                pending_synth.append((peer_dev, synth))

            for peer_dev, synth in pending_synth:
                peer_dev.setdefault("neighbors", []).append(synth)

    @staticmethod
    def _collect_device_maps(
        raw_devices: list[dict],
    ) -> tuple[
        dict[str, tuple[dict, str]],
        dict[int, set[str]],
        dict[str, dict],
        dict[int, list[tuple[str, netaddr.IPAddress, netaddr.IPNetwork]]],
        set[str],
    ]:
        mac_to_dev: dict[str, tuple[dict, str]] = {}
        dev_macs: dict[int, set[str]] = {}
        ip_to_dev: dict[str, dict] = {}
        dev_l3_nets: dict[int, list[tuple[str, netaddr.IPAddress, netaddr.IPNetwork]]] = {}
        crawled_ips: set[str] = set()

        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            d_key = id(dev)
            mac_set = dev_macs.setdefault(d_key, set())
            for intf_name, intf_info in (dev.get("interfaces_detail") or {}).items():
                imac = oui_lookup.normalize_mac((intf_info or {}).get("mac_address", "") or "").lower()
                if imac and not is_shared_or_virtual_mac(imac):
                    mac_to_dev.setdefault(imac, (dev, intf_name))
                    mac_set.add(imac)
            base_mac = oui_lookup.normalize_mac(dev.get("mac_address", "") or "").lower()
            if base_mac and not is_shared_or_virtual_mac(base_mac):
                mac_to_dev.setdefault(base_mac, (dev, ""))
                mac_set.add(base_mac)

            primary_ip = str(dev.get("ip") or "").strip()
            if primary_ip and not primary_ip.startswith(("127.", "128.0.")):
                ip_to_dev.setdefault(primary_ip, dev)
                crawled_ips.add(primary_ip)
            nets = dev_l3_nets.setdefault(d_key, [])
            for intf in dev.get("l3_interfaces", []) or []:
                ip_raw = str(intf.get("ip_address") or "").strip()
                ip_tok = ip_raw.split("/")[0].split()[0].strip()
                if (
                    ip_tok
                    and ip_tok not in ("N/A", "unassigned", "0.0.0.0")
                    and not ip_tok.startswith(("127.", "128.0."))
                ):
                    ip_to_dev.setdefault(ip_tok, dev)
                    crawled_ips.add(ip_tok)
                ip_obj, net_obj = _parse_ip_net(ip_raw)
                if ip_obj and net_obj:
                    nets.append((str(intf.get("interface") or "").strip(), ip_obj, net_obj))

        return mac_to_dev, dev_macs, ip_to_dev, dev_l3_nets, crawled_ips

    @staticmethod
    def _resolve_vlan_info(dev: dict, raw_vlan: str) -> tuple[str, str]:
        vlans = dev.get("vlans") or {}
        rv = str(raw_vlan or "").strip()
        if rv in vlans:
            vinfo = vlans[rv] or {}
            return rv, str(vinfo.get("name") or "")
        m_v = re.match(r"^(?:vlan|vl|irb)[_.-]?(\d+)$", rv, re.IGNORECASE)
        if m_v:
            vid = m_v.group(1)
            vinfo = vlans.get(vid, {}) or {}
            return vid, str(vinfo.get("name") or rv)
        for vid, vinfo in vlans.items():
            vname = str((vinfo or {}).get("name") or "")
            svi = str((vinfo or {}).get("svi_interface") or "")
            if rv and rv.lower() in (vname.lower(), svi.lower()):
                return str(vid), vname
        return (rv if rv.isdigit() else ""), rv

    def infer_mac_table_links(self, raw_devices: list[dict]) -> None:
        """
        For crawled infrastructure devices missing LLDP/CDP uplinks (including routers/firewalls
        behind shared vSwitches or switches with only AP neighbors), infer L2 switch attachment
        from crawled switch MAC forwarding tables when the switch port has no conflicting LLDP/CDP
        infra link or carrier Metro-E muxing.
        """
        from net_docu_crawler.drivers.detector import is_hypervisor_mac

        mac_to_dev, dev_macs, _, _, _ = self._collect_device_maps(raw_devices)

        # Precompute ports on each switch that carry carrier/Metro-E traffic or multi-VLAN L3 core muxing
        carrier_ports_by_sw: dict[int, set[str]] = {}
        for sw in raw_devices:
            if sw.get("status", "success") != "success" or _is_non_infra_device(sw) or not sw.get("mac_table"):
                continue
            c_ports: set[str] = set()
            port_core_peers: dict[str, set[int]] = {}
            port_core_vlans: dict[str, set[str]] = {}
            ints_detail = sw.get("interfaces_detail") or {}
            for entry in sw.get("mac_table", []):
                sw_port = (entry.get("interface") or entry.get("port") or "").strip()
                if not sw_port or sw_port.lower() in ("cpu", "self", "router", "switch"):
                    continue
                sw_port_norm = normalize_interface(sw_port).lower()
                p_desc = str((ints_detail.get(sw_port) or ints_detail.get(sw_port_norm) or {}).get("description") or "")
                vid, vname = self._resolve_vlan_info(sw, str(entry.get("vlan") or ""))
                if _CARRIER_KW_RE.search(f"{p_desc} {vname}"):
                    c_ports.add(sw_port_norm)
                emac = oui_lookup.normalize_mac(entry.get("mac", "") or "").lower()
                peer_tuple = mac_to_dev.get(emac)
                if peer_tuple and peer_tuple[0] is not sw and not is_hypervisor_mac(emac):
                    peer_d = peer_tuple[0]
                    has_infra = any(
                        (n.get("device_type") or "").lower() in _INFRA_DEV_TYPES
                        for n in (peer_d.get("neighbors") or [])
                    )
                    if has_infra and peer_d.get("l3_interfaces"):
                        port_core_peers.setdefault(sw_port_norm, set()).add(id(peer_d))
                        if vid or vname:
                            port_core_vlans.setdefault(sw_port_norm, set()).add(vid or vname.lower())
            for pn, pset in port_core_peers.items():
                if len(pset) >= 2 and len(port_core_vlans.get(pn, set())) >= 2:
                    c_ports.add(pn)
            carrier_ports_by_sw[id(sw)] = c_ports

        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            target_host, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
            if not target_host:
                continue

            dev_type = (dev.get("device_type") or "switch").lower()
            existing_nbrs = dev.get("neighbors") or []
            existing_peers = {
                normalize_hostname(n.get("remote_device", ""))[0].lower()
                for n in existing_nbrs
                if n.get("remote_device")
            }
            existing_infra_nbrs = [n for n in existing_nbrs if (n.get("device_type") or "").lower() in _INFRA_DEV_TYPES]
            existing_local_ports = {
                normalize_interface(n.get("local_port", "")).lower() for n in existing_nbrs if n.get("local_port")
            }

            target_macs = sorted(dev_macs.get(id(dev), set()))
            if not target_macs:
                continue

            linked_ports: set[str] = set()
            for sw in raw_devices:
                if (
                    sw is dev
                    or sw.get("status", "success") != "success"
                    or _is_non_infra_device(sw)
                    or not sw.get("mac_table")
                ):
                    continue
                sw_host, _ = normalize_hostname(sw.get("hostname") or sw.get("ip", ""))
                if not sw_host or sw_host.lower() in existing_peers:
                    continue

                # Ports on sw occupied by a real LLDP/CDP infra neighbor (or non-hypervisor physical neighbor)
                lldp_occupied_ports = {
                    normalize_interface(n.get("local_port", "")).lower()
                    for n in (sw.get("neighbors") or [])
                    if n.get("local_port")
                    and n.get("l2_accuracy") not in _PRESERVED_L2_ACCURACY
                    and (n.get("device_type") or "").lower() in _INFRA_DEV_TYPES
                }
                mac_inferred_ports = {
                    normalize_interface(n.get("local_port", "")).lower(): n
                    for n in (sw.get("neighbors") or [])
                    if n.get("local_port") and n.get("l2_accuracy") == "mac_inferred"
                }
                carrier_ports = carrier_ports_by_sw.get(id(sw), set())

                for entry in sw.get("mac_table", []):
                    emac = oui_lookup.normalize_mac(entry.get("mac", "") or "").lower()
                    if emac not in target_macs:
                        continue
                    sw_port = (entry.get("interface") or entry.get("port") or "").strip()
                    if not sw_port or sw_port.lower() in ("cpu", "self", "router", "switch"):
                        continue
                    sw_port_norm = normalize_interface(sw_port).lower()
                    if sw_port_norm in lldp_occupied_ports or sw_port_norm in carrier_ports:
                        continue

                    _, target_port = mac_to_dev[emac]
                    target_port_key = normalize_interface(target_port).lower() if target_port else "_base"
                    if target_port_key in linked_ports:
                        continue
                    if target_port and normalize_interface(target_port).lower() in existing_local_ports:
                        continue
                    if existing_infra_nbrs and (not target_port or dev_type not in ("router", "firewall", "switch")):
                        continue

                    # Allow multiple MAC-inferred VMs/routers on a shared virtual bridge port,
                    # but don't stack unrelated physical switches onto a single MAC-inferred access port.
                    prev_mi = mac_inferred_ports.get(sw_port_norm)
                    if prev_mi:
                        prev_mac = str(prev_mi.get("remote_mac") or "")
                        shared_bridge = (
                            is_hypervisor_mac(emac)
                            or (prev_mac and is_hypervisor_mac(prev_mac))
                            or dev_type in ("router", "firewall")
                        )
                        if not shared_bridge:
                            continue

                    note = "Inferred from switch MAC forwarding table (LLDP/CDP unavailable on peer)"
                    dev.setdefault("neighbors", []).append(
                        {
                            "local_port": target_port or "",
                            "remote_device": sw_host,
                            "remote_port": sw_port,
                            "remote_ip": sw.get("ip", ""),
                            "remote_mac": sw.get("mac_address", ""),
                            "platform": f"{sw.get('vendor', '')} {sw.get('model', '')}".strip(),
                            "remote_platform": f"{sw.get('vendor', '')} {sw.get('model', '')}".strip(),
                            "device_type": sw.get("device_type", "switch"),
                            "link_confidence": "INFERRED",
                            "l2_accuracy": "mac_inferred",
                            "l2_accuracy_note": note,
                            "transport_type": "mac_inferred",
                        }
                    )
                    sw.setdefault("neighbors", []).append(
                        {
                            "local_port": sw_port,
                            "remote_device": target_host,
                            "remote_port": target_port or "",
                            "remote_ip": dev.get("ip", ""),
                            "remote_mac": emac,
                            "platform": f"{dev.get('vendor', '')} {dev.get('model', '')}".strip(),
                            "remote_platform": f"{dev.get('vendor', '')} {dev.get('model', '')}".strip(),
                            "device_type": dev.get("device_type", "switch"),
                            "link_confidence": "INFERRED",
                            "l2_accuracy": "mac_inferred",
                            "l2_accuracy_note": note,
                            "transport_type": "mac_inferred",
                        }
                    )
                    self.add_bidirectional_link(
                        local_node=sw_host,
                        local_port=sw_port,
                        remote_node=target_host,
                        remote_port=target_port or "",
                        link_type="mac_inferred",
                        link_class="infra_uplink",
                        transport_type="mac_inferred",
                        evidence="mac_inferred",
                        is_inferred=True,
                    )
                    existing_peers.add(sw_host.lower())
                    linked_ports.add(target_port_key)
                    if not target_port:
                        break

    def _find_corroborated_wan_peer(
        self,
        hub: dict,
        hub_port: str,
        remote_core: dict,
        entry_vlan: str,
        hub_macs: set[str],
        dev_l3_nets: dict[int, list[tuple[str, netaddr.IPAddress, netaddr.IPNetwork]]],
    ) -> dict | None:
        """Verify reciprocal MAC learning and/or overlapping L3 transit subnet/ARP/routes between `hub` and `remote_core`."""
        rem_ints_detail = remote_core.get("interfaces_detail") or {}
        rem_lldp_ports = {
            normalize_interface(n.get("local_port", "")).lower()
            for n in (remote_core.get("neighbors") or [])
            if n.get("local_port")
            and n.get("l2_accuracy") not in _PRESERVED_L2_ACCURACY
            and (n.get("device_type") or "").lower() in _INFRA_DEV_TYPES
        }

        # (i) Reciprocal MAC learning of hub's MAC on remote_core
        rem_port = ""
        rem_port_score = -1
        for entry in remote_core.get("mac_table", []) or []:
            emac = oui_lookup.normalize_mac(entry.get("mac", "") or "").lower()
            if emac not in hub_macs:
                continue
            cand_p = (entry.get("interface") or entry.get("port") or "").strip()
            if not cand_p or cand_p.lower() in ("cpu", "self", "router", "switch"):
                continue
            cand_norm = normalize_interface(cand_p).lower()
            p_info = rem_ints_detail.get(cand_p) or rem_ints_detail.get(cand_norm) or {}
            is_up = str(p_info.get("status") or "").lower() == "up"
            no_lldp = cand_norm not in rem_lldp_ports
            score = (2 if no_lldp else 0) + (1 if is_up else 0)
            if score > rem_port_score:
                rem_port = cand_p
                rem_port_score = score

        # (ii) Shared L3 transit subnet (including unequal masks) or ARP/route next-hop
        h_nets = dev_l3_nets.get(id(hub), [])
        r_nets = dev_l3_nets.get(id(remote_core), [])
        matched_l3: (
            tuple[str, netaddr.IPAddress, netaddr.IPNetwork, str, netaddr.IPAddress, netaddr.IPNetwork] | None
        ) = None
        for h_if, h_ip, h_net in h_nets:
            for r_if, r_ip, r_net in r_nets:
                if h_ip != r_ip and (h_ip in r_net or r_ip in h_net):
                    matched_l3 = (h_if, h_ip, h_net, r_if, r_ip, r_net)
                    break
            if matched_l3:
                break

        hub_arp_ips = {
            str(a.get("ip") or "").strip(): normalize_interface(str(a.get("interface") or ""))
            for a in (hub.get("arp_table") or [])
            if a.get("ip")
        }
        rem_arp_ips = {
            str(a.get("ip") or "").strip(): str(a.get("interface") or "")
            for a in (remote_core.get("arp_table") or [])
            if a.get("ip")
        }
        hub_nhops = {str(r.get("next_hop") or "").strip() for r in (hub.get("routes") or []) if r.get("next_hop")}
        rem_nhops = {
            str(r.get("next_hop") or "").strip() for r in (remote_core.get("routes") or []) if r.get("next_hop")
        }

        arp_or_route_hit = False
        r_peer_ip = str(remote_core.get("ip") or "")
        h_peer_ip = str(hub.get("ip") or "")
        if matched_l3:
            h_if, h_ip, h_net, r_if, r_ip, r_net = matched_l3
            r_peer_ip = str(r_ip)
            h_peer_ip = str(h_ip)
            arp_or_route_hit = (
                r_peer_ip in hub_arp_ips or h_peer_ip in rem_arp_ips or r_peer_ip in hub_nhops or h_peer_ip in rem_nhops
            )
            if not rem_port and h_peer_ip in rem_arp_ips:
                m_br = re.search(r"\[([^\]]+)\]", rem_arp_ips[h_peer_ip])
                if m_br:
                    rem_port = normalize_interface(m_br.group(1))
        else:
            arp_or_route_hit = r_peer_ip in hub_arp_ips or r_peer_ip in hub_nhops

        if not rem_port and not matched_l3 and not arp_or_route_hit:
            return None

        transit_cidr = ""
        mask_mismatch = ""
        transit_vid, transit_vname = self._resolve_vlan_info(hub, entry_vlan)
        if matched_l3:
            h_if, _h_ip, h_net, r_if, _r_ip, r_net = matched_l3
            tighter = h_net if h_net.prefixlen >= r_net.prefixlen else r_net
            transit_cidr = f"{tighter.network}/{tighter.prefixlen}"
            if h_net.prefixlen != r_net.prefixlen:
                mask_mismatch = f"/{h_net.prefixlen} vs /{r_net.prefixlen}"
            if not transit_vid:
                transit_vid, t_vn = self._resolve_vlan_info(hub, h_if)
                if not transit_vname:
                    transit_vname = t_vn
            if not transit_vid:
                transit_vid, _ = self._resolve_vlan_info(remote_core, r_if)

        return {
            "rem_port": rem_port,
            "remote_ip": r_peer_ip,
            "hub_ip": h_peer_ip,
            "transit_cidr": transit_cidr,
            "mask_mismatch": mask_mismatch,
            "transit_vlan": transit_vid,
            "transit_vname": transit_vname,
        }

    def _infer_metro_e_wan_links(
        self,
        raw_devices: list[dict],
        mac_to_dev: dict[str, tuple[dict, str]],
        dev_macs: dict[int, set[str]],
        dev_l3_nets: dict[int, list[tuple[str, netaddr.IPAddress, netaddr.IPNetwork]]],
    ) -> None:
        # Two passes: Pass 1 handles multi-peer hub ports (>= 2 cores) so hub carrier descriptions always win;
        # Pass 2 handles single-peer carrier/WAN ports.
        for min_cores in (2, 1):
            for hub in raw_devices:
                if hub.get("status", "success") != "success" or _is_non_infra_device(hub) or not hub.get("mac_table"):
                    continue
                hub_host, _ = normalize_hostname(hub.get("hostname") or hub.get("ip", ""))
                if not hub_host:
                    continue
                hub_macs = dev_macs.get(id(hub), set())
                hub_ints = hub.get("interfaces_detail") or {}

                lldp_infra_ports = {
                    normalize_interface(n.get("local_port", "")).lower()
                    for n in (hub.get("neighbors") or [])
                    if n.get("local_port")
                    and n.get("l2_accuracy") not in _PRESERVED_L2_ACCURACY
                    and (n.get("device_type") or "").lower() in _INFRA_DEV_TYPES
                }
                existing_peers = {
                    normalize_hostname(n.get("remote_device", ""))[0].lower()
                    for n in (hub.get("neighbors") or [])
                    if n.get("remote_device")
                }

                # Group candidate remote L3 cores per hub port
                by_port: dict[str, dict[int, tuple[dict, str, str]]] = {}
                port_raw_name: dict[str, str] = {}
                for entry in hub.get("mac_table", []):
                    hp = (entry.get("interface") or entry.get("port") or "").strip()
                    if not hp or hp.lower() in ("cpu", "self", "router", "switch"):
                        continue
                    hp_norm = normalize_interface(hp).lower()
                    if hp_norm in lldp_infra_ports:
                        continue
                    emac = oui_lookup.normalize_mac(entry.get("mac", "") or "").lower()
                    peer_tuple = mac_to_dev.get(emac)
                    if not peer_tuple or peer_tuple[0] is hub or _is_non_infra_device(peer_tuple[0]):
                        continue
                    rem_dev = peer_tuple[0]
                    rem_host, _ = normalize_hostname(rem_dev.get("hostname") or rem_dev.get("ip", ""))
                    if not rem_host or rem_host.lower() in existing_peers:
                        continue
                    is_l3_core = bool(dev_l3_nets.get(id(rem_dev))) or (rem_dev.get("device_type") or "").lower() in (
                        "router",
                        "firewall",
                    )
                    if not is_l3_core:
                        continue
                    port_raw_name.setdefault(hp_norm, hp)
                    by_port.setdefault(hp_norm, {}).setdefault(
                        id(rem_dev), (rem_dev, emac, str(entry.get("vlan") or ""))
                    )

                for hp_norm, peers_map in by_port.items():
                    if len(peers_map) < min_cores:
                        continue
                    hub_port = port_raw_name[hp_norm]
                    hub_pdesc = str(
                        (hub_ints.get(hub_port) or hub_ints.get(hp_norm) or {}).get("description") or ""
                    ).strip()

                    if min_cores == 1:
                        _, _, sample_vlan = next(iter(peers_map.values()))
                        _, sample_vname = self._resolve_vlan_info(hub, sample_vlan)
                        if not _CARRIER_KW_RE.search(f"{hub_pdesc} {sample_vname}"):
                            continue
                    else:
                        vlan_tags = {
                            self._resolve_vlan_info(hub, v)[0] or self._resolve_vlan_info(hub, v)[1].lower()
                            for (_, _, v) in peers_map.values()
                            if v
                        }
                        vlan_blob = " ".join(self._resolve_vlan_info(hub, v)[1] for (_, _, v) in peers_map.values())
                        if not _CARRIER_KW_RE.search(f"{hub_pdesc} {vlan_blob}") and len(vlan_tags) < 2:
                            continue

                    for rem_dev, rem_mac, entry_vlan in peers_map.values():
                        rem_host, _ = normalize_hostname(rem_dev.get("hostname") or rem_dev.get("ip", ""))
                        if rem_host.lower() in existing_peers:
                            continue
                        corr = self._find_corroborated_wan_peer(
                            hub, hub_port, rem_dev, entry_vlan, hub_macs, dev_l3_nets
                        )
                        if not corr:
                            continue
                        if not corr["rem_port"] and not _CARRIER_KW_RE.search(f"{hub_pdesc} {corr['transit_vname']}"):
                            # Without a reciprocal switch MAC or carrier label, only treat as WAN if transit is routed P2P
                            t_cidr = corr["transit_cidr"]
                            is_p2p = bool(t_cidr and t_cidr.endswith(("/30", "/31")))
                            if not is_p2p:
                                continue

                        rem_port = corr["rem_port"]
                        rem_ints = rem_dev.get("interfaces_detail") or {}
                        rem_pdesc = str((rem_ints.get(rem_port) or {}).get("description") or "").strip()
                        desc_src = hub_pdesc or rem_pdesc
                        _, rem_vname = self._resolve_vlan_info(rem_dev, corr["transit_vlan"])
                        if "spectrum metro ethernet" in desc_src.lower():
                            carrier_cloud = "Spectrum Metro Ethernet"
                        elif _CARRIER_KW_RE.search(desc_src):
                            carrier_cloud = (
                                re.sub(r"\s+to\s+.*$", "", desc_src, flags=re.IGNORECASE).strip() or desc_src
                            )
                        else:
                            carrier_cloud = "Carrier Metro-E / WAN"

                        kw_blob = f"{desc_src} {corr['transit_vname']} {rem_vname}".lower()
                        transport_type = (
                            "metro_ethernet"
                            if any(
                                k in kw_blob
                                for k in ("metro", "ethernet", "spectrum", "spectrun", "comcast", "mpls", "carrier")
                            )
                            else "wan_carrier"
                        )
                        detail_tag = corr["transit_cidr"] or (
                            f"VLAN {corr['transit_vlan']}" if corr["transit_vlan"] else "ARP+MAC"
                        )
                        note = f"LLDP stripped across {carrier_cloud}; corroborated via MAC table, ARP & L3 transit ({detail_tag})"

                        shared_meta = {
                            "link_confidence": "INFERRED",
                            "l2_accuracy": "wan_carrier_arp_route",
                            "transport_type": transport_type,
                            "carrier_cloud": carrier_cloud,
                            "transit_vlan": corr["transit_vlan"],
                            "transit_cidr": corr["transit_cidr"],
                            "mask_mismatch": corr["mask_mismatch"],
                            "l2_accuracy_note": note,
                            "confidence_tier": "verified-telemetry",
                            "is_verified": True,
                            "blind_spot": False,
                        }
                        hub.setdefault("neighbors", []).append(
                            {
                                "local_port": hub_port,
                                "remote_device": rem_host,
                                "remote_port": rem_port,
                                "remote_ip": corr["remote_ip"],
                                "remote_mac": rem_mac,
                                "platform": f"{rem_dev.get('vendor', '')} {rem_dev.get('model', '')}".strip(),
                                "remote_platform": f"{rem_dev.get('vendor', '')} {rem_dev.get('model', '')}".strip(),
                                "device_type": rem_dev.get("device_type", "switch"),
                                **shared_meta,
                            }
                        )
                        rem_dev.setdefault("neighbors", []).append(
                            {
                                "local_port": rem_port,
                                "remote_device": hub_host,
                                "remote_port": hub_port,
                                "remote_ip": corr["hub_ip"],
                                "remote_mac": hub.get("mac_address", ""),
                                "platform": f"{hub.get('vendor', '')} {hub.get('model', '')}".strip(),
                                "remote_platform": f"{hub.get('vendor', '')} {hub.get('model', '')}".strip(),
                                "device_type": hub.get("device_type", "switch"),
                                **shared_meta,
                            }
                        )
                        self.add_bidirectional_link(
                            local_node=hub_host,
                            local_port=hub_port,
                            remote_node=rem_host,
                            remote_port=rem_port,
                            link_type="wan_carrier",
                            link_class="infra_uplink",
                            transport_type=transport_type,
                            evidence="wan_carrier_arp_route",
                        )
                        existing_peers.add(rem_host.lower())

    @staticmethod
    def _find_isp_handoff(dev: dict, fw_port: str, fw_vlan: str, fw_mac: str, fw_vendor: str) -> dict | None:
        vlans = dev.get("vlans") or {}
        ints_detail = dev.get("interfaces_detail") or {}
        mac_table = dev.get("mac_table") or []
        fw_prefix = fw_mac[:14] if len(fw_mac) >= 14 else ""

        for vid, vinfo in vlans.items():
            vname = str((vinfo or {}).get("name") or "").strip()
            if str(vid) == str(fw_vlan) or not vname:
                continue
            if not re.search(r"\b(?:isp|internet|wan|untrust|spectrum|comcast|att|at&t)\b", vname, re.IGNORECASE):
                continue

            entries = []
            for entry in mac_table:
                e_vlan = str(entry.get("vlan") or "").strip()
                if e_vlan != str(vid) and e_vlan.lower() != vname.lower():
                    continue
                port = (entry.get("interface") or entry.get("port") or "").strip()
                if not port or port.lower() in ("cpu", "self", "router", "switch"):
                    continue
                if normalize_interface(port).lower() == normalize_interface(fw_port).lower():
                    continue
                emac = oui_lookup.normalize_mac(entry.get("mac", "") or "").lower()
                evend = oui_lookup.lookup_oui(emac) if emac else "Unknown"
                pdesc = str((ints_detail.get(port) or {}).get("description") or "").strip()
                entries.append((port, emac, evend, pdesc))

            if not entries:
                continue

            fw_untrust_port = ""
            for port, emac, evend, _pdesc in entries:
                if (fw_prefix and emac.startswith(fw_prefix)) or (fw_vendor != "Unknown" and evend == fw_vendor):
                    fw_untrust_port = port
                    break
            if not fw_untrust_port:
                for port, _emac, _evend, pdesc in entries:
                    if _FW_KW_RE.search(pdesc) and "test" not in pdesc.lower():
                        fw_untrust_port = port
                        break

            isp_cand = None
            for item in entries:
                port, _emac, _evend, pdesc = item
                if port == fw_untrust_port:
                    continue
                if re.search(r"\b(?:isp|internet|spectrum|comcast|att|at&t|nid|circuit|wan)\b", pdesc, re.IGNORECASE):
                    isp_cand = item
                    break
            if not isp_cand:
                for item in entries:
                    port, _emac, evend, pdesc = item
                    if port == fw_untrust_port or "test" in pdesc.lower():
                        continue
                    if evend not in ("Unknown", "Super Micro Computer, Inc."):
                        isp_cand = item
                        break

            if isp_cand:
                isp_port, isp_mac, isp_vendor, isp_desc = isp_cand
                return {
                    "isp_port": isp_port,
                    "isp_label": isp_desc or vname,
                    "isp_mac": isp_mac,
                    "isp_vendor": isp_vendor,
                    "fw_untrust_port": fw_untrust_port,
                    "vlan_id": str(vid),
                }
        return None

    def _infer_perimeter_gateway_links(self, raw_devices: list[dict], crawled_ips: set[str]) -> None:
        gw_names_by_ip: dict[str, str] = {}
        used_names: set[str] = set()

        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            dev_host, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
            if not dev_host:
                continue

            ints_detail = dev.get("interfaces_detail") or {}
            lldp_infra_ports = {
                normalize_interface(n.get("local_port", "")).lower()
                for n in (dev.get("neighbors") or [])
                if n.get("local_port")
                and n.get("l2_accuracy") not in _PRESERVED_L2_ACCURACY
                and (n.get("device_type") or "").lower() in _INFRA_DEV_TYPES
            }

            for route in dev.get("routes", []) or []:
                if str(route.get("subnet") or "").strip() != "0.0.0.0/0":
                    continue
                next_hop = str(route.get("next_hop") or "").strip()
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", next_hop) or next_hop in crawled_ips:
                    continue

                fw_mac = ""
                arp_intf = ""
                for arp in dev.get("arp_table", []) or []:
                    if str(arp.get("ip") or "").strip() == next_hop:
                        fw_mac = oui_lookup.normalize_mac(arp.get("mac", "") or "").lower()
                        arp_intf = str(arp.get("interface") or "").strip()
                        break
                if not fw_mac or fw_mac == "00:00:00:00:00:00":
                    continue

                fw_port = ""
                fw_vlan = str(route.get("interface") or "").strip()
                for entry in dev.get("mac_table", []) or []:
                    emac = oui_lookup.normalize_mac(entry.get("mac", "") or "").lower()
                    if emac == fw_mac:
                        cand_p = (entry.get("interface") or entry.get("port") or "").strip()
                        if cand_p and cand_p.lower() not in ("cpu", "self", "router", "switch"):
                            fw_port = cand_p
                            if entry.get("vlan"):
                                fw_vlan = str(entry.get("vlan")).strip()
                            break
                if not fw_port and arp_intf:
                    m_br = re.search(r"\[([^\]]+)\]", arp_intf)
                    cand_p = normalize_interface(m_br.group(1) if m_br else arp_intf)
                    if cand_p in ints_detail or cand_p.lower() in {k.lower() for k in ints_detail}:
                        fw_port = cand_p
                if not fw_port:
                    continue

                fw_port_norm = normalize_interface(fw_port).lower()
                if fw_port_norm in lldp_infra_ports:
                    continue
                already = any(
                    n.get("remote_ip") == next_hop or (n.get("remote_mac") or "").lower() == fw_mac
                    for n in (dev.get("neighbors") or [])
                )
                if already:
                    continue

                oui_vendor = oui_lookup.lookup_oui(fw_mac)
                fw_vid, fw_vname = self._resolve_vlan_info(dev, fw_vlan)
                fw_pdesc = str(
                    (ints_detail.get(fw_port) or ints_detail.get(fw_port_norm) or {}).get("description") or ""
                )
                role = "firewall" if _FW_KW_RE.search(f"{oui_vendor} {fw_vname} {fw_pdesc}") else "router"

                if next_hop in gw_names_by_ip:
                    gw_host = gw_names_by_ip[next_hop]
                else:
                    base_name = "Perimeter-Firewall" if role == "firewall" else "Default-Gateway"
                    gw_host = base_name if base_name not in used_names else f"{base_name}-{next_hop.replace('.', '-')}"
                    gw_names_by_ip[next_hop] = gw_host
                    used_names.add(gw_host)

                plat = oui_vendor if oui_vendor != "Unknown" else f"Uncrawled {role.title()}"
                note = f"Default route 0.0.0.0/0 -> {next_hop} resolved via ARP ({fw_mac}) and MAC table port {fw_port}"
                nbr_rec: dict = {
                    "local_port": fw_port,
                    "remote_device": gw_host,
                    "remote_port": "",
                    "remote_ip": next_hop,
                    "remote_mac": fw_mac,
                    "platform": plat,
                    "remote_platform": plat,
                    "device_type": role,
                    "link_confidence": "INFERRED",
                    "transport_type": "l3_egress",
                    "l2_accuracy": "l3_next_hop_egress",
                    "l2_accuracy_note": note,
                    "route_prefix": "0.0.0.0/0",
                    "transit_vlan": fw_vid or fw_vlan,
                    "confidence_tier": "verified-telemetry",
                    "is_verified": True,
                    "blind_spot": False,
                }
                isp_handoff = self._find_isp_handoff(dev, fw_port, fw_vid or fw_vlan, fw_mac, oui_vendor)
                if isp_handoff:
                    nbr_rec["isp_handoff"] = isp_handoff

                dev.setdefault("neighbors", []).append(nbr_rec)
                self.add_bidirectional_link(
                    local_node=dev_host,
                    local_port=fw_port,
                    remote_node=gw_host,
                    remote_port="",
                    link_type="l3_egress",
                    link_class="infra_uplink",
                    transport_type="l3_egress",
                    evidence="l3_next_hop_egress",
                )
                break

    def _infer_edge_only_fallback_links(self, raw_devices: list[dict], crawled_ips: set[str]) -> None:
        """
        Synthesize candidate ``[Metro-E]`` and ``[L3 Egress]`` neighbor records when
        core/hub CLI/SSH telemetry (MAC table, ARP cache, RIB) is missing or partial.
        Never fabricates verified edges when evidence is absent or conflicting.
        """
        carrier_cands: list[tuple[dict, str, str, str, str, bool]] = []
        egress_cands: list[tuple[dict, str, str, str, str, bool]] = []

        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            dev_host, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
            if not dev_host:
                continue
            existing_nbrs = dev.get("neighbors") or []
            if any(n.get("l2_accuracy") in ("wan_carrier_arp_route", "l3_next_hop_egress") for n in existing_nbrs):
                continue

            def_routes = []
            for rt in dev.get("routes", []) or []:
                sub = str(rt.get("subnet") or "").strip()
                nh = str(rt.get("next_hop") or "").strip()
                if sub not in ("0.0.0.0/0", "::/0") or not nh or nh in ("0.0.0.0", "::"):
                    continue
                try:
                    netaddr.IPAddress(nh)
                    def_routes.append(rt)
                except (netaddr.AddrFormatError, ValueError):
                    continue

            distinct_nhs = {str(r.get("next_hop") or "").strip() for r in def_routes}
            if len(distinct_nhs) != 1:
                continue
            rt = def_routes[0]
            nh = str(rt.get("next_hop") or "").strip()
            if nh in crawled_ips:
                continue

            arp_hit = any(str(a.get("ip") or "").strip() == nh for a in (dev.get("arp_table") or []))
            nh_obj = netaddr.IPAddress(nh)
            local_match = False
            for intf in dev.get("l3_interfaces", []) or []:
                ip_raw = str(intf.get("ip_address") or "").strip()
                if not ip_raw or "/" not in ip_raw:
                    continue
                try:
                    snet = netaddr.IPNetwork(ip_raw.split()[0])
                    if snet.version == nh_obj.version and nh_obj in snet:
                        local_match = True
                        break
                except (netaddr.AddrFormatError, ValueError):
                    continue
            if not arp_hit and not local_match:
                continue

            rt_intf = str(rt.get("interface") or "").strip()
            ints_detail = dev.get("interfaces_detail") or {}
            pdesc = str((ints_detail.get(rt_intf) or {}).get("description") or "")
            vid, vname = self._resolve_vlan_info(dev, rt_intf)
            kw_blob = f"{rt_intf} {pdesc} {vname}"
            if _CARRIER_KW_RE.search(kw_blob) and "metro" in kw_blob.lower():
                carrier_cands.append((dev, dev_host, nh, rt_intf, vid, arp_hit))
            else:
                egress_cands.append((dev, dev_host, nh, rt_intf, vid, arp_hit))

        if len(carrier_cands) >= 2:
            for dev, _dev_host, nh, rt_intf, vid, arp_hit in carrier_cands:
                ev = "inferred_arp_route" if arp_hit else "inferred_route_only"
                tier = "inferred-arp-route" if arp_hit else "inferred-route-only"
                dev.setdefault("neighbors", []).append(
                    {
                        "local_port": rt_intf or "wan",
                        "remote_device": "Uncrawled-Core-Hub",
                        "remote_port": "",
                        "remote_ip": nh,
                        "device_type": "router",
                        "link_confidence": "INFERRED",
                        "transport_type": "metro_ethernet",
                        "evidence": ev,
                        "confidence_tier": tier,
                        "is_verified": False,
                        "blind_spot": True,
                        "blind_spot_reason": "missing_core_telemetry",
                        "l2_accuracy": "wan_carrier_arp_route",
                        "carrier_cloud": "Carrier Metro-E (Inferred)",
                        "transit_vlan": vid,
                        "l2_accuracy_note": f"Fallback [Metro-E] candidate from edge route -> {nh} (core telemetry missing)",
                    }
                )
        else:
            egress_cands.extend(carrier_cands)

        for dev, dev_host, nh, rt_intf, vid, arp_hit in egress_cands:
            ev = "inferred_arp_route" if arp_hit else "inferred_route_only"
            tier = "inferred-arp-route" if arp_hit else "inferred-route-only"
            gw_name = f"Default-Gateway ({nh})"
            dev.setdefault("neighbors", []).append(
                {
                    "local_port": rt_intf or "wan",
                    "remote_device": gw_name,
                    "remote_port": "",
                    "remote_ip": nh,
                    "device_type": "router",
                    "link_confidence": "INFERRED",
                    "transport_type": "l3_egress",
                    "evidence": ev,
                    "confidence_tier": tier,
                    "is_verified": False,
                    "blind_spot": True,
                    "blind_spot_reason": "missing_core_telemetry",
                    "l2_accuracy": "l3_next_hop_egress",
                    "route_prefix": "::/0" if ":" in nh else "0.0.0.0/0",
                    "transit_vlan": vid,
                    "l2_accuracy_note": f"Fallback [L3 Egress] candidate from edge route -> {nh} (gateway telemetry missing)",
                }
            )
            self.add_bidirectional_link(
                local_node=dev_host,
                local_port=rt_intf or "wan",
                remote_node=gw_name,
                remote_port="",
                link_type="l3_egress",
                link_class="infra_uplink",
                transport_type="l3_egress",
                evidence=ev,
            )

    def infer_wan_and_gateway_links(self, raw_devices: list[dict]) -> None:
        """
        Synthesize telemetry-verified inter-site WAN / Metro-E links (`wan_carrier_arp_route`),
        uncrawled Perimeter Firewall / default-gateway egress links (`l3_next_hop_egress`),
        and deterministic edge-only fallback candidates when core telemetry is missing.
        """
        mac_to_dev, dev_macs, _ip_to_dev, dev_l3_nets, crawled_ips = self._collect_device_maps(raw_devices)
        self._infer_metro_e_wan_links(raw_devices, mac_to_dev, dev_macs, dev_l3_nets)
        self._infer_perimeter_gateway_links(raw_devices, crawled_ips)
        self._infer_edge_only_fallback_links(raw_devices, crawled_ips)

    def detect_l2_anomalies(self, raw_devices: list[dict]) -> None:
        """
        Annotate neighbors that show signs of virtual bridge / LLDP-passthrough transit:
        1. Multiple distinct remote devices learned on a single physical local_port.
        2. Neighbor MAC addresses belonging to hypervisor virtual NICs (Proxmox, QEMU/KVM, VMware, etc.).
        """
        from net_docu_crawler.drivers.detector import is_hypervisor_mac

        crawled_mac_by_host: dict[str, str] = {}
        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            h, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
            if h and dev.get("mac_address"):
                crawled_mac_by_host[h.lower()] = dev["mac_address"]

        for dev in raw_devices:
            if dev.get("status", "success") != "success" or _is_non_infra_device(dev):
                continue
            port_peers: dict[str, set[str]] = {}
            for nbr in dev.get("neighbors", []):
                if nbr.get("l2_accuracy") in _PRESERVED_L2_ACCURACY:
                    continue
                lp = normalize_interface(nbr.get("local_port", "")).lower()
                rp_host, _ = normalize_hostname(nbr.get("remote_device", ""))
                if lp and rp_host:
                    port_peers.setdefault(lp, set()).add(rp_host.lower())

            for nbr in dev.get("neighbors", []):
                if nbr.get("l2_accuracy") in _PRESERVED_L2_ACCURACY:
                    continue
                lp = normalize_interface(nbr.get("local_port", "")).lower()
                rp_host, _ = normalize_hostname(nbr.get("remote_device", ""))
                rmac = nbr.get("remote_mac", "") or crawled_mac_by_host.get(rp_host.lower(), "")
                if lp and len(port_peers.get(lp, set())) >= 2:
                    nbr["l2_accuracy"] = "multi_neighbor_port"
                    nbr["l2_accuracy_note"] = (
                        "Multiple LLDP/CDP neighbors on one port (unmanaged switch or L2 passthrough transit hop)"
                    )
                elif rmac and is_hypervisor_mac(rmac):
                    nbr["l2_accuracy"] = "virtual_passthrough"
                    nbr["l2_accuracy_note"] = (
                        "Hypervisor/VM virtual NIC; physical path traverses host vSwitch/bridge (possible LLDP passthrough)"
                    )

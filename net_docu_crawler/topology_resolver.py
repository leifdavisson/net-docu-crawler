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
    r"^(?:(?:ge|mge|xe|et|fe|ae)-?\d+(?:/\d+)*(?::\d+)?|ae\d+"
    r"|(?:Gi|Te|Fa|Eth|Ethernet|Tw|Fo|Hu|GigabitEthernet|TenGigabitEthernet|FastEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE)\d+(?:/\d+)*"
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
    "openwrt",
    "opnsense",
    "mikrotik",
    "router",
    "switch",
    "localhost",
    "frr",
    "frr-router",
    "fortigate",
    "firewall",
}


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
      'Ethernet1/1' -> 'Eth1/1'
    """
    if not intf:
        return ""
    name = intf.strip().strip('"').strip("'")

    # Cisco / Arista interface abbreviations
    name = re.sub(r"^GigabitEthernet", "Gi", name, flags=re.IGNORECASE)
    name = re.sub(r"^TenGigabitEthernet", "Te", name, flags=re.IGNORECASE)
    name = re.sub(r"^FastEthernet", "Fa", name, flags=re.IGNORECASE)
    name = re.sub(r"^Ethernet(?=\d)", "Eth", name, flags=re.IGNORECASE)
    name = re.sub(r"^TwentyFiveGigE", "25GE", name, flags=re.IGNORECASE)
    name = re.sub(r"^FortyGigabitEthernet", "Fo", name, flags=re.IGNORECASE)
    name = re.sub(r"^HundredGigE", "Hu", name, flags=re.IGNORECASE)

    # Junos sub-interface strip e.g. ge-0/0/1.0 -> ge-0/0/1
    name = re.sub(r"\.0$", "", name)

    return name


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


class DeviceRegistry:
    """
    Thread-safe Central Device & Topology Registry.
    Tracks devices by verified hardware Serial Number and Base MAC to avoid duplicate crawls
    when switches have multiple SVIs, loopbacks, or VRF interfaces, while preventing false
    collisions across cloned VMs, LXC containers, or factory-default routers.
    """

    def __init__(self):
        self._lock = threading.Lock()
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

    def register_device(self, device_data: dict) -> str:
        """
        Registers a crawled device, linking all its SVIs, MACs, and hostnames to a single canonical entity.
        Rejects placeholder virtual serials and factory-default hostnames so cloned VMs/containers never collide.
        Returns the canonical device_id.
        """
        with self._lock:
            short_host, fqdn = normalize_hostname(device_data.get("hostname", ""))
            serial = device_data.get("serial", "").strip()
            base_mac = oui_lookup.normalize_mac(device_data.get("mac_address", "")).lower().strip()
            primary_ip = device_data.get("ip", "")

            has_valid_serial = bool(serial) and serial.lower() not in PLACEHOLDER_SERIALS
            has_unique_host = bool(short_host) and short_host.lower() not in GENERIC_DEFAULT_HOSTNAMES

            # Determine primary unique key: Verified Serial > Base MAC > Unique Hostname > IP
            if has_valid_serial:
                device_id = f"SER_{serial}"
            elif base_mac and base_mac != "00:00:00:00:00:00":
                device_id = f"MAC_{base_mac.replace(':', '').replace('.', '')}"
            elif has_unique_host:
                cand_id = f"HOST_{short_host}"
                existing = self.devices.get(cand_id)
                if existing and existing.get("ip") != primary_ip:
                    device_id = f"HOST_{short_host}_{primary_ip}"
                else:
                    device_id = cand_id
            else:
                device_id = f"IP_{primary_ip}"

            # Store FQDN mapping
            if short_host and fqdn:
                self.fqdn_table[short_host] = fqdn

            # Register all L3 interfaces (SVIs, Loopbacks, Routed Ports) to this device_id
            if primary_ip:
                self.ip_to_device_id[primary_ip] = device_id
            for intf in device_data.get("l3_interfaces", []):
                ip_raw = intf.get("ip_address", "")
                ip_clean = ip_raw.split("/")[0].split()[0].strip()
                if (
                    ip_clean
                    and ip_clean not in ("N/A", "unassigned", "0.0.0.0")
                    and not ip_clean.startswith(("127.", "128.0."))
                ):
                    self.ip_to_device_id[ip_clean] = device_id

            # Register base MAC and any per-interface MACs
            if base_mac:
                self.mac_to_device_id[base_mac] = device_id
            for stats in device_data.get("interfaces_detail", {}).values():
                imac = oui_lookup.normalize_mac(stats.get("mac_address", "")).lower().strip()
                if imac and imac != "00:00:00:00:00:00":
                    self.mac_to_device_id[imac] = device_id

            # Ingest device ARP entries into global ARP table
            for arp in device_data.get("arp_table", []):
                a_ip = arp.get("ip", "")
                a_mac = oui_lookup.normalize_mac(arp.get("mac", "")).lower().strip()
                if a_ip and a_mac:
                    self.global_arp[a_ip] = {
                        "mac": a_mac,
                        "vendor": arp.get("vendor") or oui_lookup.lookup_oui(a_mac),
                        "discovered_on": primary_ip,
                    }

            # Store or update the canonical record
            device_data["canonical_id"] = device_id
            device_data["canonical_hostname"] = short_host
            device_data["fqdn"] = fqdn
            self.devices[device_id] = device_data
            self.in_progress_ips.discard(primary_ip)

            return device_id

    def get_arp_mac(self, ip: str) -> str:
        """Return a previously harvested ARP MAC address for `ip`, or '' if unknown."""
        with self._lock:
            entry = self.global_arp.get(ip)
            return entry.get("mac", "") if entry else ""

    def resolve_neighbor_ip(self, neighbor_mac: str = "", neighbor_name: str = "") -> str | None:
        """
        Resolves a neighbor's IPv4 address when LLDP only provides a MAC address or system name (e.g. Junos).
        Searches the Global ARP table and registered Device Registry.
        """
        with self._lock:
            mac_clean = oui_lookup.normalize_mac(neighbor_mac).lower().strip() if neighbor_mac else ""
            # 1. Direct match in Global ARP
            if mac_clean:
                for ip, entry in self.global_arp.items():
                    if entry.get("mac") == mac_clean:
                        return ip

            # 2. Match in known Device Registry by MAC
            if mac_clean and mac_clean in self.mac_to_device_id:
                dev_id = self.mac_to_device_id[mac_clean]
                dev = self.devices.get(dev_id)
                if dev:
                    return dev.get("ip")

            # 3. Match by short hostname
            if neighbor_name:
                short, _ = normalize_hostname(neighbor_name)
                for dev in self.devices.values():
                    if dev.get("canonical_hostname", "").lower() == short.lower():
                        return dev.get("ip")

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
    ):
        """
        Stitches a connection between two nodes. Normalizes hostnames and interface names so
        (A, port1, B, port2) and (B, port2, A, port1) resolve to a single confirmed edge.
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

            # Canonical order (case-insensitive hostname comparison) for deduplication
            end_1 = (node_a.lower(), port_a.lower())
            end_2 = (node_b.lower(), port_b.lower())

            if end_1 > end_2:
                c_node_a, c_port_a, c_node_b, c_port_b = node_b, port_b, node_a, port_a
            else:
                c_node_a, c_port_a, c_node_b, c_port_b = node_a, port_a, node_b, port_b

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
                partial_port_match = (existing["port_a"].lower() == c_port_a.lower() and b_compatible) or (
                    existing["port_b"].lower() == c_port_b.lower() and a_compatible
                )
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
                    existing["status"] = "confirmed"
                    if link_class == "infra_uplink":
                        existing["link_class"] = "infra_uplink"
                    if transport_type:
                        if not existing.get("transport_type") or (
                            transport_type == "direct_l2_uplink" and existing.get("transport_type") == "mac_inferred"
                        ):
                            existing["transport_type"] = transport_type
                    if existing.get("evidence") in ("", "unidirectional_lldp") and evidence in (
                        "",
                        "unidirectional_lldp",
                        "confirmed_lldp",
                    ):
                        if existing.get("evidence") == "unidirectional_lldp" or evidence in (
                            "unidirectional_lldp",
                            "confirmed_lldp",
                        ):
                            existing["evidence"] = "confirmed_lldp"
                    elif evidence and not existing.get("evidence"):
                        existing["evidence"] = evidence
                    return

            self.links.append(
                {
                    "node_a": c_node_a,
                    "port_a": c_port_a,
                    "node_b": c_node_b,
                    "port_b": c_port_b,
                    "status": "unidirectional",
                    "type": link_type,
                    "link_class": link_class,
                    "transport_type": transport_type,
                    "evidence": evidence,
                }
            )

    def resolve_canonical_hostname(self, raw_name: str, remote_mac: str = "", remote_ip: str = "") -> str:
        """
        Resolve a potentially truncated or FQDN neighbor name (e.g. 'NMS_MDF_CORE_BL')
        to a registered device's canonical hostname ('NMS_MDF_CORE_BLDG_B').
        """
        short, _ = normalize_hostname(raw_name)
        if remote_ip and remote_ip in self.ip_to_device_id:
            dev = self.devices.get(self.ip_to_device_id[remote_ip])
            if dev and dev.get("hostname"):
                return dev["hostname"]
        if remote_mac:
            m_clean = oui_lookup.normalize_mac(remote_mac).lower().strip()
            if m_clean in self.mac_to_device_id:
                dev = self.devices.get(self.mac_to_device_id[m_clean])
                if dev and dev.get("hostname"):
                    return dev["hostname"]
        if short:
            low = short.lower()
            for dev in self.devices.values():
                ch = (dev.get("canonical_hostname") or dev.get("hostname") or "").strip()
                if ch and ch.lower() == low:
                    return ch
            if len(low) >= 12:
                prefix_matches = [
                    (dev.get("canonical_hostname") or dev.get("hostname") or "").strip()
                    for dev in self.devices.values()
                    if (dev.get("canonical_hostname") or dev.get("hostname") or "").strip().lower().startswith(low)
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

        with self._lock:
            for dev in raw_devices:
                local_host, _ = normalize_hostname(dev.get("hostname") or dev.get("ip", ""))
                for nbr in dev.get("neighbors", []):
                    if nbr.get("l2_accuracy") != "l3_next_hop_egress":
                        canon_r = self.resolve_canonical_hostname(
                            nbr.get("remote_device", ""),
                            remote_mac=nbr.get("remote_mac", ""),
                            remote_ip=nbr.get("remote_ip", ""),
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

                    if matched_link:
                        lk, resolved_remote_port = matched_link
                        if self._needs_remote_port_resolution(r_port, r_host) and resolved_remote_port:
                            if not self._needs_remote_port_resolution(resolved_remote_port, r_host):
                                nbr["remote_port"] = resolved_remote_port
                                r_port = resolved_remote_port
                        if lk["status"] == "confirmed" or has_reciprocal:
                            nbr["link_confidence"] = "two-way"
                        else:
                            nbr["link_confidence"] = "one-way"
                    else:
                        nbr["link_confidence"] = "two-way" if has_reciprocal else nbr.get("link_confidence", "one-way")

                    # Synthesize reverse neighbor on peer if peer is crawled and lacks an entry on r_port
                    if peer_dev and r_port and l_port:
                        peer_ints = {
                            normalize_interface(k).lower(): k for k in (peer_dev.get("interfaces_detail") or {})
                        }
                        if r_port.lower() in peer_ints:
                            peer_port_exact = peer_ints[r_port.lower()]
                            already = any(
                                normalize_interface(pn.get("local_port", "")).lower() == r_port.lower()
                                for pn in peer_dev.get("neighbors", [])
                            )
                            if not already:
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
                if imac and imac != "00:00:00:00:00:00":
                    mac_to_dev.setdefault(imac, (dev, intf_name))
                    mac_set.add(imac)
            base_mac = oui_lookup.normalize_mac(dev.get("mac_address", "") or "").lower()
            if base_mac and base_mac != "00:00:00:00:00:00":
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
                            "local_port": target_port or "eth0",
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

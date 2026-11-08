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

import oui_lookup

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

            if not node_a or not node_b:
                return

            # Canonical order (case-insensitive hostname comparison) for deduplication
            end_1 = (node_a.lower(), port_a.lower())
            end_2 = (node_b.lower(), port_b.lower())

            if end_1 > end_2:
                c_node_a, c_port_a, c_node_b, c_port_b = node_b, port_b, node_a, port_a
            else:
                c_node_a, c_port_a, c_node_b, c_port_b = node_a, port_a, node_b, port_b

            # Check if link already recorded (exact port match, or one side lacked remote_port like MNDP)
            for existing in self.links:
                same_nodes = (
                    existing["node_a"].lower() == c_node_a.lower() and existing["node_b"].lower() == c_node_b.lower()
                )
                if not same_nodes:
                    continue

                ports_match = (
                    existing["port_a"].lower() == c_port_a.lower() and existing["port_b"].lower() == c_port_b.lower()
                )
                partial_port_match = (
                    existing["port_a"].lower() == c_port_a.lower() and (not existing["port_b"] or not c_port_b)
                ) or (existing["port_b"].lower() == c_port_b.lower() and (not existing["port_a"] or not c_port_a))
                if ports_match or partial_port_match:
                    if not existing["port_a"] and c_port_a:
                        existing["port_a"] = c_port_a
                    if not existing["port_b"] and c_port_b:
                        existing["port_b"] = c_port_b
                    existing["status"] = "confirmed"
                    return

            self.links.append(
                {
                    "node_a": c_node_a,
                    "port_a": c_port_a,
                    "node_b": c_node_b,
                    "port_b": c_port_b,
                    "status": "unidirectional",
                    "type": link_type,
                }
            )

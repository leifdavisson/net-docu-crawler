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
Cisco IOS-XR Driver: ASR 9000, NCS 5000/5500, CRS, XRv9000, and 8000 series.
Supports read-only IOS-XR CLI telemetry (interfaces, BGP/OSPF/IS-IS, VRF, MPLS/LDP,
HSRP/VRRP, Bundle-Ether LACP/L2VPN, optics/DOM) plus optional NETCONF/gNMI enrichment.
Official Documentation: https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xr-software/tsd-products-support-series-home.html
"""

import logging
import re

import oui_lookup
import parser
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)


def _parse_xr_arp_line(line: str) -> dict | None:
    """Parse a single Cisco IOS-XR `show arp` table row."""
    # Example: 10.0.0.1        00:00:01   0011.2233.4455  Dynamic    ARPA  GigabitEthernet0/0/0/0
    m = re.match(
        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F.:-]{12,17})\s+\S+\s+\S+\s+(\S+)\s*$",
        line,
    )
    if not m:
        return None
    ip_addr, raw_mac, intf = m.groups()
    mac = oui_lookup.normalize_mac(raw_mac).lower()
    return {
        "ip_address": ip_addr,
        "mac_address": mac,
        "interface": intf,
        "vendor": oui_lookup.lookup_oui(mac),
    }


def _parse_xr_bgp_summary(raw: str) -> list[dict]:
    """Parse Cisco IOS-XR `show bgp all all summary` / `show bgp vrf all summary` output."""
    peers: list[dict] = []
    cur_vrf = "default"
    cur_afi = "IPv4 Unicast"
    in_table = False

    for line in (raw or "").splitlines():
        s = line.strip()
        if not s:
            continue
        m_vrf = re.match(r"^VRF:\s*(\S+)", s, re.IGNORECASE)
        if m_vrf:
            cur_vrf = m_vrf.group(1)
            in_table = False
            continue
        m_afi = re.match(r"^Address Family:\s*(.+)$", s, re.IGNORECASE)
        if m_afi:
            cur_afi = m_afi.group(1).strip()
            in_table = False
            continue
        if s.startswith("Neighbor") and "AS" in s:
            in_table = True
            continue
        if not in_table:
            continue

        # Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd
        parts = s.split()
        if len(parts) >= 10 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            state_tok = parts[-1]
            is_up = state_tok.isdigit()
            peers.append(
                {
                    "protocol": "bgp",
                    "vrf": cur_vrf,
                    "afi": cur_afi,
                    "neighbor_ip": parts[0],
                    "asn": parts[2],
                    "uptime": parts[-2],
                    "state": "Established" if is_up else state_tok,
                    "prefixes_received": int(state_tok) if is_up else 0,
                }
            )
    return peers


def _parse_xr_vrf_detail(raw: str) -> list[dict]:
    """Parse Cisco IOS-XR `show vrf all detail` output."""
    vrfs: list[dict] = []
    current: dict | None = None
    in_interfaces = False

    for line in (raw or "").splitlines():
        s = line.strip()
        if not s:
            continue
        m_hdr = re.match(r"^VRF\s+(\S+);\s*RD\s+(\S+);", s, re.IGNORECASE)
        if m_hdr:
            if current:
                vrfs.append(current)
            current = {
                "name": m_hdr.group(1),
                "rd": m_hdr.group(2),
                "import_rts": [],
                "export_rts": [],
                "interfaces": [],
            }
            in_interfaces = False
            continue
        if current is None:
            continue

        if s.lower().startswith("interfaces:"):
            in_interfaces = True
            tail = s.split(":", 1)[1].strip()
            if tail:
                current["interfaces"].extend(tok.strip(",") for tok in tail.split() if tok.strip(","))
            continue

        if in_interfaces:
            if any(s.lower().startswith(k) for k in ("address family", "vrf ", "import ", "export ")):
                in_interfaces = False
            else:
                current["interfaces"].extend(tok.strip(",") for tok in s.split() if tok.strip(","))
                continue

        m_rt = re.findall(r"RT:(\S+)", s)
        if m_rt:
            if "import" in s.lower():
                current["import_rts"].extend(m_rt)
            elif "export" in s.lower():
                current["export_rts"].extend(m_rt)

    if current:
        vrfs.append(current)
    return vrfs


def _parse_xr_ldp_neighbors(raw: str) -> list[dict]:
    """Parse Cisco IOS-XR `show mpls ldp neighbor brief` output."""
    neighbors: list[dict] = []
    for line in (raw or "").splitlines():
        # Peer ID          GR  NSR Up Time     Discovery   Addresses  Labels
        # 10.255.0.2:0     N   N   1d02h       1           3          12
        m = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+:\d+)\s+\S+\s+\S+\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
            line,
        )
        if m:
            neighbors.append(
                {
                    "peer_id": m.group(1),
                    "uptime": m.group(2),
                    "discovery_sources": int(m.group(3)),
                    "addresses": int(m.group(4)),
                    "labels": int(m.group(5)),
                }
            )
    return neighbors


def _parse_xr_ldp_interfaces(raw: str) -> list[dict]:
    """Parse Cisco IOS-XR `show mpls ldp interface` output."""
    interfaces: list[dict] = []
    for line in (raw or "").splitlines():
        m = re.match(
            r"^\s*((?:Gi|Te|Hu|Fo|BE|Bundle-Ether|TenGigE|GigabitEthernet|HundredGigE)\S+)\s+(Enabled|Disabled)\s+(.*)$",
            line,
            re.IGNORECASE,
        )
        if m:
            interfaces.append(
                {
                    "interface": m.group(1),
                    "status": m.group(2).lower(),
                    "detail": m.group(3).strip(),
                }
            )
    return interfaces


def _parse_xr_mpls_forwarding(raw: str) -> list[dict]:
    """Parse Cisco IOS-XR `show mpls forwarding-table` summary rows."""
    entries: list[dict] = []
    for line in (raw or "").splitlines():
        # Local  Outgoing    Prefix             Outgoing     Next Hop        Bytes
        # 24001  Pop         10.255.0.2/32      Te0/0/0/0    10.1.1.2        12345
        m = re.match(
            r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+|point2point)\s+(\d+)",
            line,
        )
        if m:
            entries.append(
                {
                    "local_label": m.group(1),
                    "outgoing_label": m.group(2),
                    "prefix": m.group(3),
                    "outgoing_interface": m.group(4),
                    "next_hop": m.group(5),
                    "bytes_switched": int(m.group(6)),
                }
            )
    return entries


class CiscoXRDriver(BaseDriver):
    """Driver for Cisco IOS-XR core and edge routing platforms."""

    vendor_name = "Cisco Systems"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = "terminal length 0"

    def __init__(
        self,
        *args,
        use_netconf: bool = False,
        netconf_port: int = 830,
        use_gnmi: bool = False,
        gnmi_port: int = 57400,
        gnmi_insecure: bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.use_netconf = use_netconf
        self.netconf_port = netconf_port
        self.use_gnmi = use_gnmi
        self.gnmi_port = gnmi_port
        self.gnmi_insecure = gnmi_insecure

    def connect(self):
        device = self._build_netmiko_params("cisco_xr", secret=self.secret, global_delay_factor=2)
        conn = self.connect_netmiko(device)
        if self.secret:
            self._safe_enable(conn)
        return conn

    def get_version(self, conn) -> dict:
        sh_ver = getattr(self, "_prefetched_sh_ver", None)
        if sh_ver is not None:
            self._prefetched_sh_ver = None
        else:
            sh_ver = conn.send_command("show version")

        ver = parser.parse_show_version(sh_ver, "cisco_xr")
        ver["os_type"] = "cisco_xr"
        ver["device_type"] = "router"
        ver["device_persona"] = "router"

        if not ver.get("hostname"):
            prompt = self._safe_find_prompt(conn)
            m_host = re.search(r":([^#>]+)[#>]", prompt or "")
            if m_host:
                ver["hostname"] = m_host.group(1).strip()

        try:
            sh_inv = conn.send_command("show inventory")
            for item in parser.parse_show_inventory(sh_inv):
                if "chassis" in item.get("name", "").lower() or "chassis" in item.get("descr", "").lower():
                    if item.get("pid"):
                        ver["model"] = item["pid"]
                    if item.get("sn") and item["sn"] != "N/A":
                        ver["serial"] = item["sn"]
                    break
        except Exception as exc:
            logger.debug("[%s] IOS-XR show inventory failed: %s", self.ip, exc)

        return ver

    def get_interfaces(self, conn) -> tuple[list, dict]:
        sh_ip_int = conn.send_command("show ipv4 interface brief")
        l3_ints = parser.parse_ip_interface_brief(sh_ip_int, "cisco_xr")

        sh_ints = conn.send_command("show interfaces")
        ints_detail = parser.parse_show_interfaces(sh_ints, "cisco_xr")
        for stats in ints_detail.values():
            if stats.get("mac_address"):
                stats["mac_address"] = oui_lookup.normalize_mac(stats["mac_address"]).lower()

        cidr_by_intf: dict[str, str] = {}
        cur_intf: str | None = None
        for line in (sh_ints or "").splitlines():
            m_hdr = re.match(r"^([A-Za-z0-9/._-]+)\s+is\s+(?:up|down|administratively)", line.strip())
            if m_hdr:
                cur_intf = m_hdr.group(1)
            elif cur_intf:
                m_addr = re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m_addr:
                    cidr_by_intf[cur_intf] = m_addr.group(1)

        for entry in l3_ints:
            ip_val = str(entry.get("ip_address") or "").strip()
            intf_name = str(entry.get("interface") or "").strip()
            if ip_val and "/" not in ip_val and " " not in ip_val and intf_name in cidr_by_intf:
                if cidr_by_intf[intf_name].startswith(ip_val + "/"):
                    entry["ip_address"] = cidr_by_intf[intf_name]

        return l3_ints, ints_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []
        seen: set[tuple[str, str]] = set()
        lldp_status = "unknown"
        cdp_status = "unknown"

        try:
            sh_lldp = conn.send_command("show lldp neighbors detail")
            low = (sh_lldp or "").lower()
            if "not enabled" in low or "lldp is not running" in low:
                lldp_status = "disabled"
            elif "invalid input" in low:
                lldp_status = "unsupported"
            else:
                lldp_status = "enabled"
                for n in parser.parse_lldp_neighbors_detail(sh_lldp):
                    n["remote_platform"] = n.get("platform", "")
                    key = (n.get("local_port", ""), n.get("remote_device", "").lower())
                    if key not in seen and n.get("local_port"):
                        seen.add(key)
                        neighbors.append(n)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show lldp neighbors detail failed: %s", self.ip, exc)

        try:
            sh_cdp = conn.send_command("show cdp neighbors detail")
            low = (sh_cdp or "").lower()
            if "cdp is not enabled" in low:
                cdp_status = "disabled"
            elif "invalid input" in low:
                cdp_status = "unsupported"
            else:
                cdp_status = "enabled"
                for n in parser.parse_cdp_neighbors_detail(sh_cdp):
                    n["remote_platform"] = n.get("platform", "")
                    key = (n.get("local_port", ""), n.get("remote_device", "").lower())
                    if key not in seen:
                        seen.add(key)
                        neighbors.append(n)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show cdp neighbors detail failed: %s", self.ip, exc)

        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": cdp_status,
            "mndp": "unsupported",
            "notes": "",
        }
        return neighbors

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        status = super().get_discovery_protocols(conn, raw_config=raw_config, neighbors=neighbors)
        cfg_low = (raw_config or "").lower()
        if re.search(r"^\s*lldp\b", cfg_low, re.MULTILINE):
            status["lldp"] = "enabled"
        if re.search(r"^\s*cdp\b", cfg_low, re.MULTILINE):
            status["cdp"] = "enabled"
        return status

    def get_routing_table(self, conn) -> list[dict]:
        try:
            sh_route = conn.send_command("show route")
            return parser.parse_show_ip_route(sh_route, "cisco_xr")
        except Exception as exc:
            logger.debug("[%s] IOS-XR show route failed: %s", self.ip, exc)
            return []

    def get_arp_table(self, conn) -> list[dict]:
        entries: list[dict] = []
        try:
            raw = conn.send_command("show arp")
            for line in (raw or "").splitlines():
                parsed = _parse_xr_arp_line(line)
                if parsed:
                    entries.append(parsed)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show arp failed: %s", self.ip, exc)
        return entries

    def get_fhrp(self, conn) -> list[dict]:
        fhrp: list[dict] = []
        for proto, cmd in (("HSRP", "show hsrp summary"), ("VRRP", "show vrrp summary")):
            try:
                raw = conn.send_command(cmd)
                if not raw or "invalid input" in raw.lower():
                    continue
                for line in raw.splitlines():
                    m = re.match(
                        r"^\s*(\S+)\s+(\d+)\s+\d+\s+(?:[P\-]\s+)?(Active|Standby|Master|Backup|Init|Listen)\b(.*)$",
                        line,
                        re.IGNORECASE,
                    )
                    if m:
                        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(4))
                        vip = ips[-1] if ips else ""
                        if vip:
                            fhrp.append(
                                {
                                    "protocol": proto,
                                    "interface": m.group(1),
                                    "group": m.group(2),
                                    "state": m.group(3),
                                    "vip": vip,
                                }
                            )
            except Exception as exc:
                logger.debug("[%s] IOS-XR %s failed: %s", self.ip, cmd, exc)
        return fhrp

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        try:
            raw_bundle = conn.send_command("show bundle")
            cur_bundle = ""
            for line in (raw_bundle or "").splitlines():
                m_b = re.match(r"^(Bundle-Ether\d+)\s*$", line.strip(), re.IGNORECASE)
                if m_b:
                    cur_bundle = m_b.group(1)
                    ops.setdefault(cur_bundle, {"mode": "trunk", "oper_mode": "trunk", "lag_role": "bundle"})
                    continue
                m_mem = re.match(
                    r"^\s*((?:Gi|Te|Hu|Fo|TenGigE|GigabitEthernet|HundredGigE)\S+)\s+(Active|Standby|Configured)\b",
                    line,
                    re.IGNORECASE,
                )
                if m_mem and cur_bundle:
                    mem = m_mem.group(1)
                    ops[mem] = {
                        "lag_id": cur_bundle,
                        "lacp_mode": "active" if "active" in m_mem.group(2).lower() else "passive",
                    }
        except Exception as exc:
            logger.debug("[%s] IOS-XR show bundle failed: %s", self.ip, exc)
        return ops

    def get_optics(self, conn) -> list[dict]:
        optics: list[dict] = []
        try:
            inv_raw = conn.send_command("show inventory")
            for item in parser.parse_show_inventory(inv_raw):
                name = item.get("name", "")
                descr = item.get("descr", "")
                pid = item.get("pid", "")
                if any(k in descr.lower() or k in pid.lower() for k in ("sfp", "qsfp", "xfp", "cfp", "optic")):
                    optics.append(
                        {
                            "port": name,
                            "part_number": pid,
                            "serial": item.get("sn", ""),
                            "description": descr,
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] IOS-XR show inventory optics failed: %s", self.ip, exc)
        return optics

    def get_routing_peers(self, conn) -> list[dict]:
        peers: list[dict] = []
        for cmd in ("show bgp all all summary", "show bgp vrf all summary"):
            try:
                raw = conn.send_command(cmd)
                if raw and "invalid input" not in raw.lower():
                    peers.extend(_parse_xr_bgp_summary(raw))
                    if peers:
                        break
            except Exception as exc:
                logger.debug("[%s] IOS-XR %s failed: %s", self.ip, cmd, exc)

        for proto, cmd in (("ospf", "show ospf neighbor"), ("isis", "show isis neighbors")):
            try:
                raw = conn.send_command(cmd)
                if not raw or "invalid input" in raw.lower():
                    continue
                for line in raw.splitlines():
                    m_ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if m_ip and ("full" in line.lower() or "up" in line.lower()):
                        peers.append({"protocol": proto, "neighbor_ip": m_ip.group(1), "state": "Up"})
            except Exception as exc:
                logger.debug("[%s] IOS-XR %s failed: %s", self.ip, cmd, exc)
        return peers

    def get_vrfs(self, conn) -> list[dict]:
        try:
            raw = conn.send_command("show vrf all detail")
            if raw and "invalid input" not in raw.lower():
                return _parse_xr_vrf_detail(raw)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show vrf all detail failed: %s", self.ip, exc)
        return []

    def get_mpls_ldp(self, conn) -> dict:
        mpls = {"ldp_neighbors": [], "ldp_interfaces": [], "forwarding": []}
        try:
            raw_nbr = conn.send_command("show mpls ldp neighbor brief")
            if raw_nbr and "invalid input" not in raw_nbr.lower():
                mpls["ldp_neighbors"] = _parse_xr_ldp_neighbors(raw_nbr)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show mpls ldp neighbor brief failed: %s", self.ip, exc)

        try:
            raw_if = conn.send_command("show mpls ldp interface")
            if raw_if and "invalid input" not in raw_if.lower():
                mpls["ldp_interfaces"] = _parse_xr_ldp_interfaces(raw_if)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show mpls ldp interface failed: %s", self.ip, exc)

        try:
            raw_fwd = conn.send_command("show mpls forwarding-table")
            if raw_fwd and "invalid input" not in raw_fwd.lower():
                mpls["forwarding"] = _parse_xr_mpls_forwarding(raw_fwd)
        except Exception as exc:
            logger.debug("[%s] IOS-XR show mpls forwarding-table failed: %s", self.ip, exc)
        return mpls

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "show running-config")

    def fetch_netconf_operational(self, xpath_filter: str = "/interfaces") -> str:
        """Optional read-only NETCONF <get> query (requires `ncclient`)."""
        if not self.use_netconf:
            return ""
        try:
            from ncclient import manager  # type: ignore[import-not-found]
        except ImportError:
            logger.warning("[%s] --netconf requested, but 'ncclient' is not installed (pip install '.[xr]').", self.ip)
            return ""

        try:
            with manager.connect(
                host=self.ip,
                port=self.netconf_port,
                username=self.username,
                password=self.password,
                hostkey_verify=False,
                timeout=self.timeout,
            ) as m:
                reply = m.get(filter=("xpath", xpath_filter))
                return getattr(reply, "xml", str(reply))
        except Exception as exc:
            logger.warning("[%s] NETCONF read-only get failed; falling back to CLI: %s", self.ip, exc)
            return ""

    def fetch_gnmi_operational(self, paths: list[str] | None = None) -> dict:
        """Optional read-only gNMI Get() query (requires `pygnmi`)."""
        if not self.use_gnmi:
            return {}
        try:
            from pygnmi.client import gNMIclient  # type: ignore[import-not-found]
        except ImportError:
            logger.warning("[%s] --gnmi requested, but 'pygnmi' is not installed (pip install '.[xr]').", self.ip)
            return {}

        target_paths = paths or ["/interfaces/interface/state", "/network-instances/network-instance/bgp"]
        try:
            with gNMIclient(
                target=(self.ip, self.gnmi_port),
                username=self.username,
                password=self.password,
                insecure=self.gnmi_insecure,
            ) as gc:
                return gc.get(path=target_paths, encoding="json_ietf")
        except Exception as exc:
            logger.warning("[%s] gNMI read-only Get failed; falling back to CLI: %s", self.ip, exc)
            return {}

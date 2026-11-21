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
Aruba Networks / HPE Driver: Aruba Instant AP (IAP) clusters & ArubaOS-CX switches.
Official Documentation:
- Aruba Instant: https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm
- Aruba AOS-CX: https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm
"""

import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)


class ArubaDriver(BaseDriver):
    vendor_name = "Aruba Networks / HPE"
    device_persona = "ap"
    default_device_type = "ap"
    paging_cmd = "no page"

    def connect(self):
        device = self._build_netmiko_params("aruba_os", global_delay_factor=2)
        return self.connect_netmiko(device)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Aruba AP",
            "serial": "Unknown",
            "firmware": "ArubaOS",
            "os_type": "aruba_os",
            "device_persona": self.device_persona,
        }
        sh_ver = getattr(self, "_prefetched_sh_ver", None)
        if sh_ver is not None:
            self._prefetched_sh_ver = None
            raw = sh_ver
        else:
            raw = conn.send_command("show version")
        raw_str = raw if isinstance(raw, str) else ""

        # Detect Aruba AOS-CX switch platform (`ArubaOS-CX` / `AOS-CX`)
        if re.search(r"ArubaOS-CX|AOS-CX", raw_str, re.IGNORECASE):
            self._is_aoscx = True
            info["device_persona"] = "switch"
            info["device_type"] = "switch"
            info["os_type"] = "aruba_aoscx"
            info["model"] = "Aruba AOS-CX Switch"
            info["firmware"] = "ArubaOS-CX"

            m_ver = re.search(r"Version\s*:\s*(\S+)", raw_str, re.IGNORECASE)
            if m_ver:
                info["firmware"] = m_ver.group(1).strip()
            m_prod = re.search(r"(?:Product Name|Model|Chassis)\s*:\s*(.+)", raw_str, re.IGNORECASE)
            if m_prod:
                info["model"] = m_prod.group(1).strip()
            m_ser = re.search(r"(?:Chassis\s+)?Serial\s+(?:Number|Nbr)\s*:\s*(\S+)", raw_str, re.IGNORECASE)
            if m_ser:
                info["serial"] = m_ser.group(1).strip()
            m_mac = re.search(r"(?:Base\s+)?MAC\s+Address\s*:\s*([0-9a-fA-F:.-]+)", raw_str, re.IGNORECASE)
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()

            try:
                raw_sys = conn.send_command("show system")
                if isinstance(raw_sys, str) and raw_sys.strip() and "Invalid input" not in raw_sys:
                    m_host = re.search(r"Hostname\s*:\s*(\S+)", raw_sys, re.IGNORECASE)
                    if m_host:
                        info["hostname"] = m_host.group(1).strip()
                    if info["model"] == "Aruba AOS-CX Switch":
                        m_p2 = re.search(r"Product\s+Name\s*:\s*(.+)", raw_sys, re.IGNORECASE)
                        if m_p2:
                            info["model"] = m_p2.group(1).strip()
                    if info["serial"] == "Unknown":
                        m_s2 = re.search(r"(?:Chassis\s+)?Serial\s+(?:Number|Nbr)\s*:\s*(\S+)", raw_sys, re.IGNORECASE)
                        if m_s2:
                            info["serial"] = m_s2.group(1).strip()
                    if not info.get("mac_address"):
                        m_m2 = re.search(r"(?:Base\s+)?MAC\s+Address\s*:\s*([0-9a-fA-F:.-]+)", raw_sys, re.IGNORECASE)
                        if m_m2:
                            info["mac_address"] = oui_lookup.normalize_mac(m_m2.group(1)).lower()
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show system failed: %s", self.ip, exc)

            if not info["hostname"]:
                prompt = self._safe_find_prompt(conn)
                if prompt:
                    info["hostname"] = prompt.replace("#", "").replace(">", "").strip()
            return info

        self._is_aoscx = False
        self._ap_hostname = ""
        self._ap_member_ip = ""
        self._swarm_lldp: dict[str, list[dict]] = {}

        m_model = re.search(r"MODEL:\s*(\w+)", raw_str)
        if m_model:
            info["model"] = f"Aruba AP-{m_model.group(1)}"
        m_ver = re.search(r"Version\s*(\S+)", raw_str)
        if m_ver:
            info["firmware"] = m_ver.group(1)

        prompt = self._safe_find_prompt(conn)
        if prompt:
            info["hostname"] = prompt.replace("#", "").replace(">", "").strip()

        # Query AP cluster details if IAP (`show aps` returns full swarm roster on Virtual Controller)
        swarm_aps: list[dict] = []
        try:
            raw_aps = conn.send_command("show aps")
            if isinstance(raw_aps, str):
                for line in raw_aps.splitlines():
                    parts = line.split()
                    if len(parts) >= 10 and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}\*?$", parts[1]):
                        is_master = parts[1].endswith("*")
                        ap_ip = parts[1].rstrip("*")
                        ap_serial = parts[9] if parts[9] not in ("-", "--") else "Unknown"
                        swarm_aps.append(
                            {
                                "name": parts[0],
                                "ip": ap_ip,
                                "serial": ap_serial,
                                "is_master": is_master,
                            }
                        )
        except Exception as exc:
            logger.debug("[%s] Aruba show aps failed: %s", self.ip, exc)

        if swarm_aps:
            info["swarm_aps"] = swarm_aps
            matched = next((a for a in swarm_aps if a["ip"] == self.ip), None)
            if not matched and info["hostname"]:
                matched = next((a for a in swarm_aps if a["name"].lower() == info["hostname"].lower()), None)
            if not matched:
                matched = next((a for a in swarm_aps if a["is_master"]), None)
            if matched:
                info["hostname"] = matched["name"]
                if matched["serial"] != "Unknown":
                    info["serial"] = matched["serial"]
                self._ap_member_ip = matched["ip"]

        self._ap_hostname = info["hostname"]
        return info

    def crawl(self, conn) -> dict:
        sh_ver = self._safe_send_command(conn, "show version")
        if re.search(
            r"Image\s+stamp\s*:|ProCurve|\b(?:WB|WC|YA|YB|YC|KB|KA|RA)\.\d{2}\.\d{2}\b",
            sh_ver,
            re.IGNORECASE,
        ):
            from net_docu_crawler.drivers.hpprocurve import HPProCurveDriver

            logger.info("[%s] Detected ArubaOS-S / ProCurve in ArubaDriver; delegating to HPProCurveDriver.", self.ip)
            procurve_drv = HPProCurveDriver(
                ip=self.ip,
                username=self.username,
                password=self.password,
                secret=self.secret,
                timeout=self.timeout,
                session_log=self.session_log,
                port=self.port,
                transport=self.transport,
            )
            return procurve_drv.crawl(conn)

        self._prefetched_sh_ver = sh_ver
        data = super().crawl(conn)
        if getattr(self, "_swarm_lldp", None):
            data["swarm_lldp"] = self._swarm_lldp
        return data

    def get_interfaces(self, conn) -> tuple[list, dict]:
        if getattr(self, "_is_aoscx", False):
            l3_interfaces: list[dict] = []
            interfaces_detail: dict[str, dict] = {}
            try:
                raw_ip = conn.send_command("show ip interface brief")
                for line in (raw_ip if isinstance(raw_ip, str) else "").splitlines():
                    m_ip = re.match(
                        r"^\s*([A-Za-z0-9/._-]+)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+(up|down)\s+(up|down)",
                        line,
                        re.IGNORECASE,
                    )
                    if m_ip:
                        intf_n, ip_v, st_a, st_p = m_ip.groups()
                        if not ip_v.startswith("127."):
                            l3_interfaces.append(
                                {
                                    "interface": intf_n,
                                    "ip_address": ip_v,
                                    "status": st_a.lower(),
                                    "protocol": st_p.lower(),
                                }
                            )
                            interfaces_detail[intf_n] = {
                                "ip_address": ip_v,
                                "status": st_p.lower(),
                                "mac_address": "",
                                "description": "",
                            }
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show ip interface brief failed: %s", self.ip, exc)
            try:
                raw_br = conn.send_command("show interface brief")
                for line in (raw_br if isinstance(raw_br, str) else "").splitlines():
                    m_br = re.match(
                        r"^\s*(\d+/\d+/\d+(?::\d+)?|lag\d+|vlan\d+)\s+\S+\s+\S+\s+\S+\s+(up|down)\b",
                        line,
                        re.IGNORECASE,
                    )
                    if m_br:
                        p_name, p_st = m_br.group(1), m_br.group(2).lower()
                        interfaces_detail.setdefault(
                            p_name,
                            {"ip_address": "", "status": p_st, "mac_address": "", "description": ""},
                        )
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show interface brief failed: %s", self.ip, exc)
            return l3_interfaces, interfaces_detail

        l3_interfaces = [{"interface": "br0", "ip_address": self.ip, "status": "up", "protocol": "up"}]
        member_ip = getattr(self, "_ap_member_ip", "")
        if member_ip and member_ip != self.ip:
            l3_interfaces.append({"interface": "br0", "ip_address": member_ip, "status": "up", "protocol": "up"})
        interfaces_detail = {
            "eth0": {
                "status": "up",
                "protocol": "up",
                "description": "Uplink to Switch",
                "mac_address": "",
                "speed": "1Gb/s",
                "duplex": "Full",
            }
        }
        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        if getattr(self, "_is_aoscx", False):
            try:
                import parser as cli_parser

                raw_cx = conn.send_command("show lldp neighbor-info detail")
                for n in cli_parser.parse_lldp_neighbors_detail(raw_cx if isinstance(raw_cx, str) else ""):
                    n["remote_platform"] = n.get("platform", "")
                    neighbors.append(n)
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show lldp neighbor-info detail failed: %s", self.ip, exc)
            return neighbors

        swarm_lldp: dict[str, list[dict]] = {}
        target_ap = (getattr(self, "_ap_hostname", "") or "").strip().lower()
        try:
            raw = conn.send_command("show ap debug lldp info")
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith(("swarm ap", "ap name")) or set(stripped) <= {"-", " "}:
                    continue
                m = re.match(
                    r"^\s*(\S+)\s+(\S+)\s+([0-9a-fA-F:.-]{12,17})\s+(\S+)\s+.*?\b([0-9a-fA-F:]{17})\s+(\S+)(?:\s+(.+))?$",
                    line,
                )
                if m:
                    ap_name, local_port, _nbr_id, rem_port_raw, rem_basemac, rem_host, _cap = m.groups()
                    rem_intf = re.sub(r"\.0$", "", rem_port_raw)
                    rem_mac = oui_lookup.normalize_mac(rem_basemac).lower()
                    plat = f"Switch ({oui_lookup.lookup_oui(rem_mac)})"
                    entry = {
                        "local_port": local_port,
                        "remote_device": rem_host.split(".")[0],
                        "remote_port": rem_intf,
                        "remote_ip": "",
                        "remote_mac": rem_mac,
                        "platform": plat,
                        "remote_platform": plat,
                        "device_type": "switch",
                    }
                    swarm_lldp.setdefault(ap_name.lower(), []).append(entry)
                    if not target_ap or ap_name.lower() == target_ap:
                        neighbors.append(entry)
        except Exception as exc:
            logger.debug("[%s] Aruba show ap debug lldp info failed: %s", self.ip, exc)
        self._swarm_lldp = swarm_lldp
        self._discovery_protocols = {
            "lldp": "enabled",
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": "",
        }
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        if getattr(self, "_is_aoscx", False):
            routes: list[dict] = []
            try:
                raw_rt = conn.send_command("show ip route")
                for line in (raw_rt if isinstance(raw_rt, str) else "").splitlines():
                    m_rt = re.match(
                        r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s*,\s*vrf\s+\S+\s+via\s+(\S+)\s*,\s*\[[^\]]+\]\s*,\s*(\S+)",
                        line,
                        re.IGNORECASE,
                    )
                    if m_rt:
                        sub, nh, proto = m_rt.groups()
                        routes.append(
                            {
                                "subnet": sub,
                                "protocol": proto,
                                "next_hop": "connected" if proto.lower() == "connected" else nh,
                                "interface": nh if proto.lower() == "connected" else "",
                            }
                        )
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show ip route failed: %s", self.ip, exc)
            return routes
        return [{"subnet": "0.0.0.0/0", "protocol": "Default", "next_hop": "Gateway", "interface": "eth0"}]

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        seen_ips = set()
        if getattr(self, "_is_aoscx", False):
            try:
                raw_arp = conn.send_command("show arp")
                for line in (raw_arp if isinstance(raw_arp, str) else "").splitlines():
                    m_a = re.match(
                        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:.-]{12,17})\s+(\S+)\s+(\S+)",
                        line,
                    )
                    if m_a:
                        a_ip, a_mac, a_port, _phys = m_a.groups()
                        norm_mac = oui_lookup.normalize_mac(a_mac).lower()
                        arp_entries.append(
                            {
                                "ip": a_ip,
                                "mac": norm_mac,
                                "interface": a_port,
                                "type": "dynamic",
                                "vendor": oui_lookup.lookup_oui(norm_mac),
                            }
                        )
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show arp failed: %s", self.ip, exc)
            return arp_entries

        try:
            raw = conn.send_command("show clients")
            for line in raw.splitlines():
                m_cli = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\b", line)
                if m_cli:
                    c_ip = m_cli.group(1)
                    if c_ip in ("0.0.0.0",) or c_ip in seen_ips:
                        continue
                    seen_ips.add(c_ip)
                    norm_mac = oui_lookup.normalize_mac(m_cli.group(2)).lower()
                    arp_entries.append(
                        {
                            "ip": c_ip,
                            "mac": norm_mac,
                            "interface": "wlan",
                            "age": "1",
                            "type": "Wireless Client",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] Aruba show clients failed: %s", self.ip, exc)
        return arp_entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show interface transceiver")
            cur_port = ""
            cur_entry: dict = {}
            for line in raw.splitlines():
                m_p = re.match(r"^(?:Transceiver in|Interface)\s+([A-Za-z0-9/\._-]+)", line.strip(), re.IGNORECASE)
                if m_p:
                    if cur_port and cur_entry:
                        optics.append(cur_entry)
                    cur_port = m_p.group(1)
                    cur_entry = {
                        "port": cur_port,
                        "vendor": "Aruba",
                        "part_number": "Unknown",
                        "serial": "Unknown",
                        "type": "SFP",
                        "tx_power_dbm": None,
                        "rx_power_dbm": None,
                        "temperature_c": None,
                        "voltage_v": None,
                    }
                elif cur_entry:
                    m_type = re.search(r"Type\s*:\s*(.+)", line, re.IGNORECASE)
                    m_pn = re.search(r"Part\s*Number\s*:\s*(\S+)", line, re.IGNORECASE)
                    m_sn = re.search(r"Serial\s*Number\s*:\s*(\S+)", line, re.IGNORECASE)
                    if m_type:
                        cur_entry["type"] = m_type.group(1).strip()
                    if m_pn:
                        cur_entry["part_number"] = m_pn.group(1).strip()
                    if m_sn:
                        cur_entry["serial"] = m_sn.group(1).strip()
            if cur_port and cur_entry:
                optics.append(cur_entry)
        except Exception as exc:
            logger.debug("[%s] Aruba show interface transceiver failed: %s", self.ip, exc)
        return optics

    def get_running_config(self, conn) -> str:
        if getattr(self, "_is_aoscx", False):
            try:
                raw = conn.send_command("show running-config")
                if isinstance(raw, str) and raw.strip() and "Invalid input" not in raw:
                    return raw
            except Exception as exc:
                logger.debug("[%s] Aruba AOS-CX show running-config failed: %s", self.ip, exc)
        try:
            return conn.send_command("show configuration")
        except Exception as exc:
            logger.debug("[%s] Aruba show configuration failed, falling back to show run: %s", self.ip, exc)
            return conn.send_command("show run")

    def get_l2_operational(self, conn) -> dict[str, dict]:
        """Collect operational trunk & LACP state on Aruba AOS-CX switches (no-op on IAP APs)."""
        if getattr(self, "_is_aoscx", None) is False:
            return {}

        ops: dict[str, dict] = {}
        try:
            raw_trunk = conn.send_command("show interface trunk")
            if (
                isinstance(raw_trunk, str)
                and raw_trunk.strip()
                and "Invalid input" not in raw_trunk
                and "Unknown command" not in raw_trunk
                and "Incomplete command" not in raw_trunk
            ):
                for line in raw_trunk.splitlines():
                    stripped = line.strip()
                    if not stripped or set(stripped) <= {"-", "="}:
                        continue
                    low = stripped.lower()
                    if low.startswith(("port", "native", "vlan")):
                        continue
                    # Match AOS-CX rows:
                    # `1/1/24   99   trunk            10G-SR   up         10,20,99`
                    # `lag1     1    native-tagged    --       up         1,10,20`
                    # `1/1/23   1    native-untagged           down Admin 10,20`
                    m_tr = re.match(
                        r"^\s*(lag\s*\d+|\d+/\d+/\d+(?::\d+)?)\s+(\d+|none|--)\s+"
                        r"(trunk|native-tagged|native-untagged)\s+.*?\b(up|down)\b.*?\s+([\d,-]+|all|none)\s*$",
                        line,
                        re.I,
                    )
                    if m_tr:
                        raw_p, nat, mode_tok, status_tok, allowed = m_tr.groups()
                        port = re.sub(r"^lag\s+(\d+)$", r"lag\1", raw_p.strip(), flags=re.I)
                        mode_l = mode_tok.lower()
                        status_l = status_tok.lower()
                        rec = ops.setdefault(port, {})
                        rec["mode"] = "trunk"
                        rec["admin_mode"] = "trunk"
                        rec["oper_mode"] = "trunk" if status_l == "up" else "down"
                        rec["encapsulation"] = "dot1q"
                        if nat.lower() not in ("--",):
                            rec["native_vlan"] = nat.lower()
                        if mode_l == "native-tagged":
                            rec["native_vlan_tagged"] = True
                        elif mode_l == "native-untagged":
                            rec["native_vlan_tagged"] = False
                        allowed_clean = allowed.strip().lower()
                        rec["trunk_allowed_vlans"] = allowed_clean
                        if status_l == "up":
                            rec["trunk_active_vlans"] = allowed_clean
        except Exception as exc:
            logger.debug("[%s] Aruba AOS-CX show interface trunk failed: %s", self.ip, exc)

        try:
            raw_lacp = conn.send_command("show lacp interfaces")
            if (
                isinstance(raw_lacp, str)
                and raw_lacp.strip()
                and "Invalid input" not in raw_lacp
                and "Unknown command" not in raw_lacp
                and "Incomplete command" not in raw_lacp
            ):
                cur_lag = ""
                for line in raw_lacp.splitlines():
                    m_agg = re.search(r"Aggregate\s+name\s*:\s*(lag\s*\d+|\S+)", line, re.I)
                    if m_agg:
                        cur_lag = re.sub(r"^lag\s+(\d+)$", r"lag\1", m_agg.group(1).strip(), flags=re.I)
                        continue
                    if cur_lag:
                        m_mem = re.match(r"^\s*(\d+/\d+/\d+(?::\d+)?)\s+\d+\s+\d+\s+([A-Z]+)\b", line)
                        if m_mem:
                            pname, state_flags = m_mem.group(1), m_mem.group(2)
                            rec = ops.setdefault(pname, {})
                            rec["lag_group"] = cur_lag
                            rec["lacp_mode"] = (
                                "passive" if ("P" in state_flags and "A" not in state_flags) else "active"
                            )
                            continue
                    # Tabular single-line format: `1/1/1   lag1   active   up`
                    m_tab = re.match(r"^\s*(\d+/\d+/\d+(?::\d+)?)\s+(lag\d+)\s+(active|passive)\b", line, re.I)
                    if m_tab:
                        pname, lag_name, lmode = m_tab.groups()
                        rec = ops.setdefault(pname, {})
                        rec["lag_group"] = lag_name.lower()
                        rec["lacp_mode"] = lmode.lower()
        except Exception as exc:
            logger.debug("[%s] Aruba AOS-CX show lacp interfaces failed: %s", self.ip, exc)

        return ops

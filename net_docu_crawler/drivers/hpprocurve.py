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
HP ProCurve / ArubaOS-S (Provision) Driver: Switches running Provision OS 14.x, 15.x, and 16.x.
Official Documentation: https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm
"""

import ipaddress
import logging
import re

import oui_lookup
import parser as cli_parser
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_BARE_VT100_RE = re.compile(r"\[(?:\?[0-9;]*[hl]|[0-9;]*[HJKr])")

_PROCURVE_SKU_MODELS: dict[str, str] = {
    "J8697A": "HP 5406zl (J8697A)",
    "J8698A": "HP 5412zl (J8698A)",
    "J9085A": "HP 2610-24 (J9085A)",
    "J9086A": "HP 2610-24/12PWR (J9086A)",
    "J9087A": "HP 2610-24-PWR (J9087A)",
    "J9088A": "HP 2610-48 (J9088A)",
    "J9089A": "HP 2610-48-PWR (J9089A)",
    "J9623A": "HP 2620-24 (J9623A)",
    "J9624A": "HP 2620-24-PPoE+ (J9624A)",
    "J9625A": "HP 2620-24-PoE+ (J9625A)",
    "J9626A": "HP 2620-48 (J9626A)",
    "J9627A": "HP 2620-48-PoE+ (J9627A)",
    "J9772A": "HP 2530-48G-PoE+ (J9772A)",
    "J9773A": "HP 2530-24G-PoE+ (J9773A)",
    "J9774A": "HP 2530-8G-PoE+ (J9774A)",
    "J9775A": "HP 2530-48G (J9775A)",
    "J9776A": "HP 2530-24G (J9776A)",
    "J9777A": "HP 2530-8G (J9777A)",
    "J9853A": "HP 2530-48G-PoE+ (J9853A)",
    "J9854A": "HP 2530-24G-PoE+ (J9854A)",
    "J9855A": "HP 2530-48G (J9855A)",
    "J9856A": "HP 2530-24G (J9856A)",
}


def _extract_model_from_config(raw_config: str) -> str:
    """Extract HP/Aruba J/JL SKU from `show running-config` header comment."""
    if not raw_config:
        return ""
    m = re.search(r";\s*(J[L]?\d{4}[A-Z])\s+Configuration Editor", raw_config, re.IGNORECASE)
    if not m:
        return ""
    sku = m.group(1).upper()
    return _PROCURVE_SKU_MODELS.get(sku, f"HP Switch ({sku})")


def _clean_procurve_output(raw: str) -> str:
    """Strip ESC-prefixed ANSI/VT100 sequences, bare CSI cursor codes, and CRs."""
    if not raw:
        return ""
    cleaned = cli_parser.clean_cli_output(raw)
    cleaned = _BARE_VT100_RE.sub("", cleaned)
    return cleaned.replace("\r", "")


class _CleanProCurveConn:
    """Transparent connection wrapper that strips ProCurve VT100/ANSI escape codes."""

    def __init__(self, conn):
        self._conn = conn

    def send_command(self, *args, **kwargs):
        return _clean_procurve_output(self._conn.send_command(*args, **kwargs))

    def find_prompt(self, *args, **kwargs):
        return _clean_procurve_output(self._conn.find_prompt(*args, **kwargs)).strip()

    def __getattr__(self, name):
        return getattr(self._conn, name)


class HPProCurveDriver(BaseDriver):
    """
    Driver for HP ProCurve, HP Enterprise, and ArubaOS-S switches (Provision OS).
    Persona: switch (L2/L3 campus switching).
    Covers legacy and modern firmware (K/RA/WB/WC 14.x, 15.x, and 16.x).
    """

    vendor_name = "HP ProCurve / ArubaOS-S"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "no page"

    def connect(self):
        device = self._build_netmiko_params("hp_procurve", secret=self.secret)
        return _CleanProCurveConn(self.connect_netmiko(device))

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "HP Switch",
            "serial": "Unknown",
            "firmware": "ArubaOS-S",
            "os_type": "hp_procurve",
            "device_persona": self.device_persona,
        }

        # Query show system
        raw_sys = self._safe_send_command(conn, "show system")

        m_host = re.search(r"System Name\s*:\s*(\S+)", raw_sys)
        if m_host:
            info["hostname"] = m_host.group(1).strip()
        else:
            prompt = self._safe_find_prompt(conn)
            if prompt:
                info["hostname"] = prompt.rstrip(">#").strip()

        m_fw = re.search(r"Software revision\s*:\s*(\S+)", raw_sys)
        if m_fw:
            info["firmware"] = m_fw.group(1).strip()

        m_ser = re.search(r"Serial Number\s*:\s*(\S+)", raw_sys)
        if m_ser:
            info["serial"] = m_ser.group(1).strip()

        m_mac = re.search(r"Base MAC Addr\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw_sys)
        if m_mac:
            info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()

        # Query show modules for precise chassis model
        try:
            raw_mod = conn.send_command("show modules")
            m_mod = re.search(r"Chassis:\s*([^\r\n]+?)\s+(?:J\w+|[A-Z0-9]+)\s+Serial Number:", raw_mod)
            if m_mod:
                info["model"] = f"HP {m_mod.group(1).strip()}"
            elif "Chassis:" in raw_mod:
                m_c = re.search(r"Chassis:\s*([^\r\n]+)", raw_mod)
                if m_c:
                    info["model"] = f"HP {m_c.group(1).split()[0].strip()}"
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show modules failed: %s", self.ip, exc)

        return info

    def crawl(self, conn) -> dict:
        data = super().crawl(conn)
        if data.get("model") in ("", "HP Switch", "Unknown"):
            sku_model = _extract_model_from_config(data.get("raw_config", ""))
            if sku_model:
                data["model"] = sku_model
        return data

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}

        # 1. Layer 3 interfaces via show ip
        try:
            raw_ip = conn.send_command("show ip")
            last_vlan = "DEFAULT_VLAN"
            for line in raw_ip.splitlines():
                if "|" in line and not ("---" in line or "IP Config" in line or "Internet" in line):
                    parts = line.split("|")
                    vlan_col = parts[0].strip()
                    if vlan_col:
                        last_vlan = vlan_col
                    vlan_name = last_vlan
                    sub_parts = parts[1].split()
                    if len(sub_parts) >= 3:
                        _cfg, ip_addr, mask = sub_parts[0], sub_parts[1], sub_parts[2]
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_addr) and re.match(r"^\d+\.\d+\.\d+\.\d+$", mask):
                            try:
                                prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                                l3_interfaces.append(
                                    {
                                        "interface": vlan_name,
                                        "ip_address": f"{ip_addr}/{prefix}",
                                        "status": "up",
                                        "protocol": "up",
                                    }
                                )
                            except ValueError as exc:
                                logger.debug(
                                    "[%s] HP ProCurve invalid netmask '%s' on %s: %s", self.ip, mask, vlan_name, exc
                                )
                                l3_interfaces.append(
                                    {
                                        "interface": vlan_name,
                                        "ip_address": f"{ip_addr} {mask}",
                                        "status": "up",
                                        "protocol": "up",
                                    }
                                )
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show ip failed: %s", self.ip, exc)

        # 2. Port descriptions via show name
        port_names = {}
        try:
            raw_names = conn.send_command("show name")
            for line in raw_names.splitlines():
                m_name = re.match(r"^\s*([A-Za-z0-9/]+)\s+\S+\s+(.+)$", line)
                if m_name and not ("Port" in line or "---" in line):
                    port_names[m_name.group(1).strip()] = m_name.group(2).strip()
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show name failed: %s", self.ip, exc)

        # 3. Physical port status via show interfaces brief
        try:
            raw_brief = conn.send_command("show interfaces brief")
            for line in raw_brief.splitlines():
                m_port = re.match(r"^\s*([A-Za-z0-9/]+)\s+\S+\s+\|\s+\S+\s+(Yes|No)\s+(Up|Down)\s+(\S+)", line)
                if m_port and not ("Port" in line or "---" in line):
                    port = m_port.group(1).strip()
                    admin_status = "up" if m_port.group(2).lower() == "yes" else "down"
                    status = "up" if m_port.group(3).lower() == "up" else "down"
                    mode = m_port.group(4)

                    speed = "Auto"
                    if "1000" in mode or "1G" in mode:
                        speed = "1Gb/s"
                    elif "10G" in mode:
                        speed = "10Gb/s"
                    elif "100" in mode:
                        speed = "100Mb/s"
                    elif "10" in mode:
                        speed = "10Mb/s"

                    duplex = "Auto"
                    if "FD" in mode:
                        duplex = "Full"
                    elif "HD" in mode:
                        duplex = "Half"

                    interfaces_detail[port] = {
                        "status": status,
                        "protocol": status,
                        "admin_status": admin_status,
                        "speed": speed,
                        "duplex": duplex,
                        "mac_address": "",
                        "description": port_names.get(port, ""),
                    }
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show interfaces brief failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []

        # 1. Primary: LLDP table
        try:
            raw_lldp = conn.send_command("show lldp info remote-device")
            lines = raw_lldp.splitlines()
            sep_line = next(
                (line_item for line_item in lines if "+ ----" in line_item or "--------- +" in line_item), None
            )
            if sep_line and "+" in sep_line:
                p_plus = sep_line.index("+")
                parts = sep_line[p_plus + 1 :].split()
                if len(parts) >= 3:
                    col1_len = len(parts[0])
                    col2_len = len(parts[1])
                    col3_len = len(parts[2])

                    for line_item in lines:
                        if "|" in line_item and not ("LocalPort" in line_item or "---" in line_item):
                            pipe = line_item.index("|")
                            local_port = line_item[:pipe].strip()
                            rest = line_item[pipe + 1 :]
                            chassis_raw = rest[: col1_len + 1].strip()
                            port_id = rest[col1_len + 1 : col1_len + 1 + col2_len + 1].strip()
                            port_descr = rest[
                                col1_len + 1 + col2_len + 1 : col1_len + 1 + col2_len + 1 + col3_len + 1
                            ].strip()
                            sys_name = rest[col1_len + 1 + col2_len + 1 + col3_len + 1 :].strip()

                            remote_mac = ""
                            clean_chassis = chassis_raw.replace(" ", ":").replace("-", ":")
                            if re.match(r"^[0-9a-fA-F:]{17}$", clean_chassis):
                                remote_mac = oui_lookup.normalize_mac(clean_chassis).lower()

                            rem_port = port_descr or port_id
                            rem_host = sys_name or (f"MAC-{remote_mac.replace(':', '')}" if remote_mac else chassis_raw)
                            rem_host = rem_host.split(".")[0]

                            plat = oui_lookup.lookup_oui(remote_mac) if remote_mac else chassis_raw
                            plat_low = plat.lower()
                            host_low = rem_host.lower()
                            dev_type = "switch"
                            if any(
                                w in plat_low or w in host_low
                                for w in ["ap", "access point", "aruba", "ruckus", "ubiquiti", "unifi"]
                            ):
                                dev_type = "ap"
                            elif any(w in plat_low or w in host_low for w in ["axis", "hikvision", "camera", "hanwha"]):
                                dev_type = "camera"
                            elif any(
                                w in plat_low or w in host_low
                                for w in ["polycom", "yealink", "mitel", "avaya", "grandstream"]
                            ):
                                dev_type = "phone"
                            elif any(w in plat_low or w in host_low for w in ["crestron", "extron", "biamp"]):
                                dev_type = "av_control"
                            elif any(w in plat_low for w in ["router", "mikrotik"]):
                                dev_type = "router"
                            elif any(w in plat_low for w in ["apple", "dell", "lenovo", "intel", "microsoft"]):
                                dev_type = "endpoint"

                            neighbors.append(
                                {
                                    "local_port": local_port,
                                    "remote_device": rem_host,
                                    "remote_port": rem_port,
                                    "remote_ip": "",
                                    "remote_mac": remote_mac,
                                    "platform": plat,
                                    "remote_platform": plat,
                                    "device_type": dev_type,
                                }
                            )
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show lldp info remote-device failed: %s", self.ip, exc)

        # Enrich with untruncated System Name / PortId from detail output when available
        if neighbors:
            try:
                raw_detail = conn.send_command("show lldp info remote-device detail")
                if raw_detail and "Invalid input" not in raw_detail and "Local Port" in raw_detail:
                    detail_map: dict[str, dict[str, str]] = {}
                    cur_lp = ""
                    for ln in raw_detail.splitlines():
                        m_lp = re.match(r"^\s*Local Port\s*:\s*(\S+)", ln)
                        if m_lp:
                            cur_lp = m_lp.group(1).strip()
                            detail_map.setdefault(cur_lp, {})
                        elif cur_lp:
                            m_sn = re.match(r"^\s*SysName\s*:\s*(.+)$", ln) or re.match(
                                r"^\s*System Name\s*:\s*(.+)$", ln
                            )
                            if m_sn:
                                detail_map[cur_lp]["sys_name"] = m_sn.group(1).strip().split(".")[0]
                            m_pid = re.match(r"^\s*PortId\s*:\s*(.+)$", ln)
                            if m_pid:
                                detail_map[cur_lp]["port_id"] = m_pid.group(1).strip()
                    for n in neighbors:
                        d_info = detail_map.get(n.get("local_port", ""))
                        if d_info:
                            if d_info.get("sys_name"):
                                n["remote_device"] = d_info["sys_name"]
                            if d_info.get("port_id") and not n.get("remote_port"):
                                n["remote_port"] = d_info["port_id"]
            except Exception as exc:
                logger.debug("[%s] HP ProCurve show lldp info remote-device detail failed: %s", self.ip, exc)

        # 2. Fallback: CDP neighbor detail if LLDP is empty
        if not neighbors:
            try:
                raw_cdp = conn.send_command("show cdp neighbor detail")
                curr: dict = {}
                for line in raw_cdp.splitlines():
                    line_s = line.strip()
                    m_port = re.match(r"^Port\s*:\s*(\S+)", line_s)
                    if m_port:
                        if curr and curr.get("local_port") and curr.get("remote_device"):
                            neighbors.append(curr)
                        curr = {
                            "local_port": m_port.group(1),
                            "remote_device": "",
                            "remote_port": "",
                            "remote_ip": "",
                            "remote_mac": "",
                            "platform": "",
                            "remote_platform": "",
                            "device_type": "switch",
                        }
                    if not curr:
                        continue
                    m_dev = re.match(r"^Device ID\s*:\s*(.+)$", line_s)
                    if m_dev:
                        curr["remote_device"] = m_dev.group(1).strip().split(".")[0]
                    m_rem_port = re.match(r"^Device Port\s*:\s*(.+)$", line_s)
                    if m_rem_port:
                        curr["remote_port"] = m_rem_port.group(1).strip()
                    m_addr = re.match(r"^Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", line_s)
                    if m_addr:
                        curr["remote_ip"] = m_addr.group(1)
                    m_plat = re.match(r"^Platform\s*:\s*(.+)$", line_s)
                    if m_plat:
                        curr["platform"] = m_plat.group(1).strip()
                        curr["remote_platform"] = curr["platform"]
                        if "router" in curr["platform"].lower():
                            curr["device_type"] = "router"
                        elif "ap" in curr["platform"].lower():
                            curr["device_type"] = "ap"
                if curr and curr.get("local_port") and curr.get("remote_device"):
                    neighbors.append(curr)
            except Exception as exc:
                logger.debug("[%s] HP ProCurve show cdp neighbor detail failed: %s", self.ip, exc)

        return neighbors

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        cfg_low = (raw_config or "").lower()
        lldp_status = "disabled" if re.search(r"^\s*no lldp run\b", cfg_low, re.MULTILINE) else "enabled"
        cdp_status = "disabled" if re.search(r"^\s*no cdp run\b", cfg_low, re.MULTILINE) else "enabled"
        notes = ""
        if lldp_status == "disabled":
            notes = "LLDP disabled via 'no lldp run' in ProCurve configuration."
        return {"lldp": lldp_status, "cdp": cdp_status, "mndp": "unsupported", "notes": notes}

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show ip route")
            for line in raw.splitlines():
                line_s = line.strip()
                if not line_s or line_s.startswith("Destination") or line_s.startswith("---") or "IP Route" in line_s:
                    continue
                parts = line_s.split()
                if len(parts) >= 4:
                    dest, gw = parts[0], parts[1]
                    # Filter rejects and local host loopbacks
                    if "reject" in gw.lower() or dest.startswith("127."):
                        continue
                    intf = parts[2] if len(parts) >= 3 else ""
                    proto = parts[3] if len(parts) >= 4 else "connected"
                    routes.append(
                        {
                            "subnet": dest,
                            "protocol": proto,
                            "next_hop": gw if gw != "DEFAULT_VLAN" else "Directly Connected",
                            "interface": intf,
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show ip route failed: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp = []
        try:
            raw = conn.send_command("show arp")
            for line in raw.splitlines():
                m_arp = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+|[0-9a-fA-F:]+)\s+(\S+)\s+(\S+)", line)
                if m_arp:
                    ip = m_arp.group(1)
                    mac = oui_lookup.normalize_mac(m_arp.group(2)).lower()
                    arp_type = m_arp.group(3)
                    intf = m_arp.group(4)
                    arp.append(
                        {
                            "ip": ip,
                            "mac": mac,
                            "interface": intf,
                            "age": "-",
                            "type": arp_type,
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show arp failed: %s", self.ip, exc)
        return arp

    def get_mac_table(self, conn) -> list[dict]:
        mac_table = []
        try:
            raw = conn.send_command("show mac-address")
            for line in raw.splitlines():
                if "MAC Address" in line or "---" in line:
                    continue
                m_mac = re.match(
                    r"^\s*([0-9a-fA-F]{6}-[0-9a-fA-F]{6}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\s+(\S+)(?:\s+(\S+))?",
                    line,
                )
                if m_mac:
                    mac = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                    port = m_mac.group(2)
                    vlan = m_mac.group(3) or "1"
                    mac_table.append(
                        {
                            "mac": mac,
                            "interface": port,
                            "port": port,
                            "vlan": vlan,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show mac-address failed: %s", self.ip, exc)
        return mac_table

    def get_stp(self, conn) -> dict:
        stp = {
            "enabled": False,
            "is_root": False,
            "protocol": "Unknown",
            "root_bridge": "",
            "bridge_id": "",
            "bridge_priority": "",
            "root_cost": "",
            "root_port": "",
            "vlans": {},
        }
        try:
            raw = conn.send_command("show spanning-tree")
            if "STP Enabled   : Yes" in raw or "STP Enabled [No] : Yes" in raw:
                stp["enabled"] = True
            elif "STP Enabled   : No" in raw:
                stp["enabled"] = False
            m_mode = re.search(r"Mode\s*:\s*(\S+)", raw, re.IGNORECASE)
            if m_mode:
                stp["protocol"] = m_mode.group(1).strip().upper()
            elif "Multiple Spanning Tree" in raw:
                stp["protocol"] = "MSTP"
            m_prio = re.search(r"Switch Priority\s*:\s*(\d+)", raw, re.IGNORECASE)
            if m_prio:
                stp["bridge_priority"] = m_prio.group(1).strip()
            m_root = re.search(
                r"(?:Root Bridge MAC Address|CST Root MAC Address)\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw
            )
            m_this = re.search(r"Switch MAC Address\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw)
            if m_root:
                stp["root_bridge"] = oui_lookup.normalize_mac(m_root.group(1)).lower()
            if m_this:
                stp["bridge_id"] = oui_lookup.normalize_mac(m_this.group(1)).lower()
            if stp["root_bridge"] and stp["bridge_id"] and stp["root_bridge"] == stp["bridge_id"]:
                stp["is_root"] = True
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show spanning-tree failed: %s", self.ip, exc)
        return stp

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show running-config")
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show running-config failed, trying show config: %s", self.ip, exc)
            return self._safe_send_command(conn, "show config")

    def get_poe(self, conn) -> dict:
        from net_docu_crawler.schema import build_empty_poe_summary

        poe = build_empty_poe_summary()
        try:
            raw = conn.send_command("show power-over-ethernet brief")
            m_red = re.search(r"PoE Power Status\s*:\s*([^\r\n]+)", raw, re.IGNORECASE)
            if m_red:
                poe["psu_redundancy"] = m_red.group(1).strip()

            # Chassis-level summary appears before any "Module X Power" section
            pre_module = re.split(r"(?m)^\s*Module\s+\S+\s+Power", raw, maxsplit=1)[0]
            m_chassis = re.search(
                r"Available:\s*([\d.]+)\s*W\s+Used:\s*([\d.]+)\s*W\s+Remaining:\s*([\d.]+)\s*W",
                pre_module,
                re.IGNORECASE,
            )
            if m_chassis:
                poe["poe_supported"] = True
                poe["total_power_watts"] = float(m_chassis.group(1))
                poe["used_power_watts"] = float(m_chassis.group(2))
                poe["available_power_watts"] = float(m_chassis.group(3))
            else:
                m_tot = re.search(r"Total Available Power\s*:\s*([\d.]+)\s*W", pre_module, re.IGNORECASE)
                m_used = re.search(r"Total Power Drawn\s*:\s*([\d.]+)\s*W", pre_module, re.IGNORECASE)
                if m_tot:
                    poe["poe_supported"] = True
                    poe["total_power_watts"] = float(m_tot.group(1))
                if m_used:
                    poe["used_power_watts"] = float(m_used.group(1))
                poe["available_power_watts"] = max(0.0, poe["total_power_watts"] - poe["used_power_watts"])

            alloc_total = 0.0
            capable_cnt = 0
            enabled_cnt = 0
            delivering_cnt = 0
            for line in raw.splitlines():
                m_p = re.match(
                    r"^\s*([A-Za-z0-9/]+)\s*\|\s*(Yes|No)\s+\S+\s+\S+\s+([\d.]+)\s*W\s+([\d.]+)\s*W\s+(.*?)\s+(Delivering|Searching|Disabled|Fault|Other Fault)\s+(\d+)",
                    line,
                    re.IGNORECASE,
                )
                if m_p:
                    port, enabled_s, alloc_s, actual_s, _ctype, det_status, p_cls = m_p.groups()
                    enabled_b = enabled_s.lower() == "yes"
                    alloc_w = float(alloc_s)
                    actual_w = float(actual_s)
                    det_l = det_status.lower()
                    capable_cnt += 1
                    if enabled_b:
                        enabled_cnt += 1
                    if det_l == "delivering" or actual_w > 0:
                        delivering_cnt += 1
                        alloc_total += alloc_w
                    poe["ports"][port] = {
                        "status": det_l,
                        "enabled": enabled_b,
                        "power_watts": actual_w,
                        "draw_watts": actual_w,
                        "allocated_watts": alloc_w,
                        "class": p_cls,
                    }
                else:
                    m_short = re.match(r"^\s*([A-Za-z0-9/]+)\s*\|\s*(Yes|No)\b.*?([\d.]+)\s*W", line, re.IGNORECASE)
                    if m_short:
                        port, enabled_s, watts = m_short.groups()
                        enabled_b = enabled_s.lower() == "yes"
                        w_val = float(watts)
                        capable_cnt += 1
                        if enabled_b:
                            enabled_cnt += 1
                        if w_val > 0:
                            delivering_cnt += 1
                        poe["ports"][port] = {
                            "status": "delivering" if w_val > 0 else "searching",
                            "enabled": enabled_b,
                            "power_watts": w_val,
                            "draw_watts": w_val,
                            "allocated_watts": w_val,
                            "class": "",
                        }
            poe["poe_capable_ports"] = capable_cnt
            poe["poe_enabled_ports"] = enabled_cnt
            poe["poe_delivering_ports"] = delivering_cnt
            poe["allocated_power_watts"] = round(alloc_total, 2)
            if capable_cnt > 0:
                poe["poe_supported"] = True
            if poe["total_power_watts"] == 0.0 and delivering_cnt > 0:
                poe["budget_unreported"] = True
                if poe["used_power_watts"] == 0.0:
                    poe["used_power_watts"] = round(sum(p.get("draw_watts", 0.0) for p in poe["ports"].values()), 2)
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show power-over-ethernet brief failed: %s", self.ip, exc)
        return poe

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show interfaces transceiver")
            for line in raw.splitlines():
                if (
                    not line.strip()
                    or "---" in line
                    or "Port" in line
                    or "Transceiver" in line
                    or "Invalid input" in line
                ):
                    continue
                m_opt = re.match(
                    r"^\s*([A-Za-z]?\d+(?:/\d+)?)\s+(\S+)\s+([A-Za-z0-9-]+)\s+([A-Za-z0-9-]+)?",
                    line,
                )
                if m_opt:
                    optics.append(
                        {
                            "port": m_opt.group(1),
                            "type": m_opt.group(2),
                            "part_number": m_opt.group(3),
                            "serial": m_opt.group(4) or "",
                            "status": "present",
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show interfaces transceiver failed: %s", self.ip, exc)
        return optics

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        try:
            raw_trunks = conn.send_command("show trunks")
            if isinstance(raw_trunks, str) and raw_trunks and "Invalid input" not in raw_trunks:
                for line in raw_trunks.splitlines():
                    m_tr = re.match(r"^\s*([A-Za-z]?\d+(?:/\d+)?)\s+\|.*?\b(Trk\d+)\s+(LACP|Trunk|Dyn\d*)", line, re.I)
                    if m_tr:
                        p, grp, proto = m_tr.group(1), m_tr.group(2), m_tr.group(3)
                        ops.setdefault(p, {})["lag_group"] = grp
                        ops[p]["lacp_mode"] = "active" if "lacp" in proto.lower() else "on"
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show trunks failed: %s", self.ip, exc)

        try:
            raw_lacp = conn.send_command("show lacp")
            if isinstance(raw_lacp, str) and raw_lacp and "Invalid input" not in raw_lacp:
                for line in raw_lacp.splitlines():
                    m_lc = re.match(r"^\s*([A-Za-z]?\d+(?:/\d+)?)\s+(Trk\d+)\s+.*?(Active|Passive)", line, re.I)
                    if m_lc:
                        p, grp, mode = m_lc.group(1), m_lc.group(2), m_lc.group(3).lower()
                        ops.setdefault(p, {})["lag_group"] = grp
                        ops[p]["lacp_mode"] = mode
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show lacp failed: %s", self.ip, exc)

        try:
            raw_vp = conn.send_command("show vlans ports all")
            if (
                isinstance(raw_vp, str)
                and raw_vp.strip()
                and "Invalid input" not in raw_vp
                and "Incomplete input" not in raw_vp
            ):
                port_vlans: dict[str, dict] = {}
                cur_port = ""
                for line in raw_vp.splitlines():
                    m_ph = re.match(r"^\s*Port\s+name\s*:\s*(\S+)", line, re.I)
                    if m_ph:
                        cur_port = m_ph.group(1).strip()
                        port_vlans.setdefault(cur_port, {"tagged": [], "untagged": "", "voice": set()})
                        continue
                    if not cur_port:
                        continue
                    m_vr = re.match(
                        r"^\s*(\d{1,4})\s+.*\|\s+\S+\s+(Yes|No)\s+(?:Yes|No)\s+(Tagged|Untagged)\b",
                        line,
                        re.I,
                    )
                    if not m_vr:
                        m_vr_simple = re.match(r"^\s*(\d{1,4})\s+\S+.*?\b(Tagged|Untagged)\b", line, re.I)
                        if m_vr_simple:
                            vid, mode_tok = m_vr_simple.group(1), m_vr_simple.group(2).lower()
                            is_voice = False
                        else:
                            continue
                    else:
                        vid, voice_tok, mode_tok = m_vr.group(1), m_vr.group(2).lower(), m_vr.group(3).lower()
                        is_voice = voice_tok == "yes"

                    pv = port_vlans[cur_port]
                    if is_voice:
                        pv["voice"].add(vid)
                    if mode_tok == "tagged":
                        if vid not in pv["tagged"]:
                            pv["tagged"].append(vid)
                    else:
                        pv["untagged"] = vid

                for port, pv in port_vlans.items():
                    tagged = pv["tagged"]
                    untagged = pv["untagged"]
                    non_voice_tagged = [v for v in tagged if v not in pv["voice"]]
                    if non_voice_tagged:
                        all_active = sorted(set(tagged) | ({untagged} if untagged else set()), key=int)
                        rec = ops.setdefault(port, {})
                        rec["mode"] = "trunk"
                        rec["oper_mode"] = "trunk"
                        rec["encapsulation"] = "dot1q"
                        rec["trunk_active_vlans"] = ",".join(all_active)
                        rec["native_vlan"] = untagged or "none"
                        rec["native_vlan_tagged"] = not bool(untagged)
                    elif untagged:
                        rec = ops.setdefault(port, {})
                        rec["mode"] = "access"
                        rec["oper_mode"] = "access"
                        rec["encapsulation"] = "dot1q"
                        rec["access_vlan"] = untagged
                        rec["native_vlan_tagged"] = False
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show vlans ports all failed: %s", self.ip, exc)

        try:
            raw_stp = conn.send_command("show spanning-tree detail")
            if isinstance(raw_stp, str) and raw_stp and "Invalid input" not in raw_stp:
                for line in raw_stp.splitlines():
                    m_st = re.match(
                        r"^\s*([A-Za-z]?\d+(?:/\d+)?)\s+\|\s+(?:100Mb|1Gb|10Gb|\S+)\s+\|\s+\d+\s+\|\s+(\S+)\s+\|\s+(\S+)",
                        line,
                    )
                    if m_st:
                        p, state, role = m_st.group(1), m_st.group(2), m_st.group(3)
                        ops.setdefault(p, {})["stp_state"] = state
                        ops[p]["stp_role"] = role
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show spanning-tree detail failed: %s", self.ip, exc)

        try:
            raw_auth = conn.send_command("show port-access authenticator")
            if isinstance(raw_auth, str) and raw_auth and "Invalid input" not in raw_auth:
                for line in raw_auth.splitlines():
                    m_au = re.match(r"^\s*([A-Za-z]?\d+(?:/\d+)?)\s+(?:Enabled|Active)", line, re.I)
                    if m_au:
                        ops.setdefault(m_au.group(1), {})["auth_policy"] = "dot1x"
        except Exception as exc:
            logger.debug("[%s] HP ProCurve show port-access authenticator failed: %s", self.ip, exc)

        return ops

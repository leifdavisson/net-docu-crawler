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
import re

import oui_lookup
import parser as cli_parser
from net_docu_crawler.drivers.base import BaseDriver

_BARE_VT100_RE = re.compile(r"\[(?:\?[0-9;]*[hl]|[0-9;]*[HJKr])")


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
        device = {
            "device_type": "hp_procurve",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.secret,
            "timeout": self.timeout,
            "auth_timeout": self.timeout,
            "ansi_escape_codes": True,
        }
        if self.session_log:
            device["session_log"] = self.session_log
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
        raw_sys = ""
        try:
            raw_sys = conn.send_command("show system")
        except Exception:
            pass

        m_host = re.search(r"System Name\s*:\s*(\S+)", raw_sys)
        if m_host:
            info["hostname"] = m_host.group(1).strip()
        else:
            try:
                info["hostname"] = conn.find_prompt().rstrip(">#").strip()
            except Exception:
                pass

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
        except Exception:
            pass

        return info

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
                            except Exception:
                                l3_interfaces.append(
                                    {
                                        "interface": vlan_name,
                                        "ip_address": f"{ip_addr} {mask}",
                                        "status": "up",
                                        "protocol": "up",
                                    }
                                )
        except Exception:
            pass

        # 2. Port descriptions via show name
        port_names = {}
        try:
            raw_names = conn.send_command("show name")
            for line in raw_names.splitlines():
                m_name = re.match(r"^\s*([A-Za-z0-9/]+)\s+\S+\s+(.+)$", line)
                if m_name and not ("Port" in line or "---" in line):
                    port_names[m_name.group(1).strip()] = m_name.group(2).strip()
        except Exception:
            pass

        # 3. Physical port status via show interfaces brief
        try:
            raw_brief = conn.send_command("show interfaces brief")
            for line in raw_brief.splitlines():
                m_port = re.match(r"^\s*([A-Za-z0-9/]+)\s+\S+\s+\|\s+\S+\s+(Yes|No)\s+(Up|Down)\s+(\S+)", line)
                if m_port and not ("Port" in line or "---" in line):
                    port = m_port.group(1).strip()
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
                        "speed": speed,
                        "duplex": duplex,
                        "mac_address": "",
                        "description": port_names.get(port, ""),
                    }
        except Exception:
            pass

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
                            dev_type = "switch"
                            if any(w in plat.lower() for w in ["ap", "access point", "aruba"]):
                                dev_type = "ap"
                            elif any(w in plat.lower() for w in ["router", "mikrotik"]):
                                dev_type = "router"

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
        except Exception:
            pass

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
            except Exception:
                pass

        return neighbors

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
        except Exception:
            pass
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
        except Exception:
            pass
        return arp

    def get_mac_table(self, conn) -> list[dict]:
        mac_table = []
        try:
            raw = conn.send_command("show mac-address")
            for line in raw.splitlines():
                m_mac = re.match(r"^\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)\s+(\S+)\s+(\S+)", line)
                if m_mac and not ("MAC Address" in line or "---" in line):
                    mac = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                    port = m_mac.group(2)
                    vlan = m_mac.group(3)
                    mac_table.append({"mac": mac, "port": port, "vlan": vlan})
        except Exception:
            pass
        return mac_table

    def get_stp(self, conn) -> dict:
        stp = {"enabled": False, "is_root": False, "vlans": {}}
        try:
            raw = conn.send_command("show spanning-tree")
            if "STP Enabled   : Yes" in raw or "STP Enabled [No] : Yes" in raw:
                stp["enabled"] = True
            m_root = re.search(r"Root Bridge MAC Address\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw)
            m_this = re.search(r"Switch MAC Address\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw)
            if m_root and m_this:
                r_mac = oui_lookup.normalize_mac(m_root.group(1)).lower()
                s_mac = oui_lookup.normalize_mac(m_this.group(1)).lower()
                if r_mac == s_mac:
                    stp["is_root"] = True
        except Exception:
            pass
        return stp

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show running-config")
        except Exception:
            try:
                return conn.send_command("show config")
            except Exception:
                return ""

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show power-over-ethernet brief")
            m_tot = re.search(r"Total Available Power\s*:\s*([\d.]+)\s*W", raw, re.IGNORECASE)
            m_used = re.search(r"Total Power Drawn\s*:\s*([\d.]+)\s*W", raw, re.IGNORECASE)
            if m_tot:
                poe["total_power_watts"] = float(m_tot.group(1))
            if m_used:
                poe["used_power_watts"] = float(m_used.group(1))
            poe["available_power_watts"] = max(0.0, poe["total_power_watts"] - poe["used_power_watts"])
            for line in raw.splitlines():
                m_p = re.match(
                    r"^\s*([A-Za-z0-9/]+)\s*\|\s*(Yes|No)\b.*?([\d.]+)\s*W",
                    line,
                    re.IGNORECASE,
                )
                if m_p:
                    port, enabled, watts = m_p.groups()
                    w_val = float(watts)
                    if w_val > 0 or enabled.lower() == "yes":
                        poe["ports"][port] = {"status": "delivering" if w_val > 0 else "idle", "power_watts": w_val}
        except Exception:
            pass
        return poe

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show interfaces transceiver")
            for line in raw.splitlines():
                m_opt = re.match(
                    r"^\s*(\S+)\s+(SFP\S*|QSFP\S*|XFP\S*)\s+(\S+)\s+",
                    line,
                    re.IGNORECASE,
                )
                if m_opt:
                    optics.append(
                        {
                            "port": m_opt.group(1),
                            "type": m_opt.group(2),
                            "part_number": m_opt.group(3),
                            "status": "present",
                        }
                    )
        except Exception:
            pass
        return optics

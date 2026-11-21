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
Fortinet Driver: FortiGate Firewalls running FortiOS.
Official Documentation: https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference
"""

import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

FORTIOS_VIRTUAL_PSEUDO_PREFIXES = ("naf.", "l2t.", "ssl.", "vsw.", "npu")


class FortinetDriver(BaseDriver):
    """
    Driver for Fortinet FortiGate appliances running FortiOS.
    Persona: firewall.
    """

    vendor_name = "Fortinet"
    device_persona = "firewall"
    default_device_type = "firewall"
    supports_telnet = False
    paging_cmd = "config system console\nset output standard\nend"

    def connect(self):
        device = self._build_netmiko_params("fortinet", global_delay_factor=2)
        return self.connect_netmiko(device)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "FortiGate Firewall",
            "serial": "Unknown",
            "firmware": "FortiOS",
            "os_type": "fortinet",
            "device_persona": "firewall",
        }
        try:
            raw = conn.send_command("get system status")
            m_host = re.search(r"Hostname:\s*(\S+)", raw)
            if m_host:
                info["hostname"] = m_host.group(1)
            m_ver = re.search(r"Version:\s*([^\r\n]+)", raw)
            if m_ver:
                info["firmware"] = m_ver.group(1).strip()
                m_mod = re.search(r"(FortiGate[^\s,]+)", m_ver.group(1))
                if m_mod:
                    info["model"] = m_mod.group(1)
            m_sn = re.search(r"Serial-Number:\s*(\S+)", raw)
            if m_sn:
                info["serial"] = m_sn.group(1)
        except Exception as exc:
            logger.debug("[%s] FortiOS get system status failed: %s", self.ip, exc)

        if not info["hostname"]:
            prompt = conn.find_prompt()
            m_p = re.match(r"^([A-Za-z0-9_-]+)", prompt)
            if m_p and m_p.group(1).lower() not in (
                "authentication",
                "password",
                "login",
                "username",
                "incorrect",
                "failed",
                "denied",
            ):
                info["hostname"] = m_p.group(1)

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}
        try:
            raw = conn.send_command("show system interface")
            current_intf = None
            for line in raw.splitlines():
                line = line.strip()
                m_edit = re.match(r'^edit\s+"([^"]+)"$|^edit\s+(\S+)$', line)
                if m_edit:
                    cand = (m_edit.group(1) or m_edit.group(2) or "").strip()
                    if not cand or cand.lower().startswith(FORTIOS_VIRTUAL_PSEUDO_PREFIXES):
                        current_intf = None
                        continue
                    current_intf = cand
                    interfaces_detail[current_intf] = {
                        "status": "up",
                        "protocol": "up",
                        "description": "",
                        "mac_address": "",
                        "speed": "N/A",
                        "duplex": "N/A",
                    }
                elif line.startswith("set ip ") and current_intf:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "0.0.0.0":
                        current_ip = parts[2]
                        mask = parts[3] if len(parts) > 3 else ""
                        l3_interfaces.append(
                            {
                                "interface": current_intf,
                                "ip_address": f"{current_ip} {mask}".strip(),
                                "status": "up",
                                "protocol": "up",
                            }
                        )
                elif line.startswith("set description ") and current_intf:
                    interfaces_detail[current_intf]["description"] = (
                        line.split("set description", 1)[1].strip().strip('"')
                    )
                elif line.startswith("set alias ") and current_intf:
                    if not interfaces_detail[current_intf]["description"]:
                        interfaces_detail[current_intf]["description"] = (
                            line.split("set alias", 1)[1].strip().strip('"')
                        )
                elif line.startswith("set vlanid ") and current_intf:
                    vlan_val = line.split("set vlanid", 1)[1].strip().strip('"')
                    if vlan_val.isdigit():
                        interfaces_detail[current_intf]["vlan"] = int(vlan_val)
                elif "set status down" in line and current_intf:
                    interfaces_detail[current_intf]["status"] = "down"
                    interfaces_detail[current_intf]["protocol"] = "down"
        except Exception as exc:
            logger.debug("[%s] FortiOS show system interface failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    @staticmethod
    def _parse_lldp_blocks(raw: str) -> list[dict]:
        neighbors = []
        current: dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Port:"):
                if current.get("local_port") and current.get("remote_device"):
                    neighbors.append(current)
                current = {
                    "local_port": line.split(":", 1)[1].strip(),
                    "remote_device": "",
                    "remote_port": "",
                    "remote_ip": "",
                    "platform": "",
                    "remote_platform": "",
                    "device_type": "switch",
                }
            elif "Chassis ID:" in line and current:
                current["remote_device"] = line.split(":", 1)[1].strip()
            elif "System Name:" in line and current:
                sys_name = line.split(":", 1)[1].strip()
                if sys_name:
                    current["remote_device"] = sys_name
            elif "Port ID:" in line and current:
                current["remote_port"] = line.split(":", 1)[1].strip()
            elif "System Description:" in line and current:
                desc = line.split(":", 1)[1].strip()[:60]
                current["platform"] = desc
                current["remote_platform"] = desc
        if current.get("local_port") and current.get("remote_device"):
            neighbors.append(current)
        return neighbors

    def get_neighbors(self, conn) -> list[dict]:
        for cmd in (
            "diagnose snmp sysinfo lldp neighbor",
            "diagnose lldp neighbor list",
            "get switch lldp neighbors-summary",
        ):
            try:
                raw = conn.send_command(cmd)
                if not raw or "command parse error" in raw.lower():
                    continue
                parsed = self._parse_lldp_blocks(raw)
                if parsed:
                    self._discovery_protocols = {
                        "lldp": "enabled",
                        "cdp": "unsupported",
                        "mndp": "unsupported",
                        "notes": "",
                    }
                    return parsed
            except Exception as exc:
                logger.debug("[%s] FortiOS LLDP command '%s' failed: %s", self.ip, cmd, exc)
        return []

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        if neighbors:
            return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}
        cfg_low = (raw_config or "").lower()
        if "set lldp-transmission enable" in cfg_low or "set lldp-reception enable" in cfg_low:
            return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}
        return {
            "lldp": "disabled",
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": "FortiOS LLDP TX/RX is disabled by default; enable per-interface or globally.",
        }

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("get router info routing-table all")
            for line in raw.splitlines():
                m = re.search(
                    r"^([A-Z*>\s]+)\s+([0-9./]+)\s+(?:\[\d+/\d+\]\s+(?:via\s+([0-9.]+))?|is\s+directly\s+connected),\s+(.+?)(?:,\s+\d{2}:\d{2}:\d{2}|,\s+\[\d+/\d+\])?$",
                    line.strip(),
                )
                if m:
                    proto = m.group(1).strip()
                    subnet = m.group(2)
                    next_hop = m.group(3) or "Direct"
                    intf = m.group(4).strip()
                    routes.append(
                        {
                            "subnet": subnet,
                            "next_hop": next_hop,
                            "interface": intf,
                            "protocol": proto,
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] FortiOS get router info routing-table all failed: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("get system arp")
            for line in raw.splitlines():
                parts = line.split()
                # FortiOS format can be: "192.168.1.10 0 fc:33:42:e6:b5:99 port1" or "192.168.1.10 fc:33:42:e6:b5:99 port1"
                if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                    mac_idx = 2 if len(parts) >= 4 and parts[1].isdigit() else 1
                    mac = oui_lookup.normalize_mac(parts[mac_idx]).lower()
                    intf = " ".join(parts[mac_idx + 1 :]) if len(parts) > mac_idx + 1 else ""
                    arp_entries.append(
                        {
                            "ip": parts[0],
                            "mac": mac,
                            "interface": intf,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] FortiOS get system arp failed: %s", self.ip, exc)
        return arp_entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("get system interface transceiver")
            cur_entry: dict = {}
            for line in raw.splitlines():
                m_if = re.match(r"^Interface\s+([A-Za-z0-9_.-]+)\s+-", line.strip(), re.IGNORECASE)
                if m_if:
                    if cur_entry:
                        optics.append(cur_entry)
                    cur_entry = {
                        "port": m_if.group(1),
                        "vendor": "Fortinet",
                        "part_number": "Unknown",
                        "serial": "Unknown",
                        "type": "SFP",
                        "tx_power_dbm": None,
                        "rx_power_dbm": None,
                        "temperature_c": None,
                        "voltage_v": None,
                    }
                elif cur_entry:
                    m_vn = re.search(r"Vendor Name\s*:\s*(.+)", line, re.IGNORECASE)
                    m_pn = re.search(r"Part No\.\s*:\s*(\S+)", line, re.IGNORECASE)
                    m_sn = re.search(r"Serial No\.\s*:\s*(\S+)", line, re.IGNORECASE)
                    if m_vn:
                        cur_entry["vendor"] = m_vn.group(1).strip()
                    if m_pn:
                        cur_entry["part_number"] = m_pn.group(1).strip()
                    if m_sn:
                        cur_entry["serial"] = m_sn.group(1).strip()
            if cur_entry:
                optics.append(cur_entry)
        except Exception as exc:
            logger.debug("[%s] FortiOS get system interface transceiver failed: %s", self.ip, exc)
        return optics

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "show full-configuration")

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
Cisco Systems Driver: IOS, IOS-XE, NX-OS, and IOS-XR.
Official Documentation: https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html
"""

import re

from netmiko import ConnectHandler

import oui_lookup
import parser
from net_docu_crawler.drivers.base import BaseDriver


class CiscoDriver(BaseDriver):
    vendor_name = "Cisco Systems"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "terminal length 0"

    def connect(self):
        device = {
            "device_type": "cisco_ios",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.secret,
            "timeout": self.timeout,
            "auth_timeout": self.timeout,
            "global_delay_factor": 2,
        }
        if self.session_log:
            device["session_log"] = self.session_log
        conn = ConnectHandler(**device)
        if self.secret:
            try:
                conn.enable()
            except Exception:
                pass
        return conn

    def get_version(self, conn) -> dict:
        sh_ver = conn.send_command("show version")
        os_type = "cisco_ios"
        if "NX-OS" in sh_ver or "Nexus" in sh_ver:
            os_type = "cisco_nxos"
        elif "IOS-XR" in sh_ver or "IOS XR" in sh_ver:
            os_type = "cisco_xr"

        ver = parser.parse_show_version(sh_ver, os_type)
        ver["os_type"] = os_type

        # Verify model and serial via show inventory if available
        try:
            sh_inv = conn.send_command("show inventory")
            inv_items = parser.parse_show_inventory(sh_inv)
            for item in inv_items:
                if "chassis" in item.get("name", "").lower() or "chassis" in item.get("descr", "").lower():
                    if item.get("pid"):
                        ver["model"] = item["pid"]
                    if item.get("sn") and item["sn"] != "N/A":
                        ver["serial"] = item["sn"]
                    break
        except Exception:
            pass

        # Classify router vs switch persona accurately (e.g. CISCO891-K9, ISR, ASR, IOS-XR)
        dev_type = parser.classify_device_type(model=ver.get("model", ""), device_id=ver.get("hostname", ""))
        if os_type == "cisco_xr" or ver.get("model", "").upper().startswith(
            ("CISCO8", "CISCO19", "CISCO29", "CISCO39")
        ):
            dev_type = "router"
        ver["device_type"] = dev_type
        ver["device_persona"] = dev_type

        return ver

    def get_interfaces(self, conn) -> tuple[list, dict]:
        sh_ip_int = conn.send_command("show ip interface brief")
        l3_ints = parser.parse_ip_interface_brief(sh_ip_int, "cisco_ios")

        sh_ints = conn.send_command("show interfaces")
        ints_detail = parser.parse_show_interfaces(sh_ints, "cisco_ios")
        for stats in ints_detail.values():
            if stats.get("mac_address"):
                stats["mac_address"] = oui_lookup.normalize_mac(stats["mac_address"]).lower()
        return l3_ints, ints_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        seen = set()
        try:
            sh_cdp = conn.send_command("show cdp neighbors detail")
            for n in parser.parse_cdp_neighbors_detail(sh_cdp):
                n["remote_platform"] = n.get("platform", "")
                key = (n.get("local_port", ""), n.get("remote_device", "").lower())
                if key not in seen:
                    seen.add(key)
                    neighbors.append(n)
        except Exception:
            pass
        try:
            sh_lldp = conn.send_command("show lldp neighbors detail")
            for n in parser.parse_lldp_neighbors_detail(sh_lldp):
                n["remote_platform"] = n.get("platform", "")
                key = (n.get("local_port", ""), n.get("remote_device", "").lower())
                if key not in seen:
                    seen.add(key)
                    neighbors.append(n)
        except Exception:
            pass
        return neighbors

    def get_stp(self, conn) -> dict:
        try:
            sh_stp = conn.send_command("show spanning-tree")
            return parser.parse_spanning_tree(sh_stp, "cisco_ios")
        except Exception:
            return {"enabled": False, "vlans": {}}

    def get_routing_table(self, conn) -> list[dict]:
        try:
            sh_route = conn.send_command("show ip route")
            return parser.parse_show_ip_route(sh_route, "cisco_ios")
        except Exception:
            return []

    def get_arp_table(self, conn) -> list[dict]:
        try:
            sh_arp = conn.send_command("show ip arp")
            return parser.parse_show_ip_arp(sh_arp)
        except Exception:
            return []

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show power inline")
            m_tot = re.search(r"Available:\s*([\d.]+)\s*\(W\)", raw)
            m_used = re.search(r"Used:\s*([\d.]+)\s*\(W\)", raw)
            m_rem = re.search(r"Remaining:\s*([\d.]+)\s*\(W\)", raw)
            if m_tot:
                poe["total_power_watts"] = float(m_tot.group(1))
            if m_used:
                poe["used_power_watts"] = float(m_used.group(1))
            if m_rem:
                poe["available_power_watts"] = float(m_rem.group(1))
        except Exception:
            pass
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show mac address-table")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 4 and ("DYNAMIC" in line.upper() or "STATIC" in line.upper()):
                    mac = oui_lookup.normalize_mac(parts[1]).lower()
                    entries.append(
                        {
                            "vlan": parts[0],
                            "mac": mac,
                            "type": parts[2].lower(),
                            "interface": parts[3],
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception:
            pass
        return entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show interfaces transceiver")
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("Port") or "---" in line or "Transceiver" in line:
                    continue
                m = re.match(
                    r"^([A-Za-z0-9/\._-]+)\s+([\d\.\-]+)\s*(?:C)?\s+([\d\.\-]+)\s*(?:V)?\s+([\d\.\-]+)\s*(?:mA)?\s+([\d\.\-]+)\s*(?:dBm)?\s+([\d\.\-]+)",
                    line,
                )
                if m:
                    port = m.group(1)
                    temp = float(m.group(2)) if m.group(2) != "N/A" else None
                    volt = float(m.group(3)) if m.group(3) != "N/A" else None
                    tx = float(m.group(5)) if m.group(5) != "N/A" else None
                    rx = float(m.group(6)) if m.group(6) != "N/A" else None
                    optics.append(
                        {
                            "port": port,
                            "vendor": "Cisco",
                            "part_number": "SFP-DOM",
                            "serial": "Unknown",
                            "type": "SFP+",
                            "tx_power_dbm": tx,
                            "rx_power_dbm": rx,
                            "temperature_c": temp,
                            "voltage_v": volt,
                        }
                    )
        except Exception:
            pass
        return optics

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show running-config")
        except Exception:
            return ""

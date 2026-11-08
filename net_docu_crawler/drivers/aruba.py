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
Official Documentation: https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm
"""

import re

from netmiko import ConnectHandler

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver


class ArubaDriver(BaseDriver):
    vendor_name = "Aruba Networks / HPE"
    device_persona = "ap"
    default_device_type = "ap"
    paging_cmd = "no page"

    def connect(self):
        device = {
            "device_type": "aruba_os",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "timeout": self.timeout,
            "auth_timeout": self.timeout,
            "global_delay_factor": 2,
        }
        if self.session_log:
            device["session_log"] = self.session_log
        conn = ConnectHandler(**device)
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Aruba AP",
            "serial": "Unknown",
            "firmware": "ArubaOS",
            "os_type": "aruba_os",
            "device_persona": self.device_persona,
        }
        raw = conn.send_command("show version")
        m_model = re.search(r"MODEL:\s*(\w+)", raw)
        if m_model:
            info["model"] = f"Aruba AP-{m_model.group(1)}"
        m_ver = re.search(r"Version\s*(\S+)", raw)
        if m_ver:
            info["firmware"] = m_ver.group(1)

        info["hostname"] = conn.find_prompt().replace("#", "").replace(">", "").strip()

        # Query AP cluster details if IAP
        try:
            raw_aps = conn.send_command("show aps")
            for line in raw_aps.splitlines():
                parts = line.split()
                if len(parts) >= 10 and "*" in parts[1]:  # Master IAP indicator
                    info["hostname"] = parts[0]
                    info["serial"] = parts[9]
                    break
        except Exception:
            pass

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = [{"interface": "br0", "ip_address": self.ip, "status": "up", "protocol": "up"}]
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
        try:
            raw = conn.send_command("show ap debug lldp info")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 9 and "." in parts[8]:
                    rem_intf = re.sub(r"\.0$", "", parts[3])
                    rem_mac = parts[7]
                    rem_host = parts[8]
                    plat = f"Switch ({oui_lookup.lookup_oui(rem_mac)})"
                    neighbors.append(
                        {
                            "local_port": parts[1],
                            "remote_device": rem_host.split(".")[0],
                            "remote_port": rem_intf,
                            "remote_ip": "",
                            "remote_mac": rem_mac,
                            "platform": plat,
                            "remote_platform": plat,
                            "device_type": "switch",
                        }
                    )
        except Exception:
            pass
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        return [{"subnet": "0.0.0.0/0", "protocol": "Default", "next_hop": "Gateway", "interface": "eth0"}]

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("show clients")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 3 and "." in parts[0] and ":" in parts[1]:
                    norm_mac = oui_lookup.normalize_mac(parts[1]).lower()
                    arp_entries.append(
                        {
                            "ip": parts[0],
                            "mac": norm_mac,
                            "interface": "wlan",
                            "age": "1",
                            "type": "Wireless Client",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception:
            pass
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show configuration")
        except Exception:
            return conn.send_command("show run")

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
Palo Alto Networks Driver: PAN-OS Firewalls and Management Appliances.
Official Documentation: https://docs.paloaltonetworks.com/pan-os
"""

import re

from netmiko import ConnectHandler

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver


class PaloAltoDriver(BaseDriver):
    """
    Driver for Palo Alto Networks Next-Generation Firewalls running PAN-OS.
    Persona: firewall.
    """

    vendor_name = "Palo Alto Networks"
    device_persona = "firewall"
    default_device_type = "firewall"
    paging_cmd = "set cli pager off"

    def connect(self):
        device = {
            "device_type": "paloalto_panos",
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
        try:
            conn.send_command(self.paging_cmd)
        except Exception:
            pass
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Palo Alto Firewall",
            "serial": "Unknown",
            "firmware": "PAN-OS",
            "os_type": "paloalto_panos",
            "device_persona": "firewall",
        }
        try:
            raw = conn.send_command("show system info")
            m_host = re.search(r"hostname:\s*(\S+)", raw)
            if m_host:
                info["hostname"] = m_host.group(1)
            m_model = re.search(r"model:\s*(\S+)", raw)
            if m_model:
                info["model"] = f"PA-{m_model.group(1)}" if not m_model.group(1).startswith("PA") else m_model.group(1)
            m_serial = re.search(r"serial:\s*(\S+)", raw)
            if m_serial:
                info["serial"] = m_serial.group(1)
            m_ver = re.search(r"sw-version:\s*(\S+)", raw)
            if m_ver:
                info["firmware"] = f"PAN-OS {m_ver.group(1)}"
            m_mac = re.search(r"mac-address:\s*([0-9a-fA-F:.-]+)", raw)
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()
        except Exception:
            pass

        if not info["hostname"]:
            prompt = conn.find_prompt()
            if "@" in prompt:
                info["hostname"] = prompt.split("@")[-1].replace(">", "").replace("#", "").strip()

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}
        try:
            raw = conn.send_command("show interface all")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 4 and ("ethernet" in parts[0] or "vlan" in parts[0] or "tunnel" in parts[0]):
                    intf_name = parts[0]
                    ip_candidate = parts[1]
                    ip_addr = (
                        ip_candidate if "/" in ip_candidate or re.match(r"\d+\.\d+\.\d+\.\d+", ip_candidate) else "N/A"
                    )
                    status = "up" if "up" in line.lower() else "down"

                    if ip_addr != "N/A":
                        l3_interfaces.append(
                            {
                                "interface": intf_name,
                                "ip_address": ip_addr,
                                "status": status,
                                "protocol": status,
                            }
                        )

                    interfaces_detail[intf_name] = {
                        "status": status,
                        "protocol": status,
                        "description": "",
                        "mac_address": "",
                        "speed": "N/A",
                        "duplex": "N/A",
                    }
        except Exception:
            pass

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("show lldp neighbors all")
            current: dict[str, str] = {}
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("Interface:"):
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
                elif "System Name:" in line and current:
                    current["remote_device"] = line.split(":", 1)[1].strip()
                elif "Port ID:" in line and current:
                    current["remote_port"] = line.split(":", 1)[1].strip()
                elif "Management Address:" in line and current:
                    current["remote_ip"] = line.split(":", 1)[1].strip()
                elif "System Description:" in line and current:
                    desc = line.split(":", 1)[1].strip()[:60]
                    current["platform"] = desc
                    current["remote_platform"] = desc
            if current.get("local_port") and current.get("remote_device"):
                neighbors.append(current)
        except Exception:
            pass

        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show routing route")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 4 and "/" in parts[0]:
                    routes.append(
                        {
                            "subnet": parts[0],
                            "next_hop": parts[1] if parts[1] != "0.0.0.0" else "Direct",
                            "interface": parts[3] if len(parts) > 3 else "N/A",
                            "protocol": parts[2] if len(parts) > 2 else "A",
                        }
                    )
        except Exception:
            pass
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("show arp all")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 3 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                    mac = oui_lookup.normalize_mac(parts[1]).lower()
                    arp_entries.append(
                        {
                            "ip": parts[0],
                            "mac": mac,
                            "interface": parts[2] if len(parts) > 2 else "",
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception:
            pass
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show config running")
        except Exception:
            return ""

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
FRRouting (FRR) Driver: Linux routing daemon suite using vtysh.
Official Documentation: https://docs.frrouting.org/
"""

import json
import re

from netmiko import ConnectHandler

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver


class FRRDriver(BaseDriver):
    """
    Driver for FRRouting daemons running on Linux hosts / containers.
    Persona: router / routing engine.
    """

    vendor_name = "FRRouting"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = ""

    def connect(self):
        device = {
            "device_type": "linux",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "timeout": self.timeout,
            "auth_timeout": self.timeout,
        }
        if self.session_log:
            device["session_log"] = self.session_log
        conn = ConnectHandler(**device)
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "FRR-Router",
            "model": "FRRouting Linux Daemon",
            "serial": "Unknown",
            "firmware": "FRR",
            "os_type": "frrouting",
            "device_persona": self.device_persona,
        }
        try:
            h = conn.send_command("hostname -s").strip()
            if h:
                info["hostname"] = h
        except Exception:
            pass

        try:
            raw = conn.send_command("vtysh -c 'show version'")
            m_ver = re.search(r"FRRouting\s+([^\s\(\)]+)", raw)
            if m_ver:
                info["firmware"] = f"FRR {m_ver.group(1)}"
        except Exception:
            pass

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}
        try:
            raw = conn.send_command("vtysh -c 'show interface json'")
            data = json.loads(raw)
            for intf_name, intf_info in data.items():
                if intf_name == "lo":
                    continue
                raw_mac = intf_info.get("hardwareAddress", "")
                mac = oui_lookup.normalize_mac(raw_mac).lower() if raw_mac else ""
                status = "up" if intf_info.get("operationalStatus") == "up" else "down"
                ip_list = intf_info.get("ipAddresses", [])
                primary_ip = ""
                for ip_obj in ip_list:
                    addr = ip_obj.get("address", "")
                    if ":" not in addr and not addr.startswith("127."):
                        primary_ip = addr
                        l3_interfaces.append(
                            {
                                "interface": intf_name,
                                "ip_address": addr,
                                "status": status,
                                "protocol": status,
                            }
                        )

                interfaces_detail[intf_name] = {
                    "ip_address": primary_ip,
                    "status": status,
                    "mac_address": mac,
                }
        except Exception:
            pass
        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("lldpcli show neighbors -f json")
            if raw.strip().startswith("{"):
                data = json.loads(raw)
                for lldp_entry in data.get("lldp", {}).get("interface", []):
                    for intf_name, info in lldp_entry.items():
                        chassis = info.get("chassis", {})
                        port = info.get("port", {})
                        descr = chassis.get("descr", {}).get("value", "")[:60]
                        neighbors.append(
                            {
                                "local_port": intf_name,
                                "remote_device": chassis.get("name", {}).get("value", "Unknown"),
                                "remote_port": port.get("id", {}).get("value", "Unknown"),
                                "remote_ip": "",
                                "platform": descr,
                                "remote_platform": descr,
                                "device_type": "router",
                            }
                        )
        except Exception:
            pass
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("vtysh -c 'show ip route json'")
            data = json.loads(raw)
            for subnet, r_list in data.items():
                for r in r_list:
                    proto = r.get("protocol", "unknown")
                    nh_list = r.get("nexthops", [])
                    next_hop = nh_list[0].get("ip", "connected") if nh_list else "connected"
                    intf = nh_list[0].get("interfaceName", "") if nh_list else ""
                    routes.append(
                        {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": next_hop,
                            "interface": intf,
                        }
                    )
        except Exception:
            pass
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("ip -j neigh show")
            data = json.loads(raw)
            for entry in data:
                ip_addr = entry.get("dst", "")
                mac = entry.get("lladdr", "")
                dev = entry.get("dev", "")
                if ip_addr and mac and ":" not in ip_addr:
                    norm_mac = oui_lookup.normalize_mac(mac).lower()
                    arp_entries.append(
                        {
                            "ip": ip_addr,
                            "mac": norm_mac,
                            "interface": dev,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception:
            pass
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("vtysh -c 'show running-config'")
        except Exception:
            return ""

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
OpenWrt Driver: Embedded Linux-based operating system for wireless routers and gateways.
Parses system details via ubus / sysfs, network interfaces via ubus network.interface dump / ip,
routing table via ip route, ARP table via /proc/net/arp, and full config via uci export.
Official Documentation: https://openwrt.org/docs/start
"""

import json
import re

from netmiko import ConnectHandler

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver


class OpenWrtDriver(BaseDriver):
    """
    Driver for OpenWrt routers, access points, and gateways.
    Persona: router / gateway / ap.
    """

    vendor_name = "OpenWrt"
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
            "hostname": "OpenWrt",
            "model": "OpenWrt Router",
            "serial": "Unknown",
            "firmware": "OpenWrt",
            "os_type": "openwrt",
            "device_persona": self.device_persona,
        }

        try:
            raw_board = conn.send_command("ubus call system board 2>/dev/null").strip()
            if raw_board.startswith("{"):
                data = json.loads(raw_board)
                if data.get("hostname"):
                    info["hostname"] = data["hostname"]
                if data.get("model"):
                    info["model"] = data["model"]
                rel = data.get("release", {})
                if rel.get("description"):
                    info["firmware"] = rel["description"]
                elif rel.get("version"):
                    info["firmware"] = f"OpenWrt {rel['version']}"
                if rel.get("target") and rel["target"] not in info["model"]:
                    info["model"] = f"{info['model']} ({rel['target']})"
        except Exception:
            pass

        if info["hostname"] == "OpenWrt":
            try:
                h = conn.send_command("cat /proc/sys/kernel/hostname 2>/dev/null || hostname").strip()
                if h:
                    info["hostname"] = h
            except Exception:
                pass

        if info["firmware"] == "OpenWrt":
            try:
                rel_raw = conn.send_command("cat /etc/openwrt_release 2>/dev/null").strip()
                m_desc = re.search(r"DISTRIB_DESCRIPTION=['\"]([^'\"]+)['\"]", rel_raw)
                if m_desc:
                    info["firmware"] = m_desc.group(1)
            except Exception:
                pass

        if info["model"] == "OpenWrt Router":
            try:
                cpuinfo = conn.send_command("cat /proc/cpuinfo 2>/dev/null").strip()
                m_mach = re.search(r"(?:machine|model name|Hardware)\s*:\s*(.+)", cpuinfo, re.IGNORECASE)
                if m_mach:
                    info["model"] = m_mach.group(1).strip()
            except Exception:
                pass

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}

        # 1. Primary method: ubus call network.interface dump
        used_ubus = False
        try:
            raw_net = conn.send_command("ubus call network.interface dump 2>/dev/null").strip()
            if raw_net.startswith("{"):
                data = json.loads(raw_net)
                intf_list = data.get("interface", [])
                for intf in intf_list:
                    logical_name = intf.get("interface", "unknown")
                    device_name = intf.get("device") or intf.get("l3_device") or logical_name
                    if device_name == "lo" or logical_name == "loopback":
                        continue
                    is_up = bool(intf.get("up", False))
                    status_str = "up" if is_up else "down"

                    ipv4_addrs = intf.get("ipv4-address", [])
                    primary_ip = ""
                    for addr_entry in ipv4_addrs:
                        addr = addr_entry.get("address")
                        mask = addr_entry.get("mask", 24)
                        if addr and not addr.startswith("127."):
                            full_ip = f"{addr}/{mask}"
                            if not primary_ip:
                                primary_ip = full_ip
                            l3_interfaces.append(
                                {
                                    "interface": device_name,
                                    "ip_address": full_ip,
                                    "status": status_str,
                                    "protocol": status_str,
                                }
                            )

                    interfaces_detail[device_name] = {
                        "ip_address": primary_ip,
                        "status": status_str,
                        "mac_address": "",
                        "description": f"OpenWrt logical interface: {logical_name} (proto={intf.get('proto', 'static')})",
                    }
                used_ubus = bool(interfaces_detail)
        except Exception:
            pass

        # 2. Extract MAC addresses and physical state via ip or sysfs
        try:
            ip_raw = conn.send_command("ip -d address show 2>/dev/null || ip address show 2>/dev/null").strip()
            current_intf = None
            for line in ip_raw.splitlines():
                m_hdr = re.match(r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):.*<([^>]+)>", line)
                if m_hdr:
                    cand = m_hdr.group(1).split("@")[0]
                    if cand == "lo":
                        current_intf = None
                        continue
                    current_intf = cand
                    flags = m_hdr.group(2)
                    status_str = "up" if "UP" in flags else "down"
                    if current_intf not in interfaces_detail:
                        interfaces_detail[current_intf] = {
                            "ip_address": "",
                            "status": status_str,
                            "mac_address": "",
                            "description": "",
                        }
                    else:
                        interfaces_detail[current_intf]["status"] = status_str
                    continue

                if not current_intf:
                    continue

                m_link = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
                if m_link:
                    mac_addr = oui_lookup.normalize_mac(m_link.group(1)).lower()
                    if current_intf in interfaces_detail:
                        interfaces_detail[current_intf]["mac_address"] = mac_addr

                if not used_ubus:
                    m_inet = re.search(r"inet\s+([\d\.]+/\d+)", line)
                    if m_inet:
                        ip_val = m_inet.group(1)
                        if not ip_val.startswith("127."):
                            st = interfaces_detail.get(current_intf, {}).get("status", "up")
                            l3_interfaces.append(
                                {
                                    "interface": current_intf,
                                    "ip_address": ip_val,
                                    "status": st,
                                    "protocol": st,
                                }
                            )
                            if current_intf in interfaces_detail and not interfaces_detail[current_intf]["ip_address"]:
                                interfaces_detail[current_intf]["ip_address"] = ip_val
        except Exception:
            pass

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw_lldp = conn.send_command("lldpcli show neighbors -f json 2>/dev/null").strip()
            if raw_lldp.startswith("{"):
                data = json.loads(raw_lldp)
                for lldp_entry in data.get("lldp", {}).get("interface", []):
                    for intf_name, info in lldp_entry.items():
                        chassis = info.get("chassis", {})
                        port = info.get("port", {})
                        mgmt_ips = chassis.get("mgmt-ip", [])
                        remote_ip = mgmt_ips[0] if isinstance(mgmt_ips, list) and mgmt_ips else ""
                        descr = chassis.get("descr", {}).get("value", "")[:60]
                        neighbors.append(
                            {
                                "local_port": intf_name,
                                "remote_device": chassis.get("name", {}).get("value", "Unknown"),
                                "remote_port": port.get("id", {}).get("value", "Unknown"),
                                "remote_ip": remote_ip,
                                "platform": descr,
                                "remote_platform": descr,
                                "device_type": "switch",
                            }
                        )
        except Exception:
            pass

        try:
            raw_assoc = conn.send_command("ubus call hostapd.* get_clients 2>/dev/null").strip()
            if raw_assoc.startswith("{"):
                data = json.loads(raw_assoc)
                clients = data.get("clients", {})
                for mac_val in clients:
                    neighbors.append(
                        {
                            "local_port": "wlan",
                            "remote_device": f"Client-{mac_val[-5:].replace(':', '')}",
                            "remote_port": "wlan0",
                            "remote_ip": "",
                            "platform": "Wireless Client",
                            "remote_platform": "Wireless Client",
                            "device_type": "host",
                        }
                    )
        except Exception:
            pass

        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("ip route show 2>/dev/null || route -n 2>/dev/null")
            for line in raw.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("Kernel") or line.startswith("Destination"):
                    continue
                parts = line.split()
                if not parts:
                    continue

                if parts[0] == "default":
                    gw = parts[2] if len(parts) >= 3 and parts[1] == "via" else "0.0.0.0"
                    dev = parts[parts.index("dev") + 1] if "dev" in parts else ""
                    proto = parts[parts.index("proto") + 1] if "proto" in parts else "static"
                    routes.append(
                        {
                            "subnet": "0.0.0.0/0",
                            "protocol": proto,
                            "next_hop": gw,
                            "interface": dev,
                        }
                    )
                elif "/" in parts[0] or parts[0].count(".") == 3:
                    subnet = parts[0] if "/" in parts[0] else f"{parts[0]}/32"
                    gw = parts[parts.index("via") + 1] if "via" in parts else "0.0.0.0"
                    dev = parts[parts.index("dev") + 1] if "dev" in parts else ""
                    proto = parts[parts.index("proto") + 1] if "proto" in parts else "connected"
                    routes.append(
                        {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": gw,
                            "interface": dev,
                        }
                    )
        except Exception:
            pass
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("cat /proc/net/arp 2>/dev/null")
            lines = raw.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    ip_val = parts[0]
                    mac_val = oui_lookup.normalize_mac(parts[3]).lower()
                    dev_val = parts[5]
                    flags = parts[2]
                    if flags != "0x0" and mac_val != "00:00:00:00:00:00":
                        arp_entries.append(
                            {
                                "ip": ip_val,
                                "mac": mac_val,
                                "interface": dev_val,
                                "type": "dynamic",
                                "vendor": oui_lookup.lookup_oui(mac_val),
                            }
                        )
        except Exception:
            pass
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            config = conn.send_command("uci export 2>/dev/null")
            if config and len(config.strip()) > 50:
                return config
        except Exception:
            pass

        try:
            return conn.send_command("head -n 1000 /etc/config/* 2>/dev/null")
        except Exception:
            return ""

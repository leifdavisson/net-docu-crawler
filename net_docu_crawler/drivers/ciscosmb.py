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
Cisco Small Business Driver: SG250 / SG300 / SG350 / SG500 / CBS250 / CBS350 Managed Switches.
Uses Netmiko's `cisco_s300` device type (and `generic_telnet` / `cisco_s300` fallback) with strictly
read-only operational commands (`show system`, `show version`, `show interfaces status`,
`show ip interface`, `show lldp neighbors`, `show ip route`, `show arp`, `show spanning-tree`,
`show power inline`, `show mac address-table`, `show fiber-ports optical-transceiver`,
`show running-config`).
Official Documentation:
https://www.cisco.com/c/en/us/support/switches/small-business-300-series-managed-switches/products-command-reference-list.html
"""

import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver


class CiscoSMBDriver(BaseDriver):
    """
    Driver for Cisco Small Business managed switches (SG250/SG300/SG350/SG500/CBS250/CBS350).
    Persona: switch.
    """

    vendor_name = "CiscoSMB"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "terminal datadump"

    def connect(self):
        device = {
            "device_type": "cisco_s300",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.secret or self.password,
            "timeout": self.timeout,
            "conn_timeout": self.timeout,
        }
        if self.session_log:
            device["session_log"] = self.session_log

        conn = self.connect_netmiko(device)
        if self.secret or self.password:
            try:
                conn.enable()
            except Exception:
                pass
        try:
            conn.send_command(self.paging_cmd)
        except Exception:
            pass
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "ciscosmb-switch",
            "model": "Cisco Small Business Switch",
            "serial": "Unknown",
            "firmware": "Unknown",
            "os_type": "cisco_s300",
            "device_persona": "switch",
            "mac_address": "",
        }
        try:
            raw_sys = conn.send_command("show system")
            m_name = re.search(r"System Name:\s*(\S+)", raw_sys, re.IGNORECASE)
            if m_name:
                info["hostname"] = m_name.group(1).strip()
            m_mac = re.search(
                r"System MAC Address:\s*([0-9a-fA-F:.-]+)",
                raw_sys,
                re.IGNORECASE,
            )
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()
            m_desc = re.search(r"System Description:\s*(.+)", raw_sys, re.IGNORECASE)
            if m_desc and "cisco" in m_desc.group(1).lower():
                info["model"] = m_desc.group(1).strip()
        except Exception:
            pass

        try:
            raw_id = conn.send_command("show system id")
            m_pid = re.search(r"(?:PID VID|Model|Unit\s+Model)\s*:\s*(\S+)", raw_id, re.IGNORECASE)
            if m_pid:
                info["model"] = m_pid.group(1).strip()
            m_ser = re.search(r"Serial\s+Number\s*:\s*(\S+)", raw_id, re.IGNORECASE)
            if m_ser:
                info["serial"] = m_ser.group(1).strip()
        except Exception:
            pass

        try:
            raw_ver = conn.send_command("show version")
            m_sw = re.search(r"(?:SW|Active-image)\s+version\s*:\s*(\S+)", raw_ver, re.IGNORECASE)
            if m_sw:
                info["firmware"] = m_sw.group(1).strip()
            if info["model"] == "Cisco Small Business Switch":
                m_hw = re.search(r"(SG\d+\S*|CBS\d+\S*)", raw_ver, re.IGNORECASE)
                if m_hw:
                    info["model"] = m_hw.group(1).strip()
        except Exception:
            pass

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}

        # 1. L3 IP Interfaces (`show ip interface`)
        try:
            raw_ip = conn.send_command("show ip interface")
            for line in raw_ip.splitlines():
                m_ip = re.match(
                    r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)\s+(Valid|Static|DHCP|Tentative)?",
                    line,
                    re.IGNORECASE,
                )
                if m_ip:
                    ip_cidr, if_name, status_tok = m_ip.groups()
                    if ip_cidr.startswith("127."):
                        continue
                    l3_interfaces.append(
                        {
                            "interface": if_name,
                            "ip_address": ip_cidr,
                            "status": (status_tok or "up").lower(),
                            "protocol": "up",
                        }
                    )
        except Exception:
            pass

        # 2. Physical Port Status (`show interfaces status`)
        try:
            raw_st = conn.send_command("show interfaces status")
            for line in raw_st.splitlines():
                m_port = re.match(
                    r"^\s*((?:gi|fa|te|tw|Po)\S+)\s+\S+\s+(Full|Half|--)\s+(\d+|--)\s+\S+\s+\S+\s+(Up|Down)",
                    line,
                    re.IGNORECASE,
                )
                if m_port:
                    port, duplex, speed_raw, state = m_port.groups()
                    if port.lower().startswith("vlan"):
                        continue
                    speed = "Auto"
                    if speed_raw == "10000":
                        speed = "10Gb/s"
                    elif speed_raw == "1000":
                        speed = "1Gb/s"
                    elif speed_raw == "100":
                        speed = "100Mb/s"
                    elif speed_raw == "10":
                        speed = "10Mb/s"

                    interfaces_detail[port] = {
                        "status": state.lower(),
                        "protocol": state.lower(),
                        "speed": speed,
                        "duplex": duplex if duplex != "--" else "Auto",
                        "mac_address": "",
                        "description": "",
                    }
        except Exception:
            pass

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw_lldp = conn.send_command("show lldp neighbors")
            for line in raw_lldp.splitlines():
                # Format: Port  Device ID  Port ID  System Name  Capabilities  TTL
                m_n = re.match(
                    r"^\s*((?:gi|fa|te|tw)\S+)\s+([0-9a-fA-F:.-]+)\s+(\S+)\s+(\S+)\s+",
                    line,
                    re.IGNORECASE,
                )
                if m_n:
                    local_port, chassis_id, remote_port, sys_name = m_n.groups()
                    remote_mac = ""
                    clean_mac = chassis_id.replace("-", ":").replace(".", ":")
                    if re.match(r"^[0-9a-fA-F:]{17}$", clean_mac):
                        remote_mac = oui_lookup.normalize_mac(clean_mac).lower()
                    plat = oui_lookup.lookup_oui(remote_mac) if remote_mac else "Unknown"
                    dev_type = "switch"
                    if any(w in plat.lower() for w in ("ap", "aruba", "ubiquiti")):
                        dev_type = "ap"
                    elif any(w in plat.lower() for w in ("router", "mikrotik")):
                        dev_type = "router"

                    neighbors.append(
                        {
                            "local_port": local_port,
                            "remote_device": sys_name.split(".")[0] if sys_name != "-" else chassis_id,
                            "remote_port": remote_port,
                            "remote_ip": "",
                            "remote_mac": remote_mac,
                            "platform": plat,
                            "remote_platform": plat,
                            "device_type": dev_type,
                            "protocol": "LLDP",
                        }
                    )
        except Exception:
            pass
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show ip route")
            for line in raw.splitlines():
                m_rt = re.match(
                    r"^\s*([CDSOB\*]+)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(?:\[\d+/\d+\]\s+)?(?:via\s+(\d+\.\d+\.\d+\.\d+)|is\s+directly\s+connected),?\s*(\S+)?",
                    line,
                    re.IGNORECASE,
                )
                if m_rt:
                    proto_tok, subnet, next_hop, iface = m_rt.groups()
                    proto = "Static" if "S" in proto_tok else ("Connected" if "C" in proto_tok else proto_tok)
                    routes.append(
                        {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": next_hop or "Direct",
                            "interface": iface or "",
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
                m_a = re.match(
                    r"^\s*(\S+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:.-]+)\s+",
                    line,
                )
                if m_a:
                    iface, _port, ip_addr, mac_raw = m_a.groups()
                    arp.append(
                        {
                            "ip": ip_addr,
                            "mac": oui_lookup.normalize_mac(mac_raw).lower(),
                            "interface": iface,
                        }
                    )
        except Exception:
            pass
        return arp

    def get_stp(self, conn) -> dict:
        stp = {"enabled": False, "is_root": False, "vlans": {}}
        try:
            raw = conn.send_command("show spanning-tree")
            if re.search(r"Spanning\s+tree\s+enabled\s+mode", raw, re.IGNORECASE):
                stp["enabled"] = True
            if re.search(r"This\s+bridge\s+is\s+(?:the\s+)?root", raw, re.IGNORECASE):
                stp["is_root"] = True
        except Exception:
            pass
        return stp

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show power inline")
            m_tot = re.search(r"Available\s*\(W\)\s*:\s*([\d.]+)", raw, re.IGNORECASE)
            m_used = re.search(r"Consumed\s*\(W\)\s*:\s*([\d.]+)", raw, re.IGNORECASE)
            if m_tot:
                poe["total_power_watts"] = float(m_tot.group(1))
            if m_used:
                poe["used_power_watts"] = float(m_used.group(1))
            poe["available_power_watts"] = max(0.0, poe["total_power_watts"] - poe["used_power_watts"])
            for line in raw.splitlines():
                m_p = re.match(r"^\s*((?:gi|fa|te)\S+)\s+\S+\s+\S+\s+([\d.]+)\s+", line, re.IGNORECASE)
                if m_p:
                    port, watts = m_p.groups()
                    w_val = float(watts)
                    if w_val > 0:
                        poe["ports"][port] = {"status": "delivering", "power_watts": w_val}
        except Exception:
            pass
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        macs = []
        try:
            raw = conn.send_command("show mac address-table")
            for line in raw.splitlines():
                m_m = re.match(r"^\s*(\d+)\s+([0-9a-fA-F:.-]+)\s+(\S+)\s+", line)
                if m_m:
                    vlan, mac_raw, port = m_m.groups()
                    mac = oui_lookup.normalize_mac(mac_raw).lower()
                    macs.append(
                        {
                            "mac": mac,
                            "interface": port,
                            "port": port,
                            "vlan": vlan,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception:
            pass
        return macs

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show fiber-ports optical-transceiver")
            for line in raw.splitlines():
                m_opt = re.match(r"^\s*((?:gi|te|tw)\S+)\s+(OK|Present|SFP\S*)", line, re.IGNORECASE)
                if m_opt:
                    optics.append(
                        {
                            "port": m_opt.group(1),
                            "type": m_opt.group(2),
                            "status": "present",
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

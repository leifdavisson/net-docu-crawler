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
OPNsense Driver: Next-generation open-source firewalls based on FreeBSD.
Parses system details, ifconfig interfaces, routing table, ARP table, and config.xml.
Official Documentation: https://docs.opnsense.org/
"""

import json
import re

import paramiko

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

OPNSENSE_PSEUDO_INTERFACES = ("lo", "enc", "pflog", "pfsync")


class OPNsenseSSHConnection:
    """Non-interactive SSH client wrapper for OPNsense / FreeBSD bypassing `/usr/local/etc/rc.initial` menu traps."""

    def __init__(self, client: paramiko.SSHClient, session_log: str = ""):
        self.client = client
        self.session_log = session_log

    def send_command(self, cmd: str, timeout: int = 15) -> str:
        _stdin, stdout, _stderr = self.client.exec_command(cmd, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="ignore")
        if self.session_log:
            try:
                with open(self.session_log, "a", encoding="utf-8") as f:
                    f.write(f"\n--- COMMAND: {cmd} ---\n{output}\n")
            except Exception:
                pass
        return output

    def disconnect(self):
        self.client.close()


class OPNsenseDriver(BaseDriver):
    """
    Driver for OPNsense firewalls running on FreeBSD.
    Persona: firewall / gateway / router.
    """

    vendor_name = "OPNsense"
    device_persona = "firewall"
    default_device_type = "firewall"
    paging_cmd = ""

    def connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.ip,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
        )
        return OPNsenseSSHConnection(client, session_log=self.session_log)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "opnsense",
            "model": "OPNsense Gateway",
            "serial": "Unknown",
            "firmware": "OPNsense",
            "os_type": "opnsense",
            "device_persona": self.device_persona,
        }
        try:
            h = conn.send_command("hostname").strip()
            if h:
                info["hostname"] = h
        except Exception:
            pass

        try:
            raw_ver = conn.send_command("opnsense-version").strip()
            if raw_ver:
                info["firmware"] = raw_ver
        except Exception:
            pass

        try:
            prod = conn.send_command("kenv smbios.system.product 2>/dev/null").strip()
            if prod:
                info["model"] = f"OPNsense ({prod})"
            ser = conn.send_command("kenv smbios.system.serial 2>/dev/null").strip()
            if ser and ser.lower() not in ("0", "none", "not specified", "default string"):
                info["serial"] = ser
        except Exception:
            pass

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}
        try:
            raw = conn.send_command("ifconfig -a")
            blocks = re.split(r"\n(?=[a-zA-Z0-9_]+:)", raw)
            for block in blocks:
                lines = block.strip().splitlines()
                if not lines:
                    continue
                header = lines[0]
                m_intf = re.match(r"^([a-zA-Z0-9_]+):", header)
                if not m_intf:
                    continue
                intf_name = m_intf.group(1)
                if intf_name.lower().startswith(OPNSENSE_PSEUDO_INTERFACES):
                    continue

                status = "up" if "<UP," in header or "<UP>" in header else "down"
                desc = ""
                mac = ""
                inet_addrs = []

                for line in lines[1:]:
                    line_s = line.strip()
                    if line_s.startswith("description:"):
                        desc = line_s.split("description:", 1)[1].strip()
                    elif line_s.startswith("ether "):
                        mac = oui_lookup.normalize_mac(line_s.split()[1].strip()).lower()
                    elif line_s.startswith("inet "):
                        parts = line_s.split()
                        ip_val = parts[1]
                        if ip_val.startswith("127."):
                            continue
                        mask_hex = parts[3] if len(parts) >= 4 and parts[2] == "netmask" else "0xffffff00"
                        try:
                            mask_int = int(mask_hex, 16)
                            prefix_len = bin(mask_int).count("1")
                        except Exception:
                            prefix_len = 24
                        full_ip = f"{ip_val}/{prefix_len}"
                        inet_addrs.append(full_ip)
                        l3_interfaces.append(
                            {
                                "interface": intf_name,
                                "ip_address": full_ip,
                                "status": status,
                                "protocol": status,
                            }
                        )

                primary_ip = inet_addrs[0] if inet_addrs else ""
                interfaces_detail[intf_name] = {
                    "ip_address": primary_ip,
                    "status": status,
                    "mac_address": mac,
                    "description": desc,
                }
        except Exception:
            pass
        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("lldpctl -f json 2>/dev/null")
            if raw and raw.strip().startswith("{"):
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
                                "device_type": "switch",
                            }
                        )
        except Exception:
            pass
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("netstat -rn -f inet")
            lines = raw.strip().splitlines()
            start = False
            for line in lines:
                if "Destination" in line and "Gateway" in line:
                    start = True
                    continue
                if not start or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    dst = parts[0]
                    gw = parts[1]
                    flags = parts[2]
                    netif = parts[3]
                    if dst == "127.0.0.1" or netif.startswith("lo"):
                        continue
                    proto = "static" if "S" in flags else "connected"
                    routes.append(
                        {
                            "subnet": "0.0.0.0/0" if dst == "default" else dst,
                            "protocol": proto,
                            "next_hop": gw,
                            "interface": netif,
                        }
                    )
        except Exception:
            pass
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("arp -an")
            for line in raw.strip().splitlines():
                m = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+([a-zA-Z0-9_]+)", line)
                if m:
                    ip_val = m.group(1)
                    mac_val = oui_lookup.normalize_mac(m.group(2)).lower()
                    intf_val = m.group(3)
                    if mac_val and mac_val != "(incomplete)":
                        arp_entries.append(
                            {
                                "ip": ip_val,
                                "mac": mac_val,
                                "interface": intf_val,
                                "type": "dynamic",
                                "vendor": oui_lookup.lookup_oui(mac_val),
                            }
                        )
        except Exception:
            pass
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("cat /conf/config.xml")
        except Exception:
            return ""

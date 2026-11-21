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
import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)


class FRRDriver(BaseDriver):
    """
    Driver for FRRouting daemons running on Linux hosts / containers.
    Persona: router / routing engine.
    """

    vendor_name = "FRRouting"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._frr_available: bool | None = None

    def _has_frr(self, conn) -> bool:
        """Checks once per session whether FRRouting (vtysh) is installed and responding."""
        if self._frr_available is not None:
            return self._frr_available
        try:
            raw = conn.send_command("vtysh -c 'show version'")
            m_ver = re.search(r"FRRouting\s+([^\s\(\)]+)", raw)
            if m_ver:
                self._frr_available = True
                self._frr_version = m_ver.group(1)
                return True
        except Exception as exc:
            logger.debug("[%s] FRR vtysh probe failed: %s", self.ip, exc)
        self._frr_available = False
        self._frr_version = ""
        return False

    def connect(self):
        device = self._build_netmiko_params("linux")
        return self.connect_netmiko(device)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "FRR-Router",
            "model": "FRRouting Linux Daemon",
            "serial": "Unknown",
            "firmware": "FRR",
            "os_type": "frrouting",
            "device_persona": self.device_persona,
            "device_type": self.default_device_type,
        }
        try:
            h = conn.send_command("hostname -s").strip()
            if h:
                info["hostname"] = h
        except Exception as exc:
            logger.debug("[%s] FRR hostname -s failed: %s", self.ip, exc)

        if self._has_frr(conn):
            ver = getattr(self, "_frr_version", "")
            if ver:
                info["firmware"] = f"FRR {ver}"
            return info

        # Safe plain-Linux host fallback when vtysh is not installed/running
        info["device_persona"] = "host"
        info["device_type"] = "server"
        info["os_type"] = "linux"
        info["model"] = "Linux Host"
        info["firmware"] = "Linux"
        try:
            os_rel = conn.send_command("cat /etc/os-release")
            m_pretty = re.search(r'^PRETTY_NAME="([^"]+)"', os_rel, re.MULTILINE)
            if m_pretty:
                pretty = m_pretty.group(1).strip()
                info["model"] = f"Linux Host ({pretty})"
                info["firmware"] = pretty
        except Exception as exc:
            logger.debug("[%s] Linux /etc/os-release read failed: %s", self.ip, exc)

        return info

    def _get_linux_interfaces(self, conn) -> tuple[list, dict]:
        """Collects read-only interface and IPv4 details via `ip -j` when vtysh is absent."""
        l3_interfaces = []
        interfaces_detail = {}
        try:
            link_raw = conn.send_command("ip -s -j link show")
            link_data = json.loads(link_raw)
            for link in link_data:
                ifname = link.get("ifname", "")
                if not ifname or ifname == "lo":
                    continue
                oper = str(link.get("operstate", "")).lower()
                status = "up" if oper == "up" else "down"
                raw_mac = link.get("address", "")
                mac = oui_lookup.normalize_mac(raw_mac).lower() if raw_mac else ""
                stats64 = link.get("stats64", {})
                rx_stats = stats64.get("rx", {})
                tx_stats = stats64.get("tx", {})
                interfaces_detail[ifname] = {
                    "ip_address": "",
                    "status": status,
                    "mac_address": mac,
                    "input_errors": int(rx_stats.get("errors", 0) or 0),
                    "crc": int(rx_stats.get("crc_errors", 0) or 0),
                    "output_errors": int(tx_stats.get("errors", 0) or 0),
                    "drops": int(rx_stats.get("dropped", 0) or 0) + int(tx_stats.get("dropped", 0) or 0),
                }
        except Exception as exc:
            logger.debug("[%s] Linux ip -s -j link show failed: %s", self.ip, exc)

        try:
            addr_raw = conn.send_command("ip -j -4 addr show")
            addr_data = json.loads(addr_raw)
            for entry in addr_data:
                ifname = entry.get("ifname", "")
                if not ifname or ifname == "lo":
                    continue
                status = interfaces_detail.get(ifname, {}).get("status", "up")
                for addr_info in entry.get("addr_info", []):
                    local = addr_info.get("local", "")
                    prefix = addr_info.get("prefixlen")
                    if not local or local.startswith("127."):
                        continue
                    cidr = f"{local}/{prefix}" if prefix is not None else local
                    l3_interfaces.append(
                        {
                            "interface": ifname,
                            "ip_address": cidr,
                            "status": status,
                            "protocol": status,
                        }
                    )
                    if ifname in interfaces_detail and not interfaces_detail[ifname]["ip_address"]:
                        interfaces_detail[ifname]["ip_address"] = cidr
        except Exception as exc:
            logger.debug("[%s] Linux ip -j -4 addr show failed: %s", self.ip, exc)
        return l3_interfaces, interfaces_detail

    def get_interfaces(self, conn) -> tuple[list, dict]:
        if not self._has_frr(conn):
            return self._get_linux_interfaces(conn)
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
        except Exception as exc:
            logger.debug("[%s] FRR show interface json failed: %s", self.ip, exc)
        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        lldp_status = "unknown"
        notes = ""
        try:
            raw = conn.send_command("lldpcli show neighbors -f json")
            if raw and raw.strip().startswith("{"):
                lldp_status = "enabled"
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
            else:
                chk = (conn.send_command("command -v lldpcli >/dev/null 2>&1 || echo __NO_LLDPD__") or "").strip()
                if "__NO_LLDPD__" in chk:
                    lldp_status = "not_installed"
                    notes = "L3-only router (FRR); lldpd is not installed."
                else:
                    lldp_status = "disabled"
                    notes = "L3-only router (FRR); lldpd service returned no neighbor data."
        except Exception as exc:
            logger.debug("[%s] FRR lldpcli neighbor query failed: %s", self.ip, exc)
        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        if not self._has_frr(conn):
            try:
                raw = conn.send_command("ip -j route show")
                data = json.loads(raw)
                for r in data:
                    dst = r.get("dst", "")
                    subnet = "0.0.0.0/0" if dst == "default" else dst
                    routes.append(
                        {
                            "subnet": subnet,
                            "protocol": r.get("protocol", "kernel"),
                            "next_hop": r.get("gateway", "connected"),
                            "interface": r.get("dev", ""),
                        }
                    )
            except Exception as exc:
                logger.debug("[%s] Linux ip -j route show failed: %s", self.ip, exc)
            return routes
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
        except Exception as exc:
            logger.debug("[%s] FRR show ip route json failed: %s", self.ip, exc)
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
        except Exception as exc:
            logger.debug("[%s] Linux ip -j neigh show failed: %s", self.ip, exc)
        return arp_entries

    def get_running_config(self, conn) -> str:
        if not self._has_frr(conn):
            return ""
        return self._safe_send_command(conn, "vtysh -c 'show running-config'")

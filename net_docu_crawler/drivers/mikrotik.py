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
MikroTik RouterOS Driver: Routers and Switches running RouterOS v7+.
Official Documentation: https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface
"""

import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)


def _clean_ros_token(val: str) -> str:
    """Strips RouterOS surrounding quotes and trailing punctuation."""
    return val.strip().strip('"').strip("'")


class MikroTikDriver(BaseDriver):
    """
    Driver for MikroTik RouterOS appliances.
    Persona: router / switch.
    """

    vendor_name = "MikroTik"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = ""

    def connect(self):
        device = self._build_netmiko_params("mikrotik_routeros")
        return self.connect_netmiko(device)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "MikroTik",
            "model": "RouterOS CHR",
            "serial": "Unknown",
            "firmware": "RouterOS",
            "os_type": "mikrotik_routeros",
            "device_persona": self.device_persona,
        }
        try:
            ident = conn.send_command("/system identity print")
            m_name = re.search(r"name:\s*(.+)", ident)
            if m_name:
                info["hostname"] = _clean_ros_token(m_name.group(1))
        except Exception as exc:
            logger.debug("[%s] RouterOS /system identity print failed: %s", self.ip, exc)

        try:
            res = conn.send_command("/system resource print")
            m_ver = re.search(r"version:\s*(.+)", res)
            if m_ver:
                info["firmware"] = f"RouterOS {_clean_ros_token(m_ver.group(1))}"
            m_board = re.search(r"board-name:\s*(.+)", res)
            if m_board:
                info["model"] = _clean_ros_token(m_board.group(1))
        except Exception as exc:
            logger.debug("[%s] RouterOS /system resource print failed: %s", self.ip, exc)

        try:
            rb = conn.send_command("/system routerboard print")
            m_ser = re.search(r"serial-number:\s*(.+)", rb)
            if m_ser:
                info["serial"] = _clean_ros_token(m_ser.group(1))
        except Exception as exc:
            logger.debug("[%s] RouterOS /system routerboard print failed: %s", self.ip, exc)

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}

        # 1. Harvest physical Ethernet interface MACs and link states (essential across L3 gateways)
        try:
            eth_raw = conn.send_command("/interface ethernet print detail")
            for block in re.split(r"(?:^|\n)\s*\d+\s+", eth_raw):
                m_name = re.search(r'(?:^|\s)name=("[^"]+"|[^\s]+)', block)
                m_mac = re.search(r"mac-address=([0-9A-Fa-f:]{17})", block)
                if m_name:
                    intf_name = _clean_ros_token(m_name.group(1))
                    is_disabled = bool(re.match(r"^[A-Z]*X", block.strip()))
                    is_running = bool(re.match(r"^[A-Z]*R", block.strip())) or not is_disabled
                    interfaces_detail[intf_name] = {
                        "ip_address": "",
                        "status": "down" if is_disabled else ("up" if is_running else "down"),
                        "mac_address": oui_lookup.normalize_mac(m_mac.group(1)).lower() if m_mac else "",
                        "description": "",
                    }
        except Exception as exc:
            logger.debug("[%s] RouterOS /interface ethernet print detail failed: %s", self.ip, exc)

        # 2. Harvest Layer 3 IPv4 addresses
        try:
            raw = conn.send_command("/ip address print detail")
            for block in re.split(r"(?:^|\n)\s*\d+\s+", raw):
                m_addr = re.search(r'address=("[^"]+"|[^\s]+)', block)
                m_intf = re.search(r'(?:^|\s)interface=("[^"]+"|[^\s]+)', block)
                if m_addr and m_intf:
                    ip = _clean_ros_token(m_addr.group(1))
                    intf = _clean_ros_token(m_intf.group(1))
                    l3_interfaces.append(
                        {
                            "interface": intf,
                            "ip_address": ip,
                            "status": "up",
                            "protocol": "up",
                        }
                    )
                    if intf in interfaces_detail:
                        interfaces_detail[intf]["ip_address"] = ip
                        interfaces_detail[intf]["status"] = "up"
                    else:
                        interfaces_detail[intf] = {
                            "ip_address": ip,
                            "status": "up",
                            "mac_address": "",
                            "description": "",
                        }
        except Exception as exc:
            logger.debug("[%s] RouterOS /ip address print detail failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("/ip neighbor print detail")
            for block in re.split(r"(?:^|\n)\s*\d+\s+", raw):
                m_intf = re.search(r'(?:^|\s)interface=("[^"]+"|[^\s]+)', block)
                m_ip = re.search(r'(?:^|\s)address=("[^"]+"|[^\s]+)', block)
                m_id = re.search(r'identity=("[^"]+"|[^\s]+)', block)
                m_plat = re.search(r'platform=("[^"]+"|[^\s]+)', block)
                m_board = re.search(r'board=("[^"]+"|[^\s]+)', block)
                m_rem_port = re.search(r'interface-name=("[^"]+"|[^\s]+)', block)
                if m_intf and (m_ip or m_id):
                    local_port = _clean_ros_token(m_intf.group(1)).split(",")[0]
                    rem_dev = _clean_ros_token(m_id.group(1)) if m_id else "Unknown"
                    rem_ip = _clean_ros_token(m_ip.group(1)) if m_ip else ""
                    rem_port = _clean_ros_token(m_rem_port.group(1)) if m_rem_port else ""
                    plat = _clean_ros_token(m_plat.group(1)) if m_plat else ""
                    if m_board:
                        plat = f"{plat} {_clean_ros_token(m_board.group(1))}".strip()

                    dev_type = "switch" if "switch" in rem_dev.lower() or "juniper" in plat.lower() else "router"
                    if "ap" in plat.lower() or "aruba" in plat.lower():
                        dev_type = "ap"

                    neighbors.append(
                        {
                            "local_port": local_port,
                            "remote_device": rem_dev,
                            "remote_port": rem_port,
                            "remote_ip": rem_ip,
                            "platform": plat,
                            "remote_platform": plat,
                            "device_type": dev_type,
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] RouterOS /ip neighbor print detail failed: %s", self.ip, exc)
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        seen = set()
        try:
            raw = conn.send_command("/ip route print detail")
            for block in re.split(r"(?:^|\n)\s*\d+\s+", raw):
                m_dst = re.search(r'dst-address=("[^"]+"|[^\s]+)', block)
                m_gw = re.search(r'(?:^|\s)gateway=("[^"]+"|[^\s]+)', block)
                m_igw = re.search(r'immediate-gw=("[^"]+"|[^\s]+)', block)
                if m_dst:
                    subnet = _clean_ros_token(m_dst.group(1))
                    next_hop = _clean_ros_token(m_gw.group(1)) if m_gw else "connected"
                    intf = ""
                    if m_igw and "%" in m_igw.group(1):
                        intf = _clean_ros_token(m_igw.group(1).split("%", 1)[1])
                    flags_prefix = block.strip().split("dst-address=", 1)[0]
                    proto = (
                        "connected"
                        if "c" in flags_prefix.lower()
                        else ("static" if "s" in flags_prefix.lower() else "dynamic")
                    )
                    key = (subnet, next_hop, proto)
                    if key not in seen:
                        seen.add(key)
                        routes.append(
                            {
                                "subnet": subnet,
                                "protocol": proto,
                                "next_hop": next_hop,
                                "interface": intf,
                            }
                        )
        except Exception as exc:
            logger.debug("[%s] RouterOS /ip route print detail failed: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("/ip arp print detail")
            for block in re.split(r"(?:^|\n)\s*\d+\s+", raw):
                m_ip = re.search(r'(?:^|\s)address=("[^"]+"|[^\s]+)', block)
                m_mac = re.search(r"mac-address=([0-9A-Fa-f:]{17})", block)
                m_intf = re.search(r'(?:^|\s)interface=("[^"]+"|[^\s]+)', block)
                if m_ip and m_mac:
                    norm_mac = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                    arp_entries.append(
                        {
                            "ip": _clean_ros_token(m_ip.group(1)),
                            "mac": norm_mac,
                            "interface": _clean_ros_token(m_intf.group(1)) if m_intf else "",
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] RouterOS /ip arp print detail failed: %s", self.ip, exc)
        return arp_entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command('/interface ethernet monitor [find where name~"sfp"] once')
            cur_name = ""
            cur_entry: dict = {}
            for line in raw.splitlines():
                m_n = re.search(r"name:\s*(\S+)", line)
                if m_n:
                    if cur_entry and cur_entry.get("part_number") != "Unknown":
                        optics.append(cur_entry)
                    cur_name = _clean_ros_token(m_n.group(1))
                    cur_entry = {
                        "port": cur_name,
                        "vendor": "MikroTik",
                        "part_number": "Unknown",
                        "serial": "Unknown",
                        "type": "SFP",
                        "tx_power_dbm": None,
                        "rx_power_dbm": None,
                        "temperature_c": None,
                        "voltage_v": None,
                    }
                elif cur_entry:
                    m_vn = re.search(r"sfp-vendor-name:\s*(\S+)", line)
                    m_pn = re.search(r"sfp-vendor-part-number:\s*(\S+)", line)
                    m_sn = re.search(r"sfp-vendor-serial:\s*(\S+)", line)
                    m_tx = re.search(r"sfp-tx-power:\s*([-\d\.]+)", line)
                    m_rx = re.search(r"sfp-rx-power:\s*([-\d\.]+)", line)
                    m_temp = re.search(r"sfp-temperature:\s*([-\d\.]+)", line)
                    if m_vn:
                        cur_entry["vendor"] = _clean_ros_token(m_vn.group(1))
                    if m_pn:
                        cur_entry["part_number"] = _clean_ros_token(m_pn.group(1))
                    if m_sn:
                        cur_entry["serial"] = _clean_ros_token(m_sn.group(1))
                    if m_tx:
                        cur_entry["tx_power_dbm"] = float(m_tx.group(1))
                    if m_rx:
                        cur_entry["rx_power_dbm"] = float(m_rx.group(1))
                    if m_temp:
                        cur_entry["temperature_c"] = float(m_temp.group(1))
            if cur_entry and cur_entry.get("part_number") != "Unknown":
                optics.append(cur_entry)
        except Exception as exc:
            logger.debug("[%s] RouterOS SFP optics monitor failed: %s", self.ip, exc)
        return optics

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "/export compact")

# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
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
from net_docu_crawler.drivers._lldpd import parse_lldpd_json
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_BAD_NEIGH_STATES = frozenset({"FAILED", "INCOMPLETE", "NOARP"})
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _strip_ansi(text: str | None) -> str:
    """Strip ANSI/VT100 terminal control sequences (e.g. bash bracketed-paste) and outer whitespace."""
    if not isinstance(text, str):
        return ""
    return _ANSI_RE.sub("", text).strip()


class FRRDriver(BaseDriver):
    """
    Driver for FRRouting daemons running on Linux hosts / containers.
    Persona: router / routing engine.
    """

    vendor_name = "FRRouting"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = ""
    supports_telnet = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._frr_available: bool | None = None
        self._frr_version: str = ""

    def _has_frr(self, conn) -> bool:
        """Checks once per session whether FRRouting (vtysh) is installed and responding."""
        if self._frr_available is not None:
            return self._frr_available
        try:
            raw = conn.send_command("vtysh -c 'show version'")
            m_ver = re.search(r"FRRouting\s+([^\s\(\)]+)", raw or "")
            if m_ver:
                self._frr_available = True
                self._frr_version = m_ver.group(1)
                return True
        except Exception as exc:
            logger.debug("[%s] FRR vtysh probe failed: %s", self.ip, exc)
        self._frr_available = False
        self._frr_version = ""
        return False

    def _send_vtysh_json(self, conn, primary_cmd: str, fallback_cmd: str = "") -> tuple[object | None, str]:
        """
        Execute a strictly read-only `vtysh -c '... json'` command with optional fallback
        (e.g. `vrf all json` -> default VRF `json`), logging JSON decode errors at WARNING.
        """
        cmds = [primary_cmd] + ([fallback_cmd] if fallback_cmd else [])
        last_cmd = primary_cmd
        last_exc: Exception | None = None

        for cmd in cmds:
            last_cmd = cmd
            try:
                raw = conn.send_command(cmd)
            except Exception as exc:
                last_exc = exc
                continue
            stripped = _strip_ansi(raw)
            if not stripped:
                continue
            if stripped.startswith(("{", "[")):
                try:
                    return json.loads(stripped), cmd
                except (json.JSONDecodeError, ValueError, TypeError) as exc:
                    last_exc = exc
                    continue

        if last_exc is not None:
            logger.warning("[%s] FRR '%s' failed: %s", self.ip, last_cmd, last_exc)
        return None, last_cmd

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
            h = _strip_ansi(conn.send_command("hostname -s"))
            if h:
                info["hostname"] = h.splitlines()[-1].strip()
        except Exception as exc:
            logger.warning("[%s] FRR hostname -s failed: %s", self.ip, exc)

        if self._has_frr(conn):
            ver = getattr(self, "_frr_version", "")
            if ver:
                info["firmware"] = f"FRR {ver}"
            return info

        # Safe plain-Linux host fallback when vtysh is not installed/running
        info["vendor"] = "Linux"
        info["device_persona"] = "host"
        info["device_type"] = "server"
        info["os_type"] = "linux"
        info["model"] = "Linux Host"
        info["firmware"] = "Linux"
        try:
            os_rel = conn.send_command("cat /etc/os-release") or ""
            m_pretty = re.search(r'^PRETTY_NAME=["\']?([^"\'\r\n]+)["\']?', os_rel, re.MULTILINE)
            if m_pretty:
                pretty = m_pretty.group(1).strip()
                info["model"] = f"Linux Host ({pretty})"
                info["firmware"] = pretty
        except Exception as exc:
            logger.warning("[%s] Linux /etc/os-release read failed: %s", self.ip, exc)

        return info

    def _get_linux_interfaces(self, conn) -> tuple[list, dict]:
        """Collects read-only interface and IPv4 details via `ip -j` when vtysh is absent."""
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        link_data = None
        last_link_exc: Exception | None = None
        for cmd in ("ip -s -j link show", "ip -j link show"):
            try:
                link_raw = _strip_ansi(conn.send_command(cmd))
                if link_raw:
                    parsed = json.loads(link_raw)
                    if isinstance(parsed, list):
                        link_data = parsed
                        break
                    logger.warning("[%s] Linux '%s' returned %s (expected list)", self.ip, cmd, type(parsed).__name__)
            except Exception as exc:
                last_link_exc = exc
                continue
        if link_data is None and last_link_exc is not None:
            logger.warning("[%s] Linux ip -s -j link show failed: %s", self.ip, last_link_exc)

        if isinstance(link_data, list):
            for link in link_data:
                if not isinstance(link, dict):
                    continue
                ifname = str(link.get("ifname") or "")
                if not ifname or ifname == "lo":
                    continue
                oper = str(link.get("operstate") or "").lower()
                raw_flags = link.get("flags")
                flags = {str(f).upper() for f in raw_flags} if isinstance(raw_flags, list) else set()
                if oper == "up":
                    status = "up"
                elif oper == "unknown" and "UP" in flags and "LOWER_UP" in flags and "NO-CARRIER" not in flags:
                    status = "up"
                else:
                    status = "down"

                raw_mac = link.get("address")
                mac = oui_lookup.normalize_mac(raw_mac).lower() if isinstance(raw_mac, str) and raw_mac else ""
                stats64 = link.get("stats64")
                rx_stats = stats64.get("rx") if isinstance(stats64, dict) else None
                tx_stats = stats64.get("tx") if isinstance(stats64, dict) else None
                rx_d = rx_stats if isinstance(rx_stats, dict) else {}
                tx_d = tx_stats if isinstance(tx_stats, dict) else {}
                interfaces_detail[ifname] = {
                    "ip_address": "",
                    "status": status,
                    "mac_address": mac,
                    "input_errors": int(rx_d.get("errors", 0) or 0),
                    "crc": int(rx_d.get("crc_errors", 0) or 0),
                    "output_errors": int(tx_d.get("errors", 0) or 0),
                    "drops": int(rx_d.get("dropped", 0) or 0) + int(tx_d.get("dropped", 0) or 0),
                }

        try:
            addr_raw = _strip_ansi(conn.send_command("ip -j -4 addr show"))
            addr_data = json.loads(addr_raw) if addr_raw else []
            if not isinstance(addr_data, list):
                logger.warning("[%s] Linux ip -j -4 addr show returned %s", self.ip, type(addr_data).__name__)
                addr_data = []
            for entry in addr_data:
                if not isinstance(entry, dict):
                    continue
                ifname = str(entry.get("ifname") or "")
                if not ifname or ifname == "lo":
                    continue
                status = interfaces_detail.get(ifname, {}).get("status", "up")
                addr_infos = entry.get("addr_info")
                if not isinstance(addr_infos, list):
                    continue
                for addr_info in addr_infos:
                    if not isinstance(addr_info, dict):
                        continue
                    local = addr_info.get("local")
                    prefix = addr_info.get("prefixlen")
                    if not isinstance(local, str) or not local or local.startswith("127."):
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
            logger.warning("[%s] Linux ip -j -4 addr show failed: %s", self.ip, exc)
        return l3_interfaces, interfaces_detail

    def get_interfaces(self, conn) -> tuple[list, dict]:
        if not self._has_frr(conn):
            return self._get_linux_interfaces(conn)
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        try:
            data, cmd = self._send_vtysh_json(
                conn,
                "vtysh -c 'show interface vrf all json'",
                "vtysh -c 'show interface json'",
            )
            if not isinstance(data, dict):
                if data is not None:
                    logger.warning("[%s] FRR '%s' returned %s (expected dict)", self.ip, cmd, type(data).__name__)
                return l3_interfaces, interfaces_detail

            for intf_name, intf_info in data.items():
                if intf_name == "lo" or not isinstance(intf_info, dict):
                    continue
                if bool(intf_info.get("pseudoInterface")):
                    continue
                raw_mac = intf_info.get("hardwareAddress")
                mac = oui_lookup.normalize_mac(raw_mac).lower() if isinstance(raw_mac, str) and raw_mac else ""
                status = "up" if str(intf_info.get("operationalStatus") or "").lower() == "up" else "down"
                ip_list = intf_info.get("ipAddresses")
                primary_ip = ""
                if isinstance(ip_list, list):
                    for ip_obj in ip_list:
                        if not isinstance(ip_obj, dict):
                            continue
                        addr = ip_obj.get("address")
                        if not isinstance(addr, str) or not addr or ":" in addr or addr.startswith("127."):
                            continue
                        is_secondary = bool(ip_obj.get("secondary", False))
                        if not primary_ip or (not is_secondary and primary_ip and ip_obj.get("secondary") is False):
                            if not primary_ip:
                                primary_ip = addr
                        l3_interfaces.append(
                            {
                                "interface": intf_name,
                                "ip_address": addr,
                                "status": status,
                                "protocol": status,
                            }
                        )

                detail: dict = {
                    "ip_address": primary_ip,
                    "status": status,
                    "mac_address": mac,
                    "description": str(intf_info.get("description") or "").strip(),
                }
                mtu = intf_info.get("mtu")
                if isinstance(mtu, int) and mtu > 0:
                    detail["mtu"] = mtu
                speed = intf_info.get("speed")
                if isinstance(speed, (int, float)) and speed > 0:
                    detail["speed"] = f"{int(speed)}Mbps"
                vrf_name = intf_info.get("vrfName")
                if isinstance(vrf_name, str) and vrf_name and vrf_name != "default":
                    detail["vrf"] = vrf_name
                interfaces_detail[intf_name] = detail
        except Exception as exc:
            logger.warning("[%s] FRR show interface json failed: %s", self.ip, exc)
        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []
        lldp_status = "unknown"
        notes = ""
        is_plain_linux = self._frr_available is False
        try:
            raw = _strip_ansi(conn.send_command("lldpcli show neighbors -f json"))
            if raw.startswith("{"):
                parsed_nbrs, ok = parse_lldpd_json(raw, default_device_type="router", log=logger, ip=self.ip)
                if ok:
                    lldp_status = "enabled"
                    neighbors.extend(parsed_nbrs)
                else:
                    lldp_status = "unknown"
                    notes = "lldpcli returned unparseable JSON output."
            else:
                chk = (conn.send_command("command -v lldpcli >/dev/null 2>&1 || echo __NO_LLDPD__") or "").strip()
                role_prefix = "Linux host" if is_plain_linux else "L3-only router (FRR)"
                if "__NO_LLDPD__" in chk:
                    lldp_status = "not_installed"
                    notes = f"{role_prefix}; lldpd is not installed."
                else:
                    lldp_status = "disabled"
                    notes = f"{role_prefix}; lldpd service returned no neighbor data."
        except Exception as exc:
            logger.warning("[%s] FRR lldpcli neighbor query failed: %s", self.ip, exc)
        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def _append_frr_prefix_routes(self, routes: list[dict], vrf_name: str, subnet: str, r_list: object) -> None:
        """Append normalized FRR routes for a single prefix, expanding all active ECMP nexthops."""
        if not isinstance(r_list, list):
            return
        for r in r_list:
            if not isinstance(r, dict):
                continue
            if r.get("selected") is False:
                continue
            proto = str(r.get("protocol") or "unknown")
            raw_nhs = r.get("nexthops")
            nh_list = [nh for nh in raw_nhs if isinstance(nh, dict)] if isinstance(raw_nhs, list) else []

            if not nh_list:
                entry = {
                    "subnet": subnet,
                    "protocol": proto,
                    "next_hop": "connected",
                    "interface": "",
                }
                if vrf_name and vrf_name != "default":
                    entry["vrf"] = vrf_name
                routes.append(entry)
                continue

            active_nhs = [nh for nh in nh_list if nh.get("active") is True]
            target_nhs = active_nhs if active_nhs else nh_list

            for nh in target_nhs:
                if nh.get("blackhole"):
                    next_hop = str(nh.get("bhType") or "blackhole")
                    intf = ""
                elif nh.get("directlyConnected"):
                    next_hop = "connected"
                    intf = str(nh.get("interfaceName") or "")
                else:
                    next_hop = str(nh.get("ip") or "connected")
                    intf = str(nh.get("interfaceName") or "")
                entry = {
                    "subnet": subnet,
                    "protocol": proto,
                    "next_hop": next_hop,
                    "interface": intf,
                }
                if vrf_name and vrf_name != "default":
                    entry["vrf"] = vrf_name
                routes.append(entry)

    def get_routing_table(self, conn) -> list[dict]:
        routes: list[dict] = []
        if not self._has_frr(conn):
            try:
                raw = _strip_ansi(conn.send_command("ip -j route show"))
                data = json.loads(raw) if raw else []
                if not isinstance(data, list):
                    logger.warning("[%s] Linux ip -j route show returned %s", self.ip, type(data).__name__)
                    return routes
                for r in data:
                    if not isinstance(r, dict):
                        continue
                    dst = str(r.get("dst") or "")
                    if not dst:
                        continue
                    subnet = "0.0.0.0/0" if dst == "default" else (f"{dst}/32" if _IPV4_RE.match(dst) else dst)
                    proto = str(r.get("protocol") or "kernel")
                    r_type = str(r.get("type") or "").lower()
                    raw_nhs = r.get("nexthops")
                    if isinstance(raw_nhs, list) and raw_nhs:
                        for nh in raw_nhs:
                            if not isinstance(nh, dict):
                                continue
                            routes.append(
                                {
                                    "subnet": subnet,
                                    "protocol": proto,
                                    "next_hop": str(nh.get("gateway") or "connected"),
                                    "interface": str(nh.get("dev") or ""),
                                }
                            )
                    elif r_type in ("blackhole", "unreachable", "prohibit", "throw"):
                        routes.append(
                            {
                                "subnet": subnet,
                                "protocol": proto,
                                "next_hop": r_type,
                                "interface": "",
                            }
                        )
                    else:
                        routes.append(
                            {
                                "subnet": subnet,
                                "protocol": proto,
                                "next_hop": str(r.get("gateway") or "connected"),
                                "interface": str(r.get("dev") or ""),
                            }
                        )
            except Exception as exc:
                logger.warning("[%s] Linux ip -j route show failed: %s", self.ip, exc)
            return routes

        try:
            data, cmd = self._send_vtysh_json(
                conn,
                "vtysh -c 'show ip route vrf all json'",
                "vtysh -c 'show ip route json'",
            )
            if not isinstance(data, dict):
                if data is not None:
                    logger.warning("[%s] FRR '%s' returned %s (expected dict)", self.ip, cmd, type(data).__name__)
                return routes

            for top_key, top_val in data.items():
                if isinstance(top_val, list):
                    # Flat single-VRF schema: {prefix: [route_objs]}
                    self._append_frr_prefix_routes(routes, "default", str(top_key), top_val)
                elif isinstance(top_val, dict):
                    # Multi-VRF schema: {vrf_name: {prefix: [route_objs]}}
                    for prefix, r_list in top_val.items():
                        self._append_frr_prefix_routes(routes, str(top_key), str(prefix), r_list)
        except Exception as exc:
            logger.warning("[%s] FRR show ip route json failed: %s", self.ip, exc)
        return routes

    def _parse_bgp_summary_block(self, peers: list[dict], vrf_name: str, block: dict) -> None:
        """Extract BGP peer dicts from an FRR AFI/SAFI or flat BGP summary JSON block."""
        if not isinstance(block, dict):
            return
        if isinstance(block.get("peers"), dict):
            local_as = str(block.get("as") or "")
            for peer_ip, pinfo in block["peers"].items():
                if not isinstance(pinfo, dict):
                    continue
                entry = {
                    "protocol": "bgp",
                    "neighbor_ip": str(peer_ip),
                    "remote_as": str(pinfo.get("remoteAs") or ""),
                    "local_as": local_as,
                    "area": "",
                    "state": str(pinfo.get("state") or "Unknown"),
                    "interface": str(pinfo.get("peerInterface") or ""),
                }
                if vrf_name and vrf_name != "default":
                    entry["vrf"] = vrf_name
                peers.append(entry)
            return

        for afi_val in block.values():
            if isinstance(afi_val, dict) and isinstance(afi_val.get("peers"), dict):
                self._parse_bgp_summary_block(peers, vrf_name, afi_val)

    def _parse_ospf_neighbors_block(self, peers: list[dict], vrf_name: str, block: dict) -> None:
        """Extract OSPF neighbor dicts from an FRR OSPF neighbor JSON block."""
        if not isinstance(block, dict):
            return
        nbr_map = block.get("neighbors")
        if not isinstance(nbr_map, dict):
            return
        for rid, entries in nbr_map.items():
            entry_list = entries if isinstance(entries, list) else ([entries] if isinstance(entries, dict) else [])
            for ninfo in entry_list:
                if not isinstance(ninfo, dict):
                    continue
                nbr_ip = str(ninfo.get("ifaceAddress") or ninfo.get("address") or rid)
                raw_iface = str(ninfo.get("ifaceName") or "")
                iface = raw_iface.split(":", 1)[0] if ":" in raw_iface else raw_iface
                entry = {
                    "protocol": "ospf",
                    "neighbor_ip": nbr_ip,
                    "remote_as": "",
                    "area": str(ninfo.get("area") or ninfo.get("areaId") or ""),
                    "state": str(ninfo.get("nbrState") or ninfo.get("state") or "Unknown"),
                    "interface": iface,
                }
                if vrf_name and vrf_name != "default":
                    entry["vrf"] = vrf_name
                peers.append(entry)

    def get_routing_peers(self, conn) -> list[dict]:
        """Collect live read-only BGP and OSPF peer state via FRR JSON output."""
        if not self._has_frr(conn):
            return []
        peers: list[dict] = []

        # 1. Live BGP peers (all VRFs -> default fallback)
        bgp_data, _ = self._send_vtysh_json(
            conn,
            "vtysh -c 'show bgp vrf all summary json'",
            "vtysh -c 'show bgp summary json'",
        )
        if isinstance(bgp_data, dict):
            if "peers" in bgp_data or any(isinstance(v, dict) and "peers" in v for v in bgp_data.values()):
                self._parse_bgp_summary_block(peers, "default", bgp_data)
            else:
                for vrf_name, vrf_block in bgp_data.items():
                    if isinstance(vrf_block, dict):
                        self._parse_bgp_summary_block(peers, str(vrf_name), vrf_block)

        # 2. Live OSPF neighbors (all VRFs -> default fallback)
        ospf_data, _ = self._send_vtysh_json(
            conn,
            "vtysh -c 'show ip ospf vrf all neighbor json'",
            "vtysh -c 'show ip ospf neighbor json'",
        )
        if isinstance(ospf_data, dict):
            if isinstance(ospf_data.get("vrfs"), dict):
                for vrf_name, vrf_block in ospf_data["vrfs"].items():
                    if isinstance(vrf_block, dict):
                        self._parse_ospf_neighbors_block(peers, str(vrf_name), vrf_block)
            elif "neighbors" in ospf_data:
                self._parse_ospf_neighbors_block(peers, "default", ospf_data)
            else:
                for vrf_name, vrf_block in ospf_data.items():
                    if isinstance(vrf_block, dict) and "neighbors" in vrf_block:
                        self._parse_ospf_neighbors_block(peers, str(vrf_name), vrf_block)

        return peers

    def get_vrfs(self, conn) -> list[dict]:
        """Collect live read-only FRR VRFs via `vtysh -c 'show vrf json'`."""
        if not self._has_frr(conn):
            return []
        vrfs: list[dict] = []
        vrf_data, _ = self._send_vtysh_json(conn, "vtysh -c 'show vrf json'")
        if isinstance(vrf_data, dict):
            for vrf_name, vinfo in vrf_data.items():
                if not vrf_name or vrf_name == "default" or not isinstance(vinfo, dict):
                    continue
                vrfs.append(
                    {
                        "name": str(vrf_name),
                        "type": "vrf",
                        "table": vinfo.get("table"),
                        "active": bool(vinfo.get("active", True)),
                    }
                )
        elif isinstance(vrf_data, list):
            for vinfo in vrf_data:
                if not isinstance(vinfo, dict):
                    continue
                vrf_name = str(vinfo.get("name") or "")
                if not vrf_name or vrf_name == "default":
                    continue
                vrfs.append(
                    {
                        "name": vrf_name,
                        "type": "vrf",
                        "table": vinfo.get("table"),
                        "active": bool(vinfo.get("active", True)),
                    }
                )
        return vrfs

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries: list[dict] = []
        try:
            raw = _strip_ansi(conn.send_command("ip -j neigh show"))
            data = json.loads(raw) if raw else []
            if not isinstance(data, list):
                logger.warning("[%s] Linux ip -j neigh show returned %s", self.ip, type(data).__name__)
                return arp_entries
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                ip_addr = entry.get("dst")
                mac = entry.get("lladdr")
                dev = str(entry.get("dev") or "")
                raw_states = entry.get("state")
                states = {str(s).upper() for s in raw_states} if isinstance(raw_states, list) else set()
                if states & _BAD_NEIGH_STATES:
                    continue
                if isinstance(ip_addr, str) and isinstance(mac, str) and ip_addr and mac and ":" not in ip_addr:
                    norm_mac = oui_lookup.normalize_mac(mac).lower()
                    if not norm_mac:
                        continue
                    arp_type = "static" if "PERMANENT" in states else "dynamic"
                    arp_entries.append(
                        {
                            "ip": ip_addr,
                            "mac": norm_mac,
                            "interface": dev,
                            "type": arp_type,
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] Linux ip -j neigh show failed: %s", self.ip, exc)
        return arp_entries

    def get_running_config(self, conn) -> str:
        if not self._has_frr(conn):
            return ""
        return self._safe_send_command(conn, "vtysh -c 'show running-config'")

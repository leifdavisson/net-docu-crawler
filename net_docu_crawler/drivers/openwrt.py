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
OpenWrt Driver: Embedded Linux-based operating system for wireless routers and gateways.
Parses system details via ubus / sysfs, network interfaces via ubus network.interface dump / ip,
routing table via ip route / route -n, ARP table via /proc/net/arp, and full config via uci export.
Official Documentation: https://openwrt.org/docs/start
"""

import ipaddress
import json
import logging
import re

import oui_lookup
from net_docu_crawler.drivers._lldpd import parse_lldpd_json
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _next_token(parts: list[str], key: str) -> str:
    """Return the token immediately following `key` in `parts`, or '' if absent/at end."""
    try:
        idx = parts.index(key)
    except ValueError:
        return ""
    return parts[idx + 1] if idx + 1 < len(parts) else ""


def _decode_concatenated_json(raw: str) -> list[dict]:
    """Decode one or more concatenated JSON objects (e.g. `ubus call hostapd.* get_clients`)."""
    decoder = json.JSONDecoder()
    objs: list[dict] = []
    pos = 0
    length = len(raw)
    while pos < length:
        while pos < length and raw[pos].isspace():
            pos += 1
        if pos >= length:
            break
        obj, end_pos = decoder.raw_decode(raw, pos)
        if isinstance(obj, dict):
            objs.append(obj)
        pos = end_pos
    return objs


def _freq_to_wlan_port(freq: object) -> str:
    """Map an 802.11 center frequency (MHz) to a concise radio band label."""
    if isinstance(freq, (int, float)):
        if 2400 <= freq < 2500:
            return "wlan-2.4g"
        if 5000 <= freq < 5900:
            return "wlan-5g"
        if freq >= 5925:
            return "wlan-6g"
    return "wlan"


class OpenWrtDriver(BaseDriver):
    """
    Driver for OpenWrt routers, access points, and gateways.
    Persona: router / gateway / ap.
    """

    vendor_name = "OpenWrt"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = ""
    supports_telnet = False

    def connect(self):
        device = self._build_netmiko_params("linux")
        return self.connect_netmiko(device)

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
            raw_board = (conn.send_command("ubus call system board 2>/dev/null") or "").strip()
            if raw_board.startswith("{"):
                data = json.loads(raw_board)
                if not isinstance(data, dict):
                    logger.warning("[%s] OpenWrt ubus system board returned %s", self.ip, type(data).__name__)
                else:
                    hostname = data.get("hostname")
                    if isinstance(hostname, str) and hostname.strip():
                        info["hostname"] = hostname.strip()
                    model = data.get("model")
                    if isinstance(model, str) and model.strip():
                        info["model"] = model.strip()
                    rel = data.get("release")
                    if isinstance(rel, dict):
                        desc = rel.get("description")
                        ver = rel.get("version")
                        target = rel.get("target")
                        if isinstance(desc, str) and desc.strip():
                            info["firmware"] = desc.strip()
                        elif isinstance(ver, str) and ver.strip():
                            info["firmware"] = f"OpenWrt {ver.strip()}"
                        if isinstance(target, str) and target.strip() and target.strip() not in info["model"]:
                            info["model"] = f"{info['model']} ({target.strip()})"
        except Exception as exc:
            logger.warning("[%s] OpenWrt ubus system board failed: %s", self.ip, exc)

        if info["hostname"] == "OpenWrt":
            try:
                h = (conn.send_command("cat /proc/sys/kernel/hostname 2>/dev/null || hostname") or "").strip()
                if h:
                    info["hostname"] = h
            except Exception as exc:
                logger.warning("[%s] OpenWrt hostname fallback failed: %s", self.ip, exc)

        if info["firmware"] == "OpenWrt":
            try:
                rel_raw = (conn.send_command("cat /etc/openwrt_release 2>/dev/null") or "").strip()
                m_desc = re.search(r"DISTRIB_DESCRIPTION=['\"]([^'\"]+)['\"]", rel_raw)
                if m_desc:
                    info["firmware"] = m_desc.group(1)
            except Exception as exc:
                logger.warning("[%s] OpenWrt /etc/openwrt_release read failed: %s", self.ip, exc)

        if info["model"] == "OpenWrt Router":
            try:
                cpuinfo = (conn.send_command("cat /proc/cpuinfo 2>/dev/null") or "").strip()
                m_mach = re.search(r"(?:machine|model name|Hardware)\s*:\s*(.+)", cpuinfo, re.IGNORECASE)
                if m_mach:
                    info["model"] = m_mach.group(1).strip()
            except Exception as exc:
                logger.warning("[%s] OpenWrt /proc/cpuinfo read failed: %s", self.ip, exc)

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        seen_l3: set[tuple[str, str]] = set()

        # 1. Primary method: ubus call network.interface dump
        ubus_devices: set[str] = set()
        try:
            raw_net = (conn.send_command("ubus call network.interface dump 2>/dev/null") or "").strip()
            if raw_net.startswith("{"):
                data = json.loads(raw_net)
                if not isinstance(data, dict):
                    logger.warning("[%s] OpenWrt ubus interface dump returned %s", self.ip, type(data).__name__)
                    intf_list = []
                else:
                    raw_list = data.get("interface")
                    intf_list = raw_list if isinstance(raw_list, list) else []

                for intf in intf_list:
                    if not isinstance(intf, dict):
                        logger.warning("[%s] Skipping non-dict OpenWrt ubus interface entry: %r", self.ip, intf)
                        continue
                    logical_name = str(intf.get("interface") or "unknown")
                    l3_dev = intf.get("l3_device")
                    dev = intf.get("device")
                    device_name = str(
                        (l3_dev if isinstance(l3_dev, str) and l3_dev else None)
                        or (dev if isinstance(dev, str) and dev else None)
                        or logical_name
                    )
                    if device_name == "lo" or logical_name == "loopback":
                        continue
                    is_up = bool(intf.get("up", False))
                    status_str = "up" if is_up else "down"

                    ipv4_raw = intf.get("ipv4-address")
                    ipv4_addrs = ipv4_raw if isinstance(ipv4_raw, list) else []
                    primary_ip = ""
                    for addr_entry in ipv4_addrs:
                        if not isinstance(addr_entry, dict):
                            continue
                        addr = addr_entry.get("address")
                        raw_mask = addr_entry.get("mask")
                        mask = 24 if raw_mask is None else raw_mask
                        if isinstance(addr, str) and addr and not addr.startswith("127."):
                            full_ip = f"{addr}/{mask}"
                            if not primary_ip:
                                primary_ip = full_ip
                            if (device_name, full_ip) not in seen_l3:
                                seen_l3.add((device_name, full_ip))
                                l3_interfaces.append(
                                    {
                                        "interface": device_name,
                                        "ip_address": full_ip,
                                        "status": status_str,
                                        "protocol": status_str,
                                    }
                                )

                    proto_str = str(intf.get("proto") or "static")
                    desc_fragment = f"OpenWrt logical interface: {logical_name} (proto={proto_str})"
                    if device_name in interfaces_detail:
                        existing = interfaces_detail[device_name]
                        if not existing.get("ip_address") and primary_ip:
                            existing["ip_address"] = primary_ip
                        if status_str == "up":
                            existing["status"] = "up"
                        if desc_fragment not in existing.get("description", ""):
                            existing["description"] = (
                                f"{existing['description']}; {logical_name} (proto={proto_str})"
                                if existing.get("description")
                                else desc_fragment
                            )
                    else:
                        interfaces_detail[device_name] = {
                            "ip_address": primary_ip,
                            "status": status_str,
                            "mac_address": "",
                            "description": desc_fragment,
                        }
                    ubus_devices.add(device_name)
        except Exception as exc:
            logger.warning("[%s] OpenWrt ubus network.interface dump failed: %s", self.ip, exc)

        # 2. Extract MAC addresses, physical carrier state, and unmanaged kernel L3 IPs via `ip`
        try:
            ip_raw = (conn.send_command("ip -d address show 2>/dev/null || ip address show 2>/dev/null") or "").strip()
            current_intf = None
            for line in ip_raw.splitlines():
                m_hdr = re.match(r"^\d+:\s+([a-zA-Z0-9_\-\.@]+):.*<([^>]+)>", line)
                if m_hdr:
                    cand = m_hdr.group(1).split("@")[0]
                    if cand == "lo":
                        current_intf = None
                        continue
                    current_intf = cand
                    flag_set = {f.strip().upper() for f in m_hdr.group(2).split(",")}
                    has_no_carrier = "NO-CARRIER" in flag_set or " state DOWN" in line
                    is_carrier_up = not has_no_carrier and (
                        "LOWER_UP" in flag_set or " state UP" in line or "UP" in flag_set
                    )
                    status_str = "up" if is_carrier_up else "down"
                    if current_intf not in interfaces_detail:
                        interfaces_detail[current_intf] = {
                            "ip_address": "",
                            "status": status_str,
                            "mac_address": "",
                            "description": "",
                        }
                    elif has_no_carrier:
                        interfaces_detail[current_intf]["status"] = "down"
                    elif current_intf not in ubus_devices:
                        interfaces_detail[current_intf]["status"] = status_str
                    continue

                if not current_intf:
                    continue

                m_link = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
                if m_link:
                    mac_addr = oui_lookup.normalize_mac(m_link.group(1)).lower()
                    if current_intf in interfaces_detail:
                        interfaces_detail[current_intf]["mac_address"] = mac_addr

                m_inet = re.search(r"\binet\s+([\d\.]+/\d+)", line)
                if m_inet:
                    ip_val = m_inet.group(1)
                    if not ip_val.startswith("127.") and (current_intf, ip_val) not in seen_l3:
                        seen_l3.add((current_intf, ip_val))
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
        except Exception as exc:
            logger.warning("[%s] OpenWrt ip address show failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []
        lldp_status = "unknown"
        notes = ""
        try:
            raw_lldp = (conn.send_command("lldpcli show neighbors -f json 2>/dev/null") or "").strip()
            if raw_lldp.startswith("{"):
                parsed_nbrs, ok = parse_lldpd_json(raw_lldp, default_device_type="switch", log=logger, ip=self.ip)
                if ok:
                    lldp_status = "enabled"
                    neighbors.extend(parsed_nbrs)
                else:
                    lldp_status = "unknown"
                    notes = "lldpcli returned unparseable JSON output."
            else:
                chk = (conn.send_command("command -v lldpcli >/dev/null 2>&1 || echo __NO_LLDPD__") or "").strip()
                if "__NO_LLDPD__" in chk:
                    lldp_status = "not_installed"
                    notes = "lldpd is not installed on OpenWrt."
                else:
                    lldp_status = "disabled"
        except Exception as exc:
            logger.warning("[%s] OpenWrt lldpcli neighbor query failed: %s", self.ip, exc)

        try:
            raw_assoc = (conn.send_command("ubus call hostapd.* get_clients 2>/dev/null") or "").strip()
            if raw_assoc.startswith("{"):
                seen_client_macs: set[str] = set()
                for radio_obj in _decode_concatenated_json(raw_assoc):
                    local_port = _freq_to_wlan_port(radio_obj.get("freq"))
                    clients = radio_obj.get("clients")
                    if not isinstance(clients, dict):
                        continue
                    for mac_val in clients:
                        if not isinstance(mac_val, str) or not mac_val.strip():
                            continue
                        norm_mac = oui_lookup.normalize_mac(mac_val).lower()
                        if not norm_mac or norm_mac in seen_client_macs:
                            continue
                        seen_client_macs.add(norm_mac)
                        oui_vendor = oui_lookup.lookup_oui(norm_mac)
                        platform = (
                            f"Wireless Client ({oui_vendor})"
                            if oui_vendor and oui_vendor != "Unknown"
                            else "Wireless Client"
                        )
                        neighbors.append(
                            {
                                "local_port": local_port,
                                "remote_device": f"Client-{norm_mac[-5:].replace(':', '')}",
                                "remote_port": "wlan0",
                                "remote_ip": "",
                                "remote_mac": norm_mac,
                                "platform": platform,
                                "remote_platform": platform,
                                "device_type": "host",
                            }
                        )
        except Exception as exc:
            logger.warning("[%s] OpenWrt hostapd get_clients failed: %s", self.ip, exc)

        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def _parse_route_n_line(self, parts: list[str]) -> dict | None:
        """Parse a single BusyBox/net-tools `route -n` row (8 columns)."""
        if len(parts) < 8:
            return None
        dst, gw, genmask, flags = parts[0], parts[1], parts[2], parts[3]
        iface = parts[7]
        if not (_IPV4_RE.match(dst) and _IPV4_RE.match(gw) and _IPV4_RE.match(genmask)):
            return None
        try:
            prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{genmask}").prefixlen
        except ValueError:
            logger.warning("[%s] Invalid route -n netmask %r for %s", self.ip, genmask, dst)
            return None
        subnet = "0.0.0.0/0" if dst == "0.0.0.0" and prefixlen == 0 else f"{dst}/{prefixlen}"
        next_hop = "connected" if gw == "0.0.0.0" else gw
        proto = "static" if "G" in flags else "connected"
        return {
            "subnet": subnet,
            "protocol": proto,
            "next_hop": next_hop,
            "interface": iface,
        }

    def get_routing_table(self, conn) -> list[dict]:
        routes: list[dict] = []
        try:
            raw = conn.send_command("ip route show 2>/dev/null || route -n 2>/dev/null") or ""
            is_route_n = False
            pending_ecmp: dict | None = None

            for raw_line in raw.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("Kernel"):
                    is_route_n = True
                    continue
                if line.startswith("Destination") and "Genmask" in line:
                    is_route_n = True
                    continue
                if line.startswith("Destination"):
                    continue

                parts = line.split()
                if not parts:
                    continue

                # BusyBox / net-tools `route -n` table row
                if is_route_n or (
                    len(parts) >= 8
                    and _IPV4_RE.match(parts[0])
                    and _IPV4_RE.match(parts[1])
                    and _IPV4_RE.match(parts[2])
                ):
                    rn_entry = self._parse_route_n_line(parts)
                    if rn_entry:
                        routes.append(rn_entry)
                    continue

                # ECMP multipath continuation line (`nexthop via <gw> dev <intf> weight <n>`)
                if parts[0] == "nexthop" and pending_ecmp is not None:
                    gw = _next_token(parts, "via") or "connected"
                    dev = _next_token(parts, "dev")
                    routes.append(
                        {
                            "subnet": pending_ecmp["subnet"],
                            "protocol": pending_ecmp["protocol"],
                            "next_hop": gw,
                            "interface": dev,
                        }
                    )
                    continue

                pending_ecmp = None

                if parts[0] in ("blackhole", "unreachable", "prohibit", "throw") and len(parts) >= 2:
                    dst = parts[1]
                    subnet = "0.0.0.0/0" if dst == "default" else (dst if "/" in dst else f"{dst}/32")
                    proto = _next_token(parts, "proto") or "static"
                    routes.append(
                        {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": parts[0],
                            "interface": "",
                        }
                    )
                    continue

                if parts[0] == "default":
                    gw = _next_token(parts, "via")
                    dev = _next_token(parts, "dev")
                    proto = _next_token(parts, "proto") or "static"
                    if not gw and not dev:
                        pending_ecmp = {"subnet": "0.0.0.0/0", "protocol": proto}
                    else:
                        routes.append(
                            {
                                "subnet": "0.0.0.0/0",
                                "protocol": proto,
                                "next_hop": gw or "connected",
                                "interface": dev,
                            }
                        )
                elif "/" in parts[0] or _IPV4_RE.match(parts[0]):
                    subnet = parts[0] if "/" in parts[0] else f"{parts[0]}/32"
                    gw = _next_token(parts, "via")
                    dev = _next_token(parts, "dev")
                    proto = _next_token(parts, "proto") or ("static" if gw else "connected")
                    if not gw and not dev:
                        pending_ecmp = {"subnet": subnet, "protocol": proto}
                    else:
                        routes.append(
                            {
                                "subnet": subnet,
                                "protocol": proto,
                                "next_hop": gw or "connected",
                                "interface": dev,
                            }
                        )
        except Exception as exc:
            logger.warning("[%s] OpenWrt routing table query failed: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("cat /proc/net/arp 2>/dev/null") or ""
            lines = raw.strip().splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    ip_val = parts[0]
                    mac_val = oui_lookup.normalize_mac(parts[3]).lower()
                    dev_val = parts[5]
                    flags = parts[2].lower()
                    if flags != "0x0" and mac_val and mac_val != "00:00:00:00:00:00":
                        arp_type = "static" if flags == "0x6" else "dynamic"
                        arp_entries.append(
                            {
                                "ip": ip_val,
                                "mac": mac_val,
                                "interface": dev_val,
                                "type": arp_type,
                                "vendor": oui_lookup.lookup_oui(mac_val),
                            }
                        )
        except Exception as exc:
            logger.warning("[%s] OpenWrt /proc/net/arp read failed: %s", self.ip, exc)
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            config = conn.send_command("uci export 2>/dev/null")
            if config and len(config.strip()) > 50:
                return config
        except Exception as exc:
            logger.warning("[%s] OpenWrt uci export failed: %s", self.ip, exc)

        return self._safe_send_command(conn, "head -n 1000 /etc/config/* 2>/dev/null")

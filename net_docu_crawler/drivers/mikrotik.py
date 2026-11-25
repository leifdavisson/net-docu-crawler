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
MikroTik RouterOS Driver: Routers and Switches running RouterOS v6/v7+.
Official Documentation: https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface
"""

import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_ROS_SYNTAX_ERROR_MARKERS = ("expected end of command", "bad command name", "syntax error")


def _clean_ros_token(val: str) -> str:
    """Strips RouterOS surrounding quotes and whitespace."""
    return val.strip().strip('"').strip("'")


def _extract_ros_flags_and_comment(block: str, first_key_re: str = r"[a-zA-Z0-9_-]+=") -> tuple[str, str]:
    """
    Isolate RouterOS flag letters and optional inline `;;;` comment strictly before
    the first `key=value` token so comment text never corrupts flag detection.
    """
    m_key = re.search(rf"(?:^|\s){first_key_re}", block)
    header = block[: m_key.start()] if m_key else block
    comment = ""
    if ";;;" in header:
        flags_raw, comment_raw = header.split(";;;", 1)
        comment_lines = [ln.strip() for ln in comment_raw.splitlines() if ln.strip()]
        comment = comment_lines[0] if comment_lines else ""
    else:
        flags_raw = header

    flags_raw = re.sub(r"^\s*\d+\s*", "", flags_raw)
    flags_clean = re.sub(r"[\s+]+", "", flags_raw)
    return flags_clean, comment


def _split_ros_numbered_blocks(raw: str) -> list[str]:
    """Split standard numbered RouterOS `print detail` output into per-entry blocks."""
    cleaned_lines = []
    for line in (raw or "").splitlines():
        if line.strip().lower().startswith("flags:"):
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    return [blk for blk in re.split(r"(?:^|\n)\s*\d+\s+", cleaned) if blk.strip()]


def _safe_float(val: str) -> float | None:
    """Parse a leading numeric value (stripping units like dBm, C, V) safely."""
    m = re.match(r"^\s*([+-]?\d+(?:\.\d+)?)", val or "")
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


class MikroTikDriver(BaseDriver):
    """
    Driver for MikroTik RouterOS appliances.
    Persona: router / switch.
    """

    vendor_name = "MikroTik"
    device_persona = "router"
    default_device_type = "router"
    paging_cmd = ""
    supports_telnet = False

    def connect(self):
        device = self._build_netmiko_params("mikrotik_routeros")
        return self.connect_netmiko(device)

    def _send_print_command(self, conn, base_cmd: str) -> str:
        """
        Execute a strictly read-only RouterOS table `print` command with `without-paging`,
        falling back to `base_cmd` only when empty or rejected by syntax error.
        """
        raw = conn.send_command(f"{base_cmd} without-paging")
        raw_str = raw if isinstance(raw, str) else ""
        low = raw_str.lower()
        if not raw_str.strip() or any(err in low for err in _ROS_SYNTAX_ERROR_MARKERS):
            fallback = conn.send_command(base_cmd)
            if isinstance(fallback, str) and fallback.strip():
                return fallback
        return raw_str

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "MikroTik",
            "model": "RouterOS CHR",
            "serial": "Unknown",
            "firmware": "RouterOS",
            "os_type": "mikrotik_routeros",
            "device_persona": self.device_persona,
            "device_type": self.default_device_type,
        }
        try:
            ident = conn.send_command("/system identity print")
            m_name = re.search(r"name:\s*(.+)", ident)
            if m_name:
                info["hostname"] = _clean_ros_token(m_name.group(1))
        except Exception as exc:
            logger.warning("[%s] RouterOS /system identity print failed: %s", self.ip, exc)

        try:
            res = conn.send_command("/system resource print")
            m_ver = re.search(r"version:\s*(.+)", res)
            if m_ver:
                info["firmware"] = f"RouterOS {_clean_ros_token(m_ver.group(1))}"
            m_board = re.search(r"board-name:\s*(.+)", res)
            if m_board:
                board = _clean_ros_token(m_board.group(1))
                info["model"] = board
                if board.upper().startswith(("CRS", "CSS")):
                    info["device_persona"] = "switch"
                    info["device_type"] = "switch"
        except Exception as exc:
            logger.warning("[%s] RouterOS /system resource print failed: %s", self.ip, exc)

        try:
            rb = conn.send_command("/system routerboard print")
            m_ser = re.search(r"serial-number:\s*(.+)", rb)
            if m_ser:
                info["serial"] = _clean_ros_token(m_ser.group(1))
        except Exception as exc:
            logger.debug("[%s] RouterOS /system routerboard print failed (expected on CHR): %s", self.ip, exc)

        return info

    def _parse_interface_blocks(self, raw: str, interfaces_detail: dict, *, overwrite_existing: bool) -> None:
        """Parse RouterOS `/interface [ethernet] print detail` blocks into `interfaces_detail`."""
        for block in _split_ros_numbered_blocks(raw):
            m_name = re.search(r'(?:^|\s)name=("[^"]*"|[^\s]+)', block)
            if not m_name:
                continue
            intf_name = _clean_ros_token(m_name.group(1))
            if not intf_name or intf_name.lower() == "lo":
                continue
            m_type = re.search(r'(?:^|\s)type=("[^"]*"|[^\s]+)', block)
            if m_type and _clean_ros_token(m_type.group(1)).lower() == "loopback":
                continue

            flags, comment = _extract_ros_flags_and_comment(block, first_key_re=r"[a-zA-Z0-9_-]+=")
            if not comment:
                m_cmt = re.search(r'(?:^|\s)comment=("[^"]*"|[^\s]+)', block)
                if m_cmt:
                    comment = _clean_ros_token(m_cmt.group(1))

            m_mac = re.search(r"(?:^|\s)mac-address=([0-9A-Fa-f:]{17})", block)
            m_mtu = re.search(r"(?:^|\s)(?:actual-mtu|mtu)=(\d+)", block)

            is_disabled = "X" in flags
            is_running = "R" in flags and not is_disabled
            status = "up" if is_running else "down"
            mac = oui_lookup.normalize_mac(m_mac.group(1)).lower() if m_mac else ""
            mtu = int(m_mtu.group(1)) if m_mtu else None

            if intf_name in interfaces_detail and not overwrite_existing:
                existing = interfaces_detail[intf_name]
                if not existing.get("mac_address") and mac:
                    existing["mac_address"] = mac
                if not existing.get("description") and comment:
                    existing["description"] = comment
                if existing.get("mtu") is None and mtu is not None:
                    existing["mtu"] = mtu
                continue

            entry = {
                "ip_address": "",
                "status": status,
                "mac_address": mac,
                "description": comment,
            }
            if mtu is not None:
                entry["mtu"] = mtu
            interfaces_detail[intf_name] = entry

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail: dict[str, dict] = {}

        # 1. Harvest physical Ethernet interface MACs and link states (essential across L3 gateways)
        try:
            eth_raw = self._send_print_command(conn, "/interface ethernet print detail")
            self._parse_interface_blocks(eth_raw, interfaces_detail, overwrite_existing=True)
        except Exception as exc:
            logger.warning("[%s] RouterOS /interface ethernet print detail failed: %s", self.ip, exc)

        # 2. Harvest non-ethernet interfaces (bridge, vlan, bonding, wireguard, vrrp, wlan)
        try:
            all_raw = self._send_print_command(conn, "/interface print detail")
            self._parse_interface_blocks(all_raw, interfaces_detail, overwrite_existing=False)
        except Exception as exc:
            logger.warning("[%s] RouterOS /interface print detail failed: %s", self.ip, exc)

        # 3. Harvest Layer 3 IPv4 addresses
        try:
            raw = self._send_print_command(conn, "/ip address print detail")
            for block in _split_ros_numbered_blocks(raw):
                flags, _ = _extract_ros_flags_and_comment(block, first_key_re=r"[a-zA-Z0-9_-]+=")
                if "X" in flags or "I" in flags:
                    continue
                m_addr = re.search(r'(?:^|\s)address=("[^"]*"|[^\s]+)', block)
                m_intf = re.search(r'(?:^|\s)interface=("[^"]*"|[^\s]+)', block)
                if m_addr and m_intf:
                    ip = _clean_ros_token(m_addr.group(1))
                    intf = _clean_ros_token(m_intf.group(1))
                    if not ip or ip.startswith("127."):
                        continue
                    intf_status = interfaces_detail[intf]["status"] if intf in interfaces_detail else "up"
                    l3_interfaces.append(
                        {
                            "interface": intf,
                            "ip_address": ip,
                            "status": intf_status,
                            "protocol": intf_status,
                        }
                    )
                    if intf in interfaces_detail:
                        if not interfaces_detail[intf].get("ip_address"):
                            interfaces_detail[intf]["ip_address"] = ip
                    else:
                        interfaces_detail[intf] = {
                            "ip_address": ip,
                            "status": "up",
                            "mac_address": "",
                            "description": "",
                        }
        except Exception as exc:
            logger.warning("[%s] RouterOS /ip address print detail failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = self._send_print_command(conn, "/ip neighbor print detail")
            for block in _split_ros_numbered_blocks(raw):
                m_intf = re.search(r'(?:^|\s)interface=("[^"]*"|[^\s]+)', block)
                m_ip4 = re.search(r'(?:^|\s)address4=("[^"]*"|[^\s]+)', block)
                m_ip = re.search(r'(?:^|\s)address=("[^"]*"|[^\s]+)', block)
                m_mac = re.search(r"(?:^|\s)mac-address=([0-9A-Fa-f:]{17})", block)
                m_id = re.search(r'(?:^|\s)identity=("[^"]*"|[^\s]+)', block)
                m_plat = re.search(r'(?:^|\s)platform=("[^"]*"|[^\s]+)', block)
                m_board = re.search(r'(?:^|\s)board=("[^"]*"|[^\s]+)', block)
                m_sysdesc = re.search(r'(?:^|\s)system-description=("[^"]*"|[^\s]+)', block)
                m_caps_en = re.search(r'(?:^|\s)system-caps-enabled=("[^"]*"|[^\s]+)', block)
                m_caps = re.search(r'(?:^|\s)system-caps=("[^"]*"|[^\s]+)', block)
                m_rem_port = re.search(r'(?:^|\s)interface-name=("[^"]*"|[^\s]+)', block)

                if not m_intf:
                    continue

                rem_ip4 = _clean_ros_token(m_ip4.group(1)) if m_ip4 else ""
                rem_ip_raw = _clean_ros_token(m_ip.group(1)) if m_ip else ""
                if rem_ip4:
                    rem_ip = rem_ip4
                elif rem_ip_raw and ":" not in rem_ip_raw:
                    rem_ip = rem_ip_raw
                else:
                    rem_ip = rem_ip_raw

                rem_mac = oui_lookup.normalize_mac(m_mac.group(1)).lower() if m_mac else ""
                rem_id = _clean_ros_token(m_id.group(1)) if m_id else ""

                if not (rem_ip or rem_id or rem_mac):
                    continue

                local_port = _clean_ros_token(m_intf.group(1)).split(",")[0]
                rem_dev = rem_id or rem_mac or "Unknown"
                rem_port = _clean_ros_token(m_rem_port.group(1)) if m_rem_port else ""

                plat = _clean_ros_token(m_plat.group(1)) if m_plat else ""
                if m_board:
                    board_val = _clean_ros_token(m_board.group(1))
                    if board_val:
                        plat = f"{plat} {board_val}".strip()
                if not plat and m_sysdesc:
                    plat = _clean_ros_token(m_sysdesc.group(1))[:80]
                if not plat and rem_mac:
                    oui_vendor = oui_lookup.lookup_oui(rem_mac)
                    if oui_vendor and oui_vendor != "Unknown":
                        plat = oui_vendor

                caps_str = (_clean_ros_token(m_caps_en.group(1)) if m_caps_en else "") or (
                    _clean_ros_token(m_caps.group(1)) if m_caps else ""
                )
                caps_low = caps_str.lower()
                plat_low = plat.lower()
                id_low = rem_dev.lower()

                if "wlan-ap" in caps_low or "wlan" in caps_low:
                    dev_type = "ap"
                elif "telephone" in caps_low:
                    dev_type = "phone"
                elif "bridge" in caps_low and "router" not in caps_low:
                    dev_type = "switch"
                elif "router" in caps_low and "bridge" not in caps_low:
                    dev_type = "router"
                elif "ap" in plat_low or "aruba" in plat_low:
                    dev_type = "ap"
                elif "switch" in id_low or "switch" in plat_low or "juniper" in plat_low or "ex2300" in plat_low:
                    dev_type = "switch"
                elif "bridge" in caps_low:
                    dev_type = "switch"
                else:
                    dev_type = "router"

                neighbors.append(
                    {
                        "local_port": local_port,
                        "remote_device": rem_dev,
                        "remote_port": rem_port,
                        "remote_ip": rem_ip,
                        "remote_mac": rem_mac,
                        "platform": plat,
                        "remote_platform": plat,
                        "device_type": dev_type,
                    }
                )
        except Exception as exc:
            logger.warning("[%s] RouterOS /ip neighbor print detail failed: %s", self.ip, exc)
        return neighbors

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        cfg_low = (raw_config or "").lower()
        if "discover-interface-list=none" in cfg_low or "discover-interface-list=!all" in cfg_low:
            return {
                "lldp": "disabled",
                "cdp": "disabled",
                "mndp": "disabled",
                "notes": "RouterOS neighbor discovery disabled (discover-interface-list=none/!all).",
            }
        m_proto = re.search(r"/ip neighbor discovery-settings[\s\S]{0,200}?protocol=([^\s\r\n]+)", cfg_low)
        if m_proto:
            protos = {p.strip() for p in m_proto.group(1).split(",") if p.strip()}
            return {
                "lldp": "enabled" if "lldp" in protos else "disabled",
                "cdp": "enabled" if "cdp" in protos else "disabled",
                "mndp": "enabled" if "mndp" in protos else "disabled",
                "notes": "",
            }
        return {"lldp": "enabled", "cdp": "enabled", "mndp": "enabled", "notes": ""}

    def get_routing_table(self, conn) -> list[dict]:
        routes_by_key: dict[tuple[str, str, str, str], dict] = {}
        proto_rank = {
            "connected": 5,
            "static": 4,
            "ospf": 3,
            "bgp": 3,
            "isis": 3,
            "rip": 3,
            "vpn": 3,
            "dhcp": 2,
            "dynamic": 1,
        }
        try:
            raw = self._send_print_command(conn, "/ip route print detail")
            blocks: list[str] = []
            cur_lines: list[str] = []
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith("flags:"):
                    continue
                is_numbered_start = bool(re.match(r"^\s*\d+\s+", line))
                is_unnumbered_start = bool(re.match(r"^\s+[A-Za-z][A-Za-z+\s]*\s+(?:;;;|dst-address=)", line))
                has_dst_already = any("dst-address=" in ln for ln in cur_lines)
                if is_numbered_start or is_unnumbered_start or ("dst-address=" in line and has_dst_already):
                    if cur_lines:
                        blocks.append("\n".join(cur_lines))
                    cur_lines = [line]
                elif cur_lines:
                    cur_lines.append(line)
                elif "dst-address=" in line:
                    cur_lines = [line]
            if cur_lines:
                blocks.append("\n".join(cur_lines))

            for block in blocks:
                m_dst = re.search(r'(?:^|\s)dst-address=("[^"]*"|[^\s]+)', block)
                if not m_dst:
                    continue
                flags_tok, _ = _extract_ros_flags_and_comment(block, first_key_re=r"dst-address=")
                flags_tok = re.sub(r"[\s+H]", "", flags_tok)
                if "X" in flags_tok or "I" in flags_tok:
                    continue

                flags_low = flags_tok.lower()
                if "c" in flags_low:
                    proto = "connected"
                elif "o" in flags_low:
                    proto = "ospf"
                elif "b" in flags_low:
                    proto = "bgp"
                elif "i" in flags_tok:
                    proto = "isis"
                elif "r" in flags_low:
                    proto = "rip"
                elif "v" in flags_tok:
                    proto = "vpn"
                elif "s" in flags_low:
                    proto = "static"
                elif "d" in flags_tok:
                    proto = "dhcp"
                else:
                    proto = "dynamic"

                m_gw = re.search(r'(?:^|\s)gateway=("[^"]*"|[^\s]+)', block)
                m_igw = re.search(r'(?:^|\s)immediate-gw=("[^"]*"|[^\s]+)', block)
                m_vrf_i = re.search(r'(?:^|\s)vrf-interface=("[^"]*"|[^\s]+)', block)
                m_rtab = re.search(r'(?:^|\s)routing-table=("[^"]*"|[^\s]+)', block)

                subnet = _clean_ros_token(m_dst.group(1))
                gw_raw = _clean_ros_token(m_gw.group(1)) if m_gw else ""
                igw_raw = _clean_ros_token(m_igw.group(1)) if m_igw else ""
                vrf_intf = _clean_ros_token(m_vrf_i.group(1)) if m_vrf_i else ""
                vrf_name = _clean_ros_token(m_rtab.group(1)) if m_rtab else "main"

                gw_list = [g.strip() for g in gw_raw.split(",") if g.strip()] if gw_raw else [""]
                igw_list = [g.strip() for g in igw_raw.split(",") if g.strip()] if igw_raw else []
                hop_count = max(len(gw_list), len(igw_list))

                for idx in range(hop_count):
                    gw_item = gw_list[idx] if idx < len(gw_list) else gw_list[0]
                    igw_item = igw_list[idx] if idx < len(igw_list) else ""

                    intf = ""
                    if "%" in igw_item:
                        igw_addr, intf = igw_item.split("%", 1)
                        if not gw_item:
                            gw_item = igw_addr
                    elif "%" in gw_item:
                        gw_item, intf = gw_item.split("%", 1)
                    elif vrf_intf:
                        intf = vrf_intf

                    if proto == "connected":
                        intf = intf or gw_item or igw_item
                        next_hop = "connected"
                    else:
                        next_hop = gw_item or "connected"

                    key = (vrf_name, subnet, next_hop, intf)
                    existing = routes_by_key.get(key)
                    if existing is None or proto_rank.get(proto, 0) > proto_rank.get(existing["protocol"], 0):
                        entry = {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": next_hop,
                            "interface": intf,
                        }
                        if vrf_name and vrf_name != "main":
                            entry["vrf"] = vrf_name
                        routes_by_key[key] = entry
        except Exception as exc:
            logger.warning("[%s] RouterOS /ip route print detail failed: %s", self.ip, exc)
        return list(routes_by_key.values())

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = self._send_print_command(conn, "/ip arp print detail")
            for block in _split_ros_numbered_blocks(raw):
                flags, _ = _extract_ros_flags_and_comment(block, first_key_re=r"[a-zA-Z0-9_-]+=")
                if "X" in flags or "I" in flags:
                    continue
                m_ip = re.search(r'(?:^|\s)address=("[^"]*"|[^\s]+)', block)
                m_mac = re.search(r"(?:^|\s)mac-address=([0-9A-Fa-f:]{17})", block)
                m_intf = re.search(r'(?:^|\s)interface=("[^"]*"|[^\s]+)', block)
                if m_ip and m_mac:
                    norm_mac = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                    arp_type = "dynamic" if "D" in flags else ("published" if "P" in flags else "static")
                    arp_entries.append(
                        {
                            "ip": _clean_ros_token(m_ip.group(1)),
                            "mac": norm_mac,
                            "interface": _clean_ros_token(m_intf.group(1)) if m_intf else "",
                            "type": arp_type,
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] RouterOS /ip arp print detail failed: %s", self.ip, exc)
        return arp_entries

    def get_optics(self, conn) -> list[dict]:
        optics: list[dict] = []

        def _flush_group(entries: list[dict]) -> None:
            for item in entries:
                has_data = (
                    item.get("part_number") != "Unknown"
                    or item.get("serial") != "Unknown"
                    or item.get("tx_power_dbm") is not None
                    or item.get("rx_power_dbm") is not None
                )
                if has_data:
                    optics.append(item)

        try:
            raw = conn.send_command('/interface ethernet monitor [find where name~"sfp"] once')
            cur_entries: list[dict] = []
            for line in (raw or "").splitlines():
                m_n = re.search(r"^\s*name:\s*(.+)$", line)
                if m_n:
                    _flush_group(cur_entries)
                    port_names = [_clean_ros_token(p) for p in m_n.group(1).split(",") if _clean_ros_token(p)]
                    cur_entries = [
                        {
                            "port": p,
                            "vendor": "MikroTik",
                            "part_number": "Unknown",
                            "serial": "Unknown",
                            "type": "SFP",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
                        for p in port_names
                    ]
                    continue

                if not cur_entries:
                    continue

                m_kv = re.match(r"^\s*([a-z0-9-]+):\s*(.+)$", line)
                if not m_kv:
                    continue
                key, raw_val = m_kv.group(1), m_kv.group(2).strip()
                vals = (
                    [_clean_ros_token(v) for v in raw_val.split(",")]
                    if len(cur_entries) > 1
                    else [_clean_ros_token(raw_val)]
                )

                for idx, entry in enumerate(cur_entries):
                    if idx >= len(vals) or not vals[idx]:
                        continue
                    v = vals[idx]
                    if key == "sfp-vendor-name":
                        entry["vendor"] = v
                    elif key == "sfp-vendor-part-number":
                        entry["part_number"] = v
                    elif key == "sfp-vendor-serial":
                        entry["serial"] = v
                    elif key == "sfp-tx-power":
                        entry["tx_power_dbm"] = _safe_float(v)
                    elif key == "sfp-rx-power":
                        entry["rx_power_dbm"] = _safe_float(v)
                    elif key == "sfp-temperature":
                        entry["temperature_c"] = _safe_float(v)
                    elif key == "sfp-supply-voltage":
                        entry["voltage_v"] = _safe_float(v)
            _flush_group(cur_entries)
        except Exception as exc:
            logger.warning("[%s] RouterOS SFP optics monitor failed: %s", self.ip, exc)
        return optics

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "/export compact")

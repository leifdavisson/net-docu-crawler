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
Cisco Systems Driver: IOS, IOS-XE, NX-OS, and IOS-XR.
Official Documentation: https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html
"""

import logging
import re

import oui_lookup
import parser
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)


class CiscoDriver(BaseDriver):
    vendor_name = "Cisco Systems"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "terminal length 0"

    def connect(self):
        device = self._build_netmiko_params("cisco_ios", secret=self.secret, global_delay_factor=2)
        conn = self.connect_netmiko(device)
        if self.secret:
            self._safe_enable(conn)
        return conn

    def crawl(self, conn) -> dict:
        sh_ver = self._safe_send_command(conn, "show version")
        prompt = self._safe_find_prompt(conn) or ""
        if re.search(r"\b(?:Arista|vEOS|cEOS)\b", sh_ver, re.IGNORECASE) or "arista" in prompt.lower():
            from net_docu_crawler.drivers.arista import AristaDriver

            logger.info("[%s] Detected Arista EOS during CiscoDriver probe; delegating to AristaDriver.", self.ip)
            self._safe_enable(conn)
            arista_drv = AristaDriver(
                ip=self.ip,
                username=self.username,
                password=self.password,
                secret=self.secret,
                timeout=self.timeout,
                session_log=self.session_log,
                port=self.port,
                transport=self.transport,
            )
            arista_drv._prefetched_sh_ver = sh_ver
            return arista_drv.crawl(conn)

        if "IOS-XR" in sh_ver or "IOS XR" in sh_ver or re.search(r"^(?:RP|LC)/\d+/\d+/CPU\d+:", prompt):
            from net_docu_crawler.drivers.cisco_xr import CiscoXRDriver

            logger.info("[%s] Detected Cisco IOS-XR during CiscoDriver probe; delegating to CiscoXRDriver.", self.ip)
            xr_drv = CiscoXRDriver(
                ip=self.ip,
                username=self.username,
                password=self.password,
                secret=self.secret,
                timeout=self.timeout,
                session_log=self.session_log,
                port=self.port,
                transport=self.transport,
            )
            xr_drv._prefetched_sh_ver = sh_ver
            return xr_drv.crawl(conn)

        self._prefetched_sh_ver = sh_ver
        return super().crawl(conn)

    def get_version(self, conn) -> dict:
        sh_ver = getattr(self, "_prefetched_sh_ver", None)
        if sh_ver is not None:
            self._prefetched_sh_ver = None
        else:
            sh_ver = conn.send_command("show version")
        os_type = "cisco_ios"
        if "NX-OS" in sh_ver or "Nexus" in sh_ver:
            os_type = "cisco_nxos"
        elif "IOS-XR" in sh_ver or "IOS XR" in sh_ver:
            os_type = "cisco_xr"

        ver = parser.parse_show_version(sh_ver, os_type)
        ver["os_type"] = os_type

        # Verify model and serial via show inventory if available
        try:
            sh_inv = conn.send_command("show inventory")
            inv_items = parser.parse_show_inventory(sh_inv)
            for item in inv_items:
                if "chassis" in item.get("name", "").lower() or "chassis" in item.get("descr", "").lower():
                    if item.get("pid"):
                        ver["model"] = item["pid"]
                    if item.get("sn") and item["sn"] != "N/A":
                        ver["serial"] = item["sn"]
                    break
        except Exception as exc:
            logger.debug("[%s] Cisco show inventory failed: %s", self.ip, exc)

        # Classify router vs switch persona accurately (e.g. CISCO891-K9, ISR, ASR, IOS-XR)
        dev_type = parser.classify_device_type(model=ver.get("model", ""), device_id=ver.get("hostname", ""))
        if os_type == "cisco_xr" or ver.get("model", "").upper().startswith(
            ("CISCO8", "CISCO19", "CISCO29", "CISCO39")
        ):
            dev_type = "router"
        ver["device_type"] = dev_type
        ver["device_persona"] = dev_type

        return ver

    def get_interfaces(self, conn) -> tuple[list, dict]:
        sh_ip_int = conn.send_command("show ip interface brief")
        l3_ints = parser.parse_ip_interface_brief(sh_ip_int, "cisco_ios")

        sh_ints = conn.send_command("show interfaces")
        ints_detail = parser.parse_show_interfaces(sh_ints, "cisco_ios")
        for stats in ints_detail.values():
            if stats.get("mac_address"):
                stats["mac_address"] = oui_lookup.normalize_mac(stats["mac_address"]).lower()

        # Backfill /prefix masks from "Internet address is X.X.X.X/Y" in show interfaces
        cidr_by_intf: dict[str, str] = {}
        cur_intf: str | None = None
        for line in sh_ints.splitlines():
            m_hdr = re.match(r"^([A-Za-z0-9/._-]+)\s+is\s+(?:up|down|administratively)", line.strip())
            if m_hdr:
                cur_intf = m_hdr.group(1)
            elif cur_intf:
                m_addr = re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m_addr:
                    cidr_by_intf[cur_intf] = m_addr.group(1)

        for entry in l3_ints:
            ip_val = str(entry.get("ip_address") or "").strip()
            intf_name = str(entry.get("interface") or "").strip()
            if ip_val and "/" not in ip_val and " " not in ip_val and intf_name in cidr_by_intf:
                if cidr_by_intf[intf_name].startswith(ip_val + "/"):
                    entry["ip_address"] = cidr_by_intf[intf_name]

        return l3_ints, ints_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        seen = set()
        cdp_status = "unknown"
        lldp_status = "unknown"
        try:
            sh_cdp = conn.send_command("show cdp neighbors detail")
            cdp_low = (sh_cdp or "").lower()
            if "cdp is not enabled" in cdp_low:
                cdp_status = "disabled"
            elif "invalid input" in cdp_low:
                cdp_status = "unsupported"
            else:
                cdp_status = "enabled"
            for n in parser.parse_cdp_neighbors_detail(sh_cdp):
                n["remote_platform"] = n.get("platform", "")
                key = (n.get("local_port", ""), n.get("remote_device", "").lower())
                if key not in seen:
                    seen.add(key)
                    neighbors.append(n)
        except Exception as exc:
            logger.debug("[%s] Cisco show cdp neighbors detail failed: %s", self.ip, exc)
        try:
            sh_lldp = conn.send_command("show lldp neighbors detail")
            lldp_low = (sh_lldp or "").lower()
            if "lldp is not enabled" in lldp_low:
                lldp_status = "disabled"
            elif "invalid input" in lldp_low:
                lldp_status = "unsupported"
            else:
                lldp_status = "enabled"

            lldp_entries = parser.parse_lldp_neighbors_detail(sh_lldp)
            # IOS 12.x `show lldp neighbors detail` omits `Local Intf`; recover it from summary table if needed.
            if lldp_status == "enabled" and any(not (e.get("local_port") or "").strip() for e in lldp_entries):
                summary_ports = self._parse_lldp_summary_ports(conn)
                for e in lldp_entries:
                    if not (e.get("local_port") or "").strip():
                        dev_key = (e.get("remote_device") or "").split(".")[0].lower()
                        port_key = (e.get("remote_port") or "").lower()
                        recovered = summary_ports.get((dev_key, port_key)) or summary_ports.get((dev_key, ""))
                        if recovered:
                            e["local_port"] = recovered

            for n in lldp_entries:
                n["remote_platform"] = n.get("platform", "")
                lldp_name = (n.get("remote_device") or "").strip()
                lldp_ip = (n.get("remote_ip") or "").strip()
                lldp_mac_hex = re.sub(r"[^0-9a-f]", "", (n.get("remote_mac") or "").lower())
                lldp_port = (n.get("local_port") or "").strip()

                # Correlate LLDP with existing CDP entries (IOS 12.x LLDP omits Local Intf,
                # while CDP often reports a 12-hex MAC as Device ID instead of System Name).
                matched_cdp = None
                for existing in neighbors:
                    ex_ip = (existing.get("remote_ip") or "").strip()
                    ex_dev_hex = re.sub(r"[^0-9a-f]", "", (existing.get("remote_device") or "").lower())
                    if lldp_port and existing.get("local_port") == lldp_port:
                        matched_cdp = existing
                        break
                    if lldp_ip and ex_ip and lldp_ip == ex_ip:
                        matched_cdp = existing
                        break
                    if lldp_mac_hex and len(lldp_mac_hex) == 12 and ex_dev_hex == lldp_mac_hex:
                        matched_cdp = existing
                        break

                if matched_cdp is not None:
                    ex_dev = (matched_cdp.get("remote_device") or "").strip()
                    if lldp_name and re.fullmatch(r"[0-9a-fA-F]{12}", ex_dev):
                        matched_cdp["remote_device"] = lldp_name
                    if not matched_cdp.get("remote_mac") and n.get("remote_mac"):
                        matched_cdp["remote_mac"] = n["remote_mac"]
                    continue

                if not lldp_port:
                    continue
                key = (lldp_port, lldp_name.lower())
                if key not in seen:
                    seen.add(key)
                    neighbors.append(n)
        except Exception as exc:
            logger.debug("[%s] Cisco show lldp neighbors detail failed: %s", self.ip, exc)

        notes = ""
        if lldp_status == "disabled":
            notes = "LLDP is disabled on Cisco IOS; run 'lldp run' to discover non-Cisco LLDP neighbors."
        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": cdp_status,
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def _parse_lldp_summary_ports(self, conn) -> dict[tuple[str, str], str]:
        """Fallback parser for `show lldp neighbors` summary table to recover Local Intf on IOS 12.x."""
        mapping: dict[tuple[str, str], str] = {}
        try:
            raw = conn.send_command("show lldp neighbors")
            for line in (raw or "").splitlines():
                m = re.match(
                    r"^\s*(\S+)\s+((?:Gi|Fa|Te|Tw|Eth|Po)\S+)\s+\d+\s+\S*\s+(\S+)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if m:
                    dev_id, local_intf, port_id = m.groups()
                    dev_short = dev_id.split(".")[0].lower()
                    mapping[(dev_short, port_id.lower())] = local_intf
                    mapping.setdefault((dev_short, ""), local_intf)
        except Exception as exc:
            logger.debug("[%s] Cisco show lldp neighbors summary fallback failed: %s", self.ip, exc)
        return mapping

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        status = super().get_discovery_protocols(conn, raw_config=raw_config, neighbors=neighbors)
        cfg_low = (raw_config or "").lower()
        if re.search(r"^\s*lldp run\b", cfg_low, re.MULTILINE):
            status["lldp"] = "enabled"
        elif re.search(r"^\s*no lldp run\b", cfg_low, re.MULTILINE):
            status["lldp"] = "disabled"
        if re.search(r"^\s*no cdp run\b", cfg_low, re.MULTILINE):
            status["cdp"] = "disabled"
        elif status["cdp"] == "unknown" and raw_config:
            status["cdp"] = "enabled"
        if status["lldp"] == "disabled" and not status["notes"]:
            status["notes"] = "LLDP is disabled on Cisco IOS; run 'lldp run' to discover non-Cisco LLDP neighbors."
        return status

    def get_stp(self, conn) -> dict:
        try:
            sh_stp = conn.send_command("show spanning-tree")
            return parser.parse_spanning_tree(sh_stp, "cisco_ios")
        except Exception as exc:
            logger.debug("[%s] Cisco show spanning-tree failed: %s", self.ip, exc)
            return {"enabled": False, "vlans": {}}

    def get_routing_table(self, conn) -> list[dict]:
        try:
            sh_route = conn.send_command("show ip route")
            return parser.parse_show_ip_route(sh_route, "cisco_ios")
        except Exception as exc:
            logger.debug("[%s] Cisco show ip route failed: %s", self.ip, exc)
            return []

    def get_arp_table(self, conn) -> list[dict]:
        try:
            sh_arp = conn.send_command("show ip arp")
            return parser.parse_show_ip_arp(sh_arp)
        except Exception as exc:
            logger.debug("[%s] Cisco show ip arp failed: %s", self.ip, exc)
            return []

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show power inline")
            m_tot = re.search(r"Available:\s*([\d.]+)\s*\(W\)", raw)
            m_used = re.search(r"Used:\s*([\d.]+)\s*\(W\)", raw)
            m_rem = re.search(r"Remaining:\s*([\d.]+)\s*\(W\)", raw)
            if m_tot:
                poe["total_power_watts"] = float(m_tot.group(1))
            if m_used:
                poe["used_power_watts"] = float(m_used.group(1))
            if m_rem:
                poe["available_power_watts"] = float(m_rem.group(1))
        except Exception as exc:
            logger.debug("[%s] Cisco show power inline failed: %s", self.ip, exc)
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show mac address-table")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 4 and ("DYNAMIC" in line.upper() or "STATIC" in line.upper()):
                    mac = oui_lookup.normalize_mac(parts[1]).lower()
                    entries.append(
                        {
                            "vlan": parts[0],
                            "mac": mac,
                            "type": parts[2].lower(),
                            "interface": parts[3],
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] Cisco show mac address-table failed: %s", self.ip, exc)
        return entries

    @staticmethod
    def _norm_port(port: str) -> str:
        p = port.strip().lower()
        for full, short in (
            ("twentyfivegige", "twe"),
            ("hundredgige", "hu"),
            ("fortygige", "fo"),
            ("tengigabitethernet", "te"),
            ("gigabitethernet", "gi"),
            ("fastethernet", "fa"),
            ("ethernet", "eth"),
        ):
            if p.startswith(full):
                return short + p[len(full) :]
        return p

    def get_optics(self, conn) -> list[dict]:
        optics_by_norm: dict[str, dict] = {}

        # 1. Pull transceiver type, PID, and serial numbers from `show inventory`
        try:
            inv_raw = conn.send_command("show inventory")
            cur_name = ""
            cur_descr = ""
            for line in inv_raw.splitlines():
                m_nd = re.search(r'NAME:\s*"([^"]+)",\s*DESCR:\s*"([^"]*)"', line)
                if m_nd:
                    cur_name = m_nd.group(1).strip()
                    cur_descr = m_nd.group(2).strip()
                    continue
                if cur_name and "PID:" in line:
                    m_pid = re.search(r"PID:\s*([^,\s]+)", line)
                    m_sn = re.search(r"SN:\s*(\S+)", line)
                    descr_l = cur_descr.lower()
                    is_xcvr = any(
                        k in descr_l
                        for k in (
                            "sfp",
                            "qsfp",
                            "xfp",
                            "gbic",
                            "1000base",
                            "10gbase",
                            "25gbase",
                            "40gbase",
                            "100gbase",
                            "transceiver",
                        )
                    ) or bool(re.match(r"^(?:Gi|Te|Twe|Fo|Hu|Eth|GigabitEthernet|TenGigabitEthernet)\d", cur_name))
                    if is_xcvr:
                        pid = m_pid.group(1).strip() if m_pid else "Unknown"
                        sn = m_sn.group(1).strip() if m_sn else "Unknown"
                        norm = self._norm_port(cur_name)
                        optics_by_norm[norm] = {
                            "port": cur_name,
                            "vendor": "Cisco",
                            "part_number": pid,
                            "serial": sn,
                            "type": cur_descr or "SFP",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
                    cur_name = ""
                    cur_descr = ""
        except Exception as exc:
            logger.debug("[%s] Cisco show inventory optics parse failed: %s", self.ip, exc)

        # 2. Merge live DOM telemetry from `show interfaces transceiver`
        try:
            raw = conn.send_command("show interfaces transceiver")
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("Port") or "---" in line or "Transceiver" in line:
                    continue
                m = re.match(
                    r"^([A-Za-z0-9/\._-]+)\s+([\d\.\-]+)\s*(?:C)?\s+([\d\.\-]+)\s*(?:V)?\s+([\d\.\-]+)\s*(?:mA)?\s+([\d\.\-]+)\s*(?:dBm)?\s+([\d\.\-]+)",
                    line,
                )
                if m:
                    port = m.group(1)
                    temp = float(m.group(2)) if m.group(2) != "N/A" else None
                    volt = float(m.group(3)) if m.group(3) != "N/A" else None
                    tx = float(m.group(5)) if m.group(5) != "N/A" else None
                    rx = float(m.group(6)) if m.group(6) != "N/A" else None
                    norm = self._norm_port(port)
                    if norm in optics_by_norm:
                        optics_by_norm[norm]["tx_power_dbm"] = tx
                        optics_by_norm[norm]["rx_power_dbm"] = rx
                        optics_by_norm[norm]["temperature_c"] = temp
                        optics_by_norm[norm]["voltage_v"] = volt
                    else:
                        optics_by_norm[norm] = {
                            "port": port,
                            "vendor": "Cisco",
                            "part_number": "SFP-DOM",
                            "serial": "Unknown",
                            "type": "SFP+",
                            "tx_power_dbm": tx,
                            "rx_power_dbm": rx,
                            "temperature_c": temp,
                            "voltage_v": volt,
                        }
        except Exception as exc:
            logger.debug("[%s] Cisco show interfaces transceiver failed: %s", self.ip, exc)
        return list(optics_by_norm.values())

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "show running-config")

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        try:
            raw_trunk = conn.send_command("show interfaces trunk")
            if (
                isinstance(raw_trunk, str)
                and raw_trunk.strip()
                and "Invalid input" not in raw_trunk
                and "Unrecognized command" not in raw_trunk
            ):
                section = ""
                for line in raw_trunk.splitlines():
                    stripped = line.strip()
                    if not stripped or set(stripped) <= {"-", "="}:
                        continue
                    low = stripped.lower()
                    if "mode" in low and "native vlan" in low:
                        section = "mode_ios"
                        continue
                    if "native" in low and "status" in low and "port" in low:
                        section = "mode_nxos"
                        continue
                    if "vlans allowed on trunk" in low:
                        section = "allowed"
                        continue
                    if "vlans allowed and active" in low:
                        section = "active"
                        continue
                    if "vlans in spanning tree forwarding" in low or "stp forwarding" in low:
                        section = "forwarding"
                        continue
                    if "vlans err-disabled" in low or low.startswith("vlans "):
                        section = "other"
                        continue
                    if low.startswith("port ") or low.startswith("vlan "):
                        continue

                    if section == "mode_ios":
                        m = re.match(
                            r"^\s*(\S+)\s+(on|auto|desirable|trunk|off)\s+(\S+)\s+(trunking|not-trunking)\s+(\d+)",
                            line,
                            re.I,
                        )
                        if m:
                            p, mode_tok, encap_tok, status_tok, nat = m.groups()
                            if p.lower() == "port":
                                continue
                            mode_l = mode_tok.lower()
                            encap_l = encap_tok.lower()
                            status_l = status_tok.lower()
                            admin_m = (
                                "dynamic_auto"
                                if mode_l == "auto"
                                else (
                                    "dynamic_desirable"
                                    if mode_l == "desirable"
                                    else ("trunk" if mode_l in ("on", "trunk") else "access")
                                )
                            )
                            encap = "isl" if "isl" in encap_l else ("negotiate" if "neg" in encap_l else "dot1q")
                            oper_m = "trunk" if status_l == "trunking" else "access"
                            entry = ops.setdefault(p, {})
                            entry["mode"] = "trunk" if status_l == "trunking" else "access"
                            entry["admin_mode"] = admin_m
                            entry["oper_mode"] = oper_m
                            entry["encapsulation"] = encap
                            entry["native_vlan"] = nat
                    elif section == "mode_nxos":
                        m_nx = re.match(r"^\s*(\S+)\s+(\d+)\s+(trunking|not-trunking)\b", line, re.I)
                        if m_nx:
                            p, nat, status_tok = m_nx.groups()
                            if p.lower() == "port":
                                continue
                            status_l = status_tok.lower()
                            entry = ops.setdefault(p, {})
                            entry["mode"] = "trunk" if status_l == "trunking" else "access"
                            entry["oper_mode"] = "trunk" if status_l == "trunking" else "access"
                            entry["encapsulation"] = "dot1q"
                            entry["native_vlan"] = nat
                    elif section == "allowed":
                        m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                        if m and m.group(1).lower() != "port":
                            p, vlans = m.group(1), m.group(2).lower()
                            entry = ops.setdefault(p, {})
                            entry["mode"] = "trunk"
                            entry.setdefault("oper_mode", "trunk")
                            entry["trunk_allowed_vlans"] = vlans
                    elif section == "active":
                        m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                        if m and m.group(1).lower() != "port":
                            p, vlans = m.group(1), m.group(2).lower()
                            entry = ops.setdefault(p, {})
                            entry.setdefault("mode", "trunk")
                            entry.setdefault("oper_mode", "trunk")
                            entry["trunk_active_vlans"] = vlans
                    elif section == "forwarding":
                        m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                        if m and m.group(1).lower() != "port":
                            p, vlans = m.group(1), m.group(2).lower()
                            entry = ops.setdefault(p, {})
                            entry.setdefault("mode", "trunk")
                            entry.setdefault("oper_mode", "trunk")
                            if not entry.get("trunk_active_vlans"):
                                entry["trunk_active_vlans"] = vlans
        except Exception as exc:
            logger.debug("[%s] Cisco show interfaces trunk failed: %s", self.ip, exc)

        try:
            raw_ec = conn.send_command("show etherchannel summary")
            if isinstance(raw_ec, str) and raw_ec.strip() and "Invalid input" not in raw_ec:
                for line in raw_ec.splitlines():
                    m_ec = re.match(r"^\s*\d+\s+(Po\d+)\(\S+\)\s+(LACP|PAgP|-)\s+(.+)$", line, re.I)
                    if m_ec:
                        po_name, proto, members_str = m_ec.group(1), m_ec.group(2).lower(), m_ec.group(3)
                        for tok in members_str.split():
                            pname = re.sub(r"\([^)]*\)$", "", tok).strip()
                            if pname:
                                ops.setdefault(pname, {})["lag_group"] = po_name
                                ops[pname]["lacp_mode"] = "active" if proto == "lacp" else "on"
        except Exception as exc:
            logger.debug("[%s] Cisco show etherchannel summary failed: %s", self.ip, exc)

        return ops

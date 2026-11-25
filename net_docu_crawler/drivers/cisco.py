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
Cisco Systems Driver: IOS, IOS-XE, NX-OS, and IOS-XR.
Official Documentation: https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html
"""

import logging
import re

import oui_lookup
import parser
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_CLI_ERROR_RE = re.compile(
    r"(?:%\s*invalid\s+(?:input|command)|%\s*unrecognized|%\s*ambiguous|%\s*authorization\s+failed)",
    re.IGNORECASE,
)


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

    def _get_os_type(self) -> str:
        return getattr(self, "_os_type", "cisco_ios") or "cisco_ios"

    def _fetch_inventory(self, conn) -> str:
        cached = getattr(self, "_cached_inventory", None)
        if cached is not None:
            return cached
        try:
            raw = conn.send_command("show inventory")
            if isinstance(raw, str):
                self._cached_inventory = raw
                return raw
        except Exception as exc:
            logger.warning("[%s] Cisco 'show inventory' failed: %s", self.ip, exc)
        return ""

    def crawl(self, conn) -> dict:
        sh_ver = self._safe_send_command(conn, "show version")
        prompt = self._safe_find_prompt(conn) or ""
        if re.search(r"\b(?:Arista|vEOS|cEOS)\b", sh_ver, re.IGNORECASE) or "arista" in prompt.lower():
            from net_docu_crawler.drivers.arista import AristaDriver

            logger.info("[%s] Detected Arista EOS during CiscoDriver probe; delegating to AristaDriver.", self.ip)
            if self.secret or prompt.strip().endswith(">"):
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
            sh_ver = self._safe_send_command(conn, "show version")
        os_type = "cisco_ios"
        if "NX-OS" in sh_ver or "Nexus" in sh_ver:
            os_type = "cisco_nxos"
        elif "IOS-XR" in sh_ver or "IOS XR" in sh_ver:
            os_type = "cisco_xr"
        self._os_type = os_type

        ver = parser.parse_show_version(sh_ver, os_type)
        ver["os_type"] = os_type

        if not ver.get("hostname"):
            prompt = self._safe_find_prompt(conn)
            if prompt:
                cleaned_prompt = re.sub(r"\([^)]*\)", "", prompt).rstrip(">#").strip()
                if cleaned_prompt:
                    ver["hostname"] = cleaned_prompt

        # Verify model and serial via show inventory if available
        try:
            sh_inv = self._fetch_inventory(conn)
            inv_items = parser.parse_show_inventory(sh_inv, os_type=os_type)
            chosen = None
            for item in inv_items:
                if "chassis" in item.get("name", "").lower() or "chassis" in item.get("descr", "").lower():
                    chosen = item
                    break
            if chosen is None:
                for item in inv_items:
                    if re.fullmatch(r"(?:switch\s*)?\d+", item.get("name", "").strip(), re.IGNORECASE) and item.get(
                        "pid"
                    ):
                        chosen = item
                        break
            if chosen:
                if chosen.get("pid"):
                    ver["model"] = chosen["pid"]
                if chosen.get("sn") and chosen["sn"] != "N/A":
                    ver["serial"] = chosen["sn"]
        except Exception as exc:
            logger.warning("[%s] Cisco show inventory parse failed: %s", self.ip, exc)

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
        os_type = self._get_os_type()
        l3_ints: list[dict] = []
        ints_detail: dict[str, dict] = {}
        try:
            sh_ip_int = conn.send_command("show ip interface brief")
            if isinstance(sh_ip_int, str) and _CLI_ERROR_RE.search(sh_ip_int):
                logger.warning("[%s] Cisco 'show ip interface brief' returned CLI error.", self.ip)
            else:
                l3_ints = parser.parse_ip_interface_brief(sh_ip_int, os_type)
        except Exception as exc:
            logger.warning("[%s] Cisco 'show ip interface brief' failed: %s", self.ip, exc)

        sh_ints = ""
        try:
            sh_ints = conn.send_command("show interfaces")
            if isinstance(sh_ints, str) and _CLI_ERROR_RE.search(sh_ints):
                logger.warning("[%s] Cisco 'show interfaces' returned CLI error.", self.ip)
                sh_ints = ""
            else:
                ints_detail = parser.parse_show_interfaces(sh_ints, os_type)
                for stats in ints_detail.values():
                    if stats.get("mac_address"):
                        stats["mac_address"] = oui_lookup.normalize_mac(stats["mac_address"]).lower()
        except Exception as exc:
            logger.warning("[%s] Cisco 'show interfaces' failed: %s", self.ip, exc)

        # Backfill /prefix masks from "Internet address is X.X.X.X/Y" in show interfaces
        cidr_by_intf: dict[str, str] = {}
        cidr_by_norm: dict[str, str] = {}
        cur_intf: str | None = None
        for line in (sh_ints or "").splitlines():
            m_hdr = re.match(r"^([A-Za-z0-9/._-]+)\s+is\s+(?:up|down|administratively)", line.strip())
            if m_hdr:
                cur_intf = m_hdr.group(1)
            elif cur_intf:
                m_addr = re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m_addr:
                    cidr_by_intf[cur_intf] = m_addr.group(1)
                    cidr_by_norm[self._norm_port(cur_intf)] = m_addr.group(1)

        for entry in l3_ints:
            ip_val = str(entry.get("ip_address") or "").strip()
            intf_name = str(entry.get("interface") or "").strip()
            cidr_cand = cidr_by_intf.get(intf_name) or cidr_by_norm.get(self._norm_port(intf_name))
            if ip_val and "/" not in ip_val and " " not in ip_val and cidr_cand:
                if cidr_cand.startswith(ip_val + "/"):
                    entry["ip_address"] = cidr_cand

        return l3_ints, ints_detail

    def get_neighbors(self, conn) -> list[dict]:
        os_type = self._get_os_type()
        neighbors = []
        seen = set()
        cdp_status = "unknown"
        lldp_status = "unknown"
        try:
            sh_cdp = conn.send_command("show cdp neighbors detail")
            cdp_low = (sh_cdp or "").lower()
            if "cdp is not enabled" in cdp_low:
                cdp_status = "disabled"
            elif "invalid input" in cdp_low or "invalid command" in cdp_low:
                cdp_status = "unsupported"
            else:
                cdp_status = "enabled"
            for n in parser.parse_cdp_neighbors_detail(sh_cdp, os_type=os_type):
                n["remote_platform"] = n.get("platform", "")
                key = (self._norm_port(n.get("local_port", "")), n.get("remote_device", "").lower())
                if key not in seen:
                    seen.add(key)
                    neighbors.append(n)
        except Exception as exc:
            logger.warning("[%s] Cisco show cdp neighbors detail failed: %s", self.ip, exc)
        try:
            sh_lldp = conn.send_command("show lldp neighbors detail")
            lldp_low = (sh_lldp or "").lower()
            if "lldp is not enabled" in lldp_low:
                lldp_status = "disabled"
            elif "invalid input" in lldp_low or "invalid command" in lldp_low:
                lldp_status = "unsupported"
            else:
                lldp_status = "enabled"

            lldp_entries = parser.parse_lldp_neighbors_detail(sh_lldp, os_type=os_type)
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
                lldp_port_norm = self._norm_port(lldp_port) if lldp_port else ""

                # Correlate LLDP with existing CDP entries using normalized port names and peer identity
                matched_cdp = None
                for existing in neighbors:
                    ex_ip = (existing.get("remote_ip") or "").strip()
                    ex_dev = (existing.get("remote_device") or "").strip()
                    ex_dev_hex = re.sub(r"[^0-9a-f]", "", ex_dev.lower())
                    ex_port_norm = self._norm_port(existing.get("local_port", ""))
                    same_port = bool(lldp_port_norm and ex_port_norm and ex_port_norm == lldp_port_norm)

                    if lldp_ip and ex_ip and lldp_ip == ex_ip:
                        matched_cdp = existing
                        break
                    if lldp_mac_hex and len(lldp_mac_hex) == 12 and ex_dev_hex == lldp_mac_hex:
                        matched_cdp = existing
                        break
                    if same_port and (
                        (lldp_name and ex_dev.lower() == lldp_name.lower())
                        or (
                            n.get("remote_port")
                            and existing.get("remote_port")
                            and self._norm_port(n["remote_port"]) == self._norm_port(existing["remote_port"])
                        )
                        or re.fullmatch(r"[0-9a-fA-F]{12}", ex_dev)
                    ):
                        matched_cdp = existing
                        break

                if matched_cdp is not None:
                    ex_dev = (matched_cdp.get("remote_device") or "").strip()
                    if lldp_name and re.fullmatch(r"[0-9a-fA-F]{12}", ex_dev):
                        matched_cdp["remote_device"] = lldp_name
                    if not matched_cdp.get("remote_mac") and n.get("remote_mac"):
                        matched_cdp["remote_mac"] = n["remote_mac"]
                    if not matched_cdp.get("remote_ip") and lldp_ip:
                        matched_cdp["remote_ip"] = lldp_ip
                    if not matched_cdp.get("platform") and n.get("platform"):
                        matched_cdp["platform"] = n["platform"]
                        matched_cdp["remote_platform"] = n["platform"]
                    continue

                if not lldp_port:
                    continue
                key = (lldp_port_norm, lldp_name.lower())
                if key not in seen:
                    seen.add(key)
                    neighbors.append(n)
        except Exception as exc:
            logger.warning("[%s] Cisco show lldp neighbors detail failed: %s", self.ip, exc)

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
            pending_dev = ""
            intf_pat = r"(?:Gi|Fa|Te|Tw|Twe|Fo|Hu|Fi|Ap|Mg|Mgmt|Eth|Po|Tu)\S+"
            row_re = re.compile(
                rf"^\s*(\S+)\s+({intf_pat})\s+\d+\s+.*?\s+(\S+)\s*$",
                re.IGNORECASE,
            )
            cont_re = re.compile(
                rf"^\s+({intf_pat})\s+\d+\s+.*?\s+(\S+)\s*$",
                re.IGNORECASE,
            )
            for line in (raw or "").splitlines():
                if not line.strip() or line.strip().startswith(("Device ID", "Capability", "Total", "-")):
                    pending_dev = ""
                    continue
                m = row_re.match(line)
                if m:
                    dev_id, local_intf, port_id = m.groups()
                    dev_short = dev_id.split(".")[0].lower()
                    mapping[(dev_short, port_id.lower())] = local_intf
                    mapping.setdefault((dev_short, ""), local_intf)
                    pending_dev = ""
                    continue
                if pending_dev:
                    m_cont = cont_re.match(line)
                    if m_cont:
                        local_intf, port_id = m_cont.groups()
                        dev_short = pending_dev.split(".")[0].lower()
                        mapping[(dev_short, port_id.lower())] = local_intf
                        mapping.setdefault((dev_short, ""), local_intf)
                        pending_dev = ""
                        continue
                parts = line.split()
                if len(parts) == 1 and not line[0].isspace():
                    pending_dev = parts[0]
                else:
                    pending_dev = ""
        except Exception as exc:
            logger.warning("[%s] Cisco show lldp neighbors summary fallback failed: %s", self.ip, exc)
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
            return parser.parse_spanning_tree(sh_stp, self._get_os_type())
        except Exception as exc:
            logger.warning("[%s] Cisco show spanning-tree failed: %s", self.ip, exc)
            return {"enabled": False, "vlans": {}}

    def get_routing_table(self, conn) -> list[dict]:
        try:
            sh_route = conn.send_command("show ip route")
            return parser.parse_show_ip_route(sh_route, self._get_os_type())
        except Exception as exc:
            logger.warning("[%s] Cisco show ip route failed: %s", self.ip, exc)
            return []

    def get_arp_table(self, conn) -> list[dict]:
        try:
            sh_arp = conn.send_command("show ip arp")
            return parser.parse_show_ip_arp(sh_arp, self._get_os_type())
        except Exception as exc:
            logger.warning("[%s] Cisco show ip arp failed: %s", self.ip, exc)
            return []

    def get_poe(self, conn) -> dict:
        poe: dict = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show power inline")
            if not isinstance(raw, str) or not raw.strip():
                return poe
            if _CLI_ERROR_RE.search(raw) or "not supported" in raw.lower():
                poe["poe_supported"] = False
                return poe

            # Catalyst 2960/3560/3750 key-value summary
            m_tot = re.search(r"Available:\s*([\d.]+)\s*\(W\)", raw)
            m_used = re.search(r"Used:\s*([\d.]+)\s*\(W\)", raw)
            m_rem = re.search(r"Remaining:\s*([\d.]+)\s*\(W\)", raw)
            if m_tot:
                poe["total_power_watts"] = float(m_tot.group(1))
            if m_used:
                poe["used_power_watts"] = float(m_used.group(1))
            if m_rem:
                poe["available_power_watts"] = float(m_rem.group(1))

            # Catalyst 3650/3850/9200/9300/9400 tabular module summary
            if poe["total_power_watts"] == 0.0:
                mod_tot = 0.0
                mod_used = 0.0
                mod_rem = 0.0
                for line in raw.splitlines():
                    m_mod = re.match(r"^\s*\d+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$", line)
                    if m_mod:
                        mod_tot += float(m_mod.group(1))
                        mod_used += float(m_mod.group(2))
                        mod_rem += float(m_mod.group(3))
                if mod_tot > 0:
                    poe["total_power_watts"] = round(mod_tot, 2)
                    poe["used_power_watts"] = round(mod_used, 2)
                    poe["available_power_watts"] = round(mod_rem, 2)

            # Per-port PoE rows (e.g. "Gi1/0/1  auto  on  15.4  AIR-AP3802I-B-K9  4  30.0")
            port_re = re.compile(
                r"^\s*((?:Gi|Fa|Te|Tw|Twe|Fo|Hu|Eth|Fi)\S+)\s+(auto|static|off)\s+(\S+)\s+([\d.]+)\s+(.*?)\s+(\S+)\s+([\d.]+)\s*$",
                re.IGNORECASE,
            )
            for line in raw.splitlines():
                m_p = port_re.match(line)
                if m_p:
                    pname, _admin, oper, watts_s, _dev, pclass, _maxw = m_p.groups()
                    w_val = float(watts_s)
                    poe["ports"][pname] = {
                        "status": oper.lower(),
                        "power_watts": w_val,
                        "watts": w_val,
                        "class": pclass,
                    }

            if poe["total_power_watts"] > 0 or poe["ports"]:
                poe["poe_supported"] = True
        except Exception as exc:
            logger.warning("[%s] Cisco show power inline failed: %s", self.ip, exc)
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries: list[dict] = []
        try:
            raw = conn.send_command("show mac address-table")
            if not isinstance(raw, str) or not raw.strip() or _CLI_ERROR_RE.search(raw):
                raw = conn.send_command("show mac-address-table")
            if not isinstance(raw, str) or not raw.strip() or _CLI_ERROR_RE.search(raw):
                return entries
            for item in parser.parse_mac_address_table(raw, self._get_os_type()):
                norm_mac = oui_lookup.normalize_mac(item["mac"]).lower()
                entries.append(
                    {
                        "vlan": item["vlan"],
                        "mac": norm_mac,
                        "type": item.get("type", "dynamic"),
                        "interface": item["interface"],
                        "vendor": oui_lookup.lookup_oui(norm_mac),
                    }
                )
        except Exception as exc:
            logger.warning("[%s] Cisco show mac address-table failed: %s", self.ip, exc)
        return entries

    @staticmethod
    def _norm_port(port: str) -> str:
        p = port.strip().lower()
        for full, short in (
            ("twentyfivegige", "twe"),
            ("hundredgige", "hu"),
            ("fortygige", "fo"),
            ("tengigabitethernet", "te"),
            ("tengige", "te"),
            ("gigabitethernet", "gi"),
            ("fastethernet", "fa"),
            ("ethernet", "eth"),
            ("port-channel", "po"),
        ):
            if p.startswith(full):
                return short + p[len(full) :]
        return p

    def get_optics(self, conn) -> list[dict]:
        optics_by_norm: dict[str, dict] = {}

        # 1. Pull transceiver type, PID, and serial numbers from `show inventory` (cached)
        try:
            inv_raw = self._fetch_inventory(conn)
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
            logger.warning("[%s] Cisco show inventory optics parse failed: %s", self.ip, exc)

        # 2. Merge live DOM telemetry from `show interfaces transceiver` (handles N/A and ++/-- alarm flags)
        def _parse_dom_float(tok: str) -> float | None:
            t = (tok or "").strip()
            if not t or t.upper() == "N/A":
                return None
            try:
                return float(t)
            except ValueError:
                return None

        val_tok = r"(?:N/A|[+-]?\d+(?:\.\d+)?)"
        alarm_tok = r"(?:\s*(?:\+\+|--|\+|-))?"
        dom_re = re.compile(
            rf"^([A-Za-z0-9/\._-]+)\s+({val_tok})(?:\s*C)?{alarm_tok}\s+"
            rf"({val_tok})(?:\s*V)?{alarm_tok}\s+"
            rf"({val_tok})(?:\s*mA)?{alarm_tok}\s+"
            rf"({val_tok})(?:\s*dBm)?{alarm_tok}\s+"
            rf"({val_tok})(?:\s*dBm)?{alarm_tok}",
            re.IGNORECASE,
        )
        try:
            raw = conn.send_command("show interfaces transceiver")
            if isinstance(raw, str) and not _CLI_ERROR_RE.search(raw):
                for line in raw.splitlines():
                    line = line.strip()
                    if not line or line.startswith("Port") or "---" in line or "Transceiver" in line:
                        continue
                    m = dom_re.match(line)
                    if m:
                        port = m.group(1)
                        temp = _parse_dom_float(m.group(2))
                        volt = _parse_dom_float(m.group(3))
                        tx = _parse_dom_float(m.group(5))
                        rx = _parse_dom_float(m.group(6))
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
            logger.warning("[%s] Cisco show interfaces transceiver failed: %s", self.ip, exc)
        return list(optics_by_norm.values())

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "show running-config")

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        try:
            raw_trunk = conn.send_command("show interfaces trunk")
            if isinstance(raw_trunk, str) and raw_trunk.strip() and not _CLI_ERROR_RE.search(raw_trunk):
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
            logger.warning("[%s] Cisco show interfaces trunk failed: %s", self.ip, exc)

        # Port-channel summary: NX-OS uses `show port-channel summary`, IOS/IOS-XE uses `show etherchannel summary`
        lag_cmds = (
            ("show port-channel summary", "show etherchannel summary")
            if self._get_os_type() == "cisco_nxos"
            else ("show etherchannel summary", "show port-channel summary")
        )
        for lag_cmd in lag_cmds:
            try:
                raw_ec = conn.send_command(lag_cmd)
                if not isinstance(raw_ec, str) or not raw_ec.strip() or _CLI_ERROR_RE.search(raw_ec):
                    continue
                matched_any = False
                for line in raw_ec.splitlines():
                    # IOS: "1  Po1(SU)  LACP  Gi1/0/21(P)  Gi1/0/22(P)"
                    # NX-OS: "1  Po1(SU)  Eth  LACP  Eth1/49(P)  Eth1/50(P)"
                    m_ec = re.match(
                        r"^\s*\d+\s+(Po\d+)\([^)]*\)\s+(?:Eth\s+)?(LACP|PAgP|NONE|-)\s+(.+)$",
                        line,
                        re.I,
                    )
                    if m_ec:
                        matched_any = True
                        po_name, proto, members_str = m_ec.group(1), m_ec.group(2).lower(), m_ec.group(3)
                        for tok in members_str.split():
                            pname = re.sub(r"\([^)]*\)$", "", tok).strip()
                            if pname:
                                ops.setdefault(pname, {})["lag_group"] = po_name
                                ops[pname]["lacp_mode"] = "active" if proto == "lacp" else "on"
                if matched_any:
                    break
            except Exception as exc:
                logger.warning("[%s] Cisco '%s' failed: %s", self.ip, lag_cmd, exc)

        return ops

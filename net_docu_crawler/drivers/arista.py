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
Arista EOS Driver: Switches and Routers running Arista EOS.
Leverages native structured JSON commands ('| json') for deterministic parsing.
Official Documentation: https://www.arista.com/en/um-eos
"""

import json
import logging
import math
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_EOS_CLI_ERROR_RE = re.compile(
    r"(?:%\s*invalid\s+input|%\s*ambiguous\s+command|%\s*incomplete\s+command|%\s*unrecognized|%\s*unavailable)",
    re.IGNORECASE,
)


def _is_eos_cli_error(raw: str) -> bool:
    return bool(isinstance(raw, str) and raw and _EOS_CLI_ERROR_RE.search(raw))


def _parse_float_safe(val) -> float | None:
    """Safely parse numeric strings (stripping units like W/dBm/C/V); return None on N/A or invalid values."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val) if math.isfinite(val) else None
    text = str(val).strip()
    if not text or text.upper() in ("N/A", "NA", "-", "NONE") or "inf" in text.lower():
        return None
    m = re.match(r"^([+-]?\d+(?:\.\d+)?)", text)
    if not m:
        return None
    try:
        parsed = float(m.group(1))
        return parsed if math.isfinite(parsed) else None
    except ValueError:
        return None


def _format_eos_bandwidth(bw) -> str:
    """Convert EOS numeric interface `bandwidth` (bits/sec) into a human-readable speed string."""
    val = _parse_float_safe(bw)
    if not val or val <= 0:
        return ""
    if val >= 1_000_000_000:
        gbps = val / 1_000_000_000
        return f"{int(gbps)}Gb/s" if gbps.is_integer() else f"{gbps:g}Gb/s"
    if val >= 1_000_000:
        mbps = val / 1_000_000
        return f"{int(mbps)}Mb/s" if mbps.is_integer() else f"{mbps:g}Mb/s"
    return f"{int(val)}b/s"


def _format_eos_duplex(val) -> str:
    s = str(val or "").strip().lower()
    if "full" in s:
        return "Full"
    if "half" in s:
        return "Half"
    if "auto" in s:
        return "Auto"
    return ""


def _extract_eos_primary_ip(intf_data: dict) -> str:
    """Extract `ip/maskLen` from EOS `interfaceAddress` whether dict, list, or None."""
    if not isinstance(intf_data, dict):
        return ""
    addr_obj = intf_data.get("interfaceAddress")
    candidates: list[dict] = []
    if isinstance(addr_obj, dict):
        candidates = [addr_obj]
    elif isinstance(addr_obj, list):
        candidates = [item for item in addr_obj if isinstance(item, dict)]

    for cand in candidates:
        primary = cand.get("primaryIp")
        if not isinstance(primary, dict):
            continue
        ip_addr = str(primary.get("address") or "").strip()
        mask_len = primary.get("maskLen", 0)
        if ip_addr and ip_addr != "0.0.0.0":
            return f"{ip_addr}/{mask_len}"
    return ""


def _extract_eos_counters(counters) -> tuple[int, int, int, int]:
    """Extract (input_errors, crc, output_errors, drops) across EOS 4.x (`totalInErrors`) and legacy schemas."""
    if not isinstance(counters, dict):
        return 0, 0, 0, 0
    in_err = counters.get("totalInErrors")
    if in_err is None:
        in_err = counters.get("inErrors", 0)
    out_err = counters.get("totalOutErrors")
    if out_err is None:
        out_err = counters.get("outErrors", 0)
    err_detail = counters.get("inputErrorsDetail")
    fcs_err = err_detail.get("fcsErrors") if isinstance(err_detail, dict) else None
    if fcs_err is None:
        fcs_err = counters.get("fcsErrors", 0)
    drops = int(counters.get("inDiscards", 0) or 0) + int(counters.get("outDiscards", 0) or 0)
    return int(in_err or 0), int(fcs_err or 0), int(out_err or 0), drops


def _classify_eos_neighbor_type(remote_sys: str, remote_caps, mac_vendor: str, remote_dev: str = "") -> str:
    """Classify an Arista EOS LLDP neighbor instead of hardcoding 'switch'."""
    sys_low = (remote_sys or "").lower()
    vend_low = (mac_vendor or "").lower() if mac_vendor and mac_vendor != "Unknown" else ""
    dev_low = (remote_dev or "").lower()
    if isinstance(remote_caps, dict):
        caps_low = " ".join(str(k).lower() for k, v in remote_caps.items() if v)
    elif isinstance(remote_caps, list):
        caps_low = " ".join(str(x).lower() for x in remote_caps)
    else:
        caps_low = str(remote_caps or "").lower()
    blob = f"{sys_low} {vend_low} {dev_low}"

    if (
        "phone" in caps_low
        or "telephone" in caps_low
        or re.search(
            r"\b(?:digium|yealink|polycom|mitel|avaya|grandstream|snom|sangoma|voip|ip phone|telephone)\b", blob
        )
    ):
        return "phone"
    if re.search(r"\b(?:axis|verkada|hikvision|valcom|hanwha|camera)\b", blob):
        return "camera"
    if (
        re.search(r"(?:\bap\b|access point|arubaos|unifi|instant|\bwlan\b|ruckus|meraki)", sys_low)
        or any(k in caps_low for k in ("wlan", "access point"))
        or (
            any(v in vend_low for v in ("aruba", "ubiquiti", "ruckus", "meraki"))
            and not re.search(r"\b(?:switch|router|icx|procurve)\b", f"{sys_low} {dev_low}")
        )
    ):
        return "ap"
    if any(k in f"{sys_low} {vend_low}" for k in ("firewall", "srx", "palo", "forti", "opnsense", "pfsense")):
        return "firewall"
    if any(k in sys_low for k in ("router", "ios software", "routeros", "frrouting")) or (
        "router" in caps_low and "bridge" not in caps_low
    ):
        return "router"
    if (
        re.search(r"\b(?:apple|dell|lenovo|intel|microsoft|realtek|workstation|desktop|laptop)\b", blob)
        and "bridge" not in caps_low
        and not re.search(r"\b(?:switch|powerconnect)\b", sys_low)
    ):
        return "endpoint"
    return "switch"


class AristaDriver(BaseDriver):
    """
    Driver for Arista appliances running EOS.
    Persona: switch / spine / leaf router.
    """

    vendor_name = "Arista"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "terminal length 0"

    def connect(self):
        device = self._build_netmiko_params("arista_eos", secret=self.secret, include_auth_timeout=True)
        conn = self.connect_netmiko(device)
        self._safe_enable(conn)
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Arista Switch",
            "serial": "Unknown",
            "firmware": "EOS",
            "os_type": "arista_eos",
            "device_persona": self.device_persona,
        }
        try:
            raw = conn.send_command("show version | json")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show version")
            info["model"] = data.get("modelName", "Arista")
            info["serial"] = data.get("serialNumber") or "Unknown"
            ver_str = data.get("version") or data.get("internalVersion") or ""
            info["firmware"] = f"EOS {ver_str}".strip()
            sys_mac = data.get("systemMacAddress", "")
            if sys_mac:
                info["mac_address"] = oui_lookup.normalize_mac(sys_mac).lower()
        except Exception as exc:
            logger.warning("[%s] Arista show version | json failed, falling back to text: %s", self.ip, exc)
            raw_txt = getattr(self, "_prefetched_sh_ver", "") or self._safe_send_command(conn, "show version")
            m_mod = re.search(r"^\s*Arista\s+(\S+)", raw_txt, re.MULTILINE)
            if m_mod:
                info["model"] = m_mod.group(1).strip()
            m_ser = re.search(r"Serial\s+number\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
            if m_ser:
                info["serial"] = m_ser.group(1).strip()
            m_ver = re.search(r"Software\s+image\s+version\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
            if m_ver:
                info["firmware"] = f"EOS {m_ver.group(1).strip()}"
            m_mac = re.search(r"(?:System|Hardware)\s+MAC\s+address\s*:\s*([0-9a-fA-F:.-]+)", raw_txt, re.IGNORECASE)
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()

        try:
            raw_host = conn.send_command("show hostname | json")
            h_data = json.loads(raw_host)
            if isinstance(h_data, dict):
                info["hostname"] = h_data.get("fqdn") or h_data.get("hostname", "")
        except Exception as exc:
            logger.warning("[%s] Arista show hostname | json failed, falling back to prompt: %s", self.ip, exc)
            prompt = self._safe_find_prompt(conn)
            if prompt:
                info["hostname"] = prompt.rstrip(">#").strip()

        if not info["hostname"]:
            raw_cfg = self._safe_send_command(conn, "show running-config")
            m_h = re.search(r"^\s*hostname\s+(\S+)", raw_cfg, re.MULTILINE)
            if m_h:
                info["hostname"] = m_h.group(1).strip()

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}
        seen_l3: set[tuple[str, str]] = set()
        try:
            raw = conn.send_command("show ip interface | json")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show ip interface")
            for intf_name, intf_data in (data.get("interfaces") or {}).items():
                if not isinstance(intf_data, dict) or intf_name.lower().startswith("loopback"):
                    continue
                full_ip = _extract_eos_primary_ip(intf_data)
                status = "up" if intf_data.get("lineProtocolStatus") == "up" else "down"
                raw_mac = (
                    intf_data.get("routedAddr")
                    or intf_data.get("burnedInAddress")
                    or intf_data.get("physicalAddress")
                    or ""
                )
                norm_mac = oui_lookup.normalize_mac(raw_mac).lower() if raw_mac else ""

                if full_ip:
                    l3_interfaces.append(
                        {
                            "interface": intf_name,
                            "ip_address": full_ip,
                            "status": status,
                            "protocol": status,
                        }
                    )
                    seen_l3.add((intf_name, full_ip))

                in_err, crc_err, out_err, drops = _extract_eos_counters(intf_data.get("interfaceCounters"))
                interfaces_detail[intf_name] = {
                    "ip_address": full_ip,
                    "status": status,
                    "mac_address": norm_mac,
                    "description": intf_data.get("description", ""),
                    "input_errors": in_err,
                    "crc": crc_err,
                    "output_errors": out_err,
                    "drops": drops,
                }
        except Exception as exc:
            logger.warning("[%s] Arista show ip interface | json failed, falling back to text: %s", self.ip, exc)

        # Enrich ALL ports (including merging counters/speed/duplex/MTU into L3 ports) via `show interfaces | json`
        try:
            raw_all = conn.send_command("show interfaces | json")
            if isinstance(raw_all, str) and raw_all.strip().startswith("{"):
                all_data = json.loads(raw_all)
                if isinstance(all_data, dict):
                    for intf_name, intf_data in (all_data.get("interfaces") or {}).items():
                        if not isinstance(intf_data, dict) or intf_name.lower().startswith("loopback"):
                            continue
                        status = "up" if intf_data.get("lineProtocolStatus") == "up" else "down"
                        raw_mac = intf_data.get("burnedInAddress") or intf_data.get("physicalAddress") or ""
                        norm_mac = oui_lookup.normalize_mac(raw_mac).lower() if raw_mac else ""
                        in_err, crc_err, out_err, drops = _extract_eos_counters(intf_data.get("interfaceCounters"))
                        speed_str = _format_eos_bandwidth(intf_data.get("bandwidth"))
                        duplex_str = _format_eos_duplex(intf_data.get("duplex"))
                        mtu_val = intf_data.get("mtu")
                        full_ip = _extract_eos_primary_ip(intf_data)

                        if full_ip and (intf_name, full_ip) not in seen_l3:
                            l3_interfaces.append(
                                {
                                    "interface": intf_name,
                                    "ip_address": full_ip,
                                    "status": status,
                                    "protocol": status,
                                }
                            )
                            seen_l3.add((intf_name, full_ip))

                        if intf_name in interfaces_detail:
                            rec = interfaces_detail[intf_name]
                            if not rec.get("mac_address") and norm_mac:
                                rec["mac_address"] = norm_mac
                            if not rec.get("description") and intf_data.get("description"):
                                rec["description"] = intf_data.get("description", "")
                            if not rec.get("ip_address") and full_ip:
                                rec["ip_address"] = full_ip
                            if speed_str:
                                rec["speed"] = speed_str
                            if duplex_str:
                                rec["duplex"] = duplex_str
                            if isinstance(mtu_val, int) and mtu_val > 0:
                                rec["mtu"] = mtu_val
                            rec["input_errors"] = max(int(rec.get("input_errors", 0) or 0), in_err)
                            rec["crc"] = max(int(rec.get("crc", 0) or 0), crc_err)
                            rec["output_errors"] = max(int(rec.get("output_errors", 0) or 0), out_err)
                            rec["drops"] = max(int(rec.get("drops", 0) or 0), drops)
                        else:
                            rec = {
                                "ip_address": full_ip,
                                "status": status,
                                "mac_address": norm_mac,
                                "description": intf_data.get("description", ""),
                                "input_errors": in_err,
                                "crc": crc_err,
                                "output_errors": out_err,
                                "drops": drops,
                            }
                            if speed_str:
                                rec["speed"] = speed_str
                            if duplex_str:
                                rec["duplex"] = duplex_str
                            if isinstance(mtu_val, int) and mtu_val > 0:
                                rec["mtu"] = mtu_val
                            interfaces_detail[intf_name] = rec
        except Exception as exc:
            logger.warning("[%s] Arista show interfaces | json failed: %s", self.ip, exc)

        if not l3_interfaces and not interfaces_detail:
            import parser as cli_parser

            sh_ip_int = self._safe_send_command(conn, "show ip interface brief")
            for entry in cli_parser.parse_ip_interface_brief(sh_ip_int, "cisco_ios"):
                if not entry.get("interface", "").lower().startswith("loopback"):
                    l3_interfaces.append(entry)
            sh_ints = self._safe_send_command(conn, "show interfaces")
            for intf_name, stats in cli_parser.parse_show_interfaces(sh_ints, "cisco_ios").items():
                if intf_name.lower().startswith("loopback"):
                    continue
                if stats.get("mac_address"):
                    stats["mac_address"] = oui_lookup.normalize_mac(stats["mac_address"]).lower()
                interfaces_detail[intf_name] = stats

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        lldp_status = "unknown"
        notes = ""
        parsed_json = False
        try:
            raw = conn.send_command("show lldp neighbors detail | json")
            raw_low = (raw or "").lower()
            if "lldp is not enabled" in raw_low or "lldp is disabled" in raw_low:
                lldp_status = "disabled"
                notes = "LLDP is disabled on Arista EOS."
            elif isinstance(raw, str) and raw.strip().startswith("{"):
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("Unexpected non-object JSON for show lldp neighbors detail")
                lldp_status = "enabled"
                parsed_json = True
                for local_port, nbr_list in (data.get("lldpNeighbors") or {}).items():
                    if not isinstance(nbr_list, dict):
                        continue
                    info_items = nbr_list.get("lldpNeighborInfo") or []
                    if isinstance(info_items, dict):
                        info_items = [info_items]
                    for nbr in info_items:
                        if not isinstance(nbr, dict):
                            continue
                        chassis_id = str(nbr.get("chassisId") or "").strip()
                        norm_mac = oui_lookup.normalize_mac(chassis_id).lower() if chassis_id else ""
                        remote_mac = norm_mac if re.match(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", norm_mac) else chassis_id
                        mac_vendor = oui_lookup.lookup_oui(remote_mac) if remote_mac else "Unknown"
                        rem_dev = nbr.get("systemName") or chassis_id or "Unknown"
                        rem_port = nbr.get("portId", "Unknown")
                        rem_sys = str(nbr.get("systemDescription") or "")[:60]
                        rem_ip = ""
                        mgmt_addrs = nbr.get("managementAddresses") or []
                        if isinstance(mgmt_addrs, dict):
                            mgmt_addrs = [mgmt_addrs]
                        for addr_item in mgmt_addrs:
                            if not isinstance(addr_item, dict):
                                continue
                            cand_ip = str(addr_item.get("address") or "").strip()
                            addr_type = str(addr_item.get("addressType") or "").lower()
                            if cand_ip and (addr_type == "ipv4" or re.match(r"^\d+\.\d+\.\d+\.\d+$", cand_ip)):
                                rem_ip = cand_ip
                                break
                            if cand_ip and not rem_ip:
                                rem_ip = cand_ip
                        caps = nbr.get("systemCapabilitiesEnabled") or nbr.get("capabilities") or ""
                        dev_type = _classify_eos_neighbor_type(rem_sys, caps, mac_vendor, rem_dev)
                        neighbors.append(
                            {
                                "local_port": local_port,
                                "remote_device": rem_dev,
                                "remote_port": rem_port,
                                "remote_ip": rem_ip,
                                "remote_mac": remote_mac,
                                "platform": rem_sys,
                                "remote_platform": rem_sys,
                                "device_type": dev_type,
                            }
                        )
        except Exception as exc:
            logger.warning("[%s] Arista show lldp neighbors detail | json failed: %s", self.ip, exc)

        # Text fallback when JSON is unavailable and LLDP is not explicitly disabled
        if not parsed_json and lldp_status != "disabled":
            try:
                raw_txt = self._safe_send_command(conn, "show lldp neighbors detail")
                raw_low = (raw_txt or "").lower()
                if "lldp is not enabled" in raw_low or "lldp is disabled" in raw_low:
                    lldp_status = "disabled"
                    notes = "LLDP is disabled on Arista EOS."
                elif raw_txt and not _is_eos_cli_error(raw_txt):
                    cur_local = ""
                    cur_entry: dict | None = None

                    def _flush_lldp():
                        nonlocal cur_entry
                        if not cur_entry or not cur_entry.get("local_port"):
                            cur_entry = None
                            return
                        if not cur_entry.get("remote_device"):
                            cur_entry["remote_device"] = cur_entry.get("remote_mac") or "Unknown"
                        rmac = cur_entry.get("remote_mac", "")
                        vend = oui_lookup.lookup_oui(rmac) if rmac else "Unknown"
                        cur_entry["device_type"] = _classify_eos_neighbor_type(
                            cur_entry.get("platform", ""), "", vend, cur_entry.get("remote_device", "")
                        )
                        neighbors.append(cur_entry)
                        cur_entry = None

                    for line in raw_txt.splitlines():
                        m_if = re.match(r"^\s*Interface\s+(\S+)\s+detected\b", line, re.IGNORECASE)
                        if m_if:
                            _flush_lldp()
                            cur_local = m_if.group(1)
                            lldp_status = "enabled"
                            continue
                        if re.match(r"^\s*Neighbor\s+\S+", line) and cur_local:
                            _flush_lldp()
                            cur_entry = {
                                "local_port": cur_local,
                                "remote_device": "",
                                "remote_port": "Unknown",
                                "remote_ip": "",
                                "remote_mac": "",
                                "platform": "",
                                "remote_platform": "",
                                "device_type": "switch",
                            }
                            continue
                        if cur_entry is None:
                            continue
                        m_ch = re.search(r"Chassis ID\s*:\s*\"?([^\"]+)\"?\s*$", line)
                        if m_ch and "type" not in line.lower():
                            raw_ch = m_ch.group(1).strip()
                            norm_ch = oui_lookup.normalize_mac(raw_ch).lower()
                            cur_entry["remote_mac"] = (
                                norm_ch if re.match(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", norm_ch) else raw_ch
                            )
                        m_pt = re.search(r"Port ID\s*:\s*\"?([^\"]+)\"?\s*$", line)
                        if m_pt and "type" not in line.lower():
                            cur_entry["remote_port"] = m_pt.group(1).strip()
                        m_sn = re.search(r"System Name\s*:\s*\"?([^\"]+)\"?\s*$", line)
                        if m_sn:
                            cur_entry["remote_device"] = m_sn.group(1).strip()
                        m_sd = re.search(r"System Description\s*:\s*\"?([^\"]+)\"?\s*$", line)
                        if m_sd:
                            plat = m_sd.group(1).strip()[:60]
                            cur_entry["platform"] = plat
                            cur_entry["remote_platform"] = plat
                        m_ip = re.search(r"Management Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", line)
                        if m_ip and not cur_entry["remote_ip"]:
                            cur_entry["remote_ip"] = m_ip.group(1)
                    _flush_lldp()
            except Exception as txt_exc:
                logger.warning("[%s] Arista show lldp neighbors detail text fallback failed: %s", self.ip, txt_exc)

        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        status = super().get_discovery_protocols(conn, raw_config=raw_config, neighbors=neighbors)
        cfg_low = (raw_config or "").lower()
        if re.search(r"^\s*no lldp run\b", cfg_low, re.MULTILINE):
            status["lldp"] = "disabled"
            status["notes"] = "LLDP disabled via 'no lldp run' in EOS configuration."
        elif status["lldp"] == "unknown" and raw_config:
            status["lldp"] = "enabled"
        return status

    def get_stp(self, conn) -> dict:
        stp = {
            "enabled": False,
            "is_root": False,
            "protocol": "Unknown",
            "root_bridge": "",
            "bridge_id": "",
            "bridge_priority": "",
            "root_port": "",
            "vlans": {},
        }
        try:
            raw = conn.send_command("show spanning-tree | json")
            if isinstance(raw, str) and raw.strip().startswith("{"):
                data = json.loads(raw)
                instances = data.get("spanningTreeInstances", {}) if isinstance(data, dict) else {}
                if isinstance(instances, dict) and instances:
                    stp["enabled"] = True
                    for inst_id, inst in instances.items():
                        if not isinstance(inst, dict):
                            continue
                        if inst.get("protocol") and stp["protocol"] == "Unknown":
                            stp["protocol"] = str(inst["protocol"])

                        bridge = inst.get("bridge") if isinstance(inst.get("bridge"), dict) else {}
                        root_b = inst.get("rootBridge") if isinstance(inst.get("rootBridge"), dict) else {}
                        b_mac_raw = str(bridge.get("macAddress") or "").strip()
                        r_mac_raw = str(root_b.get("macAddress") or "").strip()
                        b_mac = oui_lookup.normalize_mac(b_mac_raw).lower() if b_mac_raw else ""
                        r_mac = oui_lookup.normalize_mac(r_mac_raw).lower() if r_mac_raw else ""

                        if bridge.get("priority") is not None and not stp["bridge_priority"]:
                            stp["bridge_priority"] = str(bridge["priority"])
                        if b_mac and not stp["bridge_id"]:
                            stp["bridge_id"] = b_mac
                        if r_mac and not stp["root_bridge"]:
                            stp["root_bridge"] = r_mac
                        elif b_mac and not stp["root_bridge"]:
                            stp["root_bridge"] = b_mac

                        port_map: dict[str, dict] = {}
                        inst_root_port = str(inst.get("rootPort") or "").strip()
                        raw_ifaces = inst.get("interfaces")
                        if isinstance(raw_ifaces, dict):
                            for port_name, p_info in raw_ifaces.items():
                                if not isinstance(p_info, dict):
                                    continue
                                role = str(p_info.get("role") or "")
                                state = str(p_info.get("state") or "")
                                port_map[port_name] = {"role": role, "state": state}
                                if not inst_root_port and role.lower() == "root":
                                    inst_root_port = port_name
                        if inst_root_port and not stp["root_port"]:
                            stp["root_port"] = inst_root_port

                        if "isRootBridge" in inst:
                            inst_is_root = bool(inst.get("isRootBridge", False))
                        elif b_mac and r_mac:
                            inst_is_root = b_mac == r_mac
                        elif b_mac and not r_mac and not inst_root_port:
                            inst_is_root = True
                        else:
                            inst_is_root = False

                        if inst_is_root:
                            stp["is_root"] = True
                        stp["vlans"][inst_id] = port_map
                return stp
        except Exception as exc:
            logger.warning("[%s] Arista show spanning-tree | json failed: %s", self.ip, exc)

        raw_txt = self._safe_send_command(conn, "show spanning-tree")
        if "spanning tree enabled" in raw_txt.lower():
            stp["enabled"] = True
            m_proto = re.search(r"Spanning tree enabled protocol\s+(\S+)", raw_txt, re.IGNORECASE)
            if m_proto:
                stp["protocol"] = m_proto.group(1).strip()
            if "this bridge is the root" in raw_txt.lower():
                stp["is_root"] = True
            m_addr = re.search(r"Root ID.*?Address\s+([0-9a-fA-F:.-]+)", raw_txt, re.DOTALL | re.IGNORECASE)
            if m_addr:
                stp["root_bridge"] = oui_lookup.normalize_mac(m_addr.group(1)).lower()
            for m_inst in re.finditer(r"^(MST\d+|VLAN\d+)\s*$", raw_txt, re.MULTILINE):
                stp["vlans"][m_inst.group(1)] = {}
        return stp

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show ip route | json")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show ip route")
            vrfs = data.get("vrfs") or {}
            if not isinstance(vrfs, dict):
                vrfs = {}
            for vrf_name, vrf_data in vrfs.items():
                if not isinstance(vrf_data, dict):
                    continue
                for subnet, r_info in (vrf_data.get("routes") or {}).items():
                    if not isinstance(r_info, dict):
                        continue
                    proto = r_info.get("routeType", "unknown")
                    vias = r_info.get("vias") or []
                    if not isinstance(vias, list) or not vias:
                        entry = {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": "directly connected",
                            "interface": "",
                        }
                        if vrf_name != "default":
                            entry["vrf"] = vrf_name
                        routes.append(entry)
                        continue
                    for via_obj in vias:
                        if not isinstance(via_obj, dict):
                            continue
                        next_hop = via_obj.get("nexthopAddr") or "directly connected"
                        intf = via_obj.get("interface", "")
                        entry = {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": next_hop,
                            "interface": intf,
                        }
                        if vrf_name != "default":
                            entry["vrf"] = vrf_name
                        routes.append(entry)
            return routes
        except Exception as exc:
            logger.warning("[%s] Arista show ip route | json failed, falling back to text: %s", self.ip, exc)

        raw_txt = self._safe_send_command(conn, "show ip route")
        proto_map = {
            "C": "connected",
            "S": "static",
            "O": "ospf",
            "B": "bgp",
            "R": "rip",
            "K": "kernel",
            "I": "isis",
        }
        cur_proto = ""
        cur_subnet = ""
        for line in raw_txt.splitlines():
            m_hdr = re.match(r"^\s*([CSOBRKI])\*?(?:\s+[A-Z0-9]+)?\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m_hdr:
                cur_proto = proto_map.get(m_hdr.group(1), m_hdr.group(1))
                cur_subnet = m_hdr.group(2)
                m_inline_via = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s*([A-Za-z0-9/._-]+))?", line)
                m_inline_conn = re.search(r"directly connected,\s*([A-Za-z0-9/._-]+)", line, re.IGNORECASE)
                if m_inline_via:
                    routes.append(
                        {
                            "subnet": cur_subnet,
                            "protocol": cur_proto,
                            "next_hop": m_inline_via.group(1),
                            "interface": m_inline_via.group(2) or "",
                        }
                    )
                elif m_inline_conn:
                    routes.append(
                        {
                            "subnet": cur_subnet,
                            "protocol": cur_proto,
                            "next_hop": "directly connected",
                            "interface": m_inline_conn.group(1),
                        }
                    )
                continue
            if not line.strip():
                cur_subnet = ""
                continue
            if cur_subnet:
                m_via = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s*([A-Za-z0-9/._-]+))?", line)
                m_conn = re.search(r"directly connected,\s*([A-Za-z0-9/._-]+)", line, re.IGNORECASE)
                if m_via:
                    routes.append(
                        {
                            "subnet": cur_subnet,
                            "protocol": cur_proto,
                            "next_hop": m_via.group(1),
                            "interface": m_via.group(2) or "",
                        }
                    )
                elif m_conn:
                    routes.append(
                        {
                            "subnet": cur_subnet,
                            "protocol": cur_proto,
                            "next_hop": "directly connected",
                            "interface": m_conn.group(1),
                        }
                    )
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("show ip arp | json")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show ip arp")
            for entry in data.get("ipV4Neighbors", []):
                if not isinstance(entry, dict):
                    continue
                ip_addr = entry.get("address", "")
                mac = entry.get("hwAddress", "")
                intf = entry.get("interface", "")
                if ip_addr and mac:
                    norm_mac = oui_lookup.normalize_mac(mac).lower()
                    arp_entries.append(
                        {
                            "ip": ip_addr,
                            "mac": norm_mac,
                            "interface": intf,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
            return arp_entries
        except Exception as exc:
            logger.warning("[%s] Arista show ip arp | json failed, falling back to text: %s", self.ip, exc)

        raw_txt = self._safe_send_command(conn, "show ip arp")
        for line in raw_txt.splitlines():
            m_arp = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:.-]{12,17})\s+([A-Za-z0-9/._-]+)", line)
            if m_arp:
                norm_mac = oui_lookup.normalize_mac(m_arp.group(2)).lower()
                arp_entries.append(
                    {
                        "ip": m_arp.group(1),
                        "mac": norm_mac,
                        "interface": m_arp.group(3),
                        "type": "dynamic",
                        "vendor": oui_lookup.lookup_oui(norm_mac),
                    }
                )
        return arp_entries

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        json_cli_error = False
        try:
            raw = conn.send_command("show power inline | json")
            if _is_eos_cli_error(raw):
                json_cli_error = True
                raise ValueError("show power inline | json rejected by EOS CLI")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show power inline")
            summary = data.get("powerSummary") or {}
            if isinstance(summary, dict):
                poe["total_power_watts"] = _parse_float_safe(summary.get("totalPower", 0.0)) or 0.0
                poe["used_power_watts"] = _parse_float_safe(summary.get("usedPower", 0.0)) or 0.0
                poe["available_power_watts"] = _parse_float_safe(summary.get("availablePower", 0.0)) or 0.0
            for intf_name, intf_data in (data.get("interfaces") or {}).items():
                if not isinstance(intf_data, dict):
                    continue
                watts_val = _parse_float_safe(intf_data.get("power", 0.0)) or 0.0
                poe["ports"][intf_name] = {
                    "status": intf_data.get("operState", "disabled"),
                    "power_watts": watts_val,
                    "watts": watts_val,
                    "class": str(intf_data.get("class", "unknown")),
                }
        except Exception as exc:
            logger.warning("[%s] Arista show power inline | json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_txt = conn.send_command("show power inline")
                if _is_eos_cli_error(raw_txt) or (json_cli_error and not (raw_txt or "").strip()):
                    poe["poe_supported"] = False
                    return poe
                m_tot = re.search(r"Total:\s*([\d\.]+)W?", raw_txt or "", re.IGNORECASE)
                m_used = re.search(r"Used:\s*([\d\.]+)W?", raw_txt or "", re.IGNORECASE)
                m_avail = re.search(r"Available:\s*([\d\.]+)W?", raw_txt or "", re.IGNORECASE)
                if m_tot:
                    poe["total_power_watts"] = float(m_tot.group(1))
                if m_used:
                    poe["used_power_watts"] = float(m_used.group(1))
                if m_avail:
                    poe["available_power_watts"] = float(m_avail.group(1))
                for line in (raw_txt or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].startswith(("Et", "Ethernet")):
                        watts_val = _parse_float_safe(parts[3]) or 0.0
                        poe["ports"][parts[0]] = {
                            "status": parts[2],
                            "power_watts": watts_val,
                            "watts": watts_val,
                            "class": parts[4] if len(parts) > 4 else "unknown",
                        }
            except Exception as txt_exc:
                logger.warning("[%s] Arista show power inline text fallback failed: %s", self.ip, txt_exc)

        if poe["total_power_watts"] > 0 or poe["ports"]:
            poe["poe_supported"] = True
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show mac address-table | json")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show mac address-table")
            table_entries = (data.get("unicastTable") or {}).get("tableEntries", [])
            for e in table_entries:
                if not isinstance(e, dict):
                    continue
                vlan = str(e.get("vlanId", "1"))
                mac_raw = e.get("macAddress", "")
                mtype = str(e.get("entryType", "dynamic")).lower()
                intf = e.get("interface", "")
                if mac_raw and intf:
                    norm_mac = oui_lookup.normalize_mac(mac_raw).lower()
                    entries.append(
                        {
                            "vlan": vlan,
                            "mac": norm_mac,
                            "type": mtype,
                            "interface": intf,
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] Arista show mac address-table | json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_txt = conn.send_command("show mac address-table")
                for line in (raw_txt or "").splitlines():
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
            except Exception as txt_exc:
                logger.warning("[%s] Arista show mac address-table text fallback failed: %s", self.ip, txt_exc)
        return entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show interfaces transceiver | json")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("Unexpected non-object JSON for show interfaces transceiver")
            for intf_name, intf_info in (data.get("interfaces") or {}).items():
                if not isinstance(intf_info, dict):
                    continue
                optics.append(
                    {
                        "port": intf_name,
                        "vendor": intf_info.get("vendorName") or "Arista Networks",
                        "part_number": intf_info.get("vendorPartNumber") or "SFP-DOM",
                        "serial": intf_info.get("vendorSerial") or "Unknown",
                        "type": intf_info.get("mediaType") or "SFP+",
                        "tx_power_dbm": _parse_float_safe(intf_info.get("txPower")),
                        "rx_power_dbm": _parse_float_safe(intf_info.get("rxPower")),
                        "temperature_c": _parse_float_safe(intf_info.get("temperature")),
                        "voltage_v": _parse_float_safe(intf_info.get("voltage")),
                    }
                )
        except Exception as exc:
            logger.warning(
                "[%s] Arista show interfaces transceiver | json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_txt = conn.send_command("show interfaces transceiver")
                for line in (raw_txt or "").splitlines():
                    line = line.strip()
                    if not line or line.startswith("Port") or "---" in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 6 and parts[0].startswith(("Et", "Ethernet")):
                        optics.append(
                            {
                                "port": parts[0],
                                "vendor": "Arista Networks",
                                "part_number": "SFP-DOM",
                                "serial": "Unknown",
                                "type": "SFP+",
                                "tx_power_dbm": _parse_float_safe(parts[4]),
                                "rx_power_dbm": _parse_float_safe(parts[5]),
                                "temperature_c": _parse_float_safe(parts[1]),
                                "voltage_v": _parse_float_safe(parts[2]),
                            }
                        )
            except Exception as txt_exc:
                logger.warning("[%s] Arista show interfaces transceiver text fallback failed: %s", self.ip, txt_exc)
        return optics

    def get_running_config(self, conn) -> str:
        return self._safe_send_command(conn, "show running-config")

    @staticmethod
    def _eos_vlans_to_str(val) -> str:
        """Normalize Arista EOS JSON VLAN container (dict, list, or str) into a comma-separated string."""
        if not val:
            return ""
        if isinstance(val, str):
            return val.strip().lower()
        if isinstance(val, dict):
            inner = val.get("vlanIds")
            if inner is None:
                inner = val.get("vlans")
            if inner is None:
                return ""
            val = inner
        if isinstance(val, list):
            parts = [str(v).strip() for v in val if str(v).strip()]
            return ",".join(parts)
        return str(val).strip()

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}

        # 1. Operational trunk state (`show interfaces trunk | json` with text fallback)
        parsed_trunk_json = False
        try:
            raw_trunk = conn.send_command("show interfaces trunk | json")
            if isinstance(raw_trunk, str) and raw_trunk.strip().startswith("{"):
                data = json.loads(raw_trunk)
                if isinstance(data, dict) and ("trunks" in data or "interfaces" in data):
                    parsed_trunk_json = True
                    trunks = data.get("trunks") if "trunks" in data else data.get("interfaces")
                    if isinstance(trunks, dict):
                        for port, pdata in trunks.items():
                            if not isinstance(pdata, dict):
                                continue
                            status = str(pdata.get("status") or "trunking").lower()
                            oper_m = (
                                "trunk"
                                if ("trunk" in status or status == "up")
                                else ("down" if status == "down" else "access")
                            )
                            encap_raw = str(pdata.get("encapsulation") or "dot1q").lower()
                            encap = "isl" if "isl" in encap_raw else "dot1q"
                            rec = ops.setdefault(port, {})
                            rec["mode"] = "trunk" if oper_m == "trunk" else rec.get("mode", "trunk")
                            rec["oper_mode"] = oper_m
                            rec["encapsulation"] = encap
                            nat = pdata.get("nativeVlan", pdata.get("nativeVlanId"))
                            if nat is not None and str(nat).strip():
                                rec["native_vlan"] = str(nat).strip()
                            allowed = self._eos_vlans_to_str(pdata.get("allowedVlans") or pdata.get("allowed"))
                            if allowed:
                                rec["trunk_allowed_vlans"] = allowed
                            active = self._eos_vlans_to_str(
                                pdata.get("activeVlans") or pdata.get("forwardingVlans") or pdata.get("active")
                            )
                            if active:
                                rec["trunk_active_vlans"] = active
                            if "nativeVlanTagged" in pdata:
                                rec["native_vlan_tagged"] = bool(pdata["nativeVlanTagged"])
        except Exception as exc:
            logger.warning("[%s] Arista show interfaces trunk | json failed: %s", self.ip, exc)

        if not parsed_trunk_json:
            try:
                raw_txt = conn.send_command("show interfaces trunk")
                if (
                    isinstance(raw_txt, str)
                    and raw_txt.strip()
                    and not _is_eos_cli_error(raw_txt)
                    and "Invalid input" not in raw_txt
                    and "Unrecognized" not in raw_txt
                ):
                    section = ""
                    for line in raw_txt.splitlines():
                        stripped = line.strip()
                        if not stripped or set(stripped) <= {"-", "="}:
                            continue
                        low = stripped.lower()
                        if "mode" in low and "native vlan" in low:
                            section = "mode"
                            continue
                        if "vlans allowed on trunk" in low:
                            section = "allowed"
                            continue
                        if "vlans allowed and active" in low:
                            section = "active"
                            continue
                        if "vlans in spanning tree forwarding" in low:
                            section = "forwarding"
                            continue
                        if low.startswith("port "):
                            continue
                        if section == "mode":
                            m_eos = re.match(
                                r"^\s*(\S+)\s+(on|trunk|auto|desirable)\s+(?:(\S+)\s+)?(trunking|not-trunking)\s+(\d+)",
                                line,
                                re.I,
                            )
                            if m_eos:
                                p, _mode_t, _enc, status_t, nat = m_eos.groups()
                                rec = ops.setdefault(p, {})
                                is_trk = status_t.lower() == "trunking"
                                rec["mode"] = "trunk" if is_trk else "access"
                                rec["oper_mode"] = "trunk" if is_trk else "access"
                                rec["encapsulation"] = "dot1q"
                                rec["native_vlan"] = nat
                        elif section == "allowed":
                            m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                            if m:
                                p, vlans = m.group(1), m.group(2).lower()
                                rec = ops.setdefault(p, {})
                                rec["mode"] = "trunk"
                                rec.setdefault("oper_mode", "trunk")
                                rec["trunk_allowed_vlans"] = vlans
                        elif section == "active":
                            m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                            if m:
                                p, vlans = m.group(1), m.group(2).lower()
                                rec = ops.setdefault(p, {})
                                rec.setdefault("mode", "trunk")
                                rec.setdefault("oper_mode", "trunk")
                                rec["trunk_active_vlans"] = vlans
                        elif section == "forwarding":
                            m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                            if m:
                                p, vlans = m.group(1), m.group(2).lower()
                                rec = ops.setdefault(p, {})
                                if not rec.get("trunk_active_vlans"):
                                    rec["trunk_active_vlans"] = vlans
            except Exception as exc:
                logger.warning("[%s] Arista show interfaces trunk text fallback failed: %s", self.ip, exc)

        # 2. Operational Port-Channel / LAG state (`show port-channel | json` primary on EOS, `summary` fallback)
        parsed_pc_json = False
        for pc_json_cmd in ("show port-channel | json", "show port-channel summary | json"):
            try:
                raw_pc = conn.send_command(pc_json_cmd)
                if isinstance(raw_pc, str) and raw_pc.strip().startswith("{"):
                    data = json.loads(raw_pc)
                    if isinstance(data, dict) and "portChannels" in data:
                        parsed_pc_json = True
                        pcs = data.get("portChannels")
                        if isinstance(pcs, dict):
                            for pc_name, pc_info in pcs.items():
                                if not isinstance(pc_info, dict):
                                    continue
                                proto = str(pc_info.get("protocol") or "lacp").lower()
                                ports_obj = pc_info.get("ports", {})
                                if isinstance(ports_obj, dict):
                                    for m_port, m_info in ports_obj.items():
                                        lacp_m = (
                                            str(m_info.get("lacpMode") or "").lower()
                                            if isinstance(m_info, dict)
                                            else ""
                                        )
                                        if lacp_m not in ("active", "passive", "on"):
                                            lacp_m = "active" if "lacp" in proto else "on"
                                        rec = ops.setdefault(m_port, {})
                                        rec["lag_group"] = pc_name
                                        rec["lacp_mode"] = lacp_m
                                elif isinstance(ports_obj, list):
                                    for m_port in ports_obj:
                                        if isinstance(m_port, str) and m_port:
                                            rec = ops.setdefault(m_port, {})
                                            rec["lag_group"] = pc_name
                                            rec["lacp_mode"] = "active" if "lacp" in proto else "on"
                        break
            except Exception as exc:
                logger.warning("[%s] Arista %s failed: %s", self.ip, pc_json_cmd, exc)

        if not parsed_pc_json:
            for pc_txt_cmd in ("show port-channel", "show port-channel summary"):
                try:
                    raw_pc_txt = conn.send_command(pc_txt_cmd)
                    if (
                        not isinstance(raw_pc_txt, str)
                        or not raw_pc_txt.strip()
                        or _is_eos_cli_error(raw_pc_txt)
                        or "Invalid input" in raw_pc_txt
                    ):
                        continue
                    cur_pc = ""
                    matched_any = False
                    for line in raw_pc_txt.splitlines():
                        m_pc = re.match(
                            r"^\s*\d+\s+(Po\d+|Port-Channel\d+)\([^)]*\)\s+(LACP|STATIC|-)\s+(.+)$",
                            line,
                            re.I,
                        )
                        if m_pc:
                            pc_name, proto, members_str = m_pc.group(1), m_pc.group(2).lower(), m_pc.group(3)
                            for tok in members_str.split():
                                pname = re.sub(r"\([^)]*\)$", "", tok).strip()
                                if pname:
                                    rec = ops.setdefault(pname, {})
                                    rec["lag_group"] = pc_name
                                    rec["lacp_mode"] = "active" if proto == "lacp" else "on"
                                    matched_any = True
                            continue
                        m_hdr = re.match(r"^\s*(Port-Channel\d+)\s*:", line, re.I)
                        if m_hdr:
                            cur_pc = m_hdr.group(1)
                            continue
                        if cur_pc and re.search(r"(?:Active|Inactive)\s+Ports\s*:", line, re.I):
                            tail = line.split(":", 1)[1]
                            for tok in tail.split():
                                if re.match(r"^(?:Et|Ethernet)\S+", tok):
                                    rec = ops.setdefault(tok.strip(","), {})
                                    rec["lag_group"] = cur_pc
                                    rec["lacp_mode"] = "active"
                                    matched_any = True
                    if matched_any:
                        break
                except Exception as exc:
                    logger.warning("[%s] Arista %s text fallback failed: %s", self.ip, pc_txt_cmd, exc)

        return ops

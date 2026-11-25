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
Juniper Networks Driver: JunOS EX, QFX, MX, and SRX platforms.
Utilizes Junos native JSON structured outputs (`| display json`) with robust CLI fallbacks.
Official Documentation: https://www.juniper.net/documentation/product/us/en/junos-os/
"""

import json
import logging
import math
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver
from net_docu_crawler.topology_resolver import pick_clean_remote_port as _pick_clean_remote_port

logger = logging.getLogger(__name__)

_JUNOS_CLI_ERROR_RE = re.compile(
    r"(?:syntax\s+error|unknown\s+command|invalid\s+(?:command|input)|error:\s+command\s+is\s+not\s+valid)",
    re.IGNORECASE,
)


def _is_junos_cli_error(raw: str) -> bool:
    return bool(isinstance(raw, str) and raw and _JUNOS_CLI_ERROR_RE.search(raw))


def _junos_list(obj, key: str) -> list:
    """Safely return a non-None list under `key` from a Junos JSON dict (handles list, dict, None, [])."""
    if not isinstance(obj, dict):
        return []
    val = obj.get(key)
    if isinstance(val, list):
        return [item for item in val if item is not None]
    if isinstance(val, dict):
        return [val]
    return []


def _junos_first(obj, key: str) -> dict:
    """Safely return the first dict element under `key` from a Junos JSON dict, or `{}`."""
    for item in _junos_list(obj, key):
        if isinstance(item, dict):
            return item
    return {}


def _junos_data(obj, key: str, default: str = "") -> str:
    """Safely extract stripped text from a Junos JSON leaf (`[{"data": ...}]`, `{"data": ...}`, or scalar)."""
    if not isinstance(obj, dict):
        return default
    val = obj.get(key)
    if isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                raw = item.get("data")
                if raw is not None:
                    text = str(raw).strip()
                    if text:
                        return text
            elif item is not None:
                text = str(item).strip()
                if text:
                    return text
        return default
    if isinstance(val, dict):
        raw = val.get("data")
        if raw is not None:
            text = str(raw).strip()
            if text:
                return text
        return default
    if val is not None:
        text = str(val).strip()
        if text:
            return text
    return default


def _junos_attr(obj, key: str, attr_name: str, default: str = "") -> str:
    """Safely extract an XML/JSON attribute (e.g., `junos:celsius`) from a Junos JSON leaf."""
    first = _junos_first(obj, key)
    attrs = first.get("attributes")
    if isinstance(attrs, dict):
        val = attrs.get(attr_name)
        if val is not None:
            text = str(val).strip()
            if text:
                return text
    return default


def _junos_rpc_error(data) -> str:
    """Return error text if Junos JSON payload carries an RPC/XNM error, else empty string."""
    if not isinstance(data, dict):
        return "non-object JSON payload"
    for err_key in ("rpc-error", "xnm:error"):
        err_list = _junos_list(data, err_key)
        if err_list:
            first_err = err_list[0] if isinstance(err_list[0], dict) else {}
            msg = _junos_data(first_err, "error-message") or _junos_data(first_err, "message")
            return msg or err_key
    return ""


def _parse_float_safe(val) -> float | None:
    """Parse numeric string/float safely; return None for N/A, '- Inf', non-finite, or empty values."""
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


def _classify_junos_neighbor_type(remote_sys: str, remote_caps: str, mac_vendor: str, remote_dev: str = "") -> str:
    """Classify a Junos LLDP neighbor without falsely labeling APs, phones, cameras, or hosts as switches."""
    sys_low = (remote_sys or "").lower()
    caps_low = (remote_caps or "").lower()
    vend_low = (mac_vendor or "").lower() if mac_vendor and mac_vendor != "Unknown" else ""
    dev_low = (remote_dev or "").lower()
    blob = f"{sys_low} {vend_low} {dev_low}"

    if (
        "phone" in caps_low
        or "telephone" in caps_low
        or re.search(
            r"\b(?:digium|yealink|polycom|mitel|avaya|grandstream|snom|sangoma|voip|ip phone|telephone)\b",
            blob,
        )
        or re.match(r"^(?:d40|d60|d62|d65|d70|p315)-", dev_low)
    ):
        return "phone"

    if re.search(r"\b(?:axis|verkada|hikvision|valcom|hanwha|camera)\b", blob):
        return "camera"

    if (
        re.search(r"(?:\bap\b|access point|aruba|unifi|instant|\bwlan\b|ruckus|meraki)", sys_low)
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
    ) or re.match(r"^(?:desktop|laptop)-", dev_low):
        return "endpoint"

    return "switch"


# Internal Junos control-plane, PFE fabric, and tunnel pseudo-devices excluded from physical port counts
JUNOS_INTERNAL_INTERFACES = (
    "bme",
    "cbp",
    "dsc",
    "em",
    "esi",
    "fti",
    "gre",
    "ipip",
    "jsrv",
    "lo0",
    "lsi",
    "mtun",
    "pfe-",
    "pfh-",
    "pimd",
    "pime",
    "pip",
    "tap",
    "vme",
    "vtep",
)


def _is_junos_internal_interface(name: str) -> bool:
    base = name.split(".")[0].lower()
    return base.startswith(JUNOS_INTERNAL_INTERFACES)


class JuniperDriver(BaseDriver):
    vendor_name = "Juniper Networks"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "set cli screen-length 0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_chassis_hw_json: str | None = None
        self._cached_chassis_hw_txt: str | None = None

    def connect(self):
        device = self._build_netmiko_params("juniper_junos", global_delay_factor=2, include_auth_timeout=True)
        return self.connect_netmiko(device)

    def _fetch_chassis_hardware_json(self, conn) -> str:
        """Fetch and cache `show chassis hardware | display json` across version and optics collection."""
        if self._cached_chassis_hw_json is not None:
            return self._cached_chassis_hw_json
        raw_hw = conn.send_command("show chassis hardware | display json")
        if isinstance(raw_hw, str) and raw_hw.strip().startswith("{"):
            self._cached_chassis_hw_json = raw_hw
        return raw_hw

    def _fetch_chassis_hardware_text(self, conn) -> str:
        """Fetch and cache `show chassis hardware` text across version and optics collection."""
        if self._cached_chassis_hw_txt is not None:
            return self._cached_chassis_hw_txt
        raw_hw = conn.send_command("show chassis hardware")
        if isinstance(raw_hw, str) and raw_hw.strip() and not _is_junos_cli_error(raw_hw):
            self._cached_chassis_hw_txt = raw_hw
        return raw_hw

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Juniper Device",
            "serial": "Unknown",
            "firmware": "JunOS",
            "os_type": "juniper_junos",
            "device_persona": self.device_persona,
        }

        # Try structured JSON first
        try:
            raw = conn.send_command("show version | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            if "multi-routing-engine-results" in data:
                mre = _junos_first(data, "multi-routing-engine-results")
                mre_item = _junos_first(mre, "multi-routing-engine-item")
                sw_info = _junos_first(mre_item, "software-information")
            else:
                sw_info = _junos_first(data, "software-information")

            info["hostname"] = _junos_data(sw_info, "host-name")
            info["firmware"] = _junos_data(sw_info, "junos-version", info["firmware"])
            info["model"] = _junos_data(sw_info, "product-model", info["model"])
        except Exception as exc:
            logger.warning("[%s] Junos show version | display json failed, falling back to text: %s", self.ip, exc)
            try:
                raw = conn.send_command("show version")
                m_host = re.search(r"Hostname:\s+(\S+)", raw or "")
                if m_host:
                    info["hostname"] = m_host.group(1)
                m_model = re.search(r"Model:\s+(\S+)", raw or "")
                if m_model:
                    info["model"] = m_model.group(1)
                m_ver = re.search(r"Junos:\s+(\S+)", raw or "")
                if not m_ver:
                    m_ver = re.search(
                        r"JUNOS\s+(?:Base OS boot|Software Release)\s+\[([^\]]+)\]", raw or "", re.IGNORECASE
                    )
                if m_ver:
                    info["firmware"] = m_ver.group(1)
            except Exception as txt_exc:
                logger.warning("[%s] Junos show version text fallback failed: %s", self.ip, txt_exc)

        model_low = info["model"].lower()
        if "srx" in model_low:
            info["device_persona"] = "firewall"
            info["device_type"] = "firewall"
        elif any(tag in model_low for tag in ("mx", "ptx", "acx")):
            info["device_persona"] = "router"
            info["device_type"] = "router"

        # Retrieve chassis serial number
        try:
            raw_hw = self._fetch_chassis_hardware_json(conn)
            hw_data = json.loads(raw_hw)
            rpc_err = _junos_rpc_error(hw_data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            chassis = _junos_first(_junos_first(hw_data, "chassis-inventory"), "chassis")
            sn = _junos_data(chassis, "serial-number")
            desc = _junos_data(chassis, "description")
            if sn:
                info["serial"] = sn
            if desc and info["model"] == "Juniper Device":
                info["model"] = desc
        except Exception as exc:
            logger.warning(
                "[%s] Junos show chassis hardware | display json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_hw = self._fetch_chassis_hardware_text(conn)
                m_sn = re.search(r"Chassis\s+(\S+)", raw_hw or "")
                if m_sn:
                    info["serial"] = m_sn.group(1)
            except Exception as txt_exc:
                logger.warning("[%s] Junos show chassis hardware text fallback failed: %s", self.ip, txt_exc)

        # Retrieve base chassis MAC so remote routed crawls don't depend on local ARP
        try:
            raw_mac = conn.send_command("show chassis mac-addresses")
            m_mac = re.search(r"(?:Base|Public base)\s+address\s+([0-9a-fA-F:]{17})", raw_mac or "", re.IGNORECASE)
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()
        except Exception as exc:
            logger.warning("[%s] Junos show chassis mac-addresses failed: %s", self.ip, exc)

        if not info["hostname"]:
            prompt = self._safe_find_prompt(conn)
            if prompt:
                info["hostname"] = prompt.split("@")[-1].replace(">", "").replace("#", "").strip()

        self._model = info.get("model", "")
        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}

        try:
            raw = conn.send_command("show interfaces terse | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            int_list = _junos_list(_junos_first(data, "interface-information"), "physical-interface")
            for intf in int_list:
                if not isinstance(intf, dict):
                    continue
                name = _junos_data(intf, "name")
                if not name or _is_junos_internal_interface(name):
                    continue

                admin_status = _junos_data(intf, "admin-status", "down").lower()
                oper_status = _junos_data(intf, "oper-status", "down").lower()

                # Include physical switch/router/mgmt interfaces only (exclude parent pseudo-interface `irb`)
                if re.match(r"^(?:ge-|mge-|xe-|et-|fe-|ae\d|me0|fxp0|reth\d)", name):
                    default_speed = (
                        "10Gb/s"
                        if name.startswith("xe-")
                        else (
                            "100Gb/s"
                            if name.startswith("et-")
                            else (
                                "2.5Gb/s"
                                if name.startswith("mge-")
                                else ("100Mb/s" if name.startswith("fe-") else "1Gb/s")
                            )
                        )
                    )
                    interfaces_detail[name] = {
                        "status": oper_status,
                        "protocol": oper_status,
                        "admin_status": admin_status,
                        "description": "",
                        "mac_address": "",
                        "speed": default_speed,
                        "duplex": "Full",
                    }

                # Logical interfaces (SVIs / irb.0, routed units, IP addresses)
                for log_int in _junos_list(intf, "logical-interface"):
                    if not isinstance(log_int, dict):
                        continue
                    log_name = _junos_data(log_int, "name")
                    if log_name and _is_junos_internal_interface(log_name):
                        continue
                    log_oper = _junos_data(log_int, "oper-status", oper_status).lower()
                    for fam in _junos_list(log_int, "address-family"):
                        if not isinstance(fam, dict):
                            continue
                        fam_name = _junos_data(fam, "address-family-name")
                        if fam_name and fam_name != "inet":
                            continue
                        for addr in _junos_list(fam, "interface-address"):
                            if not isinstance(addr, dict):
                                continue
                            ip_str = _junos_data(addr, "ifa-local")
                            ip_dest = _junos_data(addr, "ifa-destination")
                            if not ip_str or ip_str.startswith(("127.", "128.0.")):
                                continue
                            # Attach prefix length from ifa-destination (e.g. 192.168.1.0/24 -> /24) if missing
                            if "/" not in ip_str and "/" in ip_dest:
                                prefix_len = ip_dest.split("/", 1)[1]
                                ip_str = f"{ip_str}/{prefix_len}"
                            l3_interfaces.append(
                                {
                                    "interface": log_name or name,
                                    "ip_address": ip_str,
                                    "status": log_oper,
                                    "protocol": log_oper,
                                }
                            )
        except Exception as exc:
            logger.warning(
                "[%s] Junos show interfaces terse | display json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw = conn.send_command("show interfaces terse")
                for line in (raw or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[0]
                        if _is_junos_internal_interface(name):
                            continue
                        admin = parts[1].lower()
                        oper = parts[2].lower()
                        if "." not in name and re.match(r"^(?:ge-|mge-|xe-|et-|fe-|ae\d|me0|fxp0|reth\d)", name):
                            interfaces_detail[name] = {
                                "status": oper,
                                "protocol": oper,
                                "admin_status": admin,
                                "description": "",
                                "mac_address": "",
                                "speed": "1Gb/s",
                                "duplex": "Full",
                            }
                        elif "." in name and len(parts) >= 5 and parts[3] == "inet":
                            ip_val = parts[-1]
                            if re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", ip_val) and not ip_val.startswith(
                                ("127.", "128.0.")
                            ):
                                l3_interfaces.append(
                                    {
                                        "interface": name,
                                        "ip_address": ip_val,
                                        "status": oper,
                                        "protocol": oper,
                                    }
                                )
            except Exception as txt_exc:
                logger.warning("[%s] Junos show interfaces terse text fallback failed: %s", self.ip, txt_exc)

        # Enrich physical interfaces with description, MAC, speed, duplex, MTU, and error counters (`show interfaces`)
        try:
            err_raw = conn.send_command("show interfaces")
            cur_if = ""
            in_logical = False
            for line in (err_raw or "").splitlines():
                m_if = re.match(r"^\s*Physical interface:\s*([A-Za-z0-9/\._-]+)", line)
                if m_if:
                    cur_if = m_if.group(1).rstrip(",")
                    in_logical = False
                    continue
                if re.match(r"^\s*Logical interface\b", line):
                    in_logical = True
                    continue
                if cur_if and cur_if in interfaces_detail and not in_logical:
                    rec = interfaces_detail[cur_if]
                    m_desc = re.match(r"^\s*Description:\s*(.+)$", line)
                    if m_desc and not rec.get("description"):
                        rec["description"] = m_desc.group(1).strip()
                    m_mac = re.search(r"(?:Current|Hardware)\s+address:\s*([0-9a-fA-F:]{17})", line, re.IGNORECASE)
                    if m_mac and not rec.get("mac_address"):
                        rec["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                    m_mtu = re.search(r"\bMTU:\s*(\d+)", line)
                    if m_mtu:
                        rec["mtu"] = int(m_mtu.group(1))
                    m_spd = re.search(r"\bSpeed:\s*([^\s,]+)", line)
                    if m_spd and m_spd.group(1).lower() not in ("unspecified", "auto", "unlimited"):
                        rec["speed"] = m_spd.group(1)
                    m_dup = re.search(r"\bLink-mode:\s*([^\s,]+)", line)
                    if m_dup:
                        lm = m_dup.group(1).lower()
                        if "full" in lm:
                            rec["duplex"] = "Full"
                        elif "half" in lm:
                            rec["duplex"] = "Half"
                    m_in = re.search(r"Input errors:\s*(\d+)", line, re.IGNORECASE)
                    m_out = re.search(r"Output errors:\s*(\d+)", line, re.IGNORECASE)
                    if m_in:
                        rec["input_errors"] = int(m_in.group(1))
                    if m_out:
                        rec["output_errors"] = int(m_out.group(1))
        except Exception as exc:
            logger.warning("[%s] Junos show interfaces enrichment failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("show lldp neighbors detail | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            neigh_list = _junos_list(_junos_first(data, "lldp-neighbors-information"), "lldp-neighbor-information")
            for n in neigh_list:
                if not isinstance(n, dict):
                    continue
                # Prefer physical interface name (e.g. ge-0/0/3.0 -> ge-0/0/3) over numeric SNMP port index (515)
                local_intf = (
                    _junos_data(n, "lldp-local-interface")
                    or _junos_data(n, "lldp-local-parent-interface-name")
                    or _junos_data(n, "lldp-local-port-id")
                )
                local_port = re.sub(r"\.0$", "", local_intf.strip())
                remote_dev = _junos_data(n, "lldp-remote-system-name")
                if not remote_dev:
                    remote_dev = _junos_data(n, "lldp-remote-chassis-id", "Unknown")
                raw_port_id = _junos_data(n, "lldp-remote-port-id")
                raw_port_info = _junos_data(n, "lldp-remote-port-info")
                raw_port_desc = _junos_data(n, "lldp-remote-port-description")
                remote_port, remote_port_desc = _pick_clean_remote_port(raw_port_id, raw_port_info, raw_port_desc)
                remote_ip = _junos_data(n, "lldp-remote-management-address")
                remote_sys = _junos_data(n, "lldp-remote-system-description")
                remote_caps = _junos_data(n, "lldp-remote-system-capabilities-enabled") or _junos_data(
                    n, "lldp-remote-system-capabilities-supported"
                )
                remote_mac = _junos_data(n, "lldp-remote-chassis-id")

                norm_mac = oui_lookup.normalize_mac(remote_mac or raw_port_id or remote_port)
                mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                dev_type = _classify_junos_neighbor_type(remote_sys, remote_caps, mac_vendor, remote_dev)

                plat_short = remote_sys[:60].strip()
                if not plat_short and mac_vendor != "Unknown":
                    plat_short = f"{mac_vendor} AP" if dev_type == "ap" else mac_vendor

                neighbors.append(
                    {
                        "local_port": local_port,
                        "remote_device": remote_dev,
                        "remote_port": remote_port or "Unknown",
                        "remote_port_description": remote_port_desc,
                        "remote_ip": remote_ip,
                        "remote_mac": remote_mac,
                        "platform": plat_short,
                        "remote_platform": plat_short,
                        "device_type": dev_type,
                    }
                )
        except Exception as exc:
            logger.warning(
                "[%s] Junos show lldp neighbors detail | display json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw = conn.send_command("show lldp neighbors detail")
                blocks = (raw or "").split("Local Interface:")
                for b in blocks[1:]:
                    m_port = re.match(r"\s*(\S+)", b)
                    m_sys = re.search(r"System name\s*:\s*(\S+)", b)
                    m_chassis = re.search(r"Chassis\s+(?:id|ID)\s*:\s*(\S+)", b)
                    m_ip = re.search(r"Management address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", b)
                    m_rem_port = re.search(r"Port id\s*:\s*(.+)", b, re.IGNORECASE)
                    m_rem_info = re.search(r"Port info\s*:\s*(.+)", b, re.IGNORECASE)
                    m_rem_desc = re.search(r"Port description\s*:\s*(.+)", b, re.IGNORECASE)
                    m_desc = re.search(r"System description\s*:\s*(.+)", b)
                    m_caps = re.search(r"System capabilities\s*:\s*(.+)", b)
                    if m_port and (m_sys or m_chassis):
                        local_port = re.sub(r"\.0$", "", m_port.group(1).rstrip(","))
                        remote_mac = m_chassis.group(1).strip() if m_chassis else ""
                        remote_dev = m_sys.group(1) if m_sys else remote_mac
                        norm_mac = oui_lookup.normalize_mac(remote_mac) if remote_mac else ""
                        mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                        plat_raw = m_desc.group(1).strip()[:60] if m_desc else ""
                        caps_raw = m_caps.group(1) if m_caps else ""
                        dev_type = _classify_junos_neighbor_type(plat_raw, caps_raw, mac_vendor, remote_dev)
                        plat = plat_raw
                        if not plat and mac_vendor != "Unknown":
                            plat = f"{mac_vendor} AP" if dev_type == "ap" else mac_vendor
                        elif not plat:
                            plat = "JunOS-Discovered"

                        remote_port, remote_port_desc = _pick_clean_remote_port(
                            m_rem_port.group(1).strip() if m_rem_port else "",
                            m_rem_info.group(1).strip() if m_rem_info else "",
                            m_rem_desc.group(1).strip() if m_rem_desc else "",
                        )
                        neighbors.append(
                            {
                                "local_port": local_port,
                                "remote_device": remote_dev,
                                "remote_port": remote_port or "Unknown",
                                "remote_port_description": remote_port_desc,
                                "remote_ip": m_ip.group(1) if m_ip else "",
                                "remote_mac": remote_mac,
                                "platform": plat,
                                "remote_platform": plat,
                                "device_type": dev_type,
                            }
                        )
            except Exception as txt_exc:
                logger.warning("[%s] Junos show lldp neighbors detail text fallback failed: %s", self.ip, txt_exc)

        # Fallback for Junos 17.x/18.x ELS platforms where `show lldp neighbors detail` is unsupported
        if not neighbors:
            try:
                raw_sum = conn.send_command("show lldp neighbors | display json")
                data_sum = json.loads(raw_sum)
                rpc_err = _junos_rpc_error(data_sum)
                if rpc_err:
                    raise ValueError(f"Junos RPC error: {rpc_err}")
                neigh_list = _junos_list(
                    _junos_first(data_sum, "lldp-neighbors-information"), "lldp-neighbor-information"
                )
                for n in neigh_list:
                    if not isinstance(n, dict):
                        continue
                    local_intf = _junos_data(n, "lldp-local-interface") or _junos_data(n, "lldp-local-port-id")
                    local_port = re.sub(r"\.0$", "", local_intf.strip())
                    remote_mac = _junos_data(n, "lldp-remote-chassis-id")
                    remote_dev = _junos_data(n, "lldp-remote-system-name") or remote_mac or "Unknown"
                    raw_port_id = _junos_data(n, "lldp-remote-port-id")
                    raw_port_info = _junos_data(n, "lldp-remote-port-info")
                    raw_port_desc = _junos_data(n, "lldp-remote-port-description")
                    remote_port, remote_port_desc = _pick_clean_remote_port(raw_port_id, raw_port_info, raw_port_desc)
                    norm_mac = oui_lookup.normalize_mac(remote_mac or raw_port_id or remote_port)
                    mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                    dev_type = _classify_junos_neighbor_type("", "", mac_vendor, remote_dev)
                    plat = (
                        f"{mac_vendor} AP"
                        if (dev_type == "ap" and mac_vendor != "Unknown")
                        else (mac_vendor if mac_vendor != "Unknown" else "JunOS-Discovered")
                    )
                    if local_port:
                        neighbors.append(
                            {
                                "local_port": local_port,
                                "remote_device": remote_dev,
                                "remote_port": remote_port or "Unknown",
                                "remote_port_description": remote_port_desc,
                                "remote_ip": "",
                                "remote_mac": remote_mac,
                                "platform": plat,
                                "remote_platform": plat,
                                "device_type": dev_type,
                            }
                        )
            except Exception as exc:
                logger.warning(
                    "[%s] Junos show lldp neighbors | display json failed, falling back to text: %s", self.ip, exc
                )
                try:
                    raw_sum_txt = conn.send_command("show lldp neighbors")
                    idx_pinfo = -1
                    idx_sys = -1
                    for line in (raw_sum_txt or "").splitlines():
                        if "Port info" in line and "System Name" in line:
                            idx_pinfo = line.find("Port info")
                            idx_sys = line.find("System Name")
                            continue
                        parts = line.split()
                        if len(parts) >= 5 and re.match(r"^(?:ge-|mge-|xe-|et-|fe-|ae\d)", parts[0]):
                            local_port = re.sub(r"\.0$", "", parts[0])
                            remote_mac = parts[2]
                            if idx_pinfo != -1 and idx_sys != -1 and len(line) > idx_sys:
                                raw_pinfo = line[idx_pinfo:idx_sys].strip()
                                remote_dev = line[idx_sys:].strip() or parts[-1]
                            else:
                                raw_pinfo = parts[3]
                                remote_dev = parts[4]
                            remote_port, remote_port_desc = _pick_clean_remote_port(raw_pinfo, "", "")
                            norm_mac = oui_lookup.normalize_mac(remote_mac)
                            mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                            dev_type = _classify_junos_neighbor_type("", "", mac_vendor, remote_dev)
                            plat = (
                                f"{mac_vendor} AP"
                                if (dev_type == "ap" and mac_vendor != "Unknown")
                                else (mac_vendor if mac_vendor != "Unknown" else "JunOS-Discovered")
                            )
                            neighbors.append(
                                {
                                    "local_port": local_port,
                                    "remote_device": remote_dev,
                                    "remote_port": remote_port or "Unknown",
                                    "remote_port_description": remote_port_desc,
                                    "remote_ip": "",
                                    "remote_mac": remote_mac,
                                    "platform": plat,
                                    "remote_platform": plat,
                                    "device_type": dev_type,
                                }
                            )
                except Exception as txt_exc:
                    logger.warning("[%s] Junos show lldp neighbors text fallback failed: %s", self.ip, txt_exc)

        return neighbors

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        if neighbors:
            return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}
        cfg_low = (raw_config or "").lower()
        if re.search(r"\blldp\s*\{[^}]*\bdisable\s*;", cfg_low, re.DOTALL):
            return {
                "lldp": "disabled",
                "cdp": "unsupported",
                "mndp": "unsupported",
                "notes": "LLDP is explicitly disabled under [protocols lldp] in Junos config.",
            }
        if re.search(r"\blldp\s*\{", cfg_low) or "set protocols lldp" in cfg_low:
            return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}
        if raw_config:
            return {
                "lldp": "disabled",
                "cdp": "unsupported",
                "mndp": "unsupported",
                "notes": "No [protocols lldp] stanza found in Junos configuration.",
            }
        return {"lldp": "unknown", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}

    def get_stp(self, conn) -> dict:
        stp = {
            "enabled": False,
            "is_root": False,
            "protocol": "Unknown",
            "root_bridge": "",
            "bridge_id": "",
            "bridge_priority": "",
            "root_cost": "",
            "root_port": "",
            "vlans": {},
        }
        try:
            raw = conn.send_command("show spanning-tree bridge | display json")
            if isinstance(raw, str) and raw.strip().startswith("{"):
                data = json.loads(raw)
                rpc_err = _junos_rpc_error(data)
                if rpc_err:
                    raise ValueError(f"Junos RPC error: {rpc_err}")
                # Junos ELS schema: {"stp-bridge": [{"protocol": [...], "cist-bridge-parameters": [...]}]}
                blk = _junos_first(data, "stp-bridge")
                if blk:
                    stp["enabled"] = True
                    stp["protocol"] = _junos_data(blk, "protocol", "RSTP")
                    cist = _junos_first(blk, "cist-bridge-parameters")
                    rb = _junos_first(cist, "root-bridge")
                    rb_prio = _junos_data(rb, "bridge-priority")
                    rb_mac = _junos_data(rb, "bridge-mac")
                    if rb_mac:
                        stp["root_bridge"] = f"{rb_prio}.{rb_mac}".strip(".") if rb_prio else rb_mac
                    stp["root_cost"] = _junos_data(cist, "root-cost")
                    stp["root_port"] = _junos_data(cist, "root-port")
                    tb = _junos_first(cist, "this-bridge")
                    tb_prio = _junos_data(tb, "bridge-priority")
                    tb_mac = _junos_data(tb, "bridge-mac")
                    if tb_prio:
                        stp["bridge_priority"] = tb_prio
                    if tb_mac:
                        stp["bridge_id"] = f"{tb_prio}.{tb_mac}".strip(".") if tb_prio else tb_mac
                    if rb_mac and tb_mac and rb_mac.lower() == tb_mac.lower():
                        stp["is_root"] = True
                    return stp

                stp_info = _junos_first(data, "stp-bridge-parameters-information")
                if stp_info:
                    stp["enabled"] = True
                    stp["protocol"] = _junos_data(stp_info, "enabled-protocol") or _junos_data(
                        stp_info, "protocol", "RSTP"
                    )
                    root_id = _junos_data(stp_info, "root-id")
                    bridge_id = _junos_data(stp_info, "bridge-id")
                    if root_id:
                        stp["root_bridge"] = root_id
                    if bridge_id:
                        stp["bridge_id"] = bridge_id
                        if "." in bridge_id:
                            stp["bridge_priority"] = bridge_id.split(".", 1)[0]
                    stp["root_cost"] = _junos_data(stp_info, "root-cost")
                    stp["root_port"] = _junos_data(stp_info, "root-port")
                    raw_str = json.dumps(stp_info).lower()
                    if "this bridge is the root" in raw_str or (
                        root_id and bridge_id and root_id.lower() == bridge_id.lower()
                    ):
                        stp["is_root"] = True
                    return stp
        except Exception as exc:
            logger.warning("[%s] Junos show spanning-tree bridge | display json failed: %s", self.ip, exc)

        try:
            raw_txt = conn.send_command("show spanning-tree bridge")
            low = (raw_txt or "").lower()
            if "stp bridge parameters" in low or "enabled protocol" in low:
                stp["enabled"] = True
                m_proto = re.search(r"Enabled protocol\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                if m_proto:
                    stp["protocol"] = m_proto.group(1).strip()
                m_root = re.search(r"Root ID\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                m_bridge = re.search(r"Bridge ID\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                m_cost = re.search(r"Root cost\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                m_port = re.search(r"Root port\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                if m_root:
                    stp["root_bridge"] = m_root.group(1).strip()
                if m_bridge:
                    stp["bridge_id"] = m_bridge.group(1).strip()
                    if "." in stp["bridge_id"]:
                        stp["bridge_priority"] = stp["bridge_id"].split(".", 1)[0]
                if m_cost:
                    stp["root_cost"] = m_cost.group(1).strip()
                if m_port:
                    stp["root_port"] = m_port.group(1).strip()
                if "this bridge is the root" in low or (m_root and m_bridge and m_root.group(1) == m_bridge.group(1)):
                    stp["is_root"] = True
        except Exception as exc:
            logger.warning("[%s] Junos show spanning-tree bridge text fallback failed: %s", self.ip, exc)
        return stp

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show route | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            tables = _junos_list(_junos_first(data, "route-information"), "route-table")
            for t in tables:
                if not isinstance(t, dict):
                    continue
                t_name = _junos_data(t, "table-name", "inet.0")
                if not t_name.endswith("inet.0"):
                    continue
                for r in _junos_list(t, "rt"):
                    if not isinstance(r, dict):
                        continue
                    dest = _junos_data(r, "rt-destination")
                    if not dest or dest.startswith("128.0.") or dest == "224.0.0.5/32":
                        continue
                    rt_entries = [e for e in _junos_list(r, "rt-entry") if isinstance(e, dict)]
                    if not rt_entries:
                        continue
                    active_entries = [e for e in rt_entries if _junos_data(e, "active-tag") == "*"]
                    entry = active_entries[0] if active_entries else rt_entries[0]
                    proto = _junos_data(entry, "protocol-name")
                    nh_list = [nh for nh in _junos_list(entry, "nh") if isinstance(nh, dict)]
                    if not nh_list:
                        nh_type = _junos_data(entry, "nh-type")
                        routes.append(
                            {
                                "subnet": dest,
                                "protocol": proto,
                                "next_hop": nh_type or "Directly Connected",
                                "interface": "",
                            }
                        )
                        continue
                    for nh in nh_list:
                        via = _junos_data(nh, "to", "Directly Connected")
                        nh_if = _junos_data(nh, "via")
                        routes.append({"subnet": dest, "protocol": proto, "next_hop": via, "interface": nh_if})
        except Exception as exc:
            logger.warning("[%s] Junos show route | display json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_txt = conn.send_command("show route table inet.0")
                cur_dest = ""
                cur_proto = ""
                for line in (raw_txt or "").splitlines():
                    stripped = line.strip()
                    if not stripped:
                        cur_dest = ""
                        continue
                    m_dest = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+\*?\[([A-Za-z0-9_-]+)/\d+\]", stripped)
                    if m_dest:
                        cur_dest = m_dest.group(1)
                        cur_proto = m_dest.group(2)
                        if cur_dest.startswith("128.0.") or cur_dest == "224.0.0.5/32":
                            cur_dest = ""
                        continue
                    if cur_dest:
                        m_nh = re.search(r"(?:to\s+(\d+\.\d+\.\d+\.\d+)\s+)?via\s+(\S+)", line)
                        if m_nh:
                            routes.append(
                                {
                                    "subnet": cur_dest,
                                    "protocol": cur_proto,
                                    "next_hop": m_nh.group(1) or "Directly Connected",
                                    "interface": m_nh.group(2),
                                }
                            )
            except Exception as txt_exc:
                logger.warning("[%s] Junos show route table inet.0 text fallback failed: %s", self.ip, txt_exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("show arp no-resolve | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            entries = _junos_list(_junos_first(data, "arp-table-information"), "arp-table-entry")
            for e in entries:
                if not isinstance(e, dict):
                    continue
                ip_addr = _junos_data(e, "ip-address")
                mac_addr = _junos_data(e, "mac-address")
                intf = _junos_data(e, "interface-name")
                if ip_addr and mac_addr and not ip_addr.startswith("128.0."):
                    norm_mac = oui_lookup.normalize_mac(mac_addr).lower()
                    arp_entries.append(
                        {
                            "ip": ip_addr,
                            "mac": norm_mac,
                            "interface": intf,
                            "age": "1",
                            "type": "ARPA",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.warning(
                "[%s] Junos show arp no-resolve | display json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_txt = conn.send_command("show arp no-resolve")
                for line in (raw_txt or "").splitlines():
                    parts = line.split()
                    if (
                        len(parts) >= 4
                        and re.match(r"^[0-9a-fA-F:]{17}$", parts[0])
                        and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1])
                    ):
                        ip_addr = parts[1]
                        if ip_addr.startswith("128.0."):
                            continue
                        norm_mac = oui_lookup.normalize_mac(parts[0]).lower()
                        arp_entries.append(
                            {
                                "ip": ip_addr,
                                "mac": norm_mac,
                                "interface": parts[-1],
                                "age": "1",
                                "type": "ARPA",
                                "vendor": oui_lookup.lookup_oui(norm_mac),
                            }
                        )
            except Exception as txt_exc:
                logger.warning("[%s] Junos show arp no-resolve text fallback failed: %s", self.ip, txt_exc)
        return arp_entries

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        model_l = getattr(self, "_model", "").lower()
        if model_l.startswith(("ex4600", "ex4650", "ex9200", "qfx", "ex4500", "ex4550", "mx", "srx", "ptx", "acx")):
            poe["poe_supported"] = False
            return poe
        try:
            raw = conn.send_command("show poe controller | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            ctrl_entries = _junos_list(_junos_first(data, "poe-controller-information"), "poe-controller-entry")
            if ctrl_entries:
                for c in ctrl_entries:
                    if not isinstance(c, dict):
                        continue
                    max_p = _parse_float_safe(_junos_data(c, "maximum-power", "0").replace("W", "").strip()) or 0.0
                    con_p = _parse_float_safe(_junos_data(c, "consumed-power", "0").replace("W", "").strip()) or 0.0
                    rem_p = _parse_float_safe(_junos_data(c, "available-power", "0").replace("W", "").strip()) or 0.0
                    poe["total_power_watts"] += max_p
                    poe["used_power_watts"] += con_p
                    poe["available_power_watts"] += rem_p
            else:
                # Junos 18.x+ EX schema: {"poe": [{"controller-information": [...]}]}
                ctrl_info_list = _junos_list(_junos_first(data, "poe"), "controller-information")
                for c in ctrl_info_list:
                    if not isinstance(c, dict):
                        continue
                    tot_v = (
                        _parse_float_safe(_junos_data(c, "controller-maxpower", "0").replace("W", "").strip()) or 0.0
                    )
                    used_v = _parse_float_safe(_junos_data(c, "controller-power", "0").replace("W", "").strip()) or 0.0
                    rem_raw = _junos_data(c, "controller-available-power").replace("W", "").strip()
                    rem_parsed = _parse_float_safe(rem_raw)
                    avail_v = rem_parsed if rem_parsed is not None else max(0.0, round(tot_v - used_v, 2))
                    poe["total_power_watts"] += tot_v
                    poe["used_power_watts"] += used_v
                    poe["available_power_watts"] += avail_v
        except Exception as exc:
            logger.warning(
                "[%s] Junos show poe controller | display json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_txt = conn.send_command("show poe controller")
                if _is_junos_cli_error(raw_txt):
                    poe["poe_supported"] = False
                    return poe
                m_max = re.search(r"Maximum power\s*:\s*([\d\.]+)W?", raw_txt or "", re.IGNORECASE)
                m_con = re.search(r"Power consumed\s*:\s*([\d\.]+)W?", raw_txt or "", re.IGNORECASE)
                m_avail = re.search(r"Available power\s*:\s*([\d\.]+)W?", raw_txt or "", re.IGNORECASE)
                if not m_max:
                    m_row = re.search(r"^\s*\d+\s+([\d\.]+)W?\s+([\d\.]+)W?\s+([\d\.]+)W?", raw_txt or "", re.MULTILINE)
                    if m_row:
                        poe["total_power_watts"] = float(m_row.group(1))
                        poe["used_power_watts"] = float(m_row.group(2))
                        poe["available_power_watts"] = float(m_row.group(3))
                else:
                    if m_max:
                        poe["total_power_watts"] = float(m_max.group(1))
                    if m_con:
                        poe["used_power_watts"] = float(m_con.group(1))
                    if m_avail:
                        poe["available_power_watts"] = float(m_avail.group(1))
            except Exception as txt_exc:
                logger.warning("[%s] Junos show poe controller text fallback failed: %s", self.ip, txt_exc)

        try:
            raw_if = conn.send_command("show poe interface | display json")
            data_if = json.loads(raw_if)
            rpc_err = _junos_rpc_error(data_if)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            entries = _junos_list(_junos_first(data_if, "poe-interface-information"), "poe-interface-entry")
            if entries:
                for e in entries:
                    if not isinstance(e, dict):
                        continue
                    if_name = _junos_data(e, "interface-name")
                    watts_val = _parse_float_safe(_junos_data(e, "power-consumed", "0").replace("W", "").strip()) or 0.0
                    status = _junos_data(e, "power-status")
                    p_cls = _junos_data(e, "interface-class")
                    if if_name:
                        poe["ports"][if_name] = {
                            "status": status or "ON",
                            "power_watts": watts_val,
                            "watts": watts_val,
                            "class": p_cls,
                        }
            else:
                # Junos 18.x+ EX schema: {"poe": [{"interface-information": [...]}]}
                entries_v2 = _junos_list(_junos_first(data_if, "poe"), "interface-information")
                for e in entries_v2:
                    if not isinstance(e, dict):
                        continue
                    if_name = _junos_data(e, "interface-name")
                    watts_val = (
                        _parse_float_safe(_junos_data(e, "interface-power", "0").replace("W", "").strip()) or 0.0
                    )
                    status = _junos_data(e, "interface-status")
                    p_cls = _junos_data(e, "interface-class")
                    if if_name:
                        poe["ports"][if_name] = {
                            "status": status or "ON",
                            "power_watts": watts_val,
                            "watts": watts_val,
                            "class": p_cls,
                        }
        except Exception as exc:
            logger.warning(
                "[%s] Junos show poe interface | display json failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_if_txt = conn.send_command("show poe interface")
                for line in (raw_if_txt or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].startswith(("ge-", "xe-", "mge-", "et-")):
                        watts_val = _parse_float_safe(parts[3].replace("W", "")) or 0.0
                        poe["ports"][parts[0]] = {
                            "status": parts[2],
                            "power_watts": watts_val,
                            "watts": watts_val,
                            "class": parts[4] if len(parts) > 4 else "unknown",
                        }
            except Exception as txt_exc:
                logger.warning("[%s] Junos show poe interface text fallback failed: %s", self.ip, txt_exc)

        if poe["total_power_watts"] > 0 or poe["ports"]:
            poe["poe_supported"] = True
        poe["poe_capable_ports"] = len(poe["ports"])
        poe["poe_enabled_ports"] = sum(
            1 for p in poe["ports"].values() if str(p.get("status", "")).upper() != "DISABLED"
        )
        poe["poe_delivering_ports"] = sum(1 for p in poe["ports"].values() if float(p.get("watts", 0.0) or 0.0) > 0)
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show ethernet-switching table | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            table_info = _junos_first(data, "ethernet-switching-table-information")
            mac_entries = _junos_list(table_info, "ethernet-switching-table-entry")
            if mac_entries:
                for e in mac_entries:
                    if not isinstance(e, dict):
                        continue
                    mac_raw = _junos_data(e, "mac-address")
                    if_raw = _junos_data(e, "logical-interface")
                    vlan = _junos_data(e, "vlan-name")
                    mtype = _junos_data(e, "mac-type", "dynamic").lower()
                    if mac_raw and if_raw:
                        port = if_raw.split(".")[0]
                        norm_mac = oui_lookup.normalize_mac(mac_raw).lower()
                        entries.append(
                            {
                                "vlan": vlan or "default",
                                "mac": norm_mac,
                                "type": mtype,
                                "interface": port,
                                "vendor": oui_lookup.lookup_oui(norm_mac),
                            }
                        )
            else:
                # Junos ELS (l2ng) schema: {"l2ng-l2ald-rtb-macdb": [{"l2ng-l2ald-mac-entry-vlan": [...]}]}
                vlan_blocks = _junos_list(_junos_first(data, "l2ng-l2ald-rtb-macdb"), "l2ng-l2ald-mac-entry-vlan")
                for vb in vlan_blocks:
                    if not isinstance(vb, dict):
                        continue
                    vlan_id = _junos_data(vb, "l2ng-l2-vlan-id")
                    for e in _junos_list(vb, "l2ng-mac-entry"):
                        if not isinstance(e, dict):
                            continue
                        mac_raw = _junos_data(e, "l2ng-l2-mac-address")
                        if_raw = _junos_data(e, "l2ng-l2-mac-logical-interface")
                        vlan = _junos_data(e, "l2ng-l2-mac-vlan-name") or vlan_id
                        flags = _junos_data(e, "l2ng-l2-mac-flags", "D").upper()
                        mtype = "static" if "S" in flags else "dynamic"
                        if mac_raw and if_raw:
                            port = if_raw.split(".")[0]
                            norm_mac = oui_lookup.normalize_mac(mac_raw).lower()
                            entries.append(
                                {
                                    "vlan": vlan or "default",
                                    "mac": norm_mac,
                                    "type": mtype,
                                    "interface": port,
                                    "vendor": oui_lookup.lookup_oui(norm_mac),
                                }
                            )
        except Exception as exc:
            logger.warning(
                "[%s] Junos show ethernet-switching table | display json failed, falling back to text: %s",
                self.ip,
                exc,
            )
            try:
                raw_txt = conn.send_command("show ethernet-switching table")
                for line in (raw_txt or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and re.search(r"[0-9a-fA-F]{2}[:\.-][0-9a-fA-F]{2}", parts[1]):
                        vlan = parts[0]
                        mac = oui_lookup.normalize_mac(parts[1]).lower()
                        raw_flag = parts[2].upper()
                        mtype = (
                            "static"
                            if ("S" in raw_flag and raw_flag != "LEARN")
                            else ("dynamic" if raw_flag in ("D", "DL", "DR", "L", "LEARN") else parts[2].lower())
                        )
                        port_tok = ""
                        for tok in parts[3:]:
                            if re.match(r"^(?:ge-|xe-|mge-|et-|fe-|ae\d|reth\d|vcp-|irb|vlan|me0|fxp0)", tok, re.I):
                                port_tok = tok
                                break
                        if not port_tok:
                            port_tok = parts[-1]
                        port = port_tok.split(".")[0]
                        entries.append(
                            {
                                "vlan": vlan,
                                "mac": mac,
                                "type": mtype,
                                "interface": port,
                                "vendor": oui_lookup.lookup_oui(mac),
                            }
                        )
            except Exception as txt_exc:
                logger.warning("[%s] Junos show ethernet-switching table text fallback failed: %s", self.ip, txt_exc)
        return entries

    def get_optics(self, conn) -> list[dict]:
        optics_by_port: dict[str, dict] = {}

        # 1. Extract inserted Xcvr part numbers & serials from `show chassis hardware` (JSON + Junos 9.x text fallback)
        def _xcvr_port(fpc_idx: str, pic_idx: str, xcvr_idx: str, descr: str) -> str:
            dl = descr.lower()
            if "qsfp" in dl or "100g" in dl or "40g" in dl:
                prefix = "et"
            elif "sfp+" in dl or "10g" in dl or "xfp" in dl:
                prefix = "xe"
            else:
                prefix = "ge"
            return f"{prefix}-{fpc_idx}/{pic_idx}/{xcvr_idx}"

        try:
            raw_hw = self._fetch_chassis_hardware_json(conn)
            hw_data = json.loads(raw_hw)
            rpc_err = _junos_rpc_error(hw_data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            chassis = _junos_first(_junos_first(hw_data, "chassis-inventory"), "chassis")
            for mod in _junos_list(chassis, "chassis-module"):
                if not isinstance(mod, dict):
                    continue
                m_name = _junos_data(mod, "name")
                m_fpc = re.match(r"FPC\s+(\d+)", m_name, re.IGNORECASE)
                if not m_fpc:
                    continue
                fpc_idx = m_fpc.group(1)
                for sub in _junos_list(mod, "chassis-sub-module"):
                    if not isinstance(sub, dict):
                        continue
                    s_name = _junos_data(sub, "name")
                    m_pic = re.match(r"PIC\s+(\d+)", s_name, re.IGNORECASE)
                    if not m_pic:
                        continue
                    pic_idx = m_pic.group(1)
                    for xcvr in _junos_list(sub, "chassis-sub-sub-module"):
                        if not isinstance(xcvr, dict):
                            continue
                        x_name = _junos_data(xcvr, "name")
                        m_x = re.match(r"Xcvr\s+(\d+)", x_name, re.IGNORECASE)
                        if not m_x:
                            continue
                        pn = _junos_data(xcvr, "part-number", "Unknown")
                        sn = _junos_data(xcvr, "serial-number", "Unknown")
                        desc = _junos_data(xcvr, "description", "SFP")
                        port = _xcvr_port(fpc_idx, pic_idx, m_x.group(1), desc)
                        optics_by_port[port] = {
                            "port": port,
                            "vendor": "Juniper Networks",
                            "part_number": pn or "Unknown",
                            "serial": sn or "Unknown",
                            "type": desc or "SFP",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
        except Exception as exc:
            logger.warning(
                "[%s] Junos show chassis hardware | display json optics failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_hw_txt = self._fetch_chassis_hardware_text(conn)
                fpc_idx, pic_idx = "0", "0"
                for line in (raw_hw_txt or "").splitlines():
                    m_fpc = re.match(r"^FPC\s+(\d+)", line.strip())
                    if m_fpc:
                        fpc_idx = m_fpc.group(1)
                        continue
                    m_pic = re.match(r"^\s*PIC\s+(\d+)", line)
                    if m_pic:
                        pic_idx = m_pic.group(1)
                        continue
                    m_x = re.match(r"^\s*Xcvr\s+(\d+)\s+(?:REV\s+\S+\s+)?(\S+)\s+(\S+)\s+(.+)$", line)
                    if m_x:
                        pn, sn, desc = m_x.group(2), m_x.group(3), m_x.group(4).strip()
                        port = _xcvr_port(fpc_idx, pic_idx, m_x.group(1), desc)
                        optics_by_port[port] = {
                            "port": port,
                            "vendor": "Juniper Networks",
                            "part_number": pn or "Unknown",
                            "serial": sn or "Unknown",
                            "type": desc or "SFP",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
            except Exception as txt_exc:
                logger.warning("[%s] Junos show chassis hardware optics text fallback failed: %s", self.ip, txt_exc)

        # 2. Merge live DOM telemetry from `show interfaces diagnostics optics`
        def _merge_dom(port: str, tx, rx, temp, volt):
            # Match exact port or fallback to same FPC/PIC/slot if speed prefix differed
            target_key = port
            if target_key not in optics_by_port:
                suffix = port.split("-", 1)[-1] if "-" in port else port
                for k in optics_by_port:
                    if k.endswith("-" + suffix):
                        target_key = k
                        break
            if target_key in optics_by_port:
                optics_by_port[target_key]["port"] = port
                optics_by_port[target_key]["tx_power_dbm"] = tx
                optics_by_port[target_key]["rx_power_dbm"] = rx
                optics_by_port[target_key]["temperature_c"] = temp
                optics_by_port[target_key]["voltage_v"] = volt
            else:
                optics_by_port[port] = {
                    "port": port,
                    "vendor": "Juniper Networks",
                    "part_number": "SFP-DOM",
                    "serial": "Unknown",
                    "type": "SFP+",
                    "tx_power_dbm": tx,
                    "rx_power_dbm": rx,
                    "temperature_c": temp,
                    "voltage_v": volt,
                }

        try:
            raw = conn.send_command("show interfaces diagnostics optics | display json")
            data = json.loads(raw)
            rpc_err = _junos_rpc_error(data)
            if rpc_err:
                raise ValueError(f"Junos RPC error: {rpc_err}")
            # Real Junos uses `interface-information`; preserve legacy `interfaces-diagnostics-optics-information` too
            diag_info = _junos_first(data, "interface-information") or _junos_first(
                data, "interfaces-diagnostics-optics-information"
            )
            phys = _junos_list(diag_info, "physical-interface")
            for p in phys:
                if not isinstance(p, dict):
                    continue
                p_name = _junos_data(p, "name")
                diag = _junos_first(p, "optics-diagnostics")
                if not p_name or not diag:
                    continue

                tx_raw = _junos_data(diag, "laser-output-power-dbm")
                rx_raw = _junos_data(diag, "rx-signal-avg-optical-power-dbm") or _junos_data(
                    diag, "laser-rx-optical-power-dbm"
                )
                # Multi-lane QSFP/et- fallback when top-level laser power is absent
                if not tx_raw or not rx_raw:
                    lane0 = _junos_first(diag, "optics-diagnostics-lane-values")
                    if lane0:
                        tx_raw = tx_raw or _junos_data(lane0, "laser-output-power-dbm")
                        rx_raw = (
                            rx_raw
                            or _junos_data(lane0, "laser-rx-optical-power-dbm")
                            or _junos_data(lane0, "rx-signal-avg-optical-power-dbm")
                        )

                temp_raw = _junos_attr(diag, "module-temperature", "junos:celsius") or _junos_data(
                    diag, "module-temperature"
                )
                volt_raw = _junos_data(diag, "module-voltage")

                _merge_dom(
                    p_name,
                    _parse_float_safe(tx_raw),
                    _parse_float_safe(rx_raw),
                    _parse_float_safe(temp_raw),
                    _parse_float_safe(volt_raw),
                )
        except Exception as exc:
            logger.warning(
                "[%s] Junos show interfaces diagnostics optics | display json failed, falling back to text: %s",
                self.ip,
                exc,
            )
            try:
                raw_txt = conn.send_command("show interfaces diagnostics optics")
                current_port = ""
                cur_data: dict = {}
                for line in (raw_txt or "").splitlines():
                    m_p = re.match(r"^Physical interface:\s*([A-Za-z0-9/\._-]+)", line)
                    if m_p:
                        if current_port and cur_data:
                            _merge_dom(
                                current_port,
                                cur_data.get("tx_power_dbm"),
                                cur_data.get("rx_power_dbm"),
                                cur_data.get("temperature_c"),
                                cur_data.get("voltage_v"),
                            )
                        current_port = m_p.group(1)
                        cur_data = {}
                    elif current_port:
                        m_tx = re.search(r"Laser output power\s*:\s*.*?/\s*([-\d\.]+)\s*dBm", line, re.IGNORECASE)
                        m_rx = re.search(
                            r"(?:Laser rx optical power|Receiver signal average optical power)\s*:\s*.*?/\s*([-\d\.]+)\s*dBm",
                            line,
                            re.IGNORECASE,
                        )
                        m_temp = re.search(r"Module temperature\s*:\s*([-\d\.]+)\s*degrees C", line, re.IGNORECASE)
                        m_volt = re.search(r"Module voltage\s*:\s*([-\d\.]+)\s*V", line, re.IGNORECASE)
                        if m_tx:
                            cur_data["tx_power_dbm"] = _parse_float_safe(m_tx.group(1))
                        if m_rx:
                            cur_data["rx_power_dbm"] = _parse_float_safe(m_rx.group(1))
                        if m_temp:
                            cur_data["temperature_c"] = _parse_float_safe(m_temp.group(1))
                        if m_volt:
                            cur_data["voltage_v"] = _parse_float_safe(m_volt.group(1))
                if current_port and cur_data:
                    _merge_dom(
                        current_port,
                        cur_data.get("tx_power_dbm"),
                        cur_data.get("rx_power_dbm"),
                        cur_data.get("temperature_c"),
                        cur_data.get("voltage_v"),
                    )
            except Exception as txt_exc:
                logger.warning(
                    "[%s] Junos show interfaces diagnostics optics text fallback failed: %s", self.ip, txt_exc
                )
        return list(optics_by_port.values())

    def get_running_config(self, conn) -> str:
        try:
            cfg = conn.send_command("show configuration | display set")
            if isinstance(cfg, str) and cfg.strip() and not _is_junos_cli_error(cfg):
                return cfg
            if _is_junos_cli_error(cfg):
                logger.warning(
                    "[%s] Junos show configuration | display set returned CLI error; falling back to show configuration",
                    self.ip,
                )
        except Exception as exc:
            logger.warning(
                "[%s] Junos show configuration | display set failed, falling back to show configuration: %s",
                self.ip,
                exc,
            )
        try:
            return conn.send_command("show configuration") or ""
        except Exception as exc:
            logger.warning("[%s] Junos show configuration fallback failed: %s", self.ip, exc)
            return ""

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        parsed_es_json = False

        # Prefer ELS singular `show ethernet-switching interface`; fall back to pre-ELS plural `interfaces`
        for es_json_cmd in (
            "show ethernet-switching interface | display json",
            "show ethernet-switching interfaces | display json",
        ):
            try:
                raw_es = conn.send_command(es_json_cmd)
                if isinstance(raw_es, str) and raw_es.strip().startswith("{"):
                    data = json.loads(raw_es)
                    rpc_err = _junos_rpc_error(data)
                    if rpc_err:
                        logger.warning("[%s] Junos %s returned RPC error: %s", self.ip, es_json_cmd, rpc_err)
                        continue
                    entries = _junos_list(
                        _junos_first(data, "l2ng-l2ald-iff-interface-information"),
                        "l2ng-l2ald-iff-interface-entry",
                    )
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        iname = _junos_data(entry, "l2ng-l2ald-iff-interface-name").split(".")[0]
                        if not iname:
                            continue
                        parsed_es_json = True
                        mode = _junos_data(entry, "l2ng-l2ald-iff-port-mode").lower()
                        state = (
                            _junos_data(entry, "l2ng-l2ald-iff-interface-state")
                            or _junos_data(entry, "l2ng-l2ald-iff-interface-status")
                            or "up"
                        ).lower()
                        flags = _junos_data(entry, "l2ng-l2ald-iff-interface-flags").upper()
                        is_down = state == "down" or "DN" in flags.split()

                        # Extract operational VLAN members & tagness
                        member_nodes: list[dict] = []
                        for vlist in _junos_list(entry, "l2ng-l2ald-iff-interface-vlan-member-list"):
                            if isinstance(vlist, dict):
                                member_nodes.extend(_junos_list(vlist, "l2ng-l2ald-iff-interface-vlan-member"))
                        if not member_nodes:
                            member_nodes = _junos_list(entry, "l2ng-l2ald-iff-interface-vlan-member")

                        active_vids: list[str] = []
                        tagged_vids: list[str] = []
                        untagged_vid = ""
                        for m_node in member_nodes:
                            if not isinstance(m_node, dict):
                                continue
                            tag_id = _junos_data(m_node, "l2ng-l2ald-iff-interface-vlan-member-tagid") or _junos_data(
                                m_node, "l2ng-l2ald-iff-interface-vlan-id"
                            )
                            tagness = (
                                _junos_data(m_node, "l2ng-l2ald-iff-interface-vlan-member-tagness")
                                or _junos_data(m_node, "l2ng-l2ald-iff-interface-vlan-member-tagging")
                            ).lower()
                            if tag_id.isdigit():
                                if tag_id not in active_vids:
                                    active_vids.append(tag_id)
                                if tagness == "untagged":
                                    untagged_vid = tag_id
                                elif tagness == "tagged" and tag_id not in tagged_vids:
                                    tagged_vids.append(tag_id)

                        if mode not in ("access", "trunk"):
                            if tagged_vids or len(active_vids) > 1:
                                mode = "trunk"
                            elif untagged_vid:
                                mode = "access"

                        if mode in ("access", "trunk"):
                            rec = ops.setdefault(iname, {})
                            rec["mode"] = mode
                            rec["oper_mode"] = "down" if is_down else mode
                            rec["encapsulation"] = "dot1q"
                            if mode == "trunk":
                                if active_vids:
                                    sorted_vids = sorted(active_vids, key=int)
                                    rec["trunk_active_vlans"] = ",".join(sorted_vids)
                                if untagged_vid:
                                    rec["native_vlan"] = untagged_vid
                                    rec["native_vlan_tagged"] = False
                                elif active_vids:
                                    rec["native_vlan"] = "none"
                                    rec["native_vlan_tagged"] = True
                            elif mode == "access" and untagged_vid:
                                rec["access_vlan"] = untagged_vid
                    if parsed_es_json:
                        break
            except Exception as exc:
                logger.warning("[%s] Junos %s failed: %s", self.ip, es_json_cmd, exc)

        # Text fallback for `show ethernet-switching interface` (ELS) / `interfaces` (pre-ELS)
        if not parsed_es_json:
            for es_txt_cmd in ("show ethernet-switching interface", "show ethernet-switching interfaces"):
                try:
                    raw_es_txt = conn.send_command(es_txt_cmd)
                    if not isinstance(raw_es_txt, str) or not raw_es_txt.strip() or _is_junos_cli_error(raw_es_txt):
                        continue
                    parsed_ports: dict[str, dict] = {}
                    cur_if = ""
                    for line in raw_es_txt.splitlines():
                        if not line.strip():
                            continue
                        low = line.strip().lower()
                        if low.startswith(("routing instance", "logical", "interface", "---")):
                            continue
                        m_if = re.match(r"^\s*((?:ge-|xe-|et-|fe-|mge-|ae\d)\S*)\s+(.*)$", line)
                        if m_if:
                            cur_if = m_if.group(1).split(".")[0]
                            tail = m_if.group(2)
                            p_state = parsed_ports.setdefault(cur_if, {"down": False, "tagged": [], "untagged": []})
                            if re.match(r"^down\b", tail, re.I) or re.search(r"\bDN\b", tail):
                                p_state["down"] = True
                        elif cur_if and line[0].isspace():
                            tail = line.strip()
                            p_state = parsed_ports[cur_if]
                            if re.search(r"\bDN\b", tail):
                                p_state["down"] = True
                        else:
                            continue

                        # Match ELS (`VLAN_NAME  10  65535  Forwarding  tagged`) or pre-ELS (`[up|down] VLAN_NAME  10  tagged`)
                        m_row = re.search(
                            r"^\s*(?:(?:up|down)\s+)?\S+\s+(\d{1,4})\s+(?:\d+\s+\S+.*?)?\b(tagged|untagged)\b",
                            tail,
                            re.I,
                        )
                        if m_row:
                            vid, tagness = m_row.group(1), m_row.group(2).lower()
                            if 1 <= int(vid) <= 4094:
                                bucket = p_state["tagged"] if tagness == "tagged" else p_state["untagged"]
                                if vid not in bucket:
                                    bucket.append(vid)

                    if parsed_ports:
                        for iname, p_state in parsed_ports.items():
                            tagged = p_state["tagged"]
                            untagged = p_state["untagged"]
                            all_vids = sorted(set(tagged) | set(untagged), key=int)
                            if not all_vids:
                                continue
                            rec = ops.setdefault(iname, {})
                            rec["encapsulation"] = "dot1q"
                            if tagged or len(all_vids) > 1:
                                rec["mode"] = "trunk"
                                rec["oper_mode"] = "down" if p_state["down"] else "trunk"
                                rec["trunk_active_vlans"] = ",".join(all_vids)
                                if untagged:
                                    rec["native_vlan"] = untagged[0]
                                    rec["native_vlan_tagged"] = False
                                else:
                                    rec["native_vlan"] = "none"
                                    rec["native_vlan_tagged"] = True
                            elif untagged:
                                rec["mode"] = "access"
                                rec["oper_mode"] = "down" if p_state["down"] else "access"
                                rec["access_vlan"] = untagged[0]
                        break
                except Exception as exc:
                    logger.warning("[%s] Junos %s text fallback failed: %s", self.ip, es_txt_cmd, exc)

        try:
            raw_lacp = conn.send_command("show lacp interfaces | display json")
            if isinstance(raw_lacp, str) and raw_lacp.strip().startswith("{"):
                data = json.loads(raw_lacp)
                if not _junos_rpc_error(data):
                    for grp_blk in _junos_list(
                        _junos_first(data, "lacp-interface-information-list"), "lacp-interface-information"
                    ):
                        if not isinstance(grp_blk, dict):
                            continue
                        ae_name = _junos_data(_junos_first(grp_blk, "lag-lacp-header"), "aggregate-name")
                        for p_ent in _junos_list(grp_blk, "lag-lacp-state"):
                            if not isinstance(p_ent, dict):
                                continue
                            pname = _junos_data(p_ent, "name")
                            if pname and ae_name:
                                ops.setdefault(pname, {})["lag_group"] = ae_name
                                role = _junos_data(p_ent, "lacp-activity").lower()
                                if role in ("active", "passive"):
                                    ops[pname]["lacp_mode"] = role
        except Exception as exc:
            logger.warning("[%s] Junos show lacp interfaces | display json failed: %s", self.ip, exc)

        try:
            raw_stp = conn.send_command("show spanning-tree interface | display json")
            if isinstance(raw_stp, str) and raw_stp.strip().startswith("{"):
                data = json.loads(raw_stp)
                if not _junos_rpc_error(data):
                    for stp_blk in _junos_list(data, "stp-interface-information"):
                        if not isinstance(stp_blk, dict):
                            continue
                        for p_ent in _junos_list(stp_blk, "stp-interface-entry"):
                            if not isinstance(p_ent, dict):
                                continue
                            pname = _junos_data(p_ent, "interface-name").split(".")[0]
                            if not pname:
                                continue
                            role = _junos_data(p_ent, "port-role")
                            state = _junos_data(p_ent, "port-state")
                            if role:
                                ops.setdefault(pname, {})["stp_role"] = role
                            if state:
                                ops.setdefault(pname, {})["stp_state"] = state
        except Exception as exc:
            logger.warning("[%s] Junos show spanning-tree interface | display json failed: %s", self.ip, exc)

        try:
            raw_dot1x = conn.send_command("show dot1x interface | display json")
            if isinstance(raw_dot1x, str) and raw_dot1x.strip().startswith("{"):
                data = json.loads(raw_dot1x)
                if not _junos_rpc_error(data):
                    for d_ent in _junos_list(_junos_first(data, "dot1x-interface-information"), "interface"):
                        if not isinstance(d_ent, dict):
                            continue
                        pname = _junos_data(d_ent, "interface-name").split(".")[0]
                        if pname:
                            ops.setdefault(pname, {})["auth_policy"] = "dot1x"
        except Exception as exc:
            logger.warning("[%s] Junos show dot1x interface | display json failed: %s", self.ip, exc)

        return ops

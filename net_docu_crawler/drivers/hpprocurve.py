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
HP ProCurve / ArubaOS-S (Provision) Driver: Switches running Provision OS 14.x, 15.x, and 16.x.
Official Documentation: https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm
"""

import ipaddress
import logging
import re

import oui_lookup
import parser as cli_parser
from net_docu_crawler.drivers.base import BaseDriver
from net_docu_crawler.topology_resolver import (
    is_clean_interface_token as _is_clean_interface_token,
)
from net_docu_crawler.topology_resolver import (
    pick_clean_remote_port as _pick_clean_remote_port,
)

logger = logging.getLogger(__name__)

_PROCURVE_ROUTE_RE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(.+?)\s+(connected|static|ospf|rip|bgp|local|reject)\b(?:\s+\S+)?\s+\d+\s+\d+\s*$",
    re.IGNORECASE,
)

_BARE_VT100_RE = re.compile(r"\[(?:\?[0-9;]*[hl]|[0-9;]*[HJKr])")

_PROCURVE_CLI_ERROR_RE = re.compile(
    r"(?:invalid input|incomplete input|ambiguous input|module not present|"
    r"invalid port|unknown command|command not supported|not authorized)",
    re.IGNORECASE,
)

# Matches fixed (`1`, `48`), modular (`A1`, `B24`), stacked (`2/A1`, `1/1/1`),
# trunk-member (`1-Trk1`, `A1-Trk2`), and trunk/named (`Trk1`, `Dyn1`, `port1`) ports.
_PROCURVE_PORT_PAT = r"(?:[A-Za-z]?\d+(?:/[A-Za-z]?\d+){0,2}(?:-(?:Trk|Dyn)\d+)?|(?:Trk|Dyn|port)\d+)"
_PROCURVE_MEDIA_RE = re.compile(
    r"^(?:10/100\S*|100/1000\S*|1000\S*|10GbE\S*|1GbE\S*|SFP\S*|QSFP\S*|100FX\S*|--)$",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ZERO_MAC = "00:00:00:00:00:00"

_PROCURVE_SKU_MODELS: dict[str, str] = {
    "J8697A": "HP 5406zl (J8697A)",
    "J8698A": "HP 5412zl (J8698A)",
    "J9085A": "HP 2610-24 (J9085A)",
    "J9086A": "HP 2610-24/12PWR (J9086A)",
    "J9087A": "HP 2610-24-PWR (J9087A)",
    "J9088A": "HP 2610-48 (J9088A)",
    "J9089A": "HP 2610-48-PWR (J9089A)",
    "J9623A": "HP 2620-24 (J9623A)",
    "J9624A": "HP 2620-24-PPoE+ (J9624A)",
    "J9625A": "HP 2620-24-PoE+ (J9625A)",
    "J9626A": "HP 2620-48 (J9626A)",
    "J9627A": "HP 2620-48-PoE+ (J9627A)",
    "J9772A": "HP 2530-48G-PoE+ (J9772A)",
    "J9773A": "HP 2530-24G-PoE+ (J9773A)",
    "J9774A": "HP 2530-8G-PoE+ (J9774A)",
    "J9775A": "HP 2530-48G (J9775A)",
    "J9776A": "HP 2530-24G (J9776A)",
    "J9777A": "HP 2530-8G (J9777A)",
    "J9853A": "HP 2530-48G-PoE+ (J9853A)",
    "J9854A": "HP 2530-24G-PoE+ (J9854A)",
    "J9855A": "HP 2530-48G (J9855A)",
    "J9856A": "HP 2530-24G (J9856A)",
}


def _is_procurve_cli_error(raw: str) -> bool:
    """Return True if Provision OS CLI output contains a command syntax or module error."""
    return bool(raw and _PROCURVE_CLI_ERROR_RE.search(raw))


def _extract_model_from_config(raw_config: str) -> str:
    """Extract HP/Aruba J/JL SKU from `show running-config` header comment."""
    if not raw_config:
        return ""
    m = re.search(r";\s*(J[L]?\d{4}[A-Z])\s+Configuration Editor", raw_config, re.IGNORECASE)
    if not m:
        return ""
    sku = m.group(1).upper()
    return _PROCURVE_SKU_MODELS.get(sku, f"HP Switch ({sku})")


def _clean_procurve_output(raw: str) -> str:
    """Strip ESC-prefixed ANSI/VT100 sequences, bare CSI cursor codes, and CRs."""
    if not raw:
        return ""
    cleaned = cli_parser.clean_cli_output(raw)
    cleaned = _BARE_VT100_RE.sub("", cleaned)
    return cleaned.replace("\r", "")


def _normalize_chassis_mac(raw_val: str) -> str:
    """Normalize space/dash/colon separated 6-octet MAC strings, returning '' if not a MAC."""
    if not raw_val:
        return ""
    clean = raw_val.strip().replace(" ", ":").replace("-", ":")
    if re.match(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", clean) or re.match(
        r"^[0-9a-fA-F]{6}:[0-9a-fA-F]{6}$", clean
    ):
        norm = oui_lookup.normalize_mac(clean).lower()
        return "" if norm == _ZERO_MAC else norm
    return ""


def _classify_procurve_neighbor(
    *,
    platform: str = "",
    remote_device: str = "",
    capabilities: str = "",
    remote_mac: str = "",
) -> str:
    """Classify neighbor device_type from LLDP/CDP capabilities, platform/SysDescr, hostname, and OUI."""
    caps_low = (capabilities or "").lower()
    plat_low = (platform or "").lower()
    host_low = (remote_device or "").lower()
    vendor_low = (oui_lookup.lookup_oui(remote_mac) if remote_mac else "").lower()
    blob = f"{plat_low} {host_low} {vendor_low}"

    if (
        any(k in caps_low for k in ("telephone", "phone"))
        or any(
            w in blob
            for w in [
                "polycom",
                "yealink",
                "mitel",
                "avaya",
                "grandstream",
                "digium",
                "snom",
                "sangoma",
                "ip phone",
            ]
        )
        or re.match(r"^(?:d40|d60|d62|d65|d70|p315)-", host_low)
    ):
        return "phone"
    if any(w in blob for w in ["axis", "hikvision", "camera", "hanwha", "verkada", "valcom"]):
        return "camera"
    if any(k in caps_low for k in ("wlan", "access-point", "access point")) or re.search(
        r"(?:\bap\b|access point|instant ap|aruba ap|ruckus|ubiquiti|unifi|aironet)", blob
    ):
        return "ap"
    if any(w in blob for w in ["crestron", "extron", "biamp"]):
        return "av_control"
    if any(w in blob for w in ["fortigate", "palo alto", "pan-os", "opnsense", "pfsense", "firewall"]):
        return "firewall"
    if ("router" in caps_low and "bridge" not in caps_low) or any(w in plat_low for w in ["router", "mikrotik"]):
        return "router"
    if any(
        w in plat_low
        for w in ["windows", "macos", "ubuntu", "workstation", "apple", "dell", "lenovo", "intel", "microsoft"]
    ) or re.match(r"^(?:desktop|laptop|workstation|do-fisc|do-katye)-?", host_low):
        return "endpoint"
    return "switch"


class _CleanProCurveConn:
    """Transparent connection wrapper that strips ProCurve VT100/ANSI escape codes."""

    def __init__(self, conn):
        self._conn = conn

    def send_command(self, *args, **kwargs):
        return _clean_procurve_output(self._conn.send_command(*args, **kwargs))

    def find_prompt(self, *args, **kwargs):
        return _clean_procurve_output(self._conn.find_prompt(*args, **kwargs)).strip()

    def __getattr__(self, name):
        return getattr(self._conn, name)


class HPProCurveDriver(BaseDriver):
    """
    Driver for HP ProCurve, HP Enterprise, and ArubaOS-S switches (Provision OS).
    Persona: switch (L2/L3 campus switching).
    Covers legacy and modern firmware (K/RA/WB/WC 14.x, 15.x, and 16.x).
    """

    vendor_name = "HP ProCurve / ArubaOS-S"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "no page"

    def connect(self):
        device = self._build_netmiko_params("hp_procurve", secret=self.secret)
        return _CleanProCurveConn(self.connect_netmiko(device))

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "HP Switch",
            "serial": "Unknown",
            "firmware": "ArubaOS-S",
            "os_type": "hp_procurve",
            "device_persona": self.device_persona,
        }

        # Query show system
        raw_sys = self._safe_send_command(conn, "show system")
        if _is_procurve_cli_error(raw_sys):
            logger.warning("[%s] HP ProCurve 'show system' returned CLI error: %s", self.ip, raw_sys.strip()[:160])

        m_host = re.search(r"System Name\s*:\s*(\S+)", raw_sys)
        if m_host:
            info["hostname"] = m_host.group(1).strip()
        else:
            prompt = self._safe_find_prompt(conn)
            if prompt:
                info["hostname"] = prompt.rstrip(">#").strip()

        m_fw = re.search(r"Software revision\s*:\s*(\S+)", raw_sys)
        if m_fw:
            info["firmware"] = m_fw.group(1).strip()

        m_ser = re.search(r"Serial Number\s*:\s*(\S+)", raw_sys)
        if m_ser:
            info["serial"] = m_ser.group(1).strip()

        m_mac = re.search(r"Base MAC Addr\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw_sys)
        if m_mac:
            info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()

        # Query show modules for precise chassis model
        modules_failed = False
        try:
            raw_mod = conn.send_command("show modules")
            if _is_procurve_cli_error(raw_mod):
                modules_failed = True
            else:
                m_mod = re.search(r"Chassis:\s*([^\r\n]+?)\s+(?:J\w+|[A-Z0-9]+)\s+Serial Number:", raw_mod)
                if m_mod:
                    info["model"] = f"HP {m_mod.group(1).strip()}"
                elif "Chassis:" in raw_mod:
                    m_c = re.search(r"Chassis:\s*([^\r\n]+)", raw_mod)
                    if m_c:
                        info["model"] = f"HP {m_c.group(1).split()[0].strip()}"
        except Exception as exc:
            modules_failed = True
            logger.warning("[%s] HP ProCurve show modules failed: %s", self.ip, exc)

        # Fallback to `show version` when firmware is missing or `show modules` is unsupported
        if info["firmware"] == "ArubaOS-S" or (modules_failed and info["model"] == "HP Switch"):
            try:
                raw_ver = conn.send_command("show version")
                if isinstance(raw_ver, str) and raw_ver.strip() and not _is_procurve_cli_error(raw_ver):
                    if info["firmware"] == "ArubaOS-S":
                        m_rel = re.search(
                            r"\b((?:WB|WC|YA|YB|YC|KB|KA|RA|K|R|T|N|M|Q|W)\.\d{2}\.\d{2}(?:\.\d+)?)\b",
                            raw_ver,
                        )
                        if m_rel:
                            info["firmware"] = m_rel.group(1)
            except Exception as exc:
                logger.warning("[%s] HP ProCurve show version fallback failed: %s", self.ip, exc)

        return info

    def crawl(self, conn) -> dict:
        data = super().crawl(conn)
        if data.get("model") in ("", "HP Switch", "Unknown"):
            sku_model = _extract_model_from_config(data.get("raw_config", ""))
            if sku_model:
                data["model"] = sku_model
        return data

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        self._default_gateway = ""

        # 1. Layer 3 interfaces via show ip (also capture Default Gateway for L2-only switches)
        try:
            raw_ip = conn.send_command("show ip")
            if _is_procurve_cli_error(raw_ip):
                logger.warning("[%s] HP ProCurve 'show ip' returned CLI error: %s", self.ip, raw_ip.strip()[:160])
            else:
                m_gw = re.search(r"Default\s+Gateway\s*:\s*(\d+\.\d+\.\d+\.\d+)", raw_ip, re.IGNORECASE)
                if m_gw and m_gw.group(1) != "0.0.0.0":
                    self._default_gateway = m_gw.group(1)

                last_vlan = "DEFAULT_VLAN"
                for line in raw_ip.splitlines():
                    if "|" in line and not ("---" in line or "IP Config" in line or "Internet" in line):
                        parts = line.split("|")
                        vlan_col = parts[0].strip()
                        if vlan_col:
                            last_vlan = vlan_col
                        vlan_name = last_vlan
                        sub_parts = parts[1].split()
                        if len(sub_parts) >= 3:
                            _cfg, ip_addr, mask = sub_parts[0], sub_parts[1], sub_parts[2]
                            if _IPV4_RE.match(ip_addr) and _IPV4_RE.match(mask):
                                try:
                                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                                    l3_interfaces.append(
                                        {
                                            "interface": vlan_name,
                                            "ip_address": f"{ip_addr}/{prefix}",
                                            "status": "up",
                                            "protocol": "up",
                                        }
                                    )
                                except ValueError as exc:
                                    logger.warning(
                                        "[%s] HP ProCurve invalid netmask '%s' on %s: %s", self.ip, mask, vlan_name, exc
                                    )
                                    l3_interfaces.append(
                                        {
                                            "interface": vlan_name,
                                            "ip_address": f"{ip_addr} {mask}",
                                            "status": "up",
                                            "protocol": "up",
                                        }
                                    )
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show ip failed: %s", self.ip, exc)

        # 2. Port descriptions via show name (handles blank Type column on empty SFP cages & odd port names)
        port_names: dict[str, str] = {}
        try:
            raw_names = conn.send_command("show name")
            if _is_procurve_cli_error(raw_names):
                logger.warning("[%s] HP ProCurve 'show name' returned CLI error", self.ip)
            else:
                for line in raw_names.splitlines():
                    stripped = line.strip()
                    if not stripped or "Port" in stripped or "---" in stripped or "Status and Counters" in stripped:
                        continue
                    m_name = re.match(rf"^\s*({_PROCURVE_PORT_PAT})\s+(.+)$", line)
                    if m_name:
                        pname = m_name.group(1).strip()
                        rest = m_name.group(2).strip()
                        parts = rest.split(None, 1)
                        if parts and _PROCURVE_MEDIA_RE.match(parts[0]):
                            desc = parts[1].strip() if len(parts) > 1 else ""
                        else:
                            desc = rest
                        if desc:
                            port_names[pname] = desc
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show name failed: %s", self.ip, exc)

        # 3. Physical port status via show interfaces brief (handles empty SFP cages, -Trk*, stacked/3-tuple ports)
        try:
            raw_brief = conn.send_command("show interfaces brief")
            if _is_procurve_cli_error(raw_brief):
                logger.warning("[%s] HP ProCurve 'show interfaces brief' returned CLI error", self.ip)
            else:
                for line in raw_brief.splitlines():
                    if "Port" in line or "---" in line or "Intrusion" in line:
                        continue
                    m_port = re.match(
                        rf"^\s*({_PROCURVE_PORT_PAT})(?:\s+[^|]+?)?\s*\|\s+\S+\s+(Yes|No)\s+(Up|Down)\s+(\S+)",
                        line,
                    )
                    if m_port:
                        port = m_port.group(1).strip()
                        admin_status = "up" if m_port.group(2).lower() == "yes" else "down"
                        status = "up" if m_port.group(3).lower() == "up" else "down"
                        mode = m_port.group(4)
                        mode_u = mode.upper()

                        speed = "Auto"
                        if "40G" in mode_u:
                            speed = "40Gb/s"
                        elif "25G" in mode_u:
                            speed = "25Gb/s"
                        elif "10G" in mode_u:
                            speed = "10Gb/s"
                        elif "1000" in mode_u or "1G" in mode_u:
                            speed = "1Gb/s"
                        elif "100" in mode_u:
                            speed = "100Mb/s"
                        elif "10" in mode_u:
                            speed = "10Mb/s"

                        duplex = "Auto"
                        if "FD" in mode_u:
                            duplex = "Full"
                        elif "HD" in mode_u:
                            duplex = "Half"

                        base_port = port.split("-", 1)[0]
                        interfaces_detail[port] = {
                            "status": status,
                            "protocol": status,
                            "admin_status": admin_status,
                            "speed": speed,
                            "duplex": duplex,
                            "mac_address": "",
                            "description": port_names.get(port) or port_names.get(base_port, ""),
                        }
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show interfaces brief failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    @staticmethod
    def _parse_lldp_detail_blocks(raw_detail: str) -> dict[str, list[dict[str, str]]]:
        """Parse Provision OS `show lldp info remote-device detail`/`all` blocks without overwriting multi-neighbor ports."""
        detail_by_port: dict[str, list[dict[str, str]]] = {}
        current: dict[str, str] = {}
        in_mgmt_section = False

        def _flush() -> None:
            if current.get("local_port"):
                detail_by_port.setdefault(current["local_port"], []).append(dict(current))

        for ln in raw_detail.splitlines():
            stripped = ln.strip()
            if not stripped:
                continue

            m_lp = re.match(r"^Local\s+Port\s*:\s*(\S+)", stripped, re.IGNORECASE)
            if m_lp:
                _flush()
                current = {
                    "local_port": m_lp.group(1).strip(),
                    "chassis_raw": "",
                    "remote_mac": "",
                    "port_id": "",
                    "port_descr": "",
                    "sys_name": "",
                    "sys_descr": "",
                    "capabilities": "",
                    "remote_ip": "",
                }
                in_mgmt_section = False
                continue

            if not current:
                continue

            if re.match(r"^Remote\s+Management\s+Address\b", stripped, re.IGNORECASE):
                in_mgmt_section = True
                continue

            m_kv = re.match(r"^([^:]+?)\s*:\s*(.*)$", stripped)
            if not m_kv:
                continue
            key = re.sub(r"\s+", " ", m_kv.group(1).strip().lower())
            val = m_kv.group(2).strip()
            if not val:
                continue

            if key in ("chassisid", "chassis id"):
                current["chassis_raw"] = val
                mac = _normalize_chassis_mac(val)
                if mac:
                    current["remote_mac"] = mac
                in_mgmt_section = False
            elif key in ("sysname", "system name"):
                if "." in val and not _IPV4_RE.match(val) and not _normalize_chassis_mac(val):
                    val = val.split(".", 1)[0]
                current["sys_name"] = val
                in_mgmt_section = False
            elif key in ("portid", "port id"):
                current["port_id"] = val
                in_mgmt_section = False
            elif key in ("portdescr", "port descr", "port description"):
                current["port_descr"] = val
                in_mgmt_section = False
            elif key in ("system descr", "system description", "sysdescr"):
                current["sys_descr"] = val[:100]
                in_mgmt_section = False
            elif key in ("system capabilities enabled", "capabilities enabled"):
                current["capabilities"] = val
                in_mgmt_section = False
            elif key in ("system capabilities supported", "capabilities supported"):
                if not current["capabilities"]:
                    current["capabilities"] = val
                in_mgmt_section = False
            elif key in ("management address", "mgmt address") or (in_mgmt_section and key == "address"):
                m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", val)
                if m_ip:
                    current["remote_ip"] = m_ip.group(1)

        _flush()
        return detail_by_port

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []

        # 1. Primary: LLDP summary table
        try:
            raw_lldp = conn.send_command("show lldp info remote-device")
            if _is_procurve_cli_error(raw_lldp):
                logger.warning("[%s] HP ProCurve 'show lldp info remote-device' returned CLI error", self.ip)
                raw_lldp = ""
            lines = raw_lldp.splitlines()
            sep_line = next(
                (line_item for line_item in lines if "+ ----" in line_item or "--------- +" in line_item), None
            )
            if sep_line and "+" in sep_line:
                p_plus = sep_line.index("+")
                parts = sep_line[p_plus + 1 :].split()
                if len(parts) >= 3:
                    col1_len = len(parts[0])
                    col2_len = len(parts[1])
                    col3_len = len(parts[2])

                    for line_item in lines:
                        if "|" in line_item and not ("LocalPort" in line_item or "---" in line_item):
                            pipe = line_item.index("|")
                            local_port = line_item[:pipe].strip()
                            rest = line_item[pipe + 1 :]
                            chassis_raw = rest[: col1_len + 1].strip()
                            port_id = rest[col1_len + 1 : col1_len + 1 + col2_len + 1].strip()
                            port_descr = rest[
                                col1_len + 1 + col2_len + 1 : col1_len + 1 + col2_len + 1 + col3_len + 1
                            ].strip()
                            sys_name = rest[col1_len + 1 + col2_len + 1 + col3_len + 1 :].strip()

                            remote_mac = _normalize_chassis_mac(chassis_raw) or _normalize_chassis_mac(port_id)
                            rem_port, rem_port_desc = _pick_clean_remote_port(port_id, "", port_descr)
                            rem_host = sys_name or (f"MAC-{remote_mac.replace(':', '')}" if remote_mac else chassis_raw)
                            rem_host = rem_host.split(".")[0]

                            plat = oui_lookup.lookup_oui(remote_mac) if remote_mac else chassis_raw
                            dev_type = _classify_procurve_neighbor(
                                platform=plat,
                                remote_device=rem_host,
                                remote_mac=remote_mac,
                            )

                            neighbors.append(
                                {
                                    "local_port": local_port,
                                    "remote_device": rem_host,
                                    "remote_port": rem_port,
                                    "remote_port_description": rem_port_desc,
                                    "remote_ip": "",
                                    "remote_mac": remote_mac,
                                    "platform": plat,
                                    "remote_platform": plat,
                                    "device_type": dev_type,
                                    "_chassis_raw": chassis_raw,
                                    "_port_id_raw": port_id,
                                }
                            )
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show lldp info remote-device failed: %s", self.ip, exc)

        # 2. Enrich with untruncated System Name / PortId / Mgmt IP / SysDescr / Capabilities
        # Try `detail` first, falling back to Provision OS `all` when `detail` is rejected as an invalid port
        raw_detail = ""
        for det_cmd in ("show lldp info remote-device detail", "show lldp info remote-device all"):
            try:
                cand = conn.send_command(det_cmd)
                if cand and not _is_procurve_cli_error(cand) and "Local Port" in cand:
                    raw_detail = cand
                    break
            except Exception as exc:
                logger.warning("[%s] HP ProCurve '%s' failed: %s", self.ip, det_cmd, exc)

        if raw_detail:
            detail_by_port = self._parse_lldp_detail_blocks(raw_detail)
            if neighbors:
                summary_count_by_port: dict[str, int] = {}
                for n in neighbors:
                    lp = n.get("local_port", "")
                    summary_count_by_port[lp] = summary_count_by_port.get(lp, 0) + 1

                for n in neighbors:
                    lp = n.get("local_port", "")
                    cand_list = detail_by_port.get(lp, [])
                    if not cand_list:
                        continue

                    matched_detail = None
                    n_mac = n.get("remote_mac", "")
                    n_chassis = n.get("_chassis_raw", "")
                    n_pid = n.get("_port_id_raw", "")

                    if n_mac:
                        matched_detail = next((d for d in cand_list if d.get("remote_mac") == n_mac), None)
                    if not matched_detail and n_chassis:
                        matched_detail = next(
                            (d for d in cand_list if d.get("chassis_raw", "").lower() == n_chassis.lower()), None
                        )
                    if not matched_detail and n_pid:
                        matched_detail = next(
                            (d for d in cand_list if d.get("port_id", "").lower() == n_pid.lower()), None
                        )
                    if not matched_detail and len(cand_list) == 1 and summary_count_by_port.get(lp, 0) == 1:
                        matched_detail = cand_list[0]

                    if not matched_detail:
                        continue

                    if matched_detail.get("sys_name"):
                        n["remote_device"] = matched_detail["sys_name"]
                    if matched_detail.get("remote_mac") and not n.get("remote_mac"):
                        n["remote_mac"] = matched_detail["remote_mac"]
                    if matched_detail.get("remote_ip"):
                        n["remote_ip"] = matched_detail["remote_ip"]
                    if matched_detail.get("sys_descr"):
                        n["platform"] = matched_detail["sys_descr"]
                        n["remote_platform"] = matched_detail["sys_descr"]
                    if matched_detail.get("port_id") or matched_detail.get("port_descr"):
                        clean_dp, clean_dd = _pick_clean_remote_port(
                            matched_detail.get("port_id", ""),
                            "",
                            matched_detail.get("port_descr", ""),
                        )
                        if clean_dp and (
                            not n.get("remote_port")
                            or (
                                _is_clean_interface_token(clean_dp)
                                and not _is_clean_interface_token(str(n.get("remote_port") or ""))
                            )
                        ):
                            n["remote_port"] = clean_dp
                        if clean_dd and not n.get("remote_port_description"):
                            n["remote_port_description"] = clean_dd

                    n["device_type"] = _classify_procurve_neighbor(
                        platform=n.get("platform", ""),
                        remote_device=n.get("remote_device", ""),
                        capabilities=matched_detail.get("capabilities", ""),
                        remote_mac=n.get("remote_mac", ""),
                    )
            else:
                # Populate directly from detail blocks if summary table was unavailable
                for lp, dlist in detail_by_port.items():
                    for d in dlist:
                        rem_mac = d.get("remote_mac", "")
                        rem_host = d.get("sys_name") or (
                            f"MAC-{rem_mac.replace(':', '')}" if rem_mac else d.get("chassis_raw", "")
                        )
                        if not rem_host:
                            continue
                        rem_port, rem_port_desc = _pick_clean_remote_port(
                            d.get("port_id", ""), "", d.get("port_descr", "")
                        )
                        plat = d.get("sys_descr") or (oui_lookup.lookup_oui(rem_mac) if rem_mac else "")
                        neighbors.append(
                            {
                                "local_port": lp,
                                "remote_device": rem_host,
                                "remote_port": rem_port,
                                "remote_port_description": rem_port_desc,
                                "remote_ip": d.get("remote_ip", ""),
                                "remote_mac": rem_mac,
                                "platform": plat,
                                "remote_platform": plat,
                                "device_type": _classify_procurve_neighbor(
                                    platform=plat,
                                    remote_device=rem_host,
                                    capabilities=d.get("capabilities", ""),
                                    remote_mac=rem_mac,
                                ),
                            }
                        )

        # Strip internal matching metadata keys
        for n in neighbors:
            n.pop("_chassis_raw", None)
            n.pop("_port_id_raw", None)

        # 3. Supplement with CDP neighbor detail (merge/deduplicate alongside LLDP)
        try:
            raw_cdp = conn.send_command("show cdp neighbor detail")
            if isinstance(raw_cdp, str) and raw_cdp.strip() and not _is_procurve_cli_error(raw_cdp):
                cdp_entries: list[dict[str, str]] = []
                curr: dict[str, str] = {}
                for line in raw_cdp.splitlines():
                    line_s = line.strip()
                    m_port = re.match(r"^Port\s*:\s*(\S+)", line_s)
                    if m_port:
                        if curr and curr.get("local_port") and curr.get("remote_device"):
                            cdp_entries.append(curr)
                        curr = {
                            "local_port": m_port.group(1),
                            "remote_device": "",
                            "remote_port": "",
                            "remote_ip": "",
                            "remote_mac": "",
                            "platform": "",
                            "remote_platform": "",
                            "device_type": "switch",
                        }
                    if not curr:
                        continue
                    m_dev = re.match(r"^Device ID\s*:\s*(.+)$", line_s)
                    if m_dev:
                        curr["remote_device"] = m_dev.group(1).strip().split(".")[0]
                    m_rem_port = re.match(r"^Device Port\s*:\s*(.+)$", line_s)
                    if m_rem_port:
                        curr["remote_port"] = m_rem_port.group(1).strip()
                    m_addr = re.match(r"^Address\s*:\s*(\d+\.\d+\.\d+\.\d+)", line_s)
                    if m_addr:
                        curr["remote_ip"] = m_addr.group(1)
                    m_plat = re.match(r"^Platform\s*:\s*(.+)$", line_s)
                    if m_plat:
                        curr["platform"] = m_plat.group(1).strip()
                        curr["remote_platform"] = curr["platform"]
                        curr["device_type"] = _classify_procurve_neighbor(
                            platform=curr["platform"], remote_device=curr["remote_device"]
                        )
                if curr and curr.get("local_port") and curr.get("remote_device"):
                    cdp_entries.append(curr)

                for cdp_n in cdp_entries:
                    existing = None
                    c_lp = cdp_n["local_port"]
                    c_dev = cdp_n["remote_device"].lower()
                    c_rp = cdp_n["remote_port"].lower()
                    for n in neighbors:
                        if n.get("local_port") != c_lp:
                            continue
                        n_dev = str(n.get("remote_device") or "").lower().rstrip(".")
                        n_rp = str(n.get("remote_port") or "").lower()
                        if (
                            n_dev == c_dev
                            or (n_dev and c_dev.startswith(n_dev))
                            or (c_dev and n_dev.startswith(c_dev))
                            or (c_rp and n_rp and c_rp == n_rp)
                        ):
                            existing = n
                            break
                    if existing:
                        if cdp_n.get("remote_ip") and not existing.get("remote_ip"):
                            existing["remote_ip"] = cdp_n["remote_ip"]
                        if cdp_n.get("remote_port") and not existing.get("remote_port"):
                            existing["remote_port"] = cdp_n["remote_port"]
                        if cdp_n.get("platform") and (
                            not existing.get("platform") or existing.get("platform") == "Unknown"
                        ):
                            existing["platform"] = cdp_n["platform"]
                            existing["remote_platform"] = cdp_n["platform"]
                    else:
                        neighbors.append(cdp_n)
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show cdp neighbor detail failed: %s", self.ip, exc)

        return neighbors

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        cfg_low = (raw_config or "").lower()
        lldp_status = "disabled" if re.search(r"^\s*no lldp run\b", cfg_low, re.MULTILINE) else "enabled"
        cdp_status = "disabled" if re.search(r"^\s*no cdp run\b", cfg_low, re.MULTILINE) else "enabled"
        notes = ""
        if lldp_status == "disabled":
            notes = "LLDP disabled via 'no lldp run' in ProCurve configuration."
        return {"lldp": lldp_status, "cdp": cdp_status, "mndp": "unsupported", "notes": notes}

    def get_routing_table(self, conn) -> list[dict]:
        routes: list[dict] = []
        try:
            raw = conn.send_command("show ip route")
            if _is_procurve_cli_error(raw):
                logger.warning("[%s] HP ProCurve 'show ip route' returned CLI error: %s", self.ip, raw.strip()[:160])
            else:
                for line in raw.splitlines():
                    line_s = line.strip()
                    if (
                        not line_s
                        or line_s.startswith("Destination")
                        or line_s.startswith("---")
                        or "IP Route" in line_s
                    ):
                        continue
                    m = _PROCURVE_ROUTE_RE.match(line_s)
                    if not m:
                        continue
                    dest = m.group(1)
                    middle = m.group(2).strip()
                    proto = m.group(3).lower()
                    if proto == "reject" or "reject" in middle.lower() or dest.startswith("127."):
                        continue

                    m_ip_gw = re.match(r"^(\d+\.\d+\.\d+\.\d+)(?:\s+(.*))?$", middle)
                    if m_ip_gw:
                        next_hop = m_ip_gw.group(1)
                        intf = (m_ip_gw.group(2) or "").strip()
                    else:
                        next_hop = "Directly Connected"
                        m_dv = re.match(r"^DEFAULT_VLAN\s+(.+)$", middle, re.IGNORECASE)
                        if m_dv:
                            intf = m_dv.group(1).strip()
                        elif re.match(r"^VLAN\s+\d+$", middle, re.IGNORECASE):
                            intf = middle
                        else:
                            m_tail = re.search(r"\s+(VLAN\s+\d+|\d+)$", middle, re.IGNORECASE)
                            intf = m_tail.group(1).strip() if m_tail else middle

                    routes.append(
                        {
                            "subnet": dest,
                            "protocol": proto,
                            "next_hop": next_hop,
                            "interface": intf,
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show ip route failed: %s", self.ip, exc)

        # Fallback for L2-only ProCurve switches where `show ip route` is unsupported: use `show ip` Default Gateway
        if not routes:
            gw = getattr(self, "_default_gateway", "")
            if not gw:
                try:
                    raw_ip = conn.send_command("show ip")
                    if isinstance(raw_ip, str) and not _is_procurve_cli_error(raw_ip):
                        m_gw = re.search(r"Default\s+Gateway\s*:\s*(\d+\.\d+\.\d+\.\d+)", raw_ip, re.IGNORECASE)
                        if m_gw and m_gw.group(1) != "0.0.0.0":
                            gw = m_gw.group(1)
                except Exception as exc:
                    logger.warning("[%s] HP ProCurve show ip gateway fallback failed: %s", self.ip, exc)
            if gw:
                routes.append(
                    {
                        "subnet": "0.0.0.0/0",
                        "protocol": "static",
                        "next_hop": gw,
                        "interface": "",
                    }
                )
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp: list[dict] = []
        try:
            raw = conn.send_command("show arp")
            if _is_procurve_cli_error(raw):
                logger.warning("[%s] HP ProCurve 'show arp' returned CLI error: %s", self.ip, raw.strip()[:160])
                return arp
            for line in raw.splitlines():
                # 4th column (Port) is omitted on L2-only 2530/2610 models
                m_arp = re.match(
                    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+|[0-9a-fA-F:]+)\s+(\S+)(?:\s+(\S+))?",
                    line,
                )
                if m_arp:
                    ip = m_arp.group(1)
                    mac = oui_lookup.normalize_mac(m_arp.group(2)).lower()
                    if not mac or mac == _ZERO_MAC:
                        continue
                    arp_type = m_arp.group(3)
                    intf = m_arp.group(4) or ""
                    arp.append(
                        {
                            "ip": ip,
                            "mac": mac,
                            "interface": intf,
                            "age": "-",
                            "type": arp_type,
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show arp failed: %s", self.ip, exc)
        return arp

    def get_mac_table(self, conn) -> list[dict]:
        mac_table: list[dict] = []
        try:
            raw = conn.send_command("show mac-address")
            if _is_procurve_cli_error(raw):
                logger.warning("[%s] HP ProCurve 'show mac-address' returned CLI error", self.ip)
                return mac_table
            for line in raw.splitlines():
                if "MAC Address" in line or "---" in line:
                    continue
                m_mac = re.match(
                    r"^\s*([0-9a-fA-F]{6}-[0-9a-fA-F]{6}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\s+(\S+)(?:\s+(\S+))?",
                    line,
                )
                if m_mac:
                    mac = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                    if not mac or mac == _ZERO_MAC:
                        continue
                    port = m_mac.group(2)
                    vlan = m_mac.group(3) or "1"
                    mac_table.append(
                        {
                            "mac": mac,
                            "interface": port,
                            "port": port,
                            "vlan": vlan,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show mac-address failed: %s", self.ip, exc)
        return mac_table

    def get_stp(self, conn) -> dict:
        stp: dict = {
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
            raw = conn.send_command("show spanning-tree")
            if _is_procurve_cli_error(raw):
                logger.warning("[%s] HP ProCurve 'show spanning-tree' returned CLI error", self.ip)
                return stp

            m_en = re.search(r"STP\s+Enabled(?:\s*\[[^\]]+\])?\s*:\s*(Yes|No)", raw, re.IGNORECASE)
            if m_en:
                stp["enabled"] = m_en.group(1).lower() == "yes"

            m_mode = re.search(r"Mode\s*:\s*(\S+)", raw, re.IGNORECASE)
            m_force = re.search(r"Force\s+Version\s*:\s*([^\r\n]+)", raw, re.IGNORECASE)
            if m_mode:
                stp["protocol"] = m_mode.group(1).strip().upper()
            elif m_force:
                fv = m_force.group(1).strip().upper()
                if "RSTP" in fv:
                    stp["protocol"] = "RSTP"
                elif "MSTP" in fv:
                    stp["protocol"] = "MSTP"
                elif "STP" in fv:
                    stp["protocol"] = "STP"
                else:
                    stp["protocol"] = fv.split()[0]
            elif "Multiple Spanning Tree" in raw:
                stp["protocol"] = "MSTP"

            m_prio = re.search(r"Switch\s+Priority\s*:\s*(\d+)", raw, re.IGNORECASE)
            if m_prio:
                stp["bridge_priority"] = m_prio.group(1).strip()

            m_root = re.search(
                r"(?:Root\s+Bridge\s+MAC\s+Address|CST\s+Root\s+MAC\s+Address)\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)",
                raw,
            )
            m_this = re.search(r"Switch\s+MAC\s+Address\s*:\s*([0-9a-fA-F-]+|[0-9a-fA-F:]+)", raw)
            if m_root:
                stp["root_bridge"] = oui_lookup.normalize_mac(m_root.group(1)).lower()
            if m_this:
                stp["bridge_id"] = oui_lookup.normalize_mac(m_this.group(1)).lower()
            if stp["root_bridge"] and stp["bridge_id"] and stp["root_bridge"] == stp["bridge_id"]:
                stp["is_root"] = True

            m_cost = re.search(r"(?:CST\s+)?Root\s+Path\s+Cost\s*:\s*(\d+)", raw, re.IGNORECASE)
            if m_cost:
                stp["root_cost"] = m_cost.group(1).strip()
            m_rport = re.search(r"(?:CST\s+)?Root\s+Port\s*:\s*(\S+)", raw, re.IGNORECASE)
            if m_rport:
                stp["root_port"] = m_rport.group(1).strip()

            # Parse per-port CST STP table rows into stp["vlans"]["CST"]
            cst_ports: dict[str, dict] = {}
            for line in raw.splitlines():
                if "Port" in line or "---" in line:
                    continue
                m_row = re.match(
                    rf"^\s*({_PROCURVE_PORT_PAT})\s*\|\s*[^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*"
                    r"(Forwarding|Blocking|Discarding|Learning|Listening|Disabled)\b",
                    line,
                    re.IGNORECASE,
                )
                if m_row:
                    p_name, cost_s, prio_s, state = m_row.groups()
                    cst_ports[p_name] = {
                        "cost": int(cost_s),
                        "priority": int(prio_s),
                        "state": state,
                    }
            if cst_ports:
                stp["vlans"]["CST"] = {
                    "is_root": stp["is_root"],
                    "root_cost": stp["root_cost"],
                    "root_port": stp["root_port"],
                    "ports": cst_ports,
                }
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show spanning-tree failed: %s", self.ip, exc)
        return stp

    def get_running_config(self, conn) -> str:
        try:
            raw = conn.send_command("show running-config")
            if isinstance(raw, str) and raw.strip() and not _is_procurve_cli_error(raw):
                return raw
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show running-config failed, trying show config: %s", self.ip, exc)
        return self._safe_send_command(conn, "show config")

    def get_poe(self, conn) -> dict:
        from net_docu_crawler.schema import build_empty_poe_summary

        poe = build_empty_poe_summary()
        try:
            raw = conn.send_command("show power-over-ethernet brief")
            if _is_procurve_cli_error(raw):
                logger.warning("[%s] HP ProCurve 'show power-over-ethernet brief' returned CLI error", self.ip)
                return poe

            m_red = re.search(r"PoE Power Status\s*:\s*([^\r\n]+)", raw, re.IGNORECASE)
            if m_red:
                poe["psu_redundancy"] = m_red.group(1).strip()

            # Parse chassis-level summary appearing before any "Module X Power" section
            pre_module = re.split(r"(?m)^\s*Module\s+\S+\s+Power", raw, maxsplit=1)[0]
            m_chassis = re.search(
                r"Available:\s*([\d.]+)\s*W\s+Used:\s*([\d.]+)\s*W\s+Remaining:\s*([\d.]+)\s*W",
                pre_module,
                re.IGNORECASE,
            )
            if m_chassis:
                poe["poe_supported"] = True
                poe["total_power_watts"] = float(m_chassis.group(1))
                poe["used_power_watts"] = float(m_chassis.group(2))
                poe["available_power_watts"] = float(m_chassis.group(3))
            else:
                m_tot = re.search(r"Total Available Power\s*:\s*([\d.]+)\s*W", pre_module, re.IGNORECASE)
                m_used = re.search(r"Total Power Drawn\s*:\s*([\d.]+)\s*W", pre_module, re.IGNORECASE)
                if m_tot:
                    poe["poe_supported"] = True
                    poe["total_power_watts"] = float(m_tot.group(1))
                if m_used:
                    poe["used_power_watts"] = float(m_used.group(1))
                poe["available_power_watts"] = max(0.0, poe["total_power_watts"] - poe["used_power_watts"])

            # Parse per-module power budgets on modular 5406zl/5412zl/5400R chassis
            module_budgets: dict[str, dict[str, float]] = {}
            for m_mod in re.finditer(
                r"Module\s+([A-Za-z0-9]+)\s+Power[^\n]*\n\s*"
                r"Available:\s*([\d.]+)\s*W\s+Used:\s*([\d.]+)\s*W\s+Remaining:\s*([\d.]+)\s*W",
                raw,
                re.IGNORECASE,
            ):
                mod_id = m_mod.group(1).upper()
                module_budgets[mod_id] = {
                    "total_power_watts": float(m_mod.group(2)),
                    "used_power_watts": float(m_mod.group(3)),
                    "available_power_watts": float(m_mod.group(4)),
                }
            if module_budgets:
                poe["module_budgets"] = module_budgets
                poe["poe_supported"] = True

            alloc_total = 0.0
            capable_cnt = 0
            enabled_cnt = 0
            delivering_cnt = 0
            for line in raw.splitlines():
                # Matches both pipe-delimited (YA/K) and non-pipe (WB.16.10) PoE port rows,
                # with 2 or 3 intermediate columns (`Priority [Pre-std] AllocBy`).
                m_p = re.match(
                    rf"^\s*({_PROCURVE_PORT_PAT})\s*(?:\|\s*|\s+)(Yes|No)\s+"
                    r"(?:\S+\s+){2,3}([\d.]+)\s*W\s+([\d.]+)\s*W\s*(.*?)\s+"
                    r"(Delivering|Searching|Disabled|Fault|Other Fault)\s+(\d+)",
                    line,
                    re.IGNORECASE,
                )
                if m_p:
                    port, enabled_s, alloc_s, actual_s, _ctype, det_status, p_cls = m_p.groups()
                    enabled_b = enabled_s.lower() == "yes"
                    alloc_w = float(alloc_s)
                    actual_w = float(actual_s)
                    det_l = det_status.lower()
                    capable_cnt += 1
                    if enabled_b:
                        enabled_cnt += 1
                    if det_l == "delivering" or actual_w > 0:
                        delivering_cnt += 1
                        alloc_total += alloc_w
                    poe["ports"][port] = {
                        "status": det_l,
                        "enabled": enabled_b,
                        "power_watts": actual_w,
                        "draw_watts": actual_w,
                        "allocated_watts": alloc_w,
                        "class": p_cls,
                    }
                else:
                    m_short = re.match(
                        rf"^\s*({_PROCURVE_PORT_PAT})\s*(?:\|\s*|\s+)(Yes|No)\b.*?([\d.]+)\s*W",
                        line,
                        re.IGNORECASE,
                    )
                    if m_short:
                        port, enabled_s, watts = m_short.groups()
                        enabled_b = enabled_s.lower() == "yes"
                        w_val = float(watts)
                        capable_cnt += 1
                        if enabled_b:
                            enabled_cnt += 1
                        if w_val > 0:
                            delivering_cnt += 1
                        poe["ports"][port] = {
                            "status": "delivering" if w_val > 0 else "searching",
                            "enabled": enabled_b,
                            "power_watts": w_val,
                            "draw_watts": w_val,
                            "allocated_watts": w_val,
                            "class": "",
                        }

            # If `brief` omitted chassis-level budget (e.g., 5412zl), query `show power-over-ethernet`
            if poe["total_power_watts"] == 0.0 and (capable_cnt > 0 or module_budgets):
                try:
                    raw_sys_poe = conn.send_command("show power-over-ethernet")
                    if isinstance(raw_sys_poe, str) and raw_sys_poe.strip() and not _is_procurve_cli_error(raw_sys_poe):
                        m_tot = re.search(r"Total\s+Available\s+Power\s*:\s*([\d.]+)\s*W", raw_sys_poe, re.IGNORECASE)
                        m_used = re.search(r"Total\s+Power\s+Drawn\s*:\s*([\d.]+)\s*W", raw_sys_poe, re.IGNORECASE)
                        m_ch2 = re.search(
                            r"Available:\s*([\d.]+)\s*W\s+Used:\s*([\d.]+)\s*W\s+Remaining:\s*([\d.]+)\s*W",
                            raw_sys_poe,
                            re.IGNORECASE,
                        )
                        if m_tot:
                            poe["total_power_watts"] = float(m_tot.group(1))
                            if m_used:
                                poe["used_power_watts"] = float(m_used.group(1))
                            poe["available_power_watts"] = max(
                                0.0, round(poe["total_power_watts"] - poe["used_power_watts"], 2)
                            )
                        elif m_ch2:
                            poe["total_power_watts"] = float(m_ch2.group(1))
                            poe["used_power_watts"] = float(m_ch2.group(2))
                            poe["available_power_watts"] = float(m_ch2.group(3))
                except Exception as exc:
                    logger.warning("[%s] HP ProCurve show power-over-ethernet fallback failed: %s", self.ip, exc)

                if poe["total_power_watts"] == 0.0 and module_budgets:
                    poe["total_power_watts"] = round(sum(m["total_power_watts"] for m in module_budgets.values()), 2)
                    poe["used_power_watts"] = round(sum(m["used_power_watts"] for m in module_budgets.values()), 2)
                    poe["available_power_watts"] = round(
                        sum(m["available_power_watts"] for m in module_budgets.values()), 2
                    )

            poe["poe_capable_ports"] = capable_cnt
            poe["poe_enabled_ports"] = enabled_cnt
            poe["poe_delivering_ports"] = delivering_cnt
            poe["allocated_power_watts"] = round(alloc_total, 2)
            if capable_cnt > 0:
                poe["poe_supported"] = True
            if poe["total_power_watts"] == 0.0 and delivering_cnt > 0:
                poe["budget_unreported"] = True
                if poe["used_power_watts"] == 0.0:
                    poe["used_power_watts"] = round(sum(p.get("draw_watts", 0.0) for p in poe["ports"].values()), 2)
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show power-over-ethernet brief failed: %s", self.ip, exc)
        return poe

    def get_optics(self, conn) -> list[dict]:
        optics: list[dict] = []
        try:
            raw = conn.send_command("show interfaces transceiver")
            if _is_procurve_cli_error(raw):
                logger.warning("[%s] HP ProCurve 'show interfaces transceiver' returned CLI error", self.ip)
                return optics
            for line in raw.splitlines():
                if not line.strip() or "---" in line or "Port" in line or "Transceiver" in line:
                    continue
                m_opt = re.match(
                    rf"^\s*({_PROCURVE_PORT_PAT})\s+(\S+)\s+([A-Za-z0-9-]+)(?:\s+([A-Za-z0-9-]+))?",
                    line,
                )
                if m_opt:
                    xtype = m_opt.group(2)
                    if xtype.lower() in ("none", "absent", "not", "--"):
                        continue
                    optics.append(
                        {
                            "port": m_opt.group(1),
                            "type": xtype,
                            "part_number": m_opt.group(3),
                            "serial": m_opt.group(4) or "",
                            "status": "present",
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show interfaces transceiver failed: %s", self.ip, exc)
        return optics

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        try:
            raw_trunks = conn.send_command("show trunks")
            if isinstance(raw_trunks, str) and raw_trunks and not _is_procurve_cli_error(raw_trunks):
                for line in raw_trunks.splitlines():
                    m_tr = re.match(
                        rf"^\s*({_PROCURVE_PORT_PAT})\s+\|.*?\b(Trk\d+)\s+(LACP|Trunk|Dyn\d*)",
                        line,
                        re.I,
                    )
                    if m_tr:
                        p, grp, proto = m_tr.group(1), m_tr.group(2), m_tr.group(3)
                        ops.setdefault(p, {})["lag_group"] = grp
                        ops[p]["lacp_mode"] = "active" if "lacp" in proto.lower() else "on"
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show trunks failed: %s", self.ip, exc)

        try:
            raw_lacp = conn.send_command("show lacp")
            if isinstance(raw_lacp, str) and raw_lacp and not _is_procurve_cli_error(raw_lacp):
                for line in raw_lacp.splitlines():
                    m_lc = re.match(rf"^\s*({_PROCURVE_PORT_PAT})\s+(Trk\d+)\s+.*?(Active|Passive)", line, re.I)
                    if m_lc:
                        p, grp, mode = m_lc.group(1), m_lc.group(2), m_lc.group(3).lower()
                        ops.setdefault(p, {})["lag_group"] = grp
                        ops[p]["lacp_mode"] = mode
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show lacp failed: %s", self.ip, exc)

        # Prefer `show vlans ports all detail`, falling back to `show vlans ports all`
        raw_vp = ""
        for vlan_cmd in ("show vlans ports all detail", "show vlans ports all"):
            try:
                cand = conn.send_command(vlan_cmd)
                if isinstance(cand, str) and cand.strip() and not _is_procurve_cli_error(cand):
                    if re.search(r"Port\s+name\s*:|VLAN\s+Information\s*-\s*for\s+ports", cand, re.I):
                        raw_vp = cand
                        break
            except Exception as exc:
                logger.warning("[%s] HP ProCurve '%s' failed: %s", self.ip, vlan_cmd, exc)

        if raw_vp:
            port_vlans: dict[str, dict] = {}
            cur_port = ""
            for line in raw_vp.splitlines():
                m_ph = re.match(r"^\s*Port\s+name\s*:\s*(\S+)", line, re.I) or re.search(
                    r"VLAN\s+Information\s*-\s*for\s+ports\s+(\S+)", line, re.I
                )
                if m_ph:
                    cur_port = m_ph.group(1).strip()
                    port_vlans.setdefault(cur_port, {"tagged": [], "untagged": "", "voice": set()})
                    continue
                if not cur_port:
                    continue
                m_vr = re.match(
                    r"^\s*(\d{1,4})\s+.*\|\s+\S+\s+(Yes|No)\s+(?:Yes|No)\s+(Tagged|Untagged)\b",
                    line,
                    re.I,
                )
                if not m_vr:
                    m_vr_simple = re.match(r"^\s*(\d{1,4})\s+\S+.*?\b(Tagged|Untagged)\b", line, re.I)
                    if m_vr_simple:
                        vid, mode_tok = m_vr_simple.group(1), m_vr_simple.group(2).lower()
                        is_voice = False
                    else:
                        continue
                else:
                    vid, voice_tok, mode_tok = m_vr.group(1), m_vr.group(2).lower(), m_vr.group(3).lower()
                    is_voice = voice_tok == "yes"

                pv = port_vlans[cur_port]
                if is_voice:
                    pv["voice"].add(vid)
                if mode_tok == "tagged":
                    if vid not in pv["tagged"]:
                        pv["tagged"].append(vid)
                else:
                    pv["untagged"] = vid

            for port, pv in port_vlans.items():
                tagged = pv["tagged"]
                untagged = pv["untagged"]
                non_voice_tagged = [v for v in tagged if v not in pv["voice"]]
                if non_voice_tagged:
                    all_active = sorted(set(tagged) | ({untagged} if untagged else set()), key=int)
                    rec = ops.setdefault(port, {})
                    rec["mode"] = "trunk"
                    rec["oper_mode"] = "trunk"
                    rec["encapsulation"] = "dot1q"
                    rec["trunk_active_vlans"] = ",".join(all_active)
                    rec["native_vlan"] = untagged or "none"
                    rec["native_vlan_tagged"] = not bool(untagged)
                elif untagged:
                    rec = ops.setdefault(port, {})
                    rec["mode"] = "access"
                    rec["oper_mode"] = "access"
                    rec["encapsulation"] = "dot1q"
                    rec["access_vlan"] = untagged
                    rec["native_vlan_tagged"] = False

        # Parse both real Provision KV blocks AND pipe-delimited `show spanning-tree detail`
        try:
            raw_stp = conn.send_command("show spanning-tree detail")
            if isinstance(raw_stp, str) and raw_stp and not _is_procurve_cli_error(raw_stp):
                cur_stp_port = ""
                for line in raw_stp.splitlines():
                    stripped = line.strip()
                    m_kv_port = re.match(rf"^Port\s*:\s*({_PROCURVE_PORT_PAT})\b", stripped, re.I)
                    if m_kv_port:
                        cur_stp_port = m_kv_port.group(1)
                        ops.setdefault(cur_stp_port, {})
                        continue
                    if cur_stp_port:
                        m_bpdu = re.match(r"^BPDU\s+Protection\s*:\s*(Yes|No|Enabled|Disabled)", stripped, re.I)
                        if m_bpdu:
                            ops[cur_stp_port]["bpdu_guard"] = m_bpdu.group(1).lower() in ("yes", "enabled")
                            continue
                        m_edge = re.match(r"^(?:OperEdgePort|AdminEdgePort)\s*:\s*(Yes|No)", stripped, re.I)
                        if m_edge:
                            if m_edge.group(1).lower() == "yes":
                                ops[cur_stp_port]["portfast"] = True
                            elif "portfast" not in ops[cur_stp_port]:
                                ops[cur_stp_port]["portfast"] = False
                            continue
                        m_pst = re.match(r"^Port\s+State\s*:\s*(\S+)", stripped, re.I)
                        if m_pst:
                            ops[cur_stp_port]["stp_state"] = m_pst.group(1)
                            continue
                        m_prole = re.match(r"^Port\s+Role\s*:\s*(\S+)", stripped, re.I)
                        if m_prole:
                            ops[cur_stp_port]["stp_role"] = m_prole.group(1)
                            continue

                    m_st = re.match(
                        rf"^\s*({_PROCURVE_PORT_PAT})\s+\|\s+(?:100Mb|1Gb|10Gb|\S+)\s+\|\s+\d+\s+\|\s+(\S+)\s+\|\s+(\S+)",
                        line,
                    )
                    if m_st:
                        p, state, role = m_st.group(1), m_st.group(2), m_st.group(3)
                        ops.setdefault(p, {})["stp_state"] = state
                        ops[p]["stp_role"] = role
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show spanning-tree detail failed: %s", self.ip, exc)

        try:
            raw_auth = conn.send_command("show port-access authenticator")
            if isinstance(raw_auth, str) and raw_auth and not _is_procurve_cli_error(raw_auth):
                for line in raw_auth.splitlines():
                    m_au = re.match(rf"^\s*({_PROCURVE_PORT_PAT})\s+(?:Enabled|Active)", line, re.I)
                    if m_au:
                        ops.setdefault(m_au.group(1), {})["auth_policy"] = "dot1x"
        except Exception as exc:
            logger.warning("[%s] HP ProCurve show port-access authenticator failed: %s", self.ip, exc)

        return ops

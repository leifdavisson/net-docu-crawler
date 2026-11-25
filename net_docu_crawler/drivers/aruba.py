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
Aruba Networks / HPE Driver: Aruba Instant AP (IAP) clusters & ArubaOS-CX switches.
Official Documentation:
- Aruba Instant: https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm
- Aruba AOS-CX: https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm
"""

import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_ARUBA_CLI_ERROR_RE = re.compile(
    r"(?:invalid input|unknown command|incomplete command|command not supported|"
    r"ambiguous command|unrecognized command|^\s*%\s)",
    re.IGNORECASE | re.MULTILINE,
)
_MAC_TOKEN_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$|^(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ZERO_MAC = "00:00:00:00:00:00"
_AOSCX_ROUTE_ORIGINS = {
    "c": "connected",
    "s": "static",
    "l": "local",
    "o": "ospf",
    "b": "bgp",
    "r": "rip",
}


def _is_aruba_cli_error(raw: str) -> bool:
    """Return True if Aruba IAP or AOS-CX CLI output indicates a syntax or unsupported command error."""
    return bool(raw and _ARUBA_CLI_ERROR_RE.search(raw))


def _normalize_aruba_speed(raw_speed: str) -> str:
    """Normalize AOS-CX/IAP numeric speed (Mb/s) to canonical label such as '1Gb/s' or '10Gb/s'."""
    tok = (raw_speed or "").strip().lower()
    if not tok or tok in ("--", "-", "n/a", "auto"):
        return "N/A"
    m = re.match(r"^(\d+)(?:\s*(mb/s|mbps|gb/s|gbps|m|g))?$", tok)
    if not m:
        return "N/A"
    val = int(m.group(1))
    unit = m.group(2) or ""
    if unit.startswith("g"):
        return f"{val}Gb/s"
    if val >= 1000:
        return f"{val // 1000}Gb/s" if val % 1000 == 0 else f"{val / 1000:g}Gb/s"
    if val > 0:
        return f"{val}Mb/s"
    return "N/A"


def _classify_lldp_device_type(
    capabilities: str = "", platform: str = "", remote_device: str = "", remote_mac: str = ""
) -> str:
    """Infer neighbor device_type from LLDP capabilities, platform description, and OUI vendor."""
    caps_low = (capabilities or "").lower()
    plat_low = (platform or "").lower()
    name_low = (remote_device or "").lower()
    vendor_low = (oui_lookup.lookup_oui(remote_mac) if remote_mac else "").lower()

    if any(k in caps_low for k in ("wlan", "access point")) or any(
        k in plat_low for k in ("instant", "access point", "aironet", "unifi ap", "fortiap", "ruckus", "meraki mr")
    ):
        return "ap"
    if any(k in caps_low for k in ("telephone", "phone")) or any(
        k in plat_low for k in ("ip phone", "polycom", "yealink", "avaya", "mitel")
    ):
        return "phone"
    if any(k in plat_low for k in ("camera", "axis ", "hikvision", "verkada")):
        return "camera"
    if any(k in plat_low for k in ("fortigate", "palo alto", "pan-os", "opnsense", "pfsense", "srx", "firewall")):
        return "firewall"
    if "router" in caps_low and "bridge" not in caps_low and "switch" not in plat_low:
        return "router"
    if not plat_low and any(k in vendor_low for k in ("aruba", "ruckus", "mist", "cambium")):
        if name_low.startswith(("ap", "iap")) or "ap-" in name_low or "-ap" in name_low:
            return "ap"
    return "switch"


class ArubaDriver(BaseDriver):
    vendor_name = "Aruba Networks / HPE"
    device_persona = "ap"
    default_device_type = "ap"
    supports_telnet = False
    paging_cmd = "no page"

    def connect(self):
        device = self._build_netmiko_params("aruba_os", secret=self.secret, global_delay_factor=2)
        return self.connect_netmiko(device)

    def _ensure_aoscx_no_paging(self, conn) -> None:
        """Disable AOS-CX interactive paging once per driver instance (ArubaOsSSH only sends 'no paging')."""
        if not getattr(self, "_aoscx_paging_disabled", False):
            self._aoscx_paging_disabled = True
            self._safe_send_command(conn, "no page")

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Aruba AP",
            "serial": "Unknown",
            "firmware": "ArubaOS",
            "os_type": "aruba_os",
            "device_persona": self.device_persona,
        }
        sh_ver = getattr(self, "_prefetched_sh_ver", None)
        if sh_ver is not None:
            self._prefetched_sh_ver = None
            raw = sh_ver
        else:
            try:
                raw = conn.send_command("show version")
            except Exception as exc:
                logger.warning("[%s] Aruba show version failed: %s", self.ip, exc)
                raw = ""
        raw_str = raw if isinstance(raw, str) else ""
        if _is_aruba_cli_error(raw_str):
            logger.warning("[%s] Aruba 'show version' returned CLI error: %s", self.ip, raw_str.strip()[:160])

        # Detect Aruba AOS-CX switch platform (`ArubaOS-CX` / `AOS-CX`)
        if re.search(r"ArubaOS-CX|AOS-CX", raw_str, re.IGNORECASE):
            self._is_aoscx = True
            self._ensure_aoscx_no_paging(conn)
            info["device_persona"] = "switch"
            info["device_type"] = "switch"
            info["os_type"] = "aruba_aoscx"
            info["model"] = "Aruba AOS-CX Switch"
            info["firmware"] = "ArubaOS-CX"

            m_ver = re.search(r"Version\s*:\s*(\S+)", raw_str, re.IGNORECASE)
            if m_ver:
                info["firmware"] = m_ver.group(1).strip()
            m_prod = re.search(r"(?:Product Name|Model|Chassis)\s*:\s*(.+)", raw_str, re.IGNORECASE)
            if m_prod:
                info["model"] = m_prod.group(1).strip()
            m_ser = re.search(r"(?:Chassis\s+)?Serial\s+(?:Number|Nbr)\s*:\s*(\S+)", raw_str, re.IGNORECASE)
            if m_ser:
                info["serial"] = m_ser.group(1).strip()
            m_mac = re.search(r"(?:Base\s+)?MAC\s+Address\s*:\s*([0-9a-fA-F:.-]+)", raw_str, re.IGNORECASE)
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()

            try:
                raw_sys = conn.send_command("show system")
                if isinstance(raw_sys, str) and raw_sys.strip() and not _is_aruba_cli_error(raw_sys):
                    m_host = re.search(r"Hostname\s*:\s*(\S+)", raw_sys, re.IGNORECASE)
                    if m_host:
                        info["hostname"] = m_host.group(1).strip()
                    if info["model"] == "Aruba AOS-CX Switch":
                        m_p2 = re.search(r"Product\s+Name\s*:\s*(.+)", raw_sys, re.IGNORECASE)
                        if m_p2:
                            info["model"] = m_p2.group(1).strip()
                    if info["serial"] == "Unknown":
                        m_s2 = re.search(r"(?:Chassis\s+)?Serial\s+(?:Number|Nbr)\s*:\s*(\S+)", raw_sys, re.IGNORECASE)
                        if m_s2:
                            info["serial"] = m_s2.group(1).strip()
                    if not info.get("mac_address"):
                        m_m2 = re.search(r"(?:Base\s+)?MAC\s+Address\s*:\s*([0-9a-fA-F:.-]+)", raw_sys, re.IGNORECASE)
                        if m_m2:
                            info["mac_address"] = oui_lookup.normalize_mac(m_m2.group(1)).lower()
                elif isinstance(raw_sys, str) and _is_aruba_cli_error(raw_sys):
                    logger.warning("[%s] Aruba AOS-CX 'show system' returned CLI error", self.ip)
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show system failed: %s", self.ip, exc)

            if not info["hostname"]:
                prompt = self._safe_find_prompt(conn)
                if prompt:
                    info["hostname"] = prompt.replace("#", "").replace(">", "").strip()
            return info

        self._is_aoscx = False
        self._ap_hostname = ""
        self._ap_member_ip = ""
        self._swarm_lldp: dict[str, list[dict]] = {}

        m_model = re.search(r"MODEL:\s*(\w+)", raw_str)
        if m_model:
            info["model"] = f"Aruba AP-{m_model.group(1)}"
        m_ver = re.search(r"Version\s*(\S+)", raw_str)
        if m_ver:
            info["firmware"] = m_ver.group(1)

        prompt = self._safe_find_prompt(conn)
        if prompt:
            info["hostname"] = prompt.replace("#", "").replace(">", "").strip()

        # Query AP cluster details if IAP (`show aps` returns full swarm roster on Virtual Controller)
        swarm_aps: list[dict] = []
        try:
            raw_aps = conn.send_command("show aps")
            if isinstance(raw_aps, str) and not _is_aruba_cli_error(raw_aps):
                for line in raw_aps.splitlines():
                    # Anchor on IPv4 token so AP names containing spaces parse accurately
                    m_ap = re.match(r"^\s*(.+?)\s+(\d{1,3}(?:\.\d{1,3}){3}\*?)\s+(.+)$", line)
                    if m_ap:
                        ap_name = m_ap.group(1).strip()
                        ip_tok = m_ap.group(2)
                        rest_parts = m_ap.group(3).split()
                        if len(rest_parts) >= 8 and ap_name.lower() != "name":
                            is_master = ip_tok.endswith("*")
                            ap_ip = ip_tok.rstrip("*")
                            ap_serial = rest_parts[7] if rest_parts[7] not in ("-", "--") else "Unknown"
                            swarm_aps.append(
                                {
                                    "name": ap_name,
                                    "ip": ap_ip,
                                    "serial": ap_serial,
                                    "is_master": is_master,
                                }
                            )
            elif isinstance(raw_aps, str) and _is_aruba_cli_error(raw_aps):
                logger.warning("[%s] Aruba IAP 'show aps' returned CLI error", self.ip)
        except Exception as exc:
            logger.warning("[%s] Aruba show aps failed: %s", self.ip, exc)

        if swarm_aps:
            info["swarm_aps"] = swarm_aps
            matched = next((a for a in swarm_aps if a["ip"] == self.ip), None)
            if not matched and info["hostname"]:
                matched = next((a for a in swarm_aps if a["name"].lower() == info["hostname"].lower()), None)
            if not matched:
                matched = next((a for a in swarm_aps if a["is_master"]), None)
            if matched:
                info["hostname"] = matched["name"]
                if matched["serial"] != "Unknown":
                    info["serial"] = matched["serial"]
                self._ap_member_ip = matched["ip"]

        self._ap_hostname = info["hostname"]
        return info

    def crawl(self, conn) -> dict:
        sh_ver = self._safe_send_command(conn, "show version")
        if re.search(
            r"Image\s+stamp\s*:|ProCurve|\b(?:WB|WC|YA|YB|YC|KB|KA|RA|K|R|T|N|M|Q|W)\.\d{2}\.\d{2}\b",
            sh_ver,
            re.IGNORECASE,
        ):
            from net_docu_crawler.drivers.hpprocurve import HPProCurveDriver, _CleanProCurveConn

            logger.info("[%s] Detected ArubaOS-S / ProCurve in ArubaDriver; delegating to HPProCurveDriver.", self.ip)
            clean_conn = conn if isinstance(conn, _CleanProCurveConn) else _CleanProCurveConn(conn)
            self._safe_send_command(clean_conn, "no page")
            procurve_drv = HPProCurveDriver(
                ip=self.ip,
                username=self.username,
                password=self.password,
                secret=self.secret,
                timeout=self.timeout,
                session_log=self.session_log,
                port=self.port,
                transport=self.transport,
            )
            return procurve_drv.crawl(clean_conn)

        self._prefetched_sh_ver = sh_ver
        data = super().crawl(conn)
        if getattr(self, "_swarm_lldp", None):
            data["swarm_lldp"] = self._swarm_lldp
        return data

    def get_interfaces(self, conn) -> tuple[list, dict]:
        if getattr(self, "_is_aoscx", False):
            l3_interfaces: list[dict] = []
            interfaces_detail: dict[str, dict] = {}
            try:
                raw_ip = conn.send_command("show ip interface brief")
                if isinstance(raw_ip, str) and _is_aruba_cli_error(raw_ip):
                    logger.warning("[%s] Aruba AOS-CX 'show ip interface brief' returned CLI error", self.ip)
                else:
                    for line in (raw_ip if isinstance(raw_ip, str) else "").splitlines():
                        # Supports both 4-col (`vlan10 10.0.0.1/24 up up`) and 5-col with VRF
                        m_ip = re.match(
                            r"^\s*([A-Za-z0-9/._-]+)\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"
                            r"(?:\S+\s+)?(up|down)\s+(up|down)\b",
                            line,
                            re.IGNORECASE,
                        )
                        if m_ip:
                            intf_n, ip_v, st_a, st_p = m_ip.groups()
                            if not ip_v.startswith("127."):
                                l3_interfaces.append(
                                    {
                                        "interface": intf_n,
                                        "ip_address": ip_v,
                                        "status": st_a.lower(),
                                        "protocol": st_p.lower(),
                                    }
                                )
                                interfaces_detail[intf_n] = {
                                    "ip_address": ip_v,
                                    "status": st_p.lower(),
                                    "protocol": st_p.lower(),
                                    "mac_address": "",
                                    "description": "",
                                    "speed": "N/A",
                                    "duplex": "N/A",
                                }
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show ip interface brief failed: %s", self.ip, exc)

            try:
                raw_br = conn.send_command("show interface brief")
                if isinstance(raw_br, str) and _is_aruba_cli_error(raw_br):
                    logger.warning("[%s] Aruba AOS-CX 'show interface brief' returned CLI error", self.ip)
                else:
                    for line in (raw_br if isinstance(raw_br, str) else "").splitlines():
                        # Real AOS-CX 9-column format:
                        # `1/1/1  10  access  1GbT  yes  up  --  1000  AP-Lobby`
                        m_real = re.match(
                            r"^\s*(\d+/\d+/\d+(?::\d+)?|lag\d+|vlan\d+)\s+\S+\s+\S+\s+\S+\s+"
                            r"(?:yes|no)\s+(up|down)\s*(.*)$",
                            line,
                            re.IGNORECASE,
                        )
                        if m_real:
                            p_name = m_real.group(1)
                            p_st = m_real.group(2).lower()
                            tail = m_real.group(3).strip()
                            speed = "N/A"
                            desc = ""
                            if tail:
                                cols = re.split(r"\s{2,}", tail)
                                if len(cols) >= 3:
                                    speed = _normalize_aruba_speed(cols[1])
                                    desc = "" if cols[2] in ("--", "-") else cols[2].strip()
                                elif len(cols) == 2:
                                    speed = _normalize_aruba_speed(cols[1])
                                else:
                                    toks = tail.split()
                                    if len(toks) >= 2:
                                        speed = _normalize_aruba_speed(toks[-2])
                                        if toks[-1] not in ("--", "-"):
                                            desc = toks[-1]
                            rec = interfaces_detail.setdefault(
                                p_name,
                                {
                                    "ip_address": "",
                                    "status": p_st,
                                    "protocol": p_st,
                                    "mac_address": "",
                                    "description": desc,
                                    "speed": speed,
                                    "duplex": "N/A",
                                },
                            )
                            rec["status"] = p_st
                            rec["protocol"] = p_st
                            if speed != "N/A":
                                rec["speed"] = speed
                            if desc and not rec.get("description"):
                                rec["description"] = desc
                            continue

                        # Legacy 5-column mock fallback: `1/1/1  10  access  1GbT  up`
                        m_br = re.match(
                            r"^\s*(\d+/\d+/\d+(?::\d+)?|lag\d+|vlan\d+)\s+\S+\s+\S+\s+\S+\s+(up|down)\b",
                            line,
                            re.IGNORECASE,
                        )
                        if m_br:
                            p_name, p_st = m_br.group(1), m_br.group(2).lower()
                            interfaces_detail.setdefault(
                                p_name,
                                {
                                    "ip_address": "",
                                    "status": p_st,
                                    "protocol": p_st,
                                    "mac_address": "",
                                    "description": "",
                                    "speed": "N/A",
                                    "duplex": "N/A",
                                },
                            )
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show interface brief failed: %s", self.ip, exc)
            return l3_interfaces, interfaces_detail

        # Aruba Instant AP: never fabricate 1Gb/s Full speed/duplex without real operational telemetry
        l3_interfaces = [{"interface": "br0", "ip_address": self.ip, "status": "up", "protocol": "up"}]
        member_ip = getattr(self, "_ap_member_ip", "")
        if member_ip and member_ip != self.ip:
            l3_interfaces.append({"interface": "br0", "ip_address": member_ip, "status": "up", "protocol": "up"})
        interfaces_detail = {
            "eth0": {
                "status": "up",
                "protocol": "up",
                "description": "Uplink to Switch",
                "mac_address": "",
                "speed": "N/A",
                "duplex": "N/A",
            }
        }
        return l3_interfaces, interfaces_detail

    @staticmethod
    def _parse_aoscx_lldp_detail(raw: str) -> list[dict]:
        """Parse ArubaOS-CX `show lldp neighbor-info detail` key-value blocks."""
        neighbors: list[dict] = []
        current: dict[str, str] = {}
        current_caps = ""

        def _flush() -> None:
            if not current.get("local_port") or not (current.get("remote_device") or current.get("remote_mac")):
                return
            if not current["remote_device"]:
                current["remote_device"] = current["remote_mac"]
            if not current["platform"] and current["remote_mac"]:
                vendor = oui_lookup.lookup_oui(current["remote_mac"])
                if vendor and vendor != "Unknown":
                    current["platform"] = vendor
                    current["remote_platform"] = vendor
            current["device_type"] = _classify_lldp_device_type(
                capabilities=current_caps,
                platform=current["platform"],
                remote_device=current["remote_device"],
                remote_mac=current["remote_mac"],
            )
            neighbors.append(dict(current))

        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            m_port = re.match(r"^(?:Local\s+)?Port\s*:\s*(\S+)", line, re.IGNORECASE)
            if m_port:
                _flush()
                current = {
                    "local_port": m_port.group(1).strip(),
                    "remote_device": "",
                    "remote_port": "",
                    "remote_ip": "",
                    "remote_mac": "",
                    "platform": "",
                    "remote_platform": "",
                    "device_type": "switch",
                }
                current_caps = ""
                continue
            if not current:
                continue

            m_kv = re.match(r"^([^:]+?)\s*:\s*(.*)$", line)
            if not m_kv:
                continue
            key = re.sub(r"[\s_-]+", " ", m_kv.group(1).strip().lower())
            val = m_kv.group(2).strip()
            if not val:
                continue

            if key in ("chassis id", "neighbor chassis id"):
                if _MAC_TOKEN_RE.match(val):
                    norm = oui_lookup.normalize_mac(val).lower()
                    if norm and norm != _ZERO_MAC:
                        current["remote_mac"] = norm
                if not current["remote_device"]:
                    current["remote_device"] = val
            elif key in ("neighbor system name", "system name"):
                if "." in val and not _IPV4_RE.match(val) and not _MAC_TOKEN_RE.match(val):
                    val = val.split(".", 1)[0]
                current["remote_device"] = val
            elif key in ("port id", "neighbor port id"):
                current["remote_port"] = val
            elif key in ("neighbor management address", "management address", "mgmt address"):
                m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", val)
                if m_ip:
                    current["remote_ip"] = m_ip.group(1)
            elif key in ("neighbor system description", "system description"):
                desc = val[:80]
                current["platform"] = desc
                current["remote_platform"] = desc
            elif key in ("neighbor capabilities", "system capabilities", "capabilities enabled"):
                current_caps = val

        _flush()
        return neighbors

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []
        if getattr(self, "_is_aoscx", False):
            try:
                raw_cx = conn.send_command("show lldp neighbor-info detail")
                raw_str = raw_cx if isinstance(raw_cx, str) else ""
                if _is_aruba_cli_error(raw_str):
                    logger.warning("[%s] Aruba AOS-CX 'show lldp neighbor-info detail' returned CLI error", self.ip)
                    return neighbors
                neighbors = self._parse_aoscx_lldp_detail(raw_str)
                if not neighbors and raw_str.strip():
                    import parser as cli_parser

                    for n in cli_parser.parse_lldp_neighbors_detail(raw_str):
                        n["remote_platform"] = n.get("platform", "")
                        neighbors.append(n)
                if neighbors:
                    self._discovery_protocols = {
                        "lldp": "enabled",
                        "cdp": "unsupported",
                        "mndp": "unsupported",
                        "notes": "",
                    }
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show lldp neighbor-info detail failed: %s", self.ip, exc)
            return neighbors

        swarm_lldp: dict[str, list[dict]] = {}
        target_ap = (getattr(self, "_ap_hostname", "") or "").strip().lower()
        try:
            raw = conn.send_command("show ap debug lldp info")
            if isinstance(raw, str) and _is_aruba_cli_error(raw):
                logger.warning("[%s] Aruba IAP 'show ap debug lldp info' returned CLI error", self.ip)
            elif isinstance(raw, str):
                for line in raw.splitlines():
                    stripped = line.strip()
                    if (
                        not stripped
                        or stripped.lower().startswith(("swarm ap", "ap name"))
                        or set(stripped) <= {"-", " "}
                    ):
                        continue
                    # Anchor on local AP interface (eth0/bond0/ge...) so AP names with spaces parse accurately
                    m = re.match(
                        r"^\s*(.+?)\s+(eth\d+|bond\d+|br\d+|ge\S+)\s+([0-9a-fA-F:.-]{12,17})\s+(\S+)\s+.*?"
                        r"\b([0-9a-fA-F:]{17})\s+(\S+)(?:\s+(.+))?$",
                        line,
                    )
                    if not m:
                        m = re.match(
                            r"^\s*(\S+)\s+(\S+)\s+([0-9a-fA-F:.-]{12,17})\s+(\S+)\s+.*?"
                            r"\b([0-9a-fA-F:]{17})\s+(\S+)(?:\s+(.+))?$",
                            line,
                        )
                    if m:
                        ap_name, local_port, _nbr_id, rem_port_raw, rem_basemac, rem_host, cap = m.groups()
                        ap_name = ap_name.strip()
                        rem_intf = re.sub(r"\.0$", "", rem_port_raw)
                        rem_mac = oui_lookup.normalize_mac(rem_basemac).lower()
                        plat = f"Switch ({oui_lookup.lookup_oui(rem_mac)})"
                        entry = {
                            "local_port": local_port,
                            "remote_device": rem_host.split(".")[0],
                            "remote_port": rem_intf,
                            "remote_ip": "",
                            "remote_mac": rem_mac,
                            "platform": plat,
                            "remote_platform": plat,
                            "device_type": _classify_lldp_device_type(
                                capabilities=cap or "", platform=plat, remote_device=rem_host, remote_mac=rem_mac
                            ),
                        }
                        swarm_lldp.setdefault(ap_name.lower(), []).append(entry)
                        if not target_ap or ap_name.lower() == target_ap:
                            neighbors.append(entry)
        except Exception as exc:
            logger.warning("[%s] Aruba show ap debug lldp info failed: %s", self.ip, exc)
        self._swarm_lldp = swarm_lldp
        self._discovery_protocols = {
            "lldp": "enabled",
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": "",
        }
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes: list[dict] = []
        if getattr(self, "_is_aoscx", False):
            try:
                raw_rt = conn.send_command("show ip route")
                raw_str = raw_rt if isinstance(raw_rt, str) else ""
                if _is_aruba_cli_error(raw_str):
                    logger.warning("[%s] Aruba AOS-CX 'show ip route' returned CLI error", self.ip)
                    return routes

                current_vrf: str | None = None
                for line in raw_str.splitlines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    m_vrf = re.match(r"^VRF\s*:\s*(\S+)", stripped, re.IGNORECASE)
                    if m_vrf:
                        current_vrf = m_vrf.group(1)
                        continue

                    # Real AOS-CX 10.x tabular format:
                    # `0.0.0.0/0    192.0.2.1    vlan10   -   S     [1/0]    05d:12h`
                    # `192.0.2.0/24 -            vlan10   -   C     [0/0]    -`
                    m_tab = re.match(
                        r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(\d+\.\d+\.\d+\.\d+|-)\s+(\S+)\s+\S+\s+"
                        r"([A-Za-z][A-Za-z0-9/]*)\s+\[[^\]]+\]",
                        line,
                    )
                    if m_tab:
                        sub, nh, intf, orig = m_tab.groups()
                        orig_key = orig.split("/", 1)[0].lower()
                        proto = _AOSCX_ROUTE_ORIGINS.get(orig_key, orig.lower())
                        entry: dict[str, str] = {
                            "subnet": sub,
                            "protocol": proto,
                            "next_hop": "Direct" if nh == "-" else nh,
                            "interface": "" if intf == "-" else intf,
                        }
                        if current_vrf is not None:
                            entry["vrf"] = current_vrf
                        routes.append(entry)
                        continue

                    # Legacy single-line AOS-CX format fallback
                    m_rt = re.match(
                        r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s*,\s*vrf\s+(\S+)\s+via\s+(\S+)\s*,\s*\[[^\]]+\]\s*,\s*(\S+)",
                        line,
                        re.IGNORECASE,
                    )
                    if m_rt:
                        sub, vrf_name, nh, proto = m_rt.groups()
                        routes.append(
                            {
                                "subnet": sub,
                                "protocol": proto,
                                "next_hop": "connected" if proto.lower() == "connected" else nh,
                                "interface": nh if proto.lower() == "connected" else "",
                                "vrf": vrf_name,
                            }
                        )
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show ip route failed: %s", self.ip, exc)
            return routes

        # Aruba Instant AP: attempt real read-only route query; never fabricate synthetic "Gateway" routes
        try:
            raw_iap_rt = conn.send_command("show ip route")
            raw_str = raw_iap_rt if isinstance(raw_iap_rt, str) else ""
            if raw_str and not _is_aruba_cli_error(raw_str):
                for line in raw_str.splitlines():
                    m_def = re.match(r"^\s*default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)", line, re.IGNORECASE)
                    if m_def:
                        routes.append(
                            {
                                "subnet": "0.0.0.0/0",
                                "protocol": "static",
                                "next_hop": m_def.group(1),
                                "interface": m_def.group(2),
                            }
                        )
                        continue
                    m_kern = re.match(
                        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+\.\d+\.\d+\.\d+)\s+"
                        r"([A-Z]+)\s+\d+\s+\d+\s+\d+\s+(\S+)",
                        line,
                    )
                    if m_kern:
                        dest, gw, mask, flags, intf = m_kern.groups()
                        sub = "0.0.0.0/0" if dest == "0.0.0.0" and mask == "0.0.0.0" else f"{dest} {mask}"
                        routes.append(
                            {
                                "subnet": sub,
                                "protocol": "static" if "G" in flags else "connected",
                                "next_hop": "Direct" if gw in ("*", "0.0.0.0") else gw,
                                "interface": intf,
                            }
                        )
        except Exception as exc:
            logger.debug("[%s] Aruba IAP show ip route unavailable: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries: list[dict] = []
        seen_ips: set[str] = set()
        if getattr(self, "_is_aoscx", False):
            try:
                raw_arp = conn.send_command("show arp")
                if isinstance(raw_arp, str) and _is_aruba_cli_error(raw_arp):
                    logger.warning("[%s] Aruba AOS-CX 'show arp' returned CLI error", self.ip)
                    return arp_entries
                for line in (raw_arp if isinstance(raw_arp, str) else "").splitlines():
                    m_a = re.match(
                        r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:.-]{12,17})\s+(\S+)\s+(\S+)",
                        line,
                    )
                    if m_a:
                        a_ip, a_mac, a_port, _phys = m_a.groups()
                        norm_mac = oui_lookup.normalize_mac(a_mac).lower()
                        if not norm_mac or norm_mac == _ZERO_MAC:
                            continue
                        arp_entries.append(
                            {
                                "ip": a_ip,
                                "mac": norm_mac,
                                "interface": a_port,
                                "type": "dynamic",
                                "vendor": oui_lookup.lookup_oui(norm_mac),
                            }
                        )
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show arp failed: %s", self.ip, exc)
            return arp_entries

        try:
            raw = conn.send_command("show clients")
            if isinstance(raw, str) and _is_aruba_cli_error(raw):
                logger.warning("[%s] Aruba IAP 'show clients' returned CLI error", self.ip)
                return arp_entries
            for line in (raw if isinstance(raw, str) else "").splitlines():
                m_cli = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\b", line)
                if m_cli:
                    c_ip = m_cli.group(1)
                    if c_ip in ("0.0.0.0",) or c_ip in seen_ips:
                        continue
                    seen_ips.add(c_ip)
                    norm_mac = oui_lookup.normalize_mac(m_cli.group(2)).lower()
                    arp_entries.append(
                        {
                            "ip": c_ip,
                            "mac": norm_mac,
                            "interface": "wlan",
                            "age": "1",
                            "type": "Wireless Client",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] Aruba show clients failed: %s", self.ip, exc)
        return arp_entries

    def get_stp(self, conn) -> dict:
        """Collect Spanning Tree state on Aruba AOS-CX switches (no-op on IAP APs)."""
        stp: dict = {"enabled": False, "is_root": False, "vlans": {}}
        if getattr(self, "_is_aoscx", None) is not True:
            return stp
        try:
            raw = conn.send_command("show spanning-tree")
            raw_str = raw if isinstance(raw, str) else ""
            if not raw_str.strip() or _is_aruba_cli_error(raw_str):
                if _is_aruba_cli_error(raw_str):
                    logger.warning("[%s] Aruba AOS-CX 'show spanning-tree' returned CLI error", self.ip)
                return stp

            m_en = re.search(r"Spanning\s+tree\s+status\s*:\s*(Enabled|Disabled)", raw_str, re.IGNORECASE)
            if m_en and m_en.group(1).lower() == "enabled":
                stp["enabled"] = True
            m_proto = re.search(r"Protocol\s*:\s*(\S+)", raw_str, re.IGNORECASE)
            if m_proto:
                stp["protocol"] = m_proto.group(1).strip()

            cur_inst = "CST"
            for line in raw_str.splitlines():
                stripped = line.strip()
                m_inst = re.match(r"^(VLAN\d+|MST\d+)\b", stripped, re.IGNORECASE)
                if m_inst:
                    cur_inst = m_inst.group(1).upper()
                    stp["vlans"].setdefault(cur_inst, {"is_root": False, "ports": {}})
                    continue
                if re.search(r"this\s+bridge\s+is\s+(?:the\s+)?root", stripped, re.IGNORECASE):
                    stp["is_root"] = True
                    stp["enabled"] = True
                    stp["vlans"].setdefault(cur_inst, {"is_root": True, "ports": {}})["is_root"] = True
                    continue
                m_port = re.match(
                    r"^\s*(\d+/\d+/\d+(?::\d+)?|lag\d+)\s+(Root|Designated|Alternate|Backup|Disabled)\s+"
                    r"(Forwarding|Blocking|Discarding|Learning|Listening|Disabled)\s+(\d+)\s+(\d+)",
                    line,
                    re.IGNORECASE,
                )
                if m_port:
                    p_name, role, state, cost, prio = m_port.groups()
                    inst_rec = stp["vlans"].setdefault(cur_inst, {"is_root": False, "ports": {}})
                    inst_rec["ports"][p_name] = {
                        "role": role,
                        "state": state,
                        "cost": int(cost),
                        "priority": int(prio),
                    }
        except Exception as exc:
            logger.warning("[%s] Aruba AOS-CX show spanning-tree failed: %s", self.ip, exc)
        return stp

    def get_mac_table(self, conn) -> list[dict]:
        """Collect MAC forwarding table on Aruba AOS-CX switches (no-op on IAP APs)."""
        if getattr(self, "_is_aoscx", None) is not True:
            return []
        entries: list[dict] = []
        try:
            raw = conn.send_command("show mac-address-table")
            raw_str = raw if isinstance(raw, str) else ""
            if _is_aruba_cli_error(raw_str):
                logger.warning("[%s] Aruba AOS-CX 'show mac-address-table' returned CLI error", self.ip)
                return entries
            for line in raw_str.splitlines():
                m = re.match(r"^\s*([0-9a-fA-F:.-]{12,17})\s+(\d+)\s+(\S+)\s+(\S+)", line)
                if m:
                    raw_mac, vlan_s, mtype, port = m.groups()
                    norm_mac = oui_lookup.normalize_mac(raw_mac).lower()
                    if not norm_mac or norm_mac == _ZERO_MAC:
                        continue
                    entries.append(
                        {
                            "mac": norm_mac,
                            "vlan": int(vlan_s),
                            "type": mtype.lower(),
                            "port": port,
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] Aruba AOS-CX show mac-address-table failed: %s", self.ip, exc)
        return entries

    def get_poe(self, conn) -> dict:
        """Collect PoE chassis budget and per-port power draw on Aruba AOS-CX switches (no-op on IAP APs)."""
        poe: dict = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        if getattr(self, "_is_aoscx", None) is not True:
            return poe
        try:
            raw = conn.send_command("show power-over-ethernet brief")
            raw_str = raw if isinstance(raw, str) else ""
            if _is_aruba_cli_error(raw_str):
                logger.warning("[%s] Aruba AOS-CX 'show power-over-ethernet brief' returned CLI error", self.ip)
                return poe
            m_tot = re.search(r"Available\s+Power\s*:\s*(\d+(?:\.\d+)?)", raw_str, re.IGNORECASE)
            m_used = re.search(r"Allocated\s+Power\s*:\s*(\d+(?:\.\d+)?)", raw_str, re.IGNORECASE)
            m_rem = re.search(r"Remaining\s+Power\s*:\s*(\d+(?:\.\d+)?)", raw_str, re.IGNORECASE)
            if m_tot:
                poe["total_power_watts"] = float(m_tot.group(1))
            if m_used:
                poe["used_power_watts"] = float(m_used.group(1))
            if m_rem:
                poe["available_power_watts"] = float(m_rem.group(1))
            elif poe["total_power_watts"] > 0:
                poe["available_power_watts"] = max(0.0, round(poe["total_power_watts"] - poe["used_power_watts"], 2))

            for line in raw_str.splitlines():
                m_p = re.match(
                    r"^\s*(\d+/\d+/\d+(?::\d+)?)\s+(?:yes|no)\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(\d+(?:\.\d+)?)",
                    line,
                    re.IGNORECASE,
                )
                if m_p:
                    port, oper_st, watts = m_p.groups()
                    poe["ports"][port] = {
                        "status": oper_st.lower(),
                        "power_watts": float(watts),
                    }
        except Exception as exc:
            logger.warning("[%s] Aruba AOS-CX show power-over-ethernet brief failed: %s", self.ip, exc)
        return poe

    def get_optics(self, conn) -> list[dict]:
        """Collect optical transceiver telemetry on Aruba AOS-CX switches (skipped on IAP APs)."""
        if getattr(self, "_is_aoscx", None) is False:
            return []
        optics: list[dict] = []
        try:
            raw = conn.send_command("show interface transceiver")
            raw_str = raw if isinstance(raw, str) else ""
            if _is_aruba_cli_error(raw_str):
                logger.warning("[%s] Aruba 'show interface transceiver' returned CLI error", self.ip)
                return optics

            # 1) Block format (`Transceiver in 1/1/49\n Type : ...`)
            cur_port = ""
            cur_entry: dict = {}
            for line in raw_str.splitlines():
                m_p = re.match(r"^(?:Transceiver in|Interface)\s+([A-Za-z0-9/\._-]+)", line.strip(), re.IGNORECASE)
                if m_p:
                    if cur_port and cur_entry:
                        optics.append(cur_entry)
                    cur_port = m_p.group(1)
                    cur_entry = {
                        "port": cur_port,
                        "vendor": "Aruba",
                        "part_number": "Unknown",
                        "serial": "Unknown",
                        "type": "SFP",
                        "tx_power_dbm": None,
                        "rx_power_dbm": None,
                        "temperature_c": None,
                        "voltage_v": None,
                    }
                elif cur_entry:
                    m_type = re.search(r"Type\s*:\s*(.+)", line, re.IGNORECASE)
                    m_pn = re.search(r"Part\s*Number\s*:\s*(\S+)", line, re.IGNORECASE)
                    m_sn = re.search(r"Serial\s*Number\s*:\s*(\S+)", line, re.IGNORECASE)
                    if m_type:
                        cur_entry["type"] = m_type.group(1).strip()
                    if m_pn:
                        cur_entry["part_number"] = m_pn.group(1).strip()
                    if m_sn:
                        cur_entry["serial"] = m_sn.group(1).strip()
            if cur_port and cur_entry:
                optics.append(cur_entry)

            # 2) Real AOS-CX tabular format: `1/1/49  SFP+SR  J9150D  CN99X001  1990-4391`
            if not optics:
                for line in raw_str.splitlines():
                    m_tab = re.match(
                        r"^\s*(\d+/\d+/\d+(?::\d+)?)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?",
                        line,
                    )
                    if m_tab:
                        port, xcvr_type, prod_num, serial, _part = m_tab.groups()
                        if xcvr_type.lower() in ("--", "none", "absent", "not"):
                            continue
                        optics.append(
                            {
                                "port": port,
                                "vendor": "Aruba",
                                "part_number": prod_num if prod_num not in ("--", "-") else "Unknown",
                                "serial": serial if serial not in ("--", "-") else "Unknown",
                                "type": xcvr_type,
                                "tx_power_dbm": None,
                                "rx_power_dbm": None,
                                "temperature_c": None,
                                "voltage_v": None,
                            }
                        )
        except Exception as exc:
            logger.warning("[%s] Aruba show interface transceiver failed: %s", self.ip, exc)
        return optics

    def get_running_config(self, conn) -> str:
        if getattr(self, "_is_aoscx", False):
            try:
                raw = conn.send_command("show running-config")
                if isinstance(raw, str) and raw.strip() and not _is_aruba_cli_error(raw):
                    return raw
            except Exception as exc:
                logger.warning("[%s] Aruba AOS-CX show running-config failed: %s", self.ip, exc)
        try:
            raw_cfg = conn.send_command("show configuration")
            if isinstance(raw_cfg, str) and raw_cfg.strip() and not _is_aruba_cli_error(raw_cfg):
                return raw_cfg
        except Exception as exc:
            logger.warning("[%s] Aruba show configuration failed, falling back to show run: %s", self.ip, exc)
        try:
            raw_run = conn.send_command("show run")
            if isinstance(raw_run, str) and not _is_aruba_cli_error(raw_run):
                return raw_run
            return ""
        except Exception as exc:
            logger.warning("[%s] Aruba show run fallback failed: %s", self.ip, exc)
            return ""

    def get_l2_operational(self, conn) -> dict[str, dict]:
        """Collect operational trunk & LACP state on Aruba AOS-CX switches (no-op on IAP APs)."""
        if getattr(self, "_is_aoscx", None) is False:
            return {}

        ops: dict[str, dict] = {}
        try:
            raw_trunk = conn.send_command("show interface trunk")
            if isinstance(raw_trunk, str) and raw_trunk.strip() and not _is_aruba_cli_error(raw_trunk):
                for line in raw_trunk.splitlines():
                    stripped = line.strip()
                    if not stripped or set(stripped) <= {"-", "="}:
                        continue
                    low = stripped.lower()
                    if low.startswith(("port", "native", "vlan")):
                        continue
                    m_tr = re.match(
                        r"^\s*(lag\s*\d+|\d+/\d+/\d+(?::\d+)?)\s+(\d+|none|--)\s+"
                        r"(trunk|native-tagged|native-untagged)\s+.*?\b(up|down)\b.*?\s+([\d,-]+|all|none)\s*$",
                        line,
                        re.I,
                    )
                    if m_tr:
                        raw_p, nat, mode_tok, status_tok, allowed = m_tr.groups()
                        port = re.sub(r"^lag\s+(\d+)$", r"lag\1", raw_p.strip(), flags=re.I)
                        mode_l = mode_tok.lower()
                        status_l = status_tok.lower()
                        rec = ops.setdefault(port, {})
                        rec["mode"] = "trunk"
                        rec["admin_mode"] = "trunk"
                        rec["oper_mode"] = "trunk" if status_l == "up" else "down"
                        rec["encapsulation"] = "dot1q"
                        if nat.lower() not in ("--",):
                            rec["native_vlan"] = nat.lower()
                        if mode_l == "native-tagged":
                            rec["native_vlan_tagged"] = True
                        elif mode_l == "native-untagged":
                            rec["native_vlan_tagged"] = False
                        allowed_clean = allowed.strip().lower()
                        rec["trunk_allowed_vlans"] = allowed_clean
                        if status_l == "up":
                            rec["trunk_active_vlans"] = allowed_clean
        except Exception as exc:
            logger.warning("[%s] Aruba AOS-CX show interface trunk failed: %s", self.ip, exc)

        try:
            raw_lacp = conn.send_command("show lacp interfaces")
            if isinstance(raw_lacp, str) and raw_lacp.strip() and not _is_aruba_cli_error(raw_lacp):
                cur_lag = ""
                for line in raw_lacp.splitlines():
                    m_agg = re.search(r"Aggregate\s+name\s*:\s*(lag\s*\d+|\S+)", line, re.I)
                    if m_agg:
                        cur_lag = re.sub(r"^lag\s+(\d+)$", r"lag\1", m_agg.group(1).strip(), flags=re.I)
                        continue
                    if cur_lag:
                        m_mem = re.match(r"^\s*(\d+/\d+/\d+(?::\d+)?)\s+\d+\s+\d+\s+([A-Z]+)\b", line)
                        if m_mem:
                            pname, state_flags = m_mem.group(1), m_mem.group(2)
                            rec = ops.setdefault(pname, {})
                            rec["lag_group"] = cur_lag
                            rec["lacp_mode"] = (
                                "passive" if ("P" in state_flags and "A" not in state_flags) else "active"
                            )
                            continue
                    m_tab = re.match(r"^\s*(\d+/\d+/\d+(?::\d+)?)\s+(lag\d+)\s+(active|passive)\b", line, re.I)
                    if m_tab:
                        pname, lag_name, lmode = m_tab.groups()
                        rec = ops.setdefault(pname, {})
                        rec["lag_group"] = lag_name.lower()
                        rec["lacp_mode"] = lmode.lower()
        except Exception as exc:
            logger.warning("[%s] Aruba AOS-CX show lacp interfaces failed: %s", self.ip, exc)

        return ops

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
Palo Alto Networks Driver: PAN-OS Firewalls and Management Appliances.
Official Documentation: https://docs.paloaltonetworks.com/pan-os
"""

import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

_PANOS_CLI_ERROR_RE = re.compile(
    r"(?:unknown command|invalid syntax|server error|command failed|not authorized|^error\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
_MAC_TOKEN_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV4_OR_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_PANOS_INTF_PREFIX_RE = re.compile(r"^(?:ethernet|ae|vlan|tunnel|loopback|ha|management)", re.IGNORECASE)
_PANOS_ROUTE_FLAG_RE = re.compile(r"^[ASCHOBREMI?~][A-Za-z0-9?~]{0,3}$")
_ZERO_MAC = "00:00:00:00:00:00"


def _is_panos_cli_error(raw: str) -> bool:
    """Return True if PAN-OS CLI output indicates a syntax, authorization, or server error."""
    return bool(raw and _PANOS_CLI_ERROR_RE.search(raw))


def _normalize_panos_speed(raw_speed: str) -> str:
    """Normalize PAN-OS hardware table speed token (e.g. '1000', '10000', '[n/a]', 'ukn') to canonical label."""
    tok = (raw_speed or "").strip().strip("[]").lower()
    if not tok or tok in ("n/a", "ukn", "unknown", "auto"):
        return "N/A"
    m = re.match(r"^(\d+)(g|m)?$", tok)
    if not m:
        return "N/A"
    val = int(m.group(1))
    unit = m.group(2) or ""
    if unit == "g":
        return f"{val}Gb/s"
    if val >= 1000:
        return f"{val // 1000}Gb/s" if val % 1000 == 0 else f"{val / 1000:g}Gb/s"
    if val > 0:
        return f"{val}Mb/s"
    return "N/A"


def _normalize_panos_duplex(raw_duplex: str) -> str:
    tok = (raw_duplex or "").strip().strip("[]").lower()
    if tok == "full":
        return "Full"
    if tok == "half":
        return "Half"
    return "N/A"


def _classify_lldp_device_type(
    capabilities: str = "", platform: str = "", remote_device: str = "", remote_mac: str = ""
) -> str:
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


class PaloAltoDriver(BaseDriver):
    """
    Driver for Palo Alto Networks Next-Generation Firewalls running PAN-OS.
    Persona: firewall.
    """

    vendor_name = "Palo Alto Networks"
    device_persona = "firewall"
    default_device_type = "firewall"
    supports_telnet = False
    paging_cmd = "set cli pager off"

    def connect(self):
        device = self._build_netmiko_params("paloalto_panos", global_delay_factor=2)
        conn = self.connect_netmiko(device)
        self._safe_send_command(conn, self.paging_cmd)
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Palo Alto Firewall",
            "serial": "Unknown",
            "firmware": "PAN-OS",
            "os_type": "paloalto_panos",
            "device_persona": "firewall",
        }
        try:
            raw = conn.send_command("show system info")
            if _is_panos_cli_error(raw):
                logger.warning("[%s] PAN-OS 'show system info' returned CLI error: %s", self.ip, raw.strip()[:160])
            else:
                m_host = re.search(r"hostname:\s*(\S+)", raw)
                if m_host:
                    info["hostname"] = m_host.group(1)
                m_model = re.search(r"model:\s*(\S+)", raw)
                if m_model:
                    info["model"] = (
                        f"PA-{m_model.group(1)}" if not m_model.group(1).startswith("PA") else m_model.group(1)
                    )
                m_serial = re.search(r"serial:\s*(\S+)", raw)
                if m_serial:
                    info["serial"] = m_serial.group(1)
                m_ver = re.search(r"sw-version:\s*(\S+)", raw)
                if m_ver:
                    info["firmware"] = f"PAN-OS {m_ver.group(1)}"
                m_mac = re.search(r"mac-address:\s*([0-9a-fA-F:.-]+)", raw)
                if m_mac:
                    info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()
        except Exception as exc:
            logger.warning("[%s] PAN-OS show system info failed: %s", self.ip, exc)

        if not info["hostname"]:
            prompt = self._safe_find_prompt(conn)
            if "@" in prompt:
                host_part = prompt.split("@")[-1].replace(">", "").replace("#", "").strip()
                # Strip PAN-OS HA suffix like `(active)`, `(passive)`, `(active-primary)`
                host_part = re.sub(r"\([^)]*\)$", "", host_part).strip()
                info["hostname"] = host_part

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        try:
            raw = conn.send_command("show interface all")
            if _is_panos_cli_error(raw):
                logger.warning("[%s] PAN-OS 'show interface all' returned CLI error: %s", self.ip, raw.strip()[:160])
                return l3_interfaces, interfaces_detail

            for line in raw.splitlines():
                stripped = line.strip()
                if (
                    not stripped
                    or stripped.startswith("---")
                    or stripped.lower().startswith(("name ", "total ", "aggregation "))
                ):
                    continue

                # 1) Real PAN-OS Hardware table row:
                # `ethernet1/1   16   1000/full/up        08:66:1f:aa:bb:01`
                # `ethernet1/2   17   [n/a]/[n/a]/down    08:66:1f:aa:bb:02`
                m_hw = re.match(
                    r"^((?:ethernet|ae|ha|management)\S*)\s+\d+\s+"
                    r"(\[n/a\]|[^\s/]+)/(\[n/a\]|[^\s/]+)/(up|down)\s+([0-9a-fA-F:.-]+)",
                    stripped,
                    re.IGNORECASE,
                )
                if m_hw:
                    intf_name, raw_spd, raw_dup, raw_st, raw_mac = m_hw.groups()
                    st = raw_st.lower()
                    norm_mac = oui_lookup.normalize_mac(raw_mac).lower()
                    interfaces_detail[intf_name] = {
                        "status": st,
                        "protocol": st,
                        "description": "",
                        "mac_address": "" if norm_mac == _ZERO_MAC else norm_mac,
                        "speed": _normalize_panos_speed(raw_spd),
                        "duplex": _normalize_panos_duplex(raw_dup),
                    }
                    continue

                # 2) Real PAN-OS Logical table row:
                # `ethernet1/1     16  1  untrust  vr:default  0   198.51.100.2/30`
                # `ethernet1/1.10 256  1  trust    vr:default  10  10.10.10.1/24`
                # `loopback.1     258  1  trust    vr:default  0   10.255.0.1/32`
                m_log = re.match(
                    r"^((?:ethernet|ae|vlan|tunnel|loopback)\S*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)",
                    stripped,
                    re.IGNORECASE,
                )
                if m_log:
                    intf_name, zone, _fwd, tag_s, addr = m_log.groups()
                    parent_name = intf_name.split(".", 1)[0] if "." in intf_name else intf_name
                    parent_detail = interfaces_detail.get(parent_name, {})

                    if intf_name not in interfaces_detail:
                        inherited_st = parent_detail.get("status", "up")
                        interfaces_detail[intf_name] = {
                            "status": inherited_st,
                            "protocol": inherited_st,
                            "description": "" if zone in ("N/A", "-") else f"Zone: {zone}",
                            "mac_address": parent_detail.get("mac_address", ""),
                            "speed": parent_detail.get("speed", "N/A"),
                            "duplex": parent_detail.get("duplex", "N/A"),
                        }
                    else:
                        if not interfaces_detail[intf_name].get("description") and zone not in ("N/A", "-"):
                            interfaces_detail[intf_name]["description"] = f"Zone: {zone}"

                    if tag_s.isdigit() and int(tag_s) > 0:
                        interfaces_detail[intf_name]["vlan"] = int(tag_s)

                    if _IPV4_OR_CIDR_RE.match(addr) and not addr.startswith(("0.0.0.0", "127.")):
                        eff_st = interfaces_detail[intf_name]["status"]
                        l3_interfaces.append(
                            {
                                "interface": intf_name,
                                "ip_address": addr,
                                "status": eff_st,
                                "protocol": eff_st,
                            }
                        )
                    continue

                # 3) Legacy 4-column mock format fallback: `ethernet1/1  10.0.0.1/24  up  up`
                parts = stripped.split()
                if (
                    len(parts) >= 4
                    and _PANOS_INTF_PREFIX_RE.match(parts[0])
                    and _IPV4_OR_CIDR_RE.match(parts[1])
                    and parts[2].lower() in ("up", "down")
                ):
                    intf_name = parts[0]
                    ip_addr = parts[1]
                    status = parts[2].lower()
                    proto = parts[3].lower() if parts[3].lower() in ("up", "down") else status
                    if not ip_addr.startswith(("0.0.0.0", "127.")):
                        l3_interfaces.append(
                            {
                                "interface": intf_name,
                                "ip_address": ip_addr,
                                "status": status,
                                "protocol": proto,
                            }
                        )
                    interfaces_detail.setdefault(
                        intf_name,
                        {
                            "status": status,
                            "protocol": proto,
                            "description": "",
                            "mac_address": "",
                            "speed": "N/A",
                            "duplex": "N/A",
                        },
                    )
        except Exception as exc:
            logger.warning("[%s] PAN-OS show interface all failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []
        lldp_status = "unknown"
        notes = ""
        try:
            raw = conn.send_command("show lldp neighbors all")
            raw_str = raw if isinstance(raw, str) else ""
            if _is_panos_cli_error(raw_str):
                logger.warning(
                    "[%s] PAN-OS 'show lldp neighbors all' returned CLI error: %s", self.ip, raw_str.strip()[:160]
                )
                lldp_status = "unknown"
            elif "lldp is not enabled" in raw_str.lower() or "lldp is disabled" in raw_str.lower():
                lldp_status = "disabled"
                notes = "LLDP is disabled on PAN-OS."
            elif raw is not None:
                lldp_status = "enabled"

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

            if lldp_status == "enabled":
                for line in raw_str.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    m_if = re.match(r"^(?:Local\s+)?Interface\s*:\s*(\S+)", line, re.IGNORECASE)
                    if m_if:
                        _flush()
                        current = {
                            "local_port": m_if.group(1).strip(),
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

                    low = line.lower()
                    if low.startswith("chassis id:"):
                        val = line.split(":", 1)[1].strip()
                        if _MAC_TOKEN_RE.match(val):
                            norm = oui_lookup.normalize_mac(val).lower()
                            if norm and norm != _ZERO_MAC:
                                current["remote_mac"] = norm
                        if val and not current["remote_device"]:
                            current["remote_device"] = val
                    elif low.startswith("system name:"):
                        sys_name = line.split(":", 1)[1].strip()
                        if sys_name:
                            if "." in sys_name and not _IPV4_RE.match(sys_name) and not _MAC_TOKEN_RE.match(sys_name):
                                sys_name = sys_name.split(".", 1)[0]
                            current["remote_device"] = sys_name
                    elif low.startswith("port id:"):
                        current["remote_port"] = line.split(":", 1)[1].strip()
                    elif low.startswith("management address:"):
                        val = line.split(":", 1)[1].strip()
                        m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", val)
                        if m_ip:
                            current["remote_ip"] = m_ip.group(1)
                    elif low.startswith("system description:"):
                        desc = line.split(":", 1)[1].strip()[:80]
                        current["platform"] = desc
                        current["remote_platform"] = desc
                    elif low.startswith(("system capabilities:", "enabled capabilities:")):
                        current_caps = line.split(":", 1)[1].strip()
                _flush()
        except Exception as exc:
            logger.warning("[%s] PAN-OS show lldp neighbors all failed: %s", self.ip, exc)

        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def get_routing_table(self, conn) -> list[dict]:
        routes: list[dict] = []
        try:
            raw = conn.send_command("show routing route")
            if _is_panos_cli_error(raw):
                logger.warning("[%s] PAN-OS 'show routing route' returned CLI error: %s", self.ip, raw.strip()[:160])
                return routes

            current_vr: str | None = None
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                m_vr = re.match(r"^VIRTUAL\s+ROUTER\s*:\s*(\S+)", stripped, re.IGNORECASE)
                if m_vr:
                    current_vr = m_vr.group(1)
                    continue
                if stripped.lower().startswith(("flags:", "destination", "total ", "===", "---")):
                    continue

                parts = stripped.split()
                if len(parts) < 4 or "/" not in parts[0] or not _IPV4_OR_CIDR_RE.match(parts[0]):
                    continue

                subnet = parts[0]
                next_hop = "Direct" if parts[1] == "0.0.0.0" else parts[1]

                # Real PAN-OS table has numeric `metric` in parts[2], followed by 1-2 flag tokens, optional age, optional interface
                if parts[2].isdigit():
                    idx = 3
                    flag_tokens: list[str] = []
                    while idx < len(parts):
                        tok = parts[idx]
                        if tok.isdigit() or _PANOS_INTF_PREFIX_RE.match(tok) or tok.lower().startswith("vr:"):
                            break
                        if _PANOS_ROUTE_FLAG_RE.match(tok):
                            flag_tokens.append(tok)
                            idx += 1
                        else:
                            break
                    # Optional numeric age
                    if idx < len(parts) and parts[idx].isdigit():
                        idx += 1
                    # Optional egress interface
                    intf = ""
                    if idx < len(parts) and not parts[idx].isdigit():
                        intf = parts[idx]
                    entry: dict[str, str] = {
                        "subnet": subnet,
                        "next_hop": next_hop,
                        "interface": intf,
                        "protocol": " ".join(flag_tokens) if flag_tokens else "A",
                    }
                    if current_vr is not None:
                        entry["vrf"] = current_vr
                    routes.append(entry)
                else:
                    # Legacy 4-column mock format: `0.0.0.0/0  192.168.1.254  A  ethernet1/2`
                    routes.append(
                        {
                            "subnet": subnet,
                            "next_hop": next_hop,
                            "interface": parts[3] if len(parts) > 3 else "",
                            "protocol": parts[2] if len(parts) > 2 else "A",
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] PAN-OS show routing route failed: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries: list[dict] = []
        try:
            raw = conn.send_command("show arp all")
            if _is_panos_cli_error(raw):
                logger.warning("[%s] PAN-OS 'show arp all' returned CLI error: %s", self.ip, raw.strip()[:160])
                return arp_entries

            for line in raw.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue

                # 1) Legacy 3-column mock format: `10.0.0.2  00:00:0c:99:88:77  ethernet1/1`
                if _IPV4_RE.match(parts[0]) and _MAC_TOKEN_RE.match(parts[1]):
                    mac = oui_lookup.normalize_mac(parts[1]).lower()
                    if not mac or mac == _ZERO_MAC:
                        continue
                    arp_entries.append(
                        {
                            "ip": parts[0],
                            "mac": mac,
                            "interface": parts[2],
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
                    continue

                # 2) Real PAN-OS 6-column format:
                # `ethernet1/1.10  10.10.10.50  fc:33:42:e6:b5:99  ethernet1/1  s  -`
                if _IPV4_RE.match(parts[1]):
                    raw_mac = parts[2]
                    status_flag = parts[4].lower() if len(parts) >= 5 else "c"
                    if "incomplete" in raw_mac.lower() or status_flag == "i" or not _MAC_TOKEN_RE.match(raw_mac):
                        continue
                    mac = oui_lookup.normalize_mac(raw_mac).lower()
                    if not mac or mac == _ZERO_MAC:
                        continue
                    ttl = parts[5] if len(parts) >= 6 else ""
                    arp_entries.append(
                        {
                            "ip": parts[1],
                            "mac": mac,
                            "interface": parts[0],
                            "age": ttl,
                            "type": "static" if status_flag == "s" else "dynamic",
                            "vendor": oui_lookup.lookup_oui(mac),
                        }
                    )
        except Exception as exc:
            logger.warning("[%s] PAN-OS show arp all failed: %s", self.ip, exc)
        return arp_entries

    def get_fhrp(self, conn) -> list[dict]:
        """Collect read-only PAN-OS High Availability state via `show high-availability state`."""
        ha_records: list[dict] = []
        try:
            raw = conn.send_command("show high-availability state")
            raw_str = raw if isinstance(raw, str) else ""
            if not raw_str.strip() or _is_panos_cli_error(raw_str):
                if _is_panos_cli_error(raw_str):
                    logger.warning("[%s] PAN-OS 'show high-availability state' returned CLI error", self.ip)
                return ha_records
            if "ha not enabled" in raw_str.lower() or "high availability: not enabled" in raw_str.lower():
                return ha_records

            group = ""
            mode = ""
            local_state = ""
            peer_ip = ""
            section = ""

            for raw_line in raw_str.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                m_grp = re.match(r"^Group\s+(\S+?)\s*:", line, re.IGNORECASE)
                if m_grp:
                    group = m_grp.group(1)
                    continue
                m_mode = re.match(r"^Mode\s*:\s*(.+)$", line, re.IGNORECASE)
                if m_mode:
                    mode = m_mode.group(1).strip()
                    continue
                if line.lower().startswith("local information"):
                    section = "local"
                    continue
                if line.lower().startswith("peer information"):
                    section = "peer"
                    continue
                if section == "local":
                    m_st = re.match(r"^State\s*:\s*(\S+)", line, re.IGNORECASE)
                    if m_st:
                        local_state = m_st.group(1).strip().lower()
                elif section == "peer":
                    m_pip = re.match(r"^Management\s+IP\s*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if m_pip:
                        peer_ip = m_pip.group(1)

            if group or local_state:
                ha_records.append(
                    {
                        "protocol": "PAN-OS HA",
                        "group": group or "1",
                        "state": local_state or "unknown",
                        "peer_ip": peer_ip,
                        "mode": mode,
                    }
                )
        except Exception as exc:
            logger.warning("[%s] PAN-OS show high-availability state failed: %s", self.ip, exc)
        return ha_records

    def get_running_config(self, conn) -> str:
        raw = self._safe_send_command(conn, "show config running")
        if _is_panos_cli_error(raw):
            logger.warning("[%s] PAN-OS 'show config running' returned CLI error: %s", self.ip, raw.strip()[:160])
        return raw

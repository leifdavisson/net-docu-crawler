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
Shared parser for `lldpd` (`lldpctl -f json`, `lldpcli show neighbors -f json`,
and `json0` schema variants) used across OPNsense, OpenWrt, and FRR/Linux drivers.

Official Upstream Reference:
- lldpd: https://lldpd.github.io/
"""

import json
import logging
import re

import oui_lookup

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}$")


def _extract_str_value(obj: object) -> str:
    """Extract a string from a plain string, `{'value': str}`, or `[{'value': str}]`."""
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        val = obj.get("value")
        return val.strip() if isinstance(val, str) else ""
    if isinstance(obj, list):
        for item in obj:
            extracted = _extract_str_value(item)
            if extracted:
                return extracted
    return ""


def _extract_mgmt_ip(mgmt_raw: object) -> str:
    """Extract management IP from `mgmt-ip` (string, list of strings, dict, or list of dicts), preferring IPv4."""
    candidates: list[str] = []
    if isinstance(mgmt_raw, str):
        if mgmt_raw.strip():
            candidates.append(mgmt_raw.strip())
    elif isinstance(mgmt_raw, dict):
        val = _extract_str_value(mgmt_raw)
        if val:
            candidates.append(val)
    elif isinstance(mgmt_raw, list):
        for item in mgmt_raw:
            val = _extract_str_value(item)
            if val:
                candidates.append(val)

    for ip in candidates:
        if ":" not in ip:
            return ip
    return candidates[0] if candidates else ""


def _extract_mac_from_id(id_raw: object) -> str:
    """Extract and normalize a MAC address from an `lldpd` chassis or port `id` field."""
    items = id_raw if isinstance(id_raw, list) else [id_raw]
    for item in items:
        if isinstance(item, dict):
            id_type = str(item.get("type") or "").strip().lower()
            val = str(item.get("value") or "").strip()
            if val and (id_type == "mac" or _MAC_RE.match(val)):
                return oui_lookup.normalize_mac(val).lower()
        elif isinstance(item, str) and _MAC_RE.match(item.strip()):
            return oui_lookup.normalize_mac(item.strip()).lower()
    return ""


def _classify_lldpd_device_type(caps_raw: object, descr: str, default_device_type: str) -> str:
    """Infer device_type from `lldpd` capability flags and description text."""
    caps_list = caps_raw if isinstance(caps_raw, list) else ([caps_raw] if isinstance(caps_raw, dict) else [])
    enabled_caps: set[str] = set()
    for cap in caps_list:
        if not isinstance(cap, dict):
            continue
        is_enabled = cap.get("enabled", True)
        if is_enabled is False or str(is_enabled).lower() == "false":
            continue
        ctype = str(cap.get("type") or "").strip().lower()
        if ctype:
            enabled_caps.add(ctype)

    descr_low = (descr or "").lower()
    if any("wlan" in c or "access point" in c for c in enabled_caps):
        return "ap"
    if any("telephone" in c for c in enabled_caps):
        return "phone"

    has_bridge = "bridge" in enabled_caps
    has_router = "router" in enabled_caps

    if has_bridge and not has_router:
        return "switch"
    if has_router and not has_bridge:
        return "router"
    if has_bridge and has_router:
        if any(
            k in descr_low
            for k in ("switch", "eos", "junos", "ex2300", "ex3400", "ex4", "qfx", "catalyst", "procurve", "aos-cx")
        ):
            return "switch"
        return "router"
    if any("station" in c for c in enabled_caps):
        return "host"

    if any(k in descr_low for k in ("access point", "aruba", "ruckus", "unifi", "ap-")):
        return "ap"
    if any(k in descr_low for k in ("switch", "eos", "ex2300", "ex3400", "catalyst", "procurve", "nexus")):
        return "switch"
    if any(k in descr_low for k in ("router", "frr", "mikrotik", "routeros", "vyos")):
        return "router"
    if any(k in descr_low for k in ("firewall", "opnsense", "pfsense", "fortigate", "pan-os")):
        return "firewall"
    return default_device_type


def _iter_interface_records(raw_interfaces: object) -> list[tuple[str, dict]]:
    """Normalize `lldp.interface` (dict, list of dicts, or `json0` list) into `(local_port, info)` pairs."""
    pairs: list[tuple[str, dict]] = []
    if isinstance(raw_interfaces, dict):
        for intf_name, info in raw_interfaces.items():
            if isinstance(info, dict):
                pairs.append((str(intf_name), info))
            elif isinstance(info, list):
                for item in info:
                    if isinstance(item, dict):
                        pairs.append((str(intf_name), item))
    elif isinstance(raw_interfaces, list):
        for entry in raw_interfaces:
            if not isinstance(entry, dict):
                continue
            # `lldpctl -f json0` format: {"name": "eth0", "chassis": [...], "port": [...]}
            if isinstance(entry.get("name"), str) and ("chassis" in entry or "port" in entry):
                pairs.append((entry["name"], entry))
                continue
            for intf_name, info in entry.items():
                if isinstance(info, dict):
                    pairs.append((str(intf_name), info))
                elif isinstance(info, list):
                    for item in info:
                        if isinstance(item, dict):
                            pairs.append((str(intf_name), item))
    return pairs


def _iter_chassis_records(chassis_raw: object) -> list[tuple[str, dict]]:
    """
    Normalize `chassis` into `(remote_device_name, attrs_dict)` pairs, handling:
      1. Real `lldpd -f json`: `{"desktop-switch": {"id": {...}, "descr": "...", "mgmt-ip": "..."}}`
      2. Synthetic flat format: `{"name": {"value": "EdgeRouter"}, "descr": {"value": "..."}}`
      3. Unnamed flat format: `{"id": {"type": "mac", "value": "..."}, "descr": "..."}`
      4. `lldpd -f json0` list format: `[{"name": [{"value": "..."}], "id": [...], ...}]`
    """
    if isinstance(chassis_raw, list):
        out: list[tuple[str, dict]] = []
        for item in chassis_raw:
            if isinstance(item, dict):
                name = _extract_str_value(item.get("name"))
                out.append((name, item))
        return out

    if not isinstance(chassis_raw, dict) or not chassis_raw:
        return []

    # Synthetic flat format (`chassis.name.value`)
    if "name" in chassis_raw and isinstance(chassis_raw["name"], (dict, list, str)):
        if (
            isinstance(chassis_raw["name"], str)
            or (isinstance(chassis_raw["name"], dict) and "value" in chassis_raw["name"])
            or isinstance(chassis_raw["name"], list)
        ):
            return [(_extract_str_value(chassis_raw["name"]), chassis_raw)]

    # Unnamed flat format (`chassis.id.type` / `chassis.id.value`)
    if (
        "id" in chassis_raw
        and isinstance(chassis_raw["id"], dict)
        and ("value" in chassis_raw["id"] or "type" in chassis_raw["id"])
    ):
        return [("", chassis_raw)]

    # Real `lldpd` hostname-keyed format: `{hostname: {id, descr, mgmt-ip, capability}}`
    out = []
    for host_key, attrs in chassis_raw.items():
        if isinstance(attrs, dict):
            out.append((str(host_key), attrs))
    return out


def parse_lldpd_json(
    raw: str,
    *,
    default_device_type: str = "switch",
    log: logging.Logger | None = None,
    ip: str = "",
) -> tuple[list[dict], bool]:
    """
    Parse `lldpctl -f json` / `lldpcli show neighbors -f json` output safely across
    real `lldpd` (single-dict vs list `interface`, hostname-keyed `chassis`, string or
    list `mgmt-ip`, MAC extraction) and legacy synthetic test schemas.

    Returns `(neighbors, parsed_ok)`.
    """
    active_log = log or logger
    if not isinstance(raw, str) or not raw.strip():
        return [], False

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        active_log.warning("[%s] lldpd JSON decode failed: %s", ip or "unknown", exc)
        return [], False

    if not isinstance(data, dict):
        active_log.warning("[%s] lldpd JSON root is %s (expected dict)", ip or "unknown", type(data).__name__)
        return [], False

    lldp_raw = data.get("lldp")
    if lldp_raw is None:
        return [], True

    lldp_blocks = lldp_raw if isinstance(lldp_raw, list) else ([lldp_raw] if isinstance(lldp_raw, dict) else [])
    if not lldp_blocks:
        active_log.warning("[%s] lldpd 'lldp' field has unexpected type %s", ip or "unknown", type(lldp_raw).__name__)
        return [], False

    neighbors: list[dict] = []
    for lldp_block in lldp_blocks:
        if not isinstance(lldp_block, dict):
            continue
        raw_interfaces = lldp_block.get("interface")
        if raw_interfaces is None:
            continue

        for local_port, info in _iter_interface_records(raw_interfaces):
            port_raw = info.get("port")
            port_dict = (
                port_raw[0]
                if isinstance(port_raw, list) and port_raw and isinstance(port_raw[0], dict)
                else (port_raw if isinstance(port_raw, dict) else {})
            )
            port_id_raw = port_dict.get("id")
            port_id_str = _extract_str_value(port_id_raw)
            port_descr_str = _extract_str_value(port_dict.get("descr"))
            remote_port = port_id_str or port_descr_str or "Unknown"
            port_mac = _extract_mac_from_id(port_id_raw)

            chassis_records = _iter_chassis_records(info.get("chassis"))
            if not chassis_records:
                chassis_records = [("", {})]

            for rem_name, attrs in chassis_records:
                remote_mac = _extract_mac_from_id(attrs.get("id")) or port_mac
                remote_ip = _extract_mgmt_ip(attrs.get("mgmt-ip"))
                descr = _extract_str_value(attrs.get("descr"))[:80]
                if not descr and remote_mac:
                    oui_vendor = oui_lookup.lookup_oui(remote_mac)
                    if oui_vendor and oui_vendor != "Unknown":
                        descr = oui_vendor

                remote_device = (rem_name or "").strip() or remote_mac or "Unknown"
                dev_type = _classify_lldpd_device_type(attrs.get("capability"), descr, default_device_type)

                neighbors.append(
                    {
                        "local_port": local_port,
                        "remote_device": remote_device,
                        "remote_port": remote_port,
                        "remote_ip": remote_ip,
                        "remote_mac": remote_mac,
                        "platform": descr,
                        "remote_platform": descr,
                        "device_type": dev_type,
                    }
                )

    return neighbors, True

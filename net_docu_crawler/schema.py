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
Canonical Schema v2.0 & Provenance Contract for Net-Docu-Crawler.
Defines tri-state policy values ("enabled" | "disabled" | "unknown"),
entity classification ("crawled_infra" vs endpoints/failures), site-code
extraction, and unified per-port / PoE / L3 SVI record builders.
"""

import datetime
import re

SCHEMA_VERSION = "2.1"

TRI_STATE_VALUES = ("enabled", "disabled", "unknown")
INFRA_PERSONAS = frozenset({"switch", "router", "firewall", "ap", "wlc", "wireless", "gateway", "bridge"})
APPLIANCE_TYPES = frozenset({"av_control", "camera", "display", "printer", "ups", "nas", "iot", "server"})

COLLECTION_STATES = (
    "ok",
    "not_applicable",
    "not_collected",
    "command_failed",
    "parse_failed",
    "partial",
)
COLLECTION_SECTIONS = (
    "version",
    "interfaces",
    "neighbors",
    "routes",
    "arp",
    "mac_table",
    "stp",
    "poe",
    "optics",
    "running_config",
    "vlans",
    "port_profiles",
    "vrfs",
    "routing_peers",
    "fhrp",
    "dhcp",
    "services",
    "security_policy",
    "l2_operational",
    "discovery_protocols",
)
CRITICAL_COLLECTION_SECTIONS = frozenset({"interfaces", "running_config"})
CLI_ERROR_MARKERS = (
    "% invalid input",
    "% incomplete command",
    "% ambiguous command",
    "% unknown command",
    "privileged mode required",
    "syntax error",
    "command not found",
    "unknown command",
    "invalid command",
    "authorization failed",
    "permission denied",
)

_SNIPPET_REDACT_PATTERNS = (
    (re.compile(r"(?i)\b(secret|password|passwd|key|pre-shared-key|community)\s+(?:\d+\s+)?\S+"), r"\1 <REDACTED>"),
    (re.compile(r"\$[1569a-zA-Z]+\$[^\s'\"]+"), "<REDACTED_HASH>"),
)


def normalize_collection_status(val: object) -> str:
    """Normalize a collection_status state to a canonical COLLECTION_STATES value."""
    if isinstance(val, str):
        low = val.strip().lower()
        if low in COLLECTION_STATES:
            return low
    return "not_collected"


def _sanitize_error_snippet(raw: object, max_len: int = 200) -> str:
    """Collapse whitespace, redact secret-like tokens, and bound raw_snippet length."""
    text = re.sub(r"[\r\n\t]+", " ", str(raw or "")).strip()
    for pat, repl in _SNIPPET_REDACT_PATTERNS:
        text = pat.sub(repl, text)
    if len(text) > max_len:
        text = text[: max_len - 3].rstrip() + "..."
    return text


def build_parse_error(
    section: str,
    command: str = "",
    stage: str = "parse",
    error: str = "",
    raw_snippet: str = "",
) -> dict:
    """Build a sanitized structured parse/command error record for device_data['parse_errors']."""
    clean_stage = stage if stage in ("command", "parse") else "parse"
    return {
        "section": str(section or "unknown").strip(),
        "command": str(command or "").strip()[:160],
        "stage": clean_stage,
        "error": _sanitize_error_snippet(error, max_len=200),
        "raw_snippet": _sanitize_error_snippet(raw_snippet, max_len=200),
    }


def normalize_tri_state(val: object) -> str:
    """Normalize boolean/string policy values to 'enabled' | 'disabled' | 'unknown'."""
    if val is True:
        return "enabled"
    if val is False:
        return "disabled"
    if isinstance(val, str):
        low = val.strip().lower()
        if low in ("enabled", "enable", "yes", "true", "on", "active"):
            return "enabled"
        if low in ("disabled", "disable", "no", "false", "off", "none"):
            return "disabled"
    return "unknown"


def classify_record_class(device_data: dict) -> str:
    """
    Classify a device record into one of:
      - 'crawled_infra': successfully authenticated & crawled network infrastructure
      - 'unauthenticated_infra': reachable management port, authentication failed
      - 'unsupported_appliance': non-network appliance or unsupported SSH/HTTP/SNMP host
      - 'passive_endpoint': ARP-only discovered host
    """
    status = str(device_data.get("status", "success")).strip().lower()
    dtype = str(device_data.get("device_type") or device_data.get("device_persona") or "").strip().lower()

    if status == "success":
        if dtype in APPLIANCE_TYPES:
            return "unsupported_appliance"
        return "crawled_infra"
    if status == "unauthenticated":
        return "unauthenticated_infra"
    if status == "discovered":
        return "passive_endpoint"
    return "unsupported_appliance"


def infer_site_code(hostname: str, ip: str = "") -> str:
    """
    Extract a short site/building code from a device hostname (e.g. 'DO-Main-BLDG' -> 'DO',
    'NMS_MDF_CORE_BLDG_B' -> 'NMS'). Returns '' if hostname is generic or an IPv4 address.
    """
    h = (hostname or "").strip().strip('"').strip("'")
    if not h or h == ip or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", h):
        return ""
    m = re.match(r"^([A-Za-z]{2,6})[-_]", h)
    if m:
        return m.group(1).upper()
    return ""


def build_empty_port_record(hostname: str, interface: str, normalized_interface: str = "") -> dict:
    """Return a canonical Schema v2.0 per-port record with safe 'unknown' defaults."""
    return {
        "hostname": hostname,
        "interface": interface,
        "normalized_interface": normalized_interface or interface,
        "admin_state": "unknown",
        "oper_state": "unknown",
        "oper_reason": "",
        "last_flapped": "unknown",
        "description": "",
        "mode": "unknown",
        "access_vlan": "",
        "voice_vlan": "",
        "native_vlan": "unknown",
        "allowed_vlans": [],
        "allowed_vlans_raw": "",
        "lag_id": "unknown",
        "lacp_mode": "unknown",
        "speed_configured": "",
        "speed_operational": "",
        "duplex": "",
        "mtu": None,
        "media": "",
        "optic_part_number": "",
        "rx_power_dbm": None,
        "tx_power_dbm": None,
        "neighbor_hostname": "",
        "neighbor_port": "",
        "neighbor_ip": "",
        "neighbor_type": "",
        "link_confidence": "none",
        "stp_role": "unknown",
        "stp_state": "unknown",
        "stp_edge": "unknown",
        "bpdu_guard": "unknown",
        "storm_control": "unknown",
        "auth_policy": "unknown",
        "qos_trust": "unknown",
        "acl_in": "",
        "acl_out": "",
        "poe_state": "unknown",
        "poe_allocated_watts": 0.0,
        "poe_draw_watts": 0.0,
        "poe_class": "",
        "edge_mac_count": 0,
        "trunk_mac_count": 0,
        "last_mac_seen": "unknown",
        "hygiene_disposition": "REVIEW",
        "hygiene_reason": "",
    }


def build_empty_poe_summary() -> dict:
    """Return a canonical Schema v2.0 PoE summary dict."""
    return {
        "poe_supported": False,
        "total_power_watts": 0.0,
        "used_power_watts": 0.0,
        "allocated_power_watts": 0.0,
        "available_power_watts": 0.0,
        "poe_capable_ports": 0,
        "poe_enabled_ports": 0,
        "poe_delivering_ports": 0,
        "psu_redundancy": "unknown",
        "module_budgets": {},
        "ports": {},
    }


def stamp_schema_v2(device_data: dict, capture_time: str = "") -> dict:
    """
    Stamp Schema v2.0 metadata (`schema_version`, `capture_time`, `record_class`,
    `site_code`, `evidence_sources`) onto a `device_data` record in-place.
    """
    if not capture_time:
        capture_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    device_data["schema_version"] = SCHEMA_VERSION
    device_data.setdefault("capture_time", capture_time)
    device_data["record_class"] = classify_record_class(device_data)
    if not device_data.get("site_code"):
        device_data["site_code"] = infer_site_code(
            device_data.get("hostname", ""),
            device_data.get("ip", ""),
        )
    device_data.setdefault("evidence_sources", {})
    device_data.setdefault("vlans", {})
    device_data.setdefault("ports", {})
    raw_cs = device_data.get("collection_status")
    if isinstance(raw_cs, dict):
        device_data["collection_status"] = {str(k): normalize_collection_status(v) for k, v in raw_cs.items()}
    else:
        device_data["collection_status"] = {}
    if not isinstance(device_data.get("parse_errors"), list):
        device_data["parse_errors"] = []
    return device_data

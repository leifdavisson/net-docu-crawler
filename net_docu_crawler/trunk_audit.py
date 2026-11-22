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
Vendor-Agnostic Trunk VLAN Mismatch & Layer 2 Symmetry Audit Engine.

Normalizes switchport configuration and operational state across multi-vendor
switching platforms into `TrunkPortState`, resolves physical LAG/Port-Channel
members and 802.1Q router subinterfaces onto logical parent bundles, correlates
bidirectional CDP/LLDP edges, and evaluates trunk symmetry rules (`TRK-001`
through `TRK-007` plus boundary diagnostics).

Official Vendor & Library References:
  - Cisco IOS / IOS-XE / NX-OS: https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html
  - Juniper Networks Junos OS: https://www.juniper.net/documentation/product/us/en/junos-os/
  - HPE Aruba Networking AOS-CX: https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm
  - HPE ArubaOS-Switch (ProCurve): https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm
  - Arista EOS: https://www.arista.com/en/um-eos
  - netaddr IP/Network Library: https://netaddr.readthedocs.io/
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, replace

from netaddr import valid_ipv4

from net_docu_crawler.migration_parsers import extract_vlans
from net_docu_crawler.topology_resolver import normalize_hostname

logger = logging.getLogger(__name__)

CSV_COLUMNS: tuple[str, ...] = (
    "Edge_ID",
    "Side_A_Host",
    "Side_A_Port",
    "Side_B_Host",
    "Side_B_Port",
    "Rule_ID",
    "Severity",
    "Side_A_Only_VLANs",
    "Side_B_Only_VLANs",
    "Remediation_Hint",
)

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "NONE": 0,
}

_PSEUDO_PORT_PREFIXES: tuple[str, ...] = (
    "vlan",
    "irb",
    "bvi",
    "loopback",
    "null",
    "nve",
    "tunnel",
    "vme",
    "bme",
    "jsrv",
    "pfe-",
    "pfh-",
    "dsc",
    "mtun",
    "pflog",
    "pfsync",
    "enc",
)

_PSEUDO_PORT_EXACT: frozenset[str] = frozenset(
    {"lo", "lo0", "irb", "vlan", "vme", "dsc", "mtun", "mgmt", "mgmt0", "fxp0", "me0", "em0"}
)

_EDGE_PERIPHERAL_TYPES: frozenset[str] = frozenset(
    {
        "phone",
        "telephone",
        "voip",
        "printer",
        "camera",
        "host",
        "station",
        "workstation",
        "pc",
        "server",
        "iot",
        "display",
        "av_control",
        "ups",
        "nas",
    }
)

_PERIPHERAL_PLATFORM_KEYWORDS: tuple[str, ...] = (
    "ip phone",
    "voip",
    "cp-78",
    "cp-88",
    "polycom",
    "yealink",
    "mitel",
    "grandstream",
    "laserjet",
    "printer",
    "hikvision",
    "axis",
)

_AP_TYPES: frozenset[str] = frozenset({"ap", "wlan", "wireless"})

_AP_PLATFORM_RE = re.compile(
    r"(?:\baruba(?:/hpe)?\s+ap\b|\bap[-_\s]?\d{3}\b|\baironet\b|\bcatalyst\s+91\d{2}\b"
    r"|\bmeraki\s+mr\b|\bunifi\s+u[67]\b|\buap[-_]\b|\bruckus\b|\binstant\s+ap\b)",
    re.IGNORECASE,
)

_INFRA_DEVICE_TYPES: frozenset[str] = frozenset({"switch", "router", "firewall", "wlc", "bridge"})

_SKIPPED_RECORD_CLASSES: frozenset[str] = frozenset(
    {"unauthenticated_infra", "unsupported_appliance", "passive_endpoint"}
)

_PLACEHOLDER_SERIALS: frozenset[str] = frozenset({"unknown", "0", "n/a", "none", "not specified", "default string"})

_DOWN_PORT_STATUSES: frozenset[str] = frozenset(
    {"down", "administratively down", "admin-down", "notconnect", "disabled", "err-disabled"}
)

_DTP_ADMIN_MODES: frozenset[str] = frozenset({"dynamic_auto", "dynamic_desirable"})

_LAG_INHERITED_KEYS: tuple[str, ...] = (
    "mode",
    "admin_mode",
    "oper_mode",
    "native_vlan",
    "native_vlan_tagged",
    "trunk_allowed_vlans",
    "trunk_active_vlans",
    "access_vlan",
    "encapsulation",
    "qinq_tunnel",
)

_INTERFACE_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    (r"^(?:twentyfivegigabitethernet|twentyfivegige|twe|25ge)\s*(?=\d)", "TwentyFiveGigE"),
    (r"^(?:twopointfivegigabitethernet|tw)\s*(?=\d)", "TwoPointFiveGigabitEthernet"),
    (r"^(?:hundredgigabitethernet|hundredgige|hun|hu)\s*(?=\d)", "HundredGigE"),
    (r"^(?:fortygigabitethernet|fortygige|fo)\s*(?=\d)", "FortyGigabitEthernet"),
    (r"^(?:tengigabitethernet|tengige|ten|te)\s*(?=\d)", "TenGigabitEthernet"),
    (r"^(?:fivegigabitethernet|fivegige|fi)\s*(?=\d)", "FiveGigabitEthernet"),
    (r"^(?:gigabitethernet|gig|gi)\s*(?=\d)", "GigabitEthernet"),
    (r"^(?:fastethernet|fast|fa)\s*(?=\d)", "FastEthernet"),
    (r"^(?:port-channel|po)\s*(?=\d)", "Port-channel"),
    (r"^(?:bundle-ether|be)\s*(?=\d)", "Bundle-Ether"),
    (r"^(?:ethernet|eth|et)\s*(?=\d)", "Ethernet"),
)


@dataclass
class TrunkPortState:
    """Vendor-neutral normalized L2/L3 trunk switchport operational and administrative state."""

    device_hostname: str
    device_mgmt_ip: str
    vendor: str
    interface_name: str
    lag_parent: str | None = None
    admin_mode: str = "access"
    oper_mode: str = "down"
    native_vlan: int | None = 1
    native_vlan_tagged: bool = False
    allowed_vlans: set[int] = field(default_factory=set)
    active_vlans: set[int] = field(default_factory=set)
    encapsulation: str = "dot1q"
    neighbor_hostname: str | None = None
    neighbor_interface: str | None = None
    discovery_protocol: str | None = None
    qinq_tunnel: bool = False
    is_subinterface_bundle: bool = False


@dataclass(frozen=True)
class TrunkEdgeContext:
    """Canonical undirected link endpoints and normalized switchport states under evaluation."""

    edge_id: str
    side_a_host: str
    side_a_port: str
    side_b_host: str
    side_b_port: str
    state_a: TrunkPortState | None = None
    state_b: TrunkPortState | None = None


@dataclass(frozen=True)
class TrunkDiscrepancySpec:
    """Typed specification for recording a single trunk symmetry discrepancy and CSV row."""

    edge: TrunkEdgeContext
    rule_id: str
    severity: str
    message: str
    remediation_hint: str
    side_a_only_vlans: list[int] = field(default_factory=list)
    side_b_only_vlans: list[int] = field(default_factory=list)


@dataclass
class _TrunkAuditStats:
    """Mutable aggregation accumulator for trunk audit counters, findings, and CSV rows."""

    total_trunk_ports: int = 0
    evaluated_edges: int = 0
    matched_edges: int = 0
    clean_edges: int = 0
    mismatched_edges: int = 0
    uncrawled_neighbor_edges: int = 0
    asymmetric_discovery_edges: int = 0
    qinq_boundary_edges: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )
    rule_counts: dict[str, int] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    csv_rows: list[dict] = field(default_factory=list)


@dataclass
class _PeerLookupIndex:
    """Lookup index resolving crawled hostnames, management/L3 IPv4s, MACs, and LAG members."""

    dev_by_host: dict[str, dict] = field(default_factory=dict)
    ip_to_host: dict[str, str] = field(default_factory=dict)
    mac_to_host: dict[str, str] = field(default_factory=dict)
    global_member_to_lag: dict[tuple[str, str], str] = field(default_factory=dict)

    def resolve_peer_host(self, raw_name: str, remote_ip: str = "", remote_mac: str = "") -> str:
        """Resolve a neighbor identifier to a canonical crawled hostname when possible."""
        if remote_ip and remote_ip in self.ip_to_host:
            return self.ip_to_host[remote_ip]
        if remote_mac and remote_mac.lower() in self.mac_to_host:
            return self.mac_to_host[remote_mac.lower()]
        short_r, _ = normalize_hostname(raw_name)
        r_low = short_r.lower()
        if r_low in self.dev_by_host:
            return r_low
        if len(r_low) >= 12:
            pfx = [hk for hk in self.dev_by_host if hk.startswith(r_low)]
            if len(pfx) == 1:
                return pfx[0]
        return r_low


@dataclass
class _NeighborObservation:
    """Normalized directional neighbor observation prior to undirected edge correlation."""

    local_host: str
    local_port: str
    remote_host: str
    remote_port: str
    is_direct: bool
    raw_neighbor: dict = field(default_factory=dict)


@dataclass
class _EdgeCandidate:
    """Undirected candidate switchport link aggregated from directional observations."""

    endpoint_kind: str
    sample_nbr: dict = field(default_factory=dict)
    direct_from: set[tuple[str, str]] = field(default_factory=set)


def normalize_vendor_name(vendor: str = "", os_type: str = "", device_type: str = "") -> str:
    """Normalize vendor and OS strings to canonical snake_case platform identifiers."""
    os_l = (os_type or "").strip().lower()
    ven_l = (vendor or "").strip().lower()
    dt_l = (device_type or "").strip().lower()
    combined = f"{os_l} {ven_l}"

    if os_l in {
        "cisco_ios",
        "cisco_nxos",
        "cisco_s300",
        "juniper_junos",
        "aruba_cx",
        "hp_procurve",
        "arista_eos",
    }:
        return os_l
    if os_l == "aruba_aoscx" or "aos-cx" in combined or "aoscx" in combined or "aruba_cx" in combined:
        return "aruba_cx"
    if "nxos" in combined or "nx-os" in combined:
        return "cisco_nxos"
    if any(k in combined for k in ("cisco_s300", "ciscosmb", "sg300", "sg350", "cbs")):
        return "cisco_s300"
    if "cisco" in combined:
        return "cisco_ios"
    if "juniper" in combined or "junos" in combined:
        return "juniper_junos"
    if "procurve" in combined or "arubaos-s" in combined or "provision" in combined:
        return "hp_procurve"
    if "arista" in combined or "eos" in combined:
        return "arista_eos"
    if "aruba" in combined and dt_l == "switch":
        return "aruba_cx"

    raw = os_l or ven_l or "generic"
    cleaned = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    return cleaned or "generic"


def canonicalize_interface_full(intf: str) -> str:
    """
    Expand abbreviated vendor CLI interface names into full canonical nomenclature.

    Examples:
      - 'Gi1/0/1'    -> 'GigabitEthernet1/0/1'
      - 'Te1/1/1'    -> 'TenGigabitEthernet1/1/1'
      - 'Po1'        -> 'Port-channel1'
      - 'Eth1/1'     -> 'Ethernet1/1'
      - 'ge-0/0/1.0' -> 'ge-0/0/1'
    """
    if not intf:
        return ""
    name = intf.strip().strip('"').strip("'")
    if not name:
        return ""

    name = re.sub(r"\.0$", "", name)

    m_junos = re.match(r"^(ge-|mge-|xe-|et-|fe-|ae(?=\d)|reth(?=\d))(.*)$", name, flags=re.IGNORECASE)
    if m_junos:
        return f"{m_junos.group(1).lower()}{m_junos.group(2)}"

    m_trk = re.match(r"^trk\s*(\d+)$", name, flags=re.IGNORECASE)
    if m_trk:
        return f"Trk{m_trk.group(1)}"
    m_lag = re.match(r"^lag\s*(\d+)$", name, flags=re.IGNORECASE)
    if m_lag:
        return f"lag{m_lag.group(1)}"

    for pattern, full_prefix in _INTERFACE_PREFIX_RULES:
        if re.match(pattern, name, flags=re.IGNORECASE):
            return re.sub(pattern, full_prefix, name, count=1, flags=re.IGNORECASE)

    return name


def _parse_vlan_token(
    tok: str,
    known_vlans: set[int] | None,
    vlan_name_map: dict[str, int] | None,
) -> set[int]:
    """Parse a single comma/space-delimited VLAN token or range into valid 1..4094 IDs."""
    tok_low = tok.lower()
    if tok_low in {"", "none", "null", "-"}:
        return set()
    if tok_low == "all":
        return {v for v in known_vlans if 1 <= v <= 4094} if known_vlans else set(range(1, 4095))

    m_rng = re.match(r"^(\d+)-(\d+)$", tok)
    if m_rng:
        start_v = max(1, int(m_rng.group(1)))
        end_v = min(4094, int(m_rng.group(2)))
        return set(range(start_v, end_v + 1)) if start_v <= end_v else set()

    if tok.isdigit():
        vid = int(tok)
        return {vid} if 1 <= vid <= 4094 else set()

    m_prefixed = re.match(r"^(?:vlan|vl)[_-]?0*(\d+)$", tok, flags=re.IGNORECASE)
    if m_prefixed:
        vid = int(m_prefixed.group(1))
        return {vid} if 1 <= vid <= 4094 else set()

    if vlan_name_map and tok_low in vlan_name_map:
        vid = vlan_name_map[tok_low]
        return {vid} if 1 <= vid <= 4094 else set()

    if tok_low in {"default", "default_vlan"}:
        return {1}
    return set()


def expand_vlan_spec(
    spec: str | list[str] | set[int] | None,
    known_vlans: set[int] | None = None,
    vlan_name_map: dict[str, int] | None = None,
) -> set[int]:
    """
    Expand a vendor VLAN specification into an explicit integer set within 1..4094.

    Examples:
      - '1,10-12,4094' -> {1, 10, 11, 12, 4094}
      - 'none'         -> set()
      - 'all'          -> set(known_vlans) if known_vlans else set(range(1, 4095))
    """
    if spec is None:
        return set()

    if isinstance(spec, (set, frozenset, list, tuple)):
        out: set[int] = set()
        for item in spec:
            if isinstance(item, int) and not isinstance(item, bool):
                if 1 <= item <= 4094:
                    out.add(item)
            else:
                out.update(expand_vlan_spec(str(item), known_vlans=known_vlans, vlan_name_map=vlan_name_map))
        return out

    raw = str(spec).strip().strip("[]").strip()
    if not raw:
        return set()

    low = raw.lower()
    if low in {"none", "null", "unassigned", "unknown", "-"}:
        return set()

    m_except = re.match(r"^(?:all\s+)?except\s+(.+)$", raw, flags=re.IGNORECASE)
    if m_except:
        base = set(known_vlans) if known_vlans else set(range(1, 4095))
        excluded = expand_vlan_spec(m_except.group(1), known_vlans=known_vlans, vlan_name_map=vlan_name_map)
        return {v for v in (base - excluded) if 1 <= v <= 4094}

    if low == "all":
        return {v for v in known_vlans if 1 <= v <= 4094} if known_vlans else set(range(1, 4095))

    cleaned = re.sub(r"\badd\b", ",", raw, flags=re.IGNORECASE)
    cleaned = re.sub(r"(\d)\s*-\s*(\d)", r"\1-\2", cleaned)

    result: set[int] = set()
    for token in re.split(r"[,\s]+", cleaned):
        tok = token.strip().strip('"').strip("'")
        if tok:
            result.update(_parse_vlan_token(tok, known_vlans, vlan_name_map))
    return result


def _format_vlan_run(run_start: int, run_end: int) -> str:
    """Format a contiguous run of VLAN IDs into compact range or comma notation."""
    if run_end - run_start >= 2:
        return f"{run_start}-{run_end}"
    if run_end > run_start:
        return f"{run_start},{run_end}"
    return str(run_start)


def format_vlan_set(vlans: set[int] | list[int]) -> str:
    """Format a set/list of VLAN IDs into compact sorted range notation (e.g., '10-12,50')."""
    ordered = sorted({int(v) for v in vlans if 1 <= int(v) <= 4094})
    if not ordered:
        return ""
    parts: list[str] = []
    run_start = ordered[0]
    run_end = ordered[0]
    for vid in ordered[1:]:
        if vid == run_end + 1:
            run_end = vid
        else:
            parts.append(_format_vlan_run(run_start, run_end))
            run_start = run_end = vid
    parts.append(_format_vlan_run(run_start, run_end))
    return ",".join(parts)


def _is_pseudo_or_svi_interface(port_name: str) -> bool:
    """Return True for non-switchport virtual, loopback, SVI, or kernel pseudo interfaces."""
    if not port_name:
        return True
    low = port_name.strip().lower()
    if low in _PSEUDO_PORT_EXACT:
        return True
    return low.startswith(_PSEUDO_PORT_PREFIXES)


def _is_eligible_crawled_infra(dev: object) -> bool:
    """Return True if `dev` is a successfully crawled infrastructure device record."""
    if not isinstance(dev, dict):
        return False
    if dev.get("status", "success") != "success":
        return False
    return dev.get("record_class") not in _SKIPPED_RECORD_CLASSES


def _parse_device_vlans(dev: dict) -> tuple[set[int], dict[str, int], bool]:
    """
    Extract (configured_vlan_ids, vlan_name_to_id_map, has_explicit_vlan_db) from `dev`.
    Falls back to `extract_vlans(raw_config)` for legacy datasets missing `dev["vlans"]`.
    """
    raw_vlans = dev.get("vlans")
    explicit_db = bool(raw_vlans)
    vlans_source = raw_vlans
    if not vlans_source and "vlans" not in dev and dev.get("raw_config"):
        vlans_source = extract_vlans(str(dev.get("raw_config") or ""), vendor=str(dev.get("vendor") or ""))

    configured_ids: set[int] = set()
    name_map: dict[str, int] = {}

    if isinstance(vlans_source, dict):
        for k, val in vlans_source.items():
            vid_raw = str(val.get("id") if isinstance(val, dict) and val.get("id") else k).strip()
            if vid_raw.isdigit() and 1 <= int(vid_raw) <= 4094:
                vid = int(vid_raw)
                configured_ids.add(vid)
                if isinstance(val, dict) and val.get("name"):
                    vname = str(val["name"]).strip().strip('"').strip("'").lower()
                    if vname:
                        name_map[vname] = vid
    elif isinstance(vlans_source, (list, set, tuple)):
        explicit_db = len(vlans_source) > 0
        for item in vlans_source:
            if isinstance(item, int) and 1 <= item <= 4094:
                configured_ids.add(item)
            elif isinstance(item, str) and item.strip().isdigit() and 1 <= int(item.strip()) <= 4094:
                configured_ids.add(int(item.strip()))
            elif isinstance(item, dict) and str(item.get("id", "")).strip().isdigit():
                vid = int(str(item["id"]).strip())
                if 1 <= vid <= 4094:
                    configured_ids.add(vid)
                    if item.get("name"):
                        name_map[str(item["name"]).strip().lower()] = vid

    return configured_ids, name_map, explicit_db


def _collect_profile_subinterfaces(
    merged: dict[str, dict],
    sub_groups: dict[str, dict[str, object]],
) -> None:
    """Extract `<parent>.<unit>` keys already present in `merged` into `sub_groups`."""
    sub_keys_to_pop: list[str] = []
    for port_key, prof in list(merged.items()):
        m_sub = re.match(r"^([^.\s]+)\.(\d+)$", port_key.strip())
        if not m_sub:
            continue
        sub_unit = int(m_sub.group(2))
        if sub_unit == 0:
            continue
        parent = canonicalize_interface_full(m_sub.group(1))
        if _is_pseudo_or_svi_interface(parent):
            continue
        sub_keys_to_pop.append(port_key)
        grp = sub_groups.setdefault(parent, {"vlans": set(), "native": None})
        vlans_set = grp["vlans"]
        assert isinstance(vlans_set, set)
        allowed_here = expand_vlan_spec(prof.get("trunk_allowed_vlans") or prof.get("allowed_vlans") or "")
        if allowed_here:
            vlans_set.update(allowed_here)
        elif str(prof.get("vlan_id") or "").isdigit():
            vlans_set.add(int(str(prof["vlan_id"])))
        elif 1 <= sub_unit <= 4094:
            vlans_set.add(sub_unit)
        nat_val = str(prof.get("native_vlan") or "").strip()
        if nat_val.isdigit():
            grp["native"] = int(nat_val)
            vlans_set.add(int(nat_val))

    for key in sub_keys_to_pop:
        merged.pop(key, None)


def _has_existing_subinterface_bundle(merged: dict[str, dict], parent: str) -> bool:
    """Return True if `merged` already defines `is_subinterface_bundle` for canonical `parent`."""
    return any(
        canonicalize_interface_full(existing_k) == parent and existing_v.get("is_subinterface_bundle")
        for existing_k, existing_v in merged.items()
    )


def _collect_raw_config_subinterfaces(
    raw_config: str,
    merged: dict[str, dict],
    sub_groups: dict[str, dict[str, object]],
) -> None:
    """Parse Cisco/Arista dot1Q and Juniper Junos VLAN subinterfaces from `raw_config`."""
    if not raw_config:
        return

    for blk in re.split(r"(?m)^interface\s+", raw_config)[1:]:
        lines = blk.splitlines()
        if not lines:
            continue
        m_sub = re.match(r"^([^.\s]+)\.(\d+)$", lines[0].strip())
        if not m_sub or int(m_sub.group(2)) == 0:
            continue
        body = "\n".join(lines[1:]).split("\n!")[0]
        m_dot1q = re.search(
            r"^\s*encapsulation\s+dot1[qQ]\s+(\d+)(?:\s+(native))?",
            body,
            flags=re.MULTILINE,
        )
        if not m_dot1q:
            continue
        parent = canonicalize_interface_full(m_sub.group(1))
        if _has_existing_subinterface_bundle(merged, parent):
            continue
        vid = int(m_dot1q.group(1))
        grp = sub_groups.setdefault(parent, {"vlans": set(), "native": None})
        assert isinstance(grp["vlans"], set)
        if 1 <= vid <= 4094:
            grp["vlans"].add(vid)
            if m_dot1q.group(2):
                grp["native"] = vid

    for m_j_sub in re.finditer(r"set\s+interfaces\s+(\S+)\s+unit\s+([1-9]\d*)\s+vlan-id\s+(\d+)", raw_config):
        parent = canonicalize_interface_full(m_j_sub.group(1))
        if _has_existing_subinterface_bundle(merged, parent):
            continue
        vid = int(m_j_sub.group(3))
        grp = sub_groups.setdefault(parent, {"vlans": set(), "native": None})
        assert isinstance(grp["vlans"], set)
        if 1 <= vid <= 4094:
            grp["vlans"].add(vid)


def _synthesize_subinterface_profiles(
    raw_profiles: dict[str, dict],
    raw_config: str,
) -> dict[str, dict]:
    """
    Collapse 802.1Q router-on-a-stick subinterfaces (e.g. `Gi0/0.10`, `ge-0/0/1.10`)
    into virtual parent port profiles (`is_subinterface_bundle=True`) if not already merged.
    """
    merged: dict[str, dict] = {k: dict(v) for k, v in raw_profiles.items() if isinstance(v, dict)}
    sub_groups: dict[str, dict[str, object]] = {}

    _collect_profile_subinterfaces(merged, sub_groups)
    _collect_raw_config_subinterfaces(raw_config, merged, sub_groups)

    for parent, grp in sub_groups.items():
        vlans_set = grp["vlans"]
        assert isinstance(vlans_set, set)
        if not vlans_set:
            continue
        native_id = grp["native"]
        target_key = next(
            (existing_k for existing_k in merged if canonicalize_interface_full(existing_k) == parent),
            parent,
        )
        prof = merged.setdefault(target_key, {})
        prof["mode"] = "trunk"
        prof["admin_mode"] = "trunk"
        prof["oper_mode"] = prof.get("oper_mode") or "trunk"
        prof["encapsulation"] = "dot1q"
        prof["is_subinterface_bundle"] = True
        existing_vlans = expand_vlan_spec(prof.get("trunk_allowed_vlans") or "")
        prof["trunk_allowed_vlans"] = format_vlan_set(existing_vlans | vlans_set)
        if isinstance(native_id, int):
            prof["native_vlan"] = str(native_id)
            prof["native_vlan_tagged"] = False
        elif not str(prof.get("native_vlan") or "").strip():
            prof["native_vlan"] = "none"
            prof["native_vlan_tagged"] = True

    return merged


def _collect_device_lag_member_map(dev: dict) -> dict[str, str]:
    """Return `{canonical_member_interface: canonical_parent_lag_interface}` for `dev`."""
    member_map: dict[str, str] = {}
    for source_dict in (dev.get("port_profiles") or {}, dev.get("ports") or {}):
        if not isinstance(source_dict, dict):
            continue
        for port_name, prof in source_dict.items():
            if not isinstance(prof, dict):
                continue
            raw_lag = str(prof.get("lag_parent") or prof.get("lag_group") or prof.get("lag_id") or "").strip()
            if not raw_lag or raw_lag.lower() in {"none", "unknown", "-"}:
                continue
            m_canon = canonicalize_interface_full(port_name)
            p_canon = canonicalize_interface_full(raw_lag)
            if m_canon and p_canon and m_canon != p_canon:
                member_map[m_canon] = p_canon
    return member_map


def _resolve_native_vlan_and_tagging(
    prof: dict,
    admin_mode: str,
    oper_mode: str,
    vendor: str,
    raw_config: str,
    port_canon: str,
    vlan_name_map: dict[str, int],
) -> tuple[int | None, bool]:
    """Resolve `(native_vlan, native_vlan_tagged)` across Cisco, Junos, Aruba, Arista, and ProCurve."""
    explicit_tagged = prof.get("native_vlan_tagged")
    raw_nat = prof.get("native_vlan")
    if "native_vlan" in prof and raw_nat is None and explicit_tagged is True:
        return None, True

    nat_str = str(raw_nat).strip() if raw_nat is not None else ""
    nat_low = nat_str.lower()
    tag_flag = bool(explicit_tagged) if explicit_tagged is not None else False

    if nat_low in {"none", "tagged", "null"}:
        return None, True if explicit_tagged is None else bool(explicit_tagged)
    if nat_str.isdigit():
        return int(nat_str), tag_flag
    if nat_low and nat_low in vlan_name_map:
        return vlan_name_map[nat_low], tag_flag

    is_trunk = oper_mode in {"trunk", "dot1q_tunnel"} or admin_mode in {
        "trunk",
        "dot1q_tunnel",
        "dynamic_auto",
        "dynamic_desirable",
    }
    if is_trunk:
        if vendor == "juniper_junos" and raw_config:
            m_jnat = re.search(
                rf"set\s+interfaces\s+{re.escape(port_canon)}\s+(?:unit\s+0\s+family\s+ethernet-switching\s+)?native-vlan-id\s+(\S+)",
                raw_config,
            )
            if m_jnat:
                tok = m_jnat.group(1).strip('"').lower()
                if tok.isdigit():
                    return int(tok), tag_flag
                if tok in vlan_name_map:
                    return vlan_name_map[tok], tag_flag
            return None, True if explicit_tagged is None else bool(explicit_tagged)
        return 1, tag_flag

    acc_str = str(prof.get("access_vlan") or "").strip()
    if acc_str.isdigit():
        return int(acc_str), False
    if acc_str.lower() in vlan_name_map:
        return vlan_name_map[acc_str.lower()], False
    return 1, False


def _extract_raw_port_profiles(dev: dict) -> dict[str, dict]:
    """Extract `port_profiles` or adapt Schema v2.0 `ports` dictionary into profile format."""
    raw_profiles = dev.get("port_profiles") or {}
    if raw_profiles or not isinstance(dev.get("ports"), dict):
        return raw_profiles if isinstance(raw_profiles, dict) else {}
    return {
        pk: {
            "mode": pv.get("mode", "unknown"),
            "admin_mode": pv.get("admin_mode", pv.get("mode", "unknown")),
            "oper_mode": pv.get("oper_mode", ""),
            "access_vlan": pv.get("access_vlan", ""),
            "voice_vlan": pv.get("voice_vlan", ""),
            "native_vlan": "" if pv.get("native_vlan") == "unknown" else pv.get("native_vlan", ""),
            "native_vlan_tagged": pv.get("native_vlan_tagged", False),
            "trunk_allowed_vlans": pv.get("allowed_vlans_raw") or pv.get("allowed_vlans") or "",
            "trunk_active_vlans": pv.get("trunk_active_vlans", ""),
            "lag_group": "" if pv.get("lag_id") in ("none", "unknown") else pv.get("lag_id", ""),
            "encapsulation": pv.get("encapsulation", "dot1q"),
            "qinq_tunnel": pv.get("qinq_tunnel", False),
            "is_subinterface_bundle": pv.get("is_subinterface_bundle", False),
        }
        for pk, pv in dev["ports"].items()
        if isinstance(pv, dict)
    }


def _canonicalize_device_port_maps(
    synthesized_profiles: dict[str, dict],
    interfaces_detail: dict,
    neighbors: list,
    member_to_lag: dict[str, str],
) -> tuple[dict[str, dict], dict[str, dict], dict[str, list[str]], dict[str, list[dict]]]:
    """Canonicalize device profiles, interface stats, LAG member inheritances, and port neighbors."""
    profiles_by_canon: dict[str, dict] = {}
    for pk, pv in synthesized_profiles.items():
        if not isinstance(pv, dict):
            continue
        c_name = canonicalize_interface_full(pk)
        if not c_name or _is_pseudo_or_svi_interface(c_name):
            continue
        if c_name in profiles_by_canon:
            profiles_by_canon[c_name].update({k: v for k, v in pv.items() if v not in ("", None, "unknown")})
        else:
            profiles_by_canon[c_name] = dict(pv)

    stats_by_canon: dict[str, dict] = {}
    for ik, iv in (interfaces_detail or {}).items():
        if isinstance(iv, dict):
            c_name = canonicalize_interface_full(ik)
            if c_name and not _is_pseudo_or_svi_interface(c_name):
                stats_by_canon[c_name] = iv

    lag_members_by_parent: dict[str, list[str]] = {}
    for m_port, p_lag in member_to_lag.items():
        lag_members_by_parent.setdefault(p_lag, []).append(m_port)
        p_prof = profiles_by_canon.setdefault(p_lag, {})
        m_prof = profiles_by_canon.get(m_port, {})
        for inherit_k in _LAG_INHERITED_KEYS:
            if p_prof.get(inherit_k) in ("", None, "unknown") and m_prof.get(inherit_k) not in ("", None, "unknown"):
                p_prof[inherit_k] = m_prof[inherit_k]

    neighbors_by_port: dict[str, list[dict]] = {}
    for nbr in neighbors or []:
        if not isinstance(nbr, dict):
            continue
        raw_lp = str(nbr.get("local_port") or "").strip()
        if not raw_lp:
            continue
        base_lp = re.sub(r"\.\d+$", "", raw_lp) if re.match(r"^[^.\s]+\.\d+$", raw_lp) else raw_lp
        lp_canon = canonicalize_interface_full(base_lp)
        if lp_canon and not _is_pseudo_or_svi_interface(lp_canon):
            effective_port = member_to_lag.get(lp_canon, lp_canon)
            neighbors_by_port.setdefault(effective_port, []).append(nbr)

    return profiles_by_canon, stats_by_canon, lag_members_by_parent, neighbors_by_port


def _resolve_port_modes_and_encap(
    prof: dict,
    stats: dict,
    member_ports: list[str],
    stats_by_canon: dict[str, dict],
) -> tuple[str, str, str, bool, bool]:
    """Determine `(admin_mode, oper_mode, encapsulation, qinq, is_sub_bundle)` for a switchport."""
    is_sub_bundle = bool(prof.get("is_subinterface_bundle", False))
    raw_admin = str(prof.get("admin_mode") or prof.get("mode") or "").strip().lower().replace("-", "_")
    qinq = bool(prof.get("qinq_tunnel", False)) or raw_admin in {"dot1q_tunnel", "qinq"}

    if qinq:
        admin_mode = "dot1q_tunnel"
    elif raw_admin in {"dynamic_auto", "auto"}:
        admin_mode = "dynamic_auto"
    elif raw_admin in {"dynamic_desirable", "desirable"}:
        admin_mode = "dynamic_desirable"
    elif raw_admin == "trunk" or is_sub_bundle:
        admin_mode = "trunk"
    elif raw_admin == "routed":
        admin_mode = "routed"
    else:
        admin_mode = "access"

    port_status_str = str(stats.get("status") or "").strip().lower()
    if not port_status_str and member_ports:
        member_statuses = [str(stats_by_canon.get(mp, {}).get("status") or "").strip().lower() for mp in member_ports]
        if any(ms in {"up", "connected"} for ms in member_statuses):
            port_status_str = "up"
        elif member_statuses and all(ms in _DOWN_PORT_STATUSES for ms in member_statuses):
            port_status_str = "down"

    raw_oper = str(prof.get("oper_mode") or "").strip().lower().replace("-", "_")
    if raw_oper in {"trunk", "trunking"}:
        oper_mode = "trunk"
    elif raw_oper in {"dot1q_tunnel", "qinq"}:
        oper_mode = "dot1q_tunnel"
    elif raw_oper in {"access", "static_access"}:
        oper_mode = "access"
    elif raw_oper in {"routed", "down"}:
        oper_mode = raw_oper
    elif port_status_str in _DOWN_PORT_STATUSES:
        oper_mode = "down"
    elif qinq:
        oper_mode = "dot1q_tunnel"
    elif (
        admin_mode in {"trunk", "dynamic_desirable"} or str(prof.get("mode") or "").lower() == "trunk" or is_sub_bundle
    ):
        oper_mode = "trunk"
    elif admin_mode == "dynamic_auto":
        oper_mode = "trunk" if prof.get("trunk_allowed_vlans") else "access"
    elif admin_mode == "routed":
        oper_mode = "routed"
    else:
        oper_mode = "access"

    encap_raw = str(prof.get("encapsulation") or "dot1q").strip().lower()
    if "isl" in encap_raw and "dot1q" not in encap_raw:
        encapsulation = "isl"
    elif "neg" in encap_raw:
        encapsulation = "negotiate"
    else:
        encapsulation = "dot1q"

    return admin_mode, oper_mode, encapsulation, qinq, is_sub_bundle


def _resolve_port_vlan_sets(
    prof: dict,
    admin_mode: str,
    oper_mode: str,
    vendor: str,
    qinq: bool,
    native_vlan: int | None,
    configured_vlan_ids: set[int],
    vlan_name_map: dict[str, int],
    has_explicit_vlan_db: bool,
) -> tuple[set[int], set[int]]:
    """Expand `(allowed_vlans, active_vlans)` for a normalized switchport profile."""
    raw_allowed = prof.get("trunk_allowed_vlans")
    if raw_allowed in ("", None) and "allowed_vlans" in prof:
        raw_allowed = prof.get("allowed_vlans")

    is_trunk_port = oper_mode in {"trunk", "dot1q_tunnel"} or admin_mode in {
        "trunk",
        "dot1q_tunnel",
        "dynamic_auto",
        "dynamic_desirable",
    }
    if raw_allowed not in ("", None, []):
        allowed_vlans = expand_vlan_spec(
            raw_allowed,
            known_vlans=configured_vlan_ids or None,
            vlan_name_map=vlan_name_map,
        )
    elif is_trunk_port and vendor in {"cisco_ios", "cisco_nxos", "cisco_s300", "arista_eos"} and not qinq:
        allowed_vlans = set(configured_vlan_ids) if configured_vlan_ids else set(range(1, 4095))
    elif not is_trunk_port and isinstance(native_vlan, int) and oper_mode != "routed":
        allowed_vlans = {native_vlan}
        voice_raw = str(prof.get("voice_vlan") or "").strip()
        if voice_raw.isdigit() and 1 <= int(voice_raw) <= 4094:
            allowed_vlans.add(int(voice_raw))
    else:
        allowed_vlans = set()

    raw_active = prof.get("trunk_active_vlans")
    if raw_active in ("", None) and "active_vlans" in prof:
        raw_active = prof.get("active_vlans")

    if raw_active not in ("", None, []):
        active_vlans = expand_vlan_spec(
            raw_active,
            known_vlans=configured_vlan_ids or None,
            vlan_name_map=vlan_name_map,
        )
    elif has_explicit_vlan_db and configured_vlan_ids:
        active_vlans = allowed_vlans & configured_vlan_ids
    else:
        active_vlans = set(allowed_vlans)

    return allowed_vlans, active_vlans


def _resolve_discovery_protocol(chosen_list: list[dict]) -> str:
    """Resolve aggregate discovery protocol label (`'cdp'`, `'lldp'`, `'both'`, `'mndp'`) for neighbor entries."""
    protos: set[str] = set()
    for n_item in chosen_list:
        p_val = str(n_item.get("discovery_protocol") or n_item.get("protocol") or "").strip().lower()
        if p_val == "both":
            protos.update({"cdp", "lldp"})
        elif p_val in {"cdp", "lldp", "mndp"}:
            protos.add(p_val)
    if {"cdp", "lldp"} <= protos:
        return "both"
    if protos:
        return sorted(protos)[0]
    return "lldp"


def _build_port_neighbor_states(
    base_state: TrunkPortState,
    port_nbrs: list[dict],
) -> list[TrunkPortState]:
    """Materialize one `TrunkPortState` per distinct remote host (or a single unattached state)."""
    grouped_by_remote: dict[str, list[dict]] = {}
    for nbr in port_nbrs:
        r_short, _ = normalize_hostname(str(nbr.get("remote_device") or nbr.get("remote_ip") or ""))
        r_key = r_short.lower()
        if r_key:
            grouped_by_remote.setdefault(r_key, []).append(nbr)

    if not grouped_by_remote:
        return [
            replace(
                base_state,
                allowed_vlans=set(base_state.allowed_vlans),
                active_vlans=set(base_state.active_vlans),
            )
        ]

    port_states: list[TrunkPortState] = []
    for r_host_low, nbr_list in sorted(grouped_by_remote.items()):
        direct_nbrs = [n for n in nbr_list if str(n.get("link_confidence") or "") != "INFERRED"]
        chosen_list = direct_nbrs if direct_nbrs else nbr_list
        raw_rp = str(chosen_list[0].get("remote_port") or "").strip()
        r_port_canon = None if raw_rp.lower() in {"unknown", "n/a", "-", ""} else canonicalize_interface_full(raw_rp)

        port_states.append(
            replace(
                base_state,
                allowed_vlans=set(base_state.allowed_vlans),
                active_vlans=set(base_state.active_vlans),
                neighbor_hostname=r_host_low,
                neighbor_interface=r_port_canon,
                discovery_protocol=_resolve_discovery_protocol(chosen_list),
            )
        )
    return port_states


def _build_base_port_state(
    port_canon: str,
    device_hostname: str,
    device_mgmt_ip: str,
    vendor: str,
    raw_config: str,
    prof: dict,
    stats: dict,
    member_ports: list[str],
    stats_by_canon: dict[str, dict],
    configured_vlan_ids: set[int],
    vlan_name_map: dict[str, int],
    has_explicit_vlan_db: bool,
) -> TrunkPortState:
    """Build the unattached base `TrunkPortState` for a single canonical device port."""
    admin_mode, oper_mode, encapsulation, qinq, is_sub_bundle = _resolve_port_modes_and_encap(
        prof=prof,
        stats=stats,
        member_ports=member_ports,
        stats_by_canon=stats_by_canon,
    )
    native_vlan, native_vlan_tagged = _resolve_native_vlan_and_tagging(
        prof=prof,
        admin_mode=admin_mode,
        oper_mode=oper_mode,
        vendor=vendor,
        raw_config=raw_config,
        port_canon=port_canon,
        vlan_name_map=vlan_name_map,
    )
    allowed_vlans, active_vlans = _resolve_port_vlan_sets(
        prof=prof,
        admin_mode=admin_mode,
        oper_mode=oper_mode,
        vendor=vendor,
        qinq=qinq,
        native_vlan=native_vlan,
        configured_vlan_ids=configured_vlan_ids,
        vlan_name_map=vlan_name_map,
        has_explicit_vlan_db=has_explicit_vlan_db,
    )
    return TrunkPortState(
        device_hostname=device_hostname,
        device_mgmt_ip=device_mgmt_ip,
        vendor=vendor,
        interface_name=port_canon,
        lag_parent=None,
        admin_mode=admin_mode,
        oper_mode=oper_mode,
        native_vlan=native_vlan,
        native_vlan_tagged=native_vlan_tagged,
        allowed_vlans=allowed_vlans,
        active_vlans=active_vlans,
        encapsulation=encapsulation,
        qinq_tunnel=qinq,
        is_subinterface_bundle=is_sub_bundle,
    )


def extract_device_trunk_states(dev: dict) -> list[TrunkPortState]:
    """
    Normalize a crawled device record into `TrunkPortState` instances.

    Resolves physical LAG/Port-Channel members (`lag_parent` / `lag_group`) onto
    their parent logical bundle (`Port-channel1`, `ae0`, `Trk1`, `lag1`) and
    router-on-a-stick dot1Q subinterfaces onto their parent interface prior to
    bidirectional edge correlation.
    """
    if not _is_eligible_crawled_infra(dev):
        return []

    short_host, _ = normalize_hostname(str(dev.get("hostname") or dev.get("canonical_hostname") or dev.get("ip") or ""))
    device_hostname = short_host.lower()
    device_mgmt_ip = str(dev.get("ip") or "")
    vendor = normalize_vendor_name(
        vendor=str(dev.get("vendor") or ""),
        os_type=str(dev.get("os_type") or ""),
        device_type=str(dev.get("device_type") or dev.get("device_persona") or ""),
    )
    raw_config = str(dev.get("raw_config") or "")

    configured_vlan_ids, vlan_name_map, has_explicit_vlan_db = _parse_device_vlans(dev)
    synthesized_profiles = _synthesize_subinterface_profiles(_extract_raw_port_profiles(dev), raw_config)
    member_to_lag = _collect_device_lag_member_map({"port_profiles": synthesized_profiles})

    profiles_by_canon, stats_by_canon, lag_members_by_parent, neighbors_by_port = _canonicalize_device_port_maps(
        synthesized_profiles=synthesized_profiles,
        interfaces_detail=dev.get("interfaces_detail") or {},
        neighbors=dev.get("neighbors") or [],
        member_to_lag=member_to_lag,
    )

    candidate_ports = sorted(
        (set(profiles_by_canon) | set(stats_by_canon) | set(neighbors_by_port)) - set(member_to_lag)
    )

    states: list[TrunkPortState] = []
    for port_canon in candidate_ports:
        base_state = _build_base_port_state(
            port_canon=port_canon,
            device_hostname=device_hostname,
            device_mgmt_ip=device_mgmt_ip,
            vendor=vendor,
            raw_config=raw_config,
            prof=profiles_by_canon.get(port_canon, {}),
            stats=stats_by_canon.get(port_canon, {}),
            member_ports=lag_members_by_parent.get(port_canon, []),
            stats_by_canon=stats_by_canon,
            configured_vlan_ids=configured_vlan_ids,
            vlan_name_map=vlan_name_map,
            has_explicit_vlan_db=has_explicit_vlan_db,
        )
        states.extend(_build_port_neighbor_states(base_state, neighbors_by_port.get(port_canon, [])))

    return states


def _is_trunk_like(state: TrunkPortState) -> bool:
    """Return True if a port is configured or operating as an 802.1Q trunk, DTP, QinQ, or subinterface bundle."""
    return (
        state.oper_mode in {"trunk", "dot1q_tunnel"}
        or state.admin_mode in {"trunk", "dot1q_tunnel", "dynamic_auto", "dynamic_desirable"}
        or state.qinq_tunnel
        or state.is_subinterface_bundle
    )


def _classify_neighbor_endpoint(nbr: dict, peer_dev: dict | None = None) -> str:
    """Classify a neighbor into `'peripheral'`, `'ap'`, or `'infra'`."""
    if peer_dev is not None:
        p_dtype = str(peer_dev.get("device_type") or peer_dev.get("device_persona") or "").strip().lower()
        if p_dtype in _AP_TYPES:
            return "ap"
        if p_dtype in _EDGE_PERIPHERAL_TYPES or peer_dev.get("record_class") in {
            "unsupported_appliance",
            "passive_endpoint",
        }:
            return "peripheral"
        if p_dtype in _INFRA_DEVICE_TYPES:
            return "infra"

    dtype = str(nbr.get("device_type") or "").strip().lower()
    plat = str(nbr.get("platform") or nbr.get("remote_platform") or "").strip().lower()

    if dtype in _EDGE_PERIPHERAL_TYPES or any(kw in plat for kw in _PERIPHERAL_PLATFORM_KEYWORDS):
        return "peripheral"
    if dtype in _AP_TYPES or _AP_PLATFORM_RE.search(plat):
        return "ap"
    return "infra"


def _serialize_endpoint(state: TrunkPortState | None, fallback_host: str, fallback_port: str) -> dict:
    """Serialize a `TrunkPortState` (or uncrawled stub) into the JSON finding `endpoints` schema."""
    if state is None:
        return {
            "hostname": fallback_host,
            "mgmt_ip": "",
            "vendor": "uncrawled",
            "interface": fallback_port,
            "lag_parent": None,
            "admin_mode": "unknown",
            "oper_mode": "unknown",
            "native_vlan": None,
            "native_vlan_tagged": False,
            "allowed_vlans": [],
            "active_vlans": [],
            "encapsulation": "unknown",
            "qinq_tunnel": False,
            "is_subinterface_bundle": False,
            "crawled": False,
        }
    return {
        "hostname": state.device_hostname,
        "mgmt_ip": state.device_mgmt_ip,
        "vendor": state.vendor,
        "interface": state.interface_name,
        "lag_parent": state.lag_parent,
        "admin_mode": state.admin_mode,
        "oper_mode": state.oper_mode,
        "native_vlan": state.native_vlan,
        "native_vlan_tagged": state.native_vlan_tagged,
        "allowed_vlans": sorted(state.allowed_vlans),
        "active_vlans": sorted(state.active_vlans),
        "encapsulation": state.encapsulation,
        "qinq_tunnel": state.qinq_tunnel,
        "is_subinterface_bundle": state.is_subinterface_bundle,
        "crawled": True,
    }


def _deduplicate_crawled_infra(raw_devices: list[dict]) -> list[dict]:
    """Return unique successfully crawled infrastructure devices from `raw_devices`."""
    seen_keys: set[str] = set()
    unique: list[dict] = []
    for dev in raw_devices or []:
        if not _is_eligible_crawled_infra(dev):
            continue
        cid = str(dev.get("canonical_id") or "").strip()
        serial = str(dev.get("serial") or "").strip().lower()
        short_h, _ = normalize_hostname(
            str(dev.get("hostname") or dev.get("canonical_hostname") or dev.get("ip") or "")
        )
        if cid:
            dedup_k = f"cid:{cid}"
        elif serial and serial not in _PLACEHOLDER_SERIALS:
            dedup_k = f"ser:{serial}"
        elif short_h:
            dedup_k = f"host:{short_h.lower()}:{dev.get('ip', '')}"
        else:
            dedup_k = f"ip:{dev.get('ip', '')}"
        if dedup_k not in seen_keys:
            seen_keys.add(dedup_k)
            unique.append(dev)
    return unique


def _build_peer_lookup_index(crawled_devs: list[dict]) -> _PeerLookupIndex:
    """Build hostname, management/L3 IPv4, chassis MAC, and LAG member lookup tables."""
    index = _PeerLookupIndex()
    for dev in crawled_devs:
        short_h, _ = normalize_hostname(
            str(dev.get("hostname") or dev.get("canonical_hostname") or dev.get("ip") or "")
        )
        h_low = short_h.lower()
        if not h_low:
            continue
        index.dev_by_host[h_low] = dev

        mgmt_ip = str(dev.get("ip") or "").strip()
        if mgmt_ip and valid_ipv4(mgmt_ip):
            index.ip_to_host[mgmt_ip] = h_low

        for l3 in dev.get("l3_interfaces") or []:
            if isinstance(l3, dict):
                ip_tok = str(l3.get("ip_address") or "").split("/")[0].split()[0].strip()
                if ip_tok and valid_ipv4(ip_tok) and not ip_tok.startswith("127."):
                    index.ip_to_host[ip_tok] = h_low

        base_mac = str(dev.get("mac_address") or "").strip().lower()
        if base_mac and base_mac != "00:00:00:00:00:00":
            index.mac_to_host[base_mac] = h_low

        for m_port, p_lag in _collect_device_lag_member_map(dev).items():
            index.global_member_to_lag[(h_low, m_port)] = p_lag

    return index


def _collect_all_trunk_states(
    crawled_devs: list[dict],
) -> tuple[dict[tuple[str, str], TrunkPortState], list[TrunkPortState], int]:
    """Extract normalized `TrunkPortState` records across all crawled infrastructure devices."""
    states_by_dev_port: dict[tuple[str, str], TrunkPortState] = {}
    all_states: list[TrunkPortState] = []
    for dev in crawled_devs:
        for st in extract_device_trunk_states(dev):
            st.interface_name = canonicalize_interface_full(st.lag_parent or st.interface_name)
            all_states.append(st)
            key = (st.device_hostname, st.interface_name)
            if key not in states_by_dev_port or st.neighbor_hostname is not None:
                states_by_dev_port[key] = st

    total_trunk_ports = len({(st.device_hostname, st.interface_name) for st in all_states if _is_trunk_like(st)})
    return states_by_dev_port, all_states, total_trunk_ports


def _normalize_neighbor_remote_port(
    raw_rp: str,
    l_host: str,
    l_port: str,
    l_port_phys: str,
    r_host: str,
    peer_index: _PeerLookupIndex,
    uncrawled_lag_remote_port: dict[tuple[str, str, str], str],
) -> str:
    """Canonicalize remote neighbor interface and collapse onto LAG bundle when applicable."""
    cleaned = raw_rp.strip()
    if cleaned.lower() in {"", "unknown", "n/a", "-"}:
        return ""
    base_rp = (
        re.sub(r"\.\d+$", "", cleaned)
        if (re.match(r"^[^.\s]+\.\d+$", cleaned) and not valid_ipv4(cleaned))
        else cleaned
    )
    r_port_phys = canonicalize_interface_full(base_rp)
    r_port = peer_index.global_member_to_lag.get((r_host, r_port_phys), r_port_phys)
    if l_port != l_port_phys and r_host not in peer_index.dev_by_host:
        r_port = uncrawled_lag_remote_port.setdefault((l_host, l_port, r_host), r_port)
    return r_port


def _reconcile_missing_remote_ports(observations: list[_NeighborObservation]) -> None:
    """Populate missing `remote_port` values when a reciprocal observation names the local port."""
    for obs in observations:
        if obs.remote_port:
            continue
        for other in observations:
            if (
                other.local_host == obs.remote_host
                and other.remote_host == obs.local_host
                and other.remote_port == obs.local_port
                and other.local_port
            ):
                obs.remote_port = other.local_port
                break


def _append_synthetic_state_observations(
    observations: list[_NeighborObservation],
    all_states: list[TrunkPortState],
    peer_index: _PeerLookupIndex,
) -> None:
    """Append synthetic neighbor pointers present on `TrunkPortState` without raw `dev['neighbors']`."""
    observed_pairs = {(obs.local_host, obs.local_port, obs.remote_host) for obs in observations}
    for st in all_states:
        if not st.neighbor_hostname or (st.device_hostname, st.interface_name, st.neighbor_hostname) in observed_pairs:
            continue
        r_host = peer_index.resolve_peer_host(st.neighbor_hostname)
        r_port_raw = st.neighbor_interface or ""
        r_port = peer_index.global_member_to_lag.get((r_host, r_port_raw), r_port_raw) if r_port_raw else ""
        observations.append(
            _NeighborObservation(
                local_host=st.device_hostname,
                local_port=st.interface_name,
                remote_host=r_host,
                remote_port=r_port,
                is_direct=True,
            )
        )


def _collect_neighbor_observations(
    crawled_devs: list[dict],
    peer_index: _PeerLookupIndex,
    all_states: list[TrunkPortState],
) -> list[_NeighborObservation]:
    """Collect directional neighbor observations (direct CDP/LLDP, inferred, and synthetic state pointers)."""
    observations: list[_NeighborObservation] = []
    uncrawled_lag_remote_port: dict[tuple[str, str, str], str] = {}

    for dev in crawled_devs:
        short_h, _ = normalize_hostname(
            str(dev.get("hostname") or dev.get("canonical_hostname") or dev.get("ip") or "")
        )
        l_host = short_h.lower()
        if not l_host:
            continue
        for nbr in dev.get("neighbors") or []:
            if not isinstance(nbr, dict):
                continue
            raw_lp = str(nbr.get("local_port") or "").strip()
            if not raw_lp:
                continue
            base_lp = re.sub(r"\.\d+$", "", raw_lp) if re.match(r"^[^.\s]+\.\d+$", raw_lp) else raw_lp
            l_port_phys = canonicalize_interface_full(base_lp)
            if not l_port_phys or _is_pseudo_or_svi_interface(l_port_phys):
                continue
            l_port = peer_index.global_member_to_lag.get((l_host, l_port_phys), l_port_phys)

            r_ip = str(nbr.get("remote_ip") or "").strip()
            r_mac = str(nbr.get("remote_mac") or "").strip().lower()
            r_host = peer_index.resolve_peer_host(
                str(nbr.get("remote_device") or r_ip), remote_ip=r_ip, remote_mac=r_mac
            )
            if not r_host or r_host == l_host:
                continue

            r_port = _normalize_neighbor_remote_port(
                raw_rp=str(nbr.get("remote_port") or ""),
                l_host=l_host,
                l_port=l_port,
                l_port_phys=l_port_phys,
                r_host=r_host,
                peer_index=peer_index,
                uncrawled_lag_remote_port=uncrawled_lag_remote_port,
            )
            is_direct = str(nbr.get("link_confidence") or "").upper() != "INFERRED"
            observations.append(
                _NeighborObservation(
                    local_host=l_host,
                    local_port=l_port,
                    remote_host=r_host,
                    remote_port=r_port,
                    is_direct=is_direct,
                    raw_neighbor=nbr,
                )
            )

    _append_synthetic_state_observations(observations, all_states, peer_index)
    _reconcile_missing_remote_ports(observations)
    return observations


def _should_include_candidate_observation(
    obs: _NeighborObservation,
    endpoint_kind: str,
    local_dev: dict | None,
    peer_dev: dict | None,
    local_state: TrunkPortState | None,
    states_by_dev_port: dict[tuple[str, str], TrunkPortState],
) -> bool:
    """Return False for non-trunk peripherals and normal unprofiled/uncrawled wireless AP uplinks."""
    if endpoint_kind == "peripheral":
        return False
    local_is_ap = bool(local_dev and str(local_dev.get("device_type") or "").lower() == "ap")
    if endpoint_kind == "ap" or local_is_ap:
        ap_dev = local_dev if local_is_ap else peer_dev
        sw_state = states_by_dev_port.get((obs.remote_host, obs.remote_port)) if local_is_ap else local_state
        ap_state = (
            local_state
            if local_is_ap
            else (states_by_dev_port.get((obs.remote_host, obs.remote_port)) if obs.remote_port else None)
        )
        if sw_state is None or not _is_trunk_like(sw_state) or ap_dev is None:
            return False
        if not bool(ap_dev.get("port_profiles") or {}) or ap_state is None:
            return False
    return True


def _group_candidate_edges(
    observations: list[_NeighborObservation],
    dev_by_host: dict[str, dict],
    states_by_dev_port: dict[tuple[str, str], TrunkPortState],
) -> dict[tuple[tuple[str, str], tuple[str, str]], _EdgeCandidate]:
    """Group directional observations into canonical undirected switchport edge candidates."""
    edges: dict[tuple[tuple[str, str], tuple[str, str]], _EdgeCandidate] = {}
    for obs in observations:
        local_dev = dev_by_host.get(obs.local_host)
        peer_dev = dev_by_host.get(obs.remote_host)
        endpoint_kind = _classify_neighbor_endpoint(obs.raw_neighbor, peer_dev=peer_dev)
        local_state = states_by_dev_port.get((obs.local_host, obs.local_port))

        if not _should_include_candidate_observation(
            obs, endpoint_kind, local_dev, peer_dev, local_state, states_by_dev_port
        ):
            continue

        if local_state is not None:
            local_state.neighbor_hostname = obs.remote_host
            if obs.remote_port:
                local_state.neighbor_interface = obs.remote_port

        end_1 = (obs.local_host, obs.local_port)
        end_2 = (obs.remote_host, obs.remote_port or "unknown")
        edge_key = (end_1, end_2) if end_1 <= end_2 else (end_2, end_1)

        candidate = edges.setdefault(
            edge_key,
            _EdgeCandidate(endpoint_kind=endpoint_kind, sample_nbr=obs.raw_neighbor),
        )
        if obs.is_direct:
            candidate.direct_from.add(end_1)

    return edges


def _resolve_or_default_port_state(
    host: str,
    port: str,
    dev_by_host: dict[str, dict],
    states_by_dev_port: dict[tuple[str, str], TrunkPortState],
) -> TrunkPortState | None:
    """Return existing `TrunkPortState` or materialize default VLAN 1 access state for crawled switchports."""
    if host not in dev_by_host:
        return None
    existing = states_by_dev_port.get((host, port))
    if existing is not None or port == "unknown":
        return existing
    dev = dev_by_host[host]
    return TrunkPortState(
        device_hostname=host,
        device_mgmt_ip=str(dev.get("ip") or ""),
        vendor=normalize_vendor_name(
            str(dev.get("vendor") or ""),
            str(dev.get("os_type") or ""),
            str(dev.get("device_type") or ""),
        ),
        interface_name=port,
        admin_mode="access",
        oper_mode="access",
        native_vlan=1,
        allowed_vlans={1},
        active_vlans={1},
    )


def _record_discrepancy(
    spec: TrunkDiscrepancySpec,
    discrepancies_out: list[dict] | None = None,
    stats: _TrunkAuditStats | None = None,
) -> dict:
    """Record a typed `TrunkDiscrepancySpec` into discrepancy findings, summary counters, and CSV export rows."""
    disc_entry = {
        "rule_id": spec.rule_id,
        "severity": spec.severity,
        "message": spec.message,
        "side_a_only_vlans": list(spec.side_a_only_vlans),
        "side_b_only_vlans": list(spec.side_b_only_vlans),
        "remediation_hint": spec.remediation_hint,
    }
    if discrepancies_out is not None:
        discrepancies_out.append(disc_entry)
    if stats is not None:
        stats.severity_counts[spec.severity] = stats.severity_counts.get(spec.severity, 0) + 1
        stats.rule_counts[spec.rule_id] = stats.rule_counts.get(spec.rule_id, 0) + 1
        stats.csv_rows.append(
            {
                "Edge_ID": spec.edge.edge_id,
                "Side_A_Host": spec.edge.side_a_host,
                "Side_A_Port": spec.edge.side_a_port,
                "Side_B_Host": spec.edge.side_b_host,
                "Side_B_Port": spec.edge.side_b_port,
                "Rule_ID": spec.rule_id,
                "Severity": spec.severity,
                "Side_A_Only_VLANs": format_vlan_set(spec.side_a_only_vlans),
                "Side_B_Only_VLANs": format_vlan_set(spec.side_b_only_vlans),
                "Remediation_Hint": spec.remediation_hint,
            }
        )
    return disc_entry


def _append_edge_findings(
    edge: TrunkEdgeContext,
    status: str,
    discrepancies: list[dict],
    findings_out: list[dict],
) -> None:
    """Serialize endpoint snapshots and append normalized finding records for every edge discrepancy."""
    if not discrepancies:
        return
    highest_sev = max(discrepancies, key=lambda d: _SEVERITY_RANK.get(d["severity"], 0))["severity"]
    ep_a = _serialize_endpoint(edge.state_a, edge.side_a_host, edge.side_a_port)
    ep_b = _serialize_endpoint(edge.state_b, edge.side_b_host, edge.side_b_port)
    for disc_item in discrepancies:
        findings_out.append(
            {
                "edge_id": edge.edge_id,
                "status": status,
                "rule_id": disc_item["rule_id"],
                "severity": disc_item["severity"],
                "highest_severity": highest_sev,
                "message": disc_item["message"],
                "side_a_host": edge.side_a_host,
                "side_a_port": edge.side_a_port,
                "side_b_host": edge.side_b_host,
                "side_b_port": edge.side_b_port,
                "side_a_only_vlans": disc_item["side_a_only_vlans"],
                "side_b_only_vlans": disc_item["side_b_only_vlans"],
                "remediation_hint": disc_item["remediation_hint"],
                "side_a": ep_a,
                "side_b": ep_b,
                "endpoints": {"side_a": ep_a, "side_b": ep_b},
                "discrepancies": discrepancies,
            }
        )


def _check_asymmetric_discovery(
    edge: TrunkEdgeContext,
    direct_from: set[tuple[str, str]],
) -> TrunkDiscrepancySpec | None:
    """Check `WARN_ASYMMETRIC_DISCOVERY` when only one endpoint reported a direct CDP/LLDP neighbor."""
    a_saw_b = (edge.side_a_host, edge.side_a_port) in direct_from
    b_saw_a = (edge.side_b_host, edge.side_b_port) in direct_from
    if a_saw_b == b_saw_a:
        return None
    seeing_h, seeing_p = (edge.side_a_host, edge.side_a_port) if a_saw_b else (edge.side_b_host, edge.side_b_port)
    silent_h, silent_p = (edge.side_b_host, edge.side_b_port) if a_saw_b else (edge.side_a_host, edge.side_a_port)
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="WARN_ASYMMETRIC_DISCOVERY",
        severity="MEDIUM",
        message=(
            f"Asymmetric discovery: {seeing_h}:{seeing_p} sees {silent_h}:{silent_p}, "
            f"but {silent_h} lacks a direct CDP/LLDP neighbor record."
        ),
        remediation_hint=f"Enable bidirectional LLDP/CDP transmit and receive on {silent_h} ({silent_p}).",
    )


def _check_qinq_boundary(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `INFO_QINQ_BOUNDARY` when either endpoint operates as an 802.1ad / dot1q-tunnel boundary."""
    assert edge.state_a is not None and edge.state_b is not None
    qinq_sides = [
        f"{st.device_hostname}:{st.interface_name}"
        for st in (edge.state_a, edge.state_b)
        if st.qinq_tunnel or st.admin_mode == "dot1q_tunnel"
    ]
    if not qinq_sides:
        return None
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="INFO_QINQ_BOUNDARY",
        severity="INFO",
        message=(
            f"QinQ (dot1q-tunnel) boundary on {', '.join(qinq_sides)}; "
            f"TRK-004/TRK-005 C-VLAN/S-VLAN symmetry checks bypassed."
        ),
        remediation_hint="Verify S-VLAN Baby Giant/Jumbo MTU (>=1504 bytes) and L2 protocol tunneling.",
    )


def _check_oper_mode_mismatch(edge: TrunkEdgeContext, is_qinq_edge: bool) -> TrunkDiscrepancySpec | None:
    """Check `TRK-001` (CRITICAL): Operational switchport mode mismatch across link peers."""
    assert edge.state_a is not None and edge.state_b is not None
    state_a, state_b = edge.state_a, edge.state_b
    qinq_trunk_compat = is_qinq_edge and {state_a.oper_mode, state_b.oper_mode} <= {"trunk", "dot1q_tunnel"}
    if state_a.oper_mode == state_b.oper_mode or qinq_trunk_compat:
        return None
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-001",
        severity="CRITICAL",
        message=(
            f"Operational mode mismatch: {edge.side_a_host}:{edge.side_a_port} operates as '{state_a.oper_mode}', "
            f"{edge.side_b_host}:{edge.side_b_port} operates as '{state_b.oper_mode}'."
        ),
        remediation_hint=(
            f"Configure matching static 802.1Q trunk mode on both "
            f"{edge.side_a_host}:{edge.side_a_port} and {edge.side_b_host}:{edge.side_b_port}."
        ),
    )


def _check_native_vlan_mismatch(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `TRK-002` (CRITICAL): Native / untagged PVID mismatch across link peers."""
    assert edge.state_a is not None and edge.state_b is not None
    state_a, state_b = edge.state_a, edge.state_b
    both_tagged_none = (
        state_a.native_vlan is None
        and state_b.native_vlan is None
        and state_a.native_vlan_tagged
        and state_b.native_vlan_tagged
    )
    if state_a.native_vlan == state_b.native_vlan or both_tagged_none:
        return None
    a_nat_lbl = str(state_a.native_vlan) if state_a.native_vlan is not None else "none (tagged)"
    b_nat_lbl = str(state_b.native_vlan) if state_b.native_vlan is not None else "none (tagged)"
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-002",
        severity="CRITICAL",
        message=f"Native VLAN mismatch: {edge.side_a_host} uses VLAN {a_nat_lbl}, {edge.side_b_host} uses VLAN {b_nat_lbl}.",
        side_a_only_vlans=[state_a.native_vlan] if state_a.native_vlan is not None else [],
        side_b_only_vlans=[state_b.native_vlan] if state_b.native_vlan is not None else [],
        remediation_hint=(
            f"Set identical native VLAN ID on {edge.side_a_host}:{edge.side_a_port} and "
            f"{edge.side_b_host}:{edge.side_b_port} to prevent PVID_INC blocking and VLAN leaking."
        ),
    )


def _check_native_tagging_mismatch(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `TRK-003` (HIGH): Asymmetric 802.1Q native VLAN tagging behavior."""
    assert edge.state_a is not None and edge.state_b is not None
    state_a, state_b = edge.state_a, edge.state_b
    if state_a.native_vlan_tagged == state_b.native_vlan_tagged:
        return None
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-003",
        severity="HIGH",
        message=(
            f"Native VLAN tagging mismatch: {edge.side_a_host}:{edge.side_a_port} "
            f"native_vlan_tagged={state_a.native_vlan_tagged}, "
            f"{edge.side_b_host}:{edge.side_b_port} native_vlan_tagged={state_b.native_vlan_tagged}."
        ),
        remediation_hint=(
            f"Align 802.1Q native VLAN tagging ('vlan dot1q tag native' / 'vlan trunk native tag' / "
            f"'native-vlan-id') across {edge.side_a_host} and {edge.side_b_host}."
        ),
    )


def _check_allowed_vlan_asymmetry(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `TRK-004` (HIGH): Allowed trunk VLAN set asymmetry across link peers."""
    assert edge.state_a is not None and edge.state_b is not None
    state_a, state_b = edge.state_a, edge.state_b
    if not (state_a.allowed_vlans ^ state_b.allowed_vlans):
        return None
    a_only = sorted(state_a.allowed_vlans - state_b.allowed_vlans)
    b_only = sorted(state_b.allowed_vlans - state_a.allowed_vlans)
    if a_only and b_only:
        msg = (
            f"Allowed VLAN mismatch: VLAN [{format_vlan_set(a_only)}] only on {edge.side_a_host}; "
            f"VLAN [{format_vlan_set(b_only)}] only on {edge.side_b_host}."
        )
    elif a_only:
        msg = (
            f"Allowed VLAN mismatch: VLAN [{format_vlan_set(a_only)}] permitted on "
            f"{edge.side_a_host} but missing on {edge.side_b_host}."
        )
    else:
        msg = (
            f"Allowed VLAN mismatch: VLAN [{format_vlan_set(b_only)}] permitted on "
            f"{edge.side_b_host} but missing on {edge.side_a_host}."
        )
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-004",
        severity="HIGH",
        message=msg,
        side_a_only_vlans=a_only,
        side_b_only_vlans=b_only,
        remediation_hint=(
            f"Synchronize allowed trunk VLAN lists between "
            f"{edge.side_a_host}:{edge.side_a_port} and {edge.side_b_host}:{edge.side_b_port}."
        ),
    )


def _check_vlan_database_drift(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `TRK-005` (MEDIUM): Allowed VLAN missing from local VLAN database / STP forwarding state."""
    assert edge.state_a is not None and edge.state_b is not None
    state_a, state_b = edge.state_a, edge.state_b
    common_allowed = state_a.allowed_vlans & state_b.allowed_vlans
    if not ((state_a.active_vlans ^ state_b.active_vlans) & common_allowed):
        return None
    a_only_active = sorted((state_a.active_vlans - state_b.active_vlans) & common_allowed)
    b_only_active = sorted((state_b.active_vlans - state_a.active_vlans) & common_allowed)
    drift_parts: list[str] = []
    if a_only_active:
        drift_parts.append(
            f"VLAN [{format_vlan_set(a_only_active)}] active on {edge.side_a_host} but inactive/missing on {edge.side_b_host}"
        )
    if b_only_active:
        drift_parts.append(
            f"VLAN [{format_vlan_set(b_only_active)}] active on {edge.side_b_host} but inactive/missing on {edge.side_a_host}"
        )
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-005",
        severity="MEDIUM",
        message=f"VLAN database / STP forwarding drift: {'; '.join(drift_parts)}.",
        side_a_only_vlans=a_only_active,
        side_b_only_vlans=b_only_active,
        remediation_hint=(
            "Define missing VLAN(s) in local VLAN database ('vlan <id>' / 'set vlans') and verify "
            "STP forwarding state on both peers."
        ),
    )


def _check_default_vlan1_permitted(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `TRK-006` (MEDIUM): Default VLAN 1 unpruned on an active/configured trunk link."""
    assert edge.state_a is not None and edge.state_b is not None
    state_a, state_b = edge.state_a, edge.state_b
    if not (_is_trunk_like(state_a) or _is_trunk_like(state_b)):
        return None
    if 1 not in state_a.allowed_vlans and 1 not in state_b.allowed_vlans:
        return None
    v1_hosts: list[str] = []
    if 1 in state_a.allowed_vlans:
        v1_hosts.append(f"{edge.side_a_host}:{edge.side_a_port}")
    if 1 in state_b.allowed_vlans:
        v1_hosts.append(f"{edge.side_b_host}:{edge.side_b_port}")
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-006",
        severity="MEDIUM",
        message=f"Default VLAN 1 permitted on trunk ({', '.join(v1_hosts)}).",
        side_a_only_vlans=[1] if (1 in state_a.allowed_vlans and 1 not in state_b.allowed_vlans) else [],
        side_b_only_vlans=[1] if (1 in state_b.allowed_vlans and 1 not in state_a.allowed_vlans) else [],
        remediation_hint="Prune default VLAN 1 from trunk allowed VLANs after migrating management/native traffic.",
    )


def _check_dtp_negotiation(edge: TrunkEdgeContext) -> TrunkDiscrepancySpec | None:
    """Check `TRK-007` (LOW): Dynamic Trunking Protocol (DTP) auto/desirable negotiation active."""
    assert edge.state_a is not None and edge.state_b is not None
    dtp_sides = [
        f"{st.device_hostname}:{st.interface_name} ({st.admin_mode})"
        for st in (edge.state_a, edge.state_b)
        if st.admin_mode in _DTP_ADMIN_MODES
    ]
    if not dtp_sides:
        return None
    return TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-007",
        severity="LOW",
        message=f"Dynamic trunk negotiation (DTP) enabled on {', '.join(dtp_sides)}.",
        remediation_hint="Configure static 'switchport mode trunk' and 'switchport nonegotiate' to disable DTP.",
    )


def _evaluate_uncrawled_edge(
    edge: TrunkEdgeContext,
    a_crawled: bool,
    endpoint_kind: str,
    stats: _TrunkAuditStats,
) -> None:
    """Evaluate boundary edge where one infrastructure/trunk neighbor was not crawled."""
    crawled_st = edge.state_a if a_crawled else edge.state_b
    if crawled_st is None or not (_is_trunk_like(crawled_st) or endpoint_kind == "infra"):
        return

    uncrawled_host = edge.side_b_host if a_crawled else edge.side_a_host
    uncrawled_port = edge.side_b_port if a_crawled else edge.side_a_port
    crawled_host = edge.side_a_host if a_crawled else edge.side_b_host
    crawled_port = edge.side_a_port if a_crawled else edge.side_b_port

    stats.evaluated_edges += 1
    stats.uncrawled_neighbor_edges += 1
    discrepancies: list[dict] = []
    spec = TrunkDiscrepancySpec(
        edge=edge,
        rule_id="ERR_UNCRAWLED_NEIGHBOR",
        severity="MEDIUM",
        message=(
            f"Uncrawled neighbor '{uncrawled_host}' ({uncrawled_port}) connected to "
            f"{crawled_host}:{crawled_port}; remote 802.1Q trunk state cannot be verified."
        ),
        remediation_hint=(
            f"Add '{uncrawled_host}' management IP and credentials to crawl targets to verify "
            f"bidirectional trunk VLAN symmetry."
        ),
    )
    _record_discrepancy(spec, discrepancies, stats)
    _append_edge_findings(edge, "UNCRAWLED_NEIGHBOR", discrepancies, stats.findings)


def _evaluate_matched_edge(
    edge: TrunkEdgeContext,
    candidate: _EdgeCandidate,
    stats: _TrunkAuditStats,
) -> None:
    """Evaluate all symmetry and boundary rules across a link where both endpoints were crawled."""
    if edge.state_a is None or edge.state_b is None:
        return
    state_a, state_b = edge.state_a, edge.state_b

    if (
        state_a.oper_mode == "routed"
        and state_b.oper_mode == "routed"
        and not state_a.is_subinterface_bundle
        and not state_b.is_subinterface_bundle
    ):
        return

    stats.evaluated_edges += 1
    stats.matched_edges += 1
    discrepancies: list[dict] = []

    asym_spec = _check_asymmetric_discovery(edge, candidate.direct_from)
    if asym_spec is not None:
        stats.asymmetric_discovery_edges += 1
        _record_discrepancy(asym_spec, discrepancies, stats)

    qinq_spec = _check_qinq_boundary(edge)
    is_qinq_edge = qinq_spec is not None
    if qinq_spec is not None:
        stats.qinq_boundary_edges += 1
        _record_discrepancy(qinq_spec, discrepancies, stats)

    rule_specs: list[TrunkDiscrepancySpec | None] = [
        _check_oper_mode_mismatch(edge, is_qinq_edge),
        _check_native_vlan_mismatch(edge),
        _check_native_tagging_mismatch(edge),
    ]
    if not is_qinq_edge:
        rule_specs.append(_check_allowed_vlan_asymmetry(edge))
        rule_specs.append(_check_vlan_database_drift(edge))
    rule_specs.append(_check_default_vlan1_permitted(edge))
    rule_specs.append(_check_dtp_negotiation(edge))

    for spec in rule_specs:
        if spec is not None:
            _record_discrepancy(spec, discrepancies, stats)

    if not discrepancies:
        stats.clean_edges += 1
        return

    if any(d["rule_id"].startswith("TRK-") for d in discrepancies):
        stats.mismatched_edges += 1
        status = "MISMATCH"
    elif any(d["rule_id"] == "WARN_ASYMMETRIC_DISCOVERY" for d in discrepancies):
        status = "ASYMMETRIC_DISCOVERY"
    else:
        status = "QINQ_BOUNDARY"

    _append_edge_findings(edge, status, discrepancies, stats.findings)


def _build_audit_summary(stats: _TrunkAuditStats) -> dict:
    """Build the canonical trunk audit `summary` dictionary from accumulated statistics."""
    total_discrepancies = sum(stats.severity_counts.values())
    return {
        "total_trunk_ports": stats.total_trunk_ports,
        "evaluated_edges": stats.evaluated_edges,
        "edges_evaluated": stats.evaluated_edges,
        "total_trunk_edges_evaluated": stats.evaluated_edges,
        "matched_edges": stats.matched_edges,
        "clean_edges": stats.clean_edges,
        "mismatched_edges": stats.mismatched_edges,
        "uncrawled_neighbor_edges": stats.uncrawled_neighbor_edges,
        "asymmetric_discovery_edges": stats.asymmetric_discovery_edges,
        "qinq_boundary_edges": stats.qinq_boundary_edges,
        "total_findings": total_discrepancies,
        "total_discrepancies": total_discrepancies,
        "critical_count": stats.severity_counts["CRITICAL"],
        "high_count": stats.severity_counts["HIGH"],
        "medium_count": stats.severity_counts["MEDIUM"],
        "low_count": stats.severity_counts["LOW"],
        "info_count": stats.severity_counts["INFO"],
        "by_rule": dict(sorted(stats.rule_counts.items())),
    }


def evaluate_trunk_mismatches(raw_devices: list[dict]) -> dict:
    """
    Correlate bidirectional switchport links across `raw_devices` and evaluate Contract C
    trunk VLAN mismatch rules (`TRK-001`..`TRK-007`) and boundary diagnostics
    (`ERR_UNCRAWLED_NEIGHBOR`, `WARN_ASYMMETRIC_DISCOVERY`, `INFO_QINQ_BOUNDARY`).

    Returns:
      `{"summary": dict, "findings": list[dict], "csv_rows": list[dict]}`
    """
    crawled_devs = _deduplicate_crawled_infra(raw_devices)
    peer_index = _build_peer_lookup_index(crawled_devs)
    states_by_dev_port, all_states, total_trunk_ports = _collect_all_trunk_states(crawled_devs)
    observations = _collect_neighbor_observations(crawled_devs, peer_index, all_states)
    edges = _group_candidate_edges(observations, peer_index.dev_by_host, states_by_dev_port)

    stats = _TrunkAuditStats(total_trunk_ports=total_trunk_ports)
    for ((a_host, a_port), (b_host, b_port)), candidate in sorted(edges.items()):
        a_crawled = a_host in peer_index.dev_by_host
        b_crawled = b_host in peer_index.dev_by_host
        edge = TrunkEdgeContext(
            edge_id=f"{a_host}:{a_port}<->{b_host}:{b_port}",
            side_a_host=a_host,
            side_a_port=a_port,
            side_b_host=b_host,
            side_b_port=b_port,
            state_a=_resolve_or_default_port_state(a_host, a_port, peer_index.dev_by_host, states_by_dev_port),
            state_b=_resolve_or_default_port_state(b_host, b_port, peer_index.dev_by_host, states_by_dev_port),
        )
        if not (a_crawled and b_crawled):
            _evaluate_uncrawled_edge(edge, a_crawled, candidate.endpoint_kind, stats)
        else:
            _evaluate_matched_edge(edge, candidate, stats)

    summary = _build_audit_summary(stats)
    logger.debug(
        "Trunk audit evaluated %d edges (%d mismatched, %d clean) across %d devices",
        stats.evaluated_edges,
        stats.mismatched_edges,
        stats.clean_edges,
        len(crawled_devs),
    )
    return {
        "summary": summary,
        "findings": stats.findings,
        "csv_rows": stats.csv_rows,
    }


__all__ = [
    "CSV_COLUMNS",
    "TrunkDiscrepancySpec",
    "TrunkEdgeContext",
    "TrunkPortState",
    "canonicalize_interface_full",
    "evaluate_trunk_mismatches",
    "expand_vlan_spec",
    "extract_device_trunk_states",
    "format_vlan_set",
    "normalize_vendor_name",
]

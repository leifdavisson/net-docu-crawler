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

import re
from dataclasses import dataclass, field

from netaddr import valid_ipv4

from net_docu_crawler.migration_parsers import extract_vlans
from net_docu_crawler.topology_resolver import normalize_hostname

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
      - 'Gi1/0/1'   -> 'GigabitEthernet1/0/1'
      - 'Te1/1/1'   -> 'TenGigabitEthernet1/1/1'
      - 'Fa0/1'     -> 'FastEthernet0/1'
      - 'Twe1/0/1'  -> 'TwentyFiveGigE1/0/1'
      - 'Fo1/0/1'   -> 'FortyGigabitEthernet1/0/1'
      - 'Hu1/0/1'   -> 'HundredGigE1/0/1'
      - 'Po1'       -> 'Port-channel1'
      - 'Eth1/1'    -> 'Ethernet1/1'
      - 'Et1'       -> 'Ethernet1'
      - 'ae0.0'     -> 'ae0'
      - 'ge-0/0/1.0' -> 'ge-0/0/1'
    """
    if not intf:
        return ""
    name = intf.strip().strip('"').strip("'")
    if not name:
        return ""

    # Strip Junos / logical unit .0 suffix (preserve non-zero dot1Q subinterfaces like .10)
    name = re.sub(r"\.0$", "", name)

    # Normalize Junos physical & aggregated prefixes to lowercase
    m_junos = re.match(r"^(ge-|xe-|et-|fe-|ae(?=\d)|reth(?=\d))(.*)$", name, flags=re.IGNORECASE)
    if m_junos:
        return f"{m_junos.group(1).lower()}{m_junos.group(2)}"

    # HP ProCurve / ArubaOS-S trunk groups & AOS-CX LAGs
    m_trk = re.match(r"^trk\s*(\d+)$", name, flags=re.IGNORECASE)
    if m_trk:
        return f"Trk{m_trk.group(1)}"
    m_lag = re.match(r"^lag\s*(\d+)$", name, flags=re.IGNORECASE)
    if m_lag:
        return f"lag{m_lag.group(1)}"

    # Ordered prefix expansions (longest/most specific abbreviations before shorter prefixes)
    prefix_rules: tuple[tuple[str, str], ...] = (
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
    for pattern, full_prefix in prefix_rules:
        if re.match(pattern, name, flags=re.IGNORECASE):
            return re.sub(pattern, full_prefix, name, count=1, flags=re.IGNORECASE)

    return name


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

    if isinstance(spec, (set, frozenset)):
        out: set[int] = set()
        for item in spec:
            if isinstance(item, int) and 1 <= item <= 4094:
                out.add(item)
            else:
                out.update(expand_vlan_spec(str(item), known_vlans=known_vlans, vlan_name_map=vlan_name_map))
        return out

    if isinstance(spec, (list, tuple)):
        out = set()
        for item in spec:
            if isinstance(item, int):
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

    # Handle Cisco 'all except <spec>' or 'except <spec>' syntax
    m_except = re.match(r"^(?:all\s+)?except\s+(.+)$", raw, flags=re.IGNORECASE)
    if m_except:
        base = set(known_vlans) if known_vlans else set(range(1, 4095))
        excluded = expand_vlan_spec(m_except.group(1), known_vlans=known_vlans, vlan_name_map=vlan_name_map)
        return {v for v in (base - excluded) if 1 <= v <= 4094}

    if low == "all":
        return {v for v in known_vlans if 1 <= v <= 4094} if known_vlans else set(range(1, 4095))

    # Clean Cisco 'add' keyword and spacing around range hyphens
    cleaned = re.sub(r"\badd\b", ",", raw, flags=re.IGNORECASE)
    cleaned = re.sub(r"(\d)\s*-\s*(\d)", r"\1-\2", cleaned)

    result: set[int] = set()
    for token in re.split(r"[,\s]+", cleaned):
        tok = token.strip().strip('"').strip("'")
        if not tok:
            continue
        tok_low = tok.lower()
        if tok_low in {"none", "null", "-"}:
            continue
        if tok_low == "all":
            if known_vlans:
                result.update(v for v in known_vlans if 1 <= v <= 4094)
            else:
                result.update(range(1, 4095))
            continue
        m_rng = re.match(r"^(\d+)-(\d+)$", tok)
        if m_rng:
            start_v = max(1, int(m_rng.group(1)))
            end_v = min(4094, int(m_rng.group(2)))
            if start_v <= end_v:
                result.update(range(start_v, end_v + 1))
            continue
        if tok.isdigit():
            vid = int(tok)
            if 1 <= vid <= 4094:
                result.add(vid)
            continue
        m_prefixed = re.match(r"^(?:vlan|vl)[_-]?0*(\d+)$", tok, flags=re.IGNORECASE)
        if m_prefixed:
            vid = int(m_prefixed.group(1))
            if 1 <= vid <= 4094:
                result.add(vid)
            continue
        if vlan_name_map and tok_low in vlan_name_map:
            vid = vlan_name_map[tok_low]
            if 1 <= vid <= 4094:
                result.add(vid)
        elif tok_low in {"default", "default_vlan"}:
            result.add(1)

    return result


def format_vlan_set(vlans: set[int] | list[int]) -> str:
    """Format a set/list of VLAN IDs into compact sorted range notation (e.g., '10-12,50')."""
    ordered = sorted({int(v) for v in vlans if 1 <= int(v) <= 4094})
    if not ordered:
        return ""
    parts: list[str] = []
    run_start = ordered[0]
    run_end = ordered[0]
    for v in ordered[1:]:
        if v == run_end + 1:
            run_end = v
        else:
            if run_end - run_start >= 2:
                parts.append(f"{run_start}-{run_end}")
            elif run_end > run_start:
                parts.append(f"{run_start},{run_end}")
            else:
                parts.append(str(run_start))
            run_start = run_end = v
    if run_end - run_start >= 2:
        parts.append(f"{run_start}-{run_end}")
    elif run_end > run_start:
        parts.append(f"{run_start},{run_end}")
    else:
        parts.append(str(run_start))
    return ",".join(parts)


def _is_pseudo_or_svi_interface(port_name: str) -> bool:
    """Return True for non-switchport virtual, loopback, SVI, or kernel pseudo interfaces."""
    if not port_name:
        return True
    low = port_name.strip().lower()
    if low in _PSEUDO_PORT_EXACT:
        return True
    return low.startswith(_PSEUDO_PORT_PREFIXES)


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
            if vid_raw.isdigit():
                vid = int(vid_raw)
                if 1 <= vid <= 4094:
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
            elif isinstance(item, str) and item.strip().isdigit():
                vid = int(item.strip())
                if 1 <= vid <= 4094:
                    configured_ids.add(vid)
            elif isinstance(item, dict) and str(item.get("id", "")).strip().isdigit():
                vid = int(str(item["id"]).strip())
                if 1 <= vid <= 4094:
                    configured_ids.add(vid)
                    if item.get("name"):
                        name_map[str(item["name"]).strip().lower()] = vid

    return configured_ids, name_map, explicit_db


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

    # 1. Inspect subinterface keys already present in port_profiles
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

    for k in sub_keys_to_pop:
        merged.pop(k, None)

    # 2. Fallback: inspect raw_config for dot1Q subinterfaces if parent not already marked
    if raw_config:
        # Cisco IOS / NX-OS / Arista EOS `interface Gi0/0.10` + `encapsulation dot1Q 10 [native]`
        for blk in re.split(r"(?m)^interface\s+", raw_config)[1:]:
            lines = blk.splitlines()
            if not lines:
                continue
            sub_intf = lines[0].strip()
            m_sub = re.match(r"^([^.\s]+)\.(\d+)$", sub_intf)
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
            if any(
                canonicalize_interface_full(existing_k) == parent and existing_v.get("is_subinterface_bundle")
                for existing_k, existing_v in merged.items()
            ):
                continue
            vid = int(m_dot1q.group(1))
            grp = sub_groups.setdefault(parent, {"vlans": set(), "native": None})
            assert isinstance(grp["vlans"], set)
            if 1 <= vid <= 4094:
                grp["vlans"].add(vid)
                if m_dot1q.group(2):
                    grp["native"] = vid

        # Juniper Junos `set interfaces ge-0/0/1 unit 10 vlan-id 10`
        for m_j_sub in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+([1-9]\d*)\s+vlan-id\s+(\d+)",
            raw_config,
        ):
            parent = canonicalize_interface_full(m_j_sub.group(1))
            if any(
                canonicalize_interface_full(existing_k) == parent and existing_v.get("is_subinterface_bundle")
                for existing_k, existing_v in merged.items()
            ):
                continue
            vid = int(m_j_sub.group(3))
            grp = sub_groups.setdefault(parent, {"vlans": set(), "native": None})
            assert isinstance(grp["vlans"], set)
            if 1 <= vid <= 4094:
                grp["vlans"].add(vid)

    for parent, grp in sub_groups.items():
        vlans_set = grp["vlans"]
        assert isinstance(vlans_set, set)
        if not vlans_set:
            continue
        native_id = grp["native"]
        target_key = parent
        for existing_k in merged:
            if canonicalize_interface_full(existing_k) == parent:
                target_key = existing_k
                break
        prof = merged.setdefault(target_key, {})
        prof["mode"] = "trunk"
        prof["admin_mode"] = "trunk"
        prof["oper_mode"] = prof.get("oper_mode") or "trunk"
        prof["encapsulation"] = "dot1q"
        prof["is_subinterface_bundle"] = True
        existing_vlans = expand_vlan_spec(prof.get("trunk_allowed_vlans") or "")
        combined_vlans = existing_vlans | vlans_set
        prof["trunk_allowed_vlans"] = format_vlan_set(combined_vlans)
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
    has_explicit_nat_key = "native_vlan" in prof
    raw_nat = prof.get("native_vlan")

    if has_explicit_nat_key and raw_nat is None and explicit_tagged is True:
        return None, True

    nat_str = str(raw_nat).strip() if raw_nat is not None else ""
    nat_low = nat_str.lower()

    is_trunk = oper_mode in {"trunk", "dot1q_tunnel"} or admin_mode in {
        "trunk",
        "dot1q_tunnel",
        "dynamic_auto",
        "dynamic_desirable",
    }

    if nat_low in {"none", "tagged", "null"}:
        return None, True if explicit_tagged is None else bool(explicit_tagged)

    if nat_str.isdigit():
        vid = int(nat_str)
        return vid, bool(explicit_tagged) if explicit_tagged is not None else False

    if nat_low and nat_low in vlan_name_map:
        return vlan_name_map[nat_low], bool(explicit_tagged) if explicit_tagged is not None else False

    if is_trunk:
        # Legacy Juniper fallback if raw_config is present (check native-vlan-id vs pure tagged trunk)
        if vendor == "juniper_junos" and raw_config:
            m_jnat = re.search(
                rf"set\s+interfaces\s+{re.escape(port_canon)}\s+(?:unit\s+0\s+family\s+ethernet-switching\s+)?native-vlan-id\s+(\S+)",
                raw_config,
            )
            if m_jnat:
                tok = m_jnat.group(1).strip('"').lower()
                if tok.isdigit():
                    return int(tok), bool(explicit_tagged) if explicit_tagged is not None else False
                if tok in vlan_name_map:
                    return vlan_name_map[tok], bool(explicit_tagged) if explicit_tagged is not None else False
            return None, True if explicit_tagged is None else bool(explicit_tagged)

        return 1, bool(explicit_tagged) if explicit_tagged is not None else False

    # Access / non-trunk port: PVID is access_vlan (default 1)
    acc_str = str(prof.get("access_vlan") or "").strip()
    if acc_str.isdigit():
        return int(acc_str), False
    if acc_str.lower() in vlan_name_map:
        return vlan_name_map[acc_str.lower()], False
    return 1, False


def extract_device_trunk_states(dev: dict) -> list[TrunkPortState]:
    """
    Normalize a crawled device record into `TrunkPortState` instances.

    Resolves physical LAG/Port-Channel members (`lag_parent` / `lag_group`) onto
    their parent logical bundle (`Port-channel1`, `ae0`, `Trk1`, `lag1`) and
    router-on-a-stick dot1Q subinterfaces onto their parent interface prior to
    bidirectional edge correlation.
    """
    if not isinstance(dev, dict):
        return []
    if dev.get("status", "success") != "success":
        return []
    if dev.get("record_class") in {"unauthenticated_infra", "unsupported_appliance", "passive_endpoint"}:
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

    raw_profiles = dev.get("port_profiles") or {}
    if not raw_profiles and isinstance(dev.get("ports"), dict):
        # Fallback if a caller provides Schema v2.0 `ports` without `port_profiles`
        raw_profiles = {
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

    synthesized_profiles = _synthesize_subinterface_profiles(raw_profiles, raw_config)
    member_to_lag = _collect_device_lag_member_map({"port_profiles": synthesized_profiles})

    # Canonicalize profiles, interfaces_detail, and neighbors
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
    for ik, iv in (dev.get("interfaces_detail") or {}).items():
        if not isinstance(iv, dict):
            continue
        c_name = canonicalize_interface_full(ik)
        if not c_name or _is_pseudo_or_svi_interface(c_name):
            continue
        stats_by_canon[c_name] = iv

    # Fold LAG member config/oper fallbacks onto parent bundle so parent bundle is complete
    lag_members_by_parent: dict[str, list[str]] = {}
    for m_port, p_lag in member_to_lag.items():
        lag_members_by_parent.setdefault(p_lag, []).append(m_port)
        p_prof = profiles_by_canon.setdefault(p_lag, {})
        m_prof = profiles_by_canon.get(m_port, {})
        for inherit_k in (
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
        ):
            if p_prof.get(inherit_k) in ("", None, "unknown") and m_prof.get(inherit_k) not in (
                "",
                None,
                "unknown",
            ):
                p_prof[inherit_k] = m_prof[inherit_k]

    # Group direct (non-INFERRED) and inferred neighbors onto canonical ports (mapping LAG members -> parent LAG)
    neighbors_by_port: dict[str, list[dict]] = {}
    for nbr in dev.get("neighbors") or []:
        if not isinstance(nbr, dict):
            continue
        raw_lp = str(nbr.get("local_port") or "").strip()
        if not raw_lp:
            continue
        # Map subinterface neighbor port (e.g. ge-0/0/1.0 or Gi0/0.10) to physical/bundle port
        base_lp = re.sub(r"\.\d+$", "", raw_lp) if re.match(r"^[^.\s]+\.\d+$", raw_lp) else raw_lp
        lp_canon = canonicalize_interface_full(base_lp)
        if not lp_canon or _is_pseudo_or_svi_interface(lp_canon):
            continue
        effective_port = member_to_lag.get(lp_canon, lp_canon)
        neighbors_by_port.setdefault(effective_port, []).append(nbr)

    candidate_ports = sorted(
        (set(profiles_by_canon) | set(stats_by_canon) | set(neighbors_by_port)) - set(member_to_lag)
    )

    states: list[TrunkPortState] = []
    for port_canon in candidate_ports:
        prof = profiles_by_canon.get(port_canon, {})
        stats = stats_by_canon.get(port_canon, {})
        member_ports = lag_members_by_parent.get(port_canon, [])

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

        # Determine operational status (port or any LAG member up)
        port_status_str = str(stats.get("status") or "").strip().lower()
        if not port_status_str and member_ports:
            member_statuses = [
                str(stats_by_canon.get(mp, {}).get("status") or "").strip().lower() for mp in member_ports
            ]
            if any(ms in {"up", "connected"} for ms in member_statuses):
                port_status_str = "up"
            elif member_statuses and all(
                ms in {"down", "administratively down", "admin-down", "notconnect", "disabled", "err-disabled"}
                for ms in member_statuses
            ):
                port_status_str = "down"

        raw_oper = str(prof.get("oper_mode") or "").strip().lower().replace("-", "_")
        if raw_oper in {"trunk", "trunking"}:
            oper_mode = "trunk"
        elif raw_oper in {"dot1q_tunnel", "qinq"}:
            oper_mode = "dot1q_tunnel"
        elif raw_oper in {"access", "static_access"}:
            oper_mode = "access"
        elif raw_oper == "routed":
            oper_mode = "routed"
        elif raw_oper == "down":
            oper_mode = "down"
        elif port_status_str in {
            "down",
            "administratively down",
            "admin-down",
            "notconnect",
            "disabled",
            "err-disabled",
        }:
            oper_mode = "down"
        elif qinq:
            oper_mode = "dot1q_tunnel"
        elif (
            admin_mode in {"trunk", "dynamic_desirable"}
            or str(prof.get("mode") or "").lower() == "trunk"
            or is_sub_bundle
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

        native_vlan, native_vlan_tagged = _resolve_native_vlan_and_tagging(
            prof=prof,
            admin_mode=admin_mode,
            oper_mode=oper_mode,
            vendor=vendor,
            raw_config=raw_config,
            port_canon=port_canon,
            vlan_name_map=vlan_name_map,
        )

        # Allowed VLANs expansion
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
            # Default unpruned trunk on Cisco / Arista permits all VLANs (1..4094 or known VLAN DB)
            allowed_vlans = set(configured_vlan_ids) if configured_vlan_ids else set(range(1, 4095))
        elif not is_trunk_port and isinstance(native_vlan, int) and oper_mode != "routed":
            allowed_vlans = {native_vlan}
            voice_raw = str(prof.get("voice_vlan") or "").strip()
            if voice_raw.isdigit() and 1 <= int(voice_raw) <= 4094:
                allowed_vlans.add(int(voice_raw))
        else:
            allowed_vlans = set()

        # Active VLANs calculation per Contract C
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

        # Consolidate neighbor entries per distinct remote host (collapses N physical LAG links into 1 logical state)
        port_nbrs = neighbors_by_port.get(port_canon, [])
        if not port_nbrs:
            states.append(
                TrunkPortState(
                    device_hostname=device_hostname,
                    device_mgmt_ip=device_mgmt_ip,
                    vendor=vendor,
                    interface_name=port_canon,
                    lag_parent=None,
                    admin_mode=admin_mode,
                    oper_mode=oper_mode,
                    native_vlan=native_vlan,
                    native_vlan_tagged=native_vlan_tagged,
                    allowed_vlans=set(allowed_vlans),
                    active_vlans=set(active_vlans),
                    encapsulation=encapsulation,
                    neighbor_hostname=None,
                    neighbor_interface=None,
                    discovery_protocol=None,
                    qinq_tunnel=qinq,
                    is_subinterface_bundle=is_sub_bundle,
                )
            )
            continue

        grouped_by_remote: dict[str, list[dict]] = {}
        for nbr in port_nbrs:
            r_short, _ = normalize_hostname(str(nbr.get("remote_device") or nbr.get("remote_ip") or ""))
            r_key = r_short.lower()
            if not r_key:
                continue
            grouped_by_remote.setdefault(r_key, []).append(nbr)

        if not grouped_by_remote:
            states.append(
                TrunkPortState(
                    device_hostname=device_hostname,
                    device_mgmt_ip=device_mgmt_ip,
                    vendor=vendor,
                    interface_name=port_canon,
                    lag_parent=None,
                    admin_mode=admin_mode,
                    oper_mode=oper_mode,
                    native_vlan=native_vlan,
                    native_vlan_tagged=native_vlan_tagged,
                    allowed_vlans=set(allowed_vlans),
                    active_vlans=set(active_vlans),
                    encapsulation=encapsulation,
                    neighbor_hostname=None,
                    neighbor_interface=None,
                    discovery_protocol=None,
                    qinq_tunnel=qinq,
                    is_subinterface_bundle=is_sub_bundle,
                )
            )
            continue

        for r_host_low, nbr_list in sorted(grouped_by_remote.items()):
            # Prefer direct (non-INFERRED) neighbor records over synthesized INFERRED entries
            direct_nbrs = [n for n in nbr_list if str(n.get("link_confidence") or "") != "INFERRED"]
            chosen_list = direct_nbrs if direct_nbrs else nbr_list
            chosen = chosen_list[0]

            raw_rp = str(chosen.get("remote_port") or "").strip()
            if raw_rp.lower() in {"unknown", "n/a", "-", ""}:
                r_port_canon = None
            else:
                r_port_canon = canonicalize_interface_full(raw_rp)

            protos: set[str] = set()
            for n_item in chosen_list:
                p_val = str(n_item.get("discovery_protocol") or n_item.get("protocol") or "").strip().lower()
                if p_val in {"cdp", "lldp", "both", "mndp"}:
                    if p_val == "both":
                        protos.update({"cdp", "lldp"})
                    else:
                        protos.add(p_val)
            if {"cdp", "lldp"} <= protos:
                disc_proto: str | None = "both"
            elif protos:
                disc_proto = sorted(protos)[0]
            else:
                disc_proto = "lldp"

            states.append(
                TrunkPortState(
                    device_hostname=device_hostname,
                    device_mgmt_ip=device_mgmt_ip,
                    vendor=vendor,
                    interface_name=port_canon,
                    lag_parent=None,
                    admin_mode=admin_mode,
                    oper_mode=oper_mode,
                    native_vlan=native_vlan,
                    native_vlan_tagged=native_vlan_tagged,
                    allowed_vlans=set(allowed_vlans),
                    active_vlans=set(active_vlans),
                    encapsulation=encapsulation,
                    neighbor_hostname=r_host_low,
                    neighbor_interface=r_port_canon,
                    discovery_protocol=disc_proto,
                    qinq_tunnel=qinq,
                    is_subinterface_bundle=is_sub_bundle,
                )
            )

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
    """
    Classify a neighbor into `'peripheral'`, `'ap'`, or `'infra'`.
    """
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
    if dtype in _INFRA_DEVICE_TYPES:
        return "infra"
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
        if not isinstance(dev, dict):
            continue
        if dev.get("status", "success") != "success":
            continue
        if dev.get("record_class") in {"unauthenticated_infra", "unsupported_appliance", "passive_endpoint"}:
            continue
        cid = str(dev.get("canonical_id") or "").strip()
        serial = str(dev.get("serial") or "").strip().lower()
        short_h, _ = normalize_hostname(
            str(dev.get("hostname") or dev.get("canonical_hostname") or dev.get("ip") or "")
        )
        if cid:
            dedup_k = f"cid:{cid}"
        elif serial and serial not in {"unknown", "0", "n/a", "none", "not specified", "default string"}:
            dedup_k = f"ser:{serial}"
        elif short_h:
            dedup_k = f"host:{short_h.lower()}:{dev.get('ip', '')}"
        else:
            dedup_k = f"ip:{dev.get('ip', '')}"
        if dedup_k in seen_keys:
            continue
        seen_keys.add(dedup_k)
        unique.append(dev)
    return unique


def evaluate_trunk_mismatches(raw_devices: list[dict]) -> dict:
    """
    Correlate bidirectional switchport links across `raw_devices` and evaluate Contract C
    trunk VLAN mismatch rules (`TRK-001`..`TRK-007`) and boundary diagnostics
    (`ERR_UNCRAWLED_NEIGHBOR`, `WARN_ASYMMETRIC_DISCOVERY`, `INFO_QINQ_BOUNDARY`).

    Returns:
      `{"summary": dict, "findings": list[dict], "csv_rows": list[dict]}`
    """
    crawled_devs = _deduplicate_crawled_infra(raw_devices)

    # Build lookup indexes for crawled devices (hostname, IPv4, MAC) and LAG member maps
    dev_by_host: dict[str, dict] = {}
    ip_to_host: dict[str, str] = {}
    mac_to_host: dict[str, str] = {}
    global_member_to_lag: dict[tuple[str, str], str] = {}

    for dev in crawled_devs:
        short_h, _ = normalize_hostname(
            str(dev.get("hostname") or dev.get("canonical_hostname") or dev.get("ip") or "")
        )
        h_low = short_h.lower()
        if not h_low:
            continue
        dev_by_host[h_low] = dev
        mgmt_ip = str(dev.get("ip") or "").strip()
        if mgmt_ip and valid_ipv4(mgmt_ip):
            ip_to_host[mgmt_ip] = h_low
        for l3 in dev.get("l3_interfaces") or []:
            if isinstance(l3, dict):
                ip_tok = str(l3.get("ip_address") or "").split("/")[0].split()[0].strip()
                if ip_tok and valid_ipv4(ip_tok) and not ip_tok.startswith("127."):
                    ip_to_host[ip_tok] = h_low
        base_mac = str(dev.get("mac_address") or "").strip().lower()
        if base_mac and base_mac != "00:00:00:00:00:00":
            mac_to_host[base_mac] = h_low
        for m_port, p_lag in _collect_device_lag_member_map(dev).items():
            global_member_to_lag[(h_low, m_port)] = p_lag

    def _resolve_peer_host(raw_name: str, remote_ip: str = "", remote_mac: str = "") -> str:
        if remote_ip and remote_ip in ip_to_host:
            return ip_to_host[remote_ip]
        if remote_mac and remote_mac.lower() in mac_to_host:
            return mac_to_host[remote_mac.lower()]
        short_r, _ = normalize_hostname(raw_name)
        r_low = short_r.lower()
        if r_low in dev_by_host:
            return r_low
        if len(r_low) >= 12:
            pfx = [hk for hk in dev_by_host if hk.startswith(r_low)]
            if len(pfx) == 1:
                return pfx[0]
        return r_low

    # Extract normalized TrunkPortState records for all crawled devices
    states_by_dev_port: dict[tuple[str, str], TrunkPortState] = {}
    all_states: list[TrunkPortState] = []
    for dev in crawled_devs:
        dev_states = extract_device_trunk_states(dev)
        for st in dev_states:
            effective_local = st.lag_parent or st.interface_name
            st.interface_name = canonicalize_interface_full(effective_local)
            all_states.append(st)
            # Store primary state per (host, port)
            if (st.device_hostname, st.interface_name) not in states_by_dev_port or st.neighbor_hostname is not None:
                states_by_dev_port[(st.device_hostname, st.interface_name)] = st

    total_trunk_ports = len({(st.device_hostname, st.interface_name) for st in all_states if _is_trunk_like(st)})

    # Collect raw neighbor observations (distinguishing direct CDP/LLDP vs synthesized INFERRED)
    # Observation tuple: (local_host, local_port, remote_host, remote_port, is_direct, nbr_dict)
    raw_observations: list[tuple[str, str, str, str, bool, dict]] = []
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
            l_port = global_member_to_lag.get((l_host, l_port_phys), l_port_phys)

            r_ip = str(nbr.get("remote_ip") or "").strip()
            r_mac = str(nbr.get("remote_mac") or "").strip().lower()
            r_host = _resolve_peer_host(str(nbr.get("remote_device") or r_ip), remote_ip=r_ip, remote_mac=r_mac)
            if not r_host or r_host == l_host:
                continue

            raw_rp = str(nbr.get("remote_port") or "").strip()
            if raw_rp.lower() in {"", "unknown", "n/a", "-"}:
                r_port = ""
            else:
                base_rp = (
                    re.sub(r"\.\d+$", "", raw_rp)
                    if (re.match(r"^[^.\s]+\.\d+$", raw_rp) and not valid_ipv4(raw_rp))
                    else raw_rp
                )
                r_port_phys = canonicalize_interface_full(base_rp)
                r_port = global_member_to_lag.get((r_host, r_port_phys), r_port_phys)
                if l_port != l_port_phys and r_host not in dev_by_host:
                    r_port = uncrawled_lag_remote_port.setdefault((l_host, l_port, r_host), r_port)

            is_direct = str(nbr.get("link_confidence") or "").upper() != "INFERRED"
            raw_observations.append((l_host, l_port, r_host, r_port, is_direct, nbr))

    # Also include synthetic TrunkPortState neighbor pointers created without `dev["neighbors"]` (e.g. unit tests)
    observed_pairs = {(lh, lp, rh) for (lh, lp, rh, _rp, _dir, _n) in raw_observations}
    for st in all_states:
        if st.neighbor_hostname and (st.device_hostname, st.interface_name, st.neighbor_hostname) not in observed_pairs:
            r_host = _resolve_peer_host(st.neighbor_hostname)
            r_port_raw = st.neighbor_interface or ""
            r_port = global_member_to_lag.get((r_host, r_port_raw), r_port_raw) if r_port_raw else ""
            raw_observations.append((st.device_hostname, st.interface_name, r_host, r_port, True, {}))

    # Reconcile missing `r_port` when reciprocal observation specifies it
    for idx, (lh, lp, rh, rp, is_dir, nbr) in enumerate(raw_observations):
        if rp:
            continue
        for olh, olp, orh, orp, _odir, _onbr in raw_observations:
            if olh == rh and orh == lh and orp == lp and olp:
                raw_observations[idx] = (lh, lp, rh, olp, is_dir, nbr)
                break

    # Group observations by canonical undirected edge `((a_host, a_port), (b_host, b_port))`
    edges: dict[tuple[tuple[str, str], tuple[str, str]], dict] = {}
    for lh, lp, rh, rp, is_direct, nbr in raw_observations:
        peer_dev = dev_by_host.get(rh)
        endpoint_kind = _classify_neighbor_endpoint(nbr, peer_dev=peer_dev)
        local_state = states_by_dev_port.get((lh, lp))

        # Skip non-trunk edge peripherals (VoIP phones, printers, cameras, workstations)
        if endpoint_kind == "peripheral":
            continue

        # Handle Wireless AP endpoints: skip access-port APs and normal trunk-connected APs unless AP has conflicting profile
        if endpoint_kind == "ap":
            if local_state is None or not _is_trunk_like(local_state):
                continue
            if peer_dev is None:
                # Uncrawled AP on trunk port: normal multi-SSID AP uplink, skip ERR_UNCRAWLED_NEIGHBOR
                continue
            peer_port_state = states_by_dev_port.get((rh, rp)) if rp else None
            peer_has_explicit_profile = bool(peer_dev.get("port_profiles") or {})
            if not peer_has_explicit_profile or peer_port_state is None:
                continue

        eff_rp = rp or "unknown"
        # Synchronize resolved neighbor_hostname / neighbor_interface onto local TrunkPortState
        if local_state is not None:
            local_state.neighbor_hostname = rh
            if rp:
                local_state.neighbor_interface = rp

        end_1 = (lh, lp)
        end_2 = (rh, eff_rp)
        if end_1 <= end_2:
            edge_key = (end_1, end_2)
        else:
            edge_key = (end_2, end_1)

        bucket = edges.setdefault(
            edge_key,
            {
                "direct_from": set(),
                "sample_nbr": nbr,
                "endpoint_kind": endpoint_kind,
            },
        )
        if is_direct:
            bucket["direct_from"].add((lh, lp))

    findings: list[dict] = []
    csv_rows: list[dict] = []

    evaluated_edges = 0
    matched_edges = 0
    clean_edges = 0
    mismatched_edges = 0
    uncrawled_neighbor_edges = 0
    asymmetric_discovery_edges = 0
    qinq_boundary_edges = 0
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    rule_counts: dict[str, int] = {}

    def _record_discrepancy(
        discrepancies_out: list[dict],
        edge_id_val: str,
        side_a_h: str,
        side_a_p: str,
        side_b_h: str,
        side_b_p: str,
        rule_id: str,
        severity: str,
        message: str,
        a_only: list[int],
        b_only: list[int],
        remediation: str,
    ) -> None:
        discrepancies_out.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "side_a_only_vlans": a_only,
                "side_b_only_vlans": b_only,
                "remediation_hint": remediation,
            }
        )
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
        csv_rows.append(
            {
                "Edge_ID": edge_id_val,
                "Side_A_Host": side_a_h,
                "Side_A_Port": side_a_p,
                "Side_B_Host": side_b_h,
                "Side_B_Port": side_b_p,
                "Rule_ID": rule_id,
                "Severity": severity,
                "Side_A_Only_VLANs": format_vlan_set(a_only),
                "Side_B_Only_VLANs": format_vlan_set(b_only),
                "Remediation_Hint": remediation,
            }
        )

    for ((a_host, a_port), (b_host, b_port)), meta in sorted(edges.items()):
        edge_id = f"{a_host}:{a_port}<->{b_host}:{b_port}"
        a_crawled = a_host in dev_by_host
        b_crawled = b_host in dev_by_host
        state_a = states_by_dev_port.get((a_host, a_port)) if a_crawled else None
        state_b = states_by_dev_port.get((b_host, b_port)) if b_crawled else None

        # Ensure crawled switchports not previously profile-listed still materialize default port state
        if a_crawled and state_a is None and a_port != "unknown":
            a_dev = dev_by_host[a_host]
            state_a = TrunkPortState(
                device_hostname=a_host,
                device_mgmt_ip=str(a_dev.get("ip") or ""),
                vendor=normalize_vendor_name(
                    str(a_dev.get("vendor") or ""),
                    str(a_dev.get("os_type") or ""),
                    str(a_dev.get("device_type") or ""),
                ),
                interface_name=a_port,
                admin_mode="access",
                oper_mode="access",
                native_vlan=1,
                allowed_vlans={1},
                active_vlans={1},
            )
        if b_crawled and state_b is None and b_port != "unknown":
            b_dev = dev_by_host[b_host]
            state_b = TrunkPortState(
                device_hostname=b_host,
                device_mgmt_ip=str(b_dev.get("ip") or ""),
                vendor=normalize_vendor_name(
                    str(b_dev.get("vendor") or ""),
                    str(b_dev.get("os_type") or ""),
                    str(b_dev.get("device_type") or ""),
                ),
                interface_name=b_port,
                admin_mode="access",
                oper_mode="access",
                native_vlan=1,
                allowed_vlans={1},
                active_vlans={1},
            )

        discrepancies: list[dict] = []

        # Case 1: Uncrawled Neighbor Boundary
        if not (a_crawled and b_crawled):
            crawled_st = state_a if a_crawled else state_b
            uncrawled_host = b_host if a_crawled else a_host
            uncrawled_port = b_port if a_crawled else a_port
            crawled_host = a_host if a_crawled else b_host
            crawled_port = a_port if a_crawled else b_port

            if crawled_st is not None and (_is_trunk_like(crawled_st) or meta["endpoint_kind"] == "infra"):
                evaluated_edges += 1
                uncrawled_neighbor_edges += 1
                _record_discrepancy(
                    discrepancies,
                    edge_id,
                    a_host,
                    a_port,
                    b_host,
                    b_port,
                    rule_id="ERR_UNCRAWLED_NEIGHBOR",
                    severity="MEDIUM",
                    message=(
                        f"Uncrawled neighbor '{uncrawled_host}' ({uncrawled_port}) connected to "
                        f"{crawled_host}:{crawled_port}; remote 802.1Q trunk state cannot be verified."
                    ),
                    a_only=[],
                    b_only=[],
                    remediation=(
                        f"Add '{uncrawled_host}' management IP and credentials to crawl targets to verify "
                        f"bidirectional trunk VLAN symmetry."
                    ),
                )
                ep_a = _serialize_endpoint(state_a, a_host, a_port)
                ep_b = _serialize_endpoint(state_b, b_host, b_port)
                for disc_item in discrepancies:
                    findings.append(
                        {
                            "edge_id": edge_id,
                            "status": "UNCRAWLED_NEIGHBOR",
                            "rule_id": disc_item["rule_id"],
                            "severity": disc_item["severity"],
                            "highest_severity": "MEDIUM",
                            "message": disc_item["message"],
                            "side_a_host": a_host,
                            "side_a_port": a_port,
                            "side_b_host": b_host,
                            "side_b_port": b_port,
                            "side_a_only_vlans": disc_item["side_a_only_vlans"],
                            "side_b_only_vlans": disc_item["side_b_only_vlans"],
                            "remediation_hint": disc_item["remediation_hint"],
                            "side_a": ep_a,
                            "side_b": ep_b,
                            "endpoints": {"side_a": ep_a, "side_b": ep_b},
                            "discrepancies": discrepancies,
                        }
                    )
            continue

        # Both devices crawled
        if state_a is None or state_b is None:
            continue

        # Skip pure Layer 3 routed point-to-point links (no 802.1Q subinterface tagging on either side)
        if (
            state_a.oper_mode == "routed"
            and state_b.oper_mode == "routed"
            and not state_a.is_subinterface_bundle
            and not state_b.is_subinterface_bundle
        ):
            continue

        evaluated_edges += 1
        matched_edges += 1

        direct_set: set[tuple[str, str]] = meta["direct_from"]
        a_saw_b = (a_host, a_port) in direct_set
        b_saw_a = (b_host, b_port) in direct_set
        if a_saw_b != b_saw_a:
            asymmetric_discovery_edges += 1
            seeing_h, seeing_p = (a_host, a_port) if a_saw_b else (b_host, b_port)
            silent_h, silent_p = (b_host, b_port) if a_saw_b else (a_host, a_port)
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="WARN_ASYMMETRIC_DISCOVERY",
                severity="MEDIUM",
                message=(
                    f"Asymmetric discovery: {seeing_h}:{seeing_p} sees {silent_h}:{silent_p}, "
                    f"but {silent_h} lacks a direct CDP/LLDP neighbor record."
                ),
                a_only=[],
                b_only=[],
                remediation=f"Enable bidirectional LLDP/CDP transmit and receive on {silent_h} ({silent_p}).",
            )

        is_qinq_edge = (
            state_a.qinq_tunnel
            or state_b.qinq_tunnel
            or state_a.admin_mode == "dot1q_tunnel"
            or state_b.admin_mode == "dot1q_tunnel"
        )
        if is_qinq_edge:
            qinq_boundary_edges += 1
            qinq_sides = [
                f"{st.device_hostname}:{st.interface_name}"
                for st in (state_a, state_b)
                if st.qinq_tunnel or st.admin_mode == "dot1q_tunnel"
            ]
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="INFO_QINQ_BOUNDARY",
                severity="INFO",
                message=(
                    f"QinQ (dot1q-tunnel) boundary on {', '.join(qinq_sides)}; "
                    f"TRK-004/TRK-005 C-VLAN/S-VLAN symmetry checks bypassed."
                ),
                a_only=[],
                b_only=[],
                remediation="Verify S-VLAN Baby Giant/Jumbo MTU (>=1504 bytes) and L2 protocol tunneling.",
            )

        # TRK-001 (CRITICAL): Operational mode mismatch
        qinq_trunk_compat = is_qinq_edge and {state_a.oper_mode, state_b.oper_mode} <= {"trunk", "dot1q_tunnel"}
        if state_a.oper_mode != state_b.oper_mode and not qinq_trunk_compat:
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="TRK-001",
                severity="CRITICAL",
                message=(
                    f"Operational mode mismatch: {a_host}:{a_port} operates as '{state_a.oper_mode}', "
                    f"{b_host}:{b_port} operates as '{state_b.oper_mode}'."
                ),
                a_only=[],
                b_only=[],
                remediation=f"Configure matching static 802.1Q trunk mode on both {a_host}:{a_port} and {b_host}:{b_port}.",
            )

        # TRK-002 (CRITICAL): Native / untagged VLAN mismatch (unless both explicitly tag native with None)
        both_tagged_none = (
            state_a.native_vlan is None
            and state_b.native_vlan is None
            and state_a.native_vlan_tagged
            and state_b.native_vlan_tagged
        )
        if state_a.native_vlan != state_b.native_vlan and not both_tagged_none:
            a_nat_lbl = str(state_a.native_vlan) if state_a.native_vlan is not None else "none (tagged)"
            b_nat_lbl = str(state_b.native_vlan) if state_b.native_vlan is not None else "none (tagged)"
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="TRK-002",
                severity="CRITICAL",
                message=f"Native VLAN mismatch: {a_host} uses VLAN {a_nat_lbl}, {b_host} uses VLAN {b_nat_lbl}.",
                a_only=[state_a.native_vlan] if state_a.native_vlan is not None else [],
                b_only=[state_b.native_vlan] if state_b.native_vlan is not None else [],
                remediation=f"Set identical native VLAN ID on {a_host}:{a_port} and {b_host}:{b_port} to prevent PVID_INC blocking and VLAN leaking.",
            )

        # TRK-003 (HIGH): Asymmetric native VLAN tagging
        if state_a.native_vlan_tagged != state_b.native_vlan_tagged:
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="TRK-003",
                severity="HIGH",
                message=(
                    f"Native VLAN tagging mismatch: {a_host}:{a_port} native_vlan_tagged={state_a.native_vlan_tagged}, "
                    f"{b_host}:{b_port} native_vlan_tagged={state_b.native_vlan_tagged}."
                ),
                a_only=[],
                b_only=[],
                remediation=(
                    f"Align 802.1Q native VLAN tagging ('vlan dot1q tag native' / 'vlan trunk native tag' / "
                    f"'native-vlan-id') across {a_host} and {b_host}."
                ),
            )

        # TRK-004 (HIGH) & TRK-005 (MEDIUM): Allowed and Active VLAN symmetry (bypassed on QinQ boundaries)
        if not is_qinq_edge:
            allowed_sym_diff = state_a.allowed_vlans ^ state_b.allowed_vlans
            if allowed_sym_diff:
                a_only_allowed = sorted(state_a.allowed_vlans - state_b.allowed_vlans)
                b_only_allowed = sorted(state_b.allowed_vlans - state_a.allowed_vlans)
                if a_only_allowed and b_only_allowed:
                    msg_004 = (
                        f"Allowed VLAN mismatch: VLAN [{format_vlan_set(a_only_allowed)}] only on {a_host}; "
                        f"VLAN [{format_vlan_set(b_only_allowed)}] only on {b_host}."
                    )
                elif a_only_allowed:
                    msg_004 = (
                        f"Allowed VLAN mismatch: VLAN [{format_vlan_set(a_only_allowed)}] permitted on "
                        f"{a_host} but missing on {b_host}."
                    )
                else:
                    msg_004 = (
                        f"Allowed VLAN mismatch: VLAN [{format_vlan_set(b_only_allowed)}] permitted on "
                        f"{b_host} but missing on {a_host}."
                    )
                _record_discrepancy(
                    discrepancies,
                    edge_id,
                    a_host,
                    a_port,
                    b_host,
                    b_port,
                    rule_id="TRK-004",
                    severity="HIGH",
                    message=msg_004,
                    a_only=a_only_allowed,
                    b_only=b_only_allowed,
                    remediation=f"Synchronize allowed trunk VLAN lists between {a_host}:{a_port} and {b_host}:{b_port}.",
                )

            common_allowed = state_a.allowed_vlans & state_b.allowed_vlans
            active_drift = (state_a.active_vlans ^ state_b.active_vlans) & common_allowed
            if active_drift:
                a_only_active = sorted((state_a.active_vlans - state_b.active_vlans) & common_allowed)
                b_only_active = sorted((state_b.active_vlans - state_a.active_vlans) & common_allowed)
                drift_parts: list[str] = []
                if a_only_active:
                    drift_parts.append(
                        f"VLAN [{format_vlan_set(a_only_active)}] active on {a_host} but inactive/missing on {b_host}"
                    )
                if b_only_active:
                    drift_parts.append(
                        f"VLAN [{format_vlan_set(b_only_active)}] active on {b_host} but inactive/missing on {a_host}"
                    )
                _record_discrepancy(
                    discrepancies,
                    edge_id,
                    a_host,
                    a_port,
                    b_host,
                    b_port,
                    rule_id="TRK-005",
                    severity="MEDIUM",
                    message=f"VLAN database / STP forwarding drift: {'; '.join(drift_parts)}.",
                    a_only=a_only_active,
                    b_only=b_only_active,
                    remediation=(
                        "Define missing VLAN(s) in local VLAN database ('vlan <id>' / 'set vlans') and verify "
                        "STP forwarding state on both peers."
                    ),
                )

        # TRK-006 (MEDIUM): Default VLAN 1 permitted on trunk
        if (_is_trunk_like(state_a) or _is_trunk_like(state_b)) and (
            1 in state_a.allowed_vlans or 1 in state_b.allowed_vlans
        ):
            v1_hosts: list[str] = []
            if 1 in state_a.allowed_vlans:
                v1_hosts.append(f"{a_host}:{a_port}")
            if 1 in state_b.allowed_vlans:
                v1_hosts.append(f"{b_host}:{b_port}")
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="TRK-006",
                severity="MEDIUM",
                message=f"Default VLAN 1 permitted on trunk ({', '.join(v1_hosts)}).",
                a_only=[1] if (1 in state_a.allowed_vlans and 1 not in state_b.allowed_vlans) else [],
                b_only=[1] if (1 in state_b.allowed_vlans and 1 not in state_a.allowed_vlans) else [],
                remediation="Prune default VLAN 1 from trunk allowed VLANs after migrating management/native traffic.",
            )

        # TRK-007 (LOW): DTP dynamic negotiation enabled
        dtp_modes = {"dynamic_auto", "dynamic_desirable"}
        if state_a.admin_mode in dtp_modes or state_b.admin_mode in dtp_modes:
            dtp_sides = [
                f"{st.device_hostname}:{st.interface_name} ({st.admin_mode})"
                for st in (state_a, state_b)
                if st.admin_mode in dtp_modes
            ]
            _record_discrepancy(
                discrepancies,
                edge_id,
                a_host,
                a_port,
                b_host,
                b_port,
                rule_id="TRK-007",
                severity="LOW",
                message=f"Dynamic trunk negotiation (DTP) enabled on {', '.join(dtp_sides)}.",
                a_only=[],
                b_only=[],
                remediation="Configure static 'switchport mode trunk' and 'switchport nonegotiate' to disable DTP.",
            )

        if not discrepancies:
            clean_edges += 1
            continue

        has_trk_mismatch = any(d["rule_id"].startswith("TRK-") for d in discrepancies)
        if has_trk_mismatch:
            mismatched_edges += 1
            status = "MISMATCH"
        elif any(d["rule_id"] == "WARN_ASYMMETRIC_DISCOVERY" for d in discrepancies):
            status = "ASYMMETRIC_DISCOVERY"
        else:
            status = "QINQ_BOUNDARY"

        highest_sev = max(discrepancies, key=lambda d: _SEVERITY_RANK.get(d["severity"], 0))["severity"]
        ep_a = _serialize_endpoint(state_a, a_host, a_port)
        ep_b = _serialize_endpoint(state_b, b_host, b_port)
        for disc_item in discrepancies:
            findings.append(
                {
                    "edge_id": edge_id,
                    "status": status,
                    "rule_id": disc_item["rule_id"],
                    "severity": disc_item["severity"],
                    "highest_severity": highest_sev,
                    "message": disc_item["message"],
                    "side_a_host": a_host,
                    "side_a_port": a_port,
                    "side_b_host": b_host,
                    "side_b_port": b_port,
                    "side_a_only_vlans": disc_item["side_a_only_vlans"],
                    "side_b_only_vlans": disc_item["side_b_only_vlans"],
                    "remediation_hint": disc_item["remediation_hint"],
                    "side_a": ep_a,
                    "side_b": ep_b,
                    "endpoints": {"side_a": ep_a, "side_b": ep_b},
                    "discrepancies": discrepancies,
                }
            )

    total_discrepancies = sum(severity_counts.values())
    summary = {
        "total_trunk_ports": total_trunk_ports,
        "evaluated_edges": evaluated_edges,
        "edges_evaluated": evaluated_edges,
        "total_trunk_edges_evaluated": evaluated_edges,
        "matched_edges": matched_edges,
        "clean_edges": clean_edges,
        "mismatched_edges": mismatched_edges,
        "uncrawled_neighbor_edges": uncrawled_neighbor_edges,
        "asymmetric_discovery_edges": asymmetric_discovery_edges,
        "qinq_boundary_edges": qinq_boundary_edges,
        "total_findings": total_discrepancies,
        "total_discrepancies": total_discrepancies,
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "info_count": severity_counts["INFO"],
        "by_rule": dict(sorted(rule_counts.items())),
    }

    return {
        "summary": summary,
        "findings": findings,
        "csv_rows": csv_rows,
    }


__all__ = [
    "CSV_COLUMNS",
    "TrunkPortState",
    "canonicalize_interface_full",
    "evaluate_trunk_mismatches",
    "expand_vlan_spec",
    "extract_device_trunk_states",
    "format_vlan_set",
    "normalize_vendor_name",
]

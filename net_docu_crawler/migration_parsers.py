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
Vendor-Neutral Migration Parsers for Net-Docu-Crawler.
Extracts normalized per-port L2 intent, routing peers & FHRP (HSRP/VRRP/CARP),
DHCP scopes/reservations/relays, and firewall/NAT/VPN summaries from raw configs.
"""

import ipaddress
import re
import xml.etree.ElementTree as ET


def _extract_indented_stanza_body(lines: list[str]) -> str:
    """Return lines belonging to an indented CLI interface/VLAN stanza."""
    body_lines: list[str] = []
    for ln in lines:
        stripped = ln.strip()
        if not stripped:
            continue
        if stripped == "!" or stripped.lower() == "exit":
            break
        if not ln[0].isspace():
            break
        body_lines.append(ln)
    return "\n".join(body_lines)


def _expand_numeric_vlan_tokens(spec: str) -> set[int] | None:
    """Expand a purely numeric Cisco/EOS VLAN spec like '1,10-12' into a set of ints, or None if non-numeric."""
    out: set[int] = set()
    for raw_tok in spec.split(","):
        tok = raw_tok.strip()
        if not tok:
            continue
        if "-" in tok:
            parts = tok.split("-", 1)
            if parts[0].isdigit() and parts[1].isdigit():
                s_i, e_i = int(parts[0]), int(parts[1])
                if 1 <= s_i <= e_i <= 4094:
                    out.update(range(s_i, e_i + 1))
                    continue
            return None
        if tok.isdigit():
            val = int(tok)
            if 1 <= val <= 4094:
                out.add(val)
                continue
        return None
    return out


def _compact_vlan_set(vids: set[int]) -> str:
    """Format a set of VLAN IDs compactly (e.g. {1, 10, 11, 12, 20} -> '1,10-12,20')."""
    if not vids:
        return "none"
    sorted_ids = sorted(vids)
    ranges: list[str] = []
    start = prev = sorted_ids[0]
    for v in sorted_ids[1:]:
        if v == prev + 1:
            prev = v
        else:
            ranges.append(f"{start}-{prev}" if start != prev else str(start))
            start = prev = v
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)


def _merge_allowed_vlan_directive(existing: str, directive: str) -> str:
    """Apply a Cisco/NX-OS/Arista `switchport trunk allowed vlan <directive>` line."""
    spec = directive.strip()
    if not spec:
        return existing
    low = spec.lower()
    if low.startswith("add "):
        add_part = spec[4:].strip()
        if not add_part:
            return existing
        if not existing or existing.lower() == "none":
            return add_part
        if existing.lower() == "all":
            return "all"
        return f"{existing},{add_part}"
    if low.startswith("remove "):
        rem_part = spec[7:].strip()
        cur_set = _expand_numeric_vlan_tokens(existing) if existing else None
        rem_set = _expand_numeric_vlan_tokens(rem_part)
        if cur_set is not None and rem_set is not None:
            return _compact_vlan_set(cur_set - rem_set)
        return existing
    return spec


def extract_port_profiles(
    raw_config: str,
    vendor: str = "",
    poe: dict | None = None,
) -> dict[str, dict]:
    """
    Extract normalized per-port L2/L3 switching intent from raw_config and PoE data.
    Returns {port_name: {mode, admin_mode, oper_mode, access_vlan, voice_vlan,
                         native_vlan, native_vlan_tagged, trunk_allowed_vlans,
                         trunk_active_vlans, encapsulation, qinq_tunnel,
                         is_subinterface_bundle, lag_group, lacp_mode,
                         bpdu_guard, dot1x_mab, poe_watts}}.
    """
    profiles: dict[str, dict] = {}
    if not raw_config:
        return profiles

    def _ensure_port(port: str) -> dict:
        if port not in profiles:
            profiles[port] = {
                "mode": "unknown",
                "admin_mode": "unknown",
                "oper_mode": "",
                "access_vlan": "",
                "voice_vlan": "",
                "native_vlan": "",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "",
                "trunk_active_vlans": "",
                "encapsulation": "dot1q",
                "qinq_tunnel": False,
                "is_subinterface_bundle": False,
                "lag_group": "",
                "lacp_mode": "",
                "stp_edge": False,
                "bpdu_guard": False,
                "dot1x_mab": False,
                "poe_watts": 0.0,
            }
        return profiles[port]

    v_lower = (vendor or "").lower()

    # 1. Cisco IOS / NX-OS / Arista EOS / CiscoSMB interface blocks
    is_cisco_like = any(k in v_lower for k in ("cisco", "arista")) or (
        not v_lower
        and "interface " in raw_config
        and ("switchport " in raw_config or "encapsulation dot1q" in raw_config.lower())
    )
    if is_cisco_like and "interface " in raw_config:
        global_tag_native = bool(re.search(r"(?m)^vlan\s+dot1q\s+tag\s+native\b", raw_config, re.IGNORECASE))
        global_portfast = bool(
            re.search(r"(?m)^spanning-tree\s+portfast\s+(?:edge\s+)?default\b", raw_config, re.IGNORECASE)
        )
        global_bpduguard = bool(
            re.search(
                r"(?m)^spanning-tree\s+portfast\s+(?:edge\s+)?bpduguard\s+default\b",
                raw_config,
                re.IGNORECASE,
            )
        )
        cisco_subifs: dict[str, dict] = {}
        parent_has_ip: set[str] = set()
        explicit_no_native_tag: set[str] = set()
        explicit_no_portfast: set[str] = set()
        explicit_no_bpduguard: set[str] = set()
        cisco_touched: set[str] = set()

        blocks = re.split(r"(?m)^interface\s+", raw_config)
        for blk in blocks[1:]:
            lines = blk.splitlines()
            if not lines:
                continue
            port = lines[0].strip()
            if not port or port.lower().startswith(("vlan", "loopback", "null", "nve", "tunnel")):
                continue
            body = _extract_indented_stanza_body(lines[1:])

            # Detect L3 dot1Q subinterfaces (e.g. Gi0/0.10, GigabitEthernet0/0.99)
            m_sub = re.match(r"^([^.\s]+)\.(\d+)$", port)
            if m_sub:
                m_dot1q = re.search(
                    r"^\s*encapsulation\s+dot1q\s+(?:vlan\s+)?(\d+)(\s+native)?\b",
                    body,
                    re.MULTILINE | re.IGNORECASE,
                )
                if m_dot1q:
                    parent_port = m_sub.group(1)
                    vid = m_dot1q.group(1)
                    is_nat = bool(m_dot1q.group(2))
                    entry = cisco_subifs.setdefault(parent_port, {"vlans": set(), "native_vlan": ""})
                    entry["vlans"].add(vid)
                    if is_nat:
                        entry["native_vlan"] = vid
                    continue

            if re.search(r"^\s*ip\s+address\s+\d+\.\d+\.\d+\.\d+", body, re.MULTILINE | re.IGNORECASE):
                parent_has_ip.add(port)

            prof = _ensure_port(port)
            cisco_touched.add(port)

            if re.search(r"^\s*no\s+switchport\b", body, re.MULTILINE | re.IGNORECASE):
                prof["mode"] = "routed"
                prof["admin_mode"] = "routed"
            elif re.search(r"^\s*switchport\s+mode\s+dot1q-tunnel\b", body, re.MULTILINE | re.IGNORECASE):
                prof["mode"] = "trunk"
                prof["admin_mode"] = "dot1q_tunnel"
                prof["qinq_tunnel"] = True
            elif re.search(r"^\s*switchport\s+mode\s+trunk\b", body, re.MULTILINE | re.IGNORECASE):
                prof["mode"] = "trunk"
                prof["admin_mode"] = "trunk"
            elif re.search(r"^\s*switchport\s+mode\s+access\b", body, re.MULTILINE | re.IGNORECASE):
                prof["mode"] = "access"
                prof["admin_mode"] = "access"
            elif re.search(r"^\s*switchport\s+mode\s+dynamic\s+desirable\b", body, re.MULTILINE | re.IGNORECASE):
                prof["admin_mode"] = "dynamic_desirable"
            elif re.search(r"^\s*switchport\s+mode\s+dynamic\s+auto\b", body, re.MULTILINE | re.IGNORECASE):
                prof["admin_mode"] = "dynamic_auto"

            m_enc = re.search(
                r"^\s*switchport\s+trunk\s+encapsulation\s+(dot1q|isl|negotiate)\b",
                body,
                re.MULTILINE | re.IGNORECASE,
            )
            if m_enc:
                prof["encapsulation"] = m_enc.group(1).lower()

            m_acc = re.search(r"^\s*switchport\s+access\s+vlan\s+(\d+)", body, re.MULTILINE | re.IGNORECASE)
            if m_acc:
                prof["access_vlan"] = m_acc.group(1)
                if prof["mode"] == "unknown" and prof["admin_mode"] == "unknown":
                    prof["mode"] = "access"
                    prof["admin_mode"] = "access"

            m_voice = re.search(r"^\s*switchport\s+voice\s+vlan\s+(\d+)", body, re.MULTILINE | re.IGNORECASE)
            if m_voice:
                prof["voice_vlan"] = m_voice.group(1)

            m_nat = re.search(r"^\s*switchport\s+trunk\s+native\s+vlan\s+(\d+)", body, re.MULTILINE | re.IGNORECASE)
            if m_nat:
                prof["native_vlan"] = m_nat.group(1)

            if re.search(r"^\s*no\s+switchport\s+trunk\s+native\s+vlan\s+tag\b", body, re.MULTILINE | re.IGNORECASE):
                prof["native_vlan_tagged"] = False
                explicit_no_native_tag.add(port)
            elif re.search(r"^\s*switchport\s+trunk\s+native\s+vlan\s+tag\b", body, re.MULTILINE | re.IGNORECASE):
                prof["native_vlan_tagged"] = True

            for m_all in re.finditer(
                r"^\s*switchport\s+trunk\s+allowed\s+vlan\s+([^\r\n]+)",
                body,
                re.MULTILINE | re.IGNORECASE,
            ):
                prof["trunk_allowed_vlans"] = _merge_allowed_vlan_directive(prof["trunk_allowed_vlans"], m_all.group(1))

            m_lag = re.search(r"^\s*channel-group\s+(\d+)\s+mode\s+(\S+)", body, re.MULTILINE | re.IGNORECASE)
            if m_lag:
                prof["lag_group"] = f"Po{m_lag.group(1)}"
                prof["lacp_mode"] = m_lag.group(2).lower()

            if re.search(
                r"^\s*(?:no\s+spanning-tree\s+portfast\b|spanning-tree\s+portfast\s+disable\b)",
                body,
                re.MULTILINE | re.IGNORECASE,
            ):
                prof["stp_edge"] = False
                explicit_no_portfast.add(port)
            elif re.search(r"^\s*spanning-tree\s+portfast\b", body, re.MULTILINE | re.IGNORECASE):
                prof["stp_edge"] = True

            if re.search(
                r"^\s*(?:no\s+spanning-tree\s+bpduguard\b|spanning-tree\s+bpduguard\s+disable\b)",
                body,
                re.MULTILINE | re.IGNORECASE,
            ):
                prof["bpdu_guard"] = False
                explicit_no_bpduguard.add(port)
            elif re.search(r"spanning-tree\s+bpduguard\s+enable", body, re.IGNORECASE):
                prof["bpdu_guard"] = True
            if re.search(r"authentication\s+port-control|dot1x\s+pae|mab\b", body, re.IGNORECASE):
                prof["dot1x_mab"] = True

        # Apply global `vlan dot1q tag native` & global PortFast / BPDU Guard defaults
        for port in cisco_touched:
            prof = profiles[port]
            if global_tag_native and port not in explicit_no_native_tag:
                if not prof["qinq_tunnel"] and (
                    prof["mode"] == "trunk" or prof["admin_mode"] in ("trunk", "dynamic_auto", "dynamic_desirable")
                ):
                    prof["native_vlan_tagged"] = True
            if global_portfast and port not in explicit_no_portfast and prof["mode"] == "access":
                prof["stp_edge"] = True
            if global_bpduguard and port not in explicit_no_bpduguard and prof.get("stp_edge") is True:
                prof["bpdu_guard"] = True

        # Synthesize L3 dot1Q subinterfaces onto their parent physical/LAG port
        for parent_port, sub_info in cisco_subifs.items():
            prof = _ensure_port(parent_port)
            prof["mode"] = "trunk"
            prof["admin_mode"] = "trunk"
            prof["encapsulation"] = "dot1q"
            prof["is_subinterface_bundle"] = True
            merged_vids = set(sub_info["vlans"])
            if prof["trunk_allowed_vlans"] and prof["trunk_allowed_vlans"].lower() not in ("all", "none"):
                existing_ids = _expand_numeric_vlan_tokens(prof["trunk_allowed_vlans"])
                if existing_ids is not None:
                    merged_vids.update(str(v) for v in existing_ids)
            prof["trunk_allowed_vlans"] = ",".join(sorted(merged_vids, key=lambda x: int(x) if x.isdigit() else 99999))
            if sub_info["native_vlan"]:
                prof["native_vlan"] = sub_info["native_vlan"]
                prof["native_vlan_tagged"] = False
            elif not prof["native_vlan"]:
                if parent_port in parent_has_ip:
                    prof["native_vlan_tagged"] = False
                else:
                    prof["native_vlan"] = "none"
                    prof["native_vlan_tagged"] = True

    # 2. Aruba AOS-CX interface stanzas
    is_aoscx_cfg = (
        any(k in v_lower for k in ("aruba", "aoscx", "aos-cx"))
        and "procurve" not in v_lower
        and "arubaos-s" not in v_lower
    ) or bool(re.search(r"(?m)^\s*vlan\s+(?:trunk|access)\s+", raw_config))
    if is_aoscx_cfg and "interface " in raw_config:
        aoscx_lag_lacp: dict[str, str] = {}
        aoscx_blocks = re.split(r"(?m)^interface\s+", raw_config)
        for blk in aoscx_blocks[1:]:
            lines = blk.splitlines()
            if not lines:
                continue
            raw_hdr = lines[0].strip()
            if not raw_hdr:
                continue
            # Normalize `interface lag 1` / `interface lag 1 multi-chassis` -> `lag1`
            m_lag_hdr = re.match(r"^lag\s+(\d+)\b", raw_hdr, re.IGNORECASE)
            if m_lag_hdr:
                port = f"lag{m_lag_hdr.group(1)}"
            else:
                port = raw_hdr.split()[0]
            if port.lower().startswith(("vlan", "loopback", "null", "tunnel", "vxlan", "mgmt")):
                continue
            body = _extract_indented_stanza_body(lines[1:])
            has_aoscx_tokens = bool(
                re.search(
                    r"^\s*(?:vlan\s+(?:trunk|access)\b|lag\s+\d+\b|lacp\s+mode\b|(?:no\s+)?routing\b)",
                    body,
                    re.MULTILINE | re.IGNORECASE,
                )
            )
            if not has_aoscx_tokens:
                continue

            prof = _ensure_port(port)
            prof["encapsulation"] = "dot1q"

            if re.search(r"^\s*routing\b", body, re.MULTILINE | re.IGNORECASE) and not re.search(
                r"^\s*no\s+routing\b", body, re.MULTILINE | re.IGNORECASE
            ):
                prof["mode"] = "routed"
                prof["admin_mode"] = "routed"

            m_cx_acc = re.search(r"^\s*vlan\s+access\s+(\d+)\b", body, re.MULTILINE | re.IGNORECASE)
            if m_cx_acc:
                prof["mode"] = "access"
                prof["admin_mode"] = "access"
                prof["access_vlan"] = m_cx_acc.group(1)

            m_cx_nat = re.search(
                r"^\s*vlan\s+trunk\s+native\s+(\d+)(\s+tag)?\b",
                body,
                re.MULTILINE | re.IGNORECASE,
            )
            if m_cx_nat:
                prof["mode"] = "trunk"
                prof["admin_mode"] = "trunk"
                prof["native_vlan"] = m_cx_nat.group(1)
                if m_cx_nat.group(2):
                    prof["native_vlan_tagged"] = True

            if re.search(r"^\s*vlan\s+trunk\s+native\s+tag\b", body, re.MULTILINE | re.IGNORECASE):
                prof["mode"] = "trunk"
                prof["admin_mode"] = "trunk"
                prof["native_vlan_tagged"] = True

            for m_cx_all in re.finditer(
                r"^\s*vlan\s+trunk\s+allowed\s+([^\r\n]+)",
                body,
                re.MULTILINE | re.IGNORECASE,
            ):
                prof["mode"] = "trunk"
                prof["admin_mode"] = "trunk"
                val = m_cx_all.group(1).strip()
                if prof["trunk_allowed_vlans"] and val.lower() not in ("all", "none"):
                    prof["trunk_allowed_vlans"] = f"{prof['trunk_allowed_vlans']},{val}"
                else:
                    prof["trunk_allowed_vlans"] = val

            m_cx_lag = re.search(r"^\s*lag\s+(\d+)\b", body, re.MULTILINE | re.IGNORECASE)
            if m_cx_lag:
                prof["lag_group"] = f"lag{m_cx_lag.group(1)}"
                if not prof["lacp_mode"]:
                    prof["lacp_mode"] = "active"

            m_cx_lacp = re.search(r"^\s*lacp\s+mode\s+(active|passive)\b", body, re.MULTILINE | re.IGNORECASE)
            if m_cx_lacp:
                lacp_m = m_cx_lacp.group(1).lower()
                prof["lacp_mode"] = lacp_m
                if port.startswith("lag"):
                    aoscx_lag_lacp[port] = lacp_m

            if re.search(r"^\s*spanning-tree\s+bpdu-guard\b", body, re.MULTILINE | re.IGNORECASE):
                prof["bpdu_guard"] = True
            if re.search(r"^\s*aaa\s+authentication\s+port-access\b", body, re.MULTILINE | re.IGNORECASE):
                prof["dot1x_mab"] = True

        # Propagate LACP mode from parent lagX stanza to member ports if present
        for prof in profiles.values():
            lg = prof.get("lag_group", "")
            if lg and lg in aoscx_lag_lacp:
                prof["lacp_mode"] = aoscx_lag_lacp[lg]

    # 3. HP ProCurve / ArubaOS-S VLAN & trunk blocks
    if "procurve" in v_lower or "arubaos-s" in v_lower or re.search(r"(?m)^vlan\s+\d+\b", raw_config):
        for m_trk in re.finditer(r"(?m)^trunk\s+(\S+)\s+(Trk\d+)\s*(lacp|trunk)?", raw_config, re.IGNORECASE):
            ports_spec, trk_name, mode_tok = m_trk.groups()
            for p in _expand_port_range(ports_spec):
                prof = _ensure_port(p)
                prof["lag_group"] = trk_name
                prof["lacp_mode"] = (mode_tok or "lacp").lower()

        hp_untagged: dict[str, str] = {}
        hp_tagged: dict[str, list[str]] = {}
        hp_voice_vlans: set[str] = set()

        vlan_blocks = re.split(r"(?m)^vlan\s+(\d+)\b", raw_config)
        for idx in range(1, len(vlan_blocks) - 1, 2):
            vid = vlan_blocks[idx]
            body = vlan_blocks[idx + 1].split("\nexit")[0]
            if re.search(r"^\s*voice\b", body, re.MULTILINE):
                hp_voice_vlans.add(vid)
            for m_untag in re.finditer(r"^\s*untagged\s+([^\r\n]+)", body, re.MULTILINE):
                for p in _expand_port_range(m_untag.group(1).strip()):
                    hp_untagged[p] = vid
            for m_tag in re.finditer(r"^\s*tagged\s+([^\r\n]+)", body, re.MULTILINE):
                for p in _expand_port_range(m_tag.group(1).strip()):
                    hp_tagged.setdefault(p, [])
                    if vid not in hp_tagged[p]:
                        hp_tagged[p].append(vid)

        for p in set(hp_untagged) | set(hp_tagged):
            prof = _ensure_port(p)
            prof["encapsulation"] = "dot1q"
            untag_v = hp_untagged.get(p, "")
            tag_list = hp_tagged.get(p, [])
            non_voice_tagged = [v for v in tag_list if v not in hp_voice_vlans]
            voice_tagged = [v for v in tag_list if v in hp_voice_vlans]
            if non_voice_tagged:
                prof["mode"] = "trunk"
                prof["admin_mode"] = "trunk"
                prof["native_vlan"] = untag_v or "none"
                prof["native_vlan_tagged"] = not bool(untag_v)
                allowed_all = ([untag_v] if untag_v and untag_v not in tag_list else []) + tag_list
                allowed_all = sorted(allowed_all, key=lambda x: int(x) if x.isdigit() else 99999)
                prof["trunk_allowed_vlans"] = ",".join(allowed_all)
            elif untag_v:
                prof["mode"] = "access"
                prof["admin_mode"] = "access"
                prof["access_vlan"] = untag_v
                prof["native_vlan_tagged"] = False
                if voice_tagged:
                    prof["voice_vlan"] = voice_tagged[0]

        for m_edge in re.finditer(r"(?m)^spanning-tree\s+(\S+)\s+admin-edge-port\b", raw_config):
            for p in _expand_port_range(m_edge.group(1)):
                _ensure_port(p)["stp_edge"] = True
        for m_bpdu in re.finditer(r"(?m)^spanning-tree\s+(\S+)\s+bpdu-protection\b", raw_config):
            for p in _expand_port_range(m_bpdu.group(1)):
                _ensure_port(p)["bpdu_guard"] = True
        for m_auth in re.finditer(r"(?m)^aaa\s+port-access\s+(?:authenticator|mac-based)\s+(\S+)", raw_config):
            for p in _expand_port_range(m_auth.group(1)):
                _ensure_port(p)["dot1x_mab"] = True

    # 4. Juniper Junos hierarchical / set-style interface VLANs, vlan-tagging units & ae bundles
    if (
        "juniper" in v_lower
        or "junos" in v_lower
        or "ethernet-switching" in raw_config
        or "vlan-tagging" in raw_config
        or re.search(r"set\s+interfaces\s+\S+\s+unit\s+\d+\s+vlan-id\s+\d+", raw_config)
    ):
        # Expand `set interfaces interface-range <rname> ...` into per-member lines
        irange_members: dict[str, list[str]] = {}
        for m_ir_m in re.finditer(r"set\s+interfaces\s+interface-range\s+(\S+)\s+member\s+(\S+)", raw_config):
            rname, mport = m_ir_m.group(1), m_ir_m.group(2)
            irange_members.setdefault(rname, []).append(mport)
        for m_ir_r in re.finditer(
            r"set\s+interfaces\s+interface-range\s+(\S+)\s+member-range\s+([A-Za-z]+-\d+/\d+/)(\d+)\s+to\s+[A-Za-z]+-\d+/\d+/(\d+)",
            raw_config,
        ):
            rname, pfx, s_idx, e_idx = m_ir_r.group(1), m_ir_r.group(2), int(m_ir_r.group(3)), int(m_ir_r.group(4))
            for idx in range(s_idx, e_idx + 1):
                irange_members.setdefault(rname, []).append(f"{pfx}{idx}")
        junos_cfg = raw_config
        if irange_members:
            expanded_lines = []
            for m_ir_cmd in re.finditer(
                r"set\s+interfaces\s+interface-range\s+(\S+)\s+(?!member\b|member-range\b)(.+)$",
                raw_config,
                re.MULTILINE,
            ):
                rname, tail = m_ir_cmd.group(1), m_ir_cmd.group(2)
                for mport in irange_members.get(rname, []):
                    expanded_lines.append(f"set interfaces {mport} {tail}")
            if expanded_lines:
                junos_cfg = raw_config + "\n" + "\n".join(expanded_lines)

        junos_touched: set[str] = set()
        for m_set in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+(?:interface-mode|port-mode)\s+(access|trunk)",
            junos_cfg,
        ):
            if m_set.group(1) == "interface-range":
                continue
            p_name = m_set.group(1)
            prof = _ensure_port(p_name)
            junos_touched.add(p_name)
            prof["mode"] = m_set.group(2)
            prof["admin_mode"] = m_set.group(2)
            prof["encapsulation"] = "dot1q"

        for m_nat in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+(?:unit\s+0\s+family\s+ethernet-switching\s+)?native-vlan-id\s+(\S+)",
            junos_cfg,
        ):
            if m_nat.group(1) == "interface-range":
                continue
            p_name = m_nat.group(1)
            prof = _ensure_port(p_name)
            junos_touched.add(p_name)
            prof["native_vlan"] = m_nat.group(2).strip('"')
            prof["native_vlan_tagged"] = False

        vlans_map = extract_vlans(junos_cfg, vendor)
        name_to_vid = {v["name"].strip('"').lower(): vid for vid, v in vlans_map.items() if v.get("name")}

        def _resolve_vid(tok: str) -> str:
            t_clean = tok.strip().strip('"').strip("'")
            if not t_clean:
                return ""
            if t_clean.lower() in name_to_vid:
                return name_to_vid[t_clean.lower()]
            m_vn = re.match(r"^(?:vlan|vl)[_-]?(\d+)$", t_clean, re.IGNORECASE)
            if m_vn:
                return m_vn.group(1)
            return t_clean

        for p_name in junos_touched:
            p_data = profiles[p_name]
            if p_data.get("native_vlan"):
                p_data["native_vlan"] = _resolve_vid(p_data["native_vlan"])

        junos_members: dict[str, list[str]] = {}
        for m_v in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+vlan\s+members\s+(\[[^\]]+\]|\S+)",
            junos_cfg,
        ):
            port = m_v.group(1)
            if port == "interface-range":
                continue
            raw_val = m_v.group(2).strip("[]")
            for tok in raw_val.split():
                t = _resolve_vid(tok)
                if t:
                    junos_members.setdefault(port, [])
                    if t not in junos_members[port]:
                        junos_members[port].append(t)

        for port, members in junos_members.items():
            prof = _ensure_port(port)
            junos_touched.add(port)
            prof["encapsulation"] = "dot1q"
            if prof["mode"] == "trunk" or len(members) > 1 or "all" in members:
                if prof["mode"] == "unknown":
                    prof["mode"] = "trunk"
                if prof["admin_mode"] == "unknown":
                    prof["admin_mode"] = "trunk"
                prof["trunk_allowed_vlans"] = ",".join(members)
            else:
                if prof["mode"] == "unknown":
                    prof["mode"] = "access"
                if prof["admin_mode"] == "unknown":
                    prof["admin_mode"] = "access"
                prof["access_vlan"] = members[0]

        # Synthesize L3 vlan-tagging units (e.g. `set interfaces ge-0/0/1 unit 10 vlan-id 10`) onto parent port
        junos_subif_vlans: dict[str, set[str]] = {}
        for m_unit in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+vlan-id\s+(\d+)",
            junos_cfg,
        ):
            port, vid = m_unit.group(1), m_unit.group(2)
            if port == "interface-range" or port.lower().startswith(("irb", "lo", "vlan")):
                continue
            junos_subif_vlans.setdefault(port, set()).add(vid)

        for port, vids in junos_subif_vlans.items():
            prof = _ensure_port(port)
            junos_touched.add(port)
            prof["mode"] = "trunk"
            prof["admin_mode"] = "trunk"
            prof["encapsulation"] = "dot1q"
            prof["is_subinterface_bundle"] = True
            merged_vids = set(vids)
            if prof["trunk_allowed_vlans"] and prof["trunk_allowed_vlans"].lower() not in ("all", "none"):
                existing_ids = _expand_numeric_vlan_tokens(prof["trunk_allowed_vlans"])
                if existing_ids is not None:
                    merged_vids.update(str(v) for v in existing_ids)
            prof["trunk_allowed_vlans"] = ",".join(sorted(merged_vids, key=lambda x: int(x) if x.isdigit() else 99999))

        # Finalize Junos native_vlan & native_vlan_tagged invariant on all Junos trunk ports
        for port in junos_touched:
            prof = profiles[port]
            if prof["mode"] == "trunk":
                if not prof["native_vlan"] or prof["native_vlan"].lower() == "none":
                    prof["native_vlan"] = "none"
                    prof["native_vlan_tagged"] = True
                else:
                    prof["native_vlan_tagged"] = False
            elif prof["mode"] == "access":
                prof["native_vlan_tagged"] = False

        for m_voip in re.finditer(
            r"set\s+(?:switch-options|ethernet-switching-options)\s+voip\s+interface\s+(\S+?)(?:\.0)?\s+vlan\s+(\S+)",
            junos_cfg,
        ):
            p_voip = m_voip.group(1)
            voip_vid = _resolve_vid(m_voip.group(2))
            for target_p in irange_members.get(p_voip, [p_voip]):
                prof = _ensure_port(target_p)
                prof["voice_vlan"] = voip_vid

        for m_ae in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+ether-options\s+802\.3ad\s+(ae\d+)",
            junos_cfg,
        ):
            prof = _ensure_port(m_ae.group(1))
            prof["lag_group"] = m_ae.group(2)
            prof["lacp_mode"] = "active"

        for m_edge in re.finditer(r"set\s+protocols\s+[rvx]?stp\s+interface\s+(\S+)\s+edge\b", junos_cfg):
            p_ed = m_edge.group(1).split(".")[0]
            for target_p in irange_members.get(p_ed, [p_ed]):
                _ensure_port(target_p)["stp_edge"] = True
        for m_bpdu in re.finditer(r"set\s+protocols\s+[rvx]?stp\s+interface\s+(\S+)\s+bpdu-block-on-edge\b", junos_cfg):
            p_bp = m_bpdu.group(1).split(".")[0]
            for target_p in irange_members.get(p_bp, [p_bp]):
                _ensure_port(target_p)["bpdu_guard"] = True

        # Junos brace-style `protocols { rstp/stp/mstp { interface <port> { edge; } bpdu-block-on-edge; } }`
        for m_proto in re.finditer(r"(?m)^\s*protocols\s*\{", raw_config):
            p_open = m_proto.end() - 1
            p_close = _find_matching_brace(raw_config, p_open)
            if p_close == -1:
                continue
            proto_body = raw_config[p_open + 1 : p_close]
            for m_stp in re.finditer(r"\b(?:rstp|stp|mstp|vstp)\s*\{", proto_body):
                s_open = m_stp.end() - 1
                s_close = _find_matching_brace(proto_body, s_open)
                if s_close == -1:
                    continue
                stp_body = proto_body[s_open + 1 : s_close]
                global_j_bpdu = bool(re.search(r"\bbpdu-block-on-edge\s*;", stp_body))
                edge_ports_in_block: list[str] = []
                for m_jif in re.finditer(r"\binterface\s+([^\s{};]+)\s*\{", stp_body):
                    j_open = m_jif.end() - 1
                    j_close = _find_matching_brace(stp_body, j_open)
                    if j_close == -1:
                        continue
                    j_body = stp_body[j_open + 1 : j_close]
                    p_raw = m_jif.group(1).split(".")[0]
                    if p_raw == "all":
                        continue
                    if re.search(r"\bedge\s*;", j_body):
                        for target_p in irange_members.get(p_raw, [p_raw]):
                            _ensure_port(target_p)["stp_edge"] = True
                            edge_ports_in_block.append(target_p)
                    if re.search(r"\bbpdu-block-on-edge\s*;", j_body):
                        for target_p in irange_members.get(p_raw, [p_raw]):
                            _ensure_port(target_p)["bpdu_guard"] = True
                if global_j_bpdu:
                    for target_p in edge_ports_in_block:
                        _ensure_port(target_p)["bpdu_guard"] = True
        for m_storm in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+storm-control\b", junos_cfg
        ):
            if m_storm.group(1) == "interface-range":
                continue
            prof = _ensure_port(m_storm.group(1))
            prof["storm_control"] = True
            if prof["mode"] == "unknown":
                prof["mode"] = "access"
                if prof["admin_mode"] == "unknown":
                    prof["admin_mode"] = "access"
                if not prof["access_vlan"]:
                    prof["access_vlan"] = "1"
        for m_dot1x in re.finditer(r"set\s+protocols\s+dot1x\s+authenticator\s+interface\s+(\S+)", junos_cfg):
            p_dx = m_dot1x.group(1).split(".")[0]
            for target_p in irange_members.get(p_dx, [p_dx]):
                _ensure_port(target_p)["dot1x_mab"] = True

    # Merge PoE per-port wattage if available
    if poe and isinstance(poe.get("ports"), dict):
        for port_name, pdata in poe["ports"].items():
            watts = float(pdata.get("power_watts", pdata.get("watts", 0.0)) or 0.0)
            if watts > 0:
                prof = _ensure_port(port_name)
                prof["poe_watts"] = watts

    return profiles


def _expand_port_range(spec: str) -> list[str]:
    """Expand comma-separated port specs like '1-3,5,Trk1' into individual port names."""
    out: list[str] = []
    for token in spec.split(","):
        t = token.strip()
        if not t:
            continue
        m = re.match(r"^([A-Za-z]*)(\d+)-\1?(\d+)$", t)
        if m:
            prefix, start_s, end_s = m.groups()
            s_i, e_i = int(start_s), int(end_s)
            if s_i <= e_i and (e_i - s_i) <= 128:
                for n in range(s_i, e_i + 1):
                    out.append(f"{prefix}{n}")
                continue
        out.append(t)
    return out


def extract_routing_peers_and_fhrp_from_config(
    raw_config: str,
    vendor: str = "",
) -> tuple[list[dict], list[dict]]:
    """
    Extract dynamic routing peers (BGP/OSPF) and First-Hop Redundancy (HSRP/VRRP/CARP)
    from raw_config in a vendor-neutral structure.
    """
    peers: list[dict] = []
    fhrp: list[dict] = []
    if not raw_config:
        return peers, fhrp

    # BGP neighbors (Cisco / Arista / FRR)
    current_asn = ""
    for line in raw_config.splitlines():
        s = line.strip()
        m_bgp = re.match(r"^router\s+bgp\s+(\d+)", s)
        if m_bgp:
            current_asn = m_bgp.group(1)
            continue
        if current_asn and s.startswith("neighbor "):
            m_nbr = re.match(r"^neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)", s)
            if m_nbr:
                peers.append(
                    {
                        "protocol": "bgp",
                        "neighbor_ip": m_nbr.group(1),
                        "remote_as": m_nbr.group(2),
                        "local_as": current_asn,
                        "area": "",
                        "state": "Configured",
                        "interface": "",
                    }
                )
        elif s.startswith("router ") or s == "!":
            if s.startswith("router ") and not s.startswith("router bgp"):
                current_asn = ""

    # OSPF areas / networks (Cisco / Arista / FRR)
    current_ospf_pid = ""
    for line in raw_config.splitlines():
        s = line.strip()
        m_ospf = re.match(r"^router\s+ospf\s+(\d+)", s)
        if m_ospf:
            current_ospf_pid = m_ospf.group(1)
            continue
        if current_ospf_pid and s.startswith("network "):
            m_net = re.match(r"^network\s+(\S+\s+\S+)\s+area\s+(\S+)", s)
            if m_net:
                peers.append(
                    {
                        "protocol": "ospf",
                        "neighbor_ip": m_net.group(1),
                        "remote_as": "",
                        "area": m_net.group(2),
                        "state": "Configured",
                        "interface": "",
                    }
                )
        elif s.startswith("router ") or s == "!":
            if s.startswith("router ") and not s.startswith("router ospf"):
                current_ospf_pid = ""

    # HSRP, VRRP, GLBP, NX-OS HSRP, and Arista VARP on Cisco / Arista / ProCurve interfaces
    for blk in re.split(r"(?m)^interface\s+", raw_config)[1:]:
        lines = blk.splitlines()
        if not lines:
            continue
        intf = lines[0].strip()
        body_lines = []
        for ln in lines[1:]:
            s = ln.strip()
            if s == "!" or re.match(r"^(?:router|vlan|ip\s+route|vrf|line)\b", s, re.IGNORECASE):
                break
            body_lines.append(ln)
        body = "\n".join(body_lines)

        for m_hsrp in re.finditer(r"^\s*standby\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
            grp, vip = m_hsrp.groups()
            m_pri = re.search(rf"^\s*standby\s+{grp}\s+priority\s+(\d+)", body, re.MULTILINE)
            has_preempt = bool(re.search(rf"^\s*standby\s+{grp}\s+preempt\b", body, re.MULTILINE))
            fhrp.append(
                {
                    "protocol": "hsrp",
                    "group": grp,
                    "interface": intf,
                    "vip": vip,
                    "priority": int(m_pri.group(1)) if m_pri else 100,
                    "preempt": has_preempt,
                    "state": "Configured",
                }
            )
        # Cisco NX-OS sub-block: `hsrp <grp>\n  ip <vip>\n  priority <n>\n  preempt`
        for m_nx in re.finditer(r"(?m)^[ \t]+hsrp\s+(\d+)\s*$", body):
            grp = m_nx.group(1)
            sub_tail = body[m_nx.end() :]
            sub_lines = []
            for sln in sub_tail.splitlines():
                if not sln.strip():
                    continue
                if re.match(r"^[ \t]{2,}\S", sln):
                    sub_lines.append(sln)
                else:
                    break
            sub_body = "\n".join(sub_lines)
            m_vip = re.search(r"^\s*ip\s+(\d+\.\d+\.\d+\.\d+)", sub_body, re.MULTILINE)
            if m_vip:
                m_pri = re.search(r"^\s*priority\s+(\d+)", sub_body, re.MULTILINE)
                has_preempt = bool(re.search(r"^\s*preempt\b", sub_body, re.MULTILINE))
                fhrp.append(
                    {
                        "protocol": "hsrp",
                        "group": grp,
                        "interface": intf,
                        "vip": m_vip.group(1),
                        "priority": int(m_pri.group(1)) if m_pri else 100,
                        "preempt": has_preempt,
                        "state": "Configured",
                    }
                )
        for m_vrrp in re.finditer(r"^\s*vrrp\s+(\d+)\s+(?:ip|ipv4)\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
            grp, vip = m_vrrp.groups()
            m_pri = re.search(rf"^\s*vrrp\s+{grp}\s+priority\s+(\d+)", body, re.MULTILINE)
            has_preempt = bool(re.search(rf"^\s*vrrp\s+{grp}\s+preempt\b", body, re.MULTILINE))
            fhrp.append(
                {
                    "protocol": "vrrp",
                    "group": grp,
                    "interface": intf,
                    "vip": vip,
                    "priority": int(m_pri.group(1)) if m_pri else 100,
                    "preempt": has_preempt,
                    "state": "Configured",
                }
            )
        for m_glbp in re.finditer(r"^\s*glbp\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
            grp, vip = m_glbp.groups()
            m_pri = re.search(rf"^\s*glbp\s+{grp}\s+priority\s+(\d+)", body, re.MULTILINE)
            has_preempt = bool(re.search(rf"^\s*glbp\s+{grp}\s+preempt\b", body, re.MULTILINE))
            fhrp.append(
                {
                    "protocol": "glbp",
                    "group": grp,
                    "interface": intf,
                    "vip": vip,
                    "priority": int(m_pri.group(1)) if m_pri else 100,
                    "preempt": has_preempt,
                    "state": "Configured",
                }
            )
        for m_varp in re.finditer(
            r"^\s*ip\s+virtual-router\s+address\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)", body, re.MULTILINE
        ):
            fhrp.append(
                {
                    "protocol": "varp",
                    "group": "varp",
                    "interface": intf,
                    "vip": m_varp.group(1).split("/")[0],
                    "priority": 100,
                    "preempt": True,
                    "state": "Active-Active",
                }
            )

    # Juniper Junos set-style VRRP groups
    junos_vrrp: dict[tuple[str, str], dict] = {}
    for m_jv in re.finditer(
        r"set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+\S+\s+vrrp-group\s+(\d+)\s+(.+)$",
        raw_config,
        re.MULTILINE,
    ):
        j_if, j_unit, j_grp, tail = m_jv.groups()
        key = (f"{j_if}.{j_unit}", j_grp)
        rec = junos_vrrp.setdefault(
            key,
            {
                "protocol": "vrrp",
                "group": j_grp,
                "interface": f"{j_if}.{j_unit}",
                "vip": "",
                "priority": 100,
                "preempt": False,
                "state": "Configured",
            },
        )
        m_va = re.search(r"\bvirtual-address\s+(\d+\.\d+\.\d+\.\d+)", tail)
        if m_va:
            rec["vip"] = m_va.group(1)
        m_pr = re.search(r"\bpriority\s+(\d+)", tail)
        if m_pr:
            rec["priority"] = int(m_pr.group(1))
        if re.search(r"\bpreempt\b", tail) and "no-preempt" not in tail:
            rec["preempt"] = True
    for rec in junos_vrrp.values():
        if rec["vip"]:
            fhrp.append(rec)

    # MikroTik `/interface vrrp`
    if "/interface vrrp" in raw_config:
        m_mt = re.search(r"(?ms)^/interface\s+vrrp\s*\n(.*?)(?:\n/|\Z)", raw_config)
        if m_mt:
            for ln in m_mt.group(1).splitlines():
                s = ln.strip()
                if not s.startswith("add "):
                    continue
                m_vrid = re.search(r"\bvrid=(\d+)", s)
                m_if = re.search(r"\binterface=([^\s]+)", s)
                m_pri = re.search(r"\bpriority=(\d+)", s)
                m_pre = re.search(r"\bpreemption-mode=(yes|no)", s)
                if m_vrid:
                    fhrp.append(
                        {
                            "protocol": "vrrp",
                            "group": m_vrid.group(1),
                            "interface": _strip_outer_quotes(m_if.group(1)) if m_if else "",
                            "vip": "See L3 Interface",
                            "priority": int(m_pri.group(1)) if m_pri else 100,
                            "preempt": (m_pre.group(1) == "yes") if m_pre else True,
                            "state": "Configured",
                        }
                    )

    # FortiOS `config system ha` (Active-Passive / Active-Active cluster)
    if "config system ha" in raw_config:
        m_ha = re.search(r"(?ms)^config system ha\s*\n(.*?)\nend\b", raw_config)
        if m_ha:
            ha_body = m_ha.group(1)
            m_mode = re.search(r"set\s+mode\s+(a-p|a-a)", ha_body)
            if m_mode:
                m_gid = re.search(r"set\s+group-id\s+(\d+)", ha_body)
                m_pri = re.search(r"set\s+priority\s+(\d+)", ha_body)
                has_ovr = bool(re.search(r"set\s+override\s+enable", ha_body))
                fhrp.append(
                    {
                        "protocol": "fgcp-ha",
                        "group": m_gid.group(1) if m_gid else "0",
                        "interface": "HA-Cluster",
                        "vip": "Cluster-Synced",
                        "priority": int(m_pri.group(1)) if m_pri else 128,
                        "preempt": has_ovr,
                        "state": "Active-Passive" if m_mode.group(1) == "a-p" else "Active-Active",
                    }
                )

    # OPNsense CARP VIPs in config.xml
    if "<virtualip>" in raw_config or "<VirtualIP>" in raw_config:
        try:
            root = ET.fromstring(raw_config)
            for vip_el in root.findall(".//virtualip/vip") + root.findall(".//VirtualIP/vip"):
                mode = (vip_el.findtext("mode") or "").lower()
                if mode in ("carp", "ipalias"):
                    fhrp.append(
                        {
                            "protocol": mode,
                            "group": vip_el.findtext("vhid") or "",
                            "interface": vip_el.findtext("interface") or "",
                            "vip": vip_el.findtext("subnet") or "",
                            "priority": int(vip_el.findtext("advskew") or 0),
                            "preempt": mode == "carp",
                            "state": "Configured",
                        }
                    )
        except ET.ParseError:
            pass

    return peers, fhrp


def extract_dhcp_config(raw_config: str, vendor: str = "") -> dict:
    """
    Extract normalized DHCP pools, static MAC->IP reservations, and DHCP relays
    across Cisco, OPNsense, OpenWrt, MikroTik, and FortiOS configurations.
    """
    result: dict[str, list[dict]] = {"pools": [], "reservations": [], "relays": []}
    if not raw_config:
        return result

    # 1. Cisco IOS / Arista EOS DHCP pools & ip helper-address
    for blk in re.split(r"(?m)^ip\s+dhcp\s+pool\s+", raw_config)[1:]:
        lines = blk.splitlines()
        if not lines:
            continue
        pool_name = lines[0].strip()
        body = "\n".join(lines[1:]).split("\n!")[0]
        m_net = re.search(r"^\s*network\s+(\S+\s+\S+|\S+/\d+)", body, re.MULTILINE)
        m_gw = re.search(r"^\s*default-router\s+([^\r\n]+)", body, re.MULTILINE)
        m_dns = re.search(r"^\s*dns-server\s+([^\r\n]+)", body, re.MULTILINE)
        m_host = re.search(r"^\s*host\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE)
        m_mac = re.search(r"^\s*(?:hardware-address|client-identifier)\s+(\S+)", body, re.MULTILINE)
        if m_host and m_mac:
            result["reservations"].append(
                {
                    "mac": m_mac.group(1),
                    "ip": m_host.group(1),
                    "hostname": pool_name,
                    "pool": pool_name,
                }
            )
        else:
            result["pools"].append(
                {
                    "name": pool_name,
                    "network": m_net.group(1).strip() if m_net else "",
                    "range": "",
                    "gateway": m_gw.group(1).strip() if m_gw else "",
                    "dns": m_dns.group(1).strip() if m_dns else "",
                }
            )

    # Cisco / Arista interface-scoped ip helper-address (stop at !, exit, or vlan/router stanza)
    for blk in re.split(r"(?m)^interface\s+", raw_config)[1:]:
        lines = blk.splitlines()
        if not lines:
            continue
        intf = lines[0].strip()
        body_lines = []
        for ln in lines[1:]:
            s = ln.strip()
            if s == "!" or s.lower() == "exit" or re.match(r"^(?:vlan|router|ip\s+route)\b", s, re.IGNORECASE):
                break
            body_lines.append(ln)
        body = "\n".join(body_lines)
        for m_hlp in re.finditer(
            r"^\s*(?:ip\s+helper-address\s+(?:vrf\s+\S+\s+|global\s+)?|ip\s+dhcp\s+relay\s+address\s+)(\d+\.\d+\.\d+\.\d+)",
            body,
            re.MULTILINE | re.IGNORECASE,
        ):
            result["relays"].append({"interface": intf, "helper_ip": m_hlp.group(1)})

    # HP ProCurve / ArubaOS-S VLAN-scoped ip helper-address
    if re.search(r"(?m)^vlan\s+\d+\b", raw_config):
        vlan_blocks = re.split(r"(?m)^vlan\s+(\d+)\b", raw_config)
        for idx in range(1, len(vlan_blocks) - 1, 2):
            vid = vlan_blocks[idx]
            body = vlan_blocks[idx + 1].split("\nexit")[0]
            seen_h: set[str] = set()
            for m_hlp in re.finditer(r"^\s*ip\s+helper-address\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
                hip = m_hlp.group(1)
                if hip not in seen_h:
                    seen_h.add(hip)
                    result["relays"].append({"interface": f"VLAN {vid}", "helper_ip": hip})

    # Juniper Junos forwarding-options dhcp-relay (both set-style and brace-style)
    if "dhcp-relay" in raw_config or "helpers bootp" in raw_config:
        sg_ips: dict[str, list[str]] = {}
        grp_sg: dict[str, str] = {}
        grp_intfs: dict[str, list[str]] = {}
        for m_sg in re.finditer(
            r"set\s+(?:routing-instances\s+\S+\s+)?forwarding-options\s+dhcp-relay\s+server-group\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)",
            raw_config,
        ):
            sg_ips.setdefault(m_sg.group(1), []).append(m_sg.group(2))
        for m_asg in re.finditer(
            r"set\s+(?:routing-instances\s+\S+\s+)?forwarding-options\s+dhcp-relay\s+group\s+(\S+)\s+active-server-group\s+(\S+)",
            raw_config,
        ):
            grp_sg[m_asg.group(1)] = m_asg.group(2)
        for m_gi in re.finditer(
            r"set\s+(?:routing-instances\s+\S+\s+)?forwarding-options\s+dhcp-relay\s+group\s+(\S+)\s+interface\s+(\S+)",
            raw_config,
        ):
            grp_intfs.setdefault(m_gi.group(1), []).append(m_gi.group(2))

        # Brace-style `dhcp-relay { server-group { SG { 10.0.0.1; } } group G { active-server-group { SG; } interface irb.10; } }`
        for m_dr in re.finditer(r"\bdhcp-relay\s*\{", raw_config):
            dr_open = m_dr.end() - 1
            dr_close = _find_matching_brace(raw_config, dr_open)
            if dr_close == -1:
                continue
            dr_body = raw_config[dr_open + 1 : dr_close]
            for m_sgb in re.finditer(r"\bserver-group\s*\{", dr_body):
                sg_open = m_sgb.end() - 1
                sg_close = _find_matching_brace(dr_body, sg_open)
                if sg_close == -1:
                    continue
                sg_section = dr_body[sg_open + 1 : sg_close]
                pos = 0
                while pos < len(sg_section):
                    m_named = re.search(r"([^\s{};]+)\s*\{", sg_section[pos:])
                    if not m_named:
                        break
                    sg_name = _strip_outer_quotes(m_named.group(1))
                    n_open = pos + m_named.end() - 1
                    n_close = _find_matching_brace(sg_section, n_open)
                    if n_close == -1:
                        break
                    for ip_m in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\b", sg_section[n_open + 1 : n_close]):
                        if ip_m.group(1) not in sg_ips.setdefault(sg_name, []):
                            sg_ips[sg_name].append(ip_m.group(1))
                    pos = n_close + 1
            for m_grp in re.finditer(r"\bgroup\s+([^\s{};]+)\s*\{", dr_body):
                g_name = _strip_outer_quotes(m_grp.group(1))
                g_open = m_grp.end() - 1
                g_close = _find_matching_brace(dr_body, g_open)
                if g_close == -1:
                    continue
                g_body = dr_body[g_open + 1 : g_close]
                m_asg_b = re.search(r"\bactive-server-group\s*(?:\{\s*([^\s{};]+)\s*;\s*\}|([^\s{};]+)\s*;)", g_body)
                if m_asg_b:
                    grp_sg[g_name] = _strip_outer_quotes(m_asg_b.group(1) or m_asg_b.group(2))
                for m_gif in re.finditer(r"\binterface\s+([^\s{};]+)\s*;", g_body):
                    gif = _strip_outer_quotes(m_gif.group(1))
                    if gif not in grp_intfs.setdefault(g_name, []):
                        grp_intfs[g_name].append(gif)

        for grp, intfs in grp_intfs.items():
            sg = grp_sg.get(grp, "")
            ips = sg_ips.get(sg, [])
            for intf in intfs:
                for hip in ips:
                    result["relays"].append({"interface": intf, "helper_ip": hip})
        for m_bootp in re.finditer(
            r"set\s+forwarding-options\s+helpers\s+bootp\s+server\s+(\d+\.\d+\.\d+\.\d+)\s+interface\s+(\S+)",
            raw_config,
        ):
            result["relays"].append({"interface": m_bootp.group(2), "helper_ip": m_bootp.group(1)})

    # 2. OPNsense config.xml <dhcpd>, legacy <dhcrelay>, and MVC <DHCRelay>
    if "<dhcpd>" in raw_config or "<dhcrelay>" in raw_config or "<DHCRelay>" in raw_config:
        try:
            root = ET.fromstring(raw_config)
            dhcpd = root.find("dhcpd")
            if dhcpd is not None:
                for iface_el in list(dhcpd):
                    iface_name = iface_el.tag
                    rng_from = iface_el.findtext("range/from") or ""
                    rng_to = iface_el.findtext("range/to") or ""
                    if rng_from or rng_to:
                        result["pools"].append(
                            {
                                "name": iface_name,
                                "network": "",
                                "range": f"{rng_from}-{rng_to}".strip("-"),
                                "gateway": iface_el.findtext("gateway") or "",
                                "dns": iface_el.findtext("dnsserver") or "",
                            }
                        )
                    for smap in iface_el.findall("staticmap"):
                        result["reservations"].append(
                            {
                                "mac": smap.findtext("mac") or "",
                                "ip": smap.findtext("ipaddr") or "",
                                "hostname": smap.findtext("hostname") or "",
                                "pool": iface_name,
                            }
                        )
            dhcrelay = root.find("dhcrelay")
            if dhcrelay is not None and (dhcrelay.findtext("enable") or "1").strip() not in ("0", "false"):
                r_intfs = [i.strip() for i in (dhcrelay.findtext("interface") or "").split(",") if i.strip()]
                r_srvs = [s.strip() for s in (dhcrelay.findtext("server") or "").split(",") if s.strip()]
                for r_if in r_intfs or ["global"]:
                    for r_ip in r_srvs:
                        result["relays"].append({"interface": r_if, "helper_ip": r_ip})
            for mvc_rel in root.findall(".//DHCRelay/relays/relay"):
                if (mvc_rel.findtext("enabled") or "1").strip() in ("0", "false"):
                    continue
                r_if = (mvc_rel.findtext("interface") or "global").strip()
                dest_uuid = (mvc_rel.findtext("destination") or "").strip()
                dest_srvs = []
                if dest_uuid:
                    for dest_el in root.findall(".//DHCRelay/destinations/destination"):
                        if dest_el.attrib.get("uuid") == dest_uuid:
                            dest_srvs.extend(
                                s.strip() for s in (dest_el.findtext("server") or "").split(",") if s.strip()
                            )
                for r_ip in dest_srvs:
                    result["relays"].append({"interface": r_if, "helper_ip": r_ip})
        except ET.ParseError:
            pass

    # 3. OpenWrt UCI dhcp
    if "dhcp." in raw_config and ("option start" in raw_config or "=host" in raw_config):
        for m_host in re.finditer(
            r"dhcp\.@host\[(\d+)\]\.mac='([^']+)'",
            raw_config,
        ):
            idx, mac = m_host.groups()
            m_ip = re.search(rf"dhcp\.@host\[{idx}\]\.ip='([^']+)'", raw_config)
            m_nm = re.search(rf"dhcp\.@host\[{idx}\]\.name='([^']+)'", raw_config)
            result["reservations"].append(
                {
                    "mac": mac,
                    "ip": m_ip.group(1) if m_ip else "",
                    "hostname": m_nm.group(1) if m_nm else "",
                    "pool": "openwrt",
                }
            )

    # 4. FortiOS config system dhcp server
    if "config system dhcp server" in raw_config:
        m_dhcp = re.search(
            r"(?ms)^config system dhcp server\s*\n(.*?)(?:\nend\s*$|\nend\s*\n)",
            raw_config,
        )
        if m_dhcp:
            dhcp_body = m_dhcp.group(1)
            cur_pool: dict | None = None
            sub_ctx: str | None = None
            cur_res: dict | None = None
            depth = 0
            for raw_line in dhcp_body.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("config "):
                    depth += 1
                    if depth == 1 and line == "config ip-range":
                        sub_ctx = "ip-range"
                    elif depth == 1 and line == "config reserved-address":
                        sub_ctx = "reserved-address"
                    else:
                        sub_ctx = None
                    continue
                if line == "end":
                    if depth > 0:
                        depth -= 1
                    if depth == 0:
                        sub_ctx = None
                        cur_res = None
                    continue
                m_edit = re.match(r"^edit\s+(\S+)", line)
                if m_edit:
                    if depth == 0:
                        cur_pool = {
                            "id": m_edit.group(1).strip('"'),
                            "interface": "",
                            "netmask": "",
                            "gateway": "",
                            "dns": "",
                            "ranges": [],
                            "disabled": False,
                            "reservations": [],
                        }
                    elif depth == 1 and sub_ctx == "reserved-address" and cur_pool is not None:
                        cur_res = {"mac": "", "ip": "", "hostname": "", "action": "reserved"}
                    continue
                if line == "next":
                    if depth == 0 and cur_pool is not None:
                        if not cur_pool["disabled"]:
                            rng_str = ", ".join(cur_pool["ranges"])
                            anchor = cur_pool["gateway"] or (
                                cur_pool["ranges"][0].split("-")[0] if cur_pool["ranges"] else ""
                            )
                            net_str = ""
                            if anchor and cur_pool["netmask"]:
                                try:
                                    net_str = str(ipaddress.IPv4Interface(f"{anchor}/{cur_pool['netmask']}").network)
                                except Exception:
                                    net_str = f"{anchor} {cur_pool['netmask']}"
                            pool_name = cur_pool["interface"] or f"dhcp-{cur_pool['id']}"
                            result["pools"].append(
                                {
                                    "name": pool_name,
                                    "network": net_str,
                                    "range": rng_str,
                                    "gateway": cur_pool["gateway"],
                                    "dns": cur_pool["dns"],
                                }
                            )
                            for res in cur_pool["reservations"]:
                                if res.get("ip") or res.get("mac"):
                                    result["reservations"].append(
                                        {
                                            "mac": res["mac"],
                                            "ip": res["ip"],
                                            "hostname": res["hostname"],
                                            "pool": pool_name,
                                        }
                                    )
                        cur_pool = None
                    elif depth == 1 and sub_ctx == "reserved-address" and cur_pool is not None and cur_res is not None:
                        cur_pool["reservations"].append(cur_res)
                        cur_res = None
                    continue

                if cur_pool is None:
                    continue
                if depth == 0:
                    if line == "set status disable":
                        cur_pool["disabled"] = True
                    elif line.startswith("set interface "):
                        cur_pool["interface"] = line.split("set interface", 1)[1].strip().strip('"')
                    elif line.startswith("set netmask "):
                        cur_pool["netmask"] = line.split("set netmask", 1)[1].strip().strip('"')
                    elif line.startswith("set default-gateway "):
                        cur_pool["gateway"] = line.split("set default-gateway", 1)[1].strip().strip('"')
                    elif line.startswith("set dns-server1 "):
                        cur_pool["dns"] = line.split("set dns-server1", 1)[1].strip().strip('"')
                elif depth == 1 and sub_ctx == "ip-range":
                    if line.startswith("set start-ip "):
                        cur_pool.setdefault("_start_ip", line.split("set start-ip", 1)[1].strip().strip('"'))
                        cur_pool["_start_ip"] = line.split("set start-ip", 1)[1].strip().strip('"')
                    elif line.startswith("set end-ip "):
                        end_ip = line.split("set end-ip", 1)[1].strip().strip('"')
                        start_ip = cur_pool.pop("_start_ip", "")
                        if start_ip or end_ip:
                            cur_pool["ranges"].append(f"{start_ip}-{end_ip}".strip("-"))
                elif depth == 1 and sub_ctx == "reserved-address" and cur_res is not None:
                    if line.startswith("set ip "):
                        cur_res["ip"] = line.split("set ip", 1)[1].strip().strip('"')
                    elif line.startswith("set mac "):
                        cur_res["mac"] = line.split("set mac", 1)[1].strip().strip('"').lower()
                    elif line.startswith("set description "):
                        cur_res["hostname"] = line.split("set description", 1)[1].strip().strip('"')

    # 5. FortiOS interface-scoped DHCP relays (`set dhcp-relay-ip "ip1" "ip2"`)
    if "dhcp-relay-ip" in raw_config and "config system interface" in raw_config:
        m_if_sec = re.search(r"(?ms)^config system interface\s*\n(.*?)(?:\nend\s*$|\nend\s*\n)", raw_config)
        if m_if_sec:
            for m_edit in re.finditer(r'(?ms)^\s*edit\s+"?([^"\r\n]+)"?\s*\n(.*?)^\s*next\b', m_if_sec.group(1)):
                if_name, if_body = m_edit.group(1).strip(), m_edit.group(2)
                m_rip = re.search(r"^\s*set\s+dhcp-relay-ip\s+([^\r\n]+)", if_body, re.MULTILINE)
                if m_rip:
                    for rip in re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", m_rip.group(1)):
                        result["relays"].append({"interface": if_name, "helper_ip": rip})

    # 6. MikroTik `/ip dhcp-relay`
    if "/ip dhcp-relay" in raw_config:
        m_mt = re.search(r"(?ms)^/ip\s+dhcp-relay\s*\n(.*?)(?:\n/|\Z)", raw_config)
        if m_mt:
            for ln in m_mt.group(1).splitlines():
                s = ln.strip()
                if not s.startswith("add ") or "disabled=yes" in s:
                    continue
                m_srv = re.search(r"\bdhcp-server=([^\s]+)", s)
                m_if = re.search(r"\binterface=([^\s]+)", s)
                if m_srv:
                    intf_lbl = _strip_outer_quotes(m_if.group(1)) if m_if else "global"
                    for rip in _strip_outer_quotes(m_srv.group(1)).split(","):
                        rip_c = rip.strip()
                        if rip_c:
                            result["relays"].append({"interface": intf_lbl, "helper_ip": rip_c})

    return result


def extract_firewall_nat_vpn(raw_config: str, vendor: str = "") -> dict:
    """
    Extract normalized firewall rules, NAT rules, and VPN tunnels from raw_config.
    """
    out: dict[str, list[dict]] = {"firewall_rules": [], "nat_rules": [], "vpn_tunnels": []}
    if not raw_config:
        return out

    # OPNsense config.xml
    if "<opnsense>" in raw_config or "<pfsense>" in raw_config:
        try:
            root = ET.fromstring(raw_config)
            for rule in root.findall("./filter/rule"):
                if rule.find("disabled") is not None:
                    continue
                out["firewall_rules"].append(
                    {
                        "action": rule.findtext("type") or "pass",
                        "interface": rule.findtext("interface") or "",
                        "protocol": rule.findtext("protocol") or "any",
                        "src": rule.findtext("source/network") or rule.findtext("source/address") or "any",
                        "dst": rule.findtext("destination/network") or rule.findtext("destination/address") or "any",
                        "dst_port": rule.findtext("destination/port") or "any",
                        "descr": rule.findtext("descr") or "",
                    }
                )
            for nat in root.findall("./nat/outbound/rule"):
                out["nat_rules"].append(
                    {
                        "type": "outbound",
                        "interface": nat.findtext("interface") or "",
                        "src": nat.findtext("source/network") or "",
                        "target": nat.findtext("target") or "interface-ip",
                    }
                )
            for pnat in root.findall("./nat/rule"):
                if pnat.find("disabled") is not None:
                    continue
                out["nat_rules"].append(
                    {
                        "type": "port-forward",
                        "interface": pnat.findtext("interface") or "",
                        "src": pnat.findtext("source/network") or "any",
                        "target": pnat.findtext("target") or "",
                    }
                )
            out_mode = (root.findtext("./nat/outbound/mode") or "").strip().lower()
            if out_mode in ("automatic", "hybrid") and not any(r.get("type") == "outbound" for r in out["nat_rules"]):
                out["nat_rules"].append(
                    {
                        "type": f"outbound-{out_mode}",
                        "interface": "wan",
                        "src": "lan-subnets",
                        "target": "interface-ip",
                    }
                )
            for p1 in root.findall("./ipsec/phase1"):
                out["vpn_tunnels"].append(
                    {
                        "type": "ipsec",
                        "remote_gw": p1.findtext("remote-gateway") or "",
                        "descr": p1.findtext("descr") or "",
                    }
                )
        except ET.ParseError:
            pass

    # FortiOS firewall policies & NAT
    if "config firewall policy" in raw_config:
        m_fp = re.search(r"(?ms)^config firewall policy\s*\n(.*?)(?:\nend\s*$|\nend\s*\n)", raw_config)
        fp_body = m_fp.group(1) if m_fp else raw_config
        for m_pol in re.finditer(r"edit\s+(\d+)(.*?)next", fp_body, re.DOTALL):
            body = m_pol.group(2)
            if "set srcintf" not in body:
                continue
            srcintf = re.search(r'set\s+srcintf\s+"([^"]+)"', body)
            dstintf = re.search(r'set\s+dstintf\s+"([^"]+)"', body)
            action = re.search(r"set\s+action\s+(\S+)", body)
            iface_pair = f"{srcintf.group(1) if srcintf else ''}->{dstintf.group(1) if dstintf else ''}"
            out["firewall_rules"].append(
                {
                    "action": action.group(1) if action else "deny",
                    "interface": iface_pair,
                    "protocol": "any",
                    "src": "policy",
                    "dst": "policy",
                    "dst_port": "any",
                    "descr": f"policy-{m_pol.group(1)}",
                }
            )
            if re.search(r"^\s*set\s+nat\s+enable\b", body, re.MULTILINE):
                out["nat_rules"].append(
                    {
                        "type": "policy-nat",
                        "interface": iface_pair,
                        "src": "policy",
                        "target": f"policy-{m_pol.group(1)}",
                    }
                )
    if "config firewall vip" in raw_config:
        m_vip = re.search(r"(?ms)^config firewall vip\s*\n(.*?)(?:\nend\s*$|\nend\s*\n)", raw_config)
        if m_vip:
            for m_e in re.finditer(r'(?ms)^\s*edit\s+"?([^"\r\n]+)"?\s*\n(.*?)^\s*next\b', m_vip.group(1)):
                vname, vbody = m_e.group(1).strip(), m_e.group(2)
                m_ext = re.search(r"set\s+extip\s+(\S+)", vbody)
                m_map = re.search(r'set\s+mappedip\s+"?([^"\r\n]+)"?', vbody)
                out["nat_rules"].append(
                    {
                        "type": "vip-dnat",
                        "interface": vname,
                        "src": m_ext.group(1) if m_ext else "",
                        "target": m_map.group(1).strip() if m_map else "",
                    }
                )

    # Cisco IOS / Arista EOS ACLs & NAT overload/static rules
    for m_acl in re.finditer(r"(?m)^ip\s+access-list\s+(?:extended|standard)\s+(\S+)", raw_config, re.IGNORECASE):
        out["firewall_rules"].append(
            {
                "action": "acl",
                "interface": "",
                "protocol": "ip",
                "src": "",
                "dst": "",
                "dst_port": "",
                "descr": m_acl.group(1),
            }
        )
    for m_nat in re.finditer(r"(?m)^ip\s+nat\s+(inside|outside)\s+source\s+([^\r\n]+)", raw_config, re.IGNORECASE):
        out["nat_rules"].append(
            {
                "type": f"cisco-nat-{m_nat.group(1).lower()}",
                "interface": "",
                "src": m_nat.group(2).strip()[:80],
                "target": "overload" if "overload" in m_nat.group(2).lower() else "static",
            }
        )

    # MikroTik `/ip firewall filter` & `/ip firewall nat`
    if "/ip firewall filter" in raw_config:
        m_mf = re.search(r"(?ms)^/ip\s+firewall\s+filter\s*\n(.*?)(?:\n/|\Z)", raw_config)
        if m_mf:
            for ln in m_mf.group(1).splitlines():
                s = ln.strip()
                if not s.startswith("add ") or "disabled=yes" in s:
                    continue
                m_act = re.search(r"\baction=(\S+)", s)
                m_ch = re.search(r"\bchain=(\S+)", s)
                out["firewall_rules"].append(
                    {
                        "action": m_act.group(1) if m_act else "accept",
                        "interface": m_ch.group(1) if m_ch else "forward",
                        "protocol": "any",
                        "src": "",
                        "dst": "",
                        "dst_port": "",
                        "descr": s[:80],
                    }
                )
    if "/ip firewall nat" in raw_config:
        m_mn = re.search(r"(?ms)^/ip\s+firewall\s+nat\s*\n(.*?)(?:\n/|\Z)", raw_config)
        if m_mn:
            for ln in m_mn.group(1).splitlines():
                s = ln.strip()
                if not s.startswith("add ") or "disabled=yes" in s:
                    continue
                m_act = re.search(r"\baction=(\S+)", s)
                m_if = re.search(r"\bout-interface=(\S+)", s)
                out["nat_rules"].append(
                    {
                        "type": m_act.group(1) if m_act else "nat",
                        "interface": _strip_outer_quotes(m_if.group(1)) if m_if else "",
                        "src": "",
                        "target": m_act.group(1) if m_act else "",
                    }
                )

    # OpenWrt UCI firewall rules & redirects
    for m_ur in re.finditer(r"firewall\.@rule\[(\d+)\]=rule", raw_config):
        idx = m_ur.group(1)
        m_nm = re.search(rf"firewall\.@rule\[{idx}\]\.name='([^']+)'", raw_config)
        m_tg = re.search(rf"firewall\.@rule\[{idx}\]\.target='([^']+)'", raw_config)
        out["firewall_rules"].append(
            {
                "action": m_tg.group(1) if m_tg else "ACCEPT",
                "interface": "uci",
                "protocol": "any",
                "src": "",
                "dst": "",
                "dst_port": "",
                "descr": m_nm.group(1) if m_nm else f"rule-{idx}",
            }
        )
    for m_ud in re.finditer(r"firewall\.@redirect\[(\d+)\]=redirect", raw_config):
        idx = m_ud.group(1)
        m_nm = re.search(rf"firewall\.@redirect\[{idx}\]\.name='([^']+)'", raw_config)
        out["nat_rules"].append(
            {
                "type": "uci-redirect",
                "interface": "wan",
                "src": "",
                "target": m_nm.group(1) if m_nm else f"redirect-{idx}",
            }
        )

    return out


def _strip_outer_quotes(val: str) -> str:
    s = val.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1].strip()
    return s


def _find_matching_brace(text: str, open_idx: int) -> int:
    """Return index of matching '}' for '{' at `open_idx`, or -1 if unbalanced."""
    depth = 0
    in_quote: str | None = None
    escaped = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if escaped:
            escaped = False
            continue
        if in_quote:
            if ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _extract_junos_brace_vlans(raw_config: str) -> list[tuple[str, str]]:
    """Extract (vlan_name, stanza_body) pairs from Junos brace-style `vlans { ... }` blocks."""
    blocks: list[tuple[str, str]] = []
    for m_top in re.finditer(r"(?m)^\s*vlans\s*\{", raw_config):
        open_idx = m_top.end() - 1
        close_idx = _find_matching_brace(raw_config, open_idx)
        if close_idx == -1:
            continue
        body = raw_config[open_idx + 1 : close_idx]
        pos = 0
        while pos < len(body):
            m_child = re.search(r"([^\s{};]+)\s*\{", body[pos:])
            if not m_child:
                break
            vname = _strip_outer_quotes(m_child.group(1))
            child_open = pos + m_child.end() - 1
            child_close = _find_matching_brace(body, child_open)
            if child_close == -1:
                break
            blocks.append((vname, body[child_open + 1 : child_close]))
            pos = child_close + 1
    return blocks


def extract_vlans(raw_config: str, vendor: str = "") -> dict[str, dict]:
    """
    Extract configured VLANs {vlan_id: {"id", "name", "svi_interface", "voice", "description"}}
    from Cisco IOS/Arista, HP ProCurve, and Juniper Junos configurations.
    """
    vlans: dict[str, dict] = {}
    if not raw_config:
        return vlans

    # 1. Cisco / Arista / HP ProCurve `vlan <id>` blocks
    vlan_blocks = re.split(r"(?m)^vlan\s+(\d+)\b", raw_config)
    for idx in range(1, len(vlan_blocks) - 1, 2):
        vid = vlan_blocks[idx]
        body = vlan_blocks[idx + 1].split("\nexit")[0].split("\n!")[0]
        m_name = re.search(r'^\s*name\s+"?([^"\r\n]+)"?', body, re.MULTILINE | re.IGNORECASE)
        vname = m_name.group(1).strip() if m_name else f"VLAN_{vid}"
        is_voice = bool(re.search(r"^\s*voice\b", body, re.MULTILINE | re.IGNORECASE))
        vlans[vid] = {"id": vid, "name": vname, "svi_interface": "", "voice": is_voice, "description": ""}

    # 2. Juniper Junos `set vlans ...` and brace-style `vlans { ... }`
    junos_vnames: dict[str, dict] = {}

    def _ensure_junos_vlan(vname: str) -> dict:
        return junos_vnames.setdefault(
            vname,
            {"id": "", "name": vname, "svi_interface": "", "voice": False, "description": ""},
        )

    for m_vid in re.finditer(r"set\s+vlans\s+(\S+)\s+vlan-id\s+(\d+)", raw_config):
        vname = _strip_outer_quotes(m_vid.group(1))
        _ensure_junos_vlan(vname)["id"] = m_vid.group(2)

    for m_desc in re.finditer(r"set\s+vlans\s+(\S+)\s+description\s+([^\r\n]+)", raw_config):
        vname = _strip_outer_quotes(m_desc.group(1))
        _ensure_junos_vlan(vname)["description"] = _strip_outer_quotes(m_desc.group(2))

    for m_l3 in re.finditer(r"set\s+vlans\s+(\S+)\s+l3-interface\s+(\S+)", raw_config):
        vname = _strip_outer_quotes(m_l3.group(1))
        _ensure_junos_vlan(vname)["svi_interface"] = _strip_outer_quotes(m_l3.group(2))

    for vname, stanza in _extract_junos_brace_vlans(raw_config):
        entry = _ensure_junos_vlan(vname)
        m_vid = re.search(r"\bvlan-id\s+(\d+)\s*;", stanza)
        if m_vid:
            entry["id"] = m_vid.group(1)
        m_desc = re.search(r'\bdescription\s+((?:"[^"]*"|\'[^\']*\'|[^;\r\n]+))\s*;', stanza)
        if m_desc:
            entry["description"] = _strip_outer_quotes(m_desc.group(1))
        m_l3 = re.search(r"\bl3-interface\s+(\S+?)\s*;", stanza)
        if m_l3:
            entry["svi_interface"] = _strip_outer_quotes(m_l3.group(1))

    for vname, vinfo in junos_vnames.items():
        vid = vinfo.get("id") or ""
        if not vid:
            m_vn = re.match(r"^(?:vlan|vl)[_-]?(\d+)$", vname, re.IGNORECASE)
            m_irb = re.match(r"^(?:irb|vlan)\.(\d+)$", vinfo.get("svi_interface", ""), re.IGNORECASE)
            vid = m_vn.group(1) if m_vn else (m_irb.group(1) if m_irb else "")
        if vid:
            vinfo["id"] = vid
            vlans[vid] = vinfo

    # 3. OPNsense / pfSense XML `<vlans><vlan>`
    if "<vlans>" in raw_config:
        try:
            root = ET.fromstring(raw_config)
            for v_el in root.findall(".//vlans/vlan"):
                tag = (v_el.findtext("tag") or "").strip()
                if tag.isdigit() and 1 <= int(tag) <= 4094:
                    descr = (v_el.findtext("descr") or "").strip()
                    vlanif = (v_el.findtext("vlanif") or "").strip()
                    vlans[tag] = {
                        "id": tag,
                        "name": descr or vlanif or f"VLAN_{tag}",
                        "svi_interface": vlanif,
                        "voice": False,
                        "description": descr,
                    }
        except ET.ParseError:
            pass

    # 4. FortiOS `config system interface` VLAN subinterfaces (`set vlanid <id>`)
    if "set vlanid" in raw_config and "config system interface" in raw_config:
        m_if_sec = re.search(r"(?ms)^config system interface\s*\n(.*?)(?:\nend\s*$|\nend\s*\n)", raw_config)
        if m_if_sec:
            for m_edit in re.finditer(r'(?ms)^\s*edit\s+"?([^"\r\n]+)"?\s*\n(.*?)^\s*next\b', m_if_sec.group(1)):
                if_name, if_body = m_edit.group(1).strip(), m_edit.group(2)
                m_vid = re.search(r"^\s*set\s+vlanid\s+(\d+)", if_body, re.MULTILINE)
                if m_vid and 1 <= int(m_vid.group(1)) <= 4094:
                    vid = m_vid.group(1)
                    m_alias = re.search(r'^\s*set\s+alias\s+"?([^"\r\n]+)"?', if_body, re.MULTILINE)
                    vname = m_alias.group(1).strip() if m_alias else if_name
                    vlans[vid] = {
                        "id": vid,
                        "name": vname,
                        "svi_interface": if_name,
                        "voice": False,
                        "description": vname,
                    }

    # 5. MikroTik `/interface vlan`
    if "/interface vlan" in raw_config:
        m_mt = re.search(r"(?ms)^/interface\s+vlan\s*\n(.*?)(?:\n/|\Z)", raw_config)
        if m_mt:
            for ln in m_mt.group(1).splitlines():
                s = ln.strip()
                if not s.startswith("add ") or "disabled=yes" in s:
                    continue
                m_vid = re.search(r"\bvlan-id=(\d+)", s)
                m_nm = re.search(r'\bname=("[^"]+"|[^\s]+)', s)
                if m_vid and 1 <= int(m_vid.group(1)) <= 4094:
                    vid = m_vid.group(1)
                    vname = _strip_outer_quotes(m_nm.group(1)) if m_nm else f"VLAN_{vid}"
                    vlans[vid] = {
                        "id": vid,
                        "name": vname,
                        "svi_interface": vname,
                        "voice": False,
                        "description": "",
                    }

    # 6. OpenWrt UCI `bridge-vlan` / `switch_vlan`
    for m_ov in re.finditer(r"network\.@(?:bridge-vlan|switch_vlan)\[\d+\]\.vlan='(\d+)'", raw_config):
        vid = m_ov.group(1)
        if 1 <= int(vid) <= 4094 and vid not in vlans:
            vlans[vid] = {"id": vid, "name": f"VLAN_{vid}", "svi_interface": "", "voice": False, "description": ""}

    return vlans


def extract_vrfs_and_acls(raw_config: str, vendor: str = "") -> tuple[list[dict], dict[str, dict]]:
    """
    Extract VRF / routing-instance names (with RD & bound interfaces) and per-interface ACL bindings
    (`acl_in`, `acl_out`) from Cisco IOS/NX-OS/XR, Arista, HP ProCurve, Junos, FortiOS, and FRR configs.
    """
    vrfs: list[dict] = []
    acls: dict[str, dict] = {}
    if not raw_config:
        return vrfs, acls

    vrf_map: dict[str, dict] = {}

    def _ensure_vrf(name: str, vtype: str = "vrf") -> dict:
        clean = _strip_outer_quotes(name)
        return vrf_map.setdefault(clean, {"name": clean, "type": vtype, "rd": "", "interfaces": []})

    # Cisco IOS (`ip vrf`, `vrf definition`), NX-OS (`vrf context`), Arista (`vrf instance`), IOS-XR/FRR (`vrf <name>`)
    vrf_header_re = re.compile(
        r"(?m)^(?:ip\s+vrf|vrf\s+definition|vrf\s+context|vrf\s+instance|vrf)\s+([^\s{};]+)\s*$",
        re.IGNORECASE,
    )
    reserved_vrf_tokens = frozenset(
        {"forwarding", "member", "receive", "selection", "definition", "context", "instance"}
    )
    for m_vrf in vrf_header_re.finditer(raw_config):
        vname = m_vrf.group(1).strip()
        if not vname or vname.lower() in reserved_vrf_tokens:
            continue
        rec = _ensure_vrf(vname, "vrf")
        tail = raw_config[m_vrf.end() :]
        for ln in tail.splitlines():
            if not ln.strip():
                continue
            if ln[0] in (" ", "\t"):
                m_rd = re.match(r"^\s*rd\s+(\S+)", ln, re.IGNORECASE)
                if m_rd:
                    rec["rd"] = m_rd.group(1)
            else:
                break

    # Juniper Junos set-style `routing-instances`
    for m_ri in re.finditer(r"set\s+routing-instances\s+(\S+)\s+instance-type\s+(\S+)", raw_config):
        vname, rtype = m_ri.groups()
        _ensure_vrf(vname, rtype)
    for m_ri_rd in re.finditer(r"set\s+routing-instances\s+(\S+)\s+route-distinguisher\s+(\S+)", raw_config):
        _ensure_vrf(m_ri_rd.group(1))["rd"] = m_ri_rd.group(2)
    for m_ri_if in re.finditer(r"set\s+routing-instances\s+(\S+)\s+interface\s+(\S+)", raw_config):
        rec = _ensure_vrf(m_ri_if.group(1))
        if m_ri_if.group(2) not in rec["interfaces"]:
            rec["interfaces"].append(m_ri_if.group(2))

    # Juniper Junos brace-style `routing-instances { <name> { ... } }`
    for m_top in re.finditer(r"(?m)^\s*routing-instances\s*\{", raw_config):
        r_open = m_top.end() - 1
        r_close = _find_matching_brace(raw_config, r_open)
        if r_close == -1:
            continue
        r_body = raw_config[r_open + 1 : r_close]
        pos = 0
        while pos < len(r_body):
            m_child = re.search(r"([^\s{};]+)\s*\{", r_body[pos:])
            if not m_child:
                break
            vname = _strip_outer_quotes(m_child.group(1))
            c_open = pos + m_child.end() - 1
            c_close = _find_matching_brace(r_body, c_open)
            if c_close == -1:
                break
            stanza = r_body[c_open + 1 : c_close]
            m_rt = re.search(r"\binstance-type\s+([^\s;]+)\s*;", stanza)
            rec = _ensure_vrf(vname, m_rt.group(1) if m_rt else "vrf")
            m_rd = re.search(r"\broute-distinguisher\s+([^\s;]+)\s*;", stanza)
            if m_rd:
                rec["rd"] = m_rd.group(1)
            for m_rif in re.finditer(r"\binterface\s+([^\s;]+)\s*;", stanza):
                if m_rif.group(1) not in rec["interfaces"]:
                    rec["interfaces"].append(m_rif.group(1))
            pos = c_close + 1

    # FortiOS multi-VDOM (`config vdom\n edit <vdom_name>`)
    if "config vdom" in raw_config:
        for m_vd in re.finditer(r"(?ms)^config\s+vdom\s*\n(.*?)(?:\nend\s*$|\nend\s*\n)", raw_config):
            for m_ed in re.finditer(r'(?m)^\s*edit\s+"?([^"\r\n]+)"?', m_vd.group(1)):
                _ensure_vrf(m_ed.group(1).strip(), "vdom")

    # Interface -> VRF bindings & per-interface ACLs
    for m_jfilt in re.finditer(
        r"set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+(?:ethernet-switching|inet)\s+filter\s+(input|output)\s+(\S+)",
        raw_config,
    ):
        port, direction, fname = m_jfilt.groups()
        acls.setdefault(port, {"acl_in": "", "acl_out": ""})
        acls[port]["acl_in" if direction == "input" else "acl_out"] = fname

    for m_intf in re.finditer(r"(?m)^interface\s+(\S+)\s*\r?\n((?:[ \t]+[^\r\n]+\r?\n?)*)", raw_config):
        port, body = m_intf.group(1), m_intf.group(2)
        for m_ag in re.finditer(r"(?m)^\s*(?:ip|ipv6)\s+access-group\s+(\S+)\s+(in|out)\b", body, re.IGNORECASE):
            fname, direction = m_ag.group(1), m_ag.group(2).lower()
            acls.setdefault(port, {"acl_in": "", "acl_out": ""})
            acls[port]["acl_in" if direction == "in" else "acl_out"] = fname
        m_ivrf = re.search(
            r"(?m)^\s*(?:(?:ip\s+)?vrf\s+forwarding|vrf\s+member|vrf)\s+(\S+)",
            body,
            re.IGNORECASE,
        )
        if m_ivrf:
            vname = m_ivrf.group(1).strip()
            if vname.lower() not in reserved_vrf_tokens:
                rec = _ensure_vrf(vname, "vrf")
                if port not in rec["interfaces"]:
                    rec["interfaces"].append(port)

    vrfs = []
    for rec in vrf_map.values():
        entry: dict = {"name": rec["name"], "type": rec["type"]}
        if rec.get("rd"):
            entry["rd"] = rec["rd"]
        if rec.get("interfaces"):
            entry["interfaces"] = rec["interfaces"]
        vrfs.append(entry)
    return vrfs, acls

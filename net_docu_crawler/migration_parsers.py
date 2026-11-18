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


def extract_port_profiles(
    raw_config: str,
    vendor: str = "",
    poe: dict | None = None,
) -> dict[str, dict]:
    """
    Extract normalized per-port L2/L3 switching intent from raw_config and PoE data.
    Returns {port_name: {mode, access_vlan, voice_vlan, native_vlan,
                         trunk_allowed_vlans, lag_group, lacp_mode,
                         bpdu_guard, dot1x_mab, poe_watts}}.
    """
    profiles: dict[str, dict] = {}
    if not raw_config:
        return profiles

    def _ensure_port(port: str) -> dict:
        if port not in profiles:
            profiles[port] = {
                "mode": "unknown",
                "access_vlan": "",
                "voice_vlan": "",
                "native_vlan": "",
                "trunk_allowed_vlans": "",
                "lag_group": "",
                "lacp_mode": "",
                "bpdu_guard": False,
                "dot1x_mab": False,
                "poe_watts": 0.0,
            }
        return profiles[port]

    v_lower = (vendor or "").lower()

    # 1. Cisco IOS / Arista EOS / NX-OS interface blocks
    if any(k in v_lower for k in ("cisco", "arista")) and "interface " in raw_config:
        blocks = re.split(r"(?m)^interface\s+", raw_config)
        for blk in blocks[1:]:
            lines = blk.splitlines()
            if not lines:
                continue
            port = lines[0].strip()
            if port.lower().startswith(("vlan", "loopback", "null", "nve", "tunnel")):
                continue
            body = "\n".join(lines[1:])
            prof = _ensure_port(port)
            if re.search(r"^\s*no\s+switchport\b", body, re.MULTILINE):
                prof["mode"] = "routed"
            elif re.search(r"^\s*switchport\s+mode\s+trunk\b", body, re.MULTILINE):
                prof["mode"] = "trunk"
            elif re.search(r"^\s*switchport\s+mode\s+access\b", body, re.MULTILINE):
                prof["mode"] = "access"

            m_acc = re.search(r"^\s*switchport\s+access\s+vlan\s+(\d+)", body, re.MULTILINE)
            if m_acc:
                prof["access_vlan"] = m_acc.group(1)
                if prof["mode"] == "unknown":
                    prof["mode"] = "access"

            m_voice = re.search(r"^\s*switchport\s+voice\s+vlan\s+(\d+)", body, re.MULTILINE)
            if m_voice:
                prof["voice_vlan"] = m_voice.group(1)

            m_nat = re.search(r"^\s*switchport\s+trunk\s+native\s+vlan\s+(\d+)", body, re.MULTILINE)
            if m_nat:
                prof["native_vlan"] = m_nat.group(1)

            m_all = re.search(r"^\s*switchport\s+trunk\s+allowed\s+vlan\s+([^\r\n]+)", body, re.MULTILINE)
            if m_all:
                prof["trunk_allowed_vlans"] = m_all.group(1).strip()

            m_lag = re.search(r"^\s*channel-group\s+(\d+)\s+mode\s+(\S+)", body, re.MULTILINE)
            if m_lag:
                prof["lag_group"] = f"Po{m_lag.group(1)}"
                prof["lacp_mode"] = m_lag.group(2).lower()

            if re.search(r"spanning-tree\s+bpduguard\s+enable", body, re.IGNORECASE):
                prof["bpdu_guard"] = True
            if re.search(r"authentication\s+port-control|dot1x\s+pae|mab\b", body, re.IGNORECASE):
                prof["dot1x_mab"] = True

    # 2. HP ProCurve / ArubaOS-S VLAN & trunk blocks
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
            untag_v = hp_untagged.get(p, "")
            tag_list = hp_tagged.get(p, [])
            non_voice_tagged = [v for v in tag_list if v not in hp_voice_vlans]
            voice_tagged = [v for v in tag_list if v in hp_voice_vlans]
            if non_voice_tagged:
                prof["mode"] = "trunk"
                prof["native_vlan"] = untag_v or "none"
                prof["trunk_allowed_vlans"] = ",".join(tag_list)
            elif untag_v:
                prof["mode"] = "access"
                prof["access_vlan"] = untag_v
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

    # 3. Juniper Junos hierarchical / set-style interface VLANs & ae bundles
    if "juniper" in v_lower or "ethernet-switching" in raw_config:
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

        for m_set in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+interface-mode\s+(access|trunk)",
            junos_cfg,
        ):
            if m_set.group(1) == "interface-range":
                continue
            prof = _ensure_port(m_set.group(1))
            prof["mode"] = m_set.group(2)

        for m_nat in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+(?:unit\s+0\s+family\s+ethernet-switching\s+)?native-vlan-id\s+(\S+)",
            junos_cfg,
        ):
            if m_nat.group(1) == "interface-range":
                continue
            prof = _ensure_port(m_nat.group(1))
            prof["native_vlan"] = m_nat.group(2).strip('"')

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

        for p_data in profiles.values():
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
            if prof["mode"] == "trunk" or len(members) > 1 or "all" in members:
                if prof["mode"] == "unknown":
                    prof["mode"] = "trunk"
                prof["trunk_allowed_vlans"] = ",".join(members)
                if not prof["native_vlan"]:
                    prof["native_vlan"] = "none"
            else:
                if prof["mode"] == "unknown":
                    prof["mode"] = "access"
                prof["access_vlan"] = members[0]

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
        for m_storm in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+storm-control\b", junos_cfg
        ):
            if m_storm.group(1) == "interface-range":
                continue
            prof = _ensure_port(m_storm.group(1))
            prof["storm_control"] = True
            if prof["mode"] == "unknown":
                prof["mode"] = "access"
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

    # HSRP & VRRP on Cisco / Arista interfaces
    for blk in re.split(r"(?m)^interface\s+", raw_config)[1:]:
        lines = blk.splitlines()
        if not lines:
            continue
        intf = lines[0].strip()
        body = "\n".join(lines[1:])
        for m_hsrp in re.finditer(r"^\s*standby\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
            grp, vip = m_hsrp.groups()
            m_pri = re.search(rf"^\s*standby\s+{grp}\s+priority\s+(\d+)", body, re.MULTILINE)
            fhrp.append(
                {
                    "protocol": "hsrp",
                    "group": grp,
                    "interface": intf,
                    "vip": vip,
                    "priority": int(m_pri.group(1)) if m_pri else 100,
                    "state": "Configured",
                }
            )
        for m_vrrp in re.finditer(r"^\s*vrrp\s+(\d+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
            grp, vip = m_vrrp.groups()
            m_pri = re.search(rf"^\s*vrrp\s+{grp}\s+priority\s+(\d+)", body, re.MULTILINE)
            fhrp.append(
                {
                    "protocol": "vrrp",
                    "group": grp,
                    "interface": intf,
                    "vip": vip,
                    "priority": int(m_pri.group(1)) if m_pri else 100,
                    "state": "Configured",
                }
            )

    # OPNsense CARP VIPs in config.xml
    if "<virtualip>" in raw_config:
        try:
            root = ET.fromstring(raw_config)
            for vip_el in root.findall(".//virtualip/vip"):
                mode = (vip_el.findtext("mode") or "").lower()
                if mode in ("carp", "ipalias"):
                    fhrp.append(
                        {
                            "protocol": mode,
                            "group": vip_el.findtext("vhid") or "",
                            "interface": vip_el.findtext("interface") or "",
                            "vip": vip_el.findtext("subnet") or "",
                            "priority": int(vip_el.findtext("advskew") or 0),
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
        for m_hlp in re.finditer(r"^\s*ip\s+helper-address\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
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

    # Juniper Junos forwarding-options dhcp-relay
    if "dhcp-relay" in raw_config or "helpers bootp" in raw_config:
        sg_ips: dict[str, list[str]] = {}
        grp_sg: dict[str, str] = {}
        grp_intfs: dict[str, list[str]] = {}
        for m_sg in re.finditer(
            r"set\s+forwarding-options\s+dhcp-relay\s+server-group\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)", raw_config
        ):
            sg_ips.setdefault(m_sg.group(1), []).append(m_sg.group(2))
        for m_asg in re.finditer(
            r"set\s+forwarding-options\s+dhcp-relay\s+group\s+(\S+)\s+active-server-group\s+(\S+)", raw_config
        ):
            grp_sg[m_asg.group(1)] = m_asg.group(2)
        for m_gi in re.finditer(
            r"set\s+forwarding-options\s+dhcp-relay\s+group\s+(\S+)\s+interface\s+(\S+)", raw_config
        ):
            grp_intfs.setdefault(m_gi.group(1), []).append(m_gi.group(2))
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

    # 2. OPNsense config.xml <dhcpd>
    if "<dhcpd>" in raw_config:
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

    # FortiOS firewall policies
    if "config firewall policy" in raw_config:
        for m_pol in re.finditer(r"edit\s+(\d+)(.*?)next", raw_config, re.DOTALL):
            body = m_pol.group(2)
            if "set srcintf" not in body:
                continue
            srcintf = re.search(r'set\s+srcintf\s+"([^"]+)"', body)
            dstintf = re.search(r'set\s+dstintf\s+"([^"]+)"', body)
            action = re.search(r"set\s+action\s+(\S+)", body)
            out["firewall_rules"].append(
                {
                    "action": action.group(1) if action else "deny",
                    "interface": f"{srcintf.group(1) if srcintf else ''}->{dstintf.group(1) if dstintf else ''}",
                    "protocol": "any",
                    "src": "policy",
                    "dst": "policy",
                    "dst_port": "any",
                    "descr": f"policy-{m_pol.group(1)}",
                }
            )

    return out


def extract_vlans(raw_config: str, vendor: str = "") -> dict[str, dict]:
    """
    Extract configured VLANs {vlan_id: {"id", "name", "svi_interface", "voice"}}
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
        vlans[vid] = {"id": vid, "name": vname, "svi_interface": "", "voice": is_voice}

    # 2. Juniper Junos `set vlans <vname> vlan-id <id>` & `l3-interface irb.<unit>`
    junos_vnames: dict[str, dict] = {}
    for m_vid in re.finditer(r"set\s+vlans\s+(\S+)\s+vlan-id\s+(\d+)", raw_config):
        vname, vid = m_vid.group(1), m_vid.group(2)
        junos_vnames.setdefault(vname, {"id": vid, "name": vname, "svi_interface": "", "voice": False})
        junos_vnames[vname]["id"] = vid
    for m_l3 in re.finditer(r"set\s+vlans\s+(\S+)\s+l3-interface\s+(\S+)", raw_config):
        vname, l3_if = m_l3.group(1), m_l3.group(2)
        if vname in junos_vnames:
            junos_vnames[vname]["svi_interface"] = l3_if
        else:
            m_irb = re.match(r"^irb\.(\d+)$", l3_if, re.IGNORECASE)
            m_vn = re.match(r"^(?:vlan|vl)[_-]?(\d+)$", vname, re.IGNORECASE)
            vid = m_vn.group(1) if m_vn else (m_irb.group(1) if m_irb else "")
            if vid:
                junos_vnames[vname] = {"id": vid, "name": vname, "svi_interface": l3_if, "voice": False}
    for vinfo in junos_vnames.values():
        vlans[vinfo["id"]] = vinfo

    return vlans


def extract_vrfs_and_acls(raw_config: str, vendor: str = "") -> tuple[list[dict], dict[str, dict]]:
    """
    Extract VRF / routing-instance names and per-interface ACL bindings
    (`acl_in`, `acl_out`) from Cisco, Arista, HP ProCurve, and Junos configs.
    """
    vrfs: list[dict] = []
    acls: dict[str, dict] = {}
    if not raw_config:
        return vrfs, acls

    seen_vrfs: set[str] = set()
    for m_vrf in re.finditer(r"(?m)^(?:ip\s+vrf|vrf\s+definition)\s+(\S+)", raw_config):
        vname = m_vrf.group(1)
        if vname not in seen_vrfs:
            seen_vrfs.add(vname)
            vrfs.append({"name": vname, "type": "vrf"})
    for m_ri in re.finditer(r"set\s+routing-instances\s+(\S+)\s+instance-type\s+(\S+)", raw_config):
        vname, rtype = m_ri.groups()
        if vname not in seen_vrfs:
            seen_vrfs.add(vname)
            vrfs.append({"name": vname, "type": rtype})

    for m_jfilt in re.finditer(
        r"set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+(?:ethernet-switching|inet)\s+filter\s+(input|output)\s+(\S+)",
        raw_config,
    ):
        port, direction, fname = m_jfilt.groups()
        acls.setdefault(port, {"acl_in": "", "acl_out": ""})
        acls[port]["acl_in" if direction == "input" else "acl_out"] = fname

    for m_intf in re.finditer(r"(?m)^interface\s+(\S+)\s*\r?\n((?:[ \t]+[^\r\n]+\r?\n)*)", raw_config):
        port, body = m_intf.group(1), m_intf.group(2)
        for m_ag in re.finditer(r"(?m)^\s*(?:ip|ipv6)\s+access-group\s+(\S+)\s+(in|out)\b", body, re.IGNORECASE):
            fname, direction = m_ag.group(1), m_ag.group(2).lower()
            acls.setdefault(port, {"acl_in": "", "acl_out": ""})
            acls[port]["acl_in" if direction == "in" else "acl_out"] = fname

    return vrfs, acls

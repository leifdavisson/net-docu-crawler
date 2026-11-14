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
    if any(k in v_lower for k in ("cisco", "arista", "")) and "interface " in raw_config:
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
    if "procurve" in v_lower or "vlan " in raw_config:
        for m_trk in re.finditer(r"(?m)^trunk\s+(\S+)\s+(Trk\d+)\s*(lacp|trunk)?", raw_config, re.IGNORECASE):
            ports_spec, trk_name, mode_tok = m_trk.groups()
            for p in _expand_port_range(ports_spec):
                prof = _ensure_port(p)
                prof["lag_group"] = trk_name
                prof["lacp_mode"] = (mode_tok or "lacp").lower()

        vlan_blocks = re.split(r"(?m)^vlan\s+(\d+)\b", raw_config)
        for idx in range(1, len(vlan_blocks) - 1, 2):
            vid = vlan_blocks[idx]
            body = vlan_blocks[idx + 1].split("\nexit")[0]
            for m_untag in re.finditer(r"^\s*untagged\s+([^\r\n]+)", body, re.MULTILINE):
                for p in _expand_port_range(m_untag.group(1).strip()):
                    prof = _ensure_port(p)
                    prof["access_vlan"] = vid
                    if prof["mode"] == "unknown":
                        prof["mode"] = "access"
            for m_tag in re.finditer(r"^\s*tagged\s+([^\r\n]+)", body, re.MULTILINE):
                for p in _expand_port_range(m_tag.group(1).strip()):
                    prof = _ensure_port(p)
                    prof["mode"] = "trunk"
                    existing = [v for v in prof["trunk_allowed_vlans"].split(",") if v]
                    if vid not in existing:
                        existing.append(vid)
                    prof["trunk_allowed_vlans"] = ",".join(existing)

    # 3. Juniper Junos hierarchical / set-style interface VLANs & ae bundles
    if "juniper" in v_lower or "ethernet-switching" in raw_config:
        for m_set in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+interface-mode\s+(access|trunk)",
            raw_config,
        ):
            prof = _ensure_port(m_set.group(1))
            prof["mode"] = m_set.group(2)
        for m_v in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+unit\s+0\s+family\s+ethernet-switching\s+vlan\s+members\s+(\S+)",
            raw_config,
        ):
            prof = _ensure_port(m_v.group(1))
            val = m_v.group(2).strip("[]")
            if prof["mode"] == "trunk":
                existing = [v for v in prof["trunk_allowed_vlans"].split(",") if v]
                if val not in existing:
                    existing.append(val)
                prof["trunk_allowed_vlans"] = ",".join(existing)
            else:
                prof["access_vlan"] = val
        for m_ae in re.finditer(
            r"set\s+interfaces\s+(\S+)\s+ether-options\s+802\.3ad\s+(ae\d+)",
            raw_config,
        ):
            prof = _ensure_port(m_ae.group(1))
            prof["lag_group"] = m_ae.group(2)
            prof["lacp_mode"] = "active"

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

    for blk in re.split(r"(?m)^interface\s+", raw_config)[1:]:
        lines = blk.splitlines()
        if not lines:
            continue
        intf = lines[0].strip()
        body = "\n".join(lines[1:])
        for m_hlp in re.finditer(r"^\s*ip\s+helper-address\s+(\d+\.\d+\.\d+\.\d+)", body, re.MULTILINE):
            result["relays"].append({"interface": intf, "helper_ip": m_hlp.group(1)})

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

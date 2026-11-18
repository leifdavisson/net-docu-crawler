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
Authoritative Correlation Engine for Net-Docu-Crawler (Phase 4).
Produces:
  1. Unified per-port records (`device_data["ports"]`) with hygiene dispositions
  2. Campus-wide STP root consensus (`is_verified_campus_root` vs `isolated_self_root`)
  3. Site- and device-scoped L3 SVI / VLAN / DHCP-relay join table (`build_l3_svi_table`)
"""

import ipaddress
import re

from net_docu_crawler.schema import build_empty_port_record, normalize_tri_state, stamp_schema_v2
from net_docu_crawler.topology_resolver import normalize_interface

_INFRA_NEIGHBOR_TYPES = frozenset({"switch", "router", "firewall", "wlc", "bridge"})


def correlate_device_ports(dev: dict) -> dict[str, dict]:
    """
    Join `interfaces_detail`, `port_profiles`, `poe["ports"]`, `optics`,
    `neighbors`, `mac_table`, and `vlans` into `dev["ports"]`.
    """
    hostname = dev.get("hostname") or dev.get("ip", "")
    ints_detail = dev.get("interfaces_detail", {}) or {}
    port_profiles = dev.get("port_profiles", {}) or {}
    poe_dict = dev.get("poe")
    if isinstance(poe_dict, dict):
        model_l = str(dev.get("model") or "").lower()
        if (
            poe_dict.get("poe_supported") is None
            and float(poe_dict.get("total_power_watts") or 0.0) == 0.0
            and float(poe_dict.get("used_power_watts") or 0.0) == 0.0
            and not (poe_dict.get("ports") or {})
            and model_l.startswith(("ex4600", "ex4650", "ex9200", "qfx", "ex4500", "ex4550"))
        ):
            poe_dict["poe_supported"] = False
    poe_ports = (poe_dict or {}).get("ports", {}) or {}
    optics_by_port = {normalize_interface(o.get("port", "")): o for o in (dev.get("optics") or []) if o.get("port")}
    neighbors_by_port = {
        normalize_interface(n.get("local_port", "")): n for n in (dev.get("neighbors") or []) if n.get("local_port")
    }
    vlans_map = dev.get("vlans", {}) or {}
    norm_profiles = {normalize_interface(k): v for k, v in port_profiles.items()}

    # Count MACs per normalized port
    mac_counts: dict[str, int] = {}
    for m in dev.get("mac_table", []) or []:
        p = normalize_interface(m.get("interface") or m.get("port") or "")
        if p:
            mac_counts[p] = mac_counts.get(p, 0) + 1

    ports: dict[str, dict] = {}
    for port_name, stats in ints_detail.items():
        if str(port_name).strip().lower() in ("irb", "vlan", "lo", "lo0"):
            continue
        norm_p = normalize_interface(port_name)
        rec = build_empty_port_record(hostname=hostname, interface=port_name, normalized_interface=norm_p)
        prof = port_profiles.get(port_name) or norm_profiles.get(norm_p) or {}

        rec["admin_state"] = str(stats.get("admin_status") or "unknown").lower()
        rec["oper_state"] = str(stats.get("status") or "unknown").lower()
        rec["description"] = stats.get("description") or ""
        rec["speed_operational"] = stats.get("speed") or ""
        rec["duplex"] = stats.get("duplex") or ""
        rec["mtu"] = stats.get("mtu")

        if prof:
            rec["mode"] = prof.get("mode") or "unknown"
            rec["access_vlan"] = str(prof.get("access_vlan") or "")
            rec["voice_vlan"] = str(prof.get("voice_vlan") or "")
            nat = str(prof.get("native_vlan") or "").strip()
            rec["native_vlan"] = nat if nat else "unknown"
            raw_allowed = str(prof.get("trunk_allowed_vlans") or "").strip()
            rec["allowed_vlans_raw"] = raw_allowed
            if raw_allowed.lower() == "all" and vlans_map:
                rec["allowed_vlans"] = sorted(vlans_map.keys(), key=lambda x: int(x) if x.isdigit() else 99999)
            elif raw_allowed:
                rec["allowed_vlans"] = [v.strip() for v in raw_allowed.split(",") if v.strip()]
            rec["lag_id"] = prof.get("lag_group") or "none"
            rec["lacp_mode"] = prof.get("lacp_mode") or "none"
            rec["stp_edge"] = normalize_tri_state(prof.get("stp_edge"))
            rec["bpdu_guard"] = normalize_tri_state(prof.get("bpdu_guard"))
            rec["storm_control"] = normalize_tri_state(prof.get("storm_control"))
            if prof.get("stp_role"):
                rec["stp_role"] = prof["stp_role"]
            if prof.get("stp_state"):
                rec["stp_state"] = prof["stp_state"]
            rec["auth_policy"] = prof.get("auth_policy") or ("dot1x+mab" if prof.get("dot1x_mab") else "unknown")
            if prof.get("acl_in"):
                rec["acl_in"] = prof["acl_in"]
            if prof.get("acl_out"):
                rec["acl_out"] = prof["acl_out"]

        poe_p = poe_ports.get(port_name) or poe_ports.get(norm_p)
        if poe_p:
            rec["poe_state"] = str(poe_p.get("status") or "unknown").lower()
            rec["poe_draw_watts"] = float(poe_p.get("draw_watts", poe_p.get("power_watts", poe_p.get("watts", 0.0))) or 0.0)
            rec["poe_allocated_watts"] = float(poe_p.get("allocated_watts", 0.0) or 0.0)
            rec["poe_class"] = str(poe_p.get("class") or "")

        opt = optics_by_port.get(norm_p)
        if opt:
            rec["media"] = opt.get("type") or ""
            rec["optic_part_number"] = opt.get("part_number") or ""
            rec["rx_power_dbm"] = opt.get("rx_power_dbm")
            rec["tx_power_dbm"] = opt.get("tx_power_dbm")
        elif "10g" in rec["speed_operational"].lower():
            rec["media"] = "10GBASE-CX / SFP+ (Unmonitored)"
        elif rec["oper_state"] == "up":
            rec["media"] = "1000BASE-T (RJ45)"

        nbr = neighbors_by_port.get(norm_p)
        if nbr:
            rec["neighbor_hostname"] = nbr.get("remote_device") or ""
            rec["neighbor_port"] = nbr.get("remote_port") or ""
            rec["neighbor_ip"] = nbr.get("remote_ip") or ""
            rec["neighbor_type"] = (nbr.get("device_type") or "").lower()
            rec["link_confidence"] = nbr.get("link_confidence") or "one-way"

        m_cnt = mac_counts.get(norm_p, 0)
        is_infra_uplink = rec["mode"] == "trunk" or rec["neighbor_type"] in _INFRA_NEIGHBOR_TYPES
        if is_infra_uplink:
            rec["trunk_mac_count"] = m_cnt
        else:
            rec["edge_mac_count"] = m_cnt

        # Port hygiene disposition
        if rec["oper_state"] == "err-disabled":
            rec["hygiene_disposition"] = "QUARANTINE"
            rec["hygiene_reason"] = "Port is err-disabled"
        elif is_infra_uplink or (rec["lag_id"] not in ("", "none", "unknown")):
            rec["hygiene_disposition"] = "DO_NOT_MOVE"
            rec["hygiene_reason"] = "Infrastructure uplink / trunk / LAG member"
        elif rec["oper_state"] == "up" or rec["poe_draw_watts"] > 0 or rec["edge_mac_count"] > 0 or nbr:
            rec["hygiene_disposition"] = "MIGRATE"
            rec["hygiene_reason"] = "Active link / PoE / MAC / LLDP endpoint"
        elif rec["admin_state"] == "down":
            rec["hygiene_disposition"] = "SHUTDOWN"
            rec["hygiene_reason"] = "Administratively disabled"
        elif rec["description"] or rec["last_flapped"] not in ("", "unknown", "Never"):
            rec["hygiene_disposition"] = "REVIEW"
            rec["hygiene_reason"] = "Down port with operator description or flap history"
        else:
            rec["hygiene_disposition"] = "SHUTDOWN"
            rec["hygiene_reason"] = "Unused down port (no link, no MAC, no PoE, no neighbor)"

        ports[port_name] = rec

    dev["ports"] = ports
    return ports


def compute_stp_root_consensus(raw_devices: list[dict]) -> None:
    """
    Distinguish true campus STP root bridges (`is_verified_campus_root=True`,
    corroborated by >=1 other switch) from isolated self-roots (`isolated_self_root`).
    """
    root_claims: dict[str, int] = {}
    for dev in raw_devices:
        if dev.get("status", "success") != "success":
            continue
        stp = dev.get("stp") or {}
        rb = str(stp.get("root_bridge") or "").strip().lower()
        if rb:
            root_claims[rb] = root_claims.get(rb, 0) + 1

    for dev in raw_devices:
        stp = dev.get("stp")
        if not isinstance(stp, dict):
            continue
        rb = str(stp.get("root_bridge") or "").strip().lower()
        is_root = bool(stp.get("is_root", False))
        if is_root and rb and root_claims.get(rb, 0) >= 2:
            stp["is_verified_campus_root"] = True
            stp["root_scope"] = "campus_root"
        elif is_root and rb:
            stp["is_verified_campus_root"] = False
            stp["root_scope"] = "isolated_self_root"
        elif is_root:
            stp["is_verified_campus_root"] = False
            stp["root_scope"] = "unverified_missing_bridge_id"
        else:
            stp["is_verified_campus_root"] = False
            stp["root_scope"] = "non_root" if stp.get("enabled") else "disabled_or_unknown"


def build_l3_svi_table(raw_devices: list[dict]) -> list[dict]:
    """
    Build a site- and device-scoped L3 SVI / VLAN / DHCP-relay join table
    using exact VLAN ID matching (never substring `vid in iname`).
    """
    rows: list[dict] = []
    for dev in raw_devices:
        if dev.get("record_class") != "crawled_infra" and dev.get("status", "success") != "success":
            continue
        hostname = dev.get("hostname") or dev.get("ip", "")
        site_code = dev.get("site_code") or ""
        vlans_map = dev.get("vlans", {}) or {}
        relays = (dev.get("dhcp") or {}).get("relays", []) or []
        by_svi = {
            v.get("svi_interface", "").lower(): (vid, str(v.get("name", "")).strip('"'))
            for vid, v in vlans_map.items()
            if v.get("svi_interface")
        }
        by_name = {
            str(v.get("name", "")).strip('"').lower(): (vid, str(v.get("name", "")).strip('"'))
            for vid, v in vlans_map.items()
            if v.get("name")
        }

        for intf in dev.get("l3_interfaces", []) or []:
            iname = str(intf.get("interface") or "").strip()
            ip_str = str(intf.get("ip_address") or "").strip()
            if not iname or not ip_str or ip_str in ("unassigned", "down", "up", "unset"):
                continue
            try:
                net = ipaddress.IPv4Interface(ip_str.replace(" ", "/")).network
                prefix_cidr = str(net)
            except ValueError:
                prefix_cidr = ""

            m_vid = re.match(r"^(?:vlan\.?|vl|irb\.)0*(\d+)$", iname, re.IGNORECASE)
            if m_vid:
                vid = m_vid.group(1)
                vname = str(vlans_map.get(vid, {}).get("name", "")).strip('"')
            elif iname.lower() in by_svi:
                vid, vname = by_svi[iname.lower()]
            elif iname.lower() in by_name:
                vid, vname = by_name[iname.lower()]
            elif iname.upper() == "DEFAULT_VLAN" and "1" in vlans_map:
                vid = "1"
                vname = str(vlans_map["1"].get("name", "DEFAULT_VLAN")).strip('"')
            else:
                vid, vname = "", ""

            matched_relays = sorted(
                {
                    r.get("helper_ip", "")
                    for r in relays
                    if r.get("helper_ip")
                    and (
                        r.get("interface", "").lower() == iname.lower()
                        or (vid and r.get("interface", "").lower() in (f"vlan {vid}", f"vlan{vid}", f"irb.{vid}"))
                    )
                }
            )

            rows.append(
                {
                    "site_code": site_code,
                    "source_device": hostname,
                    "vlan_id": vid,
                    "vlan_name": vname,
                    "svi_interface": iname,
                    "primary_ip": ip_str,
                    "prefix_cidr": prefix_cidr,
                    "dhcp_relays": matched_relays,
                    "confidence": "direct",
                }
            )
    return rows


def correlate_dataset(raw_devices: list[dict]) -> dict:
    """Run all Phase 4 correlation passes across `raw_devices`."""
    for dev in raw_devices:
        stamp_schema_v2(dev)
        if dev.get("status", "success") == "success":
            correlate_device_ports(dev)
    compute_stp_root_consensus(raw_devices)
    return {"l3_svi_table": build_l3_svi_table(raw_devices)}

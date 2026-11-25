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

import re

from netaddr import AddrFormatError, IPAddress, IPNetwork

from net_docu_crawler.schema import build_empty_port_record, normalize_tri_state, stamp_schema_v2
from net_docu_crawler.topology_resolver import (
    extract_vlan_id_from_interface,
    infer_interface_speed,
    normalize_interface,
    normalize_interface_key,
    normalize_stp_bridge_id,
)

_INFRA_NEIGHBOR_TYPES = frozenset({"switch", "router", "firewall", "wlc", "bridge"})
_INFERRED_L2_ACCURACIES = frozenset(
    {"mac_inferred", "l3_next_hop_egress", "wan_carrier_arp_route", "virtual_passthrough", "multi_neighbor_port"}
)
_VIRTUAL_IFACE_RE = re.compile(
    r"^(?:vtnet|veth|br[-.\d]|docker|virbr|tun|tap|wg|gre|st\d|vlan|irb|bvi|lo\d*$)",
    re.IGNORECASE,
)
_LAG_IFACE_RE = re.compile(r"^(?:po|port-channel|ae|be|bundle-ether|lag|trk|reth)\d", re.IGNORECASE)


def _neighbor_priority(nbr: dict) -> int:
    """Rank neighbor candidates on a shared port so direct infra uplinks beat MAC-inferred/endpoint entries."""
    is_direct = (
        str(nbr.get("link_confidence") or "").upper() != "INFERRED"
        and str(nbr.get("l2_accuracy") or "").strip().lower() not in _INFERRED_L2_ACCURACIES
    )
    is_infra = str(nbr.get("device_type") or "").strip().lower() in _INFRA_NEIGHBOR_TYPES
    if is_direct and is_infra:
        return 3
    if is_direct:
        return 2
    if is_infra:
        return 1
    return 0


def _infer_non_optic_media(port_name: str, speed_operational: str, oper_state: str) -> str:
    """Infer truthful link media label when DOM optical telemetry is absent."""
    p_clean = str(port_name or "").strip()
    if _VIRTUAL_IFACE_RE.match(p_clean):
        return "Virtual"
    if _LAG_IFACE_RE.match(p_clean):
        return "LAG / Logical"
    if not speed_operational and oper_state != "up":
        return ""
    mbps, _ = infer_interface_speed(speed_operational, p_clean)
    if mbps >= 100000:
        return "100GBASE / QSFP28 (Unmonitored)"
    if mbps >= 40000:
        return "40GBASE / QSFP+ (Unmonitored)"
    if mbps >= 25000:
        return "25GBASE / SFP28 (Unmonitored)"
    if mbps >= 10000:
        return "10GBASE-CX / SFP+ (Unmonitored)"
    if mbps >= 5000:
        return "5GBASE-T (RJ45)"
    if mbps >= 2500:
        return "2.5GBASE-T (RJ45)"
    if oper_state != "up":
        return ""
    if mbps == 100:
        return "100BASE-TX (RJ45)"
    if mbps == 10:
        return "10BASE-T (RJ45)"
    return "1000BASE-T (RJ45)"


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
    poe_ports_ci = {normalize_interface_key(k): v for k, v in poe_ports.items() if k}
    optics_by_port = {normalize_interface_key(o.get("port", "")): o for o in (dev.get("optics") or []) if o.get("port")}
    neighbors_by_port: dict[str, dict] = {}
    for n in dev.get("neighbors") or []:
        if not isinstance(n, dict) or not n.get("local_port"):
            continue
        nk = normalize_interface_key(n.get("local_port", ""))
        if not nk:
            continue
        prev = neighbors_by_port.get(nk)
        if prev is None or _neighbor_priority(n) > _neighbor_priority(prev):
            neighbors_by_port[nk] = n
    vlans_map = dev.get("vlans", {}) or {}
    norm_profiles = {normalize_interface_key(k): v for k, v in port_profiles.items() if k}

    # Count MACs per canonical lowercase port key
    mac_counts: dict[str, int] = {}
    for m in dev.get("mac_table", []) or []:
        pk = normalize_interface_key(m.get("interface") or m.get("port") or "")
        if pk:
            mac_counts[pk] = mac_counts.get(pk, 0) + 1

    ports: dict[str, dict] = {}
    for port_name, stats in ints_detail.items():
        if str(port_name).strip().lower() in ("irb", "vlan", "lo", "lo0"):
            continue
        norm_p = normalize_interface(port_name)
        norm_k = normalize_interface_key(port_name)
        rec = build_empty_port_record(hostname=hostname, interface=port_name, normalized_interface=norm_p)
        prof = port_profiles.get(port_name) or norm_profiles.get(norm_k) or {}

        rec["admin_state"] = str(stats.get("admin_status") or "unknown").lower()
        rec["oper_state"] = str(stats.get("status") or "unknown").lower()
        rec["description"] = stats.get("description") or ""
        rec["speed_operational"] = stats.get("speed") or ""
        rec["duplex"] = stats.get("duplex") or ""
        rec["mtu"] = stats.get("mtu")
        rec["admin_mode"] = "unknown"
        rec["oper_mode"] = ""
        rec["native_vlan_tagged"] = False
        rec["trunk_active_vlans"] = ""
        rec["encapsulation"] = "dot1q"
        rec["qinq_tunnel"] = False
        rec["is_subinterface_bundle"] = False

        if prof:
            rec["mode"] = prof.get("mode") or "unknown"
            rec["admin_mode"] = str(prof.get("admin_mode") or rec["mode"])
            rec["oper_mode"] = str(prof.get("oper_mode") or "")
            rec["native_vlan_tagged"] = bool(prof.get("native_vlan_tagged", False))
            raw_active = prof.get("trunk_active_vlans")
            if isinstance(raw_active, (list, set, tuple)):
                rec["trunk_active_vlans"] = ",".join(str(v).strip() for v in raw_active if str(v).strip())
            else:
                rec["trunk_active_vlans"] = str(raw_active or "").strip()
            rec["encapsulation"] = str(prof.get("encapsulation") or "dot1q").strip()
            rec["qinq_tunnel"] = bool(prof.get("qinq_tunnel", False))
            rec["is_subinterface_bundle"] = bool(prof.get("is_subinterface_bundle", False))
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

        poe_p = poe_ports.get(port_name) or poe_ports.get(norm_p) or poe_ports_ci.get(norm_k)
        if poe_p:
            rec["poe_state"] = str(poe_p.get("status") or "unknown").lower()
            rec["poe_draw_watts"] = float(
                poe_p.get("draw_watts", poe_p.get("power_watts", poe_p.get("watts", 0.0))) or 0.0
            )
            rec["poe_allocated_watts"] = float(poe_p.get("allocated_watts", 0.0) or 0.0)
            rec["poe_class"] = str(poe_p.get("class") or "")

        opt = optics_by_port.get(norm_k)
        if opt:
            rec["media"] = opt.get("type") or ""
            rec["optic_part_number"] = opt.get("part_number") or ""
            rec["rx_power_dbm"] = opt.get("rx_power_dbm")
            rec["tx_power_dbm"] = opt.get("tx_power_dbm")
        else:
            rec["media"] = _infer_non_optic_media(port_name, rec["speed_operational"], rec["oper_state"])

        nbr = neighbors_by_port.get(norm_k)
        if nbr:
            rec["neighbor_hostname"] = nbr.get("remote_device") or ""
            rec["neighbor_port"] = nbr.get("remote_port") or ""
            rec["neighbor_ip"] = nbr.get("remote_ip") or ""
            rec["neighbor_type"] = (nbr.get("device_type") or "").lower()
            rec["link_confidence"] = nbr.get("link_confidence") or "one-way"

        m_cnt = mac_counts.get(norm_k, 0)
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
    Normalizes bridge-ID MAC notation across Cisco dotted and Juniper/Arista colon formats.
    """
    root_claims: dict[str, int] = {}
    for dev in raw_devices:
        if dev.get("status", "success") != "success":
            continue
        stp = dev.get("stp") or {}
        rb = normalize_stp_bridge_id(str(stp.get("root_bridge") or ""))
        if rb:
            root_claims[rb] = root_claims.get(rb, 0) + 1

    for dev in raw_devices:
        stp = dev.get("stp")
        if not isinstance(stp, dict):
            continue
        rb = normalize_stp_bridge_id(str(stp.get("root_bridge") or ""))
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
    Build a site- and device-scoped L3 SVI / VLAN / DHCP-relay join table using `netaddr`
    and multi-vendor SVI/subinterface VLAN ID extraction (exact `by_svi` priority, rejecting VLAN 0).
    """
    rows: list[dict] = []
    for dev in raw_devices:
        if dev.get("record_class") != "crawled_infra" and dev.get("status", "success") != "success":
            continue
        hostname = dev.get("hostname") or dev.get("ip", "")
        site_code = dev.get("site_code") or ""
        vlans_map = dev.get("vlans", {}) or {}
        ints_detail = dev.get("interfaces_detail", {}) or {}
        relays = (dev.get("dhcp") or {}).get("relays", []) or []
        by_svi: dict[str, tuple[str, str, str]] = {}
        for vid, v in vlans_map.items():
            if isinstance(v, dict) and v.get("svi_interface"):
                svi_raw = str(v["svi_interface"]).strip()
                meta = (
                    str(vid),
                    str(v.get("name", "")).strip('"'),
                    str(v.get("description", "")).strip('"'),
                )
                by_svi[svi_raw.lower()] = meta
                by_svi[normalize_interface_key(svi_raw)] = meta
        by_name = {
            str(v.get("name", "")).strip('"').lower(): (
                str(vid),
                str(v.get("name", "")).strip('"'),
                str(v.get("description", "")).strip('"'),
            )
            for vid, v in vlans_map.items()
            if isinstance(v, dict) and v.get("name")
        }

        for intf in dev.get("l3_interfaces", []) or []:
            iname = str(intf.get("interface") or "").strip()
            ip_str = str(intf.get("ip_address") or "").strip()
            if not iname or not ip_str or ip_str.lower() in ("unassigned", "down", "up", "unset", "n/a"):
                continue
            collapsed = re.sub(r"\s+", " ", ip_str)
            mask_known = ("/" in collapsed) or (" " in collapsed)
            try:
                ip_part = collapsed.split("/", 1)[0].split(" ", 1)[0]
                ip_obj = IPAddress(ip_part)
                ip_s = str(ip_obj)
                if ip_obj.is_loopback() or ip_s in ("0.0.0.0", "::", "::1") or ip_s.startswith(("127.", "128.0.")):
                    continue
                if mask_known:
                    net = IPNetwork(collapsed.replace(" ", "/"))
                    prefix_cidr = f"{net.network}/{net.prefixlen}"
                else:
                    prefix_cidr = ""
            except (AddrFormatError, ValueError):
                prefix_cidr = ""

            iname_l = iname.lower()
            iname_k = normalize_interface_key(iname)
            if iname_l in by_svi or iname_k in by_svi:
                vid, vname, vdesc = by_svi.get(iname_l) or by_svi[iname_k]
            else:
                extracted_vid = extract_vlan_id_from_interface(iname, intf_meta=intf, interfaces_detail=ints_detail)
                if extracted_vid:
                    vid = extracted_vid
                    vinfo = vlans_map.get(vid, {}) if isinstance(vlans_map.get(vid), dict) else {}
                    vname = str(vinfo.get("name", "")).strip('"')
                    vdesc = str(vinfo.get("description", "")).strip('"')
                elif iname_l in by_name:
                    vid, vname, vdesc = by_name[iname_l]
                elif iname.upper() == "DEFAULT_VLAN" and "1" in vlans_map:
                    vid = "1"
                    vinfo = vlans_map["1"] or {}
                    vname = str(vinfo.get("name", "DEFAULT_VLAN")).strip('"')
                    vdesc = str(vinfo.get("description", "")).strip('"')
                else:
                    vid, vname, vdesc = "", "", ""

            matched_relays = sorted(
                {
                    r.get("helper_ip", "")
                    for r in relays
                    if r.get("helper_ip")
                    and (
                        str(r.get("interface") or "").strip().lower() == iname_l
                        or normalize_interface_key(str(r.get("interface") or "")) == iname_k
                        or (
                            vid
                            and str(r.get("interface") or "").strip().lower()
                            in (f"vlan {vid}", f"vlan{vid}", f"vlan.{vid}", f"vlan_{vid}", f"irb.{vid}", vid)
                        )
                    )
                }
            )

            rows.append(
                {
                    "site_code": site_code,
                    "source_device": hostname,
                    "vlan_id": vid,
                    "vlan_name": vname,
                    "vlan_description": vdesc,
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
    from net_docu_crawler.trunk_audit import evaluate_trunk_mismatches

    for dev in raw_devices:
        stamp_schema_v2(dev)
        if dev.get("status", "success") == "success":
            correlate_device_ports(dev)
    compute_stp_root_consensus(raw_devices)
    trunk_audit_result = evaluate_trunk_mismatches(raw_devices)
    return {
        "l3_svi_table": build_l3_svi_table(raw_devices),
        "trunk_audit": trunk_audit_result,
    }

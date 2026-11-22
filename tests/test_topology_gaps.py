# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Deterministic unit and fixture tests covering the 4 L2/L3 topology & rendering gaps."""

import copy
import json
import re

from net_docu_crawler.diagram_validator import validate_mermaid_block
from net_docu_crawler.topology_renderer import build_topology_graph_model, render_topology_deliverables
from net_docu_crawler.topology_resolver import DeviceRegistry
from report_generator import generate_l2_diagram, generate_l3_diagram


def _extract_mermaid_blocks(md_text: str) -> list[str]:
    return re.findall(r"```mermaid\n(.*?)```", md_text, re.DOTALL)


def _assert_valid_deliverables(devices: dict, tmp_path, prefix: str) -> None:
    l2_path = tmp_path / f"{prefix}_L2.md"
    l3_path = tmp_path / f"{prefix}_L3.md"
    html_dir = tmp_path / f"{prefix}_html"
    html_dir.mkdir(parents=True, exist_ok=True)

    generate_l2_diagram(devices, str(l2_path))
    generate_l3_diagram(devices, str(l3_path))
    written = render_topology_deliverables(devices, str(html_dir))

    l2_blocks = _extract_mermaid_blocks(l2_path.read_text(encoding="utf-8"))
    l3_blocks = _extract_mermaid_blocks(l3_path.read_text(encoding="utf-8"))
    assert l2_blocks, "Expected at least one Mermaid diagram block in L2 output"
    assert l3_blocks, "Expected at least one Mermaid diagram block in L3 output"
    for blk in l2_blocks + l3_blocks:
        assert validate_mermaid_block(blk) == []

    assert len(written) == 1
    html_text = (html_dir / "topology_interactive.html").read_text(encoding="utf-8")
    assert "Net-Docu-Crawler" in html_text
    m = re.search(r"const GRAPH = (\{.*?\});", html_text)
    assert m is not None
    parsed = json.loads(m.group(1))
    assert "l3_graph" in parsed


def test_multi_vrf_isolation_and_explicit_route_leaking(tmp_path):
    base_devices = {
        "192.168.100.1": {
            "ip": "192.168.100.1",
            "hostname": "RTR-CORE",
            "site_code": "CORE",
            "vendor": "Cisco",
            "model": "ISR4331",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "vrfs": [
                {"name": "RED", "interfaces": ["Gi0/0/1"]},
                {"name": "BLUE", "interfaces": ["Gi0/0/2"]},
            ],
            "l3_interfaces": [
                {"interface": "Gi0/0/1", "ip_address": "10.10.0.1/24", "status": "up", "vrf": "RED"},
                {"interface": "Gi0/0/2", "ip_address": "10.10.0.1/24", "status": "up", "vrf": "BLUE"},
            ],
            "interfaces_detail": {
                "Gi0/0/1": {"status": "up", "speed": "1Gb/s"},
                "Gi0/0/2": {"status": "up", "speed": "1Gb/s"},
            },
            "routes": [],
            "neighbors": [],
        },
        "192.168.100.2": {
            "ip": "192.168.100.2",
            "hostname": "SPOKE-RED",
            "site_code": "CORE",
            "vendor": "Cisco",
            "model": "ISR4221",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "vrfs": [{"name": "RED", "interfaces": ["Gi0/0/0"]}],
            "l3_interfaces": [
                {"interface": "Gi0/0/0", "ip_address": "10.10.0.2/24", "status": "up", "vrf": "RED"},
            ],
            "interfaces_detail": {"Gi0/0/0": {"status": "up", "speed": "1Gb/s"}},
            "routes": [
                {
                    "subnet": "0.0.0.0/0",
                    "protocol": "static",
                    "next_hop": "10.10.0.1",
                    "interface": "Gi0/0/0",
                    "vrf": "RED",
                },
            ],
            "neighbors": [],
        },
        "192.168.100.3": {
            "ip": "192.168.100.3",
            "hostname": "SPOKE-BLUE",
            "site_code": "CORE",
            "vendor": "Cisco",
            "model": "ISR4221",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "vrfs": [{"name": "BLUE", "interfaces": ["Gi0/0/0"]}],
            "l3_interfaces": [
                {"interface": "Gi0/0/0", "ip_address": "10.10.0.3/24", "status": "up", "vrf": "BLUE"},
            ],
            "interfaces_detail": {"Gi0/0/0": {"status": "up", "speed": "1Gb/s"}},
            "routes": [
                {
                    "subnet": "0.0.0.0/0",
                    "protocol": "static",
                    "next_hop": "10.10.0.1",
                    "interface": "Gi0/0/0",
                    "vrf": "BLUE",
                },
            ],
            "neighbors": [],
        },
    }

    # Scenario 1: Strict VRF isolation (identical 10.10.0.1/24 across RED and BLUE)
    model = build_topology_graph_model(copy.deepcopy(base_devices))
    l3g = model["l3_graph"]
    l3_nodes_by_id = {n["id"]: n for n in l3g["l3_nodes"]}

    assert "node:rtr-core::vrf:RED" in l3_nodes_by_id
    assert "node:rtr-core::vrf:BLUE" in l3_nodes_by_id
    assert "node:spoke-red::vrf:RED" in l3_nodes_by_id
    assert "node:spoke-blue::vrf:BLUE" in l3_nodes_by_id
    assert l3_nodes_by_id["node:rtr-core::vrf:RED"]["vrf"] == "RED"
    assert l3_nodes_by_id["node:rtr-core::vrf:BLUE"]["vrf"] == "BLUE"

    # Zero intra_device_overlap or duplicate_gateway_ip false conflicts across VRFs
    assert l3g["l3_conflicts"] == []

    # Isolated per-VRF graphs & zero cross-VRF links by default
    assert set(l3g["vrf_graphs"].keys()) == {"BLUE", "RED"}
    red_g = l3g["vrf_graphs"]["RED"]
    blue_g = l3g["vrf_graphs"]["BLUE"]
    assert {n["id"] for n in red_g["l3_nodes"]} == {"node:rtr-core::vrf:RED", "node:spoke-red::vrf:RED"}
    assert {n["id"] for n in blue_g["l3_nodes"]} == {"node:rtr-core::vrf:BLUE", "node:spoke-blue::vrf:BLUE"}
    assert len(red_g["l3_links"]) == 1
    assert len(blue_g["l3_links"]) == 1
    assert {red_g["l3_links"][0]["source"], red_g["l3_links"][0]["target"]} == {
        "node:rtr-core::vrf:RED",
        "node:spoke-red::vrf:RED",
    }
    assert {blue_g["l3_links"][0]["source"], blue_g["l3_links"][0]["target"]} == {
        "node:rtr-core::vrf:BLUE",
        "node:spoke-blue::vrf:BLUE",
    }
    for lk in l3g["l3_links"]:
        assert not lk.get("is_vrf_leak")
        assert l3_nodes_by_id[lk["source"]]["vrf"] == l3_nodes_by_id[lk["target"]]["vrf"]

    # Scenario 2a: Explicit `vrf_leaking` configuration emits explicit vrf_route_leak edge
    leak_devices = copy.deepcopy(base_devices)
    leak_devices["192.168.100.1"]["vrf_leaking"] = [
        {"source_vrf": "RED", "target_vrf": "BLUE", "prefixes": ["10.10.0.0/24"]}
    ]
    leak_model = build_topology_graph_model(leak_devices)
    leak_edges = [lk for lk in leak_model["l3_graph"]["l3_links"] if lk.get("is_vrf_leak")]
    assert len(leak_edges) == 1
    assert leak_edges[0]["transport_type"] == "vrf_leak"
    assert leak_edges[0]["routing_mechanism"] == "vrf_route_leak"
    assert leak_edges[0]["is_vrf_leak"] is True
    assert leak_edges[0]["source_vrf"] == "RED"
    assert leak_edges[0]["target_vrf"] == "BLUE"

    # Scenario 2b: Matching export_rts / import_rts and route import_vrf also emit explicit leak edges
    rt_devices = copy.deepcopy(base_devices)
    rt_devices["192.168.100.1"]["vrfs"] = [
        {"name": "RED", "interfaces": ["Gi0/0/1"], "export_rts": ["65000:100"]},
        {"name": "BLUE", "interfaces": ["Gi0/0/2"], "import_rts": ["65000:100"]},
    ]
    rt_model = build_topology_graph_model(rt_devices)
    rt_leaks = [lk for lk in rt_model["l3_graph"]["l3_links"] if lk.get("is_vrf_leak")]
    assert len(rt_leaks) == 1
    assert rt_leaks[0]["transport_type"] == "vrf_leak"
    assert rt_leaks[0]["routing_mechanism"] == "vrf_route_leak"
    assert rt_leaks[0]["is_vrf_leak"] is True

    imp_devices = copy.deepcopy(base_devices)
    imp_devices["192.168.100.1"]["routes"] = [
        {
            "subnet": "172.16.50.0/24",
            "protocol": "bgp",
            "next_hop": "10.10.0.2",
            "interface": "Gi0/0/2",
            "vrf": "BLUE",
            "import_vrf": "RED",
        }
    ]
    imp_model = build_topology_graph_model(imp_devices)
    imp_leaks = [lk for lk in imp_model["l3_graph"]["l3_links"] if lk.get("is_vrf_leak")]
    assert len(imp_leaks) == 1
    assert imp_leaks[0]["transport_type"] == "vrf_leak"
    assert imp_leaks[0]["routing_mechanism"] == "vrf_route_leak"
    assert imp_leaks[0]["is_vrf_leak"] is True

    _assert_valid_deliverables(leak_devices, tmp_path, "vrf_leak")


def test_dual_hub_and_full_mesh_metro_e_clouds(tmp_path):
    def _metro_nbr(remote: str, lport: str, rport: str, rip: str, cloud: str, vlan: str, cidr: str) -> dict:
        return {
            "local_port": lport,
            "remote_device": remote,
            "remote_port": rport,
            "remote_ip": rip,
            "device_type": "router",
            "l2_accuracy": "wan_carrier_arp_route",
            "transport_type": "metro_ethernet",
            "carrier_cloud": cloud,
            "transit_vlan": vlan,
            "transit_cidr": cidr,
        }

    # 1. Dual-Hub Metro-E Cloud (HUB-1, HUB-2 <-> SPOKE-1, SPOKE-2)
    dual_hub_devices = {
        "10.1.0.1": {
            "ip": "10.1.0.1",
            "hostname": "HUB-1",
            "site_code": "H1",
            "vendor": "Juniper Networks",
            "model": "MX204",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [
                {"interface": "xe-0/0/0", "ip_address": "10.250.1.1/30", "status": "up"},
                {"interface": "xe-0/0/1", "ip_address": "10.250.2.1/30", "status": "up"},
            ],
            "interfaces_detail": {
                "xe-0/0/0": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/1": {"status": "up", "speed": "10Gb/s"},
            },
            "neighbors": [
                _metro_nbr(
                    "SPOKE-1", "xe-0/0/0", "Gi0/0", "10.3.0.1", "Spectrum Dual-Hub Metro-E", "101", "10.250.1.0/30"
                ),
                _metro_nbr(
                    "SPOKE-2", "xe-0/0/1", "Gi0/0", "10.4.0.1", "Spectrum Dual-Hub Metro-E", "102", "10.250.2.0/30"
                ),
            ],
        },
        "10.2.0.1": {
            "ip": "10.2.0.1",
            "hostname": "HUB-2",
            "site_code": "H2",
            "vendor": "Juniper Networks",
            "model": "MX204",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [
                {"interface": "xe-0/0/0", "ip_address": "10.250.3.1/30", "status": "up"},
                {"interface": "xe-0/0/1", "ip_address": "10.250.4.1/30", "status": "up"},
            ],
            "interfaces_detail": {
                "xe-0/0/0": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/1": {"status": "up", "speed": "10Gb/s"},
            },
            "neighbors": [
                _metro_nbr(
                    "SPOKE-1", "xe-0/0/0", "Gi0/1", "10.3.0.1", "Spectrum Dual-Hub Metro-E", "103", "10.250.3.0/30"
                ),
                _metro_nbr(
                    "SPOKE-2", "xe-0/0/1", "Gi0/1", "10.4.0.1", "Spectrum Dual-Hub Metro-E", "104", "10.250.4.0/30"
                ),
            ],
        },
        "10.3.0.1": {
            "ip": "10.3.0.1",
            "hostname": "SPOKE-1",
            "site_code": "S1",
            "vendor": "Cisco",
            "model": "C9300",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan101", "ip_address": "10.250.1.2/30", "status": "up"}],
            "interfaces_detail": {
                "Gi0/0": {"status": "up", "speed": "1Gb/s"},
                "Gi0/1": {"status": "up", "speed": "1Gb/s"},
            },
            "neighbors": [
                _metro_nbr(
                    "HUB-1", "Gi0/0", "xe-0/0/0", "10.1.0.1", "Spectrum Dual-Hub Metro-E", "101", "10.250.1.0/30"
                ),
                _metro_nbr(
                    "HUB-2", "Gi0/1", "xe-0/0/0", "10.2.0.1", "Spectrum Dual-Hub Metro-E", "103", "10.250.3.0/30"
                ),
            ],
        },
        "10.4.0.1": {
            "ip": "10.4.0.1",
            "hostname": "SPOKE-2",
            "site_code": "S2",
            "vendor": "Cisco",
            "model": "C9300",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan102", "ip_address": "10.250.2.2/30", "status": "up"}],
            "interfaces_detail": {
                "Gi0/0": {"status": "up", "speed": "1Gb/s"},
                "Gi0/1": {"status": "up", "speed": "1Gb/s"},
            },
            "neighbors": [
                _metro_nbr(
                    "HUB-1", "Gi0/0", "xe-0/0/1", "10.1.0.1", "Spectrum Dual-Hub Metro-E", "102", "10.250.2.0/30"
                ),
                _metro_nbr(
                    "HUB-2", "Gi0/1", "xe-0/0/1", "10.2.0.1", "Spectrum Dual-Hub Metro-E", "104", "10.250.4.0/30"
                ),
            ],
        },
    }

    dh_model = build_topology_graph_model(dual_hub_devices)
    dh_by_hn = {n["hostname"]: n for n in dh_model["nodes"]}
    dh_cloud = next(n for n in dh_model["nodes"] if n["role"] == "wan_cloud")
    assert dh_cloud["cloud_mode"] == "dual-hub"
    assert len(dh_cloud["hub_ids"]) == 2
    assert set(dh_cloud["hub_ids"]) == {dh_by_hn["HUB-1"]["id"], dh_by_hn["HUB-2"]["id"]}

    edge_pairs = {(e["source"], e["target"]) for e in dh_model["edges"]}
    assert (dh_by_hn["HUB-1"]["id"], dh_cloud["id"]) in edge_pairs
    assert (dh_by_hn["HUB-2"]["id"], dh_cloud["id"]) in edge_pairs
    assert (dh_cloud["id"], dh_by_hn["SPOKE-1"]["id"]) in edge_pairs
    assert (dh_cloud["id"], dh_by_hn["SPOKE-2"]["id"]) in edge_pairs

    # 2. Full-Mesh Metro-E Cloud (SITE-A, SITE-B, SITE-C all peering)
    full_mesh_devices = {
        "10.10.1.1": {
            "ip": "10.10.1.1",
            "hostname": "SITE-A",
            "site_code": "SA",
            "vendor": "Cisco",
            "model": "ISR4431",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "Gi0/0", "ip_address": "10.251.0.1/29", "status": "up"}],
            "interfaces_detail": {"Gi0/0": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [
                _metro_nbr("SITE-B", "Gi0/0", "Gi0/0", "10.10.2.1", "Metro-E Full Mesh", "200", "10.251.0.0/29"),
                _metro_nbr("SITE-C", "Gi0/0", "Gi0/0", "10.10.3.1", "Metro-E Full Mesh", "200", "10.251.0.0/29"),
            ],
        },
        "10.10.2.1": {
            "ip": "10.10.2.1",
            "hostname": "SITE-B",
            "site_code": "SB",
            "vendor": "Cisco",
            "model": "ISR4431",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "Gi0/0", "ip_address": "10.251.0.2/29", "status": "up"}],
            "interfaces_detail": {"Gi0/0": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [
                _metro_nbr("SITE-A", "Gi0/0", "Gi0/0", "10.10.1.1", "Metro-E Full Mesh", "200", "10.251.0.0/29"),
                _metro_nbr("SITE-C", "Gi0/0", "Gi0/0", "10.10.3.1", "Metro-E Full Mesh", "200", "10.251.0.0/29"),
            ],
        },
        "10.10.3.1": {
            "ip": "10.10.3.1",
            "hostname": "SITE-C",
            "site_code": "SC",
            "vendor": "Cisco",
            "model": "ISR4431",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "Gi0/0", "ip_address": "10.251.0.3/29", "status": "up"}],
            "interfaces_detail": {"Gi0/0": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [
                _metro_nbr("SITE-A", "Gi0/0", "Gi0/0", "10.10.1.1", "Metro-E Full Mesh", "200", "10.251.0.0/29"),
                _metro_nbr("SITE-B", "Gi0/0", "Gi0/0", "10.10.2.1", "Metro-E Full Mesh", "200", "10.251.0.0/29"),
            ],
        },
    }

    fm_model = build_topology_graph_model(full_mesh_devices)
    fm_cloud = next(n for n in fm_model["nodes"] if n["role"] == "wan_cloud")
    assert fm_cloud["cloud_mode"] == "full-mesh"
    assert len(fm_cloud["hub_ids"]) == 3

    _assert_valid_deliverables(dual_hub_devices, tmp_path, "dual_hub")
    _assert_valid_deliverables(full_mesh_devices, tmp_path, "full_mesh")


def test_ipv6_unnumbered_p2p_and_overlay_tunnels(tmp_path):
    devices = {
        "2001:db8:1::1": {
            "ip": "2001:db8:1::1",
            "hostname": "RTR-V6-A",
            "site_code": "CORE",
            "vendor": "FRRouting",
            "model": "FRR-Router",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [
                {"interface": "eth0", "ip_address": "2001:db8:1::1/64", "status": "up"},
            ],
            "interfaces_detail": {
                "eth0": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/1": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/3": {"status": "up", "speed": "10Gb/s"},
            },
            "routes": [
                {"subnet": "::/0", "protocol": "static", "next_hop": "2001:db8:1::2", "interface": "eth0"},
                {"subnet": "10.200.0.0/24", "protocol": "ospf", "next_hop": "unnumbered", "interface": "xe-0/0/1"},
                {"subnet": "2001:db8:99::/48", "protocol": "ospf", "next_hop": "fe80::1", "interface": "xe-0/0/3"},
            ],
            "neighbors": [
                {
                    "local_port": "xe-0/0/1",
                    "remote_device": "RTR-V6-B",
                    "remote_port": "xe-0/0/2",
                    "remote_ip": "2001:db8:1::2",
                    "device_type": "router",
                },
                {
                    "local_port": "xe-0/0/3",
                    "remote_device": "RTR-V6-B",
                    "remote_port": "xe-0/0/4",
                    "remote_ip": "2001:db8:1::2",
                    "device_type": "router",
                },
            ],
            "security_policy": {
                "vpn_tunnels": [
                    {
                        "type": "ipsec",
                        "interface": "st0.0",
                        "local_ip": "203.0.113.1",
                        "remote_gw": "203.0.113.2",
                        "tunnel_cidr": "169.254.1.0/30",
                        "descr": "Site-to-Site IPsec",
                    }
                ]
            },
            "tunnels": [
                {
                    "type": "wireguard",
                    "interface": "wg0",
                    "local_ip": "198.51.100.1",
                    "remote_gw": "198.51.100.2",
                    "tunnel_cidr": "10.99.0.0/30",
                    "descr": "WireGuard Mesh",
                },
                {
                    "type": "gre",
                    "interface": "gre0",
                    "local_ip": "192.0.2.1",
                    "remote_gw": "192.0.2.2",
                    "tunnel_cidr": "10.98.0.0/30",
                    "descr": "GRE Transit",
                },
            ],
        },
        "2001:db8:1::2": {
            "ip": "2001:db8:1::2",
            "hostname": "RTR-V6-B",
            "site_code": "CORE",
            "vendor": "FRRouting",
            "model": "FRR-Router",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [
                {"interface": "eth0", "ip_address": "2001:db8:1::2/64", "status": "up"},
            ],
            "interfaces_detail": {
                "eth0": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/2": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/4": {"status": "up", "speed": "10Gb/s"},
            },
            "routes": [],
            "neighbors": [
                {
                    "local_port": "xe-0/0/2",
                    "remote_device": "RTR-V6-A",
                    "remote_port": "xe-0/0/1",
                    "remote_ip": "2001:db8:1::1",
                    "device_type": "router",
                },
            ],
        },
    }

    model = build_topology_graph_model(devices)
    l3_links = model["l3_graph"]["l3_links"]

    # 1. IPv6-only adjacency
    v6_links = [
        lk for lk in l3_links if lk.get("address_family") == "ipv6" and lk.get("transit_cidr") == "2001:db8:1::/64"
    ]
    assert len(v6_links) == 1
    assert v6_links[0]["address_family"] == "ipv6"
    assert "::/0" in v6_links[0]["routed_prefixes"]

    # 2. Unnumbered P2P links (explicit "unnumbered" and link-local "fe80::1")
    unnum_links = [lk for lk in l3_links if lk.get("transport_type") == "l3_unnumbered_p2p"]
    assert len(unnum_links) == 2
    unnum_v4 = next(lk for lk in unnum_links if lk["local_interface"] == "xe-0/0/1")
    assert unnum_v4["is_unnumbered"] is True
    assert unnum_v4["remote_interface"] == "xe-0/0/2"
    unnum_v6 = next(lk for lk in unnum_links if lk["local_interface"] == "xe-0/0/3")
    assert unnum_v6["is_unnumbered"] is True
    assert unnum_v6["remote_interface"] == "xe-0/0/4"
    assert unnum_v6["address_family"] == "ipv6"

    # 3. Overlay tunnels (IPsec, WireGuard, GRE)
    overlay_links = [lk for lk in l3_links if lk.get("transport_type") == "overlay_tunnel"]
    assert len(overlay_links) == 3
    by_otype = {lk["overlay_type"]: lk for lk in overlay_links}
    assert set(by_otype.keys()) == {"ipsec", "wireguard", "gre"}
    assert by_otype["ipsec"]["tunnel_interface"] == "st0.0"
    assert by_otype["wireguard"]["tunnel_interface"] == "wg0"
    assert by_otype["gre"]["tunnel_interface"] == "gre0"

    _assert_valid_deliverables(devices, tmp_path, "v6_unnum_overlay")


def test_uncrawled_core_fallback_and_no_fabrication(tmp_path):
    # 1. Edge-only crawl of two carrier-tagged spokes pointing to an uncrawled core
    edge_metro_devices = {
        "10.250.0.2": {
            "ip": "10.250.0.2",
            "hostname": "SPOKE-1",
            "site_code": "S1",
            "vendor": "Cisco",
            "model": "C9300-24T",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan1050", "ip_address": "10.250.0.2/24", "status": "up"}],
            "interfaces_detail": {
                "Gi1/0/1": {"status": "up", "speed": "1Gb/s", "description": "Spectrum Metro Ethernet"}
            },
            "vlans": {"1050": {"id": "1050", "name": "Spectrum Metro-E"}},
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.0.1", "interface": "Vlan1050"}
            ],
            "arp_table": [{"ip": "10.250.0.1", "mac": "00:11:22:33:44:55"}],
            "neighbors": [],
        },
        "10.250.1.2": {
            "ip": "10.250.1.2",
            "hostname": "SPOKE-2",
            "site_code": "S2",
            "vendor": "Cisco",
            "model": "C9300-24T",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan1051", "ip_address": "10.250.1.2/24", "status": "up"}],
            "interfaces_detail": {
                "Gi1/0/1": {"status": "up", "speed": "1Gb/s", "description": "Metro-E Carrier Circuit"}
            },
            "vlans": {"1051": {"id": "1051", "name": "Metro-E-Transit"}},
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.1.1", "interface": "Vlan1051"}
            ],
            "arp_table": [],
            "neighbors": [],
        },
    }

    metro_model = build_topology_graph_model(copy.deepcopy(edge_metro_devices))
    assert metro_model["metadata"]["missing_core_blind_spots"], "Expected missing_core_blind_spots to be populated"
    metro_edges = [e for e in metro_model["edges"] if e["transport_type"] == "metro_ethernet"]
    # Uncrawled-Core-Hub -> wan_cloud, wan_cloud -> SPOKE-1, wan_cloud -> SPOKE-2
    assert len(metro_edges) == 3
    for e in metro_edges:
        assert "Metro-E" in e["display_badge"]
        assert e["is_verified"] is False
        assert e["confidence_tier"] in ("inferred-arp-route", "inferred-route-only")
        assert e["blind_spot"] is True

    tiers_seen = {e["confidence_tier"] for e in metro_edges}
    assert tiers_seen == {"inferred-arp-route", "inferred-route-only"}

    # DeviceRegistry.infer_wan_and_gateway_links on the same edge-only crawl
    reg_metro = DeviceRegistry()
    raw_metro = copy.deepcopy(list(edge_metro_devices.values()))
    reg_metro.infer_wan_and_gateway_links(raw_metro)
    for dev in raw_metro:
        assert len(dev["neighbors"]) == 1
        nbr = dev["neighbors"][0]
        assert nbr["l2_accuracy"] == "wan_carrier_arp_route"
        assert nbr["transport_type"] == "metro_ethernet"
        assert nbr["is_verified"] is False
        assert nbr["blind_spot"] is True
        assert nbr["confidence_tier"] in ("inferred-arp-route", "inferred-route-only")

    _assert_valid_deliverables(edge_metro_devices, tmp_path, "edge_metro")

    # 2. Single-edge crawl with default route + ARP/subnet match synthesizes [L3 Egress] candidate
    single_edge_devices = {
        "192.168.50.10": {
            "ip": "192.168.50.10",
            "hostname": "EDGE-SW1",
            "site_code": "EDGE",
            "vendor": "Juniper Networks",
            "model": "EX2300-24P",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "irb.50", "ip_address": "192.168.50.10/24", "status": "up"}],
            "interfaces_detail": {"ge-0/0/0": {"status": "up", "speed": "1Gb/s"}},
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "192.168.50.1", "interface": "irb.50"}
            ],
            "arp_table": [{"ip": "192.168.50.1", "mac": "aa:bb:cc:dd:ee:01"}],
            "neighbors": [],
        }
    }

    egress_model = build_topology_graph_model(copy.deepcopy(single_edge_devices))
    assert egress_model["metadata"]["missing_core_blind_spots"]
    egress_edges = [e for e in egress_model["edges"] if e["transport_type"] == "l3_egress"]
    assert len(egress_edges) == 1
    assert "L3 Egress" in egress_edges[0]["display_badge"]
    assert egress_edges[0]["is_verified"] is False
    assert egress_edges[0]["confidence_tier"] == "inferred-arp-route"
    assert egress_edges[0]["blind_spot"] is True

    reg_single = DeviceRegistry()
    raw_single = copy.deepcopy(list(single_edge_devices.values()))
    reg_single.infer_wan_and_gateway_links(raw_single)
    assert len(raw_single[0]["neighbors"]) == 1
    assert raw_single[0]["neighbors"][0]["l2_accuracy"] == "l3_next_hop_egress"
    assert raw_single[0]["neighbors"][0]["is_verified"] is False
    assert raw_single[0]["neighbors"][0]["blind_spot"] is True

    _assert_valid_deliverables(single_edge_devices, tmp_path, "edge_single")

    # 3. Conflicting default next-hops or off-subnet next-hop without ARP/MAC emits ZERO fabricated edges
    no_fab_devices = {
        "10.1.1.10": {
            "ip": "10.1.1.10",
            "hostname": "CONFLICT-SW",
            "site_code": "LAB",
            "vendor": "Cisco",
            "model": "C2960X",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan1", "ip_address": "10.1.1.10/24", "status": "up"}],
            "interfaces_detail": {"Vlan1": {"status": "up", "speed": "1Gb/s"}},
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.1.1.1", "interface": "Vlan1"},
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.1.1.2", "interface": "Vlan1"},
            ],
            "arp_table": [],
            "neighbors": [],
        },
        "192.168.10.10": {
            "ip": "192.168.10.10",
            "hostname": "OFFSUBNET-SW",
            "site_code": "LAB",
            "vendor": "Cisco",
            "model": "C2960X",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan1", "ip_address": "192.168.10.10/24", "status": "up"}],
            "interfaces_detail": {"Vlan1": {"status": "up", "speed": "1Gb/s"}},
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "203.0.113.1", "interface": "Vlan1"},
            ],
            "arp_table": [],
            "neighbors": [],
        },
    }

    no_fab_model = build_topology_graph_model(copy.deepcopy(no_fab_devices))
    assert no_fab_model["edges"] == []
    assert no_fab_model["metadata"]["missing_core_blind_spots"] == []

    reg_nofab = DeviceRegistry()
    raw_nofab = copy.deepcopy(list(no_fab_devices.values()))
    reg_nofab.infer_wan_and_gateway_links(raw_nofab)
    assert raw_nofab[0]["neighbors"] == []
    assert raw_nofab[1]["neighbors"] == []

# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the modular topology graph model and pluggable renderer registry."""

import json
import re

import pytest

from net_docu_crawler.topology_renderer import (
    RENDERER_REGISTRY,
    TopologyRenderer,
    build_topology_graph_model,
    classify_neighbor_node,
    get_topology_renderer,
    render_topology_deliverables,
)


def test_build_topology_graph_model_and_render_interactive_html(tmp_path):
    devices = {
        "10.1.0.1": {
            "ip": "10.1.0.1",
            "hostname": "DO-MDF-CORE",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": True, "bridge_priority": "4096"},
            "poe": {"used_power_watts": 0.0, "total_power_watts": 0.0},
            "l3_interfaces": [{"interface": "irb.10", "ip_address": "10.1.0.1/24", "status": "up"}],
            "interfaces_detail": {"xe-0/0/1": {"status": "up", "speed": "10Gb/s"}},
            "neighbors": [
                {"local_port": "xe-0/0/1", "remote_device": "DO-IDF-SW1", "remote_port": "xe-0/2/0"},
                {"local_port": "ge-0/0/5", "remote_device": "d65-000fd30aae2f", "remote_port": "eth0"},
            ],
        },
        "10.1.0.2": {
            "ip": "10.1.0.2",
            "hostname": "DO-IDF-SW1",
            "vendor": "Juniper Networks",
            "model": "ex3400-48p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False},
            "poe": {"used_power_watts": 120.5, "total_power_watts": 740.0},
            "l3_interfaces": [{"interface": "irb.10", "ip_address": "10.1.0.2/24", "status": "up"}],
            "interfaces_detail": {"xe-0/2/0": {"status": "up", "speed": "10Gb/s"}},
            "neighbors": [
                {"local_port": "xe-0/2/0", "remote_device": "DO-MDF-CORE", "remote_port": "xe-0/0/1"},
            ],
        },
    }
    trunk_audit = {
        "findings": [
            {
                "Side_A_Host": "DO-MDF-CORE",
                "Side_B_Host": "DO-IDF-SW1",
                "Rule_ID": "TRK-004",
                "Severity": "HIGH",
                "Remediation_Hint": "Sync VLANs",
            }
        ]
    }
    model = build_topology_graph_model(devices, trunk_audit=trunk_audit)
    assert model["metadata"]["total_nodes"] == 2
    assert model["metadata"]["total_edges"] == 1
    assert model["edges"][0]["trunk_severity"] == "HIGH"
    assert model["l3_subnets"][0]["cidr"] == "10.1.0.0/24"

    written = render_topology_deliverables(devices, str(tmp_path), trunk_audit=trunk_audit)
    assert len(written) == 1
    html = (tmp_path / "topology_interactive.html").read_text(encoding="utf-8")
    assert "Net-Docu-Crawler Topology" in html
    assert "DO-MDF-CORE" in html
    assert "DO-IDF-SW1" in html
    m = re.search(r"const GRAPH = (\{.*?\});", html)
    assert m is not None
    parsed = json.loads(m.group(1))
    assert parsed["metadata"]["total_nodes"] == 2


def test_topology_renderer_registry_and_unknown_error():
    assert "interactive_html" in RENDERER_REGISTRY
    r = get_topology_renderer("interactive_html")
    assert isinstance(r, TopologyRenderer)
    with pytest.raises(ValueError, match="Unknown topology renderer"):
        get_topology_renderer("nonexistent_backend")


def test_connectivity_overrides_subsite_name_and_defaults_to_all():
    devices = {
        "10.250.5.2": {
            "ip": "10.250.5.2",
            "hostname": "VES_MDF_CORE_BLDG_A",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "interfaces_detail": {"xe-0/0/20": {"status": "up"}},
            "neighbors": [{"local_port": "xe-0/0/20", "remote_device": "MOT-Back-Warehouse", "remote_port": "49"}],
        },
        "172.31.79.31": {
            "ip": "172.31.79.31",
            "hostname": "MOT-Back-Warehouse",
            "vendor": "HP ProCurve",
            "model": "HP 2530-48G",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "interfaces_detail": {"49": {"status": "up"}},
            "neighbors": [{"local_port": "49", "remote_device": "VES_MDF_CORE_BLDG_A", "remote_port": "xe-0/0/20"}],
        },
    }
    model = build_topology_graph_model(devices)
    by_hn = {n["hostname"]: n for n in model["nodes"]}
    assert by_hn["MOT-Back-Warehouse"]["site"] == "VES"
    assert by_hn["MOT-Back-Warehouse"]["sub_site"] == "MOT"
    assert model["sites"] == ["VES"]


def test_classify_neighbor_node_strict_priority_order():
    # 1. Crawled infrastructure always wins (never dropped by HP/platform heuristics)
    assert (
        classify_neighbor_node(
            "MOT-Back-Warehouse.local",
            {"platform": "Hewlett Packard", "device_type": "switch"},
            crawled_hosts_lc={"mot-back-warehouse"},
        )
        == "crawled_infra"
    )
    assert (
        classify_neighbor_node(
            "172.31.2.31",
            {"remote_ip": "172.31.2.31", "platform": "Hewlett Packard Enterprise"},
            crawled_ips={"172.31.2.31"},
        )
        == "crawled_infra"
    )
    assert (
        classify_neighbor_node(
            "UnknownHost",
            {"remote_mac": "14:3F:C3:BF:44:64"},
            crawled_macs={"14:3f:c3:bf:44:64"},
        )
        == "crawled_infra"
    )

    # 2. Explicit WAN/Firewall/L3 egress & managed HPE/SnapAV switches (never drop HPE switches)
    assert (
        classify_neighbor_node(
            "Perimeter-Firewall (172.31.254.2)",
            {"device_type": "firewall", "l2_accuracy": "l3_next_hop_egress"},
        )
        == "firewall"
    )
    assert classify_neighbor_node("DO-Main-Bldg-2", {"platform": "Hewlett Packard Enterprise"}) == "uncrawled_switch"
    assert classify_neighbor_node("DO-Old-Bldg", {"platform": "HPN Supply Chain"}) == "uncrawled_switch"
    assert (
        classify_neighbor_node("DO-IDF2-Power", {"platform": "Hewlett Packard", "device_type": "switch"})
        == "uncrawled_switch"
    )
    assert (
        classify_neighbor_node("DO-PD", {"platform": "Hewlett Packard", "device_type": "switch"}) == "uncrawled_switch"
    )
    assert (
        classify_neighbor_node(
            "VES-Bldg_J_TK_7-9",
            {"platform": "Hewlett Packard", "device_type": "switch", "remote_port": "50"},
        )
        == "uncrawled_switch"
    )
    assert (
        classify_neighbor_node(
            "172.31.2.31",
            {"platform": "Hewlett Packard Enterprise", "device_type": "unknown", "remote_port": "48"},
        )
        == "uncrawled_switch"
    )
    assert (
        classify_neighbor_node("172.22.2.201", {"platform": "SnapAV", "device_type": "unknown"}) == "uncrawled_switch"
    )
    assert classify_neighbor_node("MAC-001b17000102", {"device_type": "unknown"}) == "firewall"

    # HP printers must still be endpoints
    assert (
        classify_neighbor_node("HP-LaserJet-Office", {"platform": "Hewlett Packard", "device_type": "unknown"})
        == "endpoint"
    )
    assert classify_neighbor_node("Office-MFP", {"platform": "Hewlett Packard", "device_type": "printer"}) == "endpoint"

    # 3. Wireless APs even with device_type=="unknown" or empty platform
    assert (
        classify_neighbor_node(
            "172.31.1.227",
            {"platform": "Ruckus Wireless", "device_type": "unknown", "remote_mac": "60:d0:2c:10:4b:a0"},
        )
        == "ap"
    )
    assert (
        classify_neighbor_node(
            "10.0.0.50",
            {"platform": "", "device_type": "unknown", "remote_mac": "40:e3:d6:c1:2d:a4"},
        )
        == "ap"
    )
    # ArubaOS-Switch / EdgeSwitch must NOT be misclassified as AP
    assert (
        classify_neighbor_node("Edge-SW-01", {"platform": "EdgeSwitch 48", "remote_mac": "f0:9f:c2:00:00:01"})
        == "uncrawled_switch"
    )

    # 4. Endpoints (even when raw driver set device_type="switch")
    assert classify_neighbor_node("d65-000FD30AAE38", {"platform": "Digium", "device_type": "switch"}) == "endpoint"
    assert (
        classify_neighbor_node(
            "SIP-T33G", {"platform": "JunOS-Discovered", "device_type": "switch", "remote_port": "WAN PORT"}
        )
        == "endpoint"
    )
    assert (
        classify_neighbor_node(
            "S", {"platform": "JunOS-Discovered", "device_type": "switch", "remote_port": "WAN PORT"}
        )
        == "endpoint"
    )
    assert (
        classify_neighbor_node(
            "S206005058538649", {"platform": "S206005058538649", "device_type": "switch", "remote_port": "WAN..."}
        )
        == "endpoint"
    )
    assert (
        classify_neighbor_node("DO-FISC-MELANIE", {"platform": "DO-FISC-MELANIE", "device_type": "switch"})
        == "endpoint"
    )
    assert classify_neighbor_node("DO-KATYE", {"platform": "DO-KATYE", "device_type": "switch"}) == "endpoint"
    assert (
        classify_neighbor_node("WBE-FS-POS-01", {"platform": "JunOS-Discovered", "device_type": "switch"}) == "endpoint"
    )
    assert (
        classify_neighbor_node(
            "TSW-770-C4426825C51C", {"platform": "CRESTRON ELECTRONICS, INC.", "device_type": "switch"}
        )
        == "endpoint"
    )
    assert classify_neighbor_node("00:24:e8:1c:ba:07", {"platform": "Dell Inc.", "device_type": "switch"}) == "endpoint"
    assert (
        classify_neighbor_node(
            "172.22.2.203",
            {
                "platform": "openwrt SSH-2.0-dropbear_2024.86",
                "remote_mac": "172.22.2.203",
                "remote_port": "00:d0:5f:0a:a4:60",
                "device_type": "unknown",
            },
        )
        == "endpoint"
    )


def test_multi_site_wan_cloud_fw_stp_scope_and_l3_graph(tmp_path):
    devices = {
        "10.1.0.1": {
            "ip": "10.1.0.1",
            "hostname": "DO-Main-BLDG",
            "site_code": "DO",
            "vendor": "HP ProCurve",
            "model": "HP 5412zl",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": False, "is_root": False},
            "l3_interfaces": [
                {"interface": "DO", "ip_address": "10.1.0.1/24", "status": "up"},
                {"interface": "servers", "ip_address": "10.0.0.1/24", "status": "up"},
                {"interface": "Spectrun-VES", "ip_address": "10.250.5.1/24", "status": "up"},
                {"interface": "Route to NMS", "ip_address": "10.250.6.1/24", "status": "up"},
                {"interface": "Spectrun-NES", "ip_address": "10.250.2.1/30", "status": "up"},
                {"interface": "FW Internal Route", "ip_address": "172.31.254.1/30", "status": "up"},
            ],
            "vlans": {
                "100": {"id": "100", "name": "DO", "description": "District Office"},
                "101": {"id": "101", "name": "servers", "description": "Data Center Servers"},
                "1050": {"id": "1050", "name": "Spectrun-VES", "description": "WAN Transit VES"},
                "1052": {"id": "1052", "name": "Route to NMS", "description": "Direct Fiber NMS"},
                "4009": {"id": "4009", "name": "FW Internal Route", "description": "Firewall Transit"},
            },
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "172.31.254.2", "interface": "4009"},
                {"subnet": "10.5.0.0/16", "protocol": "static", "next_hop": "10.250.5.2", "interface": "1050"},
                {"subnet": "172.23.2.0/24", "protocol": "static", "next_hop": "10.250.5.2", "interface": "1050"},
                {"subnet": "10.6.0.0/16", "protocol": "static", "next_hop": "10.250.6.2", "interface": "1052"},
                {"subnet": "216.250.157.0/27", "protocol": "static", "next_hop": "10.0.0.25", "interface": "101"},
            ],
            "dhcp": {"relays": [{"interface": "VLAN 100", "helper_ip": "10.0.0.3"}]},
            "interfaces_detail": {
                "A3": {"status": "up", "speed": "1Gb/s"},
                "C1": {"status": "up", "speed": "10Gb/s"},
                "C2": {"status": "up", "speed": "10Gb/s"},
            },
            "neighbors": [
                {
                    "local_port": "A3",
                    "remote_device": "Perimeter-Firewall (172.31.254.2)",
                    "remote_port": "",
                    "remote_ip": "172.31.254.2",
                    "remote_mac": "00:1b:17:00:01:02",
                    "platform": "Palo Alto Networks",
                    "device_type": "firewall",
                    "transport_type": "l3_egress",
                    "l2_accuracy": "l3_next_hop_egress",
                    "route_prefix": "0.0.0.0/0",
                    "transit_vlan": "4009",
                    "isp_handoff": {
                        "isp_port": "A1",
                        "isp_label": "Spectrum Internet",
                        "isp_mac": "00:11:22:33:44:55",
                        "isp_vendor": "Charter Fiber NID",
                        "fw_untrust_port": "A2",
                        "vlan_id": "2",
                    },
                },
                {
                    "local_port": "C1",
                    "remote_device": "VES_MDF_CORE_BLDG_A",
                    "remote_port": "xe-0/0/22",
                    "remote_ip": "10.250.5.2",
                    "device_type": "switch",
                    "l2_accuracy": "wan_carrier_arp_route",
                    "transport_type": "metro_ethernet",
                    "carrier_cloud": "Spectrum Metro Ethernet",
                    "transit_vlan": "1050",
                    "transit_cidr": "10.250.5.0/30",
                    "mask_mismatch": "/24 vs /30",
                },
                {
                    "local_port": "C1",
                    "remote_device": "NES_MDF_CORE_BLDG_A",
                    "remote_port": "ge-0/0/23",
                    "remote_ip": "10.250.2.2",
                    "device_type": "switch",
                    "l2_accuracy": "wan_carrier_arp_route",
                    "transport_type": "metro_ethernet",
                    "carrier_cloud": "Spectrum Metro Ethernet",
                    "transit_vlan": "1053",
                    "transit_cidr": "10.250.2.0/30",
                },
                {
                    "local_port": "C2",
                    "remote_device": "NMS_MDF_CORE_BLDG_B",
                    "remote_port": "xe-0/0/22",
                    "remote_ip": "10.250.6.2",
                    "device_type": "switch",
                    "link_confidence": "two-way",
                },
            ],
        },
        "10.250.5.2": {
            "ip": "10.250.5.2",
            "hostname": "VES_MDF_CORE_BLDG_A",
            "site_code": "VES",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False, "root_bridge": "32768.14:3f:c3:bf:44:64"},
            "l3_interfaces": [
                {"interface": "irb.1050", "ip_address": "10.250.5.2/30", "status": "up"},
                {"interface": "irb.99", "ip_address": "10.5.199.1/24", "status": "up"},
                {"interface": "irb.2052", "ip_address": "10.5.192.1/21", "status": "up"},
                {"interface": "irb.4051", "ip_address": "172.23.2.1/24", "status": "up"},
            ],
            "vlans": {
                "1050": {"id": "1050", "name": "Vlan_1050", "svi_interface": "irb.1050", "description": "WAN_UPLINK"},
                "2052": {"id": "2052", "name": "Vlan_2052", "svi_interface": "irb.2052", "description": "CHROMEBOOKS"},
                "4051": {
                    "id": "4051",
                    "name": "Vlan_4051",
                    "svi_interface": "irb.4051",
                    "description": "KCSOS_Teacher",
                },
            },
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.5.1", "interface": "irb.1050"}
            ],
            "interfaces_detail": {
                "xe-0/0/22": {"status": "up", "speed": "10Gb/s"},
                "xe-0/0/20": {"status": "up", "speed": "10Gb/s"},
            },
            "neighbors": [
                {
                    "local_port": "xe-0/0/22",
                    "remote_device": "DO-Main-BLDG",
                    "remote_port": "C1",
                    "remote_ip": "10.1.0.1",
                    "device_type": "switch",
                    "l2_accuracy": "wan_carrier_arp_route",
                    "transport_type": "metro_ethernet",
                    "carrier_cloud": "Spectrum Metro Ethernet",
                    "transit_vlan": "1050",
                    "transit_cidr": "10.250.5.0/30",
                    "mask_mismatch": "/24 vs /30",
                },
                {
                    "local_port": "xe-0/0/20",
                    "remote_device": "MOT-Back-Warehouse",
                    "remote_port": "49",
                    "device_type": "switch",
                    "link_confidence": "two-way",
                },
                {
                    "local_port": "ge-0/0/10",
                    "remote_device": "172.31.5.199",
                    "remote_port": "eth0",
                    "remote_ip": "172.31.5.199",
                    "remote_mac": "60:d0:2c:10:4b:a0",
                    "platform": "Ruckus Wireless",
                    "device_type": "unknown",
                },
            ],
        },
        "172.31.79.31": {
            "ip": "172.31.79.31",
            "hostname": "MOT-Back-Warehouse",
            "site_code": "MOT",
            "vendor": "HP ProCurve",
            "model": "HP 2530-48G",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.00:11:22:33:44:01"},
            "l3_interfaces": [{"interface": "MOT", "ip_address": "172.31.79.31/24", "status": "up"}],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "172.31.79.1"}],
            "interfaces_detail": {"49": {"status": "up", "speed": "1Gb/s"}, "50": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [
                {
                    "local_port": "49",
                    "remote_device": "VES_MDF_CORE_BLDG_A",
                    "remote_port": "xe-0/0/20",
                    "link_confidence": "two-way",
                },
                {"local_port": "50", "remote_device": "MOT-Storage", "remote_port": "25", "link_confidence": "two-way"},
            ],
        },
        "172.31.79.21": {
            "ip": "172.31.79.21",
            "hostname": "MOT-Storage",
            "site_code": "MOT",
            "vendor": "HP ProCurve",
            "model": "HP 2530-24G",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.00:11:22:33:44:02"},
            "l3_interfaces": [{"interface": "MOT", "ip_address": "172.31.79.21/24", "status": "up"}],
            "interfaces_detail": {"25": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [
                {
                    "local_port": "25",
                    "remote_device": "MOT-Back-Warehouse",
                    "remote_port": "50",
                    "link_confidence": "two-way",
                }
            ],
        },
        "10.250.2.2": {
            "ip": "10.250.2.2",
            "hostname": "NES_MDF_CORE_BLDG_A",
            "site_code": "NES",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False, "root_bridge": "32768.20:d8:0b:93:2c:73"},
            "l3_interfaces": [
                {"interface": "irb.1053", "ip_address": "10.250.2.2/30", "status": "up"},
                {"interface": "irb.4021", "ip_address": "172.23.2.1/24", "status": "up"},
                {"interface": "irb.2021", "ip_address": "10.2.1.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.2.1", "interface": "irb.1053"}
            ],
            "interfaces_detail": {"ge-0/0/23": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [],
        },
        "10.250.6.2": {
            "ip": "10.250.6.2",
            "hostname": "NMS_MDF_CORE_BLDG_B",
            "site_code": "NMS",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {
                "enabled": True,
                "is_root": True,
                "root_bridge": "32768.20:d8:0b:8f:ad:de",
                "is_verified_campus_root": True,
            },
            "l3_interfaces": [
                {"interface": "irb.1052", "ip_address": "10.250.6.2/30", "status": "up"},
                {"interface": "irb.2011", "ip_address": "10.6.11.1/24", "status": "up"},
                {"interface": "irb.3011", "ip_address": "172.31.1.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.6.1", "interface": "irb.1052"}
            ],
            "interfaces_detail": {"xe-0/0/22": {"status": "up", "speed": "10Gb/s"}},
            "neighbors": [
                {
                    "local_port": "xe-0/0/22",
                    "remote_device": "DO-Main-BLDG",
                    "remote_port": "C2",
                    "remote_ip": "10.1.0.1",
                    "device_type": "switch",
                    "link_confidence": "two-way",
                },
            ],
        },
        "172.31.1.11": {
            "ip": "172.31.1.11",
            "hostname": "NMS_BLDG_A_SW_1",
            "site_code": "NMS",
            "vendor": "Juniper Networks",
            "model": "ex3400-48p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False},
            "l3_interfaces": [
                {"interface": "irb.3010", "ip_address": "172.30.1.11/24", "status": "up"},
                {"interface": "irb.3011", "ip_address": "172.31.1.11/24", "status": "up"},
            ],
            "neighbors": [
                {"local_port": "xe-0/2/0", "remote_device": "NMS_MDF_CORE_BLDG_B", "remote_port": "xe-0/0/0"}
            ],
        },
        "172.31.1.21": {
            "ip": "172.31.1.21",
            "hostname": "NMS_BLDG_B_SW_1",
            "site_code": "NMS",
            "vendor": "Juniper Networks",
            "model": "ex3400-48p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False},
            "l3_interfaces": [
                {"interface": "irb.3010", "ip_address": "172.30.1.21/24", "status": "up"},
                {"interface": "irb.3011", "ip_address": "172.31.1.21/24", "status": "up"},
            ],
            "neighbors": [
                {"local_port": "xe-0/2/0", "remote_device": "NMS_MDF_CORE_BLDG_B", "remote_port": "xe-0/0/1"}
            ],
        },
        "172.31.5.11": {
            "ip": "172.31.5.11",
            "hostname": "VES_BLDG_A_SW_1",
            "site_code": "VES",
            "vendor": "Juniper Networks",
            "model": "ex3400-48p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False},
            "l3_interfaces": [
                {"interface": "irb.3058", "ip_address": "172.30.5.11/24", "status": "up"},
                {"interface": "irb.3059", "ip_address": "172.31.5.11/24", "status": "up"},
            ],
            "neighbors": [
                {"local_port": "xe-0/2/0", "remote_device": "VES_MDF_CORE_BLDG_A", "remote_port": "xe-0/0/0"}
            ],
        },
    }

    model = build_topology_graph_model(devices)
    by_hn = {n["hostname"]: n for n in model["nodes"]}

    # STP Root Honesty
    assert by_hn["NMS_MDF_CORE_BLDG_B"]["stp_root_scope"] == "campus_root"
    assert by_hn["NMS_MDF_CORE_BLDG_B"]["stp_root"] is True
    assert by_hn["MOT-Back-Warehouse"]["stp_root_scope"] == "isolated_self_root"
    assert by_hn["MOT-Back-Warehouse"]["stp_root"] is False
    assert by_hn["MOT-Storage"]["stp_root_scope"] == "isolated_self_root"
    assert model["metadata"]["campus_roots"] == 1
    assert model["metadata"]["isolated_roots"] == 2

    # Parent site + sub_site + true multi-hop depth
    assert by_hn["MOT-Back-Warehouse"]["site"] == "VES"
    assert by_hn["MOT-Back-Warehouse"]["sub_site"] == "MOT"
    assert by_hn["MOT-Back-Warehouse"]["hop_depth"] == 1
    assert by_hn["MOT-Storage"]["site"] == "VES"
    assert by_hn["MOT-Storage"]["sub_site"] == "MOT"
    assert by_hn["MOT-Storage"]["hop_depth"] == 2
    # Hub must NOT overwrite NMS's site even over direct L2 link
    assert by_hn["NMS_MDF_CORE_BLDG_B"]["site"] == "NMS"

    # Wireless AP rollup without inflating metadata["total_nodes"]
    assert by_hn["VES_MDF_CORE_BLDG_A"]["attached_ap_count"] == 1
    assert model["metadata"]["total_aps"] == 1
    assert len(model["ap_nodes"]) == 1
    assert len(model["wireless_aps"]) == 1
    assert all(n["role"] != "ap" for n in model["nodes"])

    # Materialized WAN cloud, Firewall, and ISP nodes (all hop_depth == 0)
    assert "Spectrum Metro Ethernet" in by_hn
    assert by_hn["Spectrum Metro Ethernet"]["role"] == "wan_cloud"
    assert by_hn["Spectrum Metro Ethernet"]["hop_depth"] == 0
    assert by_hn["Perimeter-Firewall (172.31.254.2)"]["role"] == "firewall"
    assert by_hn["Perimeter-Firewall (172.31.254.2)"]["hop_depth"] == 0
    assert by_hn["Spectrum Internet"]["role"] == "isp"
    assert by_hn["Spectrum Internet"]["hop_depth"] == 0

    # Firewall egress edge never emits dangling " ↔ A3" when remote_port is empty
    fw_edge = next(
        e
        for e in model["edges"]
        if e["source"] == by_hn["Perimeter-Firewall (172.31.254.2)"]["id"]
        and e["target"] == by_hn["DO-Main-BLDG"]["id"]
    )
    assert fw_edge["port_pairs"] == ["Trust ↔ A3"]

    # Metro-E cloud -> spoke speed reflects spoke port (10G for VES xe-0/0/22, 1G for NES ge-0/0/23)
    cloud_id = by_hn["Spectrum Metro Ethernet"]["id"]
    ves_metro = next(
        e for e in model["edges"] if e["source"] == cloud_id and e["target"] == by_hn["VES_MDF_CORE_BLDG_A"]["id"]
    )
    nes_metro = next(
        e for e in model["edges"] if e["source"] == cloud_id and e["target"] == by_hn["NES_MDF_CORE_BLDG_A"]["id"]
    )
    assert ves_metro["speed_label"] == "10G"
    assert ves_metro["display_badge"] == "Metro-E 10G"
    assert nes_metro["speed_label"] == "1G"
    assert nes_metro["display_badge"] == "Metro-E 1G"

    # Uncrawled single-IP Perimeter-Firewall must NOT trigger a false /30 vs /24 mask_mismatch
    fw_conflicts = [
        c for c in model["l3_graph"]["l3_conflicts"] if "Perimeter-Firewall (172.31.254.2)" in c.get("devices", [])
    ]
    assert fw_conflicts == []

    # Canonical bidirectional port deduplication + transport types
    nms_edge = next(e for e in model["edges"] if e["target"] == by_hn["NMS_MDF_CORE_BLDG_B"]["id"])
    assert nms_edge["port_pairs"] == ["C2 ↔ xe-0/0/22"]
    assert nms_edge["transport_type"] == "direct_l2_uplink"
    assert nms_edge["evidence"] == "confirmed_lldp"
    assert nms_edge["link_scope"] == "backbone"
    assert nms_edge["display_badge"] == "LLDP 10G"

    metro_edges = [e for e in model["edges"] if e["transport_type"] == "metro_ethernet"]
    assert len(metro_edges) == 3  # Hub -> cloud, cloud -> VES, cloud -> NES
    assert all(e["evidence"] == "wan_carrier_arp_route" for e in metro_edges)

    # L3 Graph: dual-SVI L2 access switches excluded (>10 nodes), mask mismatch kept, duplicate IP NOT bridged
    l3g = model["l3_graph"]
    l3_by_hn = {n["hostname"]: n for n in l3g["l3_nodes"]}
    assert "MOT-Back-Warehouse" not in l3_by_hn
    assert "NMS_BLDG_A_SW_1" not in l3_by_hn
    assert "VES_BLDG_A_SW_1" not in l3_by_hn
    assert "Next-Hop 10.0.0.25" in l3_by_hn

    ves_l3_links = [
        lk
        for lk in l3g["l3_links"]
        if {lk["source"], lk["target"]} == {by_hn["DO-Main-BLDG"]["id"], by_hn["VES_MDF_CORE_BLDG_A"]["id"]}
    ]
    assert len(ves_l3_links) == 1
    assert ves_l3_links[0]["mask_mismatch"] is True
    assert ves_l3_links[0]["mask_mismatch_detail"] == "/24 vs /30"
    assert ves_l3_links[0]["transport_type"] == "metro_ethernet"

    # Duplicate gateway IP 172.23.2.1/24 must NOT link VES <-> NES
    false_bridge = [
        lk
        for lk in l3g["l3_links"]
        if {lk["source"], lk["target"]} == {by_hn["VES_MDF_CORE_BLDG_A"]["id"], by_hn["NES_MDF_CORE_BLDG_A"]["id"]}
    ]
    assert false_bridge == []

    conflict_types = {c["conflict_type"] for c in l3g["l3_conflicts"]}
    assert {"duplicate_gateway_ip", "intra_device_overlap", "mask_mismatch"}.issubset(conflict_types)
    dup_c = next(c for c in l3g["l3_conflicts"] if c["conflict_type"] == "duplicate_gateway_ip")
    assert dup_c["active_hub_route_target"] == "VES_MDF_CORE_BLDG_A"

    assert "VES" in l3g["site_vlan_groups"]
    assert "Student & Wireless" in l3g["site_vlan_groups"]["VES"]
    assert l3g["dhcp_relay_targets"]["DO"] == ["10.0.0.3"]

    # Render HTML and verify all 3 views + legend + single-line GRAPH payload
    out_files = render_topology_deliverables(devices, str(tmp_path))
    html = (tmp_path / "topology_interactive.html").read_text(encoding="utf-8")
    assert len(out_files) == 1
    assert "Backbone &amp; WAN" in html
    assert "L2 Physical" in html
    assert "L3 Routed" in html
    assert "SVI &amp; Subnet Table" in html
    assert "Direct LLDP/CDP Uplink" in html
    assert "Metro-E / Carrier WAN" in html
    m = re.search(r"const GRAPH = (\{.*?\});", html)
    assert m is not None
    parsed = json.loads(m.group(1))
    assert parsed["l3_graph"]["l3_conflicts"]
    assert len(parsed["ap_nodes"]) == 1


def test_small_lab_l3_and_mac_inferred_passthrough():
    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "opnsense.lan.internal",
            "vendor": "OPNsense",
            "model": "OPNsense Gateway",
            "device_type": "firewall",
            "device_persona": "firewall",
            "status": "success",
            "l3_interfaces": [
                {"interface": "vtnet0", "ip_address": "192.168.1.1/24", "status": "up"},
                {"interface": "vtnet1", "ip_address": "107.146.224.70/19", "status": "up"},
                {"interface": "vtnet2", "ip_address": "172.16.1.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "107.146.224.1", "interface": "vtnet1"},
            ],
            "neighbors": [
                {
                    "local_port": "eth0",
                    "remote_device": "desktop-switch",
                    "remote_port": "ge-0/0/0",
                    "remote_ip": "192.168.1.3",
                    "device_type": "switch",
                    "l2_accuracy": "mac_inferred",
                }
            ],
        },
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "desktop-switch",
            "vendor": "Juniper Networks",
            "model": "ex2300-c-12p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.fc:33:42:e6:b5:bb"},
            "l3_interfaces": [{"interface": "irb.0", "ip_address": "192.168.1.3/24", "status": "up"}],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "192.168.1.1", "interface": "irb.0"}],
            "ports": {"ge-0/0/2": {"stp_state": "BLK"}},
            "neighbors": [
                {
                    "local_port": "ge-0/0/0",
                    "remote_device": "opnsense.lan.internal",
                    "remote_port": "eth0",
                    "remote_ip": "192.168.1.1",
                    "device_type": "firewall",
                    "l2_accuracy": "mac_inferred",
                },
                {
                    "local_port": "ge-0/0/1",
                    "remote_device": "Office-AP",
                    "remote_port": "eth0",
                    "remote_ip": "192.168.1.215",
                    "device_type": "ap",
                },
                {
                    "local_port": "ge-0/0/2",
                    "remote_device": "FRR-Router-01",
                    "remote_port": "eth0",
                    "remote_ip": "192.168.1.254",
                    "device_type": "router",
                    "l2_accuracy": "virtual_passthrough",
                },
            ],
        },
        "192.168.1.215": {
            "ip": "192.168.1.215",
            "hostname": "Office-AP",
            "site_code": "CORE",
            "vendor": "Aruba",
            "model": "Aruba AP-215",
            "device_type": "ap",
            "device_persona": "ap",
            "status": "success",
            "l3_interfaces": [{"interface": "br0", "ip_address": "192.168.1.215/24", "status": "up"}],
            "neighbors": [],
        },
        "192.168.1.254": {
            "ip": "192.168.1.254",
            "hostname": "FRR-Router-01",
            "site_code": "FRR",
            "vendor": "FRRouting",
            "model": "FRRouting Linux Daemon",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [
                {"interface": "eth0", "ip_address": "192.168.1.254/24", "status": "up"},
                {"interface": "eth1", "ip_address": "172.16.1.10/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "kernel", "next_hop": "192.168.1.1", "interface": "eth0"},
            ],
            "neighbors": [],
        },
    }
    model = build_topology_graph_model(devices)
    by_hn = {n["hostname"]: n for n in model["nodes"]}

    # Crawled AP stays in model["nodes"] AND wireless_aps
    assert "Office-AP" in by_hn
    assert model["metadata"]["total_aps"] == 1

    # Small lab includes 1-SVI switch in L3 graph, and shared LAN is NOT an overlapping_site_subnet conflict
    l3_hosts = {n["hostname"] for n in model["l3_graph"]["l3_nodes"]}
    assert {"opnsense.lan.internal", "desktop-switch", "FRR-Router-01", "ISP Gateway (107.146.224.1)"}.issubset(
        l3_hosts
    )
    assert model["l3_graph"]["l3_conflicts"] == []

    # Transport types & STP BLK badge
    edges_by_pair = {tuple(sorted((e["source"], e["target"]))): e for e in model["edges"]}
    mac_edge = edges_by_pair[tuple(sorted((by_hn["opnsense.lan.internal"]["id"], by_hn["desktop-switch"]["id"])))]
    assert mac_edge["transport_type"] == "mac_inferred"
    assert mac_edge["display_badge"] == "MAC Inferred"

    blk_edge = edges_by_pair[tuple(sorted((by_hn["desktop-switch"]["id"], by_hn["FRR-Router-01"]["id"])))]
    assert blk_edge["transport_type"] == "virtual_passthrough"
    assert blk_edge["is_blocked"] is True
    assert blk_edge["display_badge"] == "STP BLK"


def test_colliding_generic_hostnames_remain_distinct_nodes():
    devices = {
        "10.29.55.12": {"hostname": "Unknown", "model": "SwitchA", "device_type": "switch", "neighbors": []},
        "10.29.55.14": {"hostname": "Unknown", "model": "SwitchB", "device_type": "switch", "neighbors": []},
    }
    model = build_topology_graph_model(devices)
    assert model["metadata"]["total_nodes"] == 2
    assert {n["model"] for n in model["nodes"]} == {"SwitchA", "SwitchB"}
    assert len({n["id"] for n in model["nodes"]}) == 2


def test_testbed_server_exclusion_l3_egress_direction_port_dedup_and_site_norm():
    # 1. Linux hypervisors / monitoring hosts reporting "FRRouting Linux Host" must classify as endpoint
    assert (
        classify_neighbor_node(
            "pve",
            {"platform": "FRRouting Linux Host (Debian GNU/Linux 13 (trixie))", "device_type": "unknown"},
        )
        == "endpoint"
    )
    assert (
        classify_neighbor_node(
            "librenms",
            {"platform": "FRRouting Linux Host (Debian GNU/Linux 13 (trixie))", "device_type": "server"},
        )
        == "endpoint"
    )
    assert (
        classify_neighbor_node(
            "FRR-Router-01",
            {"platform": "FRRouting Linux Daemon", "device_type": "router"},
        )
        == "router"
    )

    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "opnsense.lan.andrews.best",
            "device_type": "firewall",
            "device_persona": "firewall",
            "status": "success",
            "l3_interfaces": [
                {"interface": "vtnet0", "ip_address": "192.168.1.1/24", "status": "up"},
                {"interface": "vtnet1", "ip_address": "107.146.224.70/19", "status": "up"},
                {"interface": "vtnet2", "ip_address": "172.16.1.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "107.146.224.1", "interface": "vtnet1"},
            ],
            "neighbors": [],
        },
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "desktop-switch",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "irb.0", "ip_address": "192.168.1.3/24", "status": "up"}],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "192.168.1.1", "interface": "irb.0"}],
            "neighbors": [
                {
                    "local_port": "ge-0/0/0",
                    "remote_device": "FortiGate-VM64-KVM",
                    "remote_port": "",
                    "remote_ip": "192.168.1.252",
                    "device_type": "firewall",
                    "l2_accuracy": "mac_inferred",
                },
                {
                    "local_port": "ge-0/0/0",
                    "remote_device": "pve",
                    "remote_port": "enp5s0",
                    "remote_ip": "192.168.1.12",
                    "platform": "FRRouting Linux Host (Debian GNU/Linux 13 (trixie))",
                    "device_type": "server",
                    "l2_accuracy": "mac_inferred",
                },
            ],
        },
        "192.168.1.252": {
            "ip": "192.168.1.252",
            "hostname": "FortiGate-VM64-KVM",
            "device_type": "firewall",
            "device_persona": "firewall",
            "status": "success",
            "l3_interfaces": [{"interface": "port1", "ip_address": "192.168.1.252/24", "status": "up"}],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "S*", "next_hop": "192.168.1.1", "interface": "port1"}],
            "neighbors": [
                {
                    "local_port": "eth0",
                    "remote_device": "desktop-switch",
                    "remote_port": "ge-0/0/0",
                    "remote_ip": "192.168.1.3",
                    "device_type": "switch",
                    "l2_accuracy": "mac_inferred",
                }
            ],
        },
        "192.168.1.253": {
            "ip": "192.168.1.253",
            "hostname": "Arista-Test-Switch",
            "site_code": "ARISTA",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "Management1", "ip_address": "192.168.1.253/24", "status": "up"}],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "192.168.1.1"}],
            "neighbors": [],
        },
        "192.168.1.254": {
            "ip": "192.168.1.254",
            "hostname": "FRR-Router-01",
            "site_code": "FRR",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [
                {"interface": "eth0", "ip_address": "192.168.1.254/24", "status": "up"},
                {"interface": "eth1", "ip_address": "172.16.1.10/24", "status": "up"},
            ],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "kernel", "next_hop": "192.168.1.1", "interface": "eth0"}],
            "neighbors": [],
        },
    }
    model = build_topology_graph_model(devices)
    by_hn = {n["hostname"]: n for n in model["nodes"]}

    # 1. Server pve excluded completely
    assert "pve" not in by_hn

    # 2. Vendor prefixes FRR/ARISTA collapse into CORE on single-LAN testbed
    assert model["sites"] == ["CORE"]
    assert by_hn["FRR-Router-01"]["site"] == "CORE"
    assert by_hn["Arista-Test-Switch"]["site"] == "CORE"

    # 3. FortiGate <-> desktop-switch deduplicates empty remote_port with reciprocal eth0 <-> ge-0/0/0
    fg_edge = next(
        e
        for e in model["edges"]
        if {e["source"], e["target"]} == {by_hn["FortiGate-VM64-KVM"]["id"], by_hn["desktop-switch"]["id"]}
    )
    assert fg_edge["port_pairs"] == ["eth0 ↔ ge-0/0/0"]

    # 4. L3 Egress arrows point TOWARD opnsense, and 172.16.1.0/24 stays connected_transit
    opn_id = by_hn["opnsense.lan.andrews.best"]["id"]
    frr_id = by_hn["FRR-Router-01"]["id"]
    fg_id = by_hn["FortiGate-VM64-KVM"]["id"]
    l3_links = model["l3_graph"]["l3_links"]

    frr_192 = next(
        lk
        for lk in l3_links
        if {lk["source"], lk["target"]} == {frr_id, opn_id} and lk["transit_cidr"] == "192.168.1.0/24"
    )
    assert frr_192["source"] == frr_id
    assert frr_192["target"] == opn_id
    assert frr_192["direction"] == "egress_upstream"
    assert frr_192["routing_mechanism"] == "static_default"

    fg_192 = next(
        lk
        for lk in l3_links
        if {lk["source"], lk["target"]} == {fg_id, opn_id} and lk["transit_cidr"] == "192.168.1.0/24"
    )
    assert fg_192["source"] == fg_id
    assert fg_192["target"] == opn_id
    assert fg_192["direction"] == "egress_upstream"

    frr_172 = next(
        lk
        for lk in l3_links
        if {lk["source"], lk["target"]} == {frr_id, opn_id} and lk["transit_cidr"] == "172.16.1.0/24"
    )
    assert frr_172["routing_mechanism"] == "connected_transit"
    assert frr_172["routed_prefixes"] == []
    assert frr_172["transport_type"] == "l3_routed"

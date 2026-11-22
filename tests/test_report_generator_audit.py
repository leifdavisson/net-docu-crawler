# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report_generator import (
    generate_cabling_matrix,
    generate_master_network_analysis_migration_blueprint,
)


def test_cabling_matrix_exports_port_profiles(tmp_path):
    devices = {
        "10.0.0.10": {
            "hostname": "DO-Main-BLDG",
            "device_persona": "switch",
            "interfaces_detail": {
                "B1": {
                    "status": "up",
                    "description": "Uplink to DO-IDF2-Power",
                    "speed": "1000",
                    "duplex": "full",
                },
                "A1": {
                    "status": "up",
                    "description": "User port",
                    "speed": "1000",
                    "duplex": "full",
                },
            },
            "port_profiles": {
                "B1": {
                    "mode": "trunk",
                    "access_vlan": "",
                    "voice_vlan": "",
                    "native_vlan": "1",
                    "allowed_vlans": ["3", "10", "100", "101"],
                    "lag_group": "Trk1",
                    "lacp_mode": "active",
                },
                "A1": {
                    "mode": "access",
                    "access_vlan": "100",
                    "voice_vlan": "2008",
                    "native_vlan": "",
                    "allowed_vlans": [],
                    "lag_group": "",
                    "lacp_mode": "",
                },
            },
            "neighbors": [
                {
                    "local_port": "B1",
                    "remote_device": "DO-IDF2-Power",
                    "remote_port": "24",
                    "platform": "HP ProCurve",
                }
            ],
        }
    }

    out_csv = tmp_path / "migration_cabling_matrix.csv"
    generate_cabling_matrix(devices, str(out_csv))

    with open(out_csv, encoding="utf-8") as f:
        rows = {r["Source Port"]: r for r in csv.DictReader(f)}

    assert rows["B1"]["Mode"] == "trunk"
    assert rows["B1"]["VLAN"] == "Trunk (3,10,100,101)"
    assert rows["B1"]["Native VLAN"] == "1"
    assert rows["B1"]["Allowed VLANs"] == "3,10,100,101"
    assert rows["B1"]["LAG Group"] == "Trk1"
    assert rows["B1"]["LACP Mode"] == "active"
    assert rows["B1"]["Neighbor Hostname"] == "DO-IDF2-Power"

    assert rows["A1"]["Mode"] == "access"
    assert rows["A1"]["VLAN"] == "100"
    assert rows["A1"]["Access VLAN"] == "100"
    assert rows["A1"]["Voice VLAN"] == "2008"


def test_migration_report_no_fabricated_defaults(tmp_path):
    devices = {
        "10.0.0.10": {
            "hostname": "SW-TEST-01",
            "device_persona": "switch",
            "model": "EX3400-48P",
            "serial": "ABC123456",
            "interfaces_detail": {"ge-0/0/1": {"status": "up", "speed": "1000", "duplex": "full"}},
            "port_profiles": {},
            "poe": {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0},
            "stp": {"enabled": True, "is_root": True, "vlans": {}},
            "fhrp": [],
            "routes": [],
            "l3_interfaces": [],
            "neighbors": [],
        }
    }

    out_md = tmp_path / "migration_architecture_report.md"
    generate_master_network_analysis_migration_blueprint(devices, str(out_md))
    content = out_md.read_text(encoding="utf-8")

    # Must not fabricate 370W / 45W PoE budgets
    assert "370.0W" not in content
    assert "45.0W" not in content
    # Must not fabricate STP defaults when missing
    assert "`32768` (Default)" not in content
    assert "Active (Error-Disable on Violation)" not in content
    assert "Unverified Root (Missing Bridge ID)" in content
    # Must not fabricate generic FHRP rows
    assert "gateway-01.corp.internal" not in content
    assert "No FHRP (HSRP / VRRP / CARP) groups were discovered" in content


def test_case_insensitive_trunk_mac_filter_and_l3_svi_join(tmp_path):
    import csv

    import report_generator

    dev = {
        "hostname": "DO-Main-BLDG",
        "ip": "10.1.0.1",
        "status": "success",
        "device_type": "switch",
        "device_persona": "switch",
        "site_code": "DO",
        "model": "HP 5412zl",
        "interfaces_detail": {"b1": {"status": "up"}, "a1": {"status": "up"}},
        "l3_interfaces": [{"interface": "Audio", "ip_address": "192.168.1.1/24", "status": "up"}],
        "vlans": {"3": {"id": "3", "name": "Audio", "svi_interface": "Audio", "voice": False}},
        "ports": {
            "b1": {"mode": "trunk", "neighbor_type": "switch"},
            "a1": {"mode": "access", "access_vlan": "3", "neighbor_type": ""},
        },
        "mac_table": [
            {"interface": "B1", "mac": "aa:bb:cc:00:00:01", "vlan": "3"},
            {"interface": "a1", "mac": "aa:bb:cc:00:00:02", "vlan": "3"},
        ],
        "routes": [
            {"subnet": "192.168.1.1/32", "protocol": "Local", "next_hop": "Local", "interface": "Audio"},
            {"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "10.1.0.254", "interface": "DO"},
        ],
        "neighbors": [],
        "arp_table": [],
        "raw_config": "",
    }
    ep_csv = str(tmp_path / "ep.csv")
    report_generator.generate_port_endpoint_mapping({"10.1.0.1": dev}, ep_csv)
    with open(ep_csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["Port"] == "a1"

    l3_md = str(tmp_path / "l3.md")
    report_generator.generate_l3_diagram({"10.1.0.1": dev}, l3_md)
    with open(l3_md, encoding="utf-8") as f:
        l3_txt = f.read()
    assert "| DO-Main-BLDG | Audio | 3 | Audio |" in l3_txt
    assert "192.168.1.1/32" not in l3_txt


def test_physical_links_link_class_export(tmp_path):
    import csv

    import report_generator
    from net_docu_crawler.topology_resolver import DeviceRegistry

    reg = DeviceRegistry()
    reg.add_bidirectional_link("SW1", "Gi1/0/1", "SW2", "Gi1/0/2", link_class="infra_uplink")
    reg.add_bidirectional_link("SW1", "Gi1/0/3", "cam-01", "eth0", link_class="edge_endpoint")
    dev = {
        "hostname": "SW1",
        "ip": "10.0.0.1",
        "status": "success",
        "ports": {},
        "vlans": {},
        "l3_interfaces": [],
        "poe": {},
    }
    report_generator.export_layered_csvs([dev], reg, str(tmp_path))
    with open(tmp_path / "03_correlated" / "physical_links.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    classes = {r["node_b"] if r["node_a"] == "SW1" else r["node_a"]: r["link_class"] for r in rows}
    assert classes["SW2"] == "infra_uplink"
    assert classes["cam-01"] == "edge_endpoint"


def test_live_report_collapses_access_internal_host_routes_and_physical_links_transport_csv(tmp_path):
    import csv

    import report_generator
    from net_docu_crawler.topology_resolver import DeviceRegistry

    routes = [
        {"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "10.250.5.1", "interface": "irb.1050"},
        *[
            {
                "subnet": f"10.5.192.{i}/32",
                "protocol": "Access-internal",
                "next_hop": "10.5.192.1",
                "interface": "irb.2052",
            }
            for i in range(10, 40)
        ],
        *[
            {
                "subnet": f"10.5.128.{i}/32",
                "protocol": "Access-internal",
                "next_hop": "10.5.128.1",
                "interface": "irb.10",
            }
            for i in range(10, 30)
        ],
    ]
    devices = {
        "10.250.5.2": {
            "hostname": "VES_MDF_CORE_BLDG_A",
            "ip": "10.250.5.2",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "interfaces_detail": {"xe-0/0/22": {"status": "up"}},
            "l3_interfaces": [{"interface": "irb.1050", "ip_address": "10.250.5.2/30", "status": "up"}],
            "routes": routes,
        }
    }
    live_md = tmp_path / "live_report.md"
    report_generator.generate_network_analysis_report(devices, output_path=str(live_md))
    live_txt = live_md.read_text(encoding="utf-8")
    assert "`0.0.0.0/0`" in live_txt
    assert (
        "*(30 `/32` Access-internal subscriber/host routes summarized)* | Access-internal | - | irb.2052 |" in live_txt
    )
    assert "*(20 `/32` Access-internal subscriber/host routes summarized)* | Access-internal | - | irb.10 |" in live_txt
    assert "10.5.192.15/32" not in live_txt

    reg = DeviceRegistry()
    reg.add_bidirectional_link(
        "DO-Main-BLDG",
        "C1",
        "VES_MDF_CORE_BLDG_A",
        "xe-0/0/22",
        link_type="wan_carrier",
        link_class="infra_uplink",
        transport_type="metro_ethernet",
        evidence="wan_carrier_arp_route",
    )
    reg.links[0]["extra_ignored_field"] = "should_not_crash"
    report_generator.export_layered_csvs([devices["10.250.5.2"]], reg, str(tmp_path))
    with open(tmp_path / "03_correlated" / "physical_links.csv", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["transport_type"] == "metro_ethernet"
    assert rows[0]["evidence"] == "wan_carrier_arp_route"

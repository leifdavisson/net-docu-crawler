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

import os

import report_generator


def test_unique_devices():
    devices = {
        "192.168.1.10": {"hostname": "switch-1", "serial": "SN123", "ip": "192.168.1.10"},
        "192.168.1.11": {"hostname": "switch-1", "serial": "SN123", "ip": "192.168.1.11"},
        "192.168.1.20": {"hostname": "switch-2", "serial": "SN456", "ip": "192.168.1.20"},
    }
    unique = report_generator.get_unique_devices(devices)
    assert len(unique) == 2
    assert any(ip in unique for ip in ["192.168.1.10", "192.168.1.11"])
    assert "192.168.1.20" in unique


def test_generate_all_reports(tmp_path):
    devices = {
        "192.168.1.10": {
            "ip": "192.168.1.10",
            "status": "success",
            "mgmt_method": "SSH",
            "hostname": "core-sw-01",
            "vendor": "Juniper Networks",
            "model": "ex2300-c-12p",
            "serial": "HV0219090020",
            "firmware": "23.4R2",
            "mac_address": "fc:33:42:e6:b5:99",
            "device_type": "switch",
            "stp": {"enabled": True, "is_root": True, "vlans": {}},
            "l3_interfaces": [{"interface": "irb.0", "ip_address": "192.168.1.10/24", "status": "up"}],
            "interfaces_detail": {
                "ge-0/0/0": {"status": "up", "speed": "1Gb/s", "duplex": "Full", "description": "Uplink"}
            },
            "neighbors": [
                {
                    "local_port": "ge-0/0/0",
                    "remote_device": "edge-rtr-01",
                    "remote_port": "ether1",
                    "remote_ip": "192.168.1.20",
                    "platform": "MikroTik RouterOS",
                    "device_type": "router",
                }
            ],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "192.168.1.1", "interface": "irb.0"}],
            "services": {"dns_servers": ["1.1.1.1"], "ntp_servers": ["time.google.com"]},
            "raw_config": "set system host-name core-sw-01\n",
        },
        "192.168.1.20": {
            "ip": "192.168.1.20",
            "status": "success",
            "mgmt_method": "SSH",
            "hostname": "edge-rtr-01",
            "vendor": "MikroTik",
            "model": "CHR",
            "serial": "CHR-SN-001",
            "firmware": "7.16.1",
            "mac_address": "bc:24:11:aa:bb:cc",
            "device_type": "router",
            "stp": {"enabled": False, "vlans": {}},
            "l3_interfaces": [{"interface": "ether1", "ip_address": "192.168.1.20/24", "status": "up"}],
            "interfaces_detail": {"ether1": {"status": "up", "speed": "1Gbps", "duplex": "Full", "description": ""}},
            "neighbors": [],
            "routes": [],
            "services": {},
            "raw_config": "/system identity set name=edge-rtr-01\n",
        },
    }

    csv_path = str(tmp_path / "asset_inventory.csv")
    report_generator.generate_asset_inventory(devices, csv_path)
    assert os.path.isfile(csv_path)

    cable_path = str(tmp_path / "cabling.csv")
    report_generator.generate_cabling_matrix(devices, cable_path)
    assert os.path.isfile(cable_path)

    l2_path = str(tmp_path / "L2_diagram.md")
    report_generator.generate_l2_diagram(devices, l2_path)
    assert os.path.isfile(l2_path)

    baseline_path = str(tmp_path / "baseline.json")
    report_generator.save_baseline_state(devices, baseline_path)
    assert os.path.isfile(baseline_path)

    verif_path = str(tmp_path / "verification.md")
    report_generator.compare_baseline_state(devices, baseline_path, output_path=verif_path)
    assert os.path.isfile(verif_path)


def test_multivendor_report_alignment_no_false_positives(tmp_path):
    """
    Verifies multi-vendor report alignment:
      1. Crawled AP/Firewall nodes are NOT overwritten as plain access switches when referenced by neighbors.
      2. Non-24 WAN CIDRs (e.g. /19) are preserved accurately in L3 diagrams.
      3. Shared LAN subnets (192.168.1.0/24 across multiple devices) do NOT trigger false overlap warnings,
         whereas true unequal CIDR overlaps (/24 vs /25) and duplicate IPs DO trigger warnings.
      4. Firewalls, routers, and APs do NOT trigger false 'Spanning Tree is DISABLED' alarms.
    """
    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "opnsense.lan",
            "model": "OPNsense Gateway",
            "device_type": "firewall",
            "stp": {"enabled": False, "vlans": {}},
            "l3_interfaces": [
                {"interface": "vtnet0", "ip_address": "192.168.1.1/24", "status": "up"},
                {"interface": "vtnet1", "ip_address": "100.64.224.70/19", "status": "up"},
            ],
            "interfaces_detail": {"vtnet0": {"status": "up"}, "vtnet1": {"status": "up"}},
            "neighbors": [],
            "routes": [],
            "services": {"dns_servers": ["1.1.1.1"], "ntp_servers": ["0.opnsense.pool.ntp.org"]},
        },
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "core-switch-01",
            "model": "ex2300-c-12p",
            "device_type": "switch",
            "stp": {"enabled": True, "vlans": {}},
            "l3_interfaces": [
                {"interface": "irb.0", "ip_address": "192.168.1.3/24", "status": "up"},
            ],
            "interfaces_detail": {"ge-0/0/3": {"status": "up"}},
            "neighbors": [
                {
                    "local_port": "ge-0/0/3",
                    "remote_device": "ap-office-01",
                    "remote_port": "eth0",
                    "remote_ip": "192.168.1.215",
                    "remote_platform": "ArubaOS (MODEL: 215)",
                    "device_type": "ap",
                }
            ],
            "routes": [],
            "services": {"dns_servers": ["192.168.1.1"], "ntp_servers": ["0.juniper.pool.ntp.org"]},
        },
        "192.168.1.215": {
            "ip": "192.168.1.215",
            "hostname": "Office",
            "model": "Aruba AP-215",
            "device_type": "ap",
            "stp": {"enabled": False, "vlans": {}},
            "l3_interfaces": [{"interface": "br0", "ip_address": "192.168.1.215", "status": "up"}],
            "interfaces_detail": {"eth0": {"status": "up"}},
            "neighbors": [],
            "routes": [],
            "services": {},
        },
    }

    l2_path = str(tmp_path / "L2.md")
    l3_path = str(tmp_path / "L3.md")
    rep_path = str(tmp_path / "report.md")

    report_generator.generate_l2_diagram(devices, l2_path)
    report_generator.generate_l3_diagram(devices, l3_path)
    report_generator.generate_network_analysis_report(devices, rep_path)

    with open(l2_path, encoding="utf-8") as f:
        l2_txt = f.read()
    with open(l3_path, encoding="utf-8") as f:
        l3_txt = f.read()
    with open(rep_path, encoding="utf-8") as f:
        rep_txt = f.read()

    # Office node must retain its AP class and never be redefined as plain ["Office"] access
    assert 'sw_2["Office<br/>(Aruba AP-215)"]' in l2_txt
    assert "class sw_2 ap;" in l2_txt
    assert 'sw_2["Office"]' not in l2_txt
    assert "class sw_2 access;" not in l2_txt
    assert "Total Discovered Access Points: **1**" in l2_txt

    # /19 WAN subnet must be preserved accurately
    assert "100.64.224.0/19" in l3_txt
    assert "100.64.224.0/24" not in l3_txt

    # No false STP alarms on firewall/AP and no false overlap warnings on shared 192.168.1.0/24
    assert "Spanning Tree is DISABLED" not in rep_txt
    assert "Overlap Warning" not in rep_txt
    assert "CRITICAL IP CONFLICT" not in rep_txt


def test_asset_inventory_partial_unauthenticated_and_custom_mgmt_method(tmp_path):
    devices = {
        "192.168.1.10": {
            "hostname": "SW-CUSTOM",
            "ip": "192.168.1.10",
            "status": "success",
            "mgmt_method": "SSH:2222",
            "vendor": "HPProCurve",
            "device_type": "switch",
            "model": "J9727A",
            "firmware": "WB.16.10",
            "serial": "SG123",
            "mac_address": "38:63:bb:57:ca:40",
            "l3_interfaces": [],
            "interfaces_detail": {},
            "neighbors": [],
            "routes": [],
            "stp": {"enabled": True, "is_root": True, "vlans": {}},
            "services": {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []},
            "raw_config": "",
        },
        "192.168.1.50": {
            "hostname": "192.168.1.50",
            "ip": "192.168.1.50",
            "status": "unauthenticated",
            "mgmt_method": "Telnet",
            "vendor": "cisco",
            "device_type": "unknown",
            "model": "Cisco Telnet Login",
            "firmware": "Unknown",
            "serial": "Unknown",
            "mac_address": "aa:bb:cc:dd:ee:01",
            "l3_interfaces": [],
            "interfaces_detail": {},
            "neighbors": [],
            "routes": [],
            "stp": {"enabled": False, "is_root": False, "vlans": {}},
            "services": {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []},
            "raw_config": "",
        },
        "192.168.1.60": {
            "hostname": "192.168.1.60",
            "ip": "192.168.1.60",
            "status": "unsupported",
            "mgmt_method": "SSH",
            "vendor": "Synology",
            "device_type": "unknown",
            "model": "Synology Device",
            "firmware": "Unknown",
            "serial": "Unknown",
            "mac_address": "aa:bb:cc:dd:ee:02",
            "l3_interfaces": [],
            "interfaces_detail": {},
            "neighbors": [],
            "routes": [],
            "stp": {"enabled": False, "is_root": False, "vlans": {}},
            "services": {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []},
            "raw_config": "",
        },
    }

    inv_path = str(tmp_path / "asset_inventory.csv")
    rep_path = str(tmp_path / "report.md")
    report_generator.generate_asset_inventory(devices, inv_path)
    report_generator.generate_network_analysis_report(devices, rep_path)

    with open(inv_path, encoding="utf-8") as f:
        inv_txt = f.read()
    with open(rep_path, encoding="utf-8") as f:
        rep_txt = f.read()

    assert "SW-CUSTOM,192.168.1.10" in inv_txt
    assert "SSH:2222" in inv_txt
    assert (
        "192.168.1.50,192.168.1.50,aa:bb:cc:dd:ee:01,Unknown,Cisco Telnet Login,Unknown,Unknown,Unauthenticated,Telnet"
        in inv_txt
    )
    assert (
        "192.168.1.60,192.168.1.60,aa:bb:cc:dd:ee:02,Unknown,Synology Device,Unknown,Unknown,Unsupported,SSH" in inv_txt
    )
    assert "Telnet" in rep_txt


def test_bom_sizing_and_target_vendor_migration_configs(tmp_path):
    devices = {
        "192.168.1.220": {
            "hostname": "SW-2920-24G",
            "ip": "192.168.1.220",
            "status": "success",
            "mgmt_method": "SSH",
            "vendor": "HPProCurve",
            "device_type": "switch",
            "model": "J9727A",
            "interfaces_detail": {"1": {"status": "up"}, "2": {"status": "down"}},
            "l3_interfaces": [{"interface": "VLAN1", "ip_address": "192.168.1.220/24"}],
            "poe": {"total_power_watts": 370.0, "used_power_watts": 45.2, "ports": {"1": {"power_watts": 45.2}}},
            "optics": [{"port": "23", "type": "SFP-SX"}, {"port": "24", "type": "SFP-SX"}],
            "port_profiles": {"1": {"mode": "access", "access_vlan": "10"}},
            "services": {"dns_servers": ["192.168.1.1"], "ntp_servers": ["192.168.1.1"]},
        }
    }

    bom_path = str(tmp_path / "bom.csv")
    junos_path = str(tmp_path / "target_juniper.md")
    report_generator.generate_bom_hardware_sizing(devices, bom_path)
    report_generator.generate_target_migration_configs(devices, target_vendor="juniper", output_path=junos_path)

    with open(bom_path, encoding="utf-8") as f:
        bom_txt = f.read()
    with open(junos_path, encoding="utf-8") as f:
        junos_txt = f.read()

    assert "SW-2920-24G,192.168.1.220,HPProCurve,J9727A,switch,2,1,370.0,45.2,1,2,SFP-SX:2,EX2300-C-12P" in bom_txt
    assert "set system host-name SW-2920-24G" in junos_txt
    assert "set interfaces 1 unit 0 family ethernet-switching vlan members 10" in junos_txt


def test_generate_l2_diagram_colliding_hostnames(tmp_path):
    """Verify two crawled devices sharing a generic hostname get distinct Mermaid node IDs."""
    devices = {
        "10.29.55.12": {"hostname": "Unknown", "model": "SwitchA", "device_type": "switch", "neighbors": []},
        "10.29.55.14": {"hostname": "Unknown", "model": "SwitchB", "device_type": "switch", "neighbors": []},
    }
    l2_path = str(tmp_path / "L2.md")
    report_generator.generate_l2_diagram(devices, l2_path)
    with open(l2_path, encoding="utf-8") as f:
        txt = f.read()
    assert 'sw_0["Unknown<br/>(SwitchA)"]' in txt
    assert 'sw_1["Unknown<br/>(SwitchB)"]' in txt


def test_blueprint_up_only_link_errors_and_optic_serials(tmp_path):
    """Verify link errors filter to UP ports only and optics table includes Serial Number."""
    devices = {
        "10.0.0.1": {
            "hostname": "SW-EDGE-01",
            "ip": "10.0.0.1",
            "status": "success",
            "vendor": "Cisco",
            "device_type": "switch",
            "model": "WS-C3750G-12S",
            "interfaces_detail": {
                "GigabitEthernet1/0/1": {
                    "status": "up",
                    "speed": "100Mb/s",
                    "duplex": "Full",
                    "input_errors": 12,
                    "crc": 3,
                    "output_errors": 0,
                },
                "GigabitEthernet1/0/2": {
                    "status": "down",
                    "speed": "Auto",
                    "duplex": "Auto",
                    "input_errors": 99,
                    "crc": 50,
                    "output_errors": 0,
                },
            },
            "optics": [
                {
                    "port": "Gi1/0/12",
                    "part_number": "GLC-SX-MMD",
                    "serial": "FNS18120999",
                    "type": "1000BASE-SX SFP",
                    "tx_power_dbm": -4.5,
                    "rx_power_dbm": -5.2,
                    "temperature_c": 34.2,
                    "voltage_v": 3.3,
                }
            ],
        }
    }
    live_path = str(tmp_path / "live_report.md")
    bp_path = str(tmp_path / "Network_Analysis.md")
    report_generator.generate_network_analysis_report(devices, output_path=live_path)
    report_generator.generate_master_network_analysis_migration_blueprint(devices, output_path=bp_path)
    with open(live_path, encoding="utf-8") as f:
        live_txt = f.read()
    with open(bp_path, encoding="utf-8") as f:
        bp_txt = f.read()
    assert "GigabitEthernet1/0/1" in live_txt
    assert "Speed restricted to **100Mb/s**" in live_txt
    assert "Input Errors: `12`, CRCs: `3`" in live_txt
    assert "GigabitEthernet1/0/2" not in live_txt
    assert "| **SW-EDGE-01** | `Gi1/0/12` | `GLC-SX-MMD` | `FNS18120999` |" in bp_txt


def test_port_utilization_filters_zero_port_and_asset_inventory_types(tmp_path):
    import csv

    devices = {
        "10.1.0.1": {
            "hostname": "DO-Main-BLDG",
            "status": "success",
            "device_type": "switch",
            "model": "HP 5412zl (J8698A)",
            "l3_interfaces": [{"interface": f"VLAN{i}", "ip_address": f"10.1.{i}.1/24"} for i in range(6)],
            "routes": [{"subnet": f"10.2.{i}.0/24", "next_hop": "10.1.0.2"} for i in range(12)],
            "interfaces_detail": {
                "A1": {"status": "up"},
                "A2": {"status": "down"},
            },
        },
        "10.1.0.225": {
            "hostname": "10.1.0.225",
            "status": "unsupported",
            "device_type": "display",
            "model": "Apple AirPlay Display",
            "interfaces_detail": {},
        },
        "10.1.0.180": {
            "hostname": "10.1.0.180",
            "status": "unsupported",
            "device_type": "av_control",
            "model": "Extron AV Controller",
            "interfaces_detail": {},
        },
    }
    live_path = str(tmp_path / "live_report.md")
    csv_path = str(tmp_path / "asset_inventory.csv")
    report_generator.generate_network_analysis_report(devices, output_path=live_path)
    report_generator.generate_asset_inventory(devices, output_path=csv_path)

    with open(live_path, encoding="utf-8") as f:
        live_txt = f.read()
    util_section = live_txt.split("### Interface Port Utilization Summary")[1].split("### ")[0]
    assert "| DO-Main-BLDG | 1 | 2 | 50.0% |" in util_section
    assert "| 10.1.0.225 |" not in util_section
    assert "| 10.1.0.180 |" not in util_section

    with open(csv_path, encoding="utf-8") as f:
        rows = {r["IP Address"]: r for r in csv.DictReader(f)}
    assert rows["10.1.0.1"]["Role"] == "Core"
    assert rows["10.1.0.225"]["Device Type"] == "Display"
    assert rows["10.1.0.180"]["Device Type"] == "AV Control"


def test_wireless_overlay_excludes_arubaos_switch_and_l3_svi_map_multi_ip(tmp_path):
    devices = {
        "192.168.1.220": {
            "ip": "192.168.1.220",
            "hostname": "SW-2920-24G",
            "vendor": "HP ProCurve / ArubaOS-S",
            "model": "HP 2920-24G-PoE+",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [
                {"interface": "DEFAULT_VLAN", "ip_address": "10.10.10.1/24", "status": "up"},
                {"interface": "DEFAULT_VLAN", "ip_address": "192.168.1.220/24", "status": "up"},
            ],
            "interfaces_detail": {},
            "neighbors": [],
            "routes": [],
            "vlans": {"1": {"name": "DEFAULT_VLAN"}},
        },
        "192.168.1.251": {
            "ip": "192.168.1.251",
            "hostname": "MikroTik",
            "vendor": "MikroTik",
            "model": "CHR",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "ether1", "ip_address": "192.168.1.251/24", "status": "up"}],
            "interfaces_detail": {},
            "neighbors": [
                {
                    "local_port": "ether1",
                    "remote_device": "SW-2920-24G",
                    "remote_port": "23",
                    "remote_ip": "192.168.1.220",
                    "platform": "HP ProCurve / ArubaOS-S HP 2920-24G-PoE+",
                },
                {
                    "local_port": "ether2",
                    "remote_device": "Office",
                    "remote_port": "eth0",
                    "remote_ip": "192.168.1.4",
                    "platform": "Aruba AP-215",
                    "device_type": "ap",
                },
            ],
            "routes": [],
        },
    }
    l2_path = str(tmp_path / "L2.md")
    l3_path = str(tmp_path / "L3.md")
    report_generator.generate_l2_diagram(devices, output_path=l2_path)
    report_generator.generate_l3_diagram(devices, output_path=l3_path)

    with open(l2_path, encoding="utf-8") as f:
        l2_txt = f.read()
    overlay = l2_txt.split("## Wireless Overlay Layout")[1].split("## ")[0]
    assert "Total Discovered Access Points: **1**" in overlay
    assert "SW-2920-24G" not in overlay
    assert "Office" in overlay

    with open(l3_path, encoding="utf-8") as f:
        l3_txt = f.read()
    assert "| SW-2920-24G | DEFAULT_VLAN | 1 | DEFAULT_VLAN | N/A | 10.10.10.1/24 | 10.10.10.0/24 | up |" in l3_txt
    assert "| SW-2920-24G | DEFAULT_VLAN | 1 | DEFAULT_VLAN | N/A | 192.168.1.220/24 | 192.168.1.0/24 | up |" in l3_txt


def test_l2_site_scoped_mermaid_has_single_header_and_compacts_oversized(tmp_path):
    import re

    devices = {}
    for idx in range(1, 25):
        site = "DO" if idx <= 12 else "MOT"
        ip = f"10.0.0.{idx}"
        peer_idx = idx + 1 if idx % 12 != 0 else idx - 1
        peer_site = "DO" if peer_idx <= 12 else "MOT"
        devices[ip] = {
            "ip": ip,
            "hostname": f"{site}-SW-{idx}",
            "site_code": site,
            "vendor": "Juniper Networks",
            "model": "ex2300",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [],
            "interfaces_detail": {"ge-0/0/1": {"status": "up"}},
            "neighbors": [
                {
                    "local_port": "ge-0/0/1",
                    "remote_device": f"{peer_site}-SW-{peer_idx}",
                    "remote_port": "ge-0/0/1",
                    "platform": "Juniper Networks ex2300",
                }
            ],
            "routes": [],
        }
    l2_path = str(tmp_path / "L2.md")
    report_generator.generate_l2_diagram(devices, output_path=l2_path)
    txt = open(l2_path, encoding="utf-8").read()
    blocks = re.findall(r"```mermaid\n(.*?)\n```", txt, re.S)
    assert len(blocks) >= 3
    for b in blocks:
        assert b.count("flowchart LR") == 1
    assert "## Collapsible Layer 2 Hierarchy Tree" in txt
    assert "<details><summary><strong>Site: DO</strong>" in txt

    # Verify oversized Mermaid block compaction drops ext_* leaf nodes
    big_block = ["```mermaid", "flowchart LR", '  sw_0["Core"]']
    big_block.extend([f'  ext_{i}["Leaf-{i}-" + "x"*200]' for i in range(250)])
    big_block.append("```")
    compacted = report_generator._compact_mermaid_block_if_oversized(big_block, max_chars=2000)
    joined = "\n".join(compacted)
    assert len(joined) < len("\n".join(big_block))
    assert "ext_summary" in joined


def test_trunk_audit_oui_role_and_manual_followup_report(tmp_path):
    devices = {
        "10.1.0.1": {
            "ip": "10.1.0.1",
            "hostname": "DO-Main-BLDG",
            "vendor": "HP ProCurve",
            "model": "HP 5412zl",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "interfaces_detail": {"B1": {"status": "up"}, "G1": {"status": "up"}},
            "neighbors": [
                {
                    "local_port": "G1",
                    "remote_device": "d65-000fd30aae2f",
                    "remote_port": "Ethernet0",
                    "remote_mac": "00:0f:d3:0a:ae:2f",
                },
            ],
        },
        "10.1.0.5": {
            "ip": "10.1.0.5",
            "hostname": "10.1.0.5",
            "status": "unauthenticated",
            "vendor": "openwrt",
        },
    }
    audit = {
        "summary": {
            "total_trunk_edges_evaluated": 2,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "info_count": 0,
            "total_findings": 2,
        },
        "findings": [
            {
                "Edge_ID": "d65-000fd30aae2f:Ethernet0<->do-main-bldg:G1",
                "Side_A_Host": "d65-000fd30aae2f",
                "Side_A_Port": "Ethernet0",
                "Side_B_Host": "do-main-bldg",
                "Side_B_Port": "G1",
                "Rule_ID": "ERR_UNCRAWLED_NEIGHBOR",
                "Severity": "MEDIUM",
                "Remediation_Hint": "Ignore phone",
            },
            {
                "Edge_ID": "do-main-bldg:B1<->sw-core:1",
                "Side_A_Host": "do-main-bldg",
                "Side_A_Port": "B1",
                "Side_B_Host": "sw-core",
                "Side_B_Port": "1",
                "Rule_ID": "TRK-001",
                "Severity": "CRITICAL",
                "Remediation_Hint": "Fix trunk",
            },
        ],
    }
    trunk_path = str(tmp_path / "trunk_vlan_audit.md")
    report_generator.generate_trunk_audit_report(audit, output_path=trunk_path, devices=devices)
    trunk_txt = open(trunk_path, encoding="utf-8").read()
    assert "Peer_OUI_Role" in trunk_txt
    assert "AP/Phone Edge Findings (Safe to Ignore): **1**" in trunk_txt
    assert "[Phone]" in trunk_txt

    followup_path = str(tmp_path / "manual_followup_report.md")
    report_generator.generate_manual_followup_report(devices, output_path=followup_path, trunk_audit=audit)
    f_txt = open(followup_path, encoding="utf-8").read()
    assert "# Manual Follow-Up & Field Verification Report" in f_txt
    assert (
        "Filtered out **1** AP/Phone edge finding(s); showing **1** switch-to-switch CRITICAL/HIGH trunk mismatch(es)."
        in f_txt
    )
    assert "`10.1.0.5`" in f_txt

    # Verify L2 diagram filters out VoIP phones, touchpanels, and PCs
    assert report_generator._is_non_infra_neighbor("d65-000fd30aae2f", {}) is True
    assert report_generator._is_non_infra_neighbor("SIP-T33G", {}) is True
    assert report_generator._is_non_infra_neighbor("TSW-770-C4426825C51C", {}) is True
    assert report_generator._is_non_infra_neighbor("AN-220-SW-R-8-POE", {"device_type": "switch"}) is False
    assert (
        report_generator._is_non_infra_neighbor(
            "DO-Main-Bldg-2", {"platform": "Hewlett Packard Enterprise", "device_type": "switch"}
        )
        is False
    )
    assert (
        report_generator._is_non_infra_neighbor(
            "172.31.5.199",
            {"platform": "Ruckus Wireless", "device_type": "unknown", "remote_mac": "60:d0:2c:10:4b:a0"},
        )
        is False
    )


def test_l2_and_l3_norris_multi_site_link_types_conflicts_and_wireless_overlay(tmp_path):
    """Verify multi-site L2/L3 diagrams, transport linkStyles, conflict nodes, Junos VLAN descriptions, and unknown-typed APs."""
    import re

    from net_docu_crawler.diagram_validator import validate_mermaid_block

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
                {"interface": "Spectrun-WBE", "ip_address": "10.250.8.1/30", "status": "up"},
                {"interface": "Spectrun-ODE", "ip_address": "10.250.4.1/30", "status": "up"},
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
                "B1": {"status": "up", "speed": "1Gb/s"},
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
                    "local_port": "B1",
                    "remote_device": "DO-Main-Bldg-2",
                    "remote_port": "50",
                    "platform": "Hewlett Packard Enterprise",
                    "device_type": "switch",
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
                    "remote_device": "WBE_MDF_CORE_BLDG_A",
                    "remote_port": "ge-0/0/23",
                    "remote_ip": "10.250.8.2",
                    "device_type": "switch",
                    "l2_accuracy": "wan_carrier_arp_route",
                    "transport_type": "metro_ethernet",
                    "carrier_cloud": "Spectrum Metro Ethernet",
                    "transit_vlan": "1051",
                    "transit_cidr": "10.250.8.0/30",
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
                    "local_port": "C1",
                    "remote_device": "ODE_MDF_CORE_BLDG_A",
                    "remote_port": "ge-0/0/23",
                    "remote_ip": "10.250.4.2",
                    "device_type": "switch",
                    "l2_accuracy": "wan_carrier_arp_route",
                    "transport_type": "metro_ethernet",
                    "carrier_cloud": "Spectrum Metro Ethernet",
                    "transit_vlan": "1054",
                    "transit_cidr": "10.250.4.0/30",
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
                {"interface": "irb.2052", "ip_address": "10.5.192.1/21", "status": "up"},
                {"interface": "irb.4051", "ip_address": "172.23.2.1/24", "status": "up"},
                *[
                    {"interface": f"irb.{310 + idx}", "ip_address": f"10.5.{idx}.1/24", "status": "up"}
                    for idx in range(1, 10)
                ],
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
                "ge-0/0/10": {"status": "up", "speed": "1Gb/s"},
                "ge-0/0/11": {"status": "up", "speed": "1Gb/s"},
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
                {
                    "local_port": "ge-0/0/11",
                    "remote_device": "172.31.5.200",
                    "remote_port": "eth0",
                    "remote_ip": "172.31.5.200",
                    "remote_mac": "10:f0:68:21:58:20",
                    "platform": "",
                    "device_type": "unknown",
                },
                {
                    "local_port": "ge-0/0/12",
                    "remote_device": "d65-000FD30AAE38",
                    "remote_port": "eth0",
                    "platform": "Digium",
                    "device_type": "switch",
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
            "stp": {"enabled": True, "is_root": False},
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
        "10.250.8.2": {
            "ip": "10.250.8.2",
            "hostname": "WBE_MDF_CORE_BLDG_A",
            "site_code": "WBE",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "irb.1051", "ip_address": "10.250.8.2/30", "status": "up"}],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.8.1", "interface": "irb.1051"}
            ],
            "interfaces_detail": {"ge-0/0/23": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [],
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
            "l3_interfaces": [
                {"interface": "irb.1053", "ip_address": "10.250.2.2/30", "status": "up"},
                {"interface": "irb.4021", "ip_address": "172.23.2.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.2.1", "interface": "irb.1053"}
            ],
            "interfaces_detail": {"ge-0/0/23": {"status": "up", "speed": "1Gb/s"}},
            "neighbors": [],
        },
        "10.250.4.2": {
            "ip": "10.250.4.2",
            "hostname": "ODE_MDF_CORE_BLDG_A",
            "site_code": "ODE",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "l3_interfaces": [{"interface": "irb.1054", "ip_address": "10.250.4.2/30", "status": "up"}],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "10.250.4.1", "interface": "irb.1054"}
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
                }
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
            "l3_interfaces": [{"interface": "irb.3011", "ip_address": "172.31.1.11/24", "status": "up"}],
            "neighbors": [
                {"local_port": "xe-0/2/0", "remote_device": "NMS_MDF_CORE_BLDG_B", "remote_port": "xe-0/0/0"}
            ],
        },
        "172.31.1.12": {
            "ip": "172.31.1.12",
            "hostname": "NMS_BLDG_B_SW_1",
            "site_code": "NMS",
            "vendor": "Juniper Networks",
            "model": "ex3400-48p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {"enabled": True, "is_root": False},
            "l3_interfaces": [{"interface": "irb.3011", "ip_address": "172.31.1.12/24", "status": "up"}],
            "neighbors": [
                {"local_port": "xe-0/2/0", "remote_device": "NMS_MDF_CORE_BLDG_B", "remote_port": "xe-0/0/1"}
            ],
        },
    }

    l2_path = str(tmp_path / "L2_network_diagrams.md")
    l3_path = str(tmp_path / "L3_network_diagrams.md")
    report_generator.generate_l2_diagram(devices, output_path=l2_path)
    report_generator.generate_l3_diagram(devices, output_path=l3_path)

    l2_txt = open(l2_path, encoding="utf-8").read()
    l3_txt = open(l3_path, encoding="utf-8").read()

    for md_txt in (l2_txt, l3_txt):
        m_blocks = re.findall(r"```mermaid\n(.*?)```", md_txt, re.DOTALL)
        assert m_blocks
        for blk in m_blocks:
            assert validate_mermaid_block(blk) == []

    # L2 verification: link-type labels, distinct linkStyles, sub-campus subgraph, AP count, STP Scope
    assert "[LLDP 10G]" in l2_txt
    assert "[Metro-E 10G" in l2_txt
    assert "[Metro-E 1G]" in l2_txt
    assert "[L3 Egress 0.0.0.0/0]" in l2_txt
    assert "stroke:#333," in l2_txt
    assert "stroke:#0d9488," in l2_txt
    assert "stroke:#6366f1," in l2_txt
    assert 'subgraph MOT_SUB ["MOT Sub-Campus"]' in l2_txt
    assert "MOT-Back-Warehouse" in l2_txt
    assert "MOT-Storage" in l2_txt
    assert "DO-Main-Bldg-2" in l2_txt
    assert "Total Discovered Access Points: **2**" in l2_txt
    assert "d65-000FD30AAE38" not in l2_txt
    assert "Campus Root" in l2_txt
    assert "Isolated Self-Root" in l2_txt

    # L3 verification: all 6 cores + FW + ISP connected, mask mismatch, conflict node, Junos VLAN desc
    for core_name in (
        "DO-Main-BLDG",
        "VES_MDF_CORE_BLDG_A",
        "WBE_MDF_CORE_BLDG_A",
        "NES_MDF_CORE_BLDG_A",
        "ODE_MDF_CORE_BLDG_A",
        "NMS_MDF_CORE_BLDG_B",
        "Perimeter-Firewall",
        "Spectrum Internet",
        "Next-Hop 10.0.0.25",
    ):
        assert core_name in l3_txt
    assert "MASK MISMATCH /24 vs /30" in l3_txt
    assert "CONFLICT: Duplicate Gateway IP" in l3_txt
    assert "CONFLICT - Hub routes to VES_MDF_CORE_BLDG_A" in l3_txt
    assert "l3_node_nes_mdf_core_bldg_a -->|" not in l3_txt.split("## Site-Scoped")[0]
    assert "l3_node_nes_mdf_core_bldg_a -.->|" in l3_txt
    assert "| VES_MDF_CORE_BLDG_A | irb.2052 | 2052 | Vlan_2052 | CHROMEBOOKS |" in l3_txt
    assert "Student & Wireless" in l3_txt


def test_l2_small_lab_all_link_styles_and_valid_mermaid(tmp_path):
    """Verify small single-site L2 & L3 diagrams emit distinct linkStyles for STP BLK, MAC Inferred, Passthrough, and L3 Egress."""
    import re

    from net_docu_crawler.diagram_validator import validate_mermaid_block

    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "opnsense",
            "vendor": "OPNsense",
            "model": "OPNsense Gateway",
            "device_type": "firewall",
            "device_persona": "firewall",
            "status": "success",
            "l3_interfaces": [{"interface": "vtnet0", "ip_address": "192.168.1.1/24", "status": "up"}],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "static", "next_hop": "100.64.224.1", "interface": "vtnet1"}
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
                    "local_port": "ge-0/0/2",
                    "remote_device": "FRR-Router-01",
                    "remote_port": "eth0",
                    "remote_ip": "192.168.1.254",
                    "device_type": "router",
                    "l2_accuracy": "virtual_passthrough",
                },
                {
                    "local_port": "ge-0/0/3",
                    "remote_device": "edge-sw",
                    "remote_port": "1",
                    "device_type": "switch",
                    "l2_accuracy": "virtual_passthrough",
                },
            ],
        },
        "192.168.1.254": {
            "ip": "192.168.1.254",
            "hostname": "FRR-Router-01",
            "vendor": "FRRouting",
            "model": "FRR Linux",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "eth0", "ip_address": "192.168.1.254/24", "status": "up"}],
            "neighbors": [],
        },
    }

    l2_path = str(tmp_path / "L2.md")
    l3_path = str(tmp_path / "L3.md")
    report_generator.generate_l2_diagram(devices, output_path=l2_path)
    report_generator.generate_l3_diagram(devices, output_path=l3_path)

    l2_txt = open(l2_path, encoding="utf-8").read()
    l3_txt = open(l3_path, encoding="utf-8").read()

    for md_txt in (l2_txt, l3_txt):
        for blk in re.findall(r"```mermaid\n(.*?)```", md_txt, re.DOTALL):
            assert validate_mermaid_block(blk) == []

    assert "[MAC Inferred]" in l2_txt
    assert "[Passthrough/Transit]" in l2_txt
    assert "[STP BLK]" in l2_txt
    assert "stroke:#d97706," in l2_txt
    assert "stroke:#9333ea," in l2_txt
    assert "stroke:#dc2626," in l2_txt
    assert "[L3 Egress 0.0.0.0/0]" in l3_txt
    assert "stroke:#6366f1," in l3_txt

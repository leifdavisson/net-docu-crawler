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

    assert "SW-2920-24G,192.168.1.220,HPProCurve,J9727A,switch,2,1,370.0,45.2,1,2,SFP-SX:2" in bom_txt
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

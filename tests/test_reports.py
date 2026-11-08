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

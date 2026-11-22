# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
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
Unit tests for Network_Analysis.md Migration Blueprint, Cutover Validation Script,
and Configuration Secret Sanitization.
"""

import os
import tempfile

from net_docu_crawler.crawler import _log_event, compute_organized_output_dir
from net_docu_crawler.drivers.base import extract_services_from_config, sanitize_raw_config
from report_generator import (
    generate_cutover_runbook,
    generate_cutover_validation_script,
    generate_master_network_analysis_migration_blueprint,
    generate_port_endpoint_mapping,
)


def test_compute_organized_output_dir():
    path = compute_organized_output_dir(targets=["192.168.1.0/24"], base_dir="docs/reports", domain="corp.internal")
    posix_path = path.replace("\\", "/")
    assert "docs/reports/192.168.1.0-24_" in posix_path
    assert path.endswith("_corp.internal")

    p2p_path = compute_organized_output_dir(targets=["10.10.1.0/30"], domain="dmz")
    posix_p2p = p2p_path.replace("\\", "/")
    assert posix_p2p.startswith("deliverables/10.10.1.0-30_")
    assert p2p_path.endswith("_dmz")


def test_sanitize_raw_config_redacts_secrets():
    cisco_cfg = """
hostname Switch-Core-01
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
enable password cisco_secret_pass
username admin privilege 15 secret 9 $9$jK8e$8j12.qwer
snmp-server community MySecretCommunity RO
crypto isakmp key SuperSecretKey123 address 10.0.0.1
set system root-authentication encrypted-password "$6$rounds=10000$saltsalt$hashedpassword"
<opnsense>
  <password>admin_clear_pass</password>
  <pre-shared-key>ipsec_psk_999</pre-shared-key>
</opnsense>
"""
    sanitized = sanitize_raw_config(cisco_cfg)
    assert "$1$mERr" not in sanitized
    assert "cisco_secret_pass" not in sanitized
    assert "SuperSecretKey123" not in sanitized
    assert "MySecretCommunity" not in sanitized
    assert "admin_clear_pass" not in sanitized
    assert "ipsec_psk_999" not in sanitized
    assert "<REDACTED_SECRET>" in sanitized
    assert "<REDACTED_COMMUNITY>" in sanitized
    assert "<REDACTED_KEY>" in sanitized
    assert "<REDACTED>" in sanitized


def test_extract_services_dhcp_relay_and_syslog():
    cisco_cfg = """
interface Vlan10
 ip address 192.168.10.1 255.255.255.0
 ip helper-address 10.0.0.254
logging host 10.0.0.50
snmp-server host 10.0.0.60
"""
    services = extract_services_from_config(cisco_cfg)
    assert "10.0.0.254" in services["dhcp_relays"]
    assert "10.0.0.50" in services["syslog_servers"]
    assert "10.0.0.60" in services["snmp_servers"]

    junos_cfg = """
set forwarding-options dhcp-relay server-group DHCP-SRVS 172.16.0.200
set system syslog host 172.16.0.50
set snmp trap-group T-CORP targets 172.16.0.60
"""
    j_services = extract_services_from_config(junos_cfg)
    assert "172.16.0.200" in j_services["dhcp_relays"]
    assert "172.16.0.50" in j_services["syslog_servers"]
    assert "172.16.0.60" in j_services["snmp_servers"]


def test_generate_master_network_analysis_migration_blueprint():
    mock_devices = {
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "Core-Switch-01",
            "vendor": "Juniper Networks",
            "model": "EX2300-C-12P",
            "serial": "CW0217120312",
            "firmware": "JunOS 23.4R2",
            "device_persona": "switch",
            "device_type": "switch",
            "stp": {"enabled": True, "is_root": True},
            "poe": {"total_power_watts": 370.0, "used_power_watts": 120.0, "available_power_watts": 250.0},
            "interfaces_detail": {
                "ge-0/0/1": {
                    "status": "up",
                    "speed": "1Gb/s",
                    "duplex": "Full",
                    "mtu": 1500,
                    "description": "Uplink to FW",
                },
                "ge-0/0/2": {
                    "status": "up",
                    "speed": "1Gb/s",
                    "duplex": "Full",
                    "mtu": 9000,
                    "description": "Jumbo Storage",
                },
            },
            "neighbors": [
                {"local_port": "ge-0/0/1", "remote_device": "FW-Gateway", "remote_port": "port1"},
                {"local_port": "ge-0/0/2", "remote_device": "Storage-Switch", "remote_port": "ge-0/0/24"},
            ],
            "l3_interfaces": [
                {"interface": "irb.1", "ip_address": "192.168.1.3/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "192.168.1.1", "interface": "irb.1"},
            ],
            "services": {
                "dns_servers": ["1.1.1.1"],
                "ntp_servers": ["0.pool.ntp.org"],
                "dhcp_relays": ["192.168.1.200"],
            },
        },
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "FW-Gateway",
            "vendor": "OPNsense",
            "model": "OPNsense DEC750",
            "serial": "FW-SN-9988",
            "firmware": "25.7",
            "device_persona": "firewall",
            "device_type": "firewall",
            "interfaces_detail": {
                "port1": {"status": "up", "speed": "1Gb/s", "duplex": "Full", "mtu": 1500},
            },
            "l3_interfaces": [
                {"interface": "port1", "ip_address": "192.168.1.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "100.64.0.1", "interface": "wan"},
            ],
            "services": {"dns_servers": ["1.1.1.1"]},
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        bp_file = os.path.join(tmpdir, "Network_Analysis.md")
        generate_master_network_analysis_migration_blueprint(
            mock_devices,
            output_path=bp_file,
            scope="192.168.1.0/24",
        )
        assert os.path.exists(bp_file)
        with open(bp_file, encoding="utf-8") as f:
            content = f.read()

        # Check for all key engineering sections and executive readiness subsections
        assert "# Network Migration Analysis Blueprint" in content
        assert "## 1. Executive Summary & Current Hardware Estate" in content
        assert "### 1.1 Discovery Confidence & Cutover Readiness Scorecard" in content
        assert "### 1.2 Deliverables & Breakout Reports Index" in content
        assert "[L2_network_diagrams.md](./L2_network_diagrams.md)" in content
        assert "[cutover_runbook.md](./cutover_runbook.md)" in content
        assert "### 1.3 Cutover Risks, Blind Spots & Single Points of Failure (SPOF)" in content
        assert "Arista 7050 / Juniper EX4400" not in content
        assert "## 2. Physical Layer 1/2 Cabling, Optics & MTU Matrix" in content
        assert "## 3. Power over Ethernet (PoE) Budget" in content
        assert "## 4. Layer 2 VLANs, 802.1Q Trunks" in content
        assert "## 5. DHCP Relay & IP Helper Addresses" in content
        assert "## 6. Spanning Tree (STP)" in content
        assert "## 7. First-Hop Redundancy Protocols" in content
        assert "## 8. Layer 3 Subnets, Routing Boundaries" in content
        assert "## 10. Infrastructure Services" in content
        assert "## 12. Maintenance Window Cutover Runbook" in content
        assert "CW0217120312" in content
        assert "192.168.1.200" in content

        runbook_file = os.path.join(tmpdir, "cutover_runbook.md")
        generate_cutover_runbook(mock_devices, output_path=runbook_file, scope="192.168.1.0/24")
        assert os.path.exists(runbook_file)
        with open(runbook_file, encoding="utf-8") as rf:
            rb_content = rf.read()
        assert "# Maintenance Window Cutover Runbook & Rollback Plan" in rb_content
        assert "## 1. Pre-Cutover T-Minus Checklist" in rb_content
        assert "## 3. Rollback Plan & Hard Abort Gate" in rb_content
        assert "192.168.1.200" in rb_content


def test_generate_cutover_validation_script():
    mock_devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "Core-GW",
            "l3_interfaces": [{"interface": "vlan1", "ip_address": "192.168.1.1/24"}],
            "services": {"dns_servers": ["1.1.1.1"]},
        },
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "Core-SW",
            "l3_interfaces": [{"interface": "irb.1", "ip_address": "192.168.1.3/24"}],
            "services": {"dns_servers": ["8.8.8.8"]},
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = os.path.join(tmpdir, "validate_cutover.sh")
        generate_cutover_validation_script(mock_devices, output_path=script_path)
        assert os.path.exists(script_path)
        # Check executable permissions
        assert os.access(script_path, os.X_OK)

        with open(script_path, encoding="utf-8") as f:
            code = f.read()

        assert "#!/usr/bin/env bash" in code
        assert 'check_ping "192.168.1.1" "Gateway / SVI"' in code
        assert 'check_ping "192.168.1.3" "Gateway / SVI"' in code
        assert 'check_port "1.1.1.1" 53 "DNS Port 53"' in code
        assert 'check_port "192.168.1.1" 22 "Core-GW SSH"' in code

        # Verify companion Windows PowerShell script
        ps1_path = os.path.join(tmpdir, "validate_cutover.ps1")
        assert os.path.exists(ps1_path)
        with open(ps1_path, encoding="utf-8") as f:
            ps1_code = f.read()

        assert "Test-PingReachability" in ps1_code
        assert 'Test-PingReachability -ip "192.168.1.1" -label "Gateway / SVI"' in ps1_code
        assert 'Test-TcpPort -ip "1.1.1.1" -port 53 -label "DNS Port 53"' in ps1_code


def test_generate_port_endpoint_mapping_csv():
    mock_devices = {
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "Core-EX2300",
            "mac_table": [
                {
                    "vlan": "10",
                    "mac": "20:4c:03:11:22:33",
                    "interface": "ge-0/0/1",
                    "type": "dynamic",
                    "vendor": "Aruba Networks",
                },
                {
                    "vlan": "20",
                    "mac": "00:50:56:aa:bb:cc",
                    "interface": "ge-0/0/2",
                    "type": "dynamic",
                    "vendor": "VMware, Inc.",
                },
            ],
            "arp_table": [
                {"ip": "192.168.10.15", "mac": "20:4c:03:11:22:33"},
                {"ip": "192.168.20.50", "mac": "00:50:56:aa:bb:cc"},
            ],
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "port_mac_endpoint_mapping.csv")
        generate_port_endpoint_mapping(mock_devices, output_path=csv_path)
        assert os.path.exists(csv_path)

        with open(csv_path, encoding="utf-8") as f:
            content = f.read()

        assert "Switch Hostname,Switch IP,Port,VLAN,MAC Address,OUI Vendor" in content
        assert "ge-0/0/1" in content
        assert "20:4c:03:11:22:33" in content
        assert "Aruba Networks" in content
        assert "Access Point" in content
        assert "192.168.10.15" in content
        assert "Server / Hypervisor" in content


def test_blueprint_sections_optics_and_port_mapping():
    mock_devices = {
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "Core-Switch",
            "device_persona": "switch",
            "optics": [
                {
                    "port": "xe-0/1/0",
                    "part_number": "SFP-10G-SR",
                    "type": "SFP+",
                    "tx_power_dbm": -2.1,
                    "rx_power_dbm": -3.4,
                    "temperature_c": 32.5,
                    "voltage_v": 3.3,
                }
            ],
            "mac_table": [
                {
                    "vlan": "10",
                    "mac": "20:4c:03:11:22:33",
                    "interface": "ge-0/0/1",
                    "vendor": "Aruba Networks",
                }
            ],
        }
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        bp_path = os.path.join(tmpdir, "Network_Analysis.md")
        generate_master_network_analysis_migration_blueprint(mock_devices, output_path=bp_path)
        assert os.path.exists(bp_path)
        with open(bp_path, encoding="utf-8") as f:
            txt = f.read()

        assert "### 2.3 Optical Transceiver & Digital Optical Monitoring (DOM) Telemetry" in txt
        assert "xe-0/1/0" in txt
        assert "SFP-10G-SR" in txt
        assert "-2.10 dBm" in txt
        assert "-3.40 dBm" in txt
        assert "✓ Optimal Optical Link" in txt
        assert "### 2.4 Port-to-Endpoint MAC Address Mapping & Access Layer Topology" in txt
        assert "20:4c:03:11:22:33" in txt
        assert "Access Point" in txt


def test_crawler_execution_logging():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "crawler_execution.log")
        _log_event(log_file, "Starting discovery probe on 192.168.1.1")
        _log_event(log_file, "Detected vendor='opnsense', banner='SSH-2.0-FreeBSD'")
        assert os.path.exists(log_file)
        with open(log_file, encoding="utf-8") as f:
            log_data = f.read()
        assert "Starting discovery probe on 192.168.1.1" in log_data
        assert "banner='SSH-2.0-FreeBSD'" in log_data


def test_blueprint_manual_verification_section_flags_unmanaged_switches_and_failed_targets(tmp_path):
    from report_generator import generate_master_network_analysis_migration_blueprint

    devices = {
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "desktop-switch",
            "vendor": "Juniper Networks",
            "model": "ex2300-c-12p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "interfaces_detail": {"ge-0/0/0": {"status": "up"}, "ge-0/0/1": {"status": "up"}},
            "neighbors": [
                {
                    "local_port": "ge-0/0/0",
                    "remote_device": "opnsense",
                    "remote_port": "eth0",
                    "l2_accuracy": "mac_inferred",
                }
            ],
            "mac_table": [
                {"interface": "ge-0/0/0", "mac": "aa:bb:cc:00:00:01", "vlan": "1"},
                {"interface": "ge-0/0/0", "mac": "aa:bb:cc:00:00:02", "vlan": "1"},
            ],
        },
        "192.168.1.12": {
            "ip": "192.168.1.12",
            "hostname": "pve",
            "vendor": "FRRouting",
            "model": "Debian",
            "device_type": "server",
            "device_persona": "server",
            "status": "success",
            "interfaces_detail": {"vmbr0": {"status": "up"}},
        },
        "192.168.1.50": {
            "ip": "192.168.1.50",
            "hostname": "sw-edge-unauth",
            "vendor": "Netgear",
            "model": "GS724T",
            "mac_address": "00:14:6c:11:22:33",
            "status": "unauthenticated",
        },
    }
    out = str(tmp_path / "Network_Analysis.md")
    generate_master_network_analysis_migration_blueprint(devices, output_path=out, failed_hosts_count=1)
    with open(out, encoding="utf-8") as f:
        txt = f.read()
    assert "### 1.5 Manual Verification & Suspected Unmanaged / Unverified Switches" in txt
    assert "`ge-0/0/0` | `2 MACs` (no direct LLDP/CDP)" in txt
    assert "`192.168.1.50` | **sw-edge-unauth**" in txt
    assert "Probable Switch / Network Appliance" in txt
    assert "**pve** (`192.168.1.12`, `server`): Hypervisor / Linux L2 bridge host" in txt
    assert "### 6.1 Loop Protection & BPDU Guard Best-Practice Matrix (By Link Type)" in txt
    assert "| **VoIP Phone + PC Daisy-Chain** |" in txt


def test_blueprint_gate_filtering_section15_filtering_section82_and_runbook_tables(tmp_path):
    """Verify Section 1.1 failed_hosts filtering, Section 1.5 endpoint/Metro-E filtering, Section 8.2 L3 summary, and runbook tables."""
    import json

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
            "stp": {
                "enabled": True,
                "is_root": True,
                "root_bridge": "32768.00:11:22:33:44:01",
                "is_verified_campus_root": True,
            },
            "interfaces_detail": {
                "C1": {"status": "up", "speed": "10Gb/s"},
                "F16": {"status": "up", "speed": "1Gb/s"},
            },
            "neighbors": [
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
                    "local_port": "B1",
                    "remote_device": "DO-Main-Bldg-2",
                    "remote_port": "50",
                    "platform": "Hewlett Packard Enterprise",
                    "device_type": "switch",
                },
                {
                    "local_port": "E1",
                    "remote_device": "d65-000FD30AAE38",
                    "remote_port": "eth0",
                    "platform": "Digium",
                    "device_type": "switch",
                },
            ],
            "mac_table": [
                {"interface": "C1", "mac": "14:3f:c3:bf:44:01", "vlan": "1050"},
                {"interface": "C1", "mac": "14:3f:c3:bf:44:02", "vlan": "1051"},
                {"interface": "C1", "mac": "14:3f:c3:bf:44:03", "vlan": "1053"},
                {"interface": "F16", "mac": "aa:bb:cc:11:22:01", "vlan": "100"},
                {"interface": "F16", "mac": "aa:bb:cc:11:22:02", "vlan": "100"},
            ],
            "l3_interfaces": [{"interface": "Spectrun-VES", "ip_address": "10.250.5.1/24", "status": "up"}],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "172.31.254.2", "interface": "4009"}],
            "dhcp": {"relays": [{"interface": f"VLAN {100 + i}", "helper_ip": f"10.0.0.{10 + i}"} for i in range(6)]},
            "discovery_protocols": {"lldp": "enabled", "cdp": "disabled"},
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
            "stp": {
                "enabled": True,
                "is_root": True,
                "root_bridge": "32768.00:11:22:33:44:01",
                "is_verified_campus_root": True,
            },
            "l3_interfaces": [
                {"interface": "irb.1050", "ip_address": "10.250.5.2/30", "status": "up"},
                {"interface": "irb.4051", "ip_address": "172.23.2.1/24", "status": "up"},
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "10.250.5.1", "interface": "irb.1050"}
            ],
            "neighbors": [],
            "discovery_protocols": {"lldp": "enabled", "cdp": "unsupported"},
        },
    }
    # Add 4 more default-gateway switches to test >4 collapsible runbook tables + isolated_self_root count
    for idx in range(1, 5):
        devices[f"10.2.0.{idx}"] = {
            "ip": f"10.2.0.{idx}",
            "hostname": f"NES-SW-{idx}",
            "site_code": "NES",
            "vendor": "Juniper Networks",
            "model": "ex3400",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "stp": {
                "enabled": True,
                "is_root": True,
                "root_bridge": f"32768.00:aa:bb:cc:dd:0{idx}",
                "is_isolated_self_root": True,
            },
            "l3_interfaces": [
                {"interface": "irb.4021", "ip_address": "172.23.2.1/24", "status": "up"}
                if idx == 1
                else {"interface": "irb.1", "ip_address": f"10.2.0.{idx}/24", "status": "up"}
            ],
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "10.2.0.254", "interface": "irb.1"}],
            "neighbors": [],
            "discovery_protocols": {"lldp": "enabled", "cdp": "unsupported"},
        }

    # Case 1: failed_hosts.json has ONLY non-infra unsupported appliances -> Gate must NOT be BLOCKED
    failed_path = tmp_path / "failed_hosts.json"
    failed_path.write_text(
        json.dumps(
            [
                {
                    "ip": "172.31.1.200",
                    "status": "unsupported",
                    "vendor": "Unknown",
                    "device_type": "unknown",
                    "model": "SSH-2.0-OpenSSH_7.9",
                },
                {"ip": "172.31.1.201", "status": "discovered", "record_class": "passive_endpoint", "vendor": "Axis"},
            ]
        ),
        encoding="utf-8",
    )
    bp_path = tmp_path / "Network_Analysis.md"
    generate_master_network_analysis_migration_blueprint(devices, output_path=str(bp_path))
    bp_txt = bp_path.read_text(encoding="utf-8")

    assert "`0` infra failed (`2` passive/unsupported non-infra hosts)" in bp_txt
    assert "❌ **BLOCKED**" not in bp_txt

    # Section 1.5 filters out Digium phone and skips Metro-E C1 multi-MAC false alarm, keeping F16 & DO-Main-Bldg-2
    sec15 = bp_txt.split("### 1.5")[1].split("## 2. Physical Layer")[0]
    assert "d65-000FD30AAE38" not in sec15
    assert "**DO-Main-BLDG** | `C1` | `3 MACs`" not in sec15
    assert "**DO-Main-BLDG** | `F16` | `2 MACs` (no direct LLDP/CDP)" in sec15
    assert "DO-Main-Bldg-2" in sec15

    # Section 8.2 summarizes L3 Backbone, Mask Mismatch, and Duplicate Gateway IP conflict
    assert "### 8.2 L3 Backbone, WAN Egress & Conflict Summary" in bp_txt
    assert "Metro-E (ARP+L3)" in bp_txt
    assert "MASK MISMATCH" in bp_txt
    assert "Duplicate Gateway Ip" in bp_txt

    # Case 2: failed_hosts.json includes an unauthenticated infra entry -> Gate IS BLOCKED
    failed_path.write_text(
        json.dumps(
            [
                {
                    "ip": "172.31.1.200",
                    "status": "unsupported",
                    "vendor": "Unknown",
                    "device_type": "unknown",
                    "model": "SSH-2.0-OpenSSH_7.9",
                },
                {"ip": "10.0.0.42", "status": "unauthenticated", "vendor": "paloalto", "device_type": "unknown"},
            ]
        ),
        encoding="utf-8",
    )
    generate_master_network_analysis_migration_blueprint(devices, output_path=str(bp_path))
    bp_txt2 = bp_path.read_text(encoding="utf-8")
    assert "❌ **BLOCKED**" in bp_txt2
    assert "`1` infra failed (`1` passive/unsupported non-infra hosts)" in bp_txt2

    # Runbook collapsible >4 tables and separate campus_root vs isolated_self_root summary
    rb_path = tmp_path / "cutover_runbook.md"
    generate_cutover_runbook(devices, output_path=str(rb_path))
    rb_txt = rb_path.read_text(encoding="utf-8")
    assert "**6** default gateways verified (expand reference table below)." in rb_txt
    assert "<details><summary><strong>Default Gateways (6)</strong></summary>" in rb_txt
    assert "<details><summary><strong>DHCP Relay Bindings (6)</strong></summary>" in rb_txt
    assert "Verified campus root(s): `DO-Main-BLDG`" in rb_txt
    assert "isolated self-root island(s) also detected" in rb_txt
    assert "STP Root Scope Breakdown (2 verified campus root(s), 4 isolated self-root(s))" in rb_txt

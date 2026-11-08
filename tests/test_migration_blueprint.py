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
    assert "10.10.1.0-30_" in posix_p2p
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

        # Check for all key engineering sections
        assert "# Network Migration Analysis Blueprint" in content
        assert "## 1. Executive Summary & Current Hardware Estate" in content
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

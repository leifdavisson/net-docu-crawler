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
Regression tests for Wave 1 Branch 1 (`swarm/reports/truthfulness-status-and-tables`):
RP-01..RP-10, RP-14, RP-15, and report_generator secondary sites of TP-01/TP-02/TP-06/TP-12.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report_generator
from net_docu_crawler import schema
from net_docu_crawler.migration_parsers import (
    extract_dhcp_config,
    extract_firewall_nat_vpn,
    extract_port_profiles,
    extract_routing_peers_and_fhrp_from_config,
    extract_vlans,
    extract_vrfs_and_acls,
)
from net_docu_crawler.quality_gates import evaluate_quality_gates, write_quality_report


def test_schema_v2_1_collection_status_and_parse_errors_contract():
    """RP-02: Explicit collection_status & parse_errors contract in schema.py."""
    assert hasattr(schema, "COLLECTION_STATES")
    assert set(schema.COLLECTION_STATES) >= {
        "ok",
        "not_applicable",
        "not_collected",
        "command_failed",
        "parse_failed",
        "partial",
    }
    assert hasattr(schema, "COLLECTION_SECTIONS")
    assert "stp" in schema.COLLECTION_SECTIONS
    assert "services" in schema.COLLECTION_SECTIONS
    assert "vrfs" in schema.COLLECTION_SECTIONS
    assert hasattr(schema, "CLI_ERROR_MARKERS")
    assert "% invalid input" in schema.CLI_ERROR_MARKERS

    assert schema.normalize_collection_status("OK") == "ok"
    assert schema.normalize_collection_status("command_failed") == "command_failed"
    assert schema.normalize_collection_status("bogus") == "not_collected"
    assert schema.normalize_collection_status(None) == "not_collected"

    err = schema.build_parse_error(
        section="running_config",
        command="show running-config",
        stage="command",
        error="authorization denied",
        raw_snippet="enable secret 5 $1$abc$secret123 " + ("x" * 400),
    )
    assert err["section"] == "running_config"
    assert err["stage"] == "command"
    assert len(err["raw_snippet"]) <= 200
    assert "$1$abc$secret123" not in err["raw_snippet"]

    dev = schema.stamp_schema_v2({"ip": "10.0.0.1", "hostname": "SW-1", "status": "success", "device_type": "switch"})
    assert isinstance(dev["collection_status"], dict)
    assert isinstance(dev["parse_errors"], list)


def test_section10_no_false_green_checks_and_includes_tacacs_snmp(tmp_path):
    """RP-01: Section 10 never emits false green checkmarks, includes TACACS+ & SNMP, checks consistency."""
    # Case A: All services undiscovered
    undiscovered = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "RTR-01",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "services": {},
            "interfaces_detail": {"eth0": {"status": "up"}},
        }
    }
    out_a = tmp_path / "bp_undiscovered.md"
    report_generator.generate_master_network_analysis_migration_blueprint(undiscovered, str(out_a))
    sec10_a = out_a.read_text(encoding="utf-8").split("## 10. Infrastructure Services")[1].split("## 11.")[0]
    assert "✓ Consistent Across Fleet" not in sec10_a
    assert "✓ Clock Synchronized" not in sec10_a
    assert "✓ Audit Trail Maintained" not in sec10_a
    assert "✓ Encrypted Identity Management" not in sec10_a
    assert "SNMP" in sec10_a

    # Case B: Divergent DNS, TACACS+, SNMP, plus explicit collection failure on one device
    fleet = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "SW-01",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "collection_status": {"services": "ok"},
            "services": {
                "dns_servers": ["1.1.1.1"],
                "ntp_servers": ["10.0.0.123"],
                "syslog_servers": ["10.0.0.50"],
                "snmp_servers": ["10.0.0.60"],
                "tacacs_servers": ["10.0.0.49"],
                "radius_servers": [],
            },
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "SW-02",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "collection_status": {"services": "ok"},
            "services": {
                "dns_servers": ["8.8.8.8"],
                "ntp_servers": ["10.0.0.123"],
                "syslog_servers": [],
                "snmp_servers": [],
                "tacacs_servers": [],
                "radius_servers": [],
            },
        },
        "10.0.0.3": {
            "ip": "10.0.0.3",
            "hostname": "SW-03",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "collection_status": {"services": "command_failed"},
            "services": {},
        },
    }
    out_b = tmp_path / "bp_fleet.md"
    report_generator.generate_master_network_analysis_migration_blueprint(fleet, str(out_b))
    sec10_b = out_b.read_text(encoding="utf-8").split("## 10. Infrastructure Services")[1].split("## 11.")[0]
    assert "10.0.0.49" in sec10_b
    assert "10.0.0.60" in sec10_b
    assert "✓ Consistent Across Fleet" not in sec10_b
    assert "failed" in sec10_b.lower() or "not collected" in sec10_b.lower()

    # Case C: Live report security gaps must NOT emit NTP/DNS/AAA gaps for non-infra/unauth devices
    live_devs = {
        "10.0.0.1": fleet["10.0.0.1"],
        "10.0.0.99": {
            "ip": "10.0.0.99",
            "hostname": "pve-host",
            "status": "success",
            "device_type": "server",
            "device_persona": "server",
            "record_class": "unsupported_appliance",
            "mgmt_method": "SSH",
            "services": {},
        },
        "10.0.0.50": {
            "ip": "10.0.0.50",
            "hostname": "unauth-sw",
            "status": "unauthenticated",
            "device_type": "unknown",
            "mgmt_method": "Telnet",
            "services": {},
        },
    }
    live_out = tmp_path / "live.md"
    report_generator.generate_network_analysis_report(live_devs, str(live_out))
    gaps_sec = live_out.read_text(encoding="utf-8").split("### Visibility & Security Gaps")[1].split("## 5.")[0]
    assert "pve-host" not in gaps_sec
    assert "unauth-sw** has **no NTP servers**" not in gaps_sec
    assert "Telnet" in gaps_sec


def test_collection_status_prevents_silent_none_and_quality_gate_integrity(tmp_path):
    """RP-02 & RP-10: Failed/uncollected status never masquerades as None/Disabled/Healthy; non-infra excluded from gates."""
    devs = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "SW-FAIL",
            "status": "success",
            "record_class": "crawled_infra",
            "device_type": "switch",
            "device_persona": "switch",
            "interfaces_detail": {"Gi1/0/1": {"status": "up"}},
            "ports": {"Gi1/0/1": {"oper_state": "up", "mode": "access", "access_vlan": "10", "allowed_vlans": []}},
            "stp": {"enabled": False, "is_root": False, "vlans": {}},
            "dhcp": {"pools": [], "reservations": [], "relays": []},
            "fhrp": [],
            "optics": [],
            "collection_status": {
                "interfaces": "ok",
                "running_config": "command_failed",
                "stp": "command_failed",
                "dhcp": "command_failed",
                "fhrp": "not_collected",
                "optics": "command_failed",
            },
            "parse_errors": [
                {
                    "section": "stp",
                    "command": "show spanning-tree",
                    "stage": "command",
                    "error": "timeout",
                    "raw_snippet": "",
                }
            ],
        },
        "10.0.0.12": {
            "ip": "10.0.0.12",
            "hostname": "pve",
            "status": "success",
            "record_class": "unsupported_appliance",
            "device_type": "server",
            "device_persona": "server",
            "interfaces_detail": {f"eth{i}": {"status": "up"} for i in range(10)},
            "ports": {f"eth{i}": {"oper_state": "up", "mode": "unknown", "access_vlan": ""} for i in range(10)},
        },
    }
    bp_out = tmp_path / "Network_Analysis.md"
    report_generator.generate_master_network_analysis_migration_blueprint(devs, str(bp_out))
    bp_txt = bp_out.read_text(encoding="utf-8")

    # STP failed -> MUST NOT say "Disabled (STP Off)"
    sec6 = bp_txt.split("## 6. Spanning Tree")[1].split("### 6.1")[0]
    assert "Disabled (STP Off)" not in sec6
    assert "failed" in sec6.lower() or "not collected" in sec6.lower()

    # Live report STP failed -> MUST NOT say "Spanning Tree is DISABLED"
    live_out = tmp_path / "live.md"
    report_generator.generate_network_analysis_report(devs, str(live_out))
    live_txt = live_out.read_text(encoding="utf-8")
    assert "Spanning Tree is DISABLED" not in live_txt

    # DHCP failed -> MUST NOT say "Unconfigured or Local DHCP"
    sec5 = bp_txt.split("## 5. DHCP Relay")[1].split("## 6.")[0]
    assert "Unconfigured or Local DHCP" not in sec5
    assert "failed" in sec5.lower() or "not collected" in sec5.lower()

    # FHRP not collected -> MUST state not collected
    sec7 = bp_txt.split("## 7. First-Hop Redundancy")[1].split("## 8.")[0]
    assert "not collected" in sec7.lower()

    # Optics failed -> MUST NOT say "✓ Healthy (Copper PHY)"
    sec23 = bp_txt.split("### 2.3 Optical Transceiver")[1].split("### 2.4")[0]
    assert "Healthy (Copper PHY)" not in sec23
    assert "failed" in sec23.lower() or "not collected" in sec23.lower()

    # Sec 4.1 with 0 evaluated trunks MUST NOT emit PASS / "✓ Zero 802.1Q trunk"
    sec41 = bp_txt.split("### 4.1 Trunk VLAN Mismatch")[1].split("## 5.")[0]
    assert "✓ Zero 802.1Q trunk" not in sec41
    assert "NOT_EVALUATED" in sec41 or "No inter-switch trunk" in sec41

    # Quality gates: pve server (10 ports) MUST be excluded -> total_ports == 1; GATE_COLLECTION_INTEGRITY fails P0 on running_config failure
    qrep = evaluate_quality_gates(list(devs.values()))
    assert qrep["port_confidence"]["total_ports"] == 1
    gates_by_name = {g["gate"]: g for g in qrep["gates"]}
    assert "GATE_COLLECTION_INTEGRITY" in gates_by_name
    assert gates_by_name["GATE_COLLECTION_INTEGRITY"]["status"] == "FAIL"
    assert qrep["passed"] is False
    # Zero trunk edges evaluated -> NOT_EVALUATED, not PASS
    assert gates_by_name["GATE_TRUNK_VLAN_MISMATCH"]["status"] == "NOT_EVALUATED"

    write_quality_report(qrep, str(tmp_path))
    dq_txt = (tmp_path / "data_quality_report.md").read_text(encoding="utf-8")
    assert "GATE_COLLECTION_INTEGRITY" in dq_txt


def test_stp_section_empty_guard_and_portfast_evidence(tmp_path):
    """RP-03: Router-only dataset has no dangling empty STP header; ports & portfast populate edge/bpdu counts."""
    router_only = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "RTR-EDGE",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "stp": {"enabled": False, "is_root": False, "vlans": {}},
            "interfaces_detail": {"eth0": {"status": "up"}},
            "routes": [],
        }
    }
    out_r = tmp_path / "router_only.md"
    report_generator.generate_master_network_analysis_migration_blueprint(router_only, str(out_r))
    sec6_r = out_r.read_text(encoding="utf-8").split("## 6. Spanning Tree")[1].split("### 6.1")[0]
    assert "| Switch Hostname | STP Protocol Detected |" not in sec6_r
    assert "no layer 2 switches" in sec6_r.lower() or "not applicable" in sec6_r.lower()

    # Correlated dev["ports"] with stp_edge="enabled" and bpdu_guard="enabled" must populate Sec 6 counts
    sw_ports = {
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "SW-EDGE",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "stp": {
                "enabled": True,
                "protocol": "RSTP",
                "bridge_priority": "32768",
                "is_root": True,
                "root_bridge": "32768.aa:bb:cc:dd:ee:01",
            },
            "port_profiles": {},
            "ports": {
                "Gi1/0/1": {"stp_edge": "enabled", "bpdu_guard": "enabled"},
                "Gi1/0/2": {"stp_edge": "enabled", "bpdu_guard": "disabled"},
            },
        }
    }
    out_s = tmp_path / "sw_ports.md"
    report_generator.generate_master_network_analysis_migration_blueprint(sw_ports, str(out_s))
    sec6_s = out_s.read_text(encoding="utf-8").split("## 6. Spanning Tree")[1].split("### 6.1")[0]
    assert "2 edge ports" in sec6_s
    assert "1 protected ports" in sec6_s

    # Parser extracts Cisco/Arista per-port & global portfast / bpduguard and Junos brace-style edge
    cisco_cfg = """
spanning-tree portfast default
spanning-tree portfast bpduguard default
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet1/0/2
 switchport mode trunk
 spanning-tree portfast disable
!
interface GigabitEthernet1/0/3
 switchport mode access
 spanning-tree portfast edge
 spanning-tree bpduguard enable
!
"""
    c_prof = extract_port_profiles(cisco_cfg, vendor="Cisco")
    assert c_prof["GigabitEthernet1/0/1"]["stp_edge"] is True
    assert c_prof["GigabitEthernet1/0/1"]["bpdu_guard"] is True
    assert c_prof["GigabitEthernet1/0/2"]["stp_edge"] is False
    assert c_prof["GigabitEthernet1/0/3"]["stp_edge"] is True
    assert c_prof["GigabitEthernet1/0/3"]["bpdu_guard"] is True

    junos_brace_cfg = """
protocols {
    rstp {
        interface ge-0/0/1 {
            edge;
        }
        bpdu-block-on-edge;
    }
}
"""
    j_prof = extract_port_profiles(junos_brace_cfg, vendor="Juniper Networks")
    assert j_prof["ge-0/0/1"]["stp_edge"] is True
    assert j_prof["ge-0/0/1"]["bpdu_guard"] is True


def test_default_routes_no_empty_header_and_no_hardcoded_ad(tmp_path):
    """RP-04: Section 8.1 omits empty table header and never hardcodes '1 (Static)' AD."""
    no_def = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "SW-NO-DEF",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "routes": [{"subnet": "10.0.0.0/24", "protocol": "Connected", "next_hop": "Direct", "interface": "Vlan10"}],
        }
    }
    out_empty = tmp_path / "no_def.md"
    report_generator.generate_master_network_analysis_migration_blueprint(no_def, str(out_empty))
    sec81_empty = (
        out_empty.read_text(encoding="utf-8").split("### 8.1 Discovered Default Routes")[1].split("### 8.2")[0]
    )
    assert "| Device Hostname | Default Route" not in sec81_empty
    assert "no default routes" in sec81_empty.lower()

    multi_ad = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "FRR-01",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "routes": [
                {"subnet": "0.0.0.0/0", "protocol": "kernel", "next_hop": "192.168.1.1", "interface": "eth0"},
                {
                    "subnet": "::/0",
                    "protocol": "OSPF",
                    "next_hop": "fe80::1",
                    "interface": "eth0",
                    "admin_distance": 110,
                },
            ],
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "JUNOS-01",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "routes": [
                {
                    "subnet": "0.0.0.0/0.0.0.0",
                    "protocol": "Static",
                    "next_hop": "192.168.1.1",
                    "interface": "irb.10",
                    "preference": 5,
                }
            ],
        },
    }
    out_ad = tmp_path / "multi_ad.md"
    report_generator.generate_master_network_analysis_migration_blueprint(multi_ad, str(out_ad))
    sec81_ad = out_ad.read_text(encoding="utf-8").split("### 8.1 Discovered Default Routes")[1].split("### 8.2")[0]
    assert "1 (Static)" not in sec81_ad
    assert "110" in sec81_ad
    assert "5" in sec81_ad
    assert "Unknown (Not Reported)" in sec81_ad
    assert "::/0" in sec81_ad


def test_l3_diagram_renders_dev_vrfs_and_multivendor_vrfs(tmp_path):
    """RP-05: L3_network_diagrams.md consumes dev['vrfs'] with RD/interfaces and respects collection_status."""
    devices = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "PE-XR-01",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "raw_config": "",
            "vrfs": [
                {"name": "CORP", "rd": "65000:100", "interfaces": ["GigabitEthernet0/0/0/1"]},
                {"name": "GUEST", "rd": "65000:200", "interfaces": ["GigabitEthernet0/0/0/2"]},
            ],
            "l3_interfaces": [],
            "routes": [],
        }
    }
    l3_out = tmp_path / "L3.md"
    report_generator.generate_l3_diagram(devices, str(l3_out))
    vrf_sec = (
        l3_out.read_text(encoding="utf-8").split("## VRF Routing Instances")[1].split("## Discovered Routing Tables")[0]
    )
    assert "CORP" in vrf_sec
    assert "65000:100" in vrf_sec
    assert "GigabitEthernet0/0/0/1" in vrf_sec
    assert "standard global table only" not in vrf_sec

    # Failed VRF/config collection must NOT falsely assert "standard global table only"
    failed_vrf_devs = {
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "RTR-NOCFG",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "raw_config": "",
            "vrfs": [],
            "collection_status": {"vrfs": "not_collected", "running_config": "command_failed"},
            "l3_interfaces": [],
            "routes": [],
        }
    }
    l3_fail = tmp_path / "L3_fail.md"
    report_generator.generate_l3_diagram(failed_vrf_devs, str(l3_fail))
    vrf_fail_sec = (
        l3_fail.read_text(encoding="utf-8")
        .split("## VRF Routing Instances")[1]
        .split("## Discovered Routing Tables")[0]
    )
    assert "standard global table only" not in vrf_fail_sec
    assert "not collected" in vrf_fail_sec.lower() or "failed" in vrf_fail_sec.lower()

    # Multi-vendor extract_vrfs_and_acls coverage
    multi_cfg = """
vrf context TENANT-NXOS
 rd 65001:10
!
vrf instance TENANT-EOS
 rd 65002:20
!
vrf TENANT-FRR
!
config vdom
edit VDOM-CORP
next
end
routing-instances {
    RI-GUEST {
        instance-type vrf;
        interface ge-0/0/5.0;
        route-distinguisher 65003:30;
    }
}
interface Ethernet1/1
 vrf member TENANT-NXOS
!
interface Ethernet2
 vrf TENANT-EOS
!
"""
    vrfs, _acls = extract_vrfs_and_acls(multi_cfg)
    vrf_by_name = {v["name"]: v for v in vrfs}
    assert "TENANT-NXOS" in vrf_by_name
    assert vrf_by_name["TENANT-NXOS"].get("rd") == "65001:10"
    assert "Ethernet1/1" in (vrf_by_name["TENANT-NXOS"].get("interfaces") or [])
    assert "TENANT-EOS" in vrf_by_name
    assert "TENANT-FRR" in vrf_by_name
    assert "VDOM-CORP" in vrf_by_name
    assert "RI-GUEST" in vrf_by_name
    assert vrf_by_name["RI-GUEST"].get("rd") == "65003:30"
    assert "ge-0/0/5.0" in (vrf_by_name["RI-GUEST"].get("interfaces") or [])


def test_sec11_lldp_counter_and_direct_adjacency_accuracy(tmp_path):
    """RP-06: Sec 1.1 never emits '0/1 LLDP enabled' + '✓ Full protocol coverage', nor counts WAN/L3 egress as direct."""
    devices = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "CORE-01",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "discovery_protocols": {"lldp": "unknown", "cdp": "unsupported"},
            "neighbors": [
                {
                    "local_port": "C1",
                    "remote_device": "WAN-PEER",
                    "remote_port": "xe-0/0/1",
                    "l2_accuracy": "wan_carrier_arp_route",
                },
                {
                    "local_port": "A3",
                    "remote_device": "FW-01",
                    "remote_port": "eth0",
                    "l2_accuracy": "l3_next_hop_egress",
                },
            ],
        }
    }
    out = tmp_path / "sec11.md"
    report_generator.generate_master_network_analysis_migration_blueprint(devices, str(out))
    sec11 = out.read_text(encoding="utf-8").split("### 1.1 Discovery Confidence")[1].split("### 1.2")[0]
    assert "✓ Full protocol coverage" not in sec11
    assert "`0` direct" in sec11


def test_vlan_svi_map_includes_l2_and_matches_l3_diagram_and_config_vars(tmp_path):
    """RP-07: Sec 4 shows vtnet0_vlan10 VLAN 10, includes L2-only VLANs, drops VLAN 0/loopbacks//32; config_vars uses real CIDR."""
    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "opnsense",
            "status": "success",
            "device_type": "firewall",
            "device_persona": "firewall",
            "vlans": {
                "10": {"id": "10", "name": "MGMT"},
                "30": {"id": "30", "name": "GUEST_L2_ONLY"},
            },
            "l3_interfaces": [
                {"interface": "vtnet0_vlan10", "ip_address": "10.10.10.1/24", "status": "up"},
                {"interface": "vtnet1", "ip_address": "100.64.224.70/19", "status": "up"},
                {"interface": "lo0", "ip_address": "127.0.0.1/8", "status": "up"},
            ],
            "interfaces_detail": {},
        },
        "192.168.1.3": {
            "ip": "192.168.1.3",
            "hostname": "desktop-switch",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "l3_interfaces": [
                {"interface": "irb.0", "ip_address": "192.168.1.3/24", "status": "up"},
            ],
            "interfaces_detail": {},
        },
        "192.168.1.4": {
            "ip": "192.168.1.4",
            "hostname": "Office-AP",
            "status": "success",
            "device_type": "ap",
            "device_persona": "ap",
            "l3_interfaces": [
                {"interface": "br0", "ip_address": "192.168.1.4", "status": "up"},
            ],
            "interfaces_detail": {},
        },
    }
    bp = tmp_path / "Network_Analysis.md"
    report_generator.generate_master_network_analysis_migration_blueprint(devices, str(bp))
    sec4 = bp.read_text(encoding="utf-8").split("## 4. Layer 2 VLANs")[1].split("### 4.1")[0]
    assert "| **10** |" in sec4
    assert "GUEST_L2_ONLY" in sec4
    assert "| **0** |" not in sec4
    assert "127.0.0.1" not in sec4
    assert "192.168.1.4/32" not in sec4

    cfg_vars_path = tmp_path / "vars.json"
    report_generator.generate_config_variables(devices, str(cfg_vars_path))
    cfg_vars = json.loads(cfg_vars_path.read_text(encoding="utf-8"))
    opn_vlans = {v["id"]: v["name"] for v in cfg_vars["opnsense"]["vlans"]}
    assert opn_vlans.get("30") == "GUEST_L2_ONLY"
    opn_svis = {s["interface"]: s["subnet"] for s in cfg_vars["opnsense"]["l3_interfaces"]}
    assert opn_svis["vtnet1"] == "100.64.224.0/19"

    # Multi-vendor extract_vlans
    opn_xml = (
        "<opnsense><vlans><vlan><tag>40</tag><descr>IOT</descr><vlanif>vtnet0_vlan40</vlanif></vlan></vlans></opnsense>"
    )
    assert extract_vlans(opn_xml, vendor="OPNsense")["40"]["name"] == "IOT"
    fg_cfg = 'config system interface\n edit "vlan50"\n  set vlanid 50\n  set alias "STAFF"\n next\nend\n'
    assert extract_vlans(fg_cfg, vendor="Fortinet")["50"]["name"] == "STAFF"
    mt_cfg = "/interface vlan\nadd interface=bridge1 name=vlan60-cam vlan-id=60\n"
    assert extract_vlans(mt_cfg, vendor="MikroTik")["60"]["name"] == "vlan60-cam"
    owrt_cfg = "network.@bridge-vlan[0]=bridge-vlan\nnetwork.@bridge-vlan[0].vlan='70'\n"
    assert "70" in extract_vlans(owrt_cfg, vendor="OpenWrt")


def test_fhrp_columns_and_multivendor_extraction(tmp_path):
    """RP-08: Sec 7 maps FHRP active/standby cleanly (never puts state in Standby column) & extracts multi-vendor FHRP."""
    devices = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "CORE-A",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "fhrp": [
                {
                    "protocol": "hsrp",
                    "group": "10",
                    "interface": "Vlan10",
                    "vip": "10.10.10.1",
                    "priority": 120,
                    "state": "Active",
                    "preempt": True,
                }
            ],
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "CORE-B",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "fhrp": [
                {
                    "protocol": "hsrp",
                    "group": "10",
                    "interface": "Vlan10",
                    "vip": "10.10.10.1",
                    "priority": 100,
                    "state": "Standby",
                    "preempt": False,
                }
            ],
        },
    }
    bp = tmp_path / "fhrp.md"
    report_generator.generate_master_network_analysis_migration_blueprint(devices, str(bp))
    sec7 = bp.read_text(encoding="utf-8").split("## 7. First-Hop Redundancy")[1].split("## 8.")[0]
    assert "| `CORE-A` | Active |" not in sec7
    assert "CORE-B" in sec7
    assert "Enabled" in sec7 or "True" in sec7

    # Multi-vendor FHRP parser
    cfg = """
interface Vlan10
 standby 10 ip 10.10.10.1
 standby 10 priority 120
 standby 10 preempt
!
interface Vlan20
 hsrp 20
  ip 10.10.20.1
  priority 110
  preempt
!
interface Vlan30
 glbp 30 ip 10.10.30.1
 glbp 30 preempt
!
interface Vlan40
 ip virtual-router address 10.10.40.1
!
set interfaces irb unit 50 family inet address 10.10.50.2/24 vrrp-group 50 virtual-address 10.10.50.1
set interfaces irb unit 50 family inet address 10.10.50.2/24 vrrp-group 50 preempt
/interface vrrp
add interface=ether1 name=vrrp60 vrid=60 v3-protocol=ipv4
"""
    _peers, fhrp = extract_routing_peers_and_fhrp_from_config(cfg)
    by_proto_grp = {(f["protocol"], str(f["group"])): f for f in fhrp}
    assert by_proto_grp[("hsrp", "10")]["preempt"] is True
    assert by_proto_grp[("hsrp", "20")]["vip"] == "10.10.20.1"
    assert by_proto_grp[("hsrp", "20")]["preempt"] is True
    assert by_proto_grp[("glbp", "30")]["vip"] == "10.10.30.1"
    assert any(f["protocol"] == "varp" and f["vip"] == "10.10.40.1" for f in fhrp)
    assert by_proto_grp[("vrrp", "50")]["vip"] == "10.10.50.1"
    assert by_proto_grp[("vrrp", "50")]["preempt"] is True
    assert any(f["protocol"] == "vrrp" and str(f["group"]) == "60" for f in fhrp)


def test_dhcp_relay_multivendor_and_local_pool_status(tmp_path):
    """RP-09: Sec 5 reports discovered local DHCP pools and extracts multi-vendor DHCP relays."""
    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "OPNsense-GW",
            "status": "success",
            "device_type": "firewall",
            "device_persona": "firewall",
            "collection_status": {"dhcp": "ok", "running_config": "ok"},
            "dhcp": {
                "pools": [{"name": "lan", "range": "192.168.1.100-192.168.1.200"}],
                "reservations": [],
                "relays": [],
            },
        }
    }
    bp = tmp_path / "dhcp.md"
    report_generator.generate_master_network_analysis_migration_blueprint(devices, str(bp))
    sec5 = bp.read_text(encoding="utf-8").split("## 5. DHCP Relay")[1].split("## 6.")[0]
    assert "local dhcp" in sec5.lower()
    assert "1" in sec5

    cfg = """
interface Vlan10
 ip helper-address vrf CORP 10.0.0.10
 ip helper-address global 10.0.0.11
!
interface Vlan20
 ip dhcp relay address 10.0.0.20
!
forwarding-options {
    dhcp-relay {
        server-group {
            SG1 {
                10.0.0.30;
            }
        }
        group G1 {
            active-server-group {
                SG1;
            }
            interface irb.30;
        }
    }
}
config system interface
 edit "port2"
  set dhcp-relay-service enable
  set dhcp-relay-ip "10.0.0.40" "10.0.0.41"
 next
end
/ip dhcp-relay
add dhcp-server=10.0.0.50 interface=ether2 name=relay1
"""
    dhcp = extract_dhcp_config(cfg)
    relay_pairs = {(r["interface"], r["helper_ip"]) for r in dhcp["relays"]}
    assert ("Vlan10", "10.0.0.10") in relay_pairs
    assert ("Vlan10", "10.0.0.11") in relay_pairs
    assert ("Vlan20", "10.0.0.20") in relay_pairs
    assert ("irb.30", "10.0.0.30") in relay_pairs
    assert ("port2", "10.0.0.40") in relay_pairs
    assert ("port2", "10.0.0.41") in relay_pairs
    assert ("ether2", "10.0.0.50") in relay_pairs

    opn_relay_xml = "<opnsense><dhcrelay><enable>1</enable><interface>lan,opt1</interface><server>10.0.0.60,10.0.0.61</server></dhcrelay></opnsense>"
    opn_relays = {(r["interface"], r["helper_ip"]) for r in extract_dhcp_config(opn_relay_xml)["relays"]}
    assert ("lan", "10.0.0.60") in opn_relays
    assert ("opt1", "10.0.0.61") in opn_relays


def test_get_unique_devices_and_get_link_speed_and_subnet_overlap_vrf():
    """TP-01/TP-02/TP-06/TP-12 secondary sites in report_generator.py."""
    # TP-06: Placeholder serials & generic hostnames must NOT collapse distinct cloned VMs; distinct real serials keep both
    devs = {
        "172.16.1.1": {"hostname": "OpenWrt", "serial": "Not Specified", "status": "success", "ip": "172.16.1.1"},
        "172.16.1.2": {"hostname": "OpenWrt", "serial": "Not Specified", "status": "success", "ip": "172.16.1.2"},
        "10.0.0.1": {"hostname": "MikroTik", "serial": "SN-REAL-1", "status": "success", "ip": "10.0.0.1"},
        "10.0.0.2": {"hostname": "MikroTik", "serial": "SN-REAL-2", "status": "success", "ip": "10.0.0.2"},
    }
    uniq = report_generator.get_unique_devices(devs)
    assert len(uniq) == 4

    # TP-02: Accurate speed inference without substring collisions
    assert report_generator.get_link_speed("et-0/0/0", {}) == "100G"
    assert report_generator.get_link_speed("vtnet0", {}) == "1G"
    assert report_generator.get_link_speed("ether1", {}) == "1G"
    assert report_generator.get_link_speed("Twe1/0/1", {}) == "25G"
    assert report_generator.get_link_speed("TwentyFiveGigE1/0/1", {}) == "25G"
    assert report_generator.get_link_speed("TwentyFiveGigabitEthernet1/0/1", {}) == "25G"
    assert report_generator.get_link_speed("Tw1/0/1", {}) == "2.5G"

    # TP-12: VRF isolation & bare IP without mask must not emit false conflicts/overlaps
    vrf_devs = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "PE-1",
            "status": "success",
            "device_type": "router",
            "l3_interfaces": [
                {"interface": "Gi0/1", "ip_address": "10.10.0.1/24", "vrf": "RED"},
                {"interface": "Gi0/2", "ip_address": "10.10.0.1/24", "vrf": "BLUE"},
            ],
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "AP-1",
            "status": "success",
            "device_type": "ap",
            "l3_interfaces": [
                {"interface": "br0", "ip_address": "10.20.0.5"},
            ],
        },
        "10.0.0.3": {
            "ip": "10.0.0.3",
            "hostname": "GW-1",
            "status": "success",
            "device_type": "router",
            "l3_interfaces": [
                {"interface": "eth0", "ip_address": "10.20.0.1/25"},
            ],
        },
    }
    overlap_lines = "\n".join(report_generator._render_subnet_overlap_section(vrf_devs))
    assert "CRITICAL IP CONFLICT" not in overlap_lines
    assert "Overlap Warning" not in overlap_lines


def test_mtu_optics_security_and_no_dangling_empty_tables(tmp_path):
    """RP-14 & RP-15: Honest MTU/Optics/Security reporting & no dangling empty PoE/Port-Util tables."""
    devs = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "EDGE-RTR",
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "mgmt_method": "SSH",
            "raw_config": "line vty 0 4\n transport input telnet ssh\nip http server\n",
            "interfaces_detail": {},
            "ports": {"Gi0/0": {"acl_in": "WAN_IN", "acl_out": "WAN_OUT"}},
            "neighbors": [{"local_port": "Gi0/0", "remote_device": "PEER", "remote_port": "Gi0/0"}],
            "optics": [],
            "poe": {"total_power_watts": 0.0, "used_power_watts": 0.0},
            "routes": [],
        }
    }
    bp = tmp_path / "bp.md"
    report_generator.generate_master_network_analysis_migration_blueprint(devs, str(bp))
    bp_txt = bp.read_text(encoding="utf-8")

    # Sec 2.2 MTU: 0 uplinks with real MTU -> must NOT assert 1500-byte verified consistency
    sec22 = bp_txt.split("### 2.2 MTU Discrepancy")[1].split("### 2.3")[0]
    assert "share consistent standard MTU boundaries (1500 bytes)" not in sec22

    # Sec 2.3 Optics: 0 optics -> must NOT falsely assert "✓ Healthy (Copper PHY)"
    sec23 = bp_txt.split("### 2.3 Optical Transceiver")[1].split("### 2.4")[0]
    assert "Healthy (Copper PHY)" not in sec23

    # Sec 3 PoE: router-only -> no dangling empty table header
    sec3 = bp_txt.split("## 3. Power over Ethernet")[1].split("## 4.")[0]
    assert "| Switch Hostname | Total PoE Capacity" not in sec3

    # Sec 9 Security: detects Telnet/HTTP in raw_config, counts port ACLs, does NOT hardcode router NAT Disabled
    sec9 = bp_txt.split("## 9. Security, Access Control Lists")[1].split("## 10.")[0]
    assert "Telnet" in sec9
    assert "Disabled (Pure L2/L3)" not in sec9
    assert "WAN_IN" in sec9 or "2 port ACL" in sec9 or "parsed" in sec9.lower()

    # Live report: 0 ports & 0 PoE -> no dangling empty Port Util or PoE table headers
    live = tmp_path / "live.md"
    report_generator.generate_network_analysis_report(devs, str(live))
    live_txt = live.read_text(encoding="utf-8")
    port_sec = live_txt.split("### Interface Port Utilization Summary")[1].split("### ")[0]
    assert "| Switch Hostname | Connected Ports |" not in port_sec
    poe_sec = live_txt.split("### PoE Power Budget")[1]
    assert "| Device | IP | PoE Budget (W) |" not in poe_sec

    # Multi-vendor extract_firewall_nat_vpn (FortiOS NAT, Cisco NAT/ACL, MikroTik, OpenWrt)
    fg_cfg = """
config firewall policy
    edit 1
        set srcintf "port2"
        set dstintf "port1"
        set action accept
        set nat enable
    next
end
"""
    fg_sec = extract_firewall_nat_vpn(fg_cfg, vendor="Fortinet")
    assert len(fg_sec["firewall_rules"]) == 1
    assert len(fg_sec["nat_rules"]) == 1

    cisco_sec_cfg = """
ip access-list extended WAN_IN
 permit tcp any any eq 443
ip nat inside source list NAT_ACL interface GigabitEthernet0/0 overload
"""
    c_sec = extract_firewall_nat_vpn(cisco_sec_cfg, vendor="Cisco")
    assert len(c_sec["firewall_rules"]) >= 1
    assert len(c_sec["nat_rules"]) >= 1

    mt_sec_cfg = """
/ip firewall filter
add action=accept chain=input protocol=tcp dst-port=22
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1
"""
    m_sec = extract_firewall_nat_vpn(mt_sec_cfg, vendor="MikroTik")
    assert len(m_sec["firewall_rules"]) == 1
    assert len(m_sec["nat_rules"]) == 1


def test_wave2_report_generator_delegates_to_topology_resolver():
    """Wave 2: report_generator delegates interface norm, speed, dedupe, and CIDR overlaps to topology_resolver."""
    from net_docu_crawler.topology_resolver import normalize_interface_key

    assert report_generator.normalize_interface_name("Ethernet1") == normalize_interface_key("Ethernet1") == "eth1"
    assert report_generator.normalize_interface_name("Et1") == "eth1"
    assert report_generator.get_link_speed("Hu0/0/0/0", {"Hu0/0/0/0": {"speed": "400G"}}) == "400G"
    assert report_generator.get_link_speed("et-0/0/0", {}) == "100G"

    # Multi-SVI same hardware MAC with Unknown serial must dedupe into 1 device via topology_resolver.dedupe_devices
    svi_dup = {
        "10.0.10.1": {
            "ip": "10.0.10.1",
            "hostname": "Switch",
            "serial": "Unknown",
            "mac_address": "00:1a:2b:3c:4d:5e",
            "status": "success",
        },
        "10.0.20.1": {
            "ip": "10.0.20.1",
            "hostname": "Switch",
            "serial": "Unknown",
            "mac_address": "00:1a:2b:3c:4d:5e",
            "status": "success",
        },
    }
    assert len(report_generator.get_unique_devices(svi_dup)) == 1


def test_wave2_bom_and_target_configs_support_parsed_target_vendor_map(tmp_path):
    """Wave 2 (CD-08 / DD-17): BOM sizing & target migration configs support persona=vendor maps and fortinet/aruba/meraki."""
    import csv

    devices = {
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "SW-ACCESS-1",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "interfaces_detail": {"Gi1/0/1": {"status": "up"}},
            "poe": {"total_power_watts": 370.0, "used_power_watts": 60.0},
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "FW-EDGE-1",
            "status": "success",
            "device_type": "firewall",
            "device_persona": "firewall",
            "interfaces_detail": {"port1": {"status": "up"}},
        },
        "10.0.0.3": {
            "ip": "10.0.0.3",
            "hostname": "AP-FLOOR-1",
            "status": "success",
            "device_type": "ap",
            "device_persona": "ap",
            "interfaces_detail": {"eth0": {"status": "up"}},
        },
    }
    bom_csv = tmp_path / "bom.csv"
    report_generator.generate_bom_hardware_sizing(
        devices,
        output_path=str(bom_csv),
        target_vendor="switch=cisco,firewall=fortinet,ap=aruba",
    )
    with open(bom_csv, encoding="utf-8") as f:
        rows = {r["Hostname"]: r for r in csv.DictReader(f)}
    assert rows["SW-ACCESS-1"]["Recommended SKU"].startswith("C9")
    assert "FortiGate" in rows["FW-EDGE-1"]["Recommended SKU"]
    assert "AP-" in rows["AP-FLOOR-1"]["Recommended SKU"]

    for tv in ("fortinet", "aruba", "meraki"):
        out_cfg = tmp_path / f"target_{tv}.md"
        report_generator.generate_target_migration_configs(devices, target_vendor=tv, output_path=str(out_cfg))
        txt = out_cfg.read_text(encoding="utf-8")
        assert f"# Unsupported target_vendor={tv}" not in txt


def test_wave2_cutover_script_rejects_leading_dash_and_escapes_ps_smart_quotes(tmp_path):
    """Wave 2 (SF-12 #75): Reject leading '-' option flags in targets and escape Unicode smart quotes in PowerShell."""
    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": "SW-\u201cSmart\u201d-\u201eQuote",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "l3_interfaces": [{"interface": "Vlan1", "ip_address": "192.168.1.1/24"}],
            "services": {"dns_servers": ["-oProxyCommand=id", "--help", "1.1.1.1"]},
        },
        "-badflag": {
            "ip": "-badflag",
            "hostname": "FlagHost",
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
        },
    }
    sh_path = tmp_path / "validate_cutover.sh"
    report_generator.generate_cutover_validation_script(devices, str(sh_path))
    sh_txt = sh_path.read_text(encoding="utf-8")
    ps_txt = (tmp_path / "validate_cutover.ps1").read_text(encoding="utf-8")

    assert "-oProxyCommand" not in sh_txt
    assert "--help" not in sh_txt
    assert "-badflag" not in sh_txt
    assert "-oProxyCommand" not in ps_txt
    assert "-badflag" not in ps_txt
    assert "\u201c" not in ps_txt
    assert "\u201d" not in ps_txt
    assert "\u201e" not in ps_txt


def test_wave2_base_extract_services_from_config_multivendor():
    """Wave 2: extract_services_from_config supports OPNsense MVC, Cisco IOS-XE AAA/VRF helper, Junos braces, MikroTik, Aruba."""
    from net_docu_crawler.drivers.base import extract_services_from_config

    cfg = """
<opnsense>
  <OPNsense>
    <Syslog>
      <destinations>
        <destination uuid="111">
          <enabled>1</enabled>
          <server>10.0.0.70</server>
        </destination>
      </destinations>
    </Syslog>
    <DHCRelay>
      <destinations>
        <destination uuid="222">
          <server>10.0.0.69,10.0.0.68</server>
        </destination>
      </destinations>
    </DHCRelay>
  </OPNsense>
</opnsense>
radius server RAD-CORP
 address ipv4 10.0.0.71 auth-port 1812 acct-port 1813
!
tacacs server TAC-CORP
 address ipv4 10.0.0.72
!
interface Vlan10
 ip helper-address vrf CORP 10.0.0.73
 ip dhcp relay address 10.0.0.74
!
system {
    name-server {
        10.0.0.75;
    }
    ntp {
        server 10.0.0.76;
    }
    syslog {
        host 10.0.0.77 {
            any info;
        }
    }
    radius-server {
        10.0.0.78 {
            secret "x";
        }
    }
    tacplus-server {
        10.0.0.79 {
            secret "x";
        }
    }
}
snmp {
    trap-group TG-1 {
        targets {
            10.0.0.80;
        }
    }
}
/system logging action
add name=remote remote=10.0.0.81 target=remote
/radius
add address=10.0.0.82 service=login
/snmp
set enabled=yes trap-target=10.0.0.83
/ip dhcp-relay
add dhcp-server=10.0.0.84 interface=ether2 name=rel1
syslog-server 10.0.0.85
wlan auth-server CORP-RAD
 ip 10.0.0.86
"""
    serv = extract_services_from_config(cfg)
    assert "10.0.0.75" in serv["dns_servers"]
    assert "10.0.0.76" in serv["ntp_servers"]
    for sys_ip in ("10.0.0.70", "10.0.0.77", "10.0.0.81", "10.0.0.85"):
        assert sys_ip in serv["syslog_servers"], f"Missing syslog {sys_ip}"
    for rad_ip in ("10.0.0.71", "10.0.0.78", "10.0.0.82", "10.0.0.86"):
        assert rad_ip in serv["radius_servers"], f"Missing radius {rad_ip}"
    for tac_ip in ("10.0.0.72", "10.0.0.79"):
        assert tac_ip in serv["tacacs_servers"], f"Missing tacacs {tac_ip}"
    for rel_ip in ("10.0.0.69", "10.0.0.68", "10.0.0.73", "10.0.0.74", "10.0.0.84"):
        assert rel_ip in serv["dhcp_relays"], f"Missing dhcp relay {rel_ip}"
    for snmp_ip in ("10.0.0.80", "10.0.0.83"):
        assert snmp_ip in serv["snmp_servers"], f"Missing snmp {snmp_ip}"


def test_wave2_base_sanitize_raw_config_sf05_complete():
    """Wave 2 (SF-05 #35): sanitize_raw_config scrubs FortiOS auth/priv-pwd, PAN-OS phash, OPNsense rocommunity/apikey, Cisco tacacs/radius/isakmp/ospf/hsrp keys, MikroTik wpa psk."""
    from net_docu_crawler.drivers.base import sanitize_raw_config

    raw = """
set auth-pwd ENC SuperSecretAuthPwd111
set priv-pwd ENC SuperSecretPrivPwd222
set api-key SuperSecretApiKey333
<phash>$1$panos$SuperSecretPanosHash444</phash>
<api-key>PanosApiKey555</api-key>
<rocommunity>OpnRoComm666</rocommunity>
<rwcommunity>OpnRwComm777</rwcommunity>
<apikey>OpnApiKey888</apikey>
<apisecret>OpnApiSecret999</apisecret>
tacacs-server key 7 CiscoTacKey101
radius-server key CiscoRadKey202
 key-string 7 CiscoKeyString303
 ip ospf message-digest-key 1 md5 7 CiscoOspfMd5Key404
 standby 10 authentication md5 key-string 7 CiscoHsrpKey505
wpa-pre-shared-key="MikrotikWpaKey606"
wpa2-pre-shared-key=MikrotikWpa2Key707
"""
    scrubbed = sanitize_raw_config(raw)
    for leaked in (
        "SuperSecretAuthPwd111",
        "SuperSecretPrivPwd222",
        "SuperSecretApiKey333",
        "SuperSecretPanosHash444",
        "PanosApiKey555",
        "OpnRoComm666",
        "OpnRwComm777",
        "OpnApiKey888",
        "OpnApiSecret999",
        "CiscoTacKey101",
        "CiscoRadKey202",
        "CiscoKeyString303",
        "CiscoOspfMd5Key404",
        "CiscoHsrpKey505",
        "MikrotikWpaKey606",
        "MikrotikWpa2Key707",
    ):
        assert leaked not in scrubbed, f"Secret {leaked!r} survived sanitize_raw_config()"

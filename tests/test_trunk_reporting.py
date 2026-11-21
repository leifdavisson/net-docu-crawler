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
End-to-end integration tests for Issue #2 Trunk VLAN Mismatch reporting:
  - `correlator.py`: propagation of trunk attributes into `dev["ports"]` and `correlate_dataset()` return
  - `quality_gates.py`: `GATE_TRUNK_VLAN_MISMATCH` (`WARN` vs `PASS`) and `trunk_audit_summary`
  - `report_generator.py` & `crawler.py`: `03_correlated/trunk_audit.json`,
    `03_correlated/trunk_mismatches.csv`, `trunk_vlan_audit.md`, `05_reports/trunk_vlan_audit.md`,
    and embedded "Trunk VLAN Mismatch & L2 Symmetry Audit" tables in `net_docu_crawler_live_report.md`
    and `Network_Analysis.md`.
"""

import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report_generator
from net_docu_crawler.correlator import correlate_dataset, correlate_device_ports
from net_docu_crawler.crawler import render_deliverables_from_dataset
from net_docu_crawler.quality_gates import evaluate_quality_gates, write_quality_report
from net_docu_crawler.topology_resolver import DeviceRegistry


def _build_mismatched_switch_pair() -> list[dict]:
    """Return a two-switch dataset with native VLAN (TRK-002) and allowed VLAN (TRK-004) mismatches."""
    sw1 = {
        "ip": "10.0.0.1",
        "hostname": "core-sw1",
        "status": "success",
        "record_class": "crawled_infra",
        "vendor": "Cisco",
        "os_type": "cisco_ios",
        "model": "C9300-48P",
        "serial": "FCW2211A001",
        "firmware": "17.9.4a",
        "mac_address": "00:1a:2b:3c:4d:01",
        "device_type": "switch",
        "device_persona": "switch",
        "vlans": {
            "1": {"id": "1", "name": "default"},
            "10": {"id": "10", "name": "DATA"},
            "20": {"id": "20", "name": "VOICE"},
            "30": {"id": "30", "name": "IOT"},
        },
        "interfaces_detail": {
            "GigabitEthernet1/0/1": {
                "status": "up",
                "admin_status": "up",
                "speed": "1Gb/s",
                "duplex": "Full",
                "description": "Uplink to dist-sw2",
            }
        },
        "port_profiles": {
            "GigabitEthernet1/0/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "1",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "10,20,30",
                "trunk_active_vlans": "10,20,30",
                "encapsulation": "dot1q",
                "qinq_tunnel": False,
                "is_subinterface_bundle": False,
            }
        },
        "neighbors": [
            {
                "local_port": "GigabitEthernet1/0/1",
                "remote_device": "dist-sw2",
                "remote_port": "ge-0/0/1",
                "remote_ip": "10.0.0.2",
                "device_type": "switch",
                "link_confidence": "two-way",
            }
        ],
        "l3_interfaces": [{"interface": "Vlan10", "ip_address": "10.0.0.1/24", "status": "up"}],
        "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.00:1a:2b:3c:4d:01"},
        "poe": {"total_power_watts": 715.0, "used_power_watts": 60.0, "poe_delivering_ports": 1},
    }
    sw2 = {
        "ip": "10.0.0.2",
        "hostname": "dist-sw2",
        "status": "success",
        "record_class": "crawled_infra",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "model": "EX3400-48P",
        "serial": "JN123456789",
        "firmware": "23.4R2",
        "mac_address": "00:1a:2b:3c:4d:02",
        "device_type": "switch",
        "device_persona": "switch",
        "vlans": {
            "10": {"id": "10", "name": "DATA"},
            "20": {"id": "20", "name": "VOICE"},
            "99": {"id": "99", "name": "NATIVE"},
        },
        "interfaces_detail": {
            "ge-0/0/1": {
                "status": "up",
                "admin_status": "up",
                "speed": "1Gb/s",
                "duplex": "Full",
                "description": "Uplink to core-sw1",
            }
        },
        "port_profiles": {
            "ge-0/0/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "99",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "10,20",
                "trunk_active_vlans": "10,20",
                "encapsulation": "dot1q",
                "qinq_tunnel": False,
                "is_subinterface_bundle": False,
            }
        },
        "neighbors": [
            {
                "local_port": "ge-0/0/1",
                "remote_device": "core-sw1",
                "remote_port": "GigabitEthernet1/0/1",
                "remote_ip": "10.0.0.1",
                "device_type": "switch",
                "link_confidence": "two-way",
            }
        ],
        "l3_interfaces": [{"interface": "irb.10", "ip_address": "10.0.0.2/24", "status": "up"}],
        "stp": {"enabled": True, "is_root": False, "root_bridge": "32768.00:1a:2b:3c:4d:01"},
        "poe": {"total_power_watts": 370.0, "used_power_watts": 30.0, "poe_delivering_ports": 1},
    }
    return [sw1, sw2]


def _build_symmetric_switch_pair() -> list[dict]:
    """Return a two-switch dataset with symmetric trunk configuration (0 CRITICAL/HIGH mismatches)."""
    devices = _build_mismatched_switch_pair()
    devices[0]["port_profiles"]["GigabitEthernet1/0/1"]["native_vlan"] = "99"
    devices[0]["port_profiles"]["GigabitEthernet1/0/1"]["trunk_allowed_vlans"] = "10,20"
    devices[0]["port_profiles"]["GigabitEthernet1/0/1"]["trunk_active_vlans"] = "10,20"
    devices[0]["vlans"]["99"] = {"id": "99", "name": "NATIVE"}
    return devices


def test_correlator_propagates_trunk_attributes_and_returns_trunk_audit():
    dev = {
        "hostname": "EDGE-RTR-01",
        "ip": "10.10.0.1",
        "status": "success",
        "interfaces_detail": {
            "Gi0/0": {"status": "up", "admin_status": "up", "speed": "1Gb/s", "duplex": "Full"},
            "Gi0/1": {"status": "up", "admin_status": "up", "speed": "1Gb/s", "duplex": "Full"},
        },
        "port_profiles": {
            "Gi0/0": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "10",
                "native_vlan_tagged": True,
                "trunk_allowed_vlans": "10,20,30",
                "trunk_active_vlans": "10,20",
                "encapsulation": "dot1q",
                "qinq_tunnel": False,
                "is_subinterface_bundle": True,
            },
            "Gi0/1": {
                "mode": "trunk",
                "admin_mode": "dot1q_tunnel",
                "oper_mode": "dot1q_tunnel",
                "access_vlan": "500",
                "native_vlan": "500",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "500",
                "trunk_active_vlans": "500",
                "encapsulation": "dot1q",
                "qinq_tunnel": True,
                "is_subinterface_bundle": False,
            },
        },
    }

    ports = correlate_device_ports(dev)
    p0 = ports["Gi0/0"]
    assert p0["admin_mode"] == "trunk"
    assert p0["oper_mode"] == "trunk"
    assert p0["native_vlan_tagged"] is True
    assert p0["trunk_active_vlans"] == "10,20"
    assert p0["encapsulation"] == "dot1q"
    assert p0["qinq_tunnel"] is False
    assert p0["is_subinterface_bundle"] is True

    p1 = ports["Gi0/1"]
    assert p1["admin_mode"] == "dot1q_tunnel"
    assert p1["oper_mode"] == "dot1q_tunnel"
    assert p1["qinq_tunnel"] is True
    assert p1["is_subinterface_bundle"] is False

    pair = _build_mismatched_switch_pair()
    corr = correlate_dataset(pair)
    assert "l3_svi_table" in corr
    assert "trunk_audit" in corr
    assert isinstance(corr["trunk_audit"], dict)
    assert "summary" in corr["trunk_audit"]
    assert "findings" in corr["trunk_audit"]
    assert "csv_rows" in corr["trunk_audit"]
    assert corr["trunk_audit"]["summary"]["critical_count"] >= 1
    assert corr["trunk_audit"]["summary"]["high_count"] >= 1


def test_quality_gates_trunk_vlan_mismatch_warn_and_pass(tmp_path):
    mismatched = _build_mismatched_switch_pair()
    corr_bad = correlate_dataset(mismatched)
    rep_warn = evaluate_quality_gates(mismatched)
    gates_warn = {g["gate"]: g for g in rep_warn["gates"]}

    assert "GATE_TRUNK_VLAN_MISMATCH" in gates_warn
    assert gates_warn["GATE_TRUNK_VLAN_MISMATCH"]["severity"] == "P1"
    assert gates_warn["GATE_TRUNK_VLAN_MISMATCH"]["status"] == "WARN"
    assert "CRITICAL" in gates_warn["GATE_TRUNK_VLAN_MISMATCH"]["detail"]
    assert "trunk_audit_summary" in rep_warn
    assert rep_warn["trunk_audit_summary"]["critical_count"] == corr_bad["trunk_audit"]["summary"]["critical_count"]
    # P1 WARN must not fail overall P0 cutover gate
    assert rep_warn["passed"] is True

    write_quality_report(rep_warn, str(tmp_path))
    dq_text = (tmp_path / "data_quality_report.md").read_text(encoding="utf-8")
    assert "GATE_TRUNK_VLAN_MISMATCH" in dq_text

    symmetric = _build_symmetric_switch_pair()
    corr_good = correlate_dataset(symmetric)
    rep_pass = evaluate_quality_gates(symmetric, trunk_audit=corr_good["trunk_audit"])
    gates_pass = {g["gate"]: g for g in rep_pass["gates"]}
    assert gates_pass["GATE_TRUNK_VLAN_MISMATCH"]["status"] == "PASS"
    assert rep_pass["trunk_audit_summary"]["critical_count"] == 0
    assert rep_pass["trunk_audit_summary"]["high_count"] == 0


def test_layered_exports_and_markdown_deliverables(tmp_path):
    mismatched = _build_mismatched_switch_pair()
    render_deliverables_from_dataset(
        raw_devices=mismatched,
        run_output_dir=str(tmp_path),
        targets=["10.0.0.0/24"],
    )

    # 1. Verify 03_correlated/trunk_audit.json
    json_path = tmp_path / "03_correlated" / "trunk_audit.json"
    assert json_path.is_file()
    audit_data = json.loads(json_path.read_text(encoding="utf-8"))
    assert audit_data["summary"]["critical_count"] >= 1
    assert audit_data["summary"]["high_count"] >= 1
    rule_ids = {f.get("rule_id") or f.get("Rule_ID") for f in audit_data["findings"]}
    assert "TRK-002" in rule_ids
    assert "TRK-004" in rule_ids

    # 2. Verify 03_correlated/trunk_mismatches.csv columns and rows
    csv_path = tmp_path / "03_correlated" / "trunk_mismatches.csv"
    assert csv_path.is_file()
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == [
            "Edge_ID",
            "Side_A_Host",
            "Side_A_Port",
            "Side_B_Host",
            "Side_B_Port",
            "Rule_ID",
            "Severity",
            "Side_A_Only_VLANs",
            "Side_B_Only_VLANs",
            "Remediation_Hint",
        ]
        csv_rows = list(reader)
    assert len(csv_rows) >= 2
    csv_rules = {r["Rule_ID"] for r in csv_rows}
    assert "TRK-002" in csv_rules
    assert "TRK-004" in csv_rules

    # 3. Verify trunk_vlan_audit.md and 05_reports/trunk_vlan_audit.md
    root_md = tmp_path / "trunk_vlan_audit.md"
    layered_md = tmp_path / "05_reports" / "trunk_vlan_audit.md"
    assert root_md.is_file()
    assert layered_md.is_file()
    md_text = root_md.read_text(encoding="utf-8")
    assert "AGPL-3.0-or-later" in md_text
    assert "GNU Affero General Public License" in md_text
    assert "## 1. Executive Summary & Audit Metrics" in md_text
    assert "## 2. Trunk VLAN Mismatch & L2 Symmetry Discrepancy Table" in md_text
    assert "## 3. Rule Reference & Multi-Vendor Remediation Guidance" in md_text
    assert "TRK-002" in md_text
    assert "TRK-004" in md_text

    # 4. Verify embedded section in net_docu_crawler_live_report.md and Network_Analysis.md
    live_text = (tmp_path / "net_docu_crawler_live_report.md").read_text(encoding="utf-8")
    bp_text = (tmp_path / "Network_Analysis.md").read_text(encoding="utf-8")
    assert "Trunk VLAN Mismatch & L2 Symmetry Audit" in live_text
    assert "TRK-002" in live_text
    assert "TRK-004" in live_text
    assert "Trunk VLAN Mismatch & L2 Symmetry Audit" in bp_text
    assert "TRK-002" in bp_text
    assert "TRK-004" in bp_text

    # 5. Verify direct call to report_generator.generate_trunk_audit_report with dict[ip, device]
    direct_md = tmp_path / "direct_trunk_audit.md"
    devices_by_ip = {d["ip"]: d for d in mismatched}
    report_generator.generate_trunk_audit_report(devices_by_ip, output_path=str(direct_md))
    assert direct_md.is_file()
    assert "TRK-002" in direct_md.read_text(encoding="utf-8")

    # 6. Verify direct call to report_generator.export_layered_csvs standalone
    standalone_dir = tmp_path / "standalone_layered"
    reg = DeviceRegistry()
    for d in mismatched:
        reg.register_device(d)
    report_generator.export_layered_csvs(mismatched, reg, str(standalone_dir))
    assert (standalone_dir / "03_correlated" / "trunk_audit.json").is_file()
    assert (standalone_dir / "03_correlated" / "trunk_mismatches.csv").is_file()
    assert (standalone_dir / "05_reports" / "trunk_vlan_audit.md").is_file()


def test_end_to_end_vendor_parser_to_trunk_deliverables(tmp_path):
    """Verify full pipeline from migration_parsers.extract_port_profiles -> trunk_audit -> correlator -> deliverables."""
    from net_docu_crawler.migration_parsers import extract_port_profiles, extract_vlans

    cisco_cfg = (
        "vlan dot1q tag native\n"
        "vlan 10\n"
        " name CORP\n"
        "vlan 20\n"
        " name VOICE\n"
        "interface GigabitEthernet1/0/1\n"
        " switchport mode trunk\n"
        " switchport trunk native vlan 10\n"
        " switchport trunk allowed vlan 10\n"
        " switchport trunk allowed vlan add 20\n"
        "!\n"
    )
    junos_cfg = (
        "set vlans CORP vlan-id 10\n"
        "set vlans VOICE vlan-id 20\n"
        "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk\n"
        "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members [ CORP VOICE ]\n"
        "set interfaces ge-0/0/1 native-vlan-id 10\n"
    )

    sw_cisco = {
        "ip": "10.20.0.1",
        "hostname": "cisco-core",
        "status": "success",
        "record_class": "crawled_infra",
        "vendor": "Cisco",
        "os_type": "cisco_ios",
        "model": "C9300-24T",
        "serial": "SN-CISCO-01",
        "firmware": "17.9.4",
        "mac_address": "00:11:22:33:44:01",
        "device_type": "switch",
        "device_persona": "switch",
        "raw_config": cisco_cfg,
        "vlans": extract_vlans(cisco_cfg, vendor="Cisco"),
        "port_profiles": extract_port_profiles(cisco_cfg, vendor="Cisco"),
        "interfaces_detail": {
            "GigabitEthernet1/0/1": {"status": "up", "admin_status": "up", "speed": "1Gb/s", "duplex": "Full"}
        },
        "neighbors": [
            {
                "local_port": "GigabitEthernet1/0/1",
                "remote_device": "junos-dist",
                "remote_port": "ge-0/0/1",
                "remote_ip": "10.20.0.2",
                "device_type": "switch",
            }
        ],
        "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.00:11:22:33:44:01"},
        "poe": {"total_power_watts": 0.0, "used_power_watts": 0.0, "poe_delivering_ports": 0},
    }
    sw_junos = {
        "ip": "10.20.0.2",
        "hostname": "junos-dist",
        "status": "success",
        "record_class": "crawled_infra",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "model": "EX3400-24T",
        "serial": "SN-JUNOS-02",
        "firmware": "23.4R2",
        "mac_address": "00:11:22:33:44:02",
        "device_type": "switch",
        "device_persona": "switch",
        "raw_config": junos_cfg,
        "vlans": extract_vlans(junos_cfg, vendor="Juniper Networks"),
        "port_profiles": extract_port_profiles(junos_cfg, vendor="Juniper Networks"),
        "interfaces_detail": {"ge-0/0/1": {"status": "up", "admin_status": "up", "speed": "1Gb/s", "duplex": "Full"}},
        "neighbors": [
            {
                "local_port": "ge-0/0/1",
                "remote_device": "cisco-core",
                "remote_port": "GigabitEthernet1/0/1",
                "remote_ip": "10.20.0.1",
                "device_type": "switch",
            }
        ],
        "stp": {"enabled": True, "is_root": False, "root_bridge": "32768.00:11:22:33:44:01"},
        "poe": {"total_power_watts": 0.0, "used_power_watts": 0.0, "poe_delivering_ports": 0},
    }

    render_deliverables_from_dataset([sw_cisco, sw_junos], run_output_dir=str(tmp_path), targets=["10.20.0.0/24"])

    # Cisco has `vlan dot1q tag native` (native_vlan_tagged=True) while Junos has `native-vlan-id 10` (native_vlan_tagged=False) -> TRK-003 HIGH
    assert sw_cisco["ports"]["GigabitEthernet1/0/1"]["native_vlan_tagged"] is True
    assert sw_junos["ports"]["ge-0/0/1"]["native_vlan_tagged"] is False

    audit_json = json.loads((tmp_path / "03_correlated" / "trunk_audit.json").read_text(encoding="utf-8"))
    rules = {f["rule_id"] for f in audit_json["findings"]}
    assert "TRK-003" in rules

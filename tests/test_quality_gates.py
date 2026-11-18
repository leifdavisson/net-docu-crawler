# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net_docu_crawler.quality_gates import evaluate_quality_gates, write_quality_report


def test_quality_gates_pass_and_fail(tmp_path):
    good = [
        {
            "hostname": "SW1",
            "status": "success",
            "record_class": "crawled_infra",
            "ports": {
                "ge-0/0/1": {"oper_state": "up", "mode": "access", "access_vlan": "10", "allowed_vlans": []},
                "ge-0/0/2": {"oper_state": "up", "mode": "trunk", "native_vlan": "1", "allowed_vlans": ["10", "20"]},
            },
            "poe": {"total_power_watts": 370.0, "poe_delivering_ports": 1},
            "stp": {"is_root": True, "root_bridge": "32768.aa:bb:cc:dd:ee:ff"},
        }
    ]
    rep = evaluate_quality_gates(good)
    assert rep["passed"] is True
    assert rep["port_confidence"]["known_vlan_pct"] == 100.0
    write_quality_report(rep, str(tmp_path))
    assert (tmp_path / "data_quality_report.md").exists()
    assert (tmp_path / "collection_manifest.json").exists()

    bad = [
        {
            "hostname": "SW-BAD",
            "status": "success",
            "record_class": "crawled_infra",
            "ports": {"A1": {"oper_state": "up", "mode": "access", "access_vlan": "", "allowed_vlans": []}},
            "poe": {"total_power_watts": 0.0, "poe_delivering_ports": 5},
            "stp": {"is_root": True, "root_bridge": ""},
        }
    ]
    bad_rep = evaluate_quality_gates(bad)
    assert bad_rep["passed"] is False
    statuses = {g["gate"]: g["status"] for g in bad_rep["gates"]}
    assert statuses["GATE_CABLING_VLAN_EMPTY"] == "FAIL"
    assert statuses["GATE_POE_CONTRADICTION"] == "FAIL"
    assert statuses["GATE_STP_ROOT_EVIDENCE"] == "FAIL"

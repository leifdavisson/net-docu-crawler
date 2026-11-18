# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net_docu_crawler.target_adapters import render_device_target_config


def test_target_adapter_gate_blocking():
    dev = {
        "hostname": "SW1",
        "ports": {
            "ge-0/0/1": {"mode": "access", "access_vlan": "10", "voice_vlan": ""},
            "ge-0/0/2": {"mode": "trunk", "native_vlan": "unknown", "allowed_vlans": ["10", "20"]},
            "ge-0/0/3": {"mode": "unknown"},
        },
    }
    junos_lines = render_device_target_config(dev, "juniper")
    assert any("vlan members 10" in ln for ln in junos_lines)
    assert any("BLOCKED: ge-0/0/2" in ln for ln in junos_lines)
    assert any("BLOCKED: ge-0/0/3" in ln for ln in junos_lines)

    meraki_lines = render_device_target_config(dev, "meraki")
    assert any('"portId": "ge-0/0/1"' in ln for ln in meraki_lines)
    assert any("BLOCKED: ge-0/0/2" in ln for ln in meraki_lines)


def test_generate_target_migration_configs_and_dataset_baseline_diff(tmp_path):
    import json

    import report_generator

    dev = {
        "hostname": "SW1",
        "ip": "10.0.0.1",
        "status": "success",
        "vendor": "HP",
        "model": "2530",
        "interfaces_detail": {"1": {"status": "up"}},
        "l3_interfaces": [{"interface": "VLAN 10", "ip_address": "10.0.10.1/24", "status": "up"}],
        "ports": {
            "1": {"mode": "access", "access_vlan": "10", "voice_vlan": ""},
            "2": {"mode": "trunk", "native_vlan": "unknown", "allowed_vlans": ["10"]},
        },
        "neighbors": [],
        "routes": [],
    }
    cfg_out = str(tmp_path / "target_junos.md")
    report_generator.generate_target_migration_configs({"10.0.0.1": dev}, "juniper", cfg_out)
    with open(cfg_out, encoding="utf-8") as f:
        txt = f.read()
    assert "BLOCKED: 2" in txt
    assert "vlan members 10" in txt

    base_path = str(tmp_path / "baseline_devices.json")
    with open(base_path, "w", encoding="utf-8") as f:
        json.dump([dev], f)
    curr_dev = dict(dev, interfaces_detail={"1": {"status": "down"}})
    diff_out = str(tmp_path / "delta.md")
    report_generator.compare_baseline_state({"10.0.0.1": curr_dev}, base_path, diff_out)
    with open(diff_out, encoding="utf-8") as f:
        diff_txt = f.read()
    assert "Interface Status Mismatch" in diff_txt

# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net_docu_crawler.schema import (
    SCHEMA_VERSION,
    build_empty_poe_summary,
    build_empty_port_record,
    classify_record_class,
    infer_site_code,
    normalize_tri_state,
    stamp_schema_v2,
)


def test_normalize_tri_state():
    assert normalize_tri_state(True) == "enabled"
    assert normalize_tri_state(False) == "disabled"
    assert normalize_tri_state("yes") == "enabled"
    assert normalize_tri_state("off") == "disabled"
    assert normalize_tri_state(None) == "unknown"
    assert normalize_tri_state("") == "unknown"


def test_classify_record_class():
    assert classify_record_class({"status": "success", "device_type": "switch"}) == "crawled_infra"
    assert classify_record_class({"status": "unauthenticated", "device_type": "switch"}) == "unauthenticated_infra"
    assert classify_record_class({"status": "unsupported", "device_type": "unknown"}) == "unsupported_appliance"
    assert classify_record_class({"status": "discovered", "device_type": "unknown"}) == "passive_endpoint"
    assert classify_record_class({"status": "success", "device_type": "camera"}) == "unsupported_appliance"


def test_infer_site_code():
    assert infer_site_code("DO-Main-BLDG") == "DO"
    assert infer_site_code("NMS_MDF_CORE_BLDG_B") == "NMS"
    assert infer_site_code("10.1.0.1", "10.1.0.1") == ""
    assert infer_site_code("") == ""


def test_empty_builders_and_stamp():
    port = build_empty_port_record("SW1", "ge-0/0/1")
    assert port["admin_state"] == "unknown"
    assert port["native_vlan"] == "unknown"
    assert port["bpdu_guard"] == "unknown"
    assert port["lag_id"] == "unknown"

    poe = build_empty_poe_summary()
    assert poe["poe_supported"] is False
    assert poe["poe_delivering_ports"] == 0

    dev = stamp_schema_v2({"ip": "10.1.0.1", "hostname": "DO-Main-BLDG", "status": "success", "device_type": "switch"})
    assert dev["schema_version"] == SCHEMA_VERSION
    assert dev["record_class"] == "crawled_infra"
    assert dev["site_code"] == "DO"
    assert "capture_time" in dev

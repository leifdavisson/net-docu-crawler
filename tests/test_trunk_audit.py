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
Unit & Verification Matrix Tests for Vendor-Agnostic Trunk VLAN Mismatch Detection
(`net_docu_crawler/trunk_audit.py`, GitHub Issue #2).
"""

import pytest

from net_docu_crawler.topology_resolver import DeviceRegistry
from net_docu_crawler.trunk_audit import (
    CSV_COLUMNS,
    TrunkDiscrepancySpec,
    TrunkEdgeContext,
    TrunkPortState,
    _build_audit_summary,
    _check_allowed_vlan_asymmetry,
    _check_native_tagging_mismatch,
    _check_native_vlan_mismatch,
    _check_oper_mode_mismatch,
    _record_discrepancy,
    _TrunkAuditStats,
    canonicalize_interface_full,
    evaluate_trunk_mismatches,
    expand_vlan_spec,
    extract_device_trunk_states,
    format_vlan_set,
    normalize_vendor_name,
)


@pytest.mark.parametrize(
    ("raw_intf", "expected"),
    [
        ("Gi1/0/1", "GigabitEthernet1/0/1"),
        ("GigabitEthernet1/0/24", "GigabitEthernet1/0/24"),
        ("Te1/1/1", "TenGigabitEthernet1/1/1"),
        ("Fa0/1", "FastEthernet0/1"),
        ("Twe1/0/1", "TwentyFiveGigE1/0/1"),
        ("25GE1/0/1", "TwentyFiveGigE1/0/1"),
        ("Fo1/0/1", "FortyGigabitEthernet1/0/1"),
        ("Hu1/0/1", "HundredGigE1/0/1"),
        ("Po1", "Port-channel1"),
        ("port-channel12", "Port-channel12"),
        ("Eth1/1", "Ethernet1/1"),
        ("Et1", "Ethernet1"),
        ("ae0.0", "ae0"),
        ("ge-0/0/1.0", "ge-0/0/1"),
        ("xe-0/0/1.0", "xe-0/0/1"),
        ("et-0/0/1.0", "et-0/0/1"),
        ("trk1", "Trk1"),
        ("lag 2", "lag2"),
        ("1/1/48", "1/1/48"),
    ],
)
def test_canonicalize_interface_full(raw_intf: str, expected: str) -> None:
    assert canonicalize_interface_full(raw_intf) == expected


def test_expand_vlan_spec_and_format() -> None:
    assert expand_vlan_spec("1,10-12,4094") == {1, 10, 11, 12, 4094}
    assert expand_vlan_spec("none") == set()
    assert expand_vlan_spec("") == set()
    assert expand_vlan_spec("all") == set(range(1, 4095))
    assert expand_vlan_spec("all", known_vlans={1, 10, 20}) == {1, 10, 20}
    assert expand_vlan_spec("all except 20", known_vlans={10, 20, 30}) == {10, 30}
    assert expand_vlan_spec(["10", "20-22", "4094"]) == {10, 20, 21, 22, 4094}
    assert format_vlan_set({1, 10, 11, 12, 50, 51, 4094}) == "1,10-12,50,51,4094"


def test_normalize_vendor_name() -> None:
    assert normalize_vendor_name("Cisco Systems", "cisco_ios") == "cisco_ios"
    assert normalize_vendor_name("Cisco Systems", "cisco_nxos") == "cisco_nxos"
    assert normalize_vendor_name("CiscoSMB", "cisco_s300") == "cisco_s300"
    assert normalize_vendor_name("Juniper Networks", "juniper_junos") == "juniper_junos"
    assert normalize_vendor_name("Aruba Networks / HPE", "aruba_aoscx", "switch") == "aruba_cx"
    assert normalize_vendor_name("HP ProCurve / ArubaOS-S", "hp_procurve") == "hp_procurve"
    assert normalize_vendor_name("Arista", "arista_eos") == "arista_eos"


def test_trunk_port_state_defaults() -> None:
    st = TrunkPortState(
        device_hostname="core-sw01",
        device_mgmt_ip="10.0.0.1",
        vendor="cisco_ios",
        interface_name="GigabitEthernet1/0/1",
    )
    assert st.lag_parent is None
    assert st.admin_mode == "access"
    assert st.oper_mode == "down"
    assert st.native_vlan == 1
    assert st.native_vlan_tagged is False
    assert st.allowed_vlans == set()
    assert st.active_vlans == set()
    assert st.encapsulation == "dot1q"
    assert st.qinq_tunnel is False
    assert st.is_subinterface_bundle is False


# ---------------------------------------------------------------------------
# Issue #2 Section 6: Verification Matrix Tests 1 - 4
# ---------------------------------------------------------------------------


def test_matrix_1_happy_path_cisco_junos_zero_discrepancies() -> None:
    """
    Test 1 (Happy Path): Cisco IOS Gi1/0/24 <-> Juniper JunOS ge-0/0/47 with
    matching native_vlan=999 and allowed_vlans={10,20,30} -> 0 discrepancies.
    """
    cisco_dev = {
        "hostname": "CORE-SW01.corp.example.com",
        "ip": "10.0.0.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "vlans": {"10": {"name": "USERS"}, "20": {"name": "VOICE"}, "30": {"name": "IOT"}, "999": {"name": "NATIVE"}},
        "interfaces_detail": {"GigabitEthernet1/0/24": {"status": "up"}},
        "port_profiles": {
            "GigabitEthernet1/0/24": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "10,20,30",
            }
        },
        "neighbors": [
            {
                "local_port": "Gi1/0/24",
                "remote_device": "idf-sw01.corp.example.com",
                "remote_port": "ge-0/0/47.0",
                "device_type": "switch",
            }
        ],
    }
    junos_dev = {
        "hostname": "idf-sw01.corp.example.com",
        "ip": "10.0.0.2",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "device_type": "switch",
        "vlans": {"10": {"name": "USERS"}, "20": {"name": "VOICE"}, "30": {"name": "IOT"}, "999": {"name": "NATIVE"}},
        "interfaces_detail": {"ge-0/0/47": {"status": "up"}},
        "port_profiles": {
            "ge-0/0/47": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "10,20,30",
            }
        },
        "neighbors": [
            {
                "local_port": "ge-0/0/47.0",
                "remote_device": "CORE-SW01",
                "remote_port": "GigabitEthernet1/0/24",
                "device_type": "switch",
            }
        ],
    }

    audit = evaluate_trunk_mismatches([cisco_dev, junos_dev])
    assert audit["summary"]["evaluated_edges"] == 1
    assert audit["summary"]["matched_edges"] == 1
    assert audit["summary"]["clean_edges"] == 1
    assert audit["summary"]["total_discrepancies"] == 0
    assert audit["findings"] == []
    assert audit["csv_rows"] == []


def test_matrix_2_lag_aggregation_single_trk004_finding() -> None:
    """
    Test 2 (LAG Aggregation): 4-link LACP bundle (Po1 <-> ae1) with mismatched
    VLAN 50 on ae1 -> Single TRK-004 finding emitted against Port-channel1 <-> ae1.
    """
    cisco_dev = {
        "hostname": "cisco-core",
        "ip": "10.0.0.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "vlans": {"10": {}, "20": {}, "30": {}, "999": {}},
        "interfaces_detail": {f"GigabitEthernet1/0/{i}": {"status": "up"} for i in range(1, 5)},
        "port_profiles": {
            "Gi1/0/1": {"mode": "trunk", "lag_group": "Po1"},
            "Gi1/0/2": {"mode": "trunk", "lag_group": "Po1"},
            "Gi1/0/3": {"mode": "trunk", "lag_group": "Po1"},
            "Gi1/0/4": {"mode": "trunk", "lag_group": "Po1"},
            "Port-channel1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "trunk_allowed_vlans": "10,20,30",
            },
        },
        "neighbors": [
            {
                "local_port": f"Gi1/0/{i}",
                "remote_device": "junos-dist",
                "remote_port": f"ge-0/0/{i}.0",
                "device_type": "switch",
            }
            for i in range(1, 5)
        ],
    }
    junos_dev = {
        "hostname": "junos-dist",
        "ip": "10.0.0.2",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "device_type": "switch",
        "vlans": {"10": {}, "20": {}, "30": {}, "50": {}, "999": {}},
        "interfaces_detail": {f"ge-0/0/{i}": {"status": "up"} for i in range(1, 5)},
        "port_profiles": {
            "ge-0/0/1": {"lag_group": "ae1"},
            "ge-0/0/2": {"lag_group": "ae1"},
            "ge-0/0/3": {"lag_group": "ae1"},
            "ge-0/0/4": {"lag_group": "ae1"},
            "ae1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "10,20,30,50",
            },
        },
        "neighbors": [
            {
                "local_port": f"ge-0/0/{i}",
                "remote_device": "cisco-core",
                "remote_port": f"GigabitEthernet1/0/{i}",
                "device_type": "switch",
            }
            for i in range(1, 5)
        ],
    }

    # Verify extract_device_trunk_states collapses 4 physical members into 1 parent LAG state
    cisco_states = extract_device_trunk_states(cisco_dev)
    assert len(cisco_states) == 1
    assert cisco_states[0].interface_name == "Port-channel1"

    audit = evaluate_trunk_mismatches([cisco_dev, junos_dev])
    assert len(audit["findings"]) == 1
    assert len(audit["csv_rows"]) == 1
    finding = audit["findings"][0]
    assert finding["edge_id"] == "cisco-core:Port-channel1<->junos-dist:ae1"
    assert finding["highest_severity"] == "HIGH"
    assert [d["rule_id"] for d in finding["discrepancies"]] == ["TRK-004"]

    row = audit["csv_rows"][0]
    assert tuple(row.keys()) == CSV_COLUMNS
    assert row["Rule_ID"] == "TRK-004"
    assert row["Side_A_Only_VLANs"] == ""
    assert row["Side_B_Only_VLANs"] == "50"


def test_matrix_3_asymmetric_native_tagging_trk003() -> None:
    """
    Test 3 (Asymmetric Native Tagging): Side A has vlan dot1q tag native
    (native_vlan_tagged=True), Side B has untagged native (native_vlan_tagged=False)
    -> TRK-003 triggered.
    """
    side_a = {
        "hostname": "sw-a",
        "ip": "10.0.0.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "port_profiles": {
            "TenGigabitEthernet1/1/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "99",
                "native_vlan_tagged": True,
                "trunk_allowed_vlans": "10,20,99",
            }
        },
        "neighbors": [
            {"local_port": "Te1/1/1", "remote_device": "sw-b", "remote_port": "1/1/1", "device_type": "switch"}
        ],
    }
    side_b = {
        "hostname": "sw-b",
        "ip": "10.0.0.2",
        "vendor": "Aruba Networks / HPE",
        "os_type": "aruba_aoscx",
        "device_type": "switch",
        "port_profiles": {
            "1/1/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "99",
                "native_vlan_tagged": False,
                "trunk_allowed_vlans": "10,20,99",
            }
        },
        "neighbors": [
            {
                "local_port": "1/1/1",
                "remote_device": "sw-a",
                "remote_port": "TenGigabitEthernet1/1/1",
                "device_type": "switch",
            }
        ],
    }

    audit = evaluate_trunk_mismatches([side_a, side_b])
    assert len(audit["findings"]) == 1
    rules = [d["rule_id"] for d in audit["findings"][0]["discrepancies"]]
    assert rules == ["TRK-003"]
    assert audit["summary"]["high_count"] == 1


def test_matrix_4_vlan_database_drift_trk005() -> None:
    """
    Test 4 (VLAN Database Drift): Both sides allow VLAN 40, but Side B lacks
    VLAN 40 in show vlan brief (`dev["vlans"]`) -> TRK-005 triggered.
    """
    side_a = {
        "hostname": "sw-a",
        "ip": "10.0.0.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "vlans": {"10": {"name": "A"}, "20": {"name": "B"}, "40": {"name": "DRIFT"}, "999": {"name": "NAT"}},
        "port_profiles": {
            "Gi1/0/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "trunk_allowed_vlans": "10,20,40",
            }
        },
        "neighbors": [
            {"local_port": "Gi1/0/1", "remote_device": "sw-b", "remote_port": "Gi1/0/1", "device_type": "switch"}
        ],
    }
    side_b = {
        "hostname": "sw-b",
        "ip": "10.0.0.2",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "vlans": {"10": {"name": "A"}, "20": {"name": "B"}, "999": {"name": "NAT"}},  # Missing VLAN 40!
        "port_profiles": {
            "Gi1/0/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "trunk_allowed_vlans": "10,20,40",
            }
        },
        "neighbors": [
            {"local_port": "Gi1/0/1", "remote_device": "sw-a", "remote_port": "Gi1/0/1", "device_type": "switch"}
        ],
    }

    audit = evaluate_trunk_mismatches([side_a, side_b])
    assert len(audit["findings"]) == 1
    disc = audit["findings"][0]["discrepancies"]
    assert [d["rule_id"] for d in disc] == ["TRK-005"]
    assert disc[0]["severity"] == "MEDIUM"
    assert disc[0]["side_a_only_vlans"] == [40]
    assert disc[0]["side_b_only_vlans"] == []
    assert audit["csv_rows"][0]["Side_A_Only_VLANs"] == "40"


# ---------------------------------------------------------------------------
# Additional Rule & Edge-Case Coverage (TRK-001, TRK-002, TRK-006, TRK-007,
# QinQ, Subinterfaces, Uncrawled Neighbor, Asymmetric Discovery)
# ---------------------------------------------------------------------------


def test_trk001_trk002_trk006_trk007_comparative_rules() -> None:
    """Verify TRK-001 (oper_mode), TRK-002 (native_vlan), TRK-006 (VLAN 1), and TRK-007 (DTP)."""
    side_a = {
        "hostname": "dist-01",
        "ip": "10.1.1.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "port_profiles": {
            "Gi1/0/1": {
                "mode": "trunk",
                "admin_mode": "dynamic_desirable",
                "oper_mode": "trunk",
                "native_vlan": "99",
                "trunk_allowed_vlans": "1,10,20,99",
            }
        },
        "neighbors": [
            {"local_port": "Gi1/0/1", "remote_device": "acc-01", "remote_port": "Gi0/1", "device_type": "switch"}
        ],
    }
    side_b = {
        "hostname": "acc-01",
        "ip": "10.1.1.2",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "port_profiles": {
            "Gi0/1": {
                "mode": "access",
                "admin_mode": "access",
                "oper_mode": "access",
                "access_vlan": "10",
            }
        },
        "neighbors": [
            {"local_port": "Gi0/1", "remote_device": "dist-01", "remote_port": "Gi1/0/1", "device_type": "switch"}
        ],
    }

    audit = evaluate_trunk_mismatches([side_a, side_b])
    assert len(audit["findings"]) == 5
    finding = audit["findings"][0]
    assert finding["highest_severity"] == "CRITICAL"
    triggered = {f["rule_id"]: f["severity"] for f in audit["findings"]}
    assert triggered["TRK-001"] == "CRITICAL"
    assert triggered["TRK-002"] == "CRITICAL"
    assert triggered["TRK-004"] == "HIGH"
    assert triggered["TRK-006"] == "MEDIUM"
    assert triggered["TRK-007"] == "LOW"
    assert audit["summary"]["critical_count"] == 2
    assert audit["summary"]["high_count"] == 1
    assert audit["summary"]["medium_count"] == 1
    assert audit["summary"]["low_count"] == 1


def test_both_sides_tagged_none_native_vlan_passes_trk002() -> None:
    """When both peers explicitly tag all VLANs with native_vlan='none', neither TRK-002 nor TRK-003 fires."""
    junos_a = {
        "hostname": "junos-a",
        "ip": "10.2.0.1",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "device_type": "switch",
        "port_profiles": {
            "xe-0/0/0": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "none",
                "native_vlan_tagged": True,
                "trunk_allowed_vlans": "100,200",
            }
        },
        "neighbors": [
            {"local_port": "xe-0/0/0", "remote_device": "procurve-b", "remote_port": "Trk1", "device_type": "switch"}
        ],
    }
    procurve_b = {
        "hostname": "procurve-b",
        "ip": "10.2.0.2",
        "vendor": "HP ProCurve / ArubaOS-S",
        "os_type": "hp_procurve",
        "device_type": "switch",
        "port_profiles": {
            "Trk1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "none",
                "native_vlan_tagged": True,
                "trunk_allowed_vlans": "100,200",
            }
        },
        "neighbors": [
            {"local_port": "Trk1", "remote_device": "junos-a", "remote_port": "xe-0/0/0", "device_type": "switch"}
        ],
    }

    audit = evaluate_trunk_mismatches([junos_a, procurve_b])
    assert audit["findings"] == []
    assert audit["summary"]["clean_edges"] == 1


def test_qinq_boundary_info_bypasses_trk004_and_trk005() -> None:
    """QinQ (dot1q_tunnel) uplink flags INFO_QINQ_BOUNDARY and bypasses TRK-004/TRK-005."""
    provider_pe = {
        "hostname": "metro-pe01",
        "ip": "10.3.0.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "vlans": {"500": {"name": "CUST_SVLAN"}},
        "port_profiles": {
            "Gi1/0/1": {
                "mode": "trunk",
                "admin_mode": "dot1q_tunnel",
                "oper_mode": "dot1q_tunnel",
                "qinq_tunnel": True,
                "native_vlan": "999",
                "trunk_allowed_vlans": "500",
            }
        },
        "neighbors": [
            {"local_port": "Gi1/0/1", "remote_device": "cust-ce01", "remote_port": "Gi0/1", "device_type": "switch"}
        ],
    }
    customer_ce = {
        "hostname": "cust-ce01",
        "ip": "10.3.0.2",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "vlans": {"10": {}, "20": {}, "30": {}},
        "port_profiles": {
            "Gi0/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "trunk_allowed_vlans": "10,20,30",
            }
        },
        "neighbors": [
            {"local_port": "Gi0/1", "remote_device": "metro-pe01", "remote_port": "Gi1/0/1", "device_type": "switch"}
        ],
    }

    audit = evaluate_trunk_mismatches([provider_pe, customer_ce])
    assert len(audit["findings"]) == 1
    finding = audit["findings"][0]
    assert finding["status"] == "QINQ_BOUNDARY"
    assert finding["highest_severity"] == "INFO"
    rules = [d["rule_id"] for d in finding["discrepancies"]]
    assert rules == ["INFO_QINQ_BOUNDARY"]
    assert "TRK-004" not in rules
    assert "TRK-005" not in rules


def test_router_on_a_stick_dot1q_subinterfaces() -> None:
    """Router L3 802.1Q subinterfaces (Gi0/0.10, Gi0/0.20, Gi0/0.99 native) synthesize into parent TrunkPortState."""
    router = {
        "hostname": "edge-rtr01",
        "ip": "10.4.0.1",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "router",
        "interfaces_detail": {"GigabitEthernet0/0": {"status": "up"}},
        "port_profiles": {},
        "raw_config": (
            "interface GigabitEthernet0/0\n"
            " no ip address\n"
            "!\n"
            "interface GigabitEthernet0/0.10\n"
            " encapsulation dot1Q 10\n"
            " ip address 10.10.0.1 255.255.255.0\n"
            "!\n"
            "interface GigabitEthernet0/0.20\n"
            " encapsulation dot1Q 20\n"
            " ip address 10.20.0.1 255.255.255.0\n"
            "!\n"
            "interface GigabitEthernet0/0.99\n"
            " encapsulation dot1Q 99 native\n"
            " ip address 10.99.0.1 255.255.255.0\n"
            "!\n"
        ),
        "neighbors": [
            {"local_port": "Gi0/0", "remote_device": "core-sw01", "remote_port": "Gi1/0/1", "device_type": "switch"}
        ],
    }
    switch = {
        "hostname": "core-sw01",
        "ip": "10.4.0.2",
        "vendor": "Cisco Systems",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "port_profiles": {
            "Gi1/0/1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "99",
                "trunk_allowed_vlans": "10,20,30,99",
            }
        },
        "neighbors": [
            {"local_port": "Gi1/0/1", "remote_device": "edge-rtr01", "remote_port": "Gi0/0", "device_type": "router"}
        ],
    }

    rtr_states = extract_device_trunk_states(router)
    assert len(rtr_states) == 1
    assert rtr_states[0].interface_name == "GigabitEthernet0/0"
    assert rtr_states[0].is_subinterface_bundle is True
    assert rtr_states[0].native_vlan == 99
    assert rtr_states[0].allowed_vlans == {10, 20, 99}

    audit = evaluate_trunk_mismatches([router, switch])
    assert len(audit["findings"]) == 1
    disc = audit["findings"][0]["discrepancies"]
    assert [d["rule_id"] for d in disc] == ["TRK-004"]
    assert disc[0]["side_a_only_vlans"] == [30]


def test_uncrawled_neighbor_and_edge_peripheral_filtering() -> None:
    """
    ERR_UNCRAWLED_NEIGHBOR fires for uncrawled switches/trunks, while VoIP phones,
    printers, and AP endpoints are skipped cleanly.
    """
    sw = {
        "hostname": "idf-sw01",
        "ip": "192.168.1.3",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "device_type": "switch",
        "port_profiles": {
            "ge-0/0/1": {"mode": "trunk", "native_vlan": "999", "trunk_allowed_vlans": "10,20"},
            "ge-0/0/2": {"mode": "trunk", "native_vlan": "999", "trunk_allowed_vlans": "10,20"},
            "ge-0/0/3": {"mode": "access", "access_vlan": "10"},
            "ge-0/0/4": {"mode": "access", "access_vlan": "10"},
        },
        "neighbors": [
            {
                "local_port": "ge-0/0/1",
                "remote_device": "uncrawled-core-sw",
                "remote_port": "23",
                "device_type": "switch",
                "platform": "Hewlett Packard Switch",
            },
            {
                "local_port": "ge-0/0/2",
                "remote_device": "lobby-ap01",
                "remote_port": "eth0",
                "device_type": "ap",
                "platform": "Aruba AP-515",
            },
            {
                "local_port": "ge-0/0/3",
                "remote_device": "SEP001122334455",
                "remote_port": "Port 1",
                "device_type": "phone",
                "platform": "Cisco IP Phone CP-8841",
            },
            {
                "local_port": "ge-0/0/4",
                "remote_device": "NPI0775A3",
                "remote_port": "eth0",
                "device_type": "printer",
                "platform": "HP LaserJet Printer",
            },
        ],
    }

    audit = evaluate_trunk_mismatches([sw])
    assert audit["summary"]["uncrawled_neighbor_edges"] == 1
    assert len(audit["findings"]) == 1
    assert audit["findings"][0]["status"] == "UNCRAWLED_NEIGHBOR"
    assert audit["findings"][0]["discrepancies"][0]["rule_id"] == "ERR_UNCRAWLED_NEIGHBOR"
    assert audit["findings"][0]["discrepancies"][0]["severity"] == "MEDIUM"


def test_asymmetric_discovery_raw_and_reconciled_inferred() -> None:
    """
    WARN_ASYMMETRIC_DISCOVERY triggers both before AND after
    DeviceRegistry.reconcile_reciprocal_neighbors() synthesizes INFERRED reverse neighbors,
    while still evaluating comparative trunk rules (e.g., TRK-004).
    """
    sw_a = {
        "hostname": "sw-alpha",
        "ip": "10.5.0.1",
        "serial": "SERA001",
        "status": "success",
        "vendor": "Arista",
        "os_type": "arista_eos",
        "device_type": "switch",
        "interfaces_detail": {"Ethernet1": {"status": "up"}},
        "port_profiles": {
            "Ethernet1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "trunk_allowed_vlans": "10,20",
            }
        },
        "neighbors": [
            {
                "local_port": "Eth1",
                "remote_device": "sw-beta",
                "remote_port": "Eth1",
                "device_type": "switch",
            }
        ],
    }
    sw_b = {
        "hostname": "sw-beta",
        "ip": "10.5.0.2",
        "serial": "SERB002",
        "status": "success",
        "vendor": "Arista",
        "os_type": "arista_eos",
        "device_type": "switch",
        "interfaces_detail": {"Ethernet1": {"status": "up"}},
        "port_profiles": {
            "Ethernet1": {
                "mode": "trunk",
                "admin_mode": "trunk",
                "oper_mode": "trunk",
                "native_vlan": "999",
                "trunk_allowed_vlans": "10,20,30",
            }
        },
        "neighbors": [],  # LLDP TX disabled on sw-beta!
    }

    # 1. Raw missing reciprocal entry
    audit_raw = evaluate_trunk_mismatches([sw_a, sw_b])
    assert audit_raw["summary"]["asymmetric_discovery_edges"] == 1
    rules_raw = [d["rule_id"] for d in audit_raw["findings"][0]["discrepancies"]]
    assert "WARN_ASYMMETRIC_DISCOVERY" in rules_raw
    assert "TRK-004" in rules_raw

    # 2. After DeviceRegistry.reconcile_reciprocal_neighbors synthesizes link_confidence="INFERRED"
    reg = DeviceRegistry()
    reg.register_device(sw_a)
    reg.register_device(sw_b)
    reg.reconcile_reciprocal_neighbors([sw_a, sw_b])
    assert any(n.get("link_confidence") == "INFERRED" for n in sw_b["neighbors"])

    audit_reconciled = evaluate_trunk_mismatches([sw_a, sw_b])
    assert audit_reconciled["summary"]["asymmetric_discovery_edges"] == 1
    rules_rec = [d["rule_id"] for d in audit_reconciled["findings"][0]["discrepancies"]]
    assert "WARN_ASYMMETRIC_DISCOVERY" in rules_rec
    assert "TRK-004" in rules_rec


def test_typed_discrepancy_spec_and_record_discrepancy_contract() -> None:
    """Verify `TrunkDiscrepancySpec` + `_record_discrepancy` schema parity and counter aggregation."""
    edge = TrunkEdgeContext(
        edge_id="core-01:Port-channel1<->dist-01:ae0",
        side_a_host="core-01",
        side_a_port="Port-channel1",
        side_b_host="dist-01",
        side_b_port="ae0",
    )
    spec = TrunkDiscrepancySpec(
        edge=edge,
        rule_id="TRK-004",
        severity="HIGH",
        message="Allowed VLAN mismatch on uplink.",
        remediation_hint="Synchronize allowed VLANs.",
        side_a_only_vlans=[10, 11, 12],
        side_b_only_vlans=[50],
    )
    discrepancies: list[dict] = []
    stats = _TrunkAuditStats(total_trunk_ports=2, evaluated_edges=1, matched_edges=1, mismatched_edges=1)

    recorded = _record_discrepancy(spec, discrepancies, stats)
    assert recorded == {
        "rule_id": "TRK-004",
        "severity": "HIGH",
        "message": "Allowed VLAN mismatch on uplink.",
        "side_a_only_vlans": [10, 11, 12],
        "side_b_only_vlans": [50],
        "remediation_hint": "Synchronize allowed VLANs.",
    }
    assert len(discrepancies) == 1
    assert len(stats.csv_rows) == 1
    csv_row = stats.csv_rows[0]
    assert tuple(csv_row.keys()) == CSV_COLUMNS
    assert csv_row["Side_A_Only_VLANs"] == "10-12"
    assert csv_row["Side_B_Only_VLANs"] == "50"

    summary = _build_audit_summary(stats)
    assert summary["high_count"] == 1
    assert summary["total_discrepancies"] == 1
    assert summary["by_rule"] == {"TRK-004": 1}


def test_single_link_discrepancy_helpers_and_routed_p2p_skip() -> None:
    """Verify decomposed single-link rule helpers and pure L3 routed link exclusion."""
    st_a = TrunkPortState(
        device_hostname="sw-a",
        device_mgmt_ip="10.0.0.1",
        vendor="cisco_ios",
        interface_name="GigabitEthernet1/0/1",
        admin_mode="trunk",
        oper_mode="trunk",
        native_vlan=10,
        native_vlan_tagged=False,
        allowed_vlans={10, 20, 30},
        active_vlans={10, 20, 30},
    )
    st_b = TrunkPortState(
        device_hostname="sw-b",
        device_mgmt_ip="10.0.0.2",
        vendor="juniper_junos",
        interface_name="ge-0/0/1",
        admin_mode="trunk",
        oper_mode="access",
        native_vlan=20,
        native_vlan_tagged=True,
        allowed_vlans={20, 40},
        active_vlans={20, 40},
    )
    edge = TrunkEdgeContext(
        edge_id="sw-a:GigabitEthernet1/0/1<->sw-b:ge-0/0/1",
        side_a_host="sw-a",
        side_a_port="GigabitEthernet1/0/1",
        side_b_host="sw-b",
        side_b_port="ge-0/0/1",
        state_a=st_a,
        state_b=st_b,
    )

    assert _check_oper_mode_mismatch(edge, is_qinq_edge=False) is not None
    nat_spec = _check_native_vlan_mismatch(edge)
    assert nat_spec is not None and nat_spec.side_a_only_vlans == [10] and nat_spec.side_b_only_vlans == [20]
    assert _check_native_tagging_mismatch(edge) is not None
    allowed_spec = _check_allowed_vlan_asymmetry(edge)
    assert (
        allowed_spec is not None
        and allowed_spec.side_a_only_vlans == [10, 30]
        and allowed_spec.side_b_only_vlans == [40]
    )

    # Pure L3 routed point-to-point links without 802.1Q subinterfaces must be skipped
    rtr_a = {
        "hostname": "rtr-a",
        "ip": "172.16.0.1",
        "vendor": "Cisco",
        "os_type": "cisco_ios",
        "device_type": "router",
        "port_profiles": {"Gi0/0": {"mode": "routed", "admin_mode": "routed", "oper_mode": "routed"}},
        "neighbors": [
            {"local_port": "Gi0/0", "remote_device": "rtr-b", "remote_port": "Gi0/0", "device_type": "router"}
        ],
    }
    rtr_b = {
        "hostname": "rtr-b",
        "ip": "172.16.0.2",
        "vendor": "Cisco",
        "os_type": "cisco_ios",
        "device_type": "router",
        "port_profiles": {"Gi0/0": {"mode": "routed", "admin_mode": "routed", "oper_mode": "routed"}},
        "neighbors": [
            {"local_port": "Gi0/0", "remote_device": "rtr-a", "remote_port": "Gi0/0", "device_type": "router"}
        ],
    }
    routed_audit = evaluate_trunk_mismatches([rtr_a, rtr_b])
    assert routed_audit["summary"]["evaluated_edges"] == 0
    assert routed_audit["findings"] == []

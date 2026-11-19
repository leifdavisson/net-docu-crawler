# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net_docu_crawler.correlator import correlate_dataset
from net_docu_crawler.topology_resolver import DeviceRegistry


def test_correlate_device_ports_and_stp_consensus():
    core = {
        "ip": "10.250.6.2",
        "hostname": "NMS_MDF_CORE_BLDG_B",
        "status": "success",
        "device_type": "switch",
        "vlans": {"10": {"id": "10", "name": "Voice"}, "3019": {"id": "3019", "name": "MGMT"}},
        "interfaces_detail": {
            "ge-0/0/8": {"status": "up", "admin_status": "up", "speed": "1Gb/s", "duplex": "Full"},
            "ge-0/0/10": {"status": "down", "admin_status": "down", "speed": "1Gb/s", "duplex": "Full"},
        },
        "port_profiles": {
            "ge-0/0/8": {"mode": "trunk", "trunk_allowed_vlans": "all", "native_vlan": "3019"},
        },
        "neighbors": [
            {
                "local_port": "ge-0/0/8",
                "remote_device": "NMS_BLDG_H_RMs_9-12",
                "remote_port": "ge-0/2/0",
                "device_type": "switch",
            }
        ],
        "mac_table": [{"interface": "ge-0/0/8", "mac": "aa:bb:cc:dd:ee:ff", "vlan": "10"}],
        "l3_interfaces": [{"interface": "irb.3019", "ip_address": "172.31.1.1/24", "status": "up"}],
        "dhcp": {"relays": [{"interface": "irb.3019", "helper_ip": "10.0.0.3"}]},
        "stp": {"enabled": True, "is_root": False, "root_bridge": "32768.20:d8:0b:8f:ad:de"},
    }
    isolated = {
        "ip": "172.31.1.81",
        "hostname": "NMS_BLDG_H_RMs_9-12",
        "status": "success",
        "device_type": "switch",
        "interfaces_detail": {},
        "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.20:d8:0b:8f:59:12"},
    }

    res = correlate_dataset([core, isolated])
    assert core["ports"]["ge-0/0/8"]["allowed_vlans"] == ["10", "3019"]
    assert core["ports"]["ge-0/0/8"]["hygiene_disposition"] == "DO_NOT_MOVE"
    assert core["ports"]["ge-0/0/8"]["edge_mac_count"] == 0
    assert core["ports"]["ge-0/0/8"]["trunk_mac_count"] == 1
    assert core["ports"]["ge-0/0/10"]["hygiene_disposition"] == "SHUTDOWN"
    assert isolated["stp"]["is_verified_campus_root"] is False
    assert isolated["stp"]["root_scope"] == "isolated_self_root"
    assert len(res["l3_svi_table"]) == 1
    assert res["l3_svi_table"][0]["vlan_id"] == "3019"
    assert res["l3_svi_table"][0]["dhcp_relays"] == ["10.0.0.3"]


def test_reciprocal_lldp_writeback():
    reg = DeviceRegistry()
    d1 = {
        "ip": "10.250.6.2",
        "hostname": "NMS_MDF_CORE_BLDG_B",
        "neighbors": [{"local_port": "ge-0/0/8", "remote_device": "NMS_BLDG_H_RMs_9-12", "remote_port": "Unknown"}],
    }
    d2 = {
        "ip": "172.31.1.81",
        "hostname": "NMS_BLDG_H_RMs_9-12",
        "neighbors": [{"local_port": "ge-0/2/0", "remote_device": "NMS_MDF_CORE_BLDG_B", "remote_port": "ge-0/0/8"}],
    }
    reg.add_bidirectional_link("NMS_MDF_CORE_BLDG_B", "ge-0/0/8", "NMS_BLDG_H_RMs_9-12", "Unknown")
    reg.add_bidirectional_link("NMS_BLDG_H_RMs_9-12", "ge-0/2/0", "NMS_MDF_CORE_BLDG_B", "ge-0/0/8")
    reg.reconcile_reciprocal_neighbors([d1, d2])
    assert d1["neighbors"][0]["remote_port"] == "ge-0/2/0"
    assert d1["neighbors"][0]["link_confidence"] == "two-way"


def test_extract_vrfs_and_acls_propagation():
    from net_docu_crawler.correlator import correlate_device_ports
    from net_docu_crawler.migration_parsers import extract_vrfs_and_acls

    cfg = "ip vrf MGMT\ninterface Gi1/0/1\n ip access-group EDGE_IN in\n ip access-group EDGE_OUT out\n!\n"
    vrfs, acls = extract_vrfs_and_acls(cfg, vendor="cisco")
    assert vrfs == [{"name": "MGMT", "type": "vrf"}]
    assert acls["Gi1/0/1"] == {"acl_in": "EDGE_IN", "acl_out": "EDGE_OUT"}

    dev = {
        "hostname": "SW-ACL",
        "ip": "10.0.0.1",
        "interfaces_detail": {"Gi1/0/1": {"status": "up", "admin_status": "up"}},
        "port_profiles": {"Gi1/0/1": {"mode": "access", "access_vlan": "10", **acls["Gi1/0/1"]}},
        "vrfs": vrfs,
    }
    ports = correlate_device_ports(dev)
    assert ports["Gi1/0/1"]["acl_in"] == "EDGE_IN"
    assert ports["Gi1/0/1"]["acl_out"] == "EDGE_OUT"

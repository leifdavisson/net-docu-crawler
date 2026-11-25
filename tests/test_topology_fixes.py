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

"""Regression tests for Topology & Registry audit fixes (TP-01..TP-17, TR-13)."""

from __future__ import annotations

import copy
import threading

import pytest

from net_docu_crawler.topology_renderer import _norm_iface, _parse_speed_mbps, build_topology_graph_model
from net_docu_crawler.topology_resolver import (
    DeviceRegistry,
    is_clean_interface_token,
    normalize_interface,
    pick_clean_remote_port,
)
from net_docu_crawler.trunk_audit import canonicalize_interface_full, evaluate_trunk_mismatches


def test_tp01_interface_normalization_consistency_across_modules():
    """TP-01: Equivalent vendor interface names normalize consistently across resolver, renderer, and trunk_audit."""
    # Arista/Cisco Ethernet aliases must converge (Ethernet1 == Eth1 == Et1 == et1)
    eth_aliases = ("Ethernet1", "Eth1", "Et1", "et1")
    assert len({normalize_interface(p).lower() for p in eth_aliases}) == 1
    assert len({_norm_iface(p) for p in eth_aliases}) == 1
    assert len({canonicalize_interface_full(p) for p in eth_aliases}) == 1

    # Linux/appliance lowercase eth0 must NOT be rewritten to Ethernet0 in trunk_audit
    assert canonicalize_interface_full("eth0") == "eth0"
    assert canonicalize_interface_full("eth1") == "eth1"
    assert normalize_interface("eth0") == "eth0"
    assert _norm_iface("eth0") == "eth0"

    # LAG / Bundle / Multi-gig / IOS-XR interface aliases must converge
    groups = [
        ("Port-channel1", "Po1", "port-channel 1"),
        ("Bundle-Ether10", "BE10", "bundle-ether 10"),
        ("TwentyFiveGigE1/0/1", "TwentyFiveGigabitEthernet1/0/1", "Twe1/0/1", "25GE1/0/1"),
        ("TwoPointFiveGigabitEthernet1/0/2", "Tw1/0/2"),
        ("FiveGigabitEthernet1/0/3", "Fi1/0/3"),
        ("TenGigabitEthernet0/0/0/0", "TenGigE0/0/0/0", "Ten0/0/0/0", "Te0/0/0/0"),
        ("FortyGigabitEthernet1/0/1", "FortyGigE1/0/1", "Fo1/0/1"),
        ("HundredGigabitEthernet1/0/1", "HundredGigE1/0/1", "Hun1/0/1", "Hu1/0/1"),
        ("GigabitEthernet1/0/1", "Gig1/0/1", "Gi1/0/1"),
        ("FastEthernet0/1", "Fast0/1", "Fa0/1"),
        ("et-0/0/0.0", "et-0/0/0"),
    ]
    for aliases in groups:
        assert len({normalize_interface(a).lower() for a in aliases}) == 1, f"topology_resolver mismatch: {aliases}"
        assert len({_norm_iface(a) for a in aliases}) == 1, f"topology_renderer mismatch: {aliases}"
        assert len({canonicalize_interface_full(a) for a in aliases}) == 1, f"trunk_audit mismatch: {aliases}"


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        ("et-0/0/0", (100000, "100G")),
        ("HundredGigabitEthernet1/0/1", (100000, "100G")),
        ("FortyGigE1/0/1", (40000, "40G")),
        ("TwentyFiveGigE1/0/1", (25000, "25G")),
        ("Twe1/0/1", (25000, "25G")),
        ("25GE1/0/1", (25000, "25G")),
        ("TenGigE0/0/0/0", (10000, "10G")),
        ("FiveGigabitEthernet1/0/1", (5000, "5G")),
        ("Fi1/0/1", (5000, "5G")),
        ("TwoPointFiveGigabitEthernet1/0/1", (2500, "2.5G")),
        ("Tw1/0/1", (2500, "2.5G")),
        ("vtnet0", (1000, "1G")),
        ("ether1", (1000, "1G")),
        ("eth0", (1000, "1G")),
    ],
)
def test_tp02_speed_inference_no_prefix_collisions(port: str, expected: tuple[int, str]):
    """TP-02: infer_interface_speed and _parse_speed_mbps avoid et-/10M and Twe/25G collisions."""
    from net_docu_crawler.topology_resolver import infer_interface_speed

    assert infer_interface_speed("", port) == expected
    assert _parse_speed_mbps("", port) == expected


def test_tp03_clean_interface_tokens_and_remote_port_picker():
    """TP-03: Valid multi-vendor port IDs (port1, Po1, BE1, Twe, TenGigE, Management1) beat description tokens."""
    for tok in (
        "port1",
        "Po1",
        "Port-channel1",
        "BE10",
        "Bundle-Ether10",
        "Twe1/0/1",
        "TwoPointFiveGigabitEthernet1/0/1",
        "FiveGigabitEthernet1/0/1",
        "TenGigE0/0/0/0",
        "Management1",
        "Mgmt0",
    ):
        assert is_clean_interface_token(tok) is True, f"Expected clean token for {tok!r}"

    assert pick_clean_remote_port("port1", "", "ge-0/0/1") == ("port1", "ge-0/0/1")
    assert pick_clean_remote_port("Po1", "", "ge-0/0/1") == ("Po1", "ge-0/0/1")
    assert pick_clean_remote_port("Twe1/0/1", "", "Uplink to Core") == ("Twe1/0/1", "Uplink to Core")


def test_tp04_fhrp_laa_and_cloned_hypervisor_macs_do_not_collide():
    """TP-04: HA peers sharing FHRP virtual MACs (VRRP/CARP/HSRP/GLBP/FGCP) or cloned hypervisor/LAA MACs stay distinct."""
    from net_docu_crawler.topology_resolver import is_fhrp_virtual_mac, is_locally_administered_mac

    assert is_fhrp_virtual_mac("00:00:5e:00:01:01")  # VRRPv2/v3 IPv4 / CARP
    assert is_fhrp_virtual_mac("00:00:5e:00:02:0a")  # VRRPv3 IPv6
    assert is_fhrp_virtual_mac("00:00:0c:07:ac:01")  # HSRPv1
    assert is_fhrp_virtual_mac("00:00:0c:9f:f0:10")  # HSRPv2
    assert is_fhrp_virtual_mac("00:07:b4:00:01:01")  # GLBP
    assert is_fhrp_virtual_mac("00:09:0f:09:00:01")  # FortiGate FGCP HA
    assert is_locally_administered_mac("02:aa:bb:cc:dd:ee")
    assert not is_locally_administered_mac("fc:33:42:e6:b5:99")

    reg = DeviceRegistry()
    fw_pri = {
        "ip": "192.168.1.2",
        "hostname": "fw-pri",
        "serial": "Unknown",
        "mac_address": "00:00:5e:00:01:01",
        "l3_interfaces": [{"interface": "vtnet0", "ip_address": "192.168.1.2/24"}],
        "interfaces_detail": {"vtnet0": {"mac_address": "00:00:5e:00:01:01"}},
    }
    fw_sec = {
        "ip": "192.168.1.3",
        "hostname": "fw-sec",
        "serial": "Unknown",
        "mac_address": "00:00:5e:00:01:01",
        "l3_interfaces": [{"interface": "vtnet0", "ip_address": "192.168.1.3/24"}],
        "interfaces_detail": {"vtnet0": {"mac_address": "00:00:5e:00:01:01"}},
    }
    id_pri = reg.register_device(fw_pri)
    id_sec = reg.register_device(fw_sec)
    assert id_pri != id_sec
    assert len(reg.devices) == 2
    assert "00:00:5e:00:01:01" not in reg.mac_to_device_id

    # Two cloned VMs sharing identical Proxmox hypervisor MAC on distinct IPs must not collide
    vm1 = {
        "ip": "192.168.1.10",
        "hostname": "OpenWrt",
        "serial": "OpenWrt-Virtual",
        "mac_address": "bc:24:11:aa:bb:cc",
        "l3_interfaces": [{"interface": "br-lan", "ip_address": "192.168.1.10/24"}],
    }
    vm2 = {
        "ip": "172.16.1.10",
        "hostname": "OpenWrt",
        "serial": "OpenWrt-Virtual",
        "mac_address": "bc:24:11:aa:bb:cc",
        "l3_interfaces": [{"interface": "br-lan", "ip_address": "172.16.1.10/24"}],
    }
    id_vm1 = reg.register_device(vm1)
    id_vm2 = reg.register_device(vm2)
    assert id_vm1 != id_vm2
    assert len(reg.devices) == 4


def test_tp05_multi_svi_chassis_without_serial_merges_cleanly():
    """TP-05: Single multi-SVI router without serial crawled via two SVI IPs/per-port MACs merges into one device."""
    reg = DeviceRegistry()
    crawl_svi1 = {
        "ip": "192.168.1.254",
        "hostname": "FRR-Router-01",
        "serial": "Unknown",
        "mac_address": "bc:24:11:00:00:01",
        "l3_interfaces": [
            {"interface": "eth0", "ip_address": "192.168.1.254/24"},
            {"interface": "eth1", "ip_address": "172.16.1.10/24"},
        ],
        "interfaces_detail": {
            "eth0": {"mac_address": "bc:24:11:00:00:01"},
            "eth1": {"mac_address": "bc:24:11:00:00:02"},
        },
    }
    crawl_svi2 = copy.deepcopy(crawl_svi1)
    crawl_svi2["ip"] = "172.16.1.10"
    crawl_svi2["mac_address"] = "bc:24:11:00:00:02"

    id1 = reg.register_device(crawl_svi1)
    id2 = reg.register_device(crawl_svi2)
    assert id1 == id2
    assert len(reg.devices) == 1


def test_tp06_canonical_dedupe_renderer_and_trunk_audit_consistency():
    """TP-06: dedupe_devices, topology_renderer, and trunk_audit preserve distinct generic/placeholder devices."""
    from net_docu_crawler.topology_resolver import dedupe_devices

    devices = {
        "192.168.1.2": {
            "ip": "192.168.1.2",
            "hostname": "OpenWrt",
            "serial": "Not Specified",
            "mac_address": "bc:24:11:01:02:03",
            "device_type": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "br-lan", "ip_address": "192.168.1.2/24"}],
        },
        "172.16.1.2": {
            "ip": "172.16.1.2",
            "hostname": "OpenWrt",
            "serial": "Not Specified",
            "mac_address": "bc:24:11:04:05:06",
            "device_type": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "br-lan", "ip_address": "172.16.1.2/24"}],
        },
        "10.0.0.1": {
            "ip": "10.0.0.1",
            "hostname": "MikroTik",
            "serial": "SN-REAL-1",
            "mac_address": "48:8f:5a:00:00:01",
            "device_type": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "ether1", "ip_address": "10.0.0.1/24"}],
        },
        "10.0.0.2": {
            "ip": "10.0.0.2",
            "hostname": "MikroTik",
            "serial": "SN-REAL-2",
            "mac_address": "48:8f:5a:00:00:02",
            "device_type": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "ether1", "ip_address": "10.0.0.2/24"}],
        },
    }
    kept = dedupe_devices(devices)
    assert set(kept.keys()) == set(devices.keys())

    model = build_topology_graph_model(devices)
    assert model["metadata"]["total_nodes"] == 4
    assert len({n["id"] for n in model["nodes"]}) == 4

    # trunk_audit must match dotted Cisco/uppercase MACs & per-interface MACs cleanly
    sw_a = {
        "hostname": "sw-a",
        "ip": "10.10.0.1",
        "vendor": "Cisco",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "status": "success",
        "mac_address": "0011.2233.4400",
        "interfaces_detail": {"Gi1/0/1": {"status": "up", "mac_address": "0011.2233.4401"}},
        "port_profiles": {"Gi1/0/1": {"mode": "trunk", "native_vlan": "10", "trunk_allowed_vlans": "10,20"}},
        "neighbors": [
            {
                "local_port": "Gi1/0/1",
                "remote_device": "sw-b-alias",
                "remote_port": "Gi1/0/2",
                "remote_mac": "AA-BB-CC-DD-EE-02",
                "device_type": "switch",
            }
        ],
    }
    sw_b = {
        "hostname": "sw-b",
        "ip": "10.10.0.2",
        "vendor": "Cisco",
        "os_type": "cisco_ios",
        "device_type": "switch",
        "status": "success",
        "mac_address": "aabb.ccdd.ee00",
        "interfaces_detail": {"Gi1/0/2": {"status": "up", "mac_address": "aa:bb:cc:dd:ee:02"}},
        "port_profiles": {"Gi1/0/2": {"mode": "trunk", "native_vlan": "10", "trunk_allowed_vlans": "10,20"}},
        "neighbors": [
            {
                "local_port": "Gi1/0/2",
                "remote_device": "sw-a",
                "remote_port": "Gi1/0/1",
                "device_type": "switch",
            }
        ],
    }
    audit = evaluate_trunk_mismatches([sw_a, sw_b])
    assert audit["summary"]["matched_edges"] == 1
    assert audit["summary"]["uncrawled_neighbor_edges"] == 0


def test_tr13_resolve_canonical_hostname_thread_safe_and_reentrant():
    """TR-13: DeviceRegistry uses RLock and safely locks resolve_canonical_hostname under concurrent access."""
    reg = DeviceRegistry()
    errors: list[Exception] = []

    def writer():
        try:
            for i in range(100):
                reg.register_device(
                    {
                        "ip": f"10.20.{i // 50}.{i % 50 + 1}",
                        "hostname": f"CORE-SWITCH-{i:03d}.corp.example.com",
                        "serial": f"SN-{i:05d}",
                        "mac_address": f"00:11:22:33:{i // 256:02x}:{i % 256:02x}",
                    }
                )
        except Exception as exc:
            errors.append(exc)

    def reader():
        try:
            for i in range(100):
                reg.resolve_canonical_hostname(f"CORE-SWITCH-{i:03d}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer), threading.Thread(target=reader), threading.Thread(target=reader)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert errors == []

    # Verify RLock type and re-entrancy (no deadlock when called while holding self._lock)
    assert isinstance(reg._lock, type(threading.RLock()))
    with reg._lock:
        assert reg.resolve_canonical_hostname("CORE-SWITCH-001.corp.example.com") == "CORE-SWITCH-001"

    # Verify resolve_canonical_hostname actually acquires self._lock (blocks while held by another thread)
    entered = threading.Event()
    finished = threading.Event()

    def probe():
        entered.set()
        reg.resolve_canonical_hostname("CORE-SWITCH-001")
        finished.set()

    with reg._lock:
        t = threading.Thread(target=probe)
        t.start()
        assert entered.wait(timeout=2.0)
        assert not finished.wait(timeout=0.05)
    t.join(timeout=2.0)
    assert finished.is_set()


# ==============================================================================
# Branch 2 Regression Tests: Links, SVI/CIDR Joins, Trunk Audit, STP, Correlator, Domain (TP-07..TP-17)
# ==============================================================================


def test_tp07_resolve_neighbor_ip_priority_and_non_mac_chassis_subtypes():
    """TP-07: Prefer crawled mgmt IP over secondary ARP, support IPv4/serial/port-MAC chassis subtypes, block multicast/generic."""
    reg = DeviceRegistry()
    reg.register_device(
        {
            "ip": "192.168.1.4",
            "hostname": "Office-AP",
            "serial": "CN12345ABC",
            "mac_address": "40:e3:d6:c1:2d:a4",
            "l3_interfaces": [{"interface": "br0", "ip_address": "192.168.1.4/24"}],
        }
    )
    # Secondary virtual-controller IP in ARP shares the same MAC -> crawled mgmt IP must win
    reg.global_arp["192.168.1.215"] = {"mac": "40:e3:d6:c1:2d:a4", "vendor": "Aruba"}
    assert reg.resolve_neighbor_ip("40:e3:d6:c1:2d:a4", "Office-AP") == "192.168.1.4"

    # Network-address chassis-ID subtype (unicast IPv4 accepted, multicast rejected)
    assert reg.resolve_neighbor_ip("198.51.100.10", "Remote-AP") == "198.51.100.10"
    assert reg.resolve_neighbor_ip("232.41.54.10", "Bad-Multicast") is None

    # MAC stored in remote_port when chassis-ID is non-MAC (e.g., Norris WBE-FS-POS-01)
    reg.global_arp["198.51.100.16"] = {"mac": "68:1d:ef:3c:5e:71", "vendor": "Shenzhen"}
    assert reg.resolve_neighbor_ip("", "WBE-FS-POS-01", remote_port="68:1d:ef:3c:5e:71") == "198.51.100.16"

    # MAC embedded in remote_device string (e.g., MAC-001b17000102)
    reg.global_arp["198.51.100.20"] = {"mac": "00:1b:17:01:02:03", "vendor": "Palo Alto"}
    assert reg.resolve_neighbor_ip("", "MAC-001b17010203") == "198.51.100.20"

    # Local serial chassis-ID subtype resolves to registered device
    assert reg.resolve_neighbor_ip("CN12345ABC", "") == "192.168.1.4"

    # Generic default hostname must NEVER resolve to an unrelated registered OpenWrt device
    reg.register_device(
        {
            "ip": "198.51.100.50",
            "hostname": "OpenWrt",
            "serial": "Unknown",
            "mac_address": "bc:24:11:99:88:77",
        }
    )
    assert reg.resolve_neighbor_ip("", "OpenWrt") is None


def test_tp08_renderer_matches_per_interface_mac_for_crawled_peer():
    """TP-08: MAC-only LLDP neighbor matching a peer's per-interface MAC (not base MAC) resolves into a crawled edge."""
    devices = {
        "198.51.100.1": {
            "ip": "198.51.100.1",
            "hostname": "CORE-SW1",
            "vendor": "Juniper Networks",
            "model": "ex4600-40f",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "mac_address": "00:11:22:33:44:00",
            "interfaces_detail": {"xe-0/0/1": {"status": "up", "speed": "10Gb/s", "mac_address": "00:11:22:33:44:01"}},
            "neighbors": [
                {
                    "local_port": "xe-0/0/1",
                    "remote_device": "MAC-001122335509",
                    "remote_port": "xe-0/0/2",
                    "remote_mac": "00:11:22:33:55:09",
                    "device_type": "switch",
                }
            ],
        },
        "198.51.100.2": {
            "ip": "198.51.100.2",
            "hostname": "DIST-SW2",
            "vendor": "Juniper Networks",
            "model": "ex3400-48p",
            "device_type": "switch",
            "device_persona": "switch",
            "status": "success",
            "mac_address": "00:11:22:33:55:00",
            "interfaces_detail": {"xe-0/0/2": {"status": "up", "speed": "10Gb/s", "mac_address": "00:11:22:33:55:09"}},
            "neighbors": [],
        },
    }
    model = build_topology_graph_model(devices)
    assert model["metadata"]["total_nodes"] == 2
    assert model["metadata"]["total_edges"] == 1
    e = model["edges"][0]
    assert {e["source"], e["target"]} == {"node:core-sw1", "node:dist-sw2"}


def test_tp09_one_way_and_inferred_links_never_promoted_to_confirmed():
    """TP-09: Duplicate same-direction or inferred add_bidirectional_link calls must NEVER promote to 'confirmed'."""
    reg = DeviceRegistry()

    # Duplicate calls in the SAME direction (SW-A -> SW-B twice)
    reg.add_bidirectional_link("SW-A", "Gi1/0/1", "SW-B", "Gi1/0/2", evidence="unidirectional_lldp")
    reg.add_bidirectional_link("SW-A", "Gi1/0/1", "SW-B", "Gi1/0/2", evidence="unidirectional_lldp")
    assert len(reg.links) == 1
    assert reg.links[0]["status"] == "unidirectional"
    assert reg.links[0]["evidence"] != "confirmed_lldp"

    # Partial port update from the SAME direction (empty remote_port -> filled) still unidirectional
    reg2 = DeviceRegistry()
    reg2.add_bidirectional_link("SW-A", "Gi1/0/1", "SW-B", "", evidence="unidirectional_lldp")
    reg2.add_bidirectional_link("SW-A", "Gi1/0/1", "SW-B", "Gi1/0/2", evidence="unidirectional_lldp")
    assert len(reg2.links) == 1
    assert reg2.links[0]["status"] == "unidirectional"

    # Inferred calls from both sides (mac_inferred) must NEVER claim confirmed_lldp
    reg3 = DeviceRegistry()
    reg3.add_bidirectional_link(
        "SW-A",
        "Gi1/0/1",
        "FW-1",
        "vtnet0",
        link_type="mac_inferred",
        transport_type="mac_inferred",
        evidence="mac_inferred",
    )
    reg3.add_bidirectional_link(
        "FW-1",
        "vtnet0",
        "SW-A",
        "Gi1/0/1",
        link_type="mac_inferred",
        transport_type="mac_inferred",
        evidence="mac_inferred",
    )
    assert len(reg3.links) == 1
    assert reg3.links[0]["status"] != "confirmed"
    assert reg3.links[0]["evidence"] == "mac_inferred"

    # Only true opposite-direction direct observations promote to confirmed + confirmed_lldp
    reg.add_bidirectional_link("SW-B", "Gi1/0/2", "SW-A", "Gi1/0/1", evidence="unidirectional_lldp")
    assert len(reg.links) == 1
    assert reg.links[0]["status"] == "confirmed"
    assert reg.links[0]["evidence"] == "confirmed_lldp"


def test_tp10_reconcile_preserves_inferred_on_synthesized_reverse_neighbors():
    """TP-10: Synthesized reverse neighbors created in reconcile_reciprocal_neighbors must remain link_confidence='INFERRED'."""
    reg = DeviceRegistry()
    sw_a = {
        "ip": "198.51.100.1",
        "hostname": "SW-A",
        "status": "success",
        "device_type": "switch",
        "interfaces_detail": {"Gi1/0/1": {"status": "up"}},
        "neighbors": [
            {
                "local_port": "Gi1/0/1",
                "remote_device": "SW-B",
                "remote_port": "Gi1/0/2",
                "device_type": "switch",
            }
        ],
    }
    sw_b = {
        "ip": "198.51.100.2",
        "hostname": "SW-B",
        "status": "success",
        "device_type": "switch",
        "interfaces_detail": {"Gi1/0/2": {"status": "up"}},
        "neighbors": [],
    }
    reg.register_device(sw_a)
    reg.register_device(sw_b)
    reg.add_bidirectional_link("SW-A", "Gi1/0/1", "SW-B", "Gi1/0/2", evidence="unidirectional_lldp")
    reg.reconcile_reciprocal_neighbors([sw_a, sw_b])

    assert sw_a["neighbors"][0]["link_confidence"] == "one-way"
    assert len(sw_b["neighbors"]) == 1
    assert sw_b["neighbors"][0]["link_confidence"] == "INFERRED"


def test_tp11_svi_vlan_cidr_joins_across_vendors_and_netaddr():
    """TP-11: build_l3_svi_table and _resolve_vlan_meta support subinterfaces/OPNsense/FortiGate/IPv6/explicit by_svi & reject VLAN 0."""
    from net_docu_crawler.correlator import build_l3_svi_table
    from net_docu_crawler.topology_renderer import _resolve_vlan_meta

    devices = [
        {
            "ip": "198.51.100.1",
            "hostname": "opn-fw",
            "site_code": "LAB",
            "status": "success",
            "record_class": "crawled_infra",
            "vlans": {
                "10": {"id": "10", "name": "CORP"},
                "20": {"id": "20", "name": "VOICE"},
            },
            "l3_interfaces": [
                {"interface": "vtnet0_vlan10", "ip_address": "198.51.100.1/24"},
                {"interface": "lo0", "ip_address": "127.0.0.1/8"},
            ],
        },
        {
            "ip": "198.51.100.2",
            "hostname": "junos-sw",
            "site_code": "LAB",
            "status": "success",
            "record_class": "crawled_infra",
            "vlans": {
                "1": {"id": "1", "name": "default", "svi_interface": "irb.0"},
                "100": {"id": "100", "name": "MGMT", "svi_interface": "irb.10"},
                "40": {"id": "40", "name": "SERVERS"},
            },
            "l3_interfaces": [
                {"interface": "irb.0", "ip_address": "198.51.100.2/24"},
                {"interface": "irb.10", "ip_address": "198.51.101.2/24"},
                {"interface": "ge-0/0/1.40", "ip_address": "2001:db8:40::1/64"},
                {"interface": "bme0.0", "ip_address": "128.0.0.1/16"},
            ],
        },
        {
            "ip": "198.51.100.3",
            "hostname": "fgt-edge",
            "site_code": "LAB",
            "status": "success",
            "record_class": "crawled_infra",
            "vlans": {"200": {"id": "200", "name": "DMZ"}},
            "interfaces_detail": {"dmz_if": {"status": "up", "vlan": "200"}},
            "l3_interfaces": [
                {"interface": "dmz_if", "ip_address": "198.51.102.1   255.255.255.0"},
                {"interface": "eth0.20", "ip_address": "198.51.103.1/24"},
                {"interface": "Gi0/0.30", "ip_address": "198.51.104.1/24"},
                {"interface": "bare_ap", "ip_address": "198.51.105.50"},
            ],
        },
    ]

    rows = build_l3_svi_table(devices)
    by_svi_row = {(r["source_device"], r["svi_interface"]): r for r in rows}

    # Loopbacks and Junos internal 128.0.0.0/16 fabric must be excluded
    assert ("opn-fw", "lo0") not in by_svi_row
    assert ("junos-sw", "bme0.0") not in by_svi_row

    # OPNsense vtnet0_vlan10
    assert by_svi_row[("opn-fw", "vtnet0_vlan10")]["vlan_id"] == "10"
    assert by_svi_row[("opn-fw", "vtnet0_vlan10")]["prefix_cidr"] == "198.51.100.0/24"

    # Explicit by_svi wins over regex (irb.0 -> VLAN 1, NOT "0"; irb.10 -> VLAN 100, NOT "10")
    assert by_svi_row[("junos-sw", "irb.0")]["vlan_id"] == "1"
    assert by_svi_row[("junos-sw", "irb.10")]["vlan_id"] == "100"

    # IPv6 + subinterfaces + multi-space subnet mask + FortiGate interfaces_detail["vlan"]
    assert by_svi_row[("junos-sw", "ge-0/0/1.40")]["vlan_id"] == "40"
    assert by_svi_row[("junos-sw", "ge-0/0/1.40")]["prefix_cidr"] == "2001:db8:40::/64"
    assert by_svi_row[("fgt-edge", "dmz_if")]["vlan_id"] == "200"
    assert by_svi_row[("fgt-edge", "dmz_if")]["prefix_cidr"] == "198.51.102.0/24"
    assert by_svi_row[("fgt-edge", "eth0.20")]["vlan_id"] == "20"
    assert by_svi_row[("fgt-edge", "Gi0/0.30")]["vlan_id"] == "30"
    # Bare IP without mask must NOT synthesize /32
    assert by_svi_row[("fgt-edge", "bare_ap")]["prefix_cidr"] == ""

    # _resolve_vlan_meta parity: irb.0 without explicit mapping must NOT return VLAN "0"; explicit by_svi wins
    assert _resolve_vlan_meta("irb.0", {}, {})[0] == ""
    assert _resolve_vlan_meta("irb.10", {"100": {"name": "MGMT", "svi_interface": "irb.10"}}, {})[0] == "100"
    assert _resolve_vlan_meta("vtnet0_vlan10", {"10": {"name": "CORP"}}, {})[0] == "10"


def test_tp12_cidr_overlaps_multi_peer_mask_mismatch_fhrp_vip_and_three_sites():
    """TP-12: Detect mask_mismatch on >=3-peer LAN, >=3-site overlaps, exempt FHRP VIPs, and expose detect_cidr_overlaps()."""
    from net_docu_crawler.topology_resolver import detect_cidr_overlaps

    # 3-peer broadcast LAN where R3 has mismatched /25 mask while R1 & R2 have /24
    lan3 = {
        "198.51.100.1": {
            "ip": "198.51.100.1",
            "hostname": "R1",
            "site_code": "CORE",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "eth0", "ip_address": "198.51.100.1/24"}],
        },
        "198.51.100.2": {
            "ip": "198.51.100.2",
            "hostname": "R2",
            "site_code": "CORE",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "eth0", "ip_address": "198.51.100.2/24"}],
        },
        "198.51.100.3": {
            "ip": "198.51.100.3",
            "hostname": "R3",
            "site_code": "CORE",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "eth0", "ip_address": "198.51.100.3/25"}],
        },
    }
    model = build_topology_graph_model(lan3)
    mm_renderer = [c for c in model["l3_graph"]["l3_conflicts"] if c["conflict_type"] == "mask_mismatch"]
    assert len(mm_renderer) >= 1

    res = detect_cidr_overlaps(lan3)
    assert len(res["mask_mismatches"]) >= 1
    assert res["duplicate_ips"] == []
    assert res["intra_device_overlaps"] == []

    # Shared FHRP VIP on HA firewall pair must NOT trigger duplicate_gateway_ip
    ha_pair = {
        "198.51.100.11": {
            "ip": "198.51.100.11",
            "hostname": "FW-PRI",
            "site_code": "CORE",
            "device_type": "firewall",
            "device_persona": "firewall",
            "status": "success",
            "fhrp": [{"protocol": "carp", "vip": "198.51.100.254"}],
            "l3_interfaces": [
                {"interface": "vtnet0", "ip_address": "198.51.100.11/24"},
                {"interface": "vtnet0_vip", "ip_address": "198.51.100.254/24"},
            ],
        },
        "198.51.100.12": {
            "ip": "198.51.100.12",
            "hostname": "FW-SEC",
            "site_code": "CORE",
            "device_type": "firewall",
            "device_persona": "firewall",
            "status": "success",
            "fhrp": [{"protocol": "carp", "vip": "198.51.100.254"}],
            "l3_interfaces": [
                {"interface": "vtnet0", "ip_address": "198.51.100.12/24"},
                {"interface": "vtnet0_vip", "ip_address": "198.51.100.254/24"},
            ],
        },
    }
    ha_model = build_topology_graph_model(ha_pair)
    assert [c for c in ha_model["l3_graph"]["l3_conflicts"] if c["conflict_type"] == "duplicate_gateway_ip"] == []
    assert detect_cidr_overlaps(ha_pair)["duplicate_ips"] == []

    # 3 disconnected sites reusing identical 172.23.2.0/24 with distinct host IPs -> overlapping_site_subnet
    three_sites = {
        f"10.250.{idx}.1": {
            "ip": f"10.250.{idx}.1",
            "hostname": f"SITE{idx}-CORE",
            "site_code": f"S{idx}",
            "device_type": "router",
            "device_persona": "router",
            "status": "success",
            "l3_interfaces": [{"interface": "Vlan40", "ip_address": f"172.23.2.{idx}/24"}],
        }
        for idx in (1, 2, 3)
    }
    three_model = build_topology_graph_model(three_sites)
    ov_conflicts = [
        c for c in three_model["l3_graph"]["l3_conflicts"] if c["conflict_type"] == "overlapping_site_subnet"
    ]
    assert len(ov_conflicts) >= 1


def test_tp13_and_tp14_trunk_audit_excludes_synthetic_links_endpoints_and_no_phantom_eth0():
    """TP-13 & TP-14: No phantom 'eth0' in MAC inference; trunk_audit excludes non-direct links, classifies endpoints, parses OPNsense _vlan."""
    # 1. infer_mac_table_links must NOT fabricate "eth0" when target has no matching interface MAC
    reg = DeviceRegistry()
    sw = {
        "ip": "198.51.100.3",
        "hostname": "core-sw",
        "status": "success",
        "device_type": "switch",
        "mac_address": "00:11:22:33:44:55",
        "interfaces_detail": {"ge-0/0/1": {"status": "up"}},
        "mac_table": [{"mac": "00:09:0f:aa:bb:cc", "interface": "ge-0/0/1", "vlan": "1"}],
        "neighbors": [],
    }
    fgt = {
        "ip": "198.51.100.252",
        "hostname": "fgt-edge",
        "status": "success",
        "device_type": "firewall",
        "mac_address": "00:09:0f:aa:bb:cc",
        "interfaces_detail": {"port1": {"status": "up"}},
        "neighbors": [],
    }
    reg.infer_mac_table_links([sw, fgt])
    assert len(fgt["neighbors"]) == 1
    assert fgt["neighbors"][0]["local_port"] != "eth0"
    assert fgt["neighbors"][0]["local_port"] == ""

    # 2. trunk_audit excludes mac_inferred, wan_carrier_arp_route, l3_next_hop_egress, virtual_passthrough, and endpoints
    sw_trunk = {
        "hostname": "do-hub",
        "ip": "198.51.100.1",
        "vendor": "HP ProCurve",
        "os_type": "hp_procurve",
        "device_type": "switch",
        "status": "success",
        "port_profiles": {
            "C1": {"mode": "trunk", "native_vlan": "1", "trunk_allowed_vlans": "1,1050,1053"},
            "A3": {"mode": "trunk", "native_vlan": "1", "trunk_allowed_vlans": "1,4009"},
            "B1": {"mode": "trunk", "native_vlan": "1", "trunk_allowed_vlans": "1,10,20"},
            "B2": {"mode": "access", "access_vlan": "10"},
        },
        "neighbors": [
            {
                "local_port": "C1",
                "remote_device": "ves-core",
                "remote_port": "xe-0/0/22",
                "device_type": "switch",
                "l2_accuracy": "wan_carrier_arp_route",
            },
            {
                "local_port": "A3",
                "remote_device": "Perimeter-Firewall",
                "remote_port": "",
                "device_type": "firewall",
                "l2_accuracy": "l3_next_hop_egress",
            },
            {
                "local_port": "B1",
                "remote_device": "fgt-edge",
                "remote_port": "port1",
                "device_type": "firewall",
                "l2_accuracy": "mac_inferred",
            },
            {
                "local_port": "B2",
                "remote_device": "WBE-FS-POS-01",
                "remote_port": "WAN PORT",
                "platform": "JunOS-Discovered",
                "device_type": "switch",
            },
        ],
    }
    ves_core = {
        "hostname": "ves-core",
        "ip": "198.51.100.2",
        "vendor": "Juniper Networks",
        "os_type": "juniper_junos",
        "device_type": "switch",
        "status": "success",
        "port_profiles": {
            "xe-0/0/22": {"mode": "trunk", "native_vlan": "none", "trunk_allowed_vlans": "1050"},
        },
        "neighbors": [],
    }
    audit = evaluate_trunk_mismatches([sw_trunk, ves_core, fgt])
    assert audit["summary"]["evaluated_edges"] == 0
    assert audit["summary"]["uncrawled_neighbor_edges"] == 0

    # 3. OPNsense _vlan<N> subinterfaces synthesize trunk bundle instead of defaulting to access VLAN 1
    from net_docu_crawler.trunk_audit import extract_device_trunk_states

    opn = {
        "hostname": "opn-gw",
        "ip": "198.51.100.254",
        "vendor": "OPNsense",
        "os_type": "opnsense",
        "device_type": "firewall",
        "status": "success",
        "interfaces_detail": {"vtnet0": {"status": "up"}, "vtnet1": {"status": "up"}},
        "l3_interfaces": [
            {"interface": "vtnet0_vlan10", "ip_address": "198.51.100.1/24"},
            {"interface": "vtnet0_vlan20", "ip_address": "198.51.101.1/24"},
            {"interface": "vtnet1", "ip_address": "203.0.113.2/30"},
        ],
    }
    opn_states = {st.interface_name: st for st in extract_device_trunk_states(opn)}
    assert opn_states["vtnet0"].oper_mode == "trunk"
    assert opn_states["vtnet0"].allowed_vlans == {10, 20}
    assert opn_states["vtnet1"].oper_mode == "routed"


def test_tp15_stp_mixed_vendor_bridge_id_and_two_switch_root_scope_alignment():
    """TP-15: Normalize dotted vs colon STP bridge IDs and align correlator/renderer root_scope on 2-switch labs."""
    from net_docu_crawler.correlator import compute_stp_root_consensus

    # Case 1: Cisco dotted bridge ID + Juniper colon bridge ID agree on the SAME campus root
    sw_cisco = {
        "ip": "198.51.100.1",
        "hostname": "CISCO-CORE",
        "status": "success",
        "device_type": "switch",
        "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.20d8.0b8f.adde"},
    }
    sw_junos = {
        "ip": "198.51.100.2",
        "hostname": "JUNOS-ACC",
        "status": "success",
        "device_type": "switch",
        "stp": {"enabled": True, "is_root": False, "root_bridge": "32768.20:d8:0b:8f:ad:de"},
    }
    compute_stp_root_consensus([sw_cisco, sw_junos])
    assert sw_cisco["stp"]["is_verified_campus_root"] is True
    assert sw_cisco["stp"]["root_scope"] == "campus_root"

    # Case 2: 2 switches with DISAGREEING root bridge IDs -> correlator AND renderer both report isolated_self_root
    sw1 = {
        "ip": "198.51.100.10",
        "hostname": "SW-ISO-1",
        "status": "success",
        "device_type": "switch",
        "device_persona": "switch",
        "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.fc:33:42:e6:b5:bb"},
    }
    sw2 = {
        "ip": "198.51.100.11",
        "hostname": "SW-ISO-2",
        "status": "success",
        "device_type": "switch",
        "device_persona": "switch",
        "stp": {"enabled": True, "is_root": True, "root_bridge": "32768.00:1c:73:aa:bb:cc"},
    }
    compute_stp_root_consensus([sw1, sw2])
    assert sw1["stp"]["root_scope"] == "isolated_self_root"
    assert sw2["stp"]["root_scope"] == "isolated_self_root"
    model = build_topology_graph_model({sw1["ip"]: sw1, sw2["ip"]: sw2})
    by_hn = {n["hostname"]: n for n in model["nodes"]}
    assert by_hn["SW-ISO-1"]["stp_root_scope"] == "isolated_self_root"
    assert by_hn["SW-ISO-1"]["stp_root"] is False
    assert by_hn["SW-ISO-2"]["stp_root_scope"] == "isolated_self_root"
    assert by_hn["SW-ISO-2"]["stp_root"] is False


def test_tp16_correlate_device_ports_case_insensitive_priority_and_media():
    """TP-16: correlate_device_ports uses case-insensitive keys, prioritizes direct infra uplinks, and avoids false 1000BASE-T."""
    from net_docu_crawler.correlator import correlate_device_ports

    dev = {
        "hostname": "edge-sw",
        "ip": "198.51.100.5",
        "interfaces_detail": {
            "Ethernet1": {"status": "up", "admin_status": "up", "speed": "25Gb/s"},
            "vtnet0": {"status": "up", "admin_status": "up", "speed": ""},
            "Fa0/1": {"status": "up", "admin_status": "up", "speed": "100Mb/s"},
        },
        "port_profiles": {
            "et1": {"mode": "trunk", "trunk_allowed_vlans": "10,20"},
        },
        "neighbors": [
            {
                "local_port": "eth1",
                "remote_device": "CORE-SW",
                "remote_port": "Eth1",
                "device_type": "switch",
                "link_confidence": "two-way",
            },
            {
                "local_port": "Ethernet1",
                "remote_device": "vm-guest",
                "remote_port": "eth0",
                "device_type": "server",
                "l2_accuracy": "mac_inferred",
                "link_confidence": "INFERRED",
            },
        ],
        "mac_table": [{"interface": "et1", "mac": "00:11:22:33:44:55", "vlan": "10"}],
    }
    ports = correlate_device_ports(dev)
    assert ports["Ethernet1"]["mode"] == "trunk"
    assert ports["Ethernet1"]["neighbor_hostname"] == "CORE-SW"
    assert ports["Ethernet1"]["trunk_mac_count"] == 1
    assert "25G" in ports["Ethernet1"]["media"]
    assert "1000BASE-T" not in ports["vtnet0"]["media"]
    assert "100BASE" in ports["Fa0/1"]["media"]


def test_tp17_domain_detector_rejects_numeric_tlds_and_parses_all_vendors():
    """TP-17: Reject version strings (v7.4.9, 23.4R2.13) as DNS domains; parse OPNsense/FortiGate/OpenWrt/PAN-OS domains."""
    from net_docu_crawler.domain_detector import extract_device_dns_domains

    devices = [
        {"hostname": "fw1", "status": "success", "model": "v7.4.9"},
        {"hostname": "sw1", "status": "success", "model": "23.4R2.13"},
        {
            "hostname": "opn",
            "status": "success",
            "raw_config": "<opnsense><system><domain>opn.example.net</domain></system></opnsense>",
        },
        {
            "hostname": "fgt",
            "status": "success",
            "raw_config": 'config system dns\n    set domain "fgt.example.org"\nend\n',
        },
        {"hostname": "owrt", "status": "success", "raw_config": "config dnsmasq\n\toption domain 'owrt.example.com'\n"},
        {"hostname": "pan", "status": "success", "raw_config": "set deviceconfig system domain pan.example.edu\n"},
    ]
    domains = extract_device_dns_domains(devices)
    assert "v7.4.9" not in domains
    assert "23.4r2.13" not in domains
    assert {"opn.example.net", "fgt.example.org", "owrt.example.com", "pan.example.edu"}.issubset(set(domains))

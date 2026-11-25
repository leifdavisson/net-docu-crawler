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

"""Regression tests for Topology & Registry audit fixes (TP-01..TP-06, TR-13)."""

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

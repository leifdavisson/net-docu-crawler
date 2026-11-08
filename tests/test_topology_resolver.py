# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
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
Unit tests for TopologyResolver and DeviceRegistry.
"""

from net_docu_crawler.topology_resolver import (
    DeviceRegistry,
    is_crawlable_network_device,
    normalize_hostname,
    normalize_interface,
)


def test_normalize_hostname():
    short, fqdn = normalize_hostname("switch-core-01.lan.example.internal")
    assert short == "switch-core-01"
    assert fqdn == "switch-core-01.lan.example.internal"

    short2, fqdn2 = normalize_hostname("dist-sw(FOC1234567)")
    assert short2 == "dist-sw"

    # Quoted RouterOS MNDP identity must strip quotes cleanly
    short_q, fqdn_q = normalize_hostname('"edge-router-01.corp.internal"')
    assert short_q == "edge-router-01"
    assert fqdn_q == "edge-router-01.corp.internal"


def test_normalize_interface():
    assert normalize_interface("GigabitEthernet1/0/1") == "Gi1/0/1"
    assert normalize_interface("TenGigabitEthernet1/0/48") == "Te1/0/48"
    assert normalize_interface("FastEthernet0/24") == "Fa0/24"
    assert normalize_interface("Ethernet1/1") == "Eth1/1"
    assert normalize_interface("ge-0/0/1.0") == "ge-0/0/1"
    assert normalize_interface("xe-1/0/0.0") == "xe-1/0/0"
    assert normalize_interface("port1") == "port1"


def test_is_crawlable_network_device():
    assert not is_crawlable_network_device(capabilities=["Phone"], device_type="IP Phone")
    assert not is_crawlable_network_device(capabilities=[], device_type="VoIP", vendor_or_model="Cisco CP-8845")
    assert not is_crawlable_network_device(capabilities=["Station"], device_type="Host")

    assert is_crawlable_network_device(capabilities=["Bridge", "Router"], device_type="Switch")
    assert is_crawlable_network_device(capabilities=["WLAN", "AP"], device_type="AP")
    assert is_crawlable_network_device(capabilities=[], device_type="Firewall")


def test_device_registry_svi_deduplication():
    registry = DeviceRegistry()

    device_data = {
        "ip": "192.168.1.1",
        "hostname": "core-gw.lan.example.internal",
        "serial": "SN-GATEWAY-1234",
        "mac_address": "bc:24:11:b4:a9:82",
        "l3_interfaces": [
            {"interface": "vlan1", "ip_address": "192.168.1.1/24"},
            {"interface": "vlan10", "ip_address": "192.168.10.1/24"},
            {"interface": "vlan20", "ip_address": "192.168.20.1/24"},
        ],
        "arp_table": [
            {"ip": "192.168.1.3", "mac": "fc:33:42:e6:b5:99"},
        ],
    }

    dev_id = registry.register_device(device_data)
    assert dev_id == "SER_SN-GATEWAY-1234"

    assert not registry.start_crawl("192.168.10.1")
    assert not registry.start_crawl("192.168.20.1")
    assert not registry.start_crawl("192.168.1.1")

    assert registry.start_crawl("192.168.1.50")
    registry.release_crawl("192.168.1.50")


def test_cloned_vms_and_virtual_placeholders_do_not_collide():
    """
    Regression test: Multiple OpenWrt / FRR / VM appliances with placeholder serials
    and default hostnames across local and remote routed subnets must NOT overwrite each other.
    """
    registry = DeviceRegistry()

    owrt_local = {
        "ip": "192.168.1.2",
        "hostname": "OpenWrt",
        "serial": "OpenWrt-Virtual",
        "mac_address": "bc:24:11:00:00:01",
        "l3_interfaces": [{"interface": "br-lan", "ip_address": "192.168.1.2/24"}],
        "arp_table": [],
    }
    owrt_remote_no_mac = {
        "ip": "172.16.1.2",
        "hostname": "OpenWrt",
        "serial": "Not Specified",
        "mac_address": "",
        "l3_interfaces": [{"interface": "br-lan", "ip_address": "172.16.1.2/24"}],
        "arp_table": [],
    }
    owrt_remote_2_no_mac = {
        "ip": "172.16.2.2",
        "hostname": "OpenWrt",
        "serial": "Unknown",
        "mac_address": "",
        "l3_interfaces": [{"interface": "br-lan", "ip_address": "172.16.2.2/24"}],
        "arp_table": [],
    }

    id1 = registry.register_device(owrt_local)
    id2 = registry.register_device(owrt_remote_no_mac)
    id3 = registry.register_device(owrt_remote_2_no_mac)

    assert len({id1, id2, id3}) == 3
    assert len(registry.devices) == 3


def test_device_registry_junos_lldp_arp_resolution():
    registry = DeviceRegistry()

    registry.global_arp["192.168.1.3"] = {
        "mac": "fc:33:42:e6:b5:99",
        "vendor": "Juniper Networks",
    }

    resolved_ip = registry.resolve_neighbor_ip("fc:33:42:e6:b5:99")
    assert resolved_ip == "192.168.1.3"


def test_bidirectional_link_stitching_and_partial_ports():
    registry = DeviceRegistry()

    # Switch A sees Switch B with full port info
    registry.add_bidirectional_link(
        local_node="Core-SW.lan.example.internal",
        local_port="GigabitEthernet1/0/24",
        remote_node="Dist-SW.lan.example.internal",
        remote_port="ge-0/0/1.0",
    )
    assert len(registry.links) == 1
    assert registry.links[0]["status"] == "unidirectional"

    # Switch B sees Switch A
    registry.add_bidirectional_link(
        local_node="Dist-SW.lan.example.internal",
        local_port="ge-0/0/1.0",
        remote_node="Core-SW.lan.example.internal",
        remote_port="GigabitEthernet1/0/24",
    )

    assert len(registry.links) == 1
    assert registry.links[0]["status"] == "confirmed"
    assert registry.links[0]["port_a"] == "Gi1/0/24" or registry.links[0]["port_b"] == "Gi1/0/24"

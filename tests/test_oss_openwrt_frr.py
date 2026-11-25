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

"""Regression tests for OpenWrtDriver, FRRDriver, and shared lldpd JSON parsing."""

import json
import logging
from unittest.mock import MagicMock

from net_docu_crawler.drivers.frr import FRRDriver
from net_docu_crawler.drivers.openwrt import OpenWrtDriver


def test_openwrt_and_frr_declare_supports_telnet_false():
    assert OpenWrtDriver.supports_telnet is False
    assert FRRDriver.supports_telnet is False


def test_openwrt_wan_wan6_alias_merge_and_l3_device():
    """DO-12: wan6 sharing eth1 must not wipe wan IPv4/status; PPPoE uses l3_device."""
    driver = OpenWrtDriver(ip="192.0.2.20")
    ubus_dump = {
        "interface": [
            {
                "interface": "wan",
                "up": True,
                "proto": "dhcp",
                "device": "eth1",
                "l3_device": "eth1",
                "ipv4-address": [{"address": "203.0.113.10", "mask": 24}],
            },
            {
                "interface": "wan6",
                "up": False,
                "proto": "dhcpv6",
                "device": "eth1",
                "l3_device": "eth1",
                "ipv4-address": [],
            },
            {
                "interface": "isp_pppoe",
                "up": True,
                "proto": "pppoe",
                "device": "eth0.2",
                "l3_device": "pppoe-wan",
                "ipv4-address": [{"address": "198.51.100.2", "mask": 32}],
            },
        ]
    }
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "ubus call network.interface dump 2>/dev/null": json.dumps(ubus_dump),
        "ip -d address show 2>/dev/null || ip address show 2>/dev/null": (
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    link/ether 00:e0:4c:68:01:02 brd ff:ff:ff:ff:ff:ff\n"
            "3: eth2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN\n"
            "    link/ether 00:e0:4c:68:01:03 brd ff:ff:ff:ff:ff:ff\n"
            "4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN\n"
            "    inet 10.200.0.1/24 scope global wg0\n"
        ),
    }.get(cmd, "")

    l3, details = driver.get_interfaces(conn)
    assert details["eth1"]["ip_address"] == "203.0.113.10/24"
    assert details["eth1"]["status"] == "up"
    assert "wan" in details["eth1"]["description"]
    assert details["eth1"]["mac_address"] == "00:e0:4c:68:01:02"

    # PPPoE IP mapped to l3_device (pppoe-wan), not physical eth0.2
    assert "pppoe-wan" in details
    assert details["pppoe-wan"]["ip_address"] == "198.51.100.2/32"

    # DO-18: Unplugged NO-CARRIER admin-UP port must be down; kernel-only wg0 IP harvested
    assert details["eth2"]["status"] == "down"
    assert any(e["interface"] == "wg0" and e["ip_address"] == "10.200.0.1/24" for e in l3)


def test_openwrt_ubus_null_and_malformed_types(caplog):
    """DO-13: JSON null/malformed fields in ubus responses must not crash or emit '/None'."""
    driver = OpenWrtDriver(ip="192.0.2.21")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "ubus call system board 2>/dev/null": json.dumps({"hostname": "OWRT-NullSafe", "model": None, "release": None}),
        "ubus call network.interface dump 2>/dev/null": json.dumps(
            {
                "interface": [
                    "not-a-dict",
                    {
                        "interface": "lan",
                        "up": True,
                        "device": "br-lan",
                        "ipv4-address": [{"address": "192.0.2.21", "mask": None}],
                    },
                    {
                        "interface": "guest",
                        "up": True,
                        "device": "br-guest",
                        "ipv4-address": None,
                    },
                ]
            }
        ),
        "ip -d address show 2>/dev/null || ip address show 2>/dev/null": "",
    }.get(cmd, "")

    ver = driver.get_version(conn)
    assert ver["hostname"] == "OWRT-NullSafe"
    assert ver["model"] == "OpenWrt Router"

    l3, details = driver.get_interfaces(conn)
    assert len(l3) == 1
    assert l3[0]["ip_address"] == "192.0.2.21/24"
    assert "None" not in l3[0]["ip_address"]
    assert "br-guest" in details


def test_openwrt_hostapd_multi_radio_concatenated_json():
    """DO-14: Multi-radio concatenated JSON from ubus hostapd.* parses all radios + remote_mac."""
    driver = OpenWrtDriver(ip="192.0.2.22")
    concat_json = (
        '{\n  "freq": 2412,\n  "clients": {\n    "40:e3:d6:11:22:33": {"auth": true}\n  }\n}\n'
        '{\n  "freq": 5180,\n  "clients": {\n    "fc:33:42:aa:bb:cc": {"auth": true}\n  }\n}\n'
    )
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "lldpcli show neighbors -f json 2>/dev/null": "{}",
        "ubus call hostapd.* get_clients 2>/dev/null": concat_json,
    }.get(cmd, "")

    nbrs = driver.get_neighbors(conn)
    assert len(nbrs) == 2
    by_mac = {n["remote_mac"]: n for n in nbrs}
    assert "40:e3:d6:11:22:33" in by_mac
    assert "fc:33:42:aa:bb:cc" in by_mac
    assert by_mac["40:e3:d6:11:22:33"]["local_port"] == "wlan-2.4g"
    assert by_mac["fc:33:42:aa:bb:cc"]["local_port"] == "wlan-5g"


def test_openwrt_lldpcli_real_json_variants():
    """DO-15: Real lldpd JSON with single-dict interface, hostname-keyed chassis, string descr & mgmt-ip."""
    driver = OpenWrtDriver(ip="192.0.2.23")
    real_lldpd = {
        "lldp": {
            "interface": {
                "eth0": {
                    "via": "LLDP",
                    "chassis": {
                        "desktop-switch": {
                            "id": {"type": "mac", "value": "fc:33:42:e6:b5:99"},
                            "descr": "Juniper Networks, Inc. ex2300-c-12p Ethernet Switch",
                            "mgmt-ip": "192.0.2.3",
                            "capability": [
                                {"type": "Bridge", "enabled": True},
                                {"type": "Router", "enabled": False},
                            ],
                        }
                    },
                    "port": {
                        "id": {"type": "ifname", "value": "ge-0/0/1"},
                        "descr": "Uplink to OpenWrt",
                    },
                }
            }
        }
    }
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "lldpcli show neighbors -f json 2>/dev/null": json.dumps(real_lldpd),
        "ubus call hostapd.* get_clients 2>/dev/null": "",
    }.get(cmd, "")

    nbrs = driver.get_neighbors(conn)
    assert len(nbrs) == 1
    assert nbrs[0]["local_port"] == "eth0"
    assert nbrs[0]["remote_device"] == "desktop-switch"
    assert nbrs[0]["remote_port"] == "ge-0/0/1"
    assert nbrs[0]["remote_ip"] == "192.0.2.3"
    assert nbrs[0]["remote_mac"] == "fc:33:42:e6:b5:99"
    assert "ex2300-c-12p" in nbrs[0]["platform"]
    assert nbrs[0]["device_type"] == "switch"


def test_openwrt_route_n_fallback_and_ip_route_safety():
    """DO-16 & DO-17: BusyBox route -n parsed properly; trailing dev/via/proto safe; ECMP supported."""
    driver = OpenWrtDriver(ip="192.0.2.24")
    conn_rn = MagicMock()
    conn_rn.send_command.return_value = (
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        "0.0.0.0         198.51.100.1    0.0.0.0         UG    0      0        0 eth1\n"
        "10.10.10.0      0.0.0.0         255.255.255.0   U     0      0        0 br-lan\n"
        "172.16.0.0      10.10.10.254    255.255.0.0     UG    10     0        0 br-lan\n"
    )
    routes_rn = driver.get_routing_table(conn_rn)
    assert len(routes_rn) == 3
    by_sub = {r["subnet"]: r for r in routes_rn}
    assert by_sub["0.0.0.0/0"] == {
        "subnet": "0.0.0.0/0",
        "protocol": "static",
        "next_hop": "198.51.100.1",
        "interface": "eth1",
    }
    assert by_sub["10.10.10.0/24"] == {
        "subnet": "10.10.10.0/24",
        "protocol": "connected",
        "next_hop": "connected",
        "interface": "br-lan",
    }
    assert by_sub["172.16.0.0/16"]["next_hop"] == "10.10.10.254"
    assert by_sub["172.16.0.0/16"]["interface"] == "br-lan"

    # ip route with trailing keyword (must NOT raise IndexError) + ECMP nexthop lines
    conn_ip = MagicMock()
    conn_ip.send_command.return_value = (
        "default proto static\n"
        "\tnexthop via 198.51.100.1 dev eth0 weight 1\n"
        "\tnexthop via 198.51.100.5 dev eth1 weight 1\n"
        "10.0.0.0/24 via\n"
        "192.168.1.0/24 dev br-lan proto kernel scope link src 192.168.1.1\n"
    )
    routes_ip = driver.get_routing_table(conn_ip)
    defaults = [r for r in routes_ip if r["subnet"] == "0.0.0.0/0"]
    assert len(defaults) == 2
    assert {(r["next_hop"], r["interface"]) for r in defaults} == {
        ("198.51.100.1", "eth0"),
        ("198.51.100.5", "eth1"),
    }
    assert any(r["subnet"] == "192.168.1.0/24" and r["next_hop"] == "connected" for r in routes_ip)


def test_frr_interfaces_vrf_secondary_ip_and_type_safety():
    """DO-19: FRR interfaces use vrf all json, preserve primary IP, parse desc/mtu/speed, skip pseudoInterface."""
    driver = FRRDriver(ip="192.0.2.30")
    driver._frr_available = True
    intf_json = {
        "eth0": {
            "operationalStatus": "up",
            "vrfName": "default",
            "pseudoInterface": False,
            "mtu": 1500,
            "speed": 10000,
            "description": "Core Transit",
            "hardwareAddress": "bc:24:11:4a:78:63",
            "ipAddresses": [
                {"address": "192.0.2.30/24", "secondary": False},
                {"address": "192.0.2.31/24", "secondary": True},
                {"address": "fe80::1/64", "secondary": False},
            ],
        },
        "vrf-cust": {
            "operationalStatus": "up",
            "vrfName": "CUST-A",
            "pseudoInterface": True,
            "ipAddresses": [],
        },
        "eth2": {
            "operationalStatus": "up",
            "vrfName": "CUST-A",
            "pseudoInterface": False,
            "mtu": 9000,
            "hardwareAddress": "bc:24:11:4a:78:99",
            "ipAddresses": None,
        },
    }
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "vtysh -c 'show interface vrf all json'": json.dumps(intf_json),
    }.get(cmd, "")

    l3, details = driver.get_interfaces(conn)
    assert "vrf-cust" not in details
    assert details["eth0"]["ip_address"] == "192.0.2.30/24"
    assert details["eth0"]["description"] == "Core Transit"
    assert details["eth0"]["mtu"] == 1500
    assert details["eth0"]["speed"] == "10000Mbps"
    assert "eth2" in details and details["eth2"]["mtu"] == 9000
    assert len(l3) == 2


def test_frr_lldpcli_real_json_variants():
    """DO-20: FRR lldpcli parses multi-interface list & single-dict, mgmt-ip list (IPv4 preferred), remote_mac."""
    driver = FRRDriver(ip="192.0.2.31")
    driver._frr_available = True
    real_lldpd = {
        "lldp": {
            "interface": [
                {
                    "eth0": {
                        "chassis": {
                            "arista-leaf-01": {
                                "id": {"type": "mac", "value": "00:1c:73:aa:bb:cc"},
                                "descr": "Arista Networks EOS version 4.32.0F",
                                "mgmt-ip": ["fe80::1", "192.0.2.50"],
                                "capability": [
                                    {"type": "Bridge", "enabled": True},
                                    {"type": "Router", "enabled": True},
                                ],
                            }
                        },
                        "port": {"id": {"type": "ifname", "value": "Ethernet1"}},
                    }
                }
            ]
        }
    }
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "lldpcli show neighbors -f json": json.dumps(real_lldpd),
    }.get(cmd, "")

    nbrs = driver.get_neighbors(conn)
    assert len(nbrs) == 1
    assert nbrs[0]["local_port"] == "eth0"
    assert nbrs[0]["remote_device"] == "arista-leaf-01"
    assert nbrs[0]["remote_port"] == "Ethernet1"
    assert nbrs[0]["remote_ip"] == "192.0.2.50"
    assert nbrs[0]["remote_mac"] == "00:1c:73:aa:bb:cc"
    assert "Arista" in nbrs[0]["platform"]
    assert nbrs[0]["device_type"] == "switch"


def test_frr_ecmp_vrf_routes_blackhole_and_get_vrfs():
    """DO-21 & DO-22: FRR ECMP active nexthops, blackhole, multi-VRF routes, and get_vrfs()."""
    driver = FRRDriver(ip="192.0.2.32")
    driver._frr_available = True
    vrf_routes_json = {
        "default": {
            "0.0.0.0/0": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "nexthops": [
                        {"ip": "10.0.0.1", "interfaceName": "eth0", "active": False},
                        {"ip": "10.0.0.2", "interfaceName": "eth1", "active": True},
                        {"ip": "10.0.0.3", "interfaceName": "eth2", "active": True},
                    ],
                }
            ],
            "198.51.100.0/24": [
                {
                    "protocol": "static",
                    "selected": True,
                    "nexthops": [{"blackhole": True, "bhType": "null", "active": True}],
                }
            ],
        },
        "CUST-A": {
            "10.99.0.0/16": [
                {
                    "protocol": "ospf",
                    "selected": True,
                    "nexthops": [{"ip": "172.16.1.1", "interfaceName": "eth3", "active": True}],
                }
            ]
        },
    }
    vrf_json = {
        "default": {"vrfId": 0, "table": 254, "active": True},
        "CUST-A": {"vrfId": 10, "table": 1001, "active": True},
    }
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "vtysh -c 'show ip route vrf all json'": json.dumps(vrf_routes_json),
        "vtysh -c 'show vrf json'": json.dumps(vrf_json),
    }.get(cmd, "")

    routes = driver.get_routing_table(conn)
    defaults = [r for r in routes if r["subnet"] == "0.0.0.0/0"]
    # Inactive 10.0.0.1 skipped; both active ECMP hops retained
    assert {(r["next_hop"], r["interface"]) for r in defaults} == {
        ("10.0.0.2", "eth1"),
        ("10.0.0.3", "eth2"),
    }
    bh = [r for r in routes if r["subnet"] == "198.51.100.0/24"][0]
    assert bh["next_hop"] == "null"

    cust_routes = [r for r in routes if r.get("vrf") == "CUST-A"]
    assert len(cust_routes) == 1
    assert cust_routes[0]["subnet"] == "10.99.0.0/16"

    vrfs = driver.get_vrfs(conn)
    assert len(vrfs) == 1
    assert vrfs[0]["name"] == "CUST-A"
    assert vrfs[0]["table"] == 1001


def test_frr_get_routing_peers_bgp_and_ospf_json():
    """DO-23: FRR get_routing_peers() collects live BGP & OSPF peers across VRFs."""
    driver = FRRDriver(ip="192.0.2.33")
    driver._frr_available = True
    bgp_json = {
        "default": {
            "ipv4Unicast": {
                "as": 65001,
                "peers": {
                    "10.0.0.2": {
                        "remoteAs": 65002,
                        "state": "Established",
                        "pfxRcd": 42,
                    },
                    "10.0.0.3": {
                        "remoteAs": 65003,
                        "state": "Active",
                        "pfxRcd": 0,
                    },
                },
            }
        }
    }
    ospf_json = {
        "vrfs": {
            "default": {
                "neighbors": {
                    "10.255.0.2": [
                        {
                            "nbrState": "Full/DR",
                            "ifaceAddress": "10.1.0.2",
                            "ifaceName": "eth1:10.1.0.1",
                            "area": "0.0.0.0",
                        }
                    ]
                }
            }
        }
    }
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "vtysh -c 'show bgp vrf all summary json'": json.dumps(bgp_json),
        "vtysh -c 'show ip ospf vrf all neighbor json'": json.dumps(ospf_json),
    }.get(cmd, "")

    peers = driver.get_routing_peers(conn)
    bgp_peers = [p for p in peers if p["protocol"] == "bgp"]
    ospf_peers = [p for p in peers if p["protocol"] == "ospf"]

    assert len(bgp_peers) == 2
    by_ip = {p["neighbor_ip"]: p for p in bgp_peers}
    assert by_ip["10.0.0.2"]["remote_as"] == "65002"
    assert by_ip["10.0.0.2"]["local_as"] == "65001"
    assert by_ip["10.0.0.2"]["state"] == "Established"
    assert by_ip["10.0.0.3"]["state"] == "Active"

    assert len(ospf_peers) == 1
    assert ospf_peers[0]["neighbor_ip"] == "10.1.0.2"
    assert ospf_peers[0]["state"] == "Full/DR"
    assert ospf_peers[0]["interface"] == "eth1"
    assert ospf_peers[0]["area"] == "0.0.0.0"


def test_frr_plain_linux_vendor_ecmp_operstate_and_arp_states():
    """DO-24 & DO-25: Plain Linux sets vendor='Linux', parses ECMP, UNKNOWN+LOWER_UP='up', ARP states."""
    driver = FRRDriver(ip="192.0.2.34")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "hostname -s": "alpine-host\n",
        "vtysh -c 'show version'": "sh: vtysh: not found\n",
        "cat /etc/os-release": "PRETTY_NAME=Alpine Linux v3.20\n",
        "ip -s -j link show": json.dumps(
            [
                {
                    "ifname": "tap202i0",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "operstate": "UNKNOWN",
                    "address": "bc:24:11:aa:bb:cc",
                    "stats64": None,
                }
            ]
        ),
        "ip -j -4 addr show": json.dumps(
            [{"ifname": "tap202i0", "addr_info": [{"local": "192.0.2.34", "prefixlen": 24}]}]
        ),
        "lldpcli show neighbors -f json": "sh: lldpcli: not found\n",
        "command -v lldpcli >/dev/null 2>&1 || echo __NO_LLDPD__": "__NO_LLDPD__\n",
        "ip -j route show": json.dumps(
            [
                {
                    "dst": "default",
                    "protocol": "static",
                    "nexthops": [
                        {"gateway": "192.0.2.1", "dev": "eth0"},
                        {"gateway": "192.0.2.2", "dev": "eth1"},
                    ],
                }
            ]
        ),
        "ip -j neigh show": json.dumps(
            [
                {"dst": "192.0.2.1", "lladdr": "00:11:22:33:44:55", "dev": "eth0", "state": ["PERMANENT"]},
                {"dst": "192.0.2.9", "lladdr": "aa:bb:cc:dd:ee:ff", "dev": "eth0", "state": ["FAILED"]},
            ]
        ),
    }.get(cmd, "")

    data = driver.crawl(conn)
    assert data["vendor"] == "Linux"
    assert "Alpine Linux v3.20" in data["model"]
    assert data["interfaces_detail"]["tap202i0"]["status"] == "up"
    assert len(data["routes"]) == 2
    assert {(r["next_hop"], r["interface"]) for r in data["routes"]} == {
        ("192.0.2.1", "eth0"),
        ("192.0.2.2", "eth1"),
    }
    assert len(data["arp_table"]) == 1
    assert data["arp_table"][0]["type"] == "static"
    assert "FRR" not in data["discovery_protocols"]["notes"]


def test_openwrt_and_frr_log_warnings_on_parse_failure(caplog):
    """DO-25: Corrupt JSON / parse errors emit WARNING logs (not silent debug)."""
    conn = MagicMock()
    conn.send_command.return_value = "{not valid json"

    owrt = OpenWrtDriver(ip="192.0.2.40")
    frr = FRRDriver(ip="192.0.2.41")
    frr._frr_available = True

    with caplog.at_level(logging.WARNING):
        owrt.get_interfaces(conn)
        owrt.get_neighbors(conn)
        frr.get_interfaces(conn)
        frr.get_neighbors(conn)
        frr.get_routing_table(conn)

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) >= 5


def test_openwrt_and_frr_send_strictly_readonly_commands():
    """Zero-blast-radius guard: neither OpenWrtDriver nor FRRDriver ever issues write commands."""
    forbidden = ("uci set", "uci commit", "opkg ", "configure ", "write ", "clear ", "reboot", "reload", "delete ")

    for drv_cls, ip, ver_map in (
        (OpenWrtDriver, "192.0.2.50", {"ubus call system board 2>/dev/null": '{"hostname":"owrt"}'}),
        (FRRDriver, "192.0.2.51", {"vtysh -c 'show version'": "FRRouting 10.3 (frr)\n"}),
    ):
        sent: list[str] = []
        conn = MagicMock()
        conn.send_command.side_effect = lambda cmd, _m=ver_map, _s=sent: _s.append(cmd) or _m.get(cmd, "")
        drv_cls(ip=ip).crawl(conn)
        assert sent
        for cmd in sent:
            low = cmd.lower()
            assert not any(bad in low for bad in forbidden), f"Write command emitted: {cmd}"

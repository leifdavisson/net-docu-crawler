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

"""Regression tests for Juniper Junos and Arista EOS JSON/CLI drivers (DE-14 through DE-23)."""

import json
import logging
from unittest.mock import MagicMock

from net_docu_crawler.drivers.arista import AristaDriver
from net_docu_crawler.drivers.juniper import JuniperDriver


def test_juniper_els_singular_ethernet_switching_interface_and_plural_fallback():
    """DE-14: Junos ELS switches require singular `show ethernet-switching interface` (plural returns syntax error)."""
    drv = JuniperDriver(ip="192.0.2.10")
    els_json = json.dumps(
        {
            "l2ng-l2ald-iff-interface-information": [
                {
                    "l2ng-l2ald-iff-interface-entry": [
                        {
                            "l2ng-l2ald-iff-interface-name": [{"data": "ge-0/0/10.0"}],
                            "l2ng-l2ald-iff-port-mode": [{"data": "trunk"}],
                            "l2ng-l2ald-iff-interface-state": [{"data": "up"}],
                            "l2ng-l2ald-iff-interface-vlan-member-list": [
                                {
                                    "l2ng-l2ald-iff-interface-vlan-member": [
                                        {
                                            "l2ng-l2ald-iff-interface-vlan-member-tagid": [{"data": "10"}],
                                            "l2ng-l2ald-iff-interface-vlan-member-tagness": [{"data": "tagged"}],
                                        },
                                        {
                                            "l2ng-l2ald-iff-interface-vlan-member-tagid": [{"data": "20"}],
                                            "l2ng-l2ald-iff-interface-vlan-member-tagness": [{"data": "untagged"}],
                                        },
                                    ]
                                }
                            ],
                        }
                    ]
                }
            ]
        }
    )

    calls = []
    conn = MagicMock()

    def _send(cmd, **_kw):
        calls.append(cmd)
        if cmd == "show ethernet-switching interface | display json":
            return els_json
        if cmd in ("show ethernet-switching interfaces | display json", "show ethernet-switching interfaces"):
            return "syntax error, expecting <command>.\n"
        return ""

    conn.send_command.side_effect = _send
    ops = drv.get_l2_operational(conn)
    assert "ge-0/0/10" in ops
    assert ops["ge-0/0/10"]["oper_mode"] == "trunk"
    assert ops["ge-0/0/10"]["trunk_active_vlans"] == "10,20"
    assert ops["ge-0/0/10"]["native_vlan"] == "20"
    assert "show ethernet-switching interfaces | display json" not in calls


def test_juniper_real_optics_dom_json_and_text_fallback_with_dark_fiber():
    """DE-15: Real Junos DOM JSON uses interface-information, rx-signal-avg-optical-power-dbm, junos:celsius, and - Inf."""
    drv = JuniperDriver(ip="192.0.2.11")
    real_dom_json = json.dumps(
        {
            "interface-information": [
                {
                    "physical-interface": [
                        {
                            "name": [{"data": "xe-0/0/0"}],
                            "optics-diagnostics": [
                                {
                                    "laser-output-power-dbm": [{"data": "-2.35"}],
                                    "rx-signal-avg-optical-power-dbm": [{"data": "-4.12"}],
                                    "module-temperature": [
                                        {
                                            "data": "32 degrees C / 89 degrees F",
                                            "attributes": {"junos:celsius": "31.8"},
                                        }
                                    ],
                                    "module-voltage": [{"data": "3.28"}],
                                }
                            ],
                        },
                        {
                            "name": [{"data": "xe-0/0/1"}],
                            "optics-diagnostics": [
                                {
                                    "laser-output-power-dbm": [{"data": "-2.10"}],
                                    "rx-signal-avg-optical-power-dbm": [{"data": "- Inf"}],
                                    "module-temperature": [{"data": "35 degrees C / 95 degrees F"}],
                                    "module-voltage": [{"data": "3.30"}],
                                }
                            ],
                        },
                    ]
                }
            ]
        }
    )

    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd, **_kw: {
        "show chassis hardware | display json": '{"chassis-inventory": [{"chassis": [{"chassis-module": []}]}]}',
        "show interfaces diagnostics optics | display json": real_dom_json,
    }.get(cmd, "")

    optics = {o["port"]: o for o in drv.get_optics(conn)}
    assert "xe-0/0/0" in optics and "xe-0/0/1" in optics
    assert optics["xe-0/0/0"]["tx_power_dbm"] == -2.35
    assert optics["xe-0/0/0"]["rx_power_dbm"] == -4.12
    assert optics["xe-0/0/0"]["temperature_c"] == 31.8
    assert optics["xe-0/0/0"]["voltage_v"] == 3.28
    assert optics["xe-0/0/1"]["tx_power_dbm"] == -2.10
    assert optics["xe-0/0/1"]["rx_power_dbm"] is None
    assert optics["xe-0/0/1"]["temperature_c"] == 35.0

    # Text fallback must also match "Receiver signal average optical power"
    conn_txt = MagicMock()
    conn_txt.send_command.side_effect = lambda cmd, **_kw: {
        "show chassis hardware | display json": "syntax error\n",
        "show chassis hardware": "",
        "show interfaces diagnostics optics | display json": "syntax error\n",
        "show interfaces diagnostics optics": (
            "Physical interface: xe-0/1/0\n"
            "    Module temperature                        :  34 degrees C / 93 degrees F\n"
            "    Module voltage                            :  3.3100 V\n"
            "    Laser output power                        :  0.5800 mW / -2.37 dBm\n"
            "    Receiver signal average optical power     :  0.3200 mW / -4.95 dBm\n"
        ),
    }.get(cmd, "")
    optics_txt = drv.get_optics(conn_txt)
    assert len(optics_txt) == 1
    assert optics_txt[0]["rx_power_dbm"] == -4.95


def test_juniper_json_malformed_empty_lists_and_none_values_no_crash():
    """DE-16: Empty lists [], [None], None, and bare dicts in Junos JSON never trigger IndexError/AttributeError."""
    drv = JuniperDriver(ip="192.0.2.12")
    conn = MagicMock()
    conn.find_prompt.return_value = "user@lab-ex>"
    conn.send_command.side_effect = lambda cmd, **_kw: {
        "show version | display json": json.dumps(
            {
                "software-information": [
                    {"host-name": [], "junos-version": [None], "product-model": {"data": "ex2300-24p"}}
                ]
            }
        ),
        "show chassis hardware | display json": json.dumps({"chassis-inventory": []}),
        "show interfaces terse | display json": json.dumps(
            {
                "interface-information": [
                    {
                        "physical-interface": [
                            {
                                "name": [{"data": "ge-0/0/0"}],
                                "admin-status": [],
                                "oper-status": [None],
                                "logical-interface": [{"name": [], "address-family": [{"interface-address": [{}]}]}],
                            }
                        ]
                    }
                ]
            }
        ),
        "show route | display json": json.dumps(
            {
                "route-information": [
                    {
                        "route-table": [
                            {
                                "table-name": [{"data": "inet.0"}],
                                "rt": [
                                    {
                                        "rt-destination": [{"data": "192.0.2.0/24"}],
                                        "rt-entry": [{"protocol-name": [{"data": "Direct"}], "nh": []}],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        "show lldp neighbors detail | display json": json.dumps({"lldp-neighbors-information": []}),
        "show arp no-resolve | display json": json.dumps({"arp-table-information": [None]}),
        "show spanning-tree bridge | display json": json.dumps({"stp-bridge": []}),
    }.get(cmd, "")

    ver = drv.get_version(conn)
    assert ver["model"] == "ex2300-24p"
    assert ver["hostname"] == "lab-ex"

    l3, detail = drv.get_interfaces(conn)
    assert "ge-0/0/0" in detail and l3 == []

    routes = drv.get_routing_table(conn)
    assert len(routes) == 1
    assert routes[0]["subnet"] == "192.0.2.0/24"
    assert routes[0]["next_hop"] == "Directly Connected"

    assert drv.get_neighbors(conn) == []
    assert drv.get_arp_table(conn) == []


def test_juniper_and_arista_poe_emit_power_watts_and_watts_and_unsupported():
    """DE-17 & DE-22: Both drivers emit power_watts + watts for reports; non-PoE EOS sets poe_supported=False."""
    j_drv = JuniperDriver(ip="192.0.2.13")
    j_conn = MagicMock()
    j_conn.send_command.side_effect = lambda cmd, **_kw: {
        "show poe controller | display json": json.dumps(
            {
                "poe": [
                    {
                        "controller-information": [
                            {"controller-maxpower": [{"data": "370W"}], "controller-power": [{"data": "15.4W"}]}
                        ]
                    }
                ]
            }
        ),
        "show poe interface | display json": json.dumps(
            {
                "poe": [
                    {
                        "interface-information": [
                            {
                                "interface-name": [{"data": "ge-0/0/1"}],
                                "interface-status": [{"data": "ON"}],
                                "interface-power": [{"data": "15.4W"}],
                                "interface-class": [{"data": "3"}],
                            }
                        ]
                    }
                ]
            }
        ),
    }.get(cmd, "")
    j_poe = j_drv.get_poe(j_conn)
    assert j_poe["ports"]["ge-0/0/1"]["power_watts"] == 15.4
    assert j_poe["ports"]["ge-0/0/1"]["watts"] == 15.4

    a_drv = AristaDriver(ip="192.0.2.14")
    a_conn = MagicMock()
    a_conn.send_command.side_effect = lambda cmd, **_kw: {
        "show power inline | json": json.dumps(
            {
                "powerSummary": {"totalPower": 370.0, "usedPower": 12.5, "availablePower": 357.5},
                "interfaces": {"Ethernet1": {"operState": "delivering", "power": 12.5, "class": "3"}},
            }
        )
    }.get(cmd, "")
    a_poe = a_drv.get_poe(a_conn)
    assert a_poe["ports"]["Ethernet1"]["power_watts"] == 12.5
    assert a_poe["ports"]["Ethernet1"]["watts"] == 12.5

    # Non-PoE Arista vEOS returns % Invalid input -> poe_supported=False
    veos_conn = MagicMock()
    veos_conn.send_command.return_value = "% Invalid input (privileged mode required or unsupported)\n"
    veos_poe = a_drv.get_poe(veos_conn)
    assert veos_poe["poe_supported"] is False


def test_juniper_interfaces_enrichment_irb_exclusion_ecmp_stp_els_mac_and_hw_cache():
    """DE-18: Enrich Junos ports from show interfaces, exclude parent irb, ECMP routes, ELS 7-col MAC, hw cache."""
    drv = JuniperDriver(ip="192.0.2.15")
    hw_calls = 0

    def _send(cmd, **_kw):
        nonlocal hw_calls
        if cmd == "show version | display json":
            return json.dumps(
                {
                    "software-information": [
                        {
                            "host-name": [{"data": "ex4100-core"}],
                            "junos-version": [{"data": "23.4R2"}],
                            "product-model": [{"data": "ex4100-48p"}],
                        }
                    ]
                }
            )
        if cmd == "show chassis hardware | display json":
            hw_calls += 1
            return json.dumps(
                {
                    "chassis-inventory": [
                        {
                            "chassis": [
                                {
                                    "serial-number": [{"data": "JN12345678"}],
                                    "chassis-module": [
                                        {
                                            "name": [{"data": "FPC 0"}],
                                            "chassis-sub-module": [
                                                {
                                                    "name": [{"data": "PIC 1"}],
                                                    "chassis-sub-sub-module": [
                                                        {
                                                            "name": [{"data": "Xcvr 0"}],
                                                            "part-number": [{"data": "740-021308"}],
                                                            "serial-number": [{"data": "OPT001"}],
                                                            "description": [{"data": "SFP+-10G-SR"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            )
        if cmd == "show interfaces terse | display json":
            return json.dumps(
                {
                    "interface-information": [
                        {
                            "physical-interface": [
                                {
                                    "name": [{"data": "ge-0/0/1"}],
                                    "admin-status": [{"data": "up"}],
                                    "oper-status": [{"data": "up"}],
                                    "logical-interface": [],
                                },
                                {
                                    "name": [{"data": "me0"}],
                                    "admin-status": [{"data": "up"}],
                                    "oper-status": [{"data": "up"}],
                                    "logical-interface": [],
                                },
                                {
                                    "name": [{"data": "irb"}],
                                    "admin-status": [{"data": "up"}],
                                    "oper-status": [{"data": "up"}],
                                    "logical-interface": [
                                        {
                                            "name": [{"data": "irb.10"}],
                                            "oper-status": [{"data": "up"}],
                                            "address-family": [
                                                {
                                                    "address-family-name": [{"data": "inet"}],
                                                    "interface-address": [
                                                        {
                                                            "ifa-local": [{"data": "192.0.2.15"}],
                                                            "ifa-destination": [{"data": "192.0.2.0/24"}],
                                                        }
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ]
                        }
                    ]
                }
            )
        if cmd == "show interfaces":
            return (
                "Physical interface: ge-0/0/1, Enabled, Physical link is Up\n"
                "  Description: Uplink to IDF-2\n"
                "  Link-level type: Ethernet, MTU: 9216, Link-mode: Full-duplex, Speed: 1000mbps\n"
                "  Current address: aa:bb:cc:dd:ee:01, Hardware address: aa:bb:cc:dd:ee:01\n"
                "  Input errors: 2, Output errors: 1\n"
            )
        if cmd == "show route | display json":
            return json.dumps(
                {
                    "route-information": [
                        {
                            "route-table": [
                                {
                                    "table-name": [{"data": "inet.0"}],
                                    "rt": [
                                        {
                                            "rt-destination": [{"data": "10.0.0.0/8"}],
                                            "rt-entry": [
                                                {
                                                    "active-tag": [{"data": "*"}],
                                                    "protocol-name": [{"data": "OSPF"}],
                                                    "nh": [
                                                        {
                                                            "to": [{"data": "192.0.2.1"}],
                                                            "via": [{"data": "xe-0/1/0.0"}],
                                                        },
                                                        {
                                                            "to": [{"data": "192.0.2.2"}],
                                                            "via": [{"data": "xe-0/1/1.0"}],
                                                        },
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            )
        if cmd == "show ethernet-switching table | display json":
            return "syntax error\n"
        if cmd == "show ethernet-switching table":
            return (
                "MAC flags (S - static MAC, D - dynamic MAC, L - locally learned)\n"
                "Ethernet switching table : 1 entries, 1 learned\n"
                "Routing instance : default-switch\n"
                "    Vlan                MAC                 MAC         Age    Logical                NH        RTR\n"
                "    name                address             flags              interface              Index     ID\n"
                "    Vlan_10             00:11:22:33:44:55   D             -   ge-0/0/12.0            0         0\n"
            )
        if cmd == "show spanning-tree bridge | display json":
            return json.dumps(
                {
                    "stp-bridge-parameters-information": [
                        {
                            "enabled-protocol": [{"data": "RSTP"}],
                            "root-id": [{"data": "32768.aa:bb:cc:dd:ee:00"}],
                            "bridge-id": [{"data": "32768.aa:bb:cc:dd:ee:00"}],
                            "root-cost": [{"data": "0"}],
                        }
                    ]
                }
            )
        return ""

    conn = MagicMock()
    conn.send_command.side_effect = _send

    drv.get_version(conn)
    optics = drv.get_optics(conn)
    assert hw_calls == 1  # Cached across get_version + get_optics
    assert len(optics) == 1 and optics[0]["serial"] == "OPT001"

    l3, detail = drv.get_interfaces(conn)
    assert "irb" not in detail
    assert "me0" in detail
    assert len(l3) == 1 and l3[0]["interface"] == "irb.10"
    assert detail["ge-0/0/1"]["description"] == "Uplink to IDF-2"
    assert detail["ge-0/0/1"]["mac_address"] == "aa:bb:cc:dd:ee:01"
    assert detail["ge-0/0/1"]["mtu"] == 9216
    assert detail["ge-0/0/1"]["input_errors"] == 2

    routes = drv.get_routing_table(conn)
    assert len(routes) == 2
    assert {r["next_hop"] for r in routes} == {"192.0.2.1", "192.0.2.2"}

    macs = drv.get_mac_table(conn)
    assert len(macs) == 1
    assert macs[0]["interface"] == "ge-0/0/12"
    assert macs[0]["type"] == "dynamic"

    stp = drv.get_stp(conn)
    assert stp["enabled"] is True
    assert stp["protocol"] == "RSTP"
    assert stp["is_root"] is True
    assert stp["bridge_id"] == "32768.aa:bb:cc:dd:ee:00"


def test_arista_real_eos_spanning_tree_json_root_and_non_root():
    """DE-19: Real EOS 4.37.0F `show spanning-tree | json` omits isRootBridge; derive from bridge vs rootBridge."""
    drv = AristaDriver(ip="192.0.2.20")

    # Case 1: Self is root bridge (bridge MAC == rootBridge MAC, no isRootBridge key)
    conn_root = MagicMock()
    conn_root.send_command.return_value = json.dumps(
        {
            "spanningTreeInstances": {
                "MST0": {
                    "protocol": "mstp",
                    "bridge": {"priority": 32768, "macAddress": "bc:24:11:ed:c2:e4"},
                    "rootBridge": {"priority": 32768, "macAddress": "bc:24:11:ed:c2:e4"},
                    "interfaces": {
                        "Ethernet1": {"role": "designated", "state": "forwarding"},
                    },
                }
            }
        }
    )
    stp_root = drv.get_stp(conn_root)
    assert stp_root["enabled"] is True
    assert stp_root["is_root"] is True
    assert stp_root["protocol"] == "mstp"
    assert stp_root["bridge_priority"] == "32768"
    assert stp_root["root_bridge"] == "bc:24:11:ed:c2:e4"
    assert stp_root["vlans"]["MST0"]["Ethernet1"]["role"] == "designated"

    # Case 2: Non-root bridge
    conn_nonroot = MagicMock()
    conn_nonroot.send_command.return_value = json.dumps(
        {
            "spanningTreeInstances": {
                "MST0": {
                    "protocol": "mstp",
                    "bridge": {"priority": 32768, "macAddress": "bc:24:11:ed:c2:e4"},
                    "rootBridge": {"priority": 4096, "macAddress": "00:11:22:33:44:55"},
                    "interfaces": {
                        "Ethernet1": {"role": "root", "state": "forwarding"},
                        "Ethernet2": {"role": "designated", "state": "forwarding"},
                    },
                }
            }
        }
    )
    stp_nr = drv.get_stp(conn_nonroot)
    assert stp_nr["enabled"] is True
    assert stp_nr["is_root"] is False
    assert stp_nr["root_bridge"] == "00:11:22:33:44:55"
    assert stp_nr["root_port"] == "Ethernet1"


def test_arista_interfaces_merge_counters_and_interface_address_list_dict_none():
    """DE-20: Merge show interfaces counters/speed/duplex/mtu into L3 ports; use totalInErrors/fcsErrors; safe interfaceAddress."""
    drv = AristaDriver(ip="192.0.2.21")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd, **_kw: {
        "show ip interface | json": json.dumps(
            {
                "interfaces": {
                    "Management1": {
                        "interfaceAddress": {"primaryIp": {"address": "192.0.2.21", "maskLen": 24}},
                        "lineProtocolStatus": "up",
                        "physicalAddress": "bc:24:11:84:1a:90",
                        "description": "OOB Mgmt",
                    },
                    "Vlan10": {
                        "interfaceAddress": [{"primaryIp": {"address": "198.51.100.1", "maskLen": 24}}],
                        "lineProtocolStatus": "up",
                    },
                    "Vlan20": {
                        "interfaceAddress": None,
                        "lineProtocolStatus": "down",
                    },
                }
            }
        ),
        "show interfaces | json": json.dumps(
            {
                "interfaces": {
                    "Management1": {
                        "lineProtocolStatus": "up",
                        "burnedInAddress": "bc:24:11:84:1a:90",
                        "bandwidth": 1000000000,
                        "duplex": "duplexFull",
                        "mtu": 1500,
                        "interfaceAddress": [{"primaryIp": {"address": "192.0.2.21", "maskLen": 24}}],
                        "interfaceCounters": {
                            "totalInErrors": 7,
                            "totalOutErrors": 2,
                            "inDiscards": 121,
                            "outDiscards": 4,
                            "inputErrorsDetail": {"fcsErrors": 3},
                        },
                    },
                    "Ethernet1": {
                        "lineProtocolStatus": "up",
                        "burnedInAddress": "bc:24:11:68:1e:51",
                        "bandwidth": 10000000000,
                        "duplex": "duplexFull",
                        "mtu": 9214,
                        "interfaceAddress": [],
                        "interfaceCounters": {
                            "totalInErrors": 1,
                            "totalOutErrors": 0,
                            "inDiscards": 5,
                            "outDiscards": 0,
                            "inputErrorsDetail": {"fcsErrors": 1},
                        },
                    },
                }
            }
        ),
    }.get(cmd, "")

    l3, detail = drv.get_interfaces(conn)
    assert {e["interface"]: e["ip_address"] for e in l3} == {
        "Management1": "192.0.2.21/24",
        "Vlan10": "198.51.100.1/24",
    }
    # Management1 counters & L1 metadata merged from `show interfaces | json` (not skipped!)
    assert detail["Management1"]["input_errors"] == 7
    assert detail["Management1"]["output_errors"] == 2
    assert detail["Management1"]["crc"] == 3
    assert detail["Management1"]["drops"] == 125
    assert detail["Management1"]["speed"] == "1Gb/s"
    assert detail["Management1"]["duplex"] == "Full"
    assert detail["Management1"]["mtu"] == 1500
    assert detail["Ethernet1"]["speed"] == "10Gb/s"
    assert detail["Ethernet1"]["crc"] == 1


def test_arista_port_channel_primary_and_empty_trunks_no_redundant_fallback():
    """DE-21: Prefer `show port-channel | json` on EOS and treat valid empty `{"trunks": {}}` as parsed."""
    drv = AristaDriver(ip="192.0.2.22")
    calls = []
    conn = MagicMock()

    def _send(cmd, **_kw):
        calls.append(cmd)
        if cmd == "show interfaces trunk | json":
            return '{"trunks": {}}'
        if cmd == "show port-channel | json":
            return json.dumps(
                {
                    "portChannels": {
                        "Port-Channel10": {
                            "protocol": "lacp",
                            "ports": {
                                "Ethernet1": {"lacpMode": "active"},
                                "Ethernet2": {"lacpMode": "passive"},
                            },
                        }
                    }
                }
            )
        if "summary" in cmd:
            return "% Invalid input\n"
        return ""

    conn.send_command.side_effect = _send
    ops = drv.get_l2_operational(conn)
    assert ops["Ethernet1"]["lag_group"] == "Port-Channel10"
    assert ops["Ethernet1"]["lacp_mode"] == "active"
    assert ops["Ethernet2"]["lacp_mode"] == "passive"
    assert "show interfaces trunk" not in calls
    assert "show port-channel summary | json" not in calls


def test_arista_lldp_mac_classification_text_fallback_and_routes_ecmp_s_star():
    """DE-22: EOS LLDP extracts remote_mac, classifies non-switches, prefers IPv4, falls back to text; ECMP + S* routes."""
    drv = AristaDriver(ip="192.0.2.23")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd, **_kw: {
        "show lldp neighbors detail | json": json.dumps(
            {
                "lldpNeighbors": {
                    "Ethernet1": {
                        "lldpNeighborInfo": [
                            {
                                "systemName": "ap-floor1",
                                "chassisId": "40e3.d6c1.3126",
                                "portId": "eth0",
                                "systemDescription": "ArubaOS (MODEL: 515) Access Point",
                                "managementAddresses": [
                                    {"address": "fe80::1", "addressType": "ipv6"},
                                    {"address": "192.0.2.50", "addressType": "ipv4"},
                                ],
                            }
                        ]
                    }
                }
            }
        ),
        "show ip route | json": json.dumps(
            {
                "vrfs": {
                    "default": {
                        "routes": {
                            "10.0.0.0/8": {
                                "routeType": "eBGP",
                                "vias": [
                                    {"nexthopAddr": "192.0.2.1", "interface": "Ethernet1"},
                                    {"nexthopAddr": "192.0.2.2", "interface": "Ethernet2"},
                                ],
                            }
                        }
                    }
                }
            }
        ),
    }.get(cmd, "")

    nbrs = drv.get_neighbors(conn)
    assert len(nbrs) == 1
    assert nbrs[0]["remote_mac"] == "40:e3:d6:c1:31:26"
    assert nbrs[0]["remote_ip"] == "192.0.2.50"
    assert nbrs[0]["device_type"] == "ap"

    routes = drv.get_routing_table(conn)
    assert len(routes) == 2
    assert {r["next_hop"] for r in routes} == {"192.0.2.1", "192.0.2.2"}

    # Text fallback for S* and O*E2 routes + LLDP text fallback
    conn_txt = MagicMock()
    conn_txt.send_command.side_effect = lambda cmd, **_kw: {
        "show ip route | json": "% Invalid input\n",
        "show ip route": (
            " S*       0.0.0.0/0 [1/0] via 192.0.2.1, Management1\n"
            " O E2     198.51.100.0/24 [110/20] via 192.0.2.2, Ethernet1\n"
            " I L2     203.0.113.0/24 [115/10] via 192.0.2.3, Ethernet2\n"
        ),
        "show lldp neighbors detail | json": "% Invalid input\n",
        "show lldp neighbors detail": (
            "Interface Ethernet3 detected 1 LLDP neighbors:\n"
            "  Neighbor 0011.2233.4455/Ethernet4, age 0:00:10\n"
            "  - Chassis ID type: MAC address (4)\n"
            "    Chassis ID     : 0011.2233.4455\n"
            "  - Port ID type: Interface name (5)\n"
            '    Port ID     : "Ethernet4"\n'
            '  - System Name: "leaf-sw-02"\n'
            '  - System Description: "Arista Networks EOS"\n'
            "  - Management Address : 192.0.2.99\n"
        ),
    }.get(cmd, "")

    routes_txt = drv.get_routing_table(conn_txt)
    assert {r["subnet"] for r in routes_txt} == {"0.0.0.0/0", "198.51.100.0/24", "203.0.113.0/24"}

    nbrs_txt = drv.get_neighbors(conn_txt)
    assert len(nbrs_txt) == 1
    assert nbrs_txt[0]["local_port"] == "Ethernet3"
    assert nbrs_txt[0]["remote_device"] == "leaf-sw-02"
    assert nbrs_txt[0]["remote_ip"] == "192.0.2.99"


def test_juniper_and_arista_parse_errors_log_warning(caplog):
    """DE-23: JSON/CLI parse failures on Juniper & Arista log at WARNING level instead of silent DEBUG."""
    j_drv = JuniperDriver(ip="192.0.2.30")
    j_conn = MagicMock()
    j_conn.send_command.return_value = "not valid json {"
    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.juniper"):
        assert j_drv.get_arp_table(j_conn) == []
    assert any("show arp" in rec.message for rec in caplog.records)

    caplog.clear()
    a_drv = AristaDriver(ip="192.0.2.31")
    a_conn = MagicMock()
    a_conn.send_command.return_value = "not valid json {"
    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.arista"):
        assert a_drv.get_arp_table(a_conn) == []
    assert any("show ip arp" in rec.message for rec in caplog.records)

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
Unit tests for Contract B: Multi-vendor trunk configuration normalization
(`extract_port_profiles`) and operational L2 telemetry (`get_l2_operational`)
across Cisco IOS/NX-OS, Juniper Junos, Aruba AOS-CX/IAP, Arista EOS,
HP ProCurve / ArubaOS-S, and CiscoSMB.
"""

from unittest.mock import MagicMock

from net_docu_crawler.drivers import (
    AristaDriver,
    ArubaDriver,
    CiscoDriver,
    CiscoSMBDriver,
    HPProCurveDriver,
    JuniperDriver,
)
from net_docu_crawler.migration_parsers import extract_port_profiles


def _assert_no_metadata_keys(profiles: dict) -> None:
    for key in profiles:
        assert not str(key).startswith("__"), f"Illegal metadata key in port_profiles: {key}"


def test_cisco_ios_nxos_multiline_add_qinq_tag_native_and_subinterfaces():
    cisco_cfg = """
hostname CORE-SW-01
vlan dot1q tag native
!
interface GigabitEthernet1/0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20
 switchport trunk allowed vlan add 30,40-45
 switchport trunk allowed vlan add 99
!
interface GigabitEthernet1/0/2
 switchport mode trunk
 switchport trunk native vlan 10
 no switchport trunk native vlan tag
 switchport trunk allowed vlan 10,20,30
 switchport trunk allowed vlan remove 20
!
interface GigabitEthernet1/0/3
 switchport mode dynamic desirable
 switchport trunk encapsulation negotiate
!
interface GigabitEthernet1/0/4
 switchport mode dynamic auto
 switchport trunk encapsulation isl
!
interface GigabitEthernet1/0/5
 switchport access vlan 100
 switchport mode dot1q-tunnel
!
interface GigabitEthernet1/0/6
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet0/0
 no ip address
!
interface GigabitEthernet0/0.10
 encapsulation dot1Q 10
 ip address 10.10.10.1 255.255.255.0
!
interface GigabitEthernet0/0.20
 encapsulation dot1Q 20
 ip address 10.10.20.1 255.255.255.0
!
interface GigabitEthernet0/0.99
 encapsulation dot1Q 99 native
 ip address 10.10.99.1 255.255.255.0
!
interface GigabitEthernet0/1.50
 encapsulation dot1q 50
 ip address 10.10.50.1 255.255.255.0
!
interface GigabitEthernet0/1.60
 encapsulation dot1q 60
 ip address 10.10.60.1 255.255.255.0
!
"""
    profiles = extract_port_profiles(cisco_cfg, vendor="Cisco Systems")
    _assert_no_metadata_keys(profiles)

    # Multi-line add + global vlan dot1q tag native
    p1 = profiles["GigabitEthernet1/0/1"]
    assert p1["mode"] == "trunk"
    assert p1["admin_mode"] == "trunk"
    assert p1["encapsulation"] == "dot1q"
    assert p1["native_vlan"] == "99"
    assert p1["native_vlan_tagged"] is True
    assert p1["trunk_allowed_vlans"] == "10,20,30,40-45,99"
    assert p1["qinq_tunnel"] is False
    assert p1["is_subinterface_bundle"] is False

    # Explicit `no switchport trunk native vlan tag` overrides global directive; `remove` subtracts VLAN 20
    p2 = profiles["GigabitEthernet1/0/2"]
    assert p2["native_vlan_tagged"] is False
    assert p2["trunk_allowed_vlans"] == "10,30"

    # DTP dynamic modes & encapsulation
    p3 = profiles["GigabitEthernet1/0/3"]
    assert p3["admin_mode"] == "dynamic_desirable"
    assert p3["encapsulation"] == "negotiate"
    assert p3["native_vlan_tagged"] is True

    p4 = profiles["GigabitEthernet1/0/4"]
    assert p4["admin_mode"] == "dynamic_auto"
    assert p4["encapsulation"] == "isl"

    # QinQ dot1q-tunnel maps to mode="trunk", admin_mode="dot1q_tunnel", qinq_tunnel=True
    p5 = profiles["GigabitEthernet1/0/5"]
    assert p5["mode"] == "trunk"
    assert p5["admin_mode"] == "dot1q_tunnel"
    assert p5["qinq_tunnel"] is True
    assert p5["access_vlan"] == "100"
    assert p5["native_vlan_tagged"] is False

    # Access port unaffected by global vlan dot1q tag native
    p6 = profiles["GigabitEthernet1/0/6"]
    assert p6["mode"] == "access"
    assert p6["admin_mode"] == "access"
    assert p6["native_vlan_tagged"] is False

    # L3 dot1Q subinterfaces synthesized onto parent port (not emitted as subinterface keys)
    assert "GigabitEthernet0/0.10" not in profiles
    assert "GigabitEthernet0/0.99" not in profiles
    p_rtr0 = profiles["GigabitEthernet0/0"]
    assert p_rtr0["mode"] == "trunk"
    assert p_rtr0["admin_mode"] == "trunk"
    assert p_rtr0["is_subinterface_bundle"] is True
    assert p_rtr0["trunk_allowed_vlans"] == "10,20,99"
    assert p_rtr0["native_vlan"] == "99"
    assert p_rtr0["native_vlan_tagged"] is False

    # Subinterface bundle without `native` keyword -> tagged-only
    assert "GigabitEthernet0/1.50" not in profiles
    p_rtr1 = profiles["GigabitEthernet0/1"]
    assert p_rtr1["is_subinterface_bundle"] is True
    assert p_rtr1["trunk_allowed_vlans"] == "50,60"
    assert p_rtr1["native_vlan"] == "none"
    assert p_rtr1["native_vlan_tagged"] is True


def test_cisco_interface_native_vlan_tag_without_global():
    nxos_cfg = """
interface Ethernet1/1
 switchport mode trunk
 switchport trunk native vlan 50
 switchport trunk native vlan tag
 switchport trunk allowed vlan 10,50
"""
    profiles = extract_port_profiles(nxos_cfg, vendor="Cisco")
    _assert_no_metadata_keys(profiles)
    e1 = profiles["Ethernet1/1"]
    assert e1["mode"] == "trunk"
    assert e1["admin_mode"] == "trunk"
    assert e1["native_vlan"] == "50"
    assert e1["native_vlan_tagged"] is True
    assert e1["trunk_allowed_vlans"] == "10,50"


def test_juniper_native_vlan_id_and_vlan_tagging_units():
    junos_cfg = """
set vlans DATA vlan-id 10
set vlans VOICE vlan-id 20
set vlans MGMT vlan-id 99
set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members [ DATA VOICE ]
set interfaces ge-0/0/2 native-vlan-id 99
set interfaces ge-0/0/2 unit 0 family ethernet-switching interface-mode trunk
set interfaces ge-0/0/2 unit 0 family ethernet-switching vlan members [ DATA VOICE MGMT ]
set interfaces ge-0/0/3 unit 0 family ethernet-switching interface-mode access
set interfaces ge-0/0/3 unit 0 family ethernet-switching vlan members DATA
set interfaces ge-0/0/4 vlan-tagging
set interfaces ge-0/0/4 unit 10 vlan-id 10
set interfaces ge-0/0/4 unit 10 family inet address 10.10.10.1/24
set interfaces ge-0/0/4 unit 20 vlan-id 20
set interfaces ge-0/0/4 unit 20 family inet address 10.10.20.1/24
set interfaces ge-0/0/5 flexible-vlan-tagging
set interfaces ge-0/0/5 native-vlan-id 99
set interfaces ge-0/0/5 unit 99 vlan-id 99
set interfaces ge-0/0/5 unit 100 vlan-id 100
"""
    profiles = extract_port_profiles(junos_cfg, vendor="Juniper Networks")
    _assert_no_metadata_keys(profiles)

    # Trunk without native-vlan-id -> native_vlan="none" & native_vlan_tagged=True
    g1 = profiles["ge-0/0/1"]
    assert g1["mode"] == "trunk"
    assert g1["admin_mode"] == "trunk"
    assert g1["native_vlan"] == "none"
    assert g1["native_vlan_tagged"] is True
    assert g1["trunk_allowed_vlans"] == "10,20"
    assert g1["encapsulation"] == "dot1q"

    # Trunk with native-vlan-id 99 -> native_vlan="99" & native_vlan_tagged=False
    g2 = profiles["ge-0/0/2"]
    assert g2["mode"] == "trunk"
    assert g2["admin_mode"] == "trunk"
    assert g2["native_vlan"] == "99"
    assert g2["native_vlan_tagged"] is False
    assert g2["trunk_allowed_vlans"] == "10,20,99"

    # Access port
    g3 = profiles["ge-0/0/3"]
    assert g3["mode"] == "access"
    assert g3["admin_mode"] == "access"
    assert g3["access_vlan"] == "10"
    assert g3["native_vlan_tagged"] is False

    # L3 vlan-tagging units synthesized onto parent ge-0/0/4 (all tagged)
    g4 = profiles["ge-0/0/4"]
    assert g4["mode"] == "trunk"
    assert g4["admin_mode"] == "trunk"
    assert g4["is_subinterface_bundle"] is True
    assert g4["trunk_allowed_vlans"] == "10,20"
    assert g4["native_vlan"] == "none"
    assert g4["native_vlan_tagged"] is True

    # L3 flexible-vlan-tagging units with native-vlan-id 99
    g5 = profiles["ge-0/0/5"]
    assert g5["is_subinterface_bundle"] is True
    assert g5["trunk_allowed_vlans"] == "99,100"
    assert g5["native_vlan"] == "99"
    assert g5["native_vlan_tagged"] is False


def test_aruba_aoscx_config_parsing_and_driver_detection():
    aoscx_cfg = """
vlan 1
vlan 10
    name DATA
vlan 20
    name VOICE
vlan 99
    name MGMT
interface lag 1
    no shutdown
    no routing
    vlan trunk native 99
    vlan trunk native tag
    vlan trunk allowed 10,20,99
    lacp mode active
interface 1/1/1
    no shutdown
    no routing
    vlan access 10
    spanning-tree bpdu-guard
interface 1/1/2
    no shutdown
    no routing
    vlan trunk native 1
    vlan trunk allowed 1,10,20
interface 1/1/3
    no shutdown
    lag 1
interface 1/1/4
    no shutdown
    routing
    ip address 10.0.0.1/30
"""
    profiles = extract_port_profiles(aoscx_cfg, vendor="Aruba Networks / HPE")
    _assert_no_metadata_keys(profiles)

    lag1 = profiles["lag1"]
    assert lag1["mode"] == "trunk"
    assert lag1["admin_mode"] == "trunk"
    assert lag1["native_vlan"] == "99"
    assert lag1["native_vlan_tagged"] is True
    assert lag1["trunk_allowed_vlans"] == "10,20,99"
    assert lag1["lacp_mode"] == "active"

    p1 = profiles["1/1/1"]
    assert p1["mode"] == "access"
    assert p1["admin_mode"] == "access"
    assert p1["access_vlan"] == "10"
    assert p1["bpdu_guard"] is True

    p2 = profiles["1/1/2"]
    assert p2["mode"] == "trunk"
    assert p2["native_vlan"] == "1"
    assert p2["native_vlan_tagged"] is False
    assert p2["trunk_allowed_vlans"] == "1,10,20"

    p3 = profiles["1/1/3"]
    assert p3["lag_group"] == "lag1"
    assert p3["lacp_mode"] == "active"

    p4 = profiles["1/1/4"]
    assert p4["mode"] == "routed"
    assert p4["admin_mode"] == "routed"

    # ArubaDriver AOS-CX switch detection & operational trunk + LACP parsing
    drv = ArubaDriver(ip="10.1.1.10")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show version": (
            "-----------------------------------------------------------------------------\n"
            "ArubaOS-CX\n"
            "(c) Copyright 2017-2024 Hewlett Packard Enterprise Development LP\n"
            "-----------------------------------------------------------------------------\n"
            "Version      : FL.10.13.1000\n"
        ),
        "show system": (
            "Hostname               : CX-CORE-01\n"
            "Product Name           : JL665A 6300F 48G\n"
            "Chassis Serial Nbr     : SG12KL0099\n"
            "Base MAC Address       : 88:3a:30:11:22:33\n"
        ),
        "show interface trunk": (
            "--------------------------------------------------------------------------------\n"
            "Port     Native    Mode             Type           Status    Reason    Allowed VLANs\n"
            "         VLAN\n"
            "--------------------------------------------------------------------------------\n"
            "1/1/24   99        native-tagged    10G-SR         up                  10,20,99\n"
            "lag1     1         native-untagged  --             up                  1,10,20\n"
            "1/1/23   1         trunk            1G-T           down      Admin down 10,20\n"
        ),
        "show lacp interfaces": (
            "Aggregate name : lag1\n"
            "--------------------------------------------------------------------------------\n"
            "Interfaces  Actor     Actor        Actor   Partner   Partner      Partner   Aggregated\n"
            "1/1/3       3         1            ALFNCD  3         1            ALFNCD    up\n"
            "1/1/4       4         1            PLFNCD  4         1            ALFNCD    up\n"
        ),
    }.get(cmd, "")
    mock_conn.find_prompt.return_value = "CX-CORE-01#"

    ver = drv.get_version(mock_conn)
    assert ver["device_persona"] == "switch"
    assert ver["device_type"] == "switch"
    assert ver["os_type"] == "aruba_aoscx"
    assert ver["hostname"] == "CX-CORE-01"
    assert ver["serial"] == "SG12KL0099"
    assert ver["firmware"] == "FL.10.13.1000"
    assert ver["mac_address"] == "88:3a:30:11:22:33"

    ops = drv.get_l2_operational(mock_conn)
    _assert_no_metadata_keys(ops)
    assert ops["1/1/24"]["oper_mode"] == "trunk"
    assert ops["1/1/24"]["native_vlan"] == "99"
    assert ops["1/1/24"]["native_vlan_tagged"] is True
    assert ops["1/1/24"]["trunk_allowed_vlans"] == "10,20,99"
    assert ops["1/1/24"]["trunk_active_vlans"] == "10,20,99"
    assert ops["lag1"]["oper_mode"] == "trunk"
    assert ops["lag1"]["native_vlan_tagged"] is False
    assert ops["1/1/23"]["oper_mode"] == "down"
    assert ops["1/1/3"]["lag_group"] == "lag1"
    assert ops["1/1/3"]["lacp_mode"] == "active"
    assert ops["1/1/4"]["lag_group"] == "lag1"
    assert ops["1/1/4"]["lacp_mode"] == "passive"

    # IAP AP gracefully no-ops get_l2_operational
    iap_drv = ArubaDriver(ip="10.1.1.20")
    iap_conn = MagicMock()
    iap_conn.send_command.side_effect = lambda cmd: {
        "show version": "Aruba Operating System Software.\nArubaOS (MODEL: 515), Version 8.10.0.5\n",
        "show aps": "",
    }.get(cmd, "Invalid input detected")
    iap_conn.find_prompt.return_value = "AP-Lobby#"
    iap_ver = iap_drv.get_version(iap_conn)
    assert iap_ver["device_persona"] == "ap"
    assert iap_ver["os_type"] == "aruba_os"
    assert iap_drv.get_l2_operational(iap_conn) == {}


def test_cisco_driver_get_l2_operational_ios_and_nxos():
    drv = CiscoDriver(ip="10.1.1.1")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show interfaces trunk": (
            "Port        Mode             Encapsulation  Status        Native vlan\n"
            "Gi1/0/24    on               802.1q         trunking      99\n"
            "Po1         desirable        n-802.1q       trunking      1\n"
            "\n"
            "Port        Vlans allowed on trunk\n"
            "Gi1/0/24    10,20,30,99\n"
            "Po1         1,10,20\n"
            "\n"
            "Port        Vlans allowed and active in management domain\n"
            "Gi1/0/24    10,20,99\n"
            "Po1         1,10,20\n"
            "\n"
            "Port        Vlans in spanning tree forwarding state and not pruned\n"
            "Gi1/0/24    10,20,99\n"
            "Po1         1,10,20\n"
        ),
        "show etherchannel summary": ("1      Po1(SU)         LACP      Gi1/0/21(P)  Gi1/0/22(P)\n"),
    }.get(cmd, "")

    ops = drv.get_l2_operational(mock_conn)
    _assert_no_metadata_keys(ops)
    assert ops["Gi1/0/24"]["oper_mode"] == "trunk"
    assert ops["Gi1/0/24"]["admin_mode"] == "trunk"
    assert ops["Gi1/0/24"]["encapsulation"] == "dot1q"
    assert ops["Gi1/0/24"]["native_vlan"] == "99"
    assert ops["Gi1/0/24"]["trunk_allowed_vlans"] == "10,20,30,99"
    assert ops["Gi1/0/24"]["trunk_active_vlans"] == "10,20,99"
    assert ops["Po1"]["admin_mode"] == "dynamic_desirable"
    assert ops["Po1"]["trunk_active_vlans"] == "1,10,20"
    assert ops["Gi1/0/21"]["lag_group"] == "Po1"
    assert ops["Gi1/0/21"]["lacp_mode"] == "active"

    # NX-OS `show interfaces trunk` format (with STP Forwarding section)
    nxos_conn = MagicMock()
    nxos_conn.send_command.side_effect = lambda cmd: {
        "show interfaces trunk": (
            "--------------------------------------------------------------------------------\n"
            "Port          Native  Status        Port\n"
            "              Vlan                  Channel\n"
            "--------------------------------------------------------------------------------\n"
            "Eth1/1        99      trunking      --\n"
            "\n"
            "--------------------------------------------------------------------------------\n"
            "Port          Vlans Allowed on Trunk\n"
            "--------------------------------------------------------------------------------\n"
            "Eth1/1        10,20,99\n"
            "\n"
            "--------------------------------------------------------------------------------\n"
            "Port          STP Forwarding\n"
            "--------------------------------------------------------------------------------\n"
            "Eth1/1        10,99\n"
        )
    }.get(cmd, "")
    nx_ops = drv.get_l2_operational(nxos_conn)
    _assert_no_metadata_keys(nx_ops)
    assert nx_ops["Eth1/1"]["oper_mode"] == "trunk"
    assert nx_ops["Eth1/1"]["native_vlan"] == "99"
    assert nx_ops["Eth1/1"]["trunk_allowed_vlans"] == "10,20,99"
    assert nx_ops["Eth1/1"]["trunk_active_vlans"] == "10,99"

    # Safe against unconfigured MagicMock return values
    bare_conn = MagicMock()
    assert drv.get_l2_operational(bare_conn) == {}


def test_juniper_driver_get_l2_operational_json_and_text_fallback():
    drv = JuniperDriver(ip="10.1.1.2")

    # 1. Structured JSON path
    json_conn = MagicMock()
    json_conn.send_command.side_effect = lambda cmd: {
        "show ethernet-switching interfaces | display json": """{
            "l2ng-l2ald-iff-interface-information": [{
                "l2ng-l2ald-iff-interface-entry": [
                    {
                        "l2ng-l2ald-iff-interface-name": [{"data": "ge-0/0/1.0"}],
                        "l2ng-l2ald-iff-port-mode": [{"data": "trunk"}],
                        "l2ng-l2ald-iff-interface-state": [{"data": "up"}],
                        "l2ng-l2ald-iff-interface-vlan-member-list": [{
                            "l2ng-l2ald-iff-interface-vlan-member": [
                                {"l2ng-l2ald-iff-interface-vlan-member-tagid": [{"data": "10"}], "l2ng-l2ald-iff-interface-vlan-member-tagness": [{"data": "tagged"}]},
                                {"l2ng-l2ald-iff-interface-vlan-member-tagid": [{"data": "20"}], "l2ng-l2ald-iff-interface-vlan-member-tagness": [{"data": "tagged"}]}
                            ]
                        }]
                    },
                    {
                        "l2ng-l2ald-iff-interface-name": [{"data": "ge-0/0/2.0"}],
                        "l2ng-l2ald-iff-port-mode": [{"data": "trunk"}],
                        "l2ng-l2ald-iff-interface-state": [{"data": "up"}],
                        "l2ng-l2ald-iff-interface-vlan-member-list": [{
                            "l2ng-l2ald-iff-interface-vlan-member": [
                                {"l2ng-l2ald-iff-interface-vlan-member-tagid": [{"data": "10"}], "l2ng-l2ald-iff-interface-vlan-member-tagness": [{"data": "tagged"}]},
                                {"l2ng-l2ald-iff-interface-vlan-member-tagid": [{"data": "99"}], "l2ng-l2ald-iff-interface-vlan-member-tagness": [{"data": "untagged"}]}
                            ]
                        }]
                    }
                ]
            }]
        }"""
    }.get(cmd, "")

    ops_json = drv.get_l2_operational(json_conn)
    _assert_no_metadata_keys(ops_json)
    assert ops_json["ge-0/0/1"]["oper_mode"] == "trunk"
    assert ops_json["ge-0/0/1"]["trunk_active_vlans"] == "10,20"
    assert ops_json["ge-0/0/1"]["native_vlan"] == "none"
    assert ops_json["ge-0/0/1"]["native_vlan_tagged"] is True
    assert ops_json["ge-0/0/2"]["trunk_active_vlans"] == "10,99"
    assert ops_json["ge-0/0/2"]["native_vlan"] == "99"
    assert ops_json["ge-0/0/2"]["native_vlan_tagged"] is False

    # 2. Text fallback path
    txt_conn = MagicMock()
    txt_conn.send_command.side_effect = lambda cmd: {
        "show ethernet-switching interfaces | display json": "syntax error",
        "show ethernet-switching interfaces": (
            "Routing Instance Name : default-switch\n"
            "Logical     Vlan         TAG  MAC    STP       Logical         Tagging\n"
            "interface   members           limit  state     interface flags\n"
            "ge-0/0/1.0  DATA         10   65535  Forwarding                tagged\n"
            "            VOICE        20   65535  Forwarding                tagged\n"
            "ge-0/0/2.0  DATA         10   65535  Forwarding                untagged\n"
        ),
    }.get(cmd, "")

    ops_txt = drv.get_l2_operational(txt_conn)
    _assert_no_metadata_keys(ops_txt)
    assert ops_txt["ge-0/0/1"]["oper_mode"] == "trunk"
    assert ops_txt["ge-0/0/1"]["trunk_active_vlans"] == "10,20"
    assert ops_txt["ge-0/0/1"]["native_vlan"] == "none"
    assert ops_txt["ge-0/0/1"]["native_vlan_tagged"] is True
    assert ops_txt["ge-0/0/2"]["oper_mode"] == "access"
    assert ops_txt["ge-0/0/2"]["access_vlan"] == "10"


def test_arista_driver_get_l2_operational_json_and_text_fallback():
    drv = AristaDriver(ip="10.1.1.3")

    # 1. JSON path
    json_conn = MagicMock()
    json_conn.send_command.side_effect = lambda cmd: {
        "show interfaces trunk | json": """{
            "trunks": {
                "Ethernet1": {
                    "nativeVlan": 99,
                    "encapsulation": "dot1q",
                    "status": "trunking",
                    "allowedVlans": {"vlanIds": [10, 20, 99]},
                    "activeVlans": {"vlanIds": [10, 99]}
                }
            }
        }""",
        "show port-channel summary | json": """{
            "portChannels": {
                "Port-Channel1": {
                    "protocol": "lacp",
                    "ports": {
                        "Ethernet1": {"lacpMode": "active"},
                        "Ethernet2": {"lacpMode": "active"}
                    }
                }
            }
        }""",
    }.get(cmd, "")

    ops = drv.get_l2_operational(json_conn)
    _assert_no_metadata_keys(ops)
    assert ops["Ethernet1"]["oper_mode"] == "trunk"
    assert ops["Ethernet1"]["native_vlan"] == "99"
    assert ops["Ethernet1"]["trunk_allowed_vlans"] == "10,20,99"
    assert ops["Ethernet1"]["trunk_active_vlans"] == "10,99"
    assert ops["Ethernet1"]["lag_group"] == "Port-Channel1"
    assert ops["Ethernet1"]["lacp_mode"] == "active"
    assert ops["Ethernet2"]["lag_group"] == "Port-Channel1"

    # 2. Text fallback path
    txt_conn = MagicMock()
    txt_conn.send_command.side_effect = lambda cmd: {
        "show interfaces trunk | json": "Invalid input",
        "show interfaces trunk": (
            "Port       Mode         Status         Native vlan\n"
            "Et1        trunk        trunking       10\n"
            "Port       Vlans allowed on trunk\n"
            "Et1        10,20,30\n"
            "Port       Vlans allowed and active in management domain\n"
            "Et1        10,20\n"
        ),
        "show port-channel summary | json": "Invalid input",
        "show port-channel summary": "1      Po1(U)        LACP        Et1(P) Et2(P)\n",
    }.get(cmd, "")

    ops_txt = drv.get_l2_operational(txt_conn)
    _assert_no_metadata_keys(ops_txt)
    assert ops_txt["Et1"]["oper_mode"] == "trunk"
    assert ops_txt["Et1"]["native_vlan"] == "10"
    assert ops_txt["Et1"]["trunk_allowed_vlans"] == "10,20,30"
    assert ops_txt["Et1"]["trunk_active_vlans"] == "10,20"
    assert ops_txt["Et1"]["lag_group"] == "Po1"


def test_hpprocurve_config_and_get_l2_operational():
    hp_cfg = """
trunk 23-24 Trk1 lacp
vlan 1
   name "DEFAULT_VLAN"
   untagged 1-22
   exit
vlan 10
   name "DATA"
   tagged 22,Trk1
   exit
vlan 20
   name "SERVERS"
   tagged 22,Trk1
   exit
"""
    profiles = extract_port_profiles(hp_cfg, vendor="HP ProCurve / ArubaOS-S")
    _assert_no_metadata_keys(profiles)

    # Port 22 has untagged 1 + tagged 10,20 -> native_vlan="1", native_vlan_tagged=False
    p22 = profiles["22"]
    assert p22["mode"] == "trunk"
    assert p22["admin_mode"] == "trunk"
    assert p22["encapsulation"] == "dot1q"
    assert p22["native_vlan"] == "1"
    assert p22["native_vlan_tagged"] is False
    assert p22["trunk_allowed_vlans"] == "1,10,20"

    # Trk1 has tagged 10,20 with NO untagged VLAN -> native_vlan="none", native_vlan_tagged=True
    trk1 = profiles["Trk1"]
    assert trk1["mode"] == "trunk"
    assert trk1["admin_mode"] == "trunk"
    assert trk1["encapsulation"] == "dot1q"
    assert trk1["native_vlan"] == "none"
    assert trk1["native_vlan_tagged"] is True
    assert trk1["trunk_allowed_vlans"] == "10,20"

    # Access port 1
    p1 = profiles["1"]
    assert p1["mode"] == "access"
    assert p1["admin_mode"] == "access"
    assert p1["access_vlan"] == "1"
    assert p1["native_vlan_tagged"] is False

    # Operational command parsing
    drv = HPProCurveDriver(ip="10.1.1.4")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show trunks": "  23 | 100/1000T | Trk1 LACP\n  24 | 100/1000T | Trk1 LACP\n",
        "show vlans ports all": (
            " Port name: Trk1\n"
            " VLAN ID Name                             | Status     Voice Jumbo Mode\n"
            " ------- -------------------------------- + ---------- ----- ----- --------\n"
            " 10      DATA                             | Port-based No    No    Tagged\n"
            " 20      SERVERS                          | Port-based No    No    Tagged\n"
            " Port name: 22\n"
            " 1       DEFAULT_VLAN                     | Port-based No    No    Untagged\n"
            " 10      DATA                             | Port-based No    No    Tagged\n"
        ),
    }.get(cmd, "")

    ops = drv.get_l2_operational(mock_conn)
    _assert_no_metadata_keys(ops)
    assert ops["Trk1"]["oper_mode"] == "trunk"
    assert ops["Trk1"]["trunk_active_vlans"] == "10,20"
    assert ops["Trk1"]["native_vlan"] == "none"
    assert ops["Trk1"]["native_vlan_tagged"] is True
    assert ops["22"]["oper_mode"] == "trunk"
    assert ops["22"]["trunk_active_vlans"] == "1,10"
    assert ops["22"]["native_vlan"] == "1"
    assert ops["22"]["native_vlan_tagged"] is False
    assert ops["23"]["lag_group"] == "Trk1"


def test_ciscosmb_get_l2_operational():
    drv = CiscoSMBDriver(ip="10.1.1.5")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show interfaces switchport": (
            "Port : gi24\n"
            "Port Mode: Trunk\n"
            "Ingress UnTagged VLAN ( NATIVE ): 99\n"
            "Vlan               Name               Egress rule Port Membership Type\n"
            "---- -------------------------------- ----------- --------------------\n"
            " 10               DATA                  Tagged           Static\n"
            " 20               VOICE                 Tagged           Static\n"
            " 99               MGMT                 Untagged          Static\n"
            "Port : gi1\n"
            "Port Mode: Access\n"
            "Ingress UnTagged VLAN ( NATIVE ): 10\n"
            " 10               DATA                 Untagged          Static\n"
        ),
        "show interfaces port-channel": "Po1   Active: gi25,gi26\n",
    }.get(cmd, "")

    ops = drv.get_l2_operational(mock_conn)
    _assert_no_metadata_keys(ops)
    assert ops["gi24"]["oper_mode"] == "trunk"
    assert ops["gi24"]["native_vlan"] == "99"
    assert ops["gi24"]["native_vlan_tagged"] is False
    assert ops["gi24"]["trunk_active_vlans"] == "10,20,99"
    assert ops["gi1"]["oper_mode"] == "access"
    assert ops["gi1"]["access_vlan"] == "10"
    assert ops["gi25"]["lag_group"] == "Po1"
    assert ops["gi26"]["lag_group"] == "Po1"

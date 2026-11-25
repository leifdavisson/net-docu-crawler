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

"""Regression tests for parser.py, CiscoDriver (IOS/IOS-XE/NX-OS), and CiscoSMBDriver."""

import logging
from unittest.mock import MagicMock, patch

import parser
from net_docu_crawler.drivers.cisco import CiscoDriver
from net_docu_crawler.drivers.ciscosmb import CiscoSMBDriver


def test_textfsm_argument_order_and_logging(caplog):
    """DE-01 / DE-23: TextFSM calls pass (output, platform=..., command=...) and log warnings on failure."""
    nx_ver = (
        "Cisco Nexus Operating System (NX-OS) Software\n"
        "Software\n"
        "  BIOS: version 05.45\n"
        "  NXOS: version 9.3(10)\n"
        "Hardware\n"
        "  cisco Nexus9000 C93180YC-FX Chassis\n"
        "  Processor Board ID FDO23120ABC\n"
        "  Device name: N9K-LEAF-01\n"
    )
    calls = []

    def _spy(raw_output, platform=None, command=None, **kwargs):
        calls.append((raw_output, platform, command))
        raise RuntimeError("forced textfsm error")

    with (
        patch.object(parser, "get_structured_data", side_effect=_spy),
        caplog.at_level(logging.WARNING, logger="parser"),
    ):
        res = parser.parse_show_version(nx_ver, "cisco_nxos")

    assert len(calls) == 1
    assert calls[0][0].startswith("Cisco Nexus")
    assert calls[0][1] == "cisco_nxos"
    assert calls[0][2] == "show version"
    assert any("forced textfsm error" in rec.message for rec in caplog.records)
    # Regex fallback must also extract NX-OS hostname
    assert res["hostname"] == "N9K-LEAF-01"
    assert res["firmware"] == "9.3(10)"
    assert res["serial"] == "FDO23120ABC"


def test_parse_show_interfaces_preserves_mac_on_l3_intf():
    """DE-02: Internet address line must NEVER overwrite hardware MAC address."""
    output = (
        "Vlan1 is up, line protocol is up\n"
        "  Hardware is EtherSVI, address is 78da.6ea2.4fdf (bia 78da.6ea2.4fdf)\n"
        "  Description: Management Uplink via FE0\n"
        "  Internet address is 192.168.1.250/24\n"
        "  MTU 1500 bytes, BW 100000 Kbit/sec, DLY 100 usec\n"
        "     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\n"
        "     0 output errors, 1 interface resets\n"
    )
    # Test both with TextFSM disabled (regex path) and default path
    with patch.object(parser, "get_structured_data", None):
        details = parser.parse_show_interfaces(output, "cisco_ios")
    assert details["Vlan1"]["mac_address"] == "78da6ea24fdf"
    assert details["Vlan1"]["description"] == "Management Uplink via FE0"


def test_parse_show_ip_route_default_xr_nxos_classful():
    """DE-03: Parse S* default, O*E2, O IA, D EX, classful subnetted, IOS-XR uptimes, and NX-OS *via routes."""
    ios_out = (
        "Gateway of last resort is 192.168.1.1 to network 0.0.0.0\n\n"
        "S*    0.0.0.0/0 [1/0] via 192.168.1.1\n"
        "O*E2  0.0.0.0/0 [110/1] via 10.0.0.2, 01:23:45, GigabitEthernet0/0\n"
        "      172.16.0.0/24 is subnetted, 2 subnets\n"
        "C        172.16.1.0 is directly connected, Vlan10\n"
        "O IA     172.16.2.0 [110/2] via 10.0.0.2, 00:12:34, GigabitEthernet0/0\n"
        "D EX     192.168.20.0/24 [170/25600] via 10.0.0.3, 00:10:00, GigabitEthernet0/1\n"
    )
    with patch.object(parser, "get_structured_data", None):
        ios_routes = parser.parse_show_ip_route(ios_out, "cisco_ios")

    by_key = {(r["subnet"], r["protocol"], r["next_hop"]): r["interface"] for r in ios_routes}
    assert ("0.0.0.0/0", "Static", "192.168.1.1") in by_key
    assert by_key[("0.0.0.0/0", "OSPF", "10.0.0.2")] == "GigabitEthernet0/0"
    assert by_key[("172.16.1.0/24", "Connected", "Directly Connected")] == "Vlan10"
    assert by_key[("172.16.2.0/24", "OSPF", "10.0.0.2")] == "GigabitEthernet0/0"
    assert by_key[("192.168.20.0/24", "EIGRP", "10.0.0.3")] == "GigabitEthernet0/1"

    xr_out = (
        "C    10.10.0.0/30 is directly connected, 4w2d, Bundle-Ether1\n"
        "L    10.10.0.1/32 is directly connected, 4w2d, Bundle-Ether1\n"
        "S*   0.0.0.0/0 [1/0] via 10.10.0.2, 2w1d, Bundle-Ether1\n"
        "B    10.255.0.2/32 [200/0] via 10.10.0.2, 2w1d\n"
        "O    10.30.0.0/24 [110/2] via 10.10.0.2, 1d02h, Bundle-Ether1\n"
    )
    with patch.object(parser, "get_structured_data", None):
        xr_routes = parser.parse_show_ip_route(xr_out, "cisco_xr")
    xr_by_sub = {r["subnet"]: r for r in xr_routes}
    assert xr_by_sub["10.10.0.0/30"]["interface"] == "Bundle-Ether1"
    assert xr_by_sub["0.0.0.0/0"]["next_hop"] == "10.10.0.2"
    assert xr_by_sub["0.0.0.0/0"]["interface"] == "Bundle-Ether1"
    assert xr_by_sub["10.255.0.2/32"]["interface"] == ""
    assert xr_by_sub["10.30.0.0/24"]["interface"] == "Bundle-Ether1"

    nxos_out = (
        "0.0.0.0/0, ubest/mbest: 1/0\n"
        "    *via 10.0.0.1, Eth1/1, [1/0], 2w1d, static\n"
        "10.10.0.0/24, ubest/mbest: 1/0, attached\n"
        "    *via 10.10.0.1, Vlan10, [0/0], 3w0d, direct\n"
    )
    with patch.object(parser, "get_structured_data", None):
        nx_routes = parser.parse_show_ip_route(nxos_out, "cisco_nxos")
    nx_by_sub = {r["subnet"]: r for r in nx_routes}
    assert nx_by_sub["0.0.0.0/0"]["next_hop"] == "10.0.0.1"
    assert nx_by_sub["0.0.0.0/0"]["interface"] == "Eth1/1"
    assert nx_by_sub["0.0.0.0/0"]["protocol"].lower() == "static"
    assert nx_by_sub["10.10.0.0/24"]["interface"] == "Vlan10"


def test_parse_spanning_tree_disabled_and_ios_router():
    """DE-04: STP disabled text must return enabled=False; IOS router STP must extract bridge ID & protocol."""
    assert parser.parse_spanning_tree("No spanning tree instance exists.\n", "cisco_ios")["enabled"] is False
    assert parser.parse_spanning_tree("Spanning tree disabled for VLAN 1\n", "cisco_ios")["enabled"] is False
    assert parser.parse_spanning_tree("% Invalid input detected at '^' marker.\n", "cisco_ios")["enabled"] is False

    ios_router_stp = (
        " VLAN1 is executing the ieee compatible Spanning Tree protocol\n"
        "  Bridge Identifier has priority 32768, address 78da.6ea2.4fdf\n"
        "  Configured hello time 2, max age 20, forward delay 15\n"
        "  We are the root of the spanning tree\n"
        " Port 1 (FastEthernet0) of VLAN1 is forwarding\n"
        "   Designated root has priority 32768, address 78da.6ea2.4fdf\n"
    )
    stp = parser.parse_spanning_tree(ios_router_stp, "cisco_ios")
    assert stp["enabled"] is True
    assert stp["is_root"] is True
    assert stp["root_bridge"] == "78da6ea24fdf"
    assert stp["bridge_priority"] == "32768"
    assert stp["protocol"].lower() == "ieee"


def test_parse_ip_interface_brief_ignores_cli_errors():
    """DE-06: CLI error lines must never be parsed as L3 interfaces."""
    err = "% Invalid input detected at '^' marker.\n"
    with patch.object(parser, "get_structured_data", None):
        assert parser.parse_ip_interface_brief(err, "cisco_ios") == []


def test_cisco_nxos_interfaces_mac_version_and_lag():
    """DE-05: NX-OS 3-col IP int brief, speed/errors, MAC flag stripping, hostname, and show port-channel summary."""
    drv = CiscoDriver(ip="10.20.0.1")
    conn = MagicMock()
    conn.find_prompt.return_value = "N9K-LEAF-01#"
    responses = {
        "show version": (
            "Cisco Nexus Operating System (NX-OS) Software\n"
            "Software\n"
            "  NXOS: version 9.3(10)\n"
            "Hardware\n"
            "  cisco Nexus9000 C93180YC-FX Chassis\n"
            "  Processor Board ID FDO23120ABC\n"
            "  Device name: N9K-LEAF-01\n"
        ),
        "show inventory": (
            'NAME: "Chassis", DESCR: "Nexus9000 C93180YC-FX Chassis"\n'
            "PID: N9K-C93180YC-FX   , VID: V02 , SN: FDO23120ABC\n"
        ),
        "show ip interface brief": (
            'IP Interface Status for VRF "default"(1)\n'
            "Interface            IP Address      Interface Status\n"
            "Vlan10               10.10.10.1      protocol-up/link-up/admin-up\n"
            "Eth1/1               10.1.1.1        protocol-up/link-up/admin-up\n"
        ),
        "show interfaces": (
            "Ethernet1/1 is up\n"
            "admin state is up, Dedicated Interface\n"
            "  Hardware: 1000/10000 Ethernet, address: 5000.0001.0007 (bia 5000.0001.0007)\n"
            "  Description: Spine-Link\n"
            "  Internet address is 10.1.1.1/30\n"
            "  full-duplex, 10 Gb/s, media type is 10G\n"
            "  RX\n"
            "    3 input error  0 short frame  2 CRC\n"
            "  TX\n"
            "    1 output error  0 collision\n"
        ),
        "show mac address-table": (
            "   VLAN     MAC Address      Type      age     Secure NTFY Ports\n"
            "---------+-----------------+--------+---------+------+----+------------------\n"
            "*  10       0050.56ab.cd01   dynamic  0         F      F    Eth1/1\n"
            "+  20       0011.2233.4455   dynamic  30        F      F    Po1\n"
            "G  10       5000.0001.0007   static   -         F      F    sup-eth1(R)\n"
        ),
        "show interfaces trunk": "",
        "show etherchannel summary": "% Invalid command at '^' marker.\n",
        "show port-channel summary": ("1     Po1(SU)     Eth      LACP      Eth1/49(P)   Eth1/50(P)\n"),
    }
    conn.send_command.side_effect = lambda cmd, **_kw: responses.get(cmd, "")

    ver = drv.get_version(conn)
    assert ver["os_type"] == "cisco_nxos"
    assert ver["hostname"] == "N9K-LEAF-01"

    l3, detail = drv.get_interfaces(conn)
    assert len(l3) == 2
    assert {e["interface"]: e["ip_address"] for e in l3}["Vlan10"] == "10.10.10.1"
    assert detail["Ethernet1/1"]["mac_address"] == "50:00:00:01:00:07"
    assert "10" in detail["Ethernet1/1"]["speed"]
    assert detail["Ethernet1/1"]["input_errors"] == 3
    assert detail["Ethernet1/1"]["output_errors"] == 1

    macs = drv.get_mac_table(conn)
    assert len(macs) == 2  # sup-eth1(R) filtered
    assert macs[0]["vlan"] == "10"
    assert macs[0]["mac"] == "00:50:56:ab:cd:01"
    assert macs[0]["interface"] == "Eth1/1"
    assert macs[1]["vlan"] == "20"
    assert macs[1]["interface"] == "Po1"

    l2_ops = drv.get_l2_operational(conn)
    assert l2_ops["Eth1/49"]["lag_group"] == "Po1"
    assert l2_ops["Eth1/49"]["lacp_mode"] == "active"


def test_cisco_lldp_non_cisco_xr_mgmt_and_cdp_dedup():
    """DE-07: Non-Cisco LLDP platform, XR Management Address, CDP capabilities, summary caps/Hu, and port-norm dedup."""
    xr_lldp = (
        "Local Interface: TenGigE0/0/0/0\n"
        "Chassis id: 00aa.bbcc.dd01\n"
        "Port id: xe-0/0/0\n"
        "System Name: dist-mx-01\n"
        "System Description:\n"
        "Juniper Networks MX204\n"
        "System Capabilities: B,R\n"
        "Enabled Capabilities: R\n"
        "Management Address: 10.255.0.2\n"
    )
    with patch.object(parser, "get_structured_data", None):
        parsed = parser.parse_lldp_neighbors_detail(xr_lldp)
    assert len(parsed) == 1
    assert parsed[0]["remote_ip"] == "10.255.0.2"
    assert "Juniper Networks MX204" in parsed[0]["platform"]
    assert parsed[0]["device_type"] == "router"

    cdp_mt = (
        "-------------------------\n"
        "Device ID: MikroTik\n"
        "Entry address(es):\n"
        "  IP address: 192.168.1.240\n"
        "Platform: MikroTik,  Capabilities: Router\n"
        "Interface: FastEthernet0,  Port ID (outgoing port): ether1\n"
    )
    with patch.object(parser, "get_structured_data", None):
        cdp_parsed = parser.parse_cdp_neighbors_detail(cdp_mt)
    assert cdp_parsed[0]["device_type"] == "router"

    # Normalized port dedup (GigabitEthernet1/0/5 vs Gi1/0/5) without dropping 2nd peer
    conn = MagicMock()
    conn.send_command.side_effect = [
        (
            "-------------------------\n"
            "Device ID: Aruba-AP-01\n"
            "Platform: Aruba AP-215,  Capabilities: Trans-Bridge\n"
            "Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): eth0\n"
        ),
        (
            "------------------------------------------------\n"
            "Local Intf: Gi1/0/5\n"
            "Chassis id: 40e3.d6c1.2da4\n"
            "Port id: eth0\n"
            "System Name: Aruba-AP-01\n"
            "System Description: ArubaOS (MODEL: 215)\n"
        ),
    ]
    drv = CiscoDriver(ip="10.0.0.1")
    nbrs = drv.get_neighbors(conn)
    assert len(nbrs) == 1
    assert nbrs[0]["remote_mac"] == "40e3.d6c1.2da4"

    # Summary fallback with space in caps, Hu port, wrapped hostname
    conn_sum = MagicMock()
    conn_sum.send_command.return_value = (
        "Device ID           Local Intf     Hold-time  Capability      Port ID\n"
        "Core-SW-01.corp     Gi1/0/1        120        B, R            Gi1/0/24\n"
        "Spine-01            Hu1/0/1        120        B,R             Ethernet1/1\n"
        "VeryLongHostnameSwitchNameThatWraps\n"
        "                    Gi1/0/2        120        B               ge-0/0/1\n"
    )
    summary = drv._parse_lldp_summary_ports(conn_sum)
    assert summary[("core-sw-01", "gi1/0/24")] == "Gi1/0/1"
    assert summary[("spine-01", "ethernet1/1")] == "Hu1/0/1"
    assert summary[("verylonghostnameswitchnameThatwraps".lower(), "ge-0/0/1")] == "Gi1/0/2"


def test_cisco_cat9k_poe_optics_alarms_and_legacy_mac():
    """DE-08: Cat 9300 tabular PoE + per-port draw, optics N/A & ++/-- alarms, and show mac-address-table fallback."""
    drv = CiscoDriver(ip="10.0.0.2")
    conn = MagicMock()
    conn.send_command.return_value = (
        "Module   Available     Used     Remaining\n"
        "          (Watts)     (Watts)    (Watts)\n"
        "------   ---------   --------   ---------\n"
        "1           715.0      120.4       594.6\n"
        "2           715.0       30.0       685.0\n"
        "Interface Admin  Oper       Power   Device              Class Max\n"
        "                            (Watts)\n"
        "--------- ------ ---------- ------- ------------------- ----- ----\n"
        "Gi1/0/1   auto   on         15.4    AIR-AP3802I-B-K9    4     30.0\n"
        "Gi1/0/2   auto   off        0.0     n/a                 n/a   30.0\n"
    )
    poe = drv.get_poe(conn)
    assert poe["poe_supported"] is True
    assert poe["total_power_watts"] == 1430.0
    assert poe["used_power_watts"] == 150.4
    assert poe["available_power_watts"] == 1279.6
    assert poe["ports"]["Gi1/0/1"]["power_watts"] == 15.4
    assert poe["ports"]["Gi1/0/1"]["watts"] == 15.4

    # Non-PoE % Invalid input
    conn_nopoe = MagicMock()
    conn_nopoe.send_command.return_value = "% Invalid input detected at '^' marker.\n"
    assert drv.get_poe(conn_nopoe)["poe_supported"] is False

    # Optics with N/A and ++/-- alarm flags
    conn_opt = MagicMock()
    conn_opt.send_command.side_effect = [
        "",
        (
            "Port       Temp         Volt     Current   Tx Power  Rx Power\n"
            "Te1/0/2      31.0       3.31       N/A      -2.8       N/A\n"
            "Te1/0/3      34.1 ++    3.29      25.0      -2.1      -40.0 --\n"
        ),
    ]
    optics = {o["port"]: o for o in drv.get_optics(conn_opt)}
    assert (
        "Te1/0/2" in optics and optics["Te1/0/2"]["rx_power_dbm"] is None and optics["Te1/0/2"]["tx_power_dbm"] == -2.8
    )
    assert (
        "Te1/0/3" in optics
        and optics["Te1/0/3"]["rx_power_dbm"] == -40.0
        and optics["Te1/0/3"]["temperature_c"] == 34.1
    )

    # Legacy IOS 12.x hyphenated mac-address-table fallback
    conn_mac = MagicMock()
    conn_mac.send_command.side_effect = [
        "% Invalid input detected at '^' marker.\n",
        "   1    0011.2233.4455    DYNAMIC     Fa0/1\n",
    ]
    macs = drv.get_mac_table(conn_mac)
    assert len(macs) == 1 and macs[0]["interface"] == "Fa0/1"


def test_ciscosmb_real_sg350_cbs350_outputs_and_session():
    """DE-12 / DE-13: Real CiscoSMB tabular show system id, vlan 10 SVI/ARP, self MAC filter, LAG ranges, auth_timeout."""
    drv = CiscoSMBDriver(ip="192.168.10.2", username="admin", password="pw", timeout=15)

    # Verify connect sets auth_timeout and doesn't duplicate terminal datadump
    mock_conn = MagicMock()
    with patch.object(drv, "connect_netmiko", return_value=mock_conn) as mock_connect:
        drv.connect()
        params = mock_connect.call_args[0][0]
        assert params["auth_timeout"] == 15
        assert not any(
            call.args and "terminal datadump" in str(call.args[0]) for call in mock_conn.send_command.call_args_list
        )

    conn = MagicMock()
    conn.find_prompt.return_value = "SW-OFFICE-01#"
    responses = {
        "show system": (
            "System Description:                       SG350-28P 28-Port Gigabit PoE Managed Switch\n"
            "System Name:                              SW-OFFICE-01\n"
            "System MAC Address:                       c4:b9:cd:11:22:33\n"
        ),
        "show system id": (
            "Unit  Model       Serial Number  PID VID\n"
            "----  ----------  -------------  -------\n"
            "1     SG350-28P   DNI22010099    V02\n"
        ),
        "show version": ("Active-image: flash://system/images/image1.bin\n  Version: 2.5.9.16\n  MD5 Digest: abc\n"),
        "show ip interface": (
            "IP Address         I/F       Type     Directed   Precedence Status\n"
            "------------------ --------- -------- ---------- ---------- -----------\n"
            "192.168.10.2/24    vlan 10   Static   disable    No         Valid\n"
            "192.168.20.2/24    vlan 20   Static   disable    No         Valid\n"
        ),
        "show interfaces status": (
            "Port      Type         Duplex  Speed Neg      ctrl State       Pressure Mode\n"
            "-------- ------------ ------  ----- -------- ---- ----------- -------- -------\n"
            "gi1/0/1  1G-Copper    Full    1000  Enabled  Off  Up          Disabled Off\n"
            "gi1/0/25 1G-Combo-F     --      --     --     --  Not Present    --     --\n"
            "Po1      1G-Copper    Full    2000  Enabled  Off  Up          Disabled Off\n"
        ),
        "show arp": (
            "VLAN     Interface       IP address        HW address        status\n"
            "-------- --------------- ----------------- ----------------- ---------\n"
            "vlan 10  gi1/0/1         192.168.10.1      00:11:22:33:44:55 dynamic\n"
            "vlan 10  gi1/0/2         192.168.10.50     aa:bb:cc:dd:ee:ff static\n"
        ),
        "show mac address-table": (
            "    Vlan          Mac Address         Port       Type\n"
            "------------ --------------------- ---------- ----------\n"
            "     10        00:11:22:33:44:55    gi1/0/1    dynamic\n"
            "     10        c4:b9:cd:11:22:33       0         self\n"
        ),
        "show interfaces switchport": "",
        "show interfaces port-channel": "Po1      Active: gi1/0/23-24\n",
        "show spanning-tree": (
            "Spanning tree enabled mode RSTP\n"
            "Default port fast mode is disabled\n"
            "Root ID    Priority    32768\n"
            "           Address     c4:b9:cd:11:22:33\n"
            "           This bridge is the root\n"
        ),
    }
    conn.send_command.side_effect = lambda cmd, **_kw: responses.get(cmd, "")

    ver = drv.get_version(conn)
    assert ver["model"] == "SG350-28P"
    assert ver["serial"] == "DNI22010099"
    assert ver["firmware"] == "2.5.9.16"

    l3, detail = drv.get_interfaces(conn)
    assert {e["interface"]: e["ip_address"] for e in l3} == {
        "Vlan10": "192.168.10.2/24",
        "Vlan20": "192.168.20.2/24",
    }
    assert detail["Po1"]["speed"] == "2Gb/s"
    assert detail["gi1/0/25"]["status"] == "down"

    arp = drv.get_arp_table(conn)
    assert len(arp) == 2
    assert arp[0]["ip"] == "192.168.10.1"
    assert arp[0]["interface"] == "Vlan10"

    macs = drv.get_mac_table(conn)
    assert len(macs) == 1  # self/CPU entry filtered
    assert macs[0]["interface"] == "gi1/0/1"

    ops = drv.get_l2_operational(conn)
    assert ops["gi1/0/23"]["lag_group"] == "Po1"
    assert ops["gi1/0/24"]["lag_group"] == "Po1"

    stp = drv.get_stp(conn)
    assert stp["enabled"] is True
    assert stp["is_root"] is True
    assert stp["protocol"] == "RSTP"
    assert stp["root_bridge"] == "c4:b9:cd:11:22:33"

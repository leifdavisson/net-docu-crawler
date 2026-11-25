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

"""Regression tests for ArubaDriver and PaloAltoDriver (DG-06..DG-14, SF-07, SF-08, DG-22)."""

import logging
from unittest.mock import MagicMock, patch

from net_docu_crawler.drivers.aruba import ArubaDriver
from net_docu_crawler.drivers.hpprocurve import _CleanProCurveConn
from net_docu_crawler.drivers.paloalto import PaloAltoDriver

# ---------------------------------------------------------------------------
# ArubaDriver tests (DG-11..DG-14, SF-07, SF-08, DG-22)
# ---------------------------------------------------------------------------


def test_aruba_connect_secret_telnet_guard_and_paging_on_aoscx_and_procurve():
    """DG-11 / SF-07 / SF-08: Pass secret on connect, forbid Telnet, disable paging on AOS-CX & ProCurve delegation."""
    drv = ArubaDriver(ip="192.0.2.20", username="admin", password="pw", secret="en-sec")
    assert drv.supports_telnet is False

    with patch.object(drv, "connect_netmiko", return_value=MagicMock()) as mock_cm:
        drv.connect()
    params = mock_cm.call_args[0][0]
    assert params["device_type"] == "aruba_os"
    assert params["secret"] == "en-sec"

    # AOS-CX detection must issue `no page` so large show commands never hang on --MORE--
    cx_cmds: list[str] = []
    cx_conn = MagicMock()
    cx_conn.find_prompt.return_value = "CX-EDGE-01#"

    def _cx_send(cmd):
        cx_cmds.append(cmd)
        if cmd == "show version":
            return "ArubaOS-CX\nVersion : FL.10.13.1000\n"
        if cmd == "show system":
            return "Hostname : CX-EDGE-01\nProduct Name : JL665A 6300F\nChassis Serial Nbr : SG0001\n"
        return ""

    cx_conn.send_command.side_effect = _cx_send
    drv_cx = ArubaDriver(ip="192.0.2.21")
    drv_cx.get_version(cx_conn)
    assert "no page" in cx_cmds

    # ProCurve delegation must wrap connection in _CleanProCurveConn and send `no page`
    pc_conn = MagicMock()
    pc_conn.send_command.side_effect = lambda cmd: (
        "\x1b[24;1HImage stamp: /ws/swbuildm/rel_ver/code/build/lakes\nWB.16.10.0025\n" if cmd == "show version" else ""
    )
    drv_pc = ArubaDriver(ip="192.0.2.22")
    with patch(
        "net_docu_crawler.drivers.hpprocurve.HPProCurveDriver.crawl", return_value={"hostname": "SW1"}
    ) as mock_c:
        drv_pc.crawl(pc_conn)
    delegated_conn = mock_c.call_args[0][0]
    assert isinstance(delegated_conn, _CleanProCurveConn)
    sent_pc_cmds = [call.args[0] for call in pc_conn.send_command.call_args_list]
    assert "no page" in sent_pc_cmds


def test_aruba_iap_removes_fabricated_gateway_route_and_speed_and_skips_optics():
    """DG-12 / DG-14: IAP never fabricates 'Gateway' route or '1Gb/s Full', and skips unsupported optics query."""
    drv = ArubaDriver(ip="192.0.2.30")
    sent_cmds: list[str] = []
    conn = MagicMock()
    conn.find_prompt.return_value = "Main Lobby AP#"

    def _iap_send(cmd):
        sent_cmds.append(cmd)
        return {
            "show version": "ArubaOS (MODEL: 515), Version 8.10.0.5\n",
            "show aps": (
                "Name            IP Address       Mode    Spectrum  Clients  Type         IPv6 Address  Mesh Role  Zone  Serial #\n"
                "----            ----------       ----    --------  -------  ----         ------------  ---------  ----  --------\n"
                "Main Lobby AP   192.0.2.30*      access  disable   4        515(indoor)  --            N/A        -     CN1234567\n"
            ),
            "show ap debug lldp info": (
                "ap name         interface_name  neighbor_id        remote_interface  mau  power supply  neighbor_vlan  neighbor_basemac   neighbor_hostname  neighbor_capability\n"
                "Main Lobby AP   eth0            fc:33:42:e6:b5:9d  ge-0/0/1               POE-AT                       fc:33:42:e6:b5:99  core-sw.corp.local Bridge, Router\n"
            ),
            "show ip route": "Invalid input detected\n",
            "show clients": "",
            "show configuration": "virtual-controller-ip 192.0.2.30\n",
        }.get(cmd, "")

    conn.send_command.side_effect = _iap_send
    data = drv.crawl(conn)

    # Spaces in AP name preserved properly
    assert data["hostname"] == "Main Lobby AP"
    assert data["serial"] == "CN1234567"
    assert len(data["neighbors"]) == 1
    assert data["neighbors"][0]["remote_device"] == "core-sw"

    # No fabricated "Gateway" route
    assert data["routes"] == []
    assert not any(r.get("next_hop") == "Gateway" for r in data["routes"])

    # No fabricated 1Gb/s Full speed/duplex when port status is unavailable
    assert data["interfaces_detail"]["eth0"]["speed"] == "N/A"
    assert data["interfaces_detail"]["eth0"]["duplex"] == "N/A"

    # IAP must not run unsupported switch transceiver command
    assert "show interface transceiver" not in sent_cmds
    assert data["optics"] == []


def test_aruba_aoscx_interfaces_routes_lldp_stp_mac_poe_and_tabular_optics():
    """DG-13 / DG-14: Real AOS-CX CLI formats parse interfaces, routes, LLDP, STP, MAC, PoE, and tabular optics."""
    drv = ArubaDriver(ip="192.0.2.40")
    conn = MagicMock()
    conn.find_prompt.return_value = "CX-ACCESS-01#"
    conn.send_command.side_effect = lambda cmd: {
        "show version": "ArubaOS-CX\nVersion : FL.10.13.1000\n",
        "show system": (
            "Hostname               : CX-ACCESS-01\n"
            "Product Name           : JL665A 6300F 48G\n"
            "Chassis Serial Nbr     : SG99CX0001\n"
            "Base MAC Address       : 88:3a:30:aa:bb:cc\n"
        ),
        "show ip interface brief": (
            "Interface        IP Address         Status  Admin\n"
            "---------------------------------------------------\n"
            "vlan10           192.0.2.40/24      up      up\n"
            "loopback0        10.255.0.40/32     up      up\n"
        ),
        "show interface brief": (
            "--------------------------------------------------------------------------------------------\n"
            "Port     Native  Mode   Type         Enabled Status  Reason               Speed   Description\n"
            "         VLAN                                                             (Mb/s)\n"
            "--------------------------------------------------------------------------------------------\n"
            "1/1/1    10      access 1GbT         yes     up      --                   1000    AP-Lobby\n"
            "1/1/2    10      access 1GbT         yes     down    Waiting for link     --      --\n"
            "1/1/49   1       trunk  10G-SR       yes     up      --                   10000   Uplink-Core\n"
            "lag1     1       trunk  --           yes     up      --                   20000   Core-LAG\n"
        ),
        "show ip route": (
            "Displaying ipv4 routes selected for forwarding\n"
            "VRF: default\n"
            "Prefix              Nexthop          Interface     VRF(egress)       Origin/   Distance/    Age\n"
            "                                                                     Type      Metric\n"
            "---------------------------------------------------------------------------------------------------\n"
            "0.0.0.0/0           192.0.2.1        vlan10        -                 S         [1/0]        05d:12h\n"
            "192.0.2.0/24        -                vlan10        -                 C         [0/0]        -\n"
            "10.50.0.0/16        192.0.2.2        1/1/49        -                 O/E2      [110/20]     01h:10m\n"
        ),
        "show lldp neighbor-info detail": (
            "LLDP Neighbor Information\n"
            "=========================\n"
            "Port                      : 1/1/49\n"
            "Neighbor Entries          : 1\n"
            "Chassis-ID                : fc:33:42:e6:b5:99\n"
            "Port-ID                   : ge-0/0/1\n"
            "Neighbor System-Name      : CORE-SW-01.corp.local\n"
            "Neighbor System-Description : Juniper Networks EX4300\n"
            "Neighbor Management-Address : 192.0.2.2\n"
            "Neighbor Capabilities     : Bridge, Router\n"
            "Port                      : 1/1/1\n"
            "Chassis-ID                : 40:e3:d6:c1:31:26\n"
            "Port-ID                   : eth0\n"
            "Neighbor System-Name      : AP-Lobby\n"
            "Neighbor Management-Address : 192.0.2.50\n"
            "Neighbor Capabilities     : WLAN Access Point\n"
        ),
        "show spanning-tree": (
            "Spanning tree status : Enabled Protocol: RPVST\n"
            "VLAN10\n"
            "  Root ID    Priority : 4096\n"
            "             MAC-Address: 88:3a:30:aa:bb:cc\n"
            "             This bridge is the root\n"
            "  Bridge ID  Priority : 4096\n"
            "             MAC-Address: 88:3a:30:aa:bb:cc\n"
            "Port         Role           State      Cost       Priority   Type\n"
            "-------------------------------------------------------------------\n"
            "1/1/1        Designated     Forwarding 20000      128        P2P Edge\n"
            "1/1/49       Designated     Forwarding 2000       128        P2P\n"
        ),
        "show mac-address-table": (
            "MAC age-time            : 300 seconds\n"
            "MAC Address          VLAN     Type                      Port\n"
            "-----------------------------------------------------------------\n"
            "40:e3:d6:c1:31:26    10       dynamic                   1/1/1\n"
            "fc:33:42:e6:b5:99    10       dynamic                   1/1/49\n"
        ),
        "show power-over-ethernet brief": (
            "Status and Configuration Information\n"
            "  Available Power      : 740.00 W\n"
            "  Allocated Power      : 28.40 W\n"
            "  Remaining Power      : 711.60 W\n"
            "Port     Power   Priority  OperStatus        Class  Type   Power(W)\n"
            "---------------------------------------------------------------------\n"
            "1/1/1    yes     low       delivering        4      type2  15.20\n"
            "1/1/2    yes     low       searching         -      -      0.00\n"
        ),
        "show interface transceiver": (
            "-----------------------------------------------------------------------------\n"
            "Port      Type        Product      Serial          Part\n"
            "                      Number       Number          Number\n"
            "-----------------------------------------------------------------------------\n"
            "1/1/49    SFP+SR      J9150D       CN99X001        1990-4391\n"
        ),
        "show arp": "192.0.2.1  00:1b:21:aa:bb:cc  vlan10  1/1/49\n",
        "show running-config": "hostname CX-ACCESS-01\n",
    }.get(cmd, "")

    data = drv.crawl(conn)
    assert data["device_persona"] == "switch"
    assert data["interfaces_detail"]["1/1/1"]["status"] == "up"
    assert data["interfaces_detail"]["1/1/1"]["speed"] == "1Gb/s"
    assert data["interfaces_detail"]["1/1/1"]["description"] == "AP-Lobby"
    assert data["interfaces_detail"]["1/1/2"]["status"] == "down"
    assert data["interfaces_detail"]["1/1/49"]["speed"] == "10Gb/s"

    # Routes
    assert len(data["routes"]) == 3
    by_sub = {r["subnet"]: r for r in data["routes"]}
    assert by_sub["0.0.0.0/0"]["next_hop"] == "192.0.2.1"
    assert by_sub["0.0.0.0/0"]["interface"] == "vlan10"
    assert by_sub["0.0.0.0/0"]["protocol"] == "static"
    assert by_sub["192.0.2.0/24"]["next_hop"] == "Direct"
    assert by_sub["192.0.2.0/24"]["protocol"] == "connected"
    assert by_sub["10.50.0.0/16"]["protocol"] == "ospf"

    # LLDP
    assert len(data["neighbors"]) == 2
    n_core = next(n for n in data["neighbors"] if n["local_port"] == "1/1/49")
    assert n_core["remote_device"] == "CORE-SW-01"
    assert n_core["remote_mac"] == "fc:33:42:e6:b5:99"
    assert n_core["remote_ip"] == "192.0.2.2"
    n_ap = next(n for n in data["neighbors"] if n["local_port"] == "1/1/1")
    assert n_ap["device_type"] == "ap"

    # STP, MAC, PoE, Optics
    assert data["stp"]["enabled"] is True
    assert data["stp"]["is_root"] is True
    assert "VLAN10" in data["stp"]["vlans"]
    assert len(data["mac_table"]) == 2
    assert data["mac_table"][0]["port"] == "1/1/1"
    assert data["poe"]["total_power_watts"] == 740.0
    assert data["poe"]["used_power_watts"] == 28.4
    assert data["poe"]["ports"]["1/1/1"]["power_watts"] == 15.2
    assert len(data["optics"]) == 1
    assert data["optics"][0]["port"] == "1/1/49"
    assert data["optics"][0]["part_number"] == "J9150D"
    assert data["optics"][0]["serial"] == "CN99X001"


def test_aruba_unguarded_exceptions_and_cli_error_logging(caplog):
    """DG-14 / DG-22: Transport exceptions in get_version and get_running_config fallback never crash and log warnings."""
    drv = ArubaDriver(ip="192.0.2.45")
    conn = MagicMock()
    conn.send_command.side_effect = RuntimeError("ssh read timeout")
    conn.find_prompt.side_effect = RuntimeError("prompt timeout")

    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.aruba"):
        ver = drv.get_version(conn)
        cfg = drv.get_running_config(conn)
    assert ver["hostname"] == ""
    assert cfg == ""
    assert any("show version" in r.message.lower() for r in caplog.records)
    assert any("show run" in r.message.lower() or "show configuration" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# PaloAltoDriver tests (DG-06..DG-10, DG-22)
# ---------------------------------------------------------------------------


def test_paloalto_real_two_table_interfaces_routes_arp_lldp_and_ha():
    """DG-06..DG-10: Real PAN-OS 2-table interfaces, VR routing table, 6-col ARP, LLDP, HA state, and prompt cleanup."""
    drv = PaloAltoDriver(ip="192.0.2.100")
    assert drv.supports_telnet is False

    conn = MagicMock()
    conn.find_prompt.return_value = "admin@PA-FW01(active)>"
    conn.send_command.side_effect = lambda cmd: {
        "show system info": (
            "model: PA-3220\nserial: 016201000001\nsw-version: 11.1.2\nmac-address: 08:66:1f:aa:bb:00\n"
        ),
        "show interface all": (
            "total configured hardware interfaces: 3\n"
            "\n"
            "name                id    speed/duplex/state        mac address\n"
            "--------------------------------------------------------------------------------\n"
            "ethernet1/1         16    1000/full/up              08:66:1f:aa:bb:01\n"
            "ethernet1/2         17    [n/a]/[n/a]/down          08:66:1f:aa:bb:02\n"
            "ae1                 20    10000/full/up             08:66:1f:aa:bb:10\n"
            "\n"
            "aggregation groups: 1\n"
            "total configured logical interfaces: 5\n"
            "\n"
            "name                id    vsys zone             forwarding               tag    address\n"
            "--------------------------------------------------------------------------------\n"
            "ethernet1/1         16    1    untrust          vr:default               0      198.51.100.2/30\n"
            "ethernet1/1.10      256   1    trust            vr:default               10     10.10.10.1/24\n"
            "ae1.20              257   1    dmz              vr:default               20     10.20.20.1/24\n"
            "loopback.1          258   1    trust            vr:default               0      10.255.0.1/32\n"
            "tunnel.1            259   1    vpn              vr:default               0      169.254.1.1/30\n"
        ),
        "show routing route": (
            "flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp\n"
            "VIRTUAL ROUTER: default (id 1)\n"
            "  ==========\n"
            "destination                                 nexthop                                 metric flags      age   interface          next-AS\n"
            "0.0.0.0/0                                   198.51.100.1                            10     A S              ethernet1/1\n"
            "10.10.10.0/24                               10.10.10.1                              0      A C              ethernet1/1.10\n"
            "10.10.10.1/32                               0.0.0.0                                 0      A H\n"
            "10.30.0.0/16                                10.10.10.2                              20     A Oi       1204  ethernet1/1.10\n"
            "10.40.0.0/16                                198.51.100.5                            0      A B        4320  ethernet1/1        65001\n"
        ),
        "show arp all": (
            "maximum of entries supported :      500\n"
            "status: s - static, c - complete, e - expiring, i - incomplete\n"
            "\n"
            "interface         ip address      hw address        port              status   ttl\n"
            "--------------------------------------------------------------------------------\n"
            "ethernet1/1       198.51.100.1    00:1b:21:aa:bb:cc ethernet1/1         c      1420\n"
            "ethernet1/1.10    10.10.10.50     fc:33:42:e6:b5:99 ethernet1/1         s      -\n"
            "ethernet1/1.10    10.10.10.99     (incomplete)      ethernet1/1         i      10\n"
        ),
        "show lldp neighbors all": (
            "Local Interface: ethernet1/1\n"
            "  Chassis ID: fc:33:42:e6:b5:99\n"
            "  Port ID: ge-0/0/1\n"
            "  System Name: CORE-SW-01.corp.local\n"
            "  System Description: Juniper Networks EX4300\n"
            "  Management Address: 10.10.10.2\n"
            "  System Capabilities: Bridge, Router\n"
        ),
        "show high-availability state": (
            "Group 1:\n"
            "  Mode: Active-Passive\n"
            "  Local Information:\n"
            "    State: active (last 12 days)\n"
            "    Management IP: 192.0.2.100/24\n"
            "  Peer Information:\n"
            "    State: passive\n"
            "    Management IP: 192.0.2.101/24\n"
        ),
        "show config running": "<config><system><hostname>PA-FW01</hostname></system></config>\n",
    }.get(cmd, "")

    data = drv.crawl(conn)

    # Prompt fallback strips HA (active) suffix
    assert data["hostname"] == "PA-FW01"

    # DG-06: HW status/MAC/speed preserved when logical table appears; ae1 & loopback.1 included
    det = data["interfaces_detail"]
    assert det["ethernet1/1"]["status"] == "up"
    assert det["ethernet1/1"]["mac_address"] == "08:66:1f:aa:bb:01"
    assert det["ethernet1/1"]["speed"] == "1Gb/s"
    assert det["ethernet1/1"]["duplex"] == "Full"
    assert det["ethernet1/2"]["status"] == "down"
    assert det["ae1"]["speed"] == "10Gb/s"
    assert det["ethernet1/1.10"]["vlan"] == 10
    assert det["ethernet1/1.10"]["status"] == "up"
    assert "loopback.1" in det
    l3_by_if = {r["interface"]: r for r in data["l3_interfaces"]}
    assert l3_by_if["ethernet1/1"]["ip_address"] == "198.51.100.2/30"
    assert l3_by_if["ae1.20"]["ip_address"] == "10.20.20.1/24"
    assert l3_by_if["loopback.1"]["ip_address"] == "10.255.0.1/32"

    # DG-07: Real routing table parses flags, interface, next_hop, and VRF (not metric as protocol!)
    r_by_sub = {r["subnet"]: r for r in data["routes"]}
    assert r_by_sub["0.0.0.0/0"]["next_hop"] == "198.51.100.1"
    assert r_by_sub["0.0.0.0/0"]["interface"] == "ethernet1/1"
    assert r_by_sub["0.0.0.0/0"]["protocol"] == "A S"
    assert r_by_sub["0.0.0.0/0"]["vrf"] == "default"
    assert r_by_sub["10.10.10.1/32"]["next_hop"] == "Direct"
    assert r_by_sub["10.10.10.1/32"]["interface"] == ""
    assert r_by_sub["10.30.0.0/16"]["interface"] == "ethernet1/1.10"
    assert r_by_sub["10.30.0.0/16"]["protocol"] == "A Oi"
    assert r_by_sub["10.40.0.0/16"]["interface"] == "ethernet1/1"
    assert r_by_sub["10.40.0.0/16"]["protocol"] == "A B"

    # DG-08: Real 6-col ARP drops (incomplete), preserves static & interface
    assert len(data["arp_table"]) == 2
    arp_by_ip = {a["ip"]: a for a in data["arp_table"]}
    assert arp_by_ip["198.51.100.1"]["interface"] == "ethernet1/1"
    assert arp_by_ip["198.51.100.1"]["type"] == "dynamic"
    assert arp_by_ip["10.10.10.50"]["interface"] == "ethernet1/1.10"
    assert arp_by_ip["10.10.10.50"]["type"] == "static"
    assert "10.10.10.99" not in arp_by_ip

    # DG-09: Local Interface + Chassis ID -> remote_mac + FQDN stripped
    assert len(data["neighbors"]) == 1
    assert data["neighbors"][0]["local_port"] == "ethernet1/1"
    assert data["neighbors"][0]["remote_device"] == "CORE-SW-01"
    assert data["neighbors"][0]["remote_mac"] == "fc:33:42:e6:b5:99"
    assert data["neighbors"][0]["remote_ip"] == "10.10.10.2"

    # DG-10: Read-only HA state populated in fhrp
    assert len(data["fhrp"]) == 1
    assert data["fhrp"][0]["protocol"] == "PAN-OS HA"
    assert data["fhrp"][0]["group"] == "1"
    assert data["fhrp"][0]["state"] == "active"
    assert data["fhrp"][0]["peer_ip"] == "192.0.2.101"


def test_paloalto_error_handling_safe_prompt_and_lldp_error_not_enabled(caplog):
    """DG-09 / DG-10 / DG-22: CLI errors log warnings, never false-positive LLDP enabled, and find_prompt is safe."""
    drv = PaloAltoDriver(ip="192.0.2.105")
    conn = MagicMock()
    conn.find_prompt.side_effect = RuntimeError("prompt read failed")
    conn.send_command.side_effect = lambda cmd: {
        "show system info": "Server error : command failed\n",
        "show lldp neighbors all": "Unknown command: lldp\n",
        "show routing route": "Invalid syntax.\n",
    }.get(cmd, "")

    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.paloalto"):
        ver = drv.get_version(conn)
        nbrs = drv.get_neighbors(conn)
        dp = drv.get_discovery_protocols(conn)
        routes = drv.get_routing_table(conn)

    assert ver["hostname"] == ""
    assert nbrs == []
    assert dp["lldp"] == "unknown"
    assert routes == []
    assert any("lldp" in r.message.lower() for r in caplog.records)
    assert any("routing" in r.message.lower() or "route" in r.message.lower() for r in caplog.records)

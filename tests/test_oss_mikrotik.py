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

"""Regression tests for MikroTikDriver parsers, paging safety, and logging."""

import logging
from unittest.mock import MagicMock

from net_docu_crawler.drivers.mikrotik import MikroTikDriver


def test_mikrotik_declares_supports_telnet_false():
    assert MikroTikDriver.supports_telnet is False


def test_mikrotik_commands_use_without_paging_and_are_readonly():
    driver = MikroTikDriver(ip="192.0.2.10")
    sent_commands: list[str] = []

    responses = {
        "/system identity print": "  name: MT-Core-01\n",
        "/system resource print": "  version: 7.16.1 (stable)\n  board-name: RB5009UG+S+\n",
        "/system routerboard print": "  serial-number: HE12345678\n",
        "/interface ethernet print detail without-paging": (
            'Flags: X - disabled, R - running; S - slave\n 0 R  name="ether1" mtu=1500 mac-address=D4:01:C3:11:22:33\n'
        ),
        "/interface print detail without-paging": (
            "Flags: D - dynamic; X - disabled, R - running; S - slave\n"
            ' 0 R  name="ether1" type="ether" mtu=1500 mac-address=D4:01:C3:11:22:33\n'
        ),
        "/ip address print detail without-paging": (
            "Flags: X - disabled, I - invalid, D - dynamic\n"
            " 0    address=192.0.2.10/24 network=192.0.2.0 interface=ether1\n"
        ),
        "/ip neighbor print detail without-paging": (
            " 0 interface=ether1 address4=192.0.2.1 mac-address=FC:33:42:E6:B5:99 "
            'identity="core-sw-01" platform="Juniper" interface-name="ge-0/0/1"\n'
        ),
        "/ip route print detail without-paging": (
            "Flags: D - dynamic; X - disabled, I - inactive, A - active; c - connect, s - static\n"
            " 0 As dst-address=0.0.0.0/0 routing-table=main gateway=192.0.2.1 immediate-gw=192.0.2.1%ether1\n"
        ),
        "/ip arp print detail without-paging": (
            "Flags: X - disabled, I - invalid, D - dynamic; C - complete\n"
            " 0 DC address=192.0.2.1 mac-address=FC:33:42:E6:B5:99 interface=ether1\n"
        ),
        '/interface ethernet monitor [find where name~"sfp"] once': "",
        "/export compact": "# RouterOS export\n/system identity set name=MT-Core-01\n",
    }

    def _send(cmd):
        sent_commands.append(cmd)
        return responses.get(cmd, "")

    conn = MagicMock()
    conn.send_command.side_effect = _send
    data = driver.crawl(conn)

    assert data["hostname"] == "MT-Core-01"
    for expected in (
        "/interface ethernet print detail without-paging",
        "/interface print detail without-paging",
        "/ip address print detail without-paging",
        "/ip neighbor print detail without-paging",
        "/ip route print detail without-paging",
        "/ip arp print detail without-paging",
    ):
        assert expected in sent_commands

    # Zero-blast-radius check: no mutating verbs anywhere in sent commands
    forbidden_verbs = (" set ", " add ", " remove ", " reset", " reboot", " clear ", " import ")
    for cmd in sent_commands:
        low = f" {cmd.lower()} "
        assert not any(v in low for v in forbidden_verbs), f"Write-capable command detected: {cmd}"


def test_mikrotik_unplugged_port_status_and_comments():
    """DO-01: Enabled-but-unplugged ports (no R, no X) MUST be 'down'; comments & MTU parsed."""
    driver = MikroTikDriver(ip="192.0.2.11")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "/interface ethernet print detail without-paging": (
            "Flags: X - disabled, R - running; S - slave\n"
            " 0 R  ;;; Uplink to Juniper Core\n"
            '      name="ether1" default-name="ether1" mtu=1500 mac-address=D4:01:C3:00:00:01\n'
            " 1    ;;; Spare Unplugged Port\n"
            '      name="ether2" default-name="ether2" mtu=1500 mac-address=D4:01:C3:00:00:02\n'
            " 2 X  ;;; Admin Disabled Port\n"
            '      name="ether3" default-name="ether3" mtu=1500 mac-address=D4:01:C3:00:00:03\n'
            ' 3 RS name="ether4" default-name="ether4" mtu=9000 mac-address=D4:01:C3:00:00:04\n'
            ' 4  S name="ether5" default-name="ether5" mtu=1500 mac-address=D4:01:C3:00:00:05\n'
        ),
        "/interface print detail without-paging": "",
        "/ip address print detail without-paging": "",
    }.get(cmd, "")

    _, details = driver.get_interfaces(conn)
    assert details["ether1"]["status"] == "up"
    assert details["ether1"]["description"] == "Uplink to Juniper Core"
    assert details["ether1"]["mtu"] == 1500
    assert details["ether2"]["status"] == "down"
    assert details["ether2"]["description"] == "Spare Unplugged Port"
    assert details["ether3"]["status"] == "down"
    assert details["ether4"]["status"] == "up"
    assert details["ether4"]["mtu"] == 9000
    assert details["ether5"]["status"] == "down"


def test_mikrotik_non_ethernet_interfaces_and_disabled_ips():
    """DO-02: Non-ethernet interfaces harvested, disabled/invalid IPs skipped, primary IP & down status preserved."""
    driver = MikroTikDriver(ip="192.0.2.12")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "/interface ethernet print detail without-paging": (
            "Flags: X - disabled, R - running; S - slave\n"
            ' 0 R  name="ether1" mtu=1500 mac-address=D4:01:C3:10:00:01\n'
            ' 1    name="ether2" mtu=1500 mac-address=D4:01:C3:10:00:02\n'
        ),
        "/interface print detail without-paging": (
            "Flags: D - dynamic; X - disabled, R - running; S - slave\n"
            ' 0 R  name="ether1" type="ether" mtu=1500 mac-address=D4:01:C3:10:00:01\n'
            ' 1    name="ether2" type="ether" mtu=1500 mac-address=D4:01:C3:10:00:02\n'
            " 2 R  ;;; LAN Bridge\n"
            '      name="bridge1" type="bridge" mtu=1500 mac-address=D4:01:C3:10:00:AA\n'
            ' 3 R  name="vlan10" type="vlan" mtu=1500 mac-address=D4:01:C3:10:00:AA\n'
            ' 4 R  name="wg0" type="wg" mtu=1420\n'
            ' 5 X  name="bond-backup" type="bond" mtu=1500 mac-address=D4:01:C3:10:00:BB\n'
        ),
        "/ip address print detail without-paging": (
            "Flags: X - disabled, I - invalid, D - dynamic\n"
            " 0    address=10.0.10.1/24 network=10.0.10.0 interface=vlan10\n"
            " 1    address=10.0.10.2/24 network=10.0.10.0 interface=vlan10\n"
            " 2 X  ;;; Old disabled IP\n"
            "      address=10.99.99.1/24 network=10.99.99.0 interface=ether1\n"
            " 3 I  address=10.88.88.1/24 network=10.88.88.0 interface=ether2\n"
            " 4    address=198.51.100.1/30 network=198.51.100.0 interface=ether2\n"
        ),
    }.get(cmd, "")

    l3, details = driver.get_interfaces(conn)
    assert "bridge1" in details
    assert details["bridge1"]["mac_address"] == "d4:01:c3:10:00:aa"
    assert details["bridge1"]["description"] == "LAN Bridge"
    assert details["bridge1"]["status"] == "up"
    assert "wg0" in details and details["wg0"]["mtu"] == 1420
    assert details["bond-backup"]["status"] == "down"

    # Disabled (X) and invalid (I) IPs must not appear in l3_interfaces
    ips = [e["ip_address"] for e in l3]
    assert "10.99.99.1/24" not in ips
    assert "10.88.88.1/24" not in ips
    assert "10.0.10.1/24" in ips
    assert "10.0.10.2/24" in ips

    # Primary IP preserved (first non-disabled IP, not overwritten by secondary)
    assert details["vlan10"]["ip_address"] == "10.0.10.1/24"
    # Down physical port must NOT be forced "up" merely because it has an IP configured
    assert details["ether2"]["status"] == "down"
    ether2_l3 = [e for e in l3 if e["interface"] == "ether2"][0]
    assert ether2_l3["status"] == "down"


def test_mikrotik_neighbors_remote_mac_lldp_and_address4():
    """DO-03: remote_mac, address4, system-description, system-caps, MAC-only peer, empty identity."""
    driver = MikroTikDriver(ip="192.0.2.13")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "/ip neighbor print detail without-paging": (
            " 0 interface=ether1,bridge1 address=fe80::1 address4=192.0.2.2 "
            'mac-address=FC:33:42:E6:B5:99 identity="junos-sw-01" '
            'system-description="Juniper Networks, Inc. ex2300-c-12p" '
            "system-caps=bridge,router system-caps-enabled=bridge "
            'interface-name="ge-0/0/1"\n'
            ' 1 interface=ether2 mac-address=40:E3:D6:C1:31:26 identity="" '
            "system-caps=wlan-ap,bridge system-caps-enabled=wlan-ap "
            'interface-name="eth0"\n'
        ),
    }.get(cmd, "")

    nbrs = driver.get_neighbors(conn)
    assert len(nbrs) == 2

    n0 = nbrs[0]
    assert n0["local_port"] == "ether1"
    assert n0["remote_device"] == "junos-sw-01"
    assert n0["remote_ip"] == "192.0.2.2"
    assert n0["remote_mac"] == "fc:33:42:e6:b5:99"
    assert "ex2300-c-12p" in n0["platform"]
    assert n0["device_type"] == "switch"

    n1 = nbrs[1]
    assert n1["local_port"] == "ether2"
    assert n1["remote_mac"] == "40:e3:d6:c1:31:26"
    assert n1["remote_device"] != ""
    assert n1["device_type"] == "ap"
    assert n1["platform"] != ""  # OUI fallback when platform & system-description absent


def test_mikrotik_route_comments_ecmp_and_vrf_tables():
    """DO-04: Route ;;; comments must not drop/misclassify routes; ECMP & VRF tables handled."""
    driver = MikroTikDriver(ip="192.0.2.14")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "/ip route print detail without-paging": (
            "Flags: D - dynamic; X - disabled, I - inactive, A - active; "
            "c - connect, s - static, r - rip, b - bgp, o - ospf, i - is-is, d - dhcp, v - vpn; + - ecmp\n"
            " 0 As  ;;; ISP Primary Uplink\n"
            "       dst-address=0.0.0.0/0 routing-table=main gateway=198.51.100.1 immediate-gw=198.51.100.1%ether1\n"
            " 1 As  ;;; corp branch subnet\n"
            "       dst-address=10.20.0.0/16 routing-table=main gateway=10.0.0.2,10.0.0.3 "
            "immediate-gw=10.0.0.2%ether2,10.0.0.3%ether3\n"
            " 2 As  dst-address=0.0.0.0/0 routing-table=vrf-guest gateway=172.16.99.1 "
            "immediate-gw=172.16.99.1%vlan99\n"
            " 3 DAi dst-address=10.50.0.0/16 routing-table=main gateway=10.0.0.4 immediate-gw=10.0.0.4%ether2\n"
            " 4 XI  dst-address=10.99.0.0/16 routing-table=main gateway=10.0.0.9\n"
        ),
    }.get(cmd, "")

    routes = driver.get_routing_table(conn)
    # Route 0 (comment has 'I' in 'ISP') MUST NOT be dropped
    main_defaults = [r for r in routes if r["subnet"] == "0.0.0.0/0" and r.get("vrf", "main") == "main"]
    assert len(main_defaults) == 1
    assert main_defaults[0]["protocol"] == "static"
    assert main_defaults[0]["next_hop"] == "198.51.100.1"
    assert main_defaults[0]["interface"] == "ether1"

    # Route 1 (comment has 'c','o','r' in 'corp') MUST stay static AND expand both ECMP hops cleanly
    corp_routes = [r for r in routes if r["subnet"] == "10.20.0.0/16"]
    assert len(corp_routes) == 2
    assert {(r["protocol"], r["next_hop"], r["interface"]) for r in corp_routes} == {
        ("static", "10.0.0.2", "ether2"),
        ("static", "10.0.0.3", "ether3"),
    }

    # Route 2 in non-main VRF preserved without colliding with main default route
    vrf_defaults = [r for r in routes if r["subnet"] == "0.0.0.0/0" and r.get("vrf") == "vrf-guest"]
    assert len(vrf_defaults) == 1
    assert vrf_defaults[0]["next_hop"] == "172.16.99.1"

    # Route 3 lowercase 'i' (IS-IS) is NOT confused with uppercase 'I' (inactive)
    isis_routes = [r for r in routes if r["subnet"] == "10.50.0.0/16"]
    assert len(isis_routes) == 1
    assert isis_routes[0]["protocol"] == "isis"

    # Route 4 (X/I) excluded
    assert not any(r["subnet"] == "10.99.0.0/16" for r in routes)


def test_mikrotik_arp_flags_multi_sfp_and_crs_persona():
    """DO-06: ARP skips X/I and sets static/dynamic; multi-SFP optics & voltage parsed; CRS -> switch."""
    driver = MikroTikDriver(ip="192.0.2.15")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "/system identity print": "  name: CRS-Access-01\n",
        "/system resource print": "  version: 7.16.1 (stable)\n  board-name: CRS326-24G-2S+\n",
        "/system routerboard print": "  serial-number: CRS-998877\n",
        "/ip arp print detail without-paging": (
            "Flags: X - disabled, I - invalid, H - dhcp, D - dynamic, P - published; C - complete\n"
            " 0 DC address=192.0.2.1 mac-address=FC:33:42:E6:B5:99 interface=bridge1\n"
            " 1    ;;; Static gateway\n"
            "      address=192.0.2.2 mac-address=00:11:22:33:44:55 interface=bridge1\n"
            " 2 X  address=192.0.2.99 mac-address=AA:BB:CC:DD:EE:FF interface=bridge1\n"
        ),
        '/interface ethernet monitor [find where name~"sfp"] once': (
            "                    name: sfp-sfpplus1,sfp-sfpplus2\n"
            "                  status: link-ok,link-ok\n"
            "         sfp-vendor-name: MikroTik,FS\n"
            "  sfp-vendor-part-number: S+85DLC03D,SFP-10GSR-85\n"
            "       sfp-vendor-serial: MT111111,FS222222\n"
            "        sfp-temperature: 42C,38C\n"
            "     sfp-supply-voltage: 3.31V,3.29V\n"
            "           sfp-tx-power: -2.1dBm,-2.4dBm\n"
            "           sfp-rx-power: -3.5dBm,-4.0dBm\n"
        ),
    }.get(cmd, "")

    ver = driver.get_version(conn)
    assert ver["device_persona"] == "switch"
    assert ver["device_type"] == "switch"

    arp = driver.get_arp_table(conn)
    assert len(arp) == 2
    by_ip = {a["ip"]: a for a in arp}
    assert by_ip["192.0.2.1"]["type"] == "dynamic"
    assert by_ip["192.0.2.2"]["type"] == "static"
    assert "192.0.2.99" not in by_ip

    optics = driver.get_optics(conn)
    assert len(optics) == 2
    assert optics[0]["port"] == "sfp-sfpplus1"
    assert optics[0]["serial"] == "MT111111"
    assert optics[0]["temperature_c"] == 42.0
    assert optics[0]["voltage_v"] == 3.31
    assert optics[0]["tx_power_dbm"] == -2.1
    assert optics[0]["rx_power_dbm"] == -3.5
    assert optics[1]["port"] == "sfp-sfpplus2"
    assert optics[1]["vendor"] == "FS"
    assert optics[1]["serial"] == "FS222222"


def test_mikrotik_parse_failures_log_warning(caplog):
    """DO-25: Transport/parse errors emit WARNING logs rather than being hidden at DEBUG."""
    driver = MikroTikDriver(ip="192.0.2.16")
    conn = MagicMock()
    conn.send_command.side_effect = RuntimeError("simulated timeout")

    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.mikrotik"):
        driver.get_interfaces(conn)
        driver.get_neighbors(conn)
        driver.get_routing_table(conn)
        driver.get_arp_table(conn)

    warn_messages = [rec.message for rec in caplog.records if rec.levelno >= logging.WARNING]
    assert len(warn_messages) >= 4

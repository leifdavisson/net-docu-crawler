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

"""Regression tests for OPNsenseDriver data-collection parsers (DO-07..DO-11, DO-25)."""

import json
import logging
from unittest.mock import MagicMock

from net_docu_crawler.drivers.opnsense import OPNsenseDriver

IFCONFIG = (
    "igb0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n"
    "\tdescription: LAN (lan)\n"
    "\tether 00:11:22:33:44:55\n"
    "\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255\n"
    "\tinet 192.0.2.2 netmask 0xffffff00 broadcast 192.0.2.255 vhid 1\n"
    "\tcarp: MASTER vhid 1 advbase 1 advskew 0\n"
    "\tstatus: active\n"
    "igb1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n"
    "\tether 00:11:22:33:44:66\n"
    "\tmedia: Ethernet autoselect (none)\n"
    "\tstatus: no carrier\n"
    "igb0.10: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n"
    "\tdescription: TRUSTED (opt1)\n"
    "\tether 00:11:22:33:44:55\n"
    "\tinet 198.51.100.1 netmask 0xffffff00 broadcast 198.51.100.255\n"
    "\tstatus: active\n"
    "wg-site1: flags=10080c1<UP,RUNNING,NOARP,MULTICAST> metric 0 mtu 1420\n"
    "\tinet 203.0.113.9 netmask 0xffffffff\n"
    "ovpnc1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> metric 0 mtu 1500\n"
    "\tinet 10.8.0.6 --> 10.8.0.5 netmask 0xffffffff\n"
    "gif0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> metric 0 mtu 1280\n"
    "\tinet 10.9.0.1 --> 10.9.0.2\n"
    "lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384\n"
    "\tinet 127.0.0.1 netmask 0xff000000\n"
    "pflog0: flags=0 metric 0 mtu 33152\n"
)


def _conn(mapping: dict[str, str]):
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd, **kwargs: mapping.get(cmd, "")
    return conn


def test_opnsense_dotted_hyphenated_interfaces_p2p_netmask_and_carrier():
    """DO-07 & DO-08: dotted/hyphenated names split correctly; P2P -> /32; no-carrier -> down."""
    driver = OPNsenseDriver(ip="192.0.2.1")
    l3, details = driver.get_interfaces(_conn({"ifconfig -a": IFCONFIG}))

    for name in ("igb0", "igb1", "igb0.10", "wg-site1", "ovpnc1", "gif0"):
        assert name in details, name
    assert "lo0" not in details and "pflog0" not in details

    # Dotted VLAN not merged into parent
    assert details["igb0"]["ip_address"] == "192.0.2.1/24"
    assert details["igb0.10"]["ip_address"] == "198.51.100.1/24"
    assert details["igb0.10"]["description"] == "TRUSTED (opt1)"

    by_if = {(e["interface"], e["ip_address"]) for e in l3}
    assert ("ovpnc1", "10.8.0.6/32") in by_if
    assert ("gif0", "10.9.0.1/32") in by_if
    assert ("wg-site1", "203.0.113.9/32") in by_if

    # Admin-up but unplugged port
    assert details["igb1"]["status"] == "down"
    assert details["igb0"]["status"] == "up"


def test_opnsense_live_carp_get_fhrp_is_readonly_and_parsed():
    """DO-08: CARP state parsed from `ifconfig -a` output with no extra commands."""
    driver = OPNsenseDriver(ip="192.0.2.1")
    conn = _conn({"ifconfig -a": IFCONFIG})
    driver.get_interfaces(conn)
    before = conn.send_command.call_count
    fhrp = driver.get_fhrp(conn)
    assert conn.send_command.call_count == before
    assert len(fhrp) == 1
    assert fhrp[0]["protocol"] == "carp"
    assert fhrp[0]["group"] == "1"
    assert fhrp[0]["interface"] == "igb0"
    assert fhrp[0]["state"] == "MASTER"
    assert fhrp[0]["vip"] == "192.0.2.2/24"
    assert fhrp[0]["priority"] == 0


def test_opnsense_lldpctl_real_json_variants():
    """DO-09: real lldpd JSON (single dict interface, hostname-keyed chassis) populates ip/mac."""
    real = {
        "lldp": {
            "interface": {
                "igb0": {
                    "chassis": {
                        "core-sw": {
                            "id": {"type": "mac", "value": "fc:33:42:e6:b5:99"},
                            "descr": "Juniper Networks EX2300",
                            "mgmt-ip": "192.0.2.3",
                            "capability": [{"type": "Bridge", "enabled": True}],
                        }
                    },
                    "port": {"id": {"type": "ifname", "value": "ge-0/0/1"}},
                }
            }
        }
    }
    driver = OPNsenseDriver(ip="192.0.2.1")
    nbrs = driver.get_neighbors(_conn({"lldpctl -f json 2>/dev/null": json.dumps(real)}))
    assert len(nbrs) == 1
    assert nbrs[0]["local_port"] == "igb0"
    assert nbrs[0]["remote_device"] == "core-sw"
    assert nbrs[0]["remote_port"] == "ge-0/0/1"
    assert nbrs[0]["remote_ip"] == "192.0.2.3"
    assert nbrs[0]["remote_mac"] == "fc:33:42:e6:b5:99"
    assert nbrs[0]["device_type"] == "switch"
    assert driver.get_discovery_protocols(MagicMock())["lldp"] == "enabled"


def test_opnsense_arp_dotted_interface_and_permanent_type():
    """DO-10: ARP interface capture keeps dots/hyphens; permanent -> static."""
    raw = (
        "? (198.51.100.50) at 2e:4d:9d:46:0c:5a on igb0.10 expires in 1159 seconds [vlan]\n"
        "? (198.51.100.1) at 00:11:22:33:44:55 on igb0.10 permanent [vlan]\n"
        "? (203.0.113.5) at 2e:4d:9d:46:0c:5b on wg-site1 expires in 10 seconds [ethernet]\n"
        "? (192.0.2.130) at (incomplete) on igb0 expired [ethernet]\n"
    )
    arp = OPNsenseDriver(ip="192.0.2.1").get_arp_table(_conn({"arp -an": raw}))
    assert len(arp) == 3
    by_ip = {a["ip"]: a for a in arp}
    assert by_ip["198.51.100.50"]["interface"] == "igb0.10"
    assert by_ip["198.51.100.50"]["type"] == "dynamic"
    assert by_ip["198.51.100.1"]["type"] == "static"
    assert by_ip["203.0.113.5"]["interface"] == "wg-site1"


def test_opnsense_routing_flags_host_routes_and_smbios_placeholders():
    """DO-11: non-static gateways != connected; bare host IPs get /32; placeholder serials rejected."""
    netstat = (
        "Internet:\n"
        "Destination        Gateway            Flags   Nhop#    Mtu            Netif Expire\n"
        "default            198.51.100.254     UGS        14   1500           igb1\n"
        "10.50.0.0/16       192.0.2.77         UG          5   1500           igb0\n"
        "192.0.2.0/24       link#1             U          10   1500           igb0\n"
        "192.0.2.200        00:11:22:33:44:77  UHS        11   1500           igb0\n"
        "198.51.100.10      192.0.2.9          UGH         6   1500           igb0\n"
    )
    driver = OPNsenseDriver(ip="192.0.2.1")
    routes = driver.get_routing_table(_conn({"netstat -rnW -f inet": netstat}))
    by_sub = {r["subnet"]: r for r in routes}
    assert by_sub["0.0.0.0/0"]["protocol"] == "static"
    assert by_sub["10.50.0.0/16"]["protocol"] == "dynamic"
    assert by_sub["192.0.2.0/24"]["protocol"] == "connected"
    assert "198.51.100.10/32" in by_sub
    assert by_sub["198.51.100.10/32"]["protocol"] == "dynamic"
    assert by_sub["192.0.2.200/32"]["protocol"] == "connected"

    ver = driver.get_version(
        _conn(
            {
                "hostname": "fw\n",
                "kenv smbios.system.serial 2>/dev/null": "To be filled by O.E.M.\n",
                "kenv smbios.system.product 2>/dev/null": "Box\n",
            }
        )
    )
    assert ver["serial"] == "Unknown"


def test_opnsense_parse_failures_log_warning(caplog):
    """DO-25: corrupt lldp JSON and command failures are visible at WARNING."""
    driver = OPNsenseDriver(ip="192.0.2.1")
    bad = _conn({"lldpctl -f json 2>/dev/null": "{not json"})
    failing = MagicMock()
    failing.send_command.side_effect = RuntimeError("boom")

    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.opnsense"):
        driver.get_neighbors(bad)
        driver.get_arp_table(failing)
        driver.get_version(failing)
        driver.get_fhrp(failing)

    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) >= 4


def test_opnsense_commands_remain_readonly():
    forbidden = (" set ", "configctl", "pfctl -f", "reboot", "service ", "rm ", "write", "clear")
    sent: list[str] = []
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd, **kw: sent.append(cmd) or ""
    OPNsenseDriver(ip="192.0.2.1").crawl(conn)
    assert sent
    for cmd in sent:
        low = f" {cmd.lower()} "
        assert not any(bad in low for bad in forbidden), cmd

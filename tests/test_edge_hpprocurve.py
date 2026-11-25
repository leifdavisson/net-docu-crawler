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

"""Regression tests for HPProCurveDriver (DG-15..DG-22)."""

import logging
from unittest.mock import MagicMock

from net_docu_crawler.drivers.hpprocurve import HPProCurveDriver


def test_hpprocurve_multi_neighbor_lldp_detail_no_overwrite_and_all_fallback():
    """DG-15: Multi-neighbor port does not overwrite detail, extracts mgmt IP/descr/caps, falls back to 'all'."""
    drv = HPProCurveDriver(ip="192.0.2.60")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "show lldp info remote-device": (
            " LLDP Remote Devices Information\n"
            "\n"
            "  LocalPort | ChassisId          PortId             PortDescr SysName\n"
            "  --------- + ------------------ ------------------ --------- ------------------\n"
            "  A1        | 00 0f d3 0a ae 38  eth0               PhonePort d65-phone01\n"
            "  A1        | 50 9a 4c 41 d8 c8  50 9a 4c 41 d8 c8            WORKSTATION-01\n"
            "  A2        | 40 e3 d6 c1 31 26  eth0               Uplink    AP-Gym-LongNam...\n"
        ),
        "show lldp info remote-device detail": "Module not present for port or invalid port: detail\n",
        "show lldp info remote-device all": (
            " LLDP Remote Device Information Detail\n"
            "\n"
            "  Local Port   : A1\n"
            "  ChassisType  : mac-address\n"
            "  ChassisId    : 00 0f d3 0a ae 38\n"
            "  PortType     : local\n"
            "  PortId       : eth0\n"
            "  SysName      : d65-phone01.corp.local\n"
            "  System Descr : Digium D65 IP Phone\n"
            "  PortDescr    : PhonePort\n"
            "  System Capabilities Supported  : bridge, telephone\n"
            "  System Capabilities Enabled    : bridge, telephone\n"
            "  Remote Management Address\n"
            "     Type    : ipv4\n"
            "     Address : 192.0.2.81\n"
            "\n"
            "  Local Port   : A1\n"
            "  ChassisType  : mac-address\n"
            "  ChassisId    : 50 9a 4c 41 d8 c8\n"
            "  PortType     : mac-address\n"
            "  PortId       : 50 9a 4c 41 d8 c8\n"
            "  SysName      : WORKSTATION-01.corp.local\n"
            "  System Descr : Windows 11 Workstation\n"
            "  Remote Management Address\n"
            "     Type    : ipv4\n"
            "     Address : 192.0.2.82\n"
            "\n"
            "  Local Port   : A2\n"
            "  ChassisType  : mac-address\n"
            "  ChassisId    : 40 e3 d6 c1 31 26\n"
            "  PortType     : interface-name\n"
            "  PortId       : eth0\n"
            "  SysName      : AP-Gym-LongName-North.corp.local\n"
            "  System Descr : Aruba Instant AP-515\n"
            "  System Capabilities Enabled    : wlan-access-point\n"
            "  Remote Management Address\n"
            "     Type    : ipv4\n"
            "     Address : 192.0.2.90\n"
        ),
        "show cdp neighbor detail": "",
    }.get(cmd, "")

    nbrs = drv.get_neighbors(conn)
    assert len(nbrs) == 3

    a1_nbrs = {n["remote_mac"]: n for n in nbrs if n["local_port"] == "A1"}
    assert len(a1_nbrs) == 2
    assert a1_nbrs["00:0f:d3:0a:ae:38"]["remote_device"] == "d65-phone01"
    assert a1_nbrs["00:0f:d3:0a:ae:38"]["remote_ip"] == "192.0.2.81"
    assert a1_nbrs["00:0f:d3:0a:ae:38"]["device_type"] == "phone"
    assert a1_nbrs["50:9a:4c:41:d8:c8"]["remote_device"] == "WORKSTATION-01"
    assert a1_nbrs["50:9a:4c:41:d8:c8"]["remote_ip"] == "192.0.2.82"

    a2 = next(n for n in nbrs if n["local_port"] == "A2")
    assert a2["remote_device"] == "AP-Gym-LongName-North"
    assert a2["remote_ip"] == "192.0.2.90"
    assert a2["device_type"] == "ap"
    assert "Aruba Instant" in a2["platform"]


def test_hpprocurve_cdp_supplements_and_deduplicates_lldp():
    """DG-16: CDP runs alongside LLDP, enriching matching LLDP neighbors and appending CDP-only peers."""
    drv = HPProCurveDriver(ip="192.0.2.61")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "show lldp info remote-device": (
            " LLDP Remote Devices Information\n"
            "  LocalPort | ChassisId          PortId             PortDescr SysName\n"
            "  --------- + ------------------ ------------------ --------- ------------------\n"
            "  23        | fc 33 42 e6 b5 99  ge-0/0/1                     CORE-SW-01\n"
        ),
        "show lldp info remote-device detail": "",
        "show lldp info remote-device all": "",
        "show cdp neighbor detail": (
            " CDP neighbors information\n"
            "\n"
            "  Port : 23\n"
            "  Device ID : CORE-SW-01.corp.local\n"
            "  Address Type : IP\n"
            "  Address : 192.0.2.2\n"
            "  Platform : Juniper EX4300\n"
            "  Device Port : ge-0/0/1\n"
            "\n"
            "  Port : 12\n"
            "  Device ID : CISCO-LEGACY-SW\n"
            "  Address Type : IP\n"
            "  Address : 192.0.2.70\n"
            "  Platform : cisco WS-C2960G-24TC-L\n"
            "  Device Port : GigabitEthernet0/24\n"
        ),
    }.get(cmd, "")

    nbrs = drv.get_neighbors(conn)
    assert len(nbrs) == 2
    p23 = next(n for n in nbrs if n["local_port"] == "23")
    assert p23["remote_device"] == "CORE-SW-01"
    assert p23["remote_ip"] == "192.0.2.2"
    p12 = next(n for n in nbrs if n["local_port"] == "12")
    assert p12["remote_device"] == "CISCO-LEGACY-SW"
    assert p12["remote_ip"] == "192.0.2.70"
    assert p12["remote_port"] == "GigabitEthernet0/24"


def test_hpprocurve_l2_operational_vlan_detail_and_kv_stp_detail():
    """DG-17: Prefer 'show vlans ports all detail' with real Provision header and parse KV 'show spanning-tree detail'."""
    drv = HPProCurveDriver(ip="192.0.2.62")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "show trunks": "  A23 | 10GbE-T | Trk1 LACP\n  A24 | 10GbE-T | Trk1 LACP\n",
        "show lacp": "  A23   Trk1   Active   Up\n",
        "show vlans ports all detail": (
            " Status and Counters - VLAN Information - for ports Trk1\n"
            "\n"
            "  VLAN ID Name                             | Status     Voice Jumbo Mode\n"
            "  ------- -------------------------------- + ---------- ----- ----- --------\n"
            "  1       DEFAULT_VLAN                     | Port-based No    No    Untagged\n"
            "  10      DATA                             | Port-based No    No    Tagged\n"
            "  20      VOICE                            | Port-based Yes   No    Tagged\n"
            "\n"
            " Status and Counters - VLAN Information - for ports A1\n"
            "\n"
            "  VLAN ID Name                             | Status     Voice Jumbo Mode\n"
            "  ------- -------------------------------- + ---------- ----- ----- --------\n"
            "  10      DATA                             | Port-based No    No    Untagged\n"
        ),
        "show spanning-tree detail": (
            " Status and Counters - CST Port(s) Detailed Information\n"
            "\n"
            "  Port                     : A1\n"
            "  Status                   : Up\n"
            "  BPDU Protection          : Yes\n"
            "  BPDU Filtering           : No\n"
            "  AdminEdgePort            : Yes\n"
            "  OperEdgePort             : Yes\n"
            "  Port State               : Forwarding\n"
            "  Port Role                : Designated\n"
            "\n"
            "  Port                     : Trk1\n"
            "  Status                   : Up\n"
            "  BPDU Protection          : No\n"
            "  AdminEdgePort            : No\n"
            "  OperEdgePort             : No\n"
            "  Port State               : Forwarding\n"
            "  Port Role                : Root\n"
        ),
    }.get(cmd, "")

    ops = drv.get_l2_operational(conn)
    assert ops["Trk1"]["oper_mode"] == "trunk"
    assert ops["Trk1"]["native_vlan"] == "1"
    assert ops["Trk1"]["trunk_active_vlans"] == "1,10,20"
    assert ops["Trk1"]["stp_state"] == "Forwarding"
    assert ops["Trk1"]["stp_role"] == "Root"
    assert ops["Trk1"]["bpdu_guard"] is False
    assert ops["A1"]["oper_mode"] == "access"
    assert ops["A1"]["access_vlan"] == "10"
    assert ops["A1"]["bpdu_guard"] is True
    assert ops["A1"]["portfast"] is True
    assert ops["A1"]["stp_state"] == "Forwarding"
    assert ops["A23"]["lag_group"] == "Trk1"


def test_hpprocurve_poe_nonpipe_wb16_and_modular_5412zl_budget_fallback():
    """DG-18: Parse WB.16.10 non-pipe PoE rows, 5412zl per-module budgets, and 'show power-over-ethernet' fallback."""
    drv = HPProCurveDriver(ip="192.0.2.63")

    # Case 1: WB.16.10 non-pipe PoE table
    wb_conn = MagicMock()
    wb_conn.send_command.side_effect = lambda cmd: {
        "show power-over-ethernet brief": (
            " Status and Counters - PoE Power Status\n"
            "  Available: 370 W  Used: 18.4 W  Remaining: 351.6 W\n"
            "  PoE   | Power  Power   Pre-std Alloc Alloc  Actual Configured  Detection       Power\n"
            "  Port  | Enable Priority Detect  By    Power  Power  Type        Status          Class\n"
            "  ----- + ------ -------- ------- ----- ------ ------ ----------- --------------- -----\n"
            "  1       Yes    low      off     usage 17 W   8.4 W              Delivering      4\n"
            "  2       Yes    low      off     usage 17 W   10.0 W             Delivering      3\n"
            "  3       Yes    low      off     usage 17 W   0.0 W              Searching       0\n"
        )
    }.get(cmd, "")
    poe_wb = drv.get_poe(wb_conn)
    assert poe_wb["total_power_watts"] == 370.0
    assert poe_wb["poe_delivering_ports"] == 2
    assert poe_wb["ports"]["1"]["draw_watts"] == 8.4
    assert poe_wb["ports"]["1"]["status"] == "delivering"
    assert poe_wb["ports"]["3"]["status"] == "searching"

    # Case 2: 5412zl modular per-module Power headers + chassis summary from `show power-over-ethernet`
    zl_conn = MagicMock()
    zl_conn.send_command.side_effect = lambda cmd: {
        "show power-over-ethernet brief": (
            " Status and Counters - PoE Power Status\n"
            "  Module A Power\n"
            "    Available: 300 W  Used: 95 W  Remaining: 205 W\n"
            "  A1    | Yes    low      off     usage 17 W   12.5 W             Delivering      4\n"
            "  Module B Power\n"
            "    Available: 300 W  Used: 40 W  Remaining: 260 W\n"
            "  B1    | Yes    low      off     usage 17 W   15.0 W             Delivering      4\n"
        ),
        "show power-over-ethernet": (
            " Status and Counters - System Power Status\n"
            "  Total Available Power : 1500 W\n"
            "  Total Power Drawn     : 135 W\n"
        ),
    }.get(cmd, "")
    poe_zl = drv.get_poe(zl_conn)
    assert poe_zl["total_power_watts"] == 1500.0
    assert poe_zl["used_power_watts"] == 135.0
    assert poe_zl["available_power_watts"] == 1365.0
    assert "A" in poe_zl["module_budgets"]
    assert poe_zl["module_budgets"]["A"]["total_power_watts"] == 300.0
    assert poe_zl["module_budgets"]["B"]["used_power_watts"] == 40.0
    assert poe_zl["ports"]["A1"]["draw_watts"] == 12.5


def test_hpprocurve_stp_flexible_spacing_force_version_cost_port_and_table():
    """DG-19: Flexible STP Enabled spacing, Force Version protocol, CST Root Path Cost/Port, and per-port table."""
    drv = HPProCurveDriver(ip="192.0.2.64")
    conn = MagicMock()
    conn.send_command.return_value = (
        " Multiple Spanning Tree (MST) Information\n"
        "\n"
        "  STP Enabled : Yes\n"
        "  Force Version : RSTP-operation\n"
        "  Switch MAC Address : 3863bb-57ca40\n"
        "  Switch Priority : 32768\n"
        "  CST Root MAC Address : 001b21-112233\n"
        "  CST Root Path Cost : 20000\n"
        "  CST Root Port : Trk1\n"
        "\n"
        "  Port  | Type       | Cost      | Priority | State       | Designated Bridge\n"
        "  ----- + ---------- + --------- + -------- + ----------- + -----------------\n"
        "  A1    | 100/1000T  | 20000     | 128      | Forwarding  | 3863bb-57ca40\n"
        "  Trk1  |            | 10000     | 128      | Forwarding  | 001b21-112233\n"
    )
    stp = drv.get_stp(conn)
    assert stp["enabled"] is True
    assert stp["is_root"] is False
    assert stp["protocol"] == "RSTP"
    assert stp["root_cost"] == "20000"
    assert stp["root_port"] == "Trk1"
    assert "CST" in stp["vlans"]
    assert stp["vlans"]["CST"]["ports"]["A1"]["state"] == "Forwarding"
    assert stp["vlans"]["CST"]["ports"]["Trk1"]["cost"] == 10000


def test_hpprocurve_empty_sfp_cages_trk_ports_3col_arp_default_gw_and_logging(caplog):
    """DG-20 / DG-21 / DG-22: Empty SFP cages, -Trk1/stacked ports, 3-col ARP, Default GW fallback, version fallback, warnings."""
    drv = HPProCurveDriver(ip="192.0.2.65")
    conn = MagicMock()
    conn.find_prompt.return_value = "IDF-2530-01#"
    conn.send_command.side_effect = lambda cmd: {
        "show system": "  System Name : IDF-2530-01\n  Serial Number : CN67G2K099\n",
        "show modules": "Invalid input: modules\n",
        "show version": "Image stamp: /ws/swbuildm/rel_ver/code/build/lakes\n  YA.16.02.0014\n",
        "show ip": (
            " Internet (IP) Service\n"
            "  IP Routing : Disabled\n"
            "  Default Gateway : 192.0.2.1\n"
            "  VLAN         | IP Config  IP Address      Subnet Mask\n"
            "  ------------ + ---------- --------------- ---------------\n"
            "  DEFAULT_VLAN | Manual     192.0.2.65      255.255.255.0\n"
        ),
        "show name": (
            " Status and Counters - Port Alias Information\n"
            "  Port  Type       Name\n"
            "  ----- ---------- ------------------------------\n"
            "  1     100/1000T  Uplink-Trunk-1\n"
            "  A4               Spare-SFP-Cage\n"
            "  2/A1  10GbE-SR   Stack-Uplink\n"
        ),
        "show interfaces brief": (
            " Status and Counters - Port Status\n"
            "  Port         Type       | Alert     Enabled Status Mode       Mode Ctrl Limit\n"
            "  ------------ ---------- + --------- ------- ------ ---------- ---- ---- -----\n"
            "  1-Trk1       100/1000T  | No        Yes     Up     1000FDx    Auto off  0\n"
            "  A4                      | No        Yes     Down   1000FDx    NA   off  0\n"
            "  2/A1         10GbE-SR   | No        Yes     Up     10GigFD    NA   off  0\n"
            "  1/1/1        100/1000T  | No        Yes     Up     1000FDx    Auto off  0\n"
        ),
        "show ip route": "Invalid input: route\n",
        "show arp": (
            " IP ARP table\n"
            "  IP Address       MAC Address       Type\n"
            "  ---------------  ----------------- -------\n"
            "  192.0.2.1        001b21-aabbcc     dynamic\n"
            "  192.0.2.2        000000-000000     dynamic\n"
        ),
        "show interfaces transceiver": (
            " Port    Type        Product Number  Serial Number  Part Number\n"
            " 2/A1    10GbE-SR    J9150A          CN00112233     1990-3657\n"
            " 1/1/49  10GbE-LR    J9151A          CN00112244     1990-3658\n"
        ),
    }.get(cmd, "")

    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.hpprocurve"):
        ver = drv.get_version(conn)
        l3, detail = drv.get_interfaces(conn)
        routes = drv.get_routing_table(conn)
        arp = drv.get_arp_table(conn)
        optics = drv.get_optics(conn)

    # DG-21: show version fallback supplies firmware when show system omits it
    assert ver["firmware"] == "YA.16.02.0014"

    # DG-20: Empty SFP cage A4, -Trk1 port, stacked 2/A1 and 1/1/1 all parsed with descriptions
    assert "1-Trk1" in detail
    assert detail["1-Trk1"]["description"] == "Uplink-Trunk-1"
    assert "A4" in detail
    assert detail["A4"]["status"] == "down"
    assert detail["A4"]["description"] == "Spare-SFP-Cage"
    assert "2/A1" in detail
    assert detail["2/A1"]["speed"] == "10Gb/s"
    assert "1/1/1" in detail
    assert len(l3) == 1

    # DG-21: L2-only switch falls back to Default Gateway from `show ip`
    assert len(routes) == 1
    assert routes[0]["subnet"] == "0.0.0.0/0"
    assert routes[0]["next_hop"] == "192.0.2.1"

    # DG-21: 3-column ARP parses without Port column and drops 000000-000000
    assert len(arp) == 1
    assert arp[0]["ip"] == "192.0.2.1"
    assert arp[0]["mac"] == "00:1b:21:aa:bb:cc"

    # DG-20: Optics handles 2/A1 and 1/1/49 port names
    assert {o["port"] for o in optics} == {"2/A1", "1/1/49"}

    # DG-22: CLI errors emitted warnings
    assert any("invalid input" in r.message.lower() or "show ip route" in r.message.lower() for r in caplog.records)

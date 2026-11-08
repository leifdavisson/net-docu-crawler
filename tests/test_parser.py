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

import parser


def test_clean_cli_output():
    raw = "\r\nLine 1\r\nLine 2\x1b[2K\rLine 3\n"
    cleaned = parser.clean_cli_output(raw)
    assert "Line 1" in cleaned
    assert "\x1b[2K" not in cleaned


def test_parse_show_version_ios():
    output = """
Cisco IOS Software, C3850 Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.5b, RELEASE SOFTWARE (fc2)
cisco WS-C3850-24T (MIPS) processor with 4194304K/1048576K bytes of memory.
Processor board ID FDO12345678
Switch uptime is 12 weeks, 3 days, 4 hours
Base ethernet MAC Address: 00:1a:a1:b2:c3:04
Switch-Core#
    """
    res = parser.parse_show_version(output, "cisco_ios")
    assert res["firmware"] == "16.12.5b"
    assert res["model"] == "WS-C3850-24T"
    assert res["serial"] == "FDO12345678"


def test_parse_show_inventory():
    output = """
NAME: "c3850 Chassis", DESCR: "Cisco Catalyst 3850-24T"
PID: WS-C3850-24T      , VID: V01  , SN: FDO12345678

NAME: "Switch 1 - Power Supply A", DESCR: "Power Supply"
PID: PWR-C1-350WAC     , VID: V01  , SN: LIT87654321
    """
    items = parser.parse_show_inventory(output)
    assert len(items) == 2
    assert items[0]["name"] == "c3850 Chassis"
    assert items[0]["pid"] == "WS-C3850-24T"
    assert items[0]["sn"] == "FDO12345678"
    assert items[1]["pid"] == "PWR-C1-350WAC"


def test_parse_ip_interface_brief():
    output = """
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1/0/1   unassigned      YES unset  up                    up
GigabitEthernet1/0/2   unassigned      YES unset  down                  down
Vlan10                 192.168.10.1    YES NVRAM  up                    up
Loopback0              10.255.255.1    YES manual up                    up
    """
    ints = parser.parse_ip_interface_brief(output, "cisco_ios")
    assert len(ints) == 4
    vlan10 = next(i for i in ints if i["interface"] == "Vlan10")
    assert vlan10["ip_address"] == "192.168.10.1"
    assert vlan10["status"] == "up"


def test_parse_show_interfaces():
    output = """
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 001a.a1b2.c301 (bia 001a.a1b2.c301)
  Description: Uplink to Core
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
GigabitEthernet1/0/2 is administratively down, line protocol is down
  Hardware is Gigabit Ethernet, address is 001a.a1b2.c302 (bia 001a.a1b2.c302)
  Auto-duplex, Auto-speed, media type is 10/100/1000BaseTX
    """
    details = parser.parse_show_interfaces(output, "cisco_ios")
    assert "GigabitEthernet1/0/1" in details
    int1 = details["GigabitEthernet1/0/1"]
    assert int1["description"] == "Uplink to Core"
    assert "1000Mb/s" in int1["speed"] or "1Gb/s" in int1["speed"]


def test_parse_cdp_neighbors_detail():
    output = """
-------------------------
Device ID: Core-Switch.domain.local
Entry address(es):
  IP address: 192.168.1.1
Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
    """
    neighbors = parser.parse_cdp_neighbors_detail(output)
    assert len(neighbors) == 1
    assert neighbors[0]["remote_device"] == "Core-Switch"
    assert neighbors[0]["remote_ip"] == "192.168.1.1"
    assert neighbors[0]["local_port"] == "GigabitEthernet1/0/1"
    assert neighbors[0]["remote_port"] == "GigabitEthernet1/0/24"


def test_parse_lldp_neighbors_detail():
    output = """
------------------------------------------------
Chassis id: 001a.a1b2.c305
Port id: Gi1/0/1
Port Description: Uplink
System Name: Dist-Switch-01
System Description: Cisco IOS Software
Management Addresses:
    IP: 192.168.1.5
Time to live: 120 sec
    """
    neighbors = parser.parse_lldp_neighbors_detail(output)
    assert len(neighbors) >= 1
    assert any(n.get("remote_device") == "Dist-Switch-01" or n.get("remote_ip") == "192.168.1.5" for n in neighbors)


def test_parse_spanning_tree():
    output = """
VLAN0010
  Spanning tree enabled protocol rstp
  Root ID    Priority    32778
             Address     001a.a1b2.c301
             This bridge is the root
  Bridge ID  Priority    32778
             Address     001a.a1b2.c301
Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------
Gi1/0/1             Desg FWD 4         128.1    P2p
Gi1/0/2             Desg BLK 4         128.2    P2p
    """
    stp = parser.parse_spanning_tree(output, "cisco_ios")
    assert stp.get("is_root") is True
    vlans = stp.get("vlans", {})
    assert "0010" in vlans or "10" in vlans


def test_parse_services():
    config = """
!
ip domain-name enterprise.local
ip name-server 8.8.8.8 8.8.4.4
ntp server pool.ntp.org
radius-server host 10.0.0.50
tacacs-server host 10.0.0.60
!
    """
    services = parser.parse_services(config)
    assert "8.8.8.8" in services["dns_servers"]
    assert "pool.ntp.org" in services["ntp_servers"]
    assert "10.0.0.50" in services["radius_servers"]
    assert "10.0.0.60" in services["tacacs_servers"]


def test_parse_show_ip_arp():
    arp_output = """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.1.1             -   001a.a1b2.c301  ARPA   Vlan1
Internet  192.168.1.50            5   001a.a144.5566  ARPA   Vlan1
Internet  192.168.1.254          12   001b.17aa.bbcc  ARPA   Vlan1
    """
    entries = parser.parse_show_ip_arp(arp_output)
    assert len(entries) == 3
    assert entries[0]["ip"] == "192.168.1.1"
    assert entries[0]["mac"] == "00:1A:A1:B2:C3:01"
    assert entries[2]["ip"] == "192.168.1.254"
    assert entries[2]["mac"] == "00:1B:17:AA:BB:CC"


def test_parse_mac_address_table():
    mac_output = """
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
   1    001a.a1b2.c301    DYNAMIC     Gi1/0/1
  10    001b.17aa.bbcc    DYNAMIC     Gi1/0/2
Total Mac Addresses for this module: 2
    """
    entries = parser.parse_mac_address_table(mac_output)
    assert len(entries) == 2
    assert entries[0]["vlan"] == "1"
    assert entries[0]["mac"] == "00:1A:A1:B2:C3:01"
    assert entries[0]["port"] == "Gi1/0/1"
    assert entries[1]["vlan"] == "10"
    assert entries[1]["mac"] == "00:1B:17:AA:BB:CC"


def test_classify_device_type():
    assert parser.classify_device_type(platform="AIR-AP3802I-B-K9") == "ap"
    assert parser.classify_device_type(device_id="AP-Floor1") == "ap"
    assert parser.classify_device_type(platform="AIR-CT5520-K9") == "wlc"
    assert parser.classify_device_type(description="Palo Alto Networks") == "firewall"
    assert parser.classify_device_type(platform="Fortinet FortiGate") == "firewall"
    assert parser.classify_device_type(platform="ISR4431/K9") == "router"
    assert parser.classify_device_type(platform="WS-C3850-24T") == "switch"

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

from unittest.mock import MagicMock, patch

from net_docu_crawler.drivers import (
    DRIVER_REGISTRY,
    DRIVER_VENDOR_MAP,
    CiscoDriver,
    CiscoXRDriver,
    resolve_driver_for_vendor,
)


def _xr_mock_conn():
    conn = MagicMock()
    conn.find_prompt.return_value = "RP/0/0/CPU0:core-xr-01#"

    responses = {
        "show version": (
            "Cisco IOS XR Software, Version 7.9.2\n"
            "Copyright (c) 2013-2023 by Cisco Systems, Inc.\n"
            "cisco ASR9K () processor\n"
            "System uptime is 4 weeks, 2 days\n"
        ),
        "show inventory": (
            'NAME: "Rack 0-Chassis", DESCR: "ASR 9006 4-slot Chassis"\n'
            "PID: ASR-9006-AC, VID: V02, SN: FOX1901ABCD\n\n"
            'NAME: "TenGigE0/0/0/0", DESCR: "Cisco SFP+ 10GBASE-LR"\n'
            "PID: SFP-10G-LR, VID: V01, SN: OPM22011234\n"
        ),
        "show ipv4 interface brief": (
            "Interface                      IP-Address      Status          Protocol Vrf-Name\n"
            "Loopback0                      10.255.0.1      Up              Up       default\n"
            "Bundle-Ether1                  10.10.0.1       Up              Up       default\n"
            "TenGigE0/0/0/0                 unassigned      Up              Up       default\n"
        ),
        "show interfaces": (
            "Loopback0 is up, line protocol is up\n"
            "  Internet address is 10.255.0.1/32\n"
            "Bundle-Ether1 is up, line protocol is up\n"
            "  Hardware is Aggregated Ethernet interface(s), address is 0011.2233.4400\n"
            "  Internet address is 10.10.0.1/30\n"
            "  MTU 9216 bytes, BW 20000000 Kbit\n"
            "TenGigE0/0/0/0 is up, line protocol is up\n"
            "  Hardware is TenGigE, address is 0011.2233.4401\n"
            "  MTU 9216 bytes, BW 10000000 Kbit\n"
        ),
        "show lldp neighbors detail": (
            "Local Interface: TenGigE0/0/0/0\n"
            "Chassis id: 00aa.bbcc.dd01\n"
            "Port id: xe-0/0/0\n"
            "System Name: dist-mx-01\n"
            "System Description: Juniper Networks MX204\n"
            "Management Address: 10.255.0.2\n"
        ),
        "show cdp neighbors detail": "% CDP is not enabled\n",
        "show route": (
            "C    10.10.0.0/30 is directly connected, 4w2d, Bundle-Ether1\n"
            "L    10.10.0.1/32 is directly connected, 4w2d, Bundle-Ether1\n"
            "B    10.255.0.2/32 [200/0] via 10.10.0.2, 2w1d\n"
        ),
        "show arp": (
            "-------------------------------------------------------------------------------\n"
            "0/0/CPU0\n"
            "-------------------------------------------------------------------------------\n"
            "Address         Age        Hardware Addr   State      Type  Interface\n"
            "10.10.0.2       00:05:12   00aa.bbcc.dd02  Dynamic    ARPA  Bundle-Ether1\n"
        ),
        "show hsrp summary": (
            "Interface   Grp  Prio P State   Active addr     Standby addr    Group addr\n"
            "Bundle-Ether1 10 110  P Active  local           10.10.0.3       10.10.0.254\n"
        ),
        "show vrrp summary": "% Invalid input detected at '^' marker.\n",
        "show bundle": (
            "Bundle-Ether1\n"
            "  Status: Up\n"
            "  Local links <active/standby/configured>: 1 / 0 / 1\n"
            "    Port                  State           Port ID         B/W, kbps\n"
            "    TenGigE0/0/0/0        Active          0x8000, 0x0001  10000000\n"
        ),
        "show bgp all all summary": (
            "VRF: default\n"
            "Address Family: IPv4 Unicast\n"
            "Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd\n"
            "10.255.0.2        0 65001   12345   12340      100    0    0     2w1d        420\n"
            "VRF: CORP_MPLS\n"
            "Address Family: VPNv4 Unicast\n"
            "Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd\n"
            "10.20.0.2         0 65100     500     502       20    0    0     1d04h        18\n"
        ),
        "show ospf neighbor": "10.255.0.2   1   FULL/  -   00:00:35   10.10.0.2   Bundle-Ether1\n",
        "show isis neighbors": "",
        "show vrf all detail": (
            "VRF CORP_MPLS; RD 65001:100; VPN ID not set\n"
            "  Interfaces:\n"
            "    Bundle-Ether1.100\n"
            "  Address family IPV4 Unicast\n"
            "    Import VPN route-target communities:\n"
            "      RT:65001:100\n"
            "    Export VPN route-target communities:\n"
            "      RT:65001:100\n"
        ),
        "show mpls ldp neighbor brief": (
            "Peer ID          GR  NSR Up Time     Discovery   Addresses  Labels\n"
            "10.255.0.2:0     N   N   2w1d        1           4          128\n"
        ),
        "show mpls ldp interface": "Bundle-Ether1                 Enabled      default\n",
        "show mpls forwarding-table": (
            "Local  Outgoing    Prefix             Outgoing     Next Hop        Bytes\n"
            "24001  Pop         10.255.0.2/32      BE1          10.10.0.2       987654\n"
        ),
        "show running-config": (
            "hostname core-xr-01\n"
            "lldp\n"
            "vrf CORP_MPLS\n"
            " address-family ipv4 unicast\n"
            "  import route-target\n"
            "   65001:100\n"
            "!\n"
        ),
    }
    conn.send_command.side_effect = lambda cmd, **_kw: responses.get(cmd, "")
    return conn


def test_cisco_xr_driver_registered():
    assert DRIVER_REGISTRY["cisco_xr"] is CiscoXRDriver
    assert DRIVER_REGISTRY["iosxr"] is CiscoXRDriver
    assert DRIVER_VENDOR_MAP[CiscoXRDriver] == "cisco_xr"
    assert resolve_driver_for_vendor("cisco_xr") is CiscoXRDriver


def test_cisco_driver_delegates_to_cisco_xr_driver():
    conn = _xr_mock_conn()
    drv = CiscoDriver(ip="10.255.0.1", username="admin", password="pw")
    data = drv.crawl(conn)

    assert data["os_type"] == "cisco_xr"
    assert data["device_persona"] == "router"
    assert data["model"] == "ASR-9006-AC"
    assert data["serial"] == "FOX1901ABCD"
    assert data["hostname"] == "core-xr-01"


def test_cisco_xr_full_telemetry_crawl():
    conn = _xr_mock_conn()
    drv = CiscoXRDriver(ip="10.255.0.1", username="admin", password="pw")
    data = drv.crawl(conn)

    # L3 interfaces with CIDR backfill
    ips = {e["interface"]: e["ip_address"] for e in data["l3_interfaces"]}
    assert ips["Loopback0"] == "10.255.0.1/32"
    assert ips["Bundle-Ether1"] == "10.10.0.1/30"

    # ARP & Neighbors
    assert len(data["arp_table"]) == 1
    assert data["arp_table"][0]["mac_address"] == "00:aa:bb:cc:dd:02"
    assert data["neighbors"][0]["remote_device"] == "dist-mx-01"
    assert data["discovery_protocols"]["lldp"] == "enabled"
    assert data["discovery_protocols"]["cdp"] == "disabled"

    # FHRP & Bundle-Ether L2 operational
    assert data["fhrp"][0]["protocol"] == "HSRP"
    assert data["fhrp"][0]["vip"] == "10.10.0.254"
    assert data["port_profiles"]["TenGigE0/0/0/0"]["lag_id"] == "Bundle-Ether1"

    # Optics
    assert len(data["optics"]) == 1
    assert data["optics"][0]["part_number"] == "SFP-10G-LR"

    # BGP/OSPF peers, VRFs, and MPLS/LDP
    bgp_peers = [p for p in data["routing_peers"] if p["protocol"] == "bgp"]
    assert len(bgp_peers) == 2
    assert bgp_peers[0]["prefixes_received"] == 420
    assert bgp_peers[1]["vrf"] == "CORP_MPLS"

    assert len(data["vrfs"]) == 1
    assert data["vrfs"][0]["name"] == "CORP_MPLS"
    assert data["vrfs"][0]["rd"] == "65001:100"
    assert "Bundle-Ether1.100" in data["vrfs"][0]["interfaces"]

    assert len(data["mpls"]["ldp_neighbors"]) == 1
    assert data["mpls"]["ldp_neighbors"][0]["peer_id"] == "10.255.0.2:0"
    assert data["mpls"]["ldp_interfaces"][0]["status"] == "enabled"
    assert data["mpls"]["forwarding"][0]["local_label"] == "24001"


def test_cisco_xr_netconf_and_gnmi_graceful_fallback():
    drv = CiscoXRDriver(ip="10.255.0.1", username="admin", password="pw", use_netconf=True, use_gnmi=True)
    with patch.dict("sys.modules", {"ncclient": None, "pygnmi": None, "pygnmi.client": None}):
        assert drv.fetch_netconf_operational() == ""
        assert drv.fetch_gnmi_operational() == {}

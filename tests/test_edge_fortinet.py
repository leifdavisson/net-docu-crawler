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

"""Regression tests for FortinetDriver (DG-01..DG-05, SF-01, SF-09, DG-22)."""

import logging
from unittest.mock import MagicMock, patch

import pytest
from netmiko.exceptions import ReadTimeout

from net_docu_crawler.drivers.fortinet import FortinetDriver


class _FakeFortiChannel:
    """In-memory channel simulating interactive FortiOS output with --More-- paging."""

    def __init__(self, script: dict[str, list[str]], banner_chunks: list[str] | None = None):
        self.script = script
        self.queue: list[str] = list(banner_chunks or ["FortiGate-60F # "])
        self.writes: list[str] = []
        self._pending_pages: list[str] = []

    def write_channel(self, data: str) -> None:
        self.writes.append(data)
        cmd = data.strip()
        if data == " ":
            # Pager scroll key: next page already queued if scripted, or pull next from active pages
            if self._pending_pages:
                self.queue.append(self._pending_pages.pop(0))
            return
        if data == "q":
            self._pending_pages = []
            self.queue.append("\r         \rFortiGate-60F # ")
            return
        if cmd == "a":
            self.queue.append("\nFortiGate-60F # ")
            return
        if cmd in self.script:
            pages = list(self.script[cmd])
            self._pending_pages = pages[1:]
            self.queue.append(pages[0])
        elif cmd == "exit":
            self.queue.append("")
        else:
            self.queue.append("\nFortiGate-60F # ")

    def read_channel(self) -> str:
        if self.queue:
            return self.queue.pop(0)
        return ""

    def clear_buffer(self) -> str:
        drained = "".join(self.queue)
        self.queue.clear()
        return drained


def _build_readonly_conn(script: dict[str, list[str]], banner_chunks: list[str] | None = None):
    from net_docu_crawler.drivers.fortinet import ReadOnlyFortinetSSH

    conn = ReadOnlyFortinetSSH.__new__(ReadOnlyFortinetSSH)
    fake_ch = _FakeFortiChannel(script, banner_chunks=banner_chunks)
    conn.channel = fake_ch
    conn.RETURN = "\n"
    conn.RESPONSE_RETURN = "\n"
    conn.base_prompt = "FortiGate-60F"
    conn.ansi_escape_codes = False
    conn.disable_lf_normalization = False
    conn.session_log = None
    conn._read_buffer = ""
    conn.global_delay_factor = 1.0
    conn.read_timeout_override = None
    conn.fast_cli = False
    conn.host = "192.0.2.10"
    conn._session_log_fin = False
    conn.write_channel = fake_ch.write_channel
    conn.read_channel = fake_ch.read_channel
    conn.clear_buffer = fake_ch.clear_buffer
    return conn, fake_ch


def test_fortinet_zero_blast_radius_paging_cmd_and_supports_telnet():
    """DG-01 / SF-01: FortinetDriver must never declare config-write paging_cmd and must reject Telnet."""
    drv = FortinetDriver(ip="192.0.2.10")
    assert drv.paging_cmd == ""
    assert "config system console" not in drv.paging_cmd.lower()
    assert drv.supports_telnet is False


def test_readonly_fortinet_ssh_blocks_writes_and_preserves_kex():
    """DG-01 / SF-01 / SF-09: ReadOnlyFortinetSSH never writes config, hard-blocks write APIs, preserves KEX."""
    from net_docu_crawler.drivers.fortinet import FORTINET_READONLY_DEVICE_TYPE, ReadOnlyFortinetSSH

    conn, fake_ch = _build_readonly_conn(
        script={},
        banner_chunks=["Press 'a' to accept banner: ", "FortiGate-60F # "],
    )
    # Mock _test_channel_read and set_base_prompt to verify session_preparation sequence
    reads = ["Press 'a' to accept", "FortiGate-60F # "]
    conn._test_channel_read = MagicMock(side_effect=reads)
    conn.set_base_prompt = MagicMock(return_value="FortiGate-60F")

    conn.session_preparation()
    assert fake_ch.writes == ["a\r"]

    # disable_paging is a strict no-op
    assert conn.disable_paging() == ""
    assert fake_ch.writes == ["a\r"]

    # cleanup sends ONLY exit (no config system console / set output more / end)
    conn.cleanup()
    assert fake_ch.writes == ["a\r", "exit\n"]
    joined_writes = "\n".join(fake_ch.writes).lower()
    assert "config system console" not in joined_writes
    assert "set output" not in joined_writes
    assert "config global" not in joined_writes

    # Hard-blocked write APIs raise RuntimeError
    for method, args in [
        ("config_mode", ()),
        ("send_config_set", (["set hostname bad"],)),
        ("send_config_from_file", ("bad.cfg",)),
        ("save_config", ()),
        ("_config_global", ()),
        ("_exit_config_global", ()),
    ]:
        with pytest.raises(RuntimeError, match="Zero-Blast-Radius"):
            getattr(conn, method)(*args)

    # send_command also rejects write-capable commands (single-line and newline-chained)
    with pytest.raises(RuntimeError, match="Zero-Blast-Radius"):
        conn.send_command("config system console")
    with pytest.raises(RuntimeError, match="Zero-Blast-Radius"):
        conn.send_command("get system status\nconfig system console")

    # __init__ must NOT strip modern KEX algorithms when disabled_algorithms={}
    captured_kwargs: dict = {}

    def _fake_parent_init(self_obj, *args, **kwargs):
        captured_kwargs.update(kwargs)

    with patch("netmiko.cisco_base_connection.CiscoSSHConnection.__init__", _fake_parent_init):
        ReadOnlyFortinetSSH(host="192.0.2.10", username="ro", password="pw", disabled_algorithms={})
    assert captured_kwargs.get("disabled_algorithms") == {}

    # FortinetDriver.connect() requests FORTINET_READONLY_DEVICE_TYPE
    drv = FortinetDriver(ip="192.0.2.10", username="ro", password="pw")
    with patch.object(drv, "connect_netmiko", return_value=conn) as mock_cm:
        drv.connect()
    assert mock_cm.call_args[0][0]["device_type"] == FORTINET_READONLY_DEVICE_TYPE


def test_readonly_fortinet_ssh_drains_more_pager_and_enforces_bounds():
    """DG-01 / SF-01: Bounded --More-- pager drains multi-page output cleanly and enforces max_pages & timeout."""
    conn, fake_ch = _build_readonly_conn(
        script={
            "get system status": [
                "get system status\nVersion: FortiGate-60F v7.4.9\n--More-- ",
                "\r         \rSerial-Number: FGT60F0000000001\n--More-- ",
                "\r         \rHostname: FG-Edge-01\nFortiGate-60F # ",
            ]
        }
    )
    out = conn.send_command("get system status")
    assert "Version: FortiGate-60F v7.4.9" in out
    assert "Serial-Number: FGT60F0000000001" in out
    assert "Hostname: FG-Edge-01" in out
    assert "--More--" not in out
    assert "FortiGate-60F #" not in out
    assert fake_ch.writes == ["get system status\n", " ", " "]

    # max_pages cap terminates cleanly with 'q'
    conn2, fake_ch2 = _build_readonly_conn(
        script={
            "show full-configuration": [
                "show full-configuration\nline 1\n--More-- ",
                "\r         \rline 2\n--More-- ",
                "\r         \rline 3\n--More-- ",
                "\r         \rline 4\nFortiGate-60F # ",
            ]
        }
    )
    out2 = conn2.send_command("show full-configuration", max_pages=1)
    assert "line 1" in out2
    assert "line 2" in out2
    assert "line 3" not in out2
    assert "q" in fake_ch2.writes

    # Stall timeout raises ReadTimeout cleanly
    conn3, _ = _build_readonly_conn(script={"get system status": ["get system status\npartial output"]})
    with pytest.raises(ReadTimeout):
        conn3.send_command("get system status", read_timeout=0.05, poll_interval=0.01)


def test_fortinet_lldprx_details_mac_ip_oui_and_cli_error_logging(caplog):
    """DG-02 / DG-22: FortiOS 7.x diagnose lldprx neighbor details extracts remote_mac/remote_ip/device_type and logs errors."""
    drv = FortinetDriver(ip="192.0.2.10")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "diagnose lldprx neighbor details": (
            "VDOM: root, Port: port1\n"
            "  Chassis ID: 40:e3:d6:c1:31:26\n"
            "  System Name: AP-Lobby.corp.local\n"
            "  Port ID: eth0\n"
            "  Port Description: Uplink\n"
            "  Management Address: 192.0.2.50\n"
            "  System Capabilities: Bridge, WLAN Access Point\n"
            "VDOM: root, Port: port2\n"
            "  Chassis ID: fc:33:42:e6:b5:99\n"
            "  System Name: CORE-SW-01\n"
            "  Port ID: ge-0/0/1\n"
            "  System Description: Juniper Networks EX2300\n"
            "  Management Address: 192.0.2.3\n"
        ),
    }.get(cmd, "command parse error before 'x'\nCommand fail. Return code -61\n")

    nbrs = drv.get_neighbors(conn)
    assert len(nbrs) == 2
    assert nbrs[0]["local_port"] == "port1"
    assert nbrs[0]["remote_device"] == "AP-Lobby"
    assert nbrs[0]["remote_mac"] == "40:e3:d6:c1:31:26"
    assert nbrs[0]["remote_ip"] == "192.0.2.50"
    assert nbrs[0]["device_type"] == "ap"
    assert nbrs[1]["local_port"] == "port2"
    assert nbrs[1]["remote_mac"] == "fc:33:42:e6:b5:99"
    assert nbrs[1]["remote_ip"] == "192.0.2.3"
    assert nbrs[1]["device_type"] == "switch"

    # When all LLDP commands fail (like live FortiOS 7.4.9 log), log warning instead of silent swallow
    err_conn = MagicMock()
    err_conn.send_command.return_value = "ambiguous command before 'lldp'\nCommand fail. Return code -7\n"
    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.fortinet"):
        assert drv.get_neighbors(err_conn) == []
    assert any("lldp" in rec.message.lower() for rec in caplog.records)


def test_fortinet_operational_interfaces_mac_link_speed_and_dhcp():
    """DG-03: Combine show system interface with get system interface + physical for real link, MAC, speed, DHCP."""
    drv = FortinetDriver(ip="192.0.2.10")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "show system interface": (
            "config system interface\n"
            '    edit "port1"\n'
            "        set mode dhcp\n"
            '        set alias "WAN-ISP"\n'
            "        set type physical\n"
            "    next\n"
            '    edit "port2"\n'
            "        set ip 192.0.2.10 255.255.255.0\n"
            "        set type physical\n"
            "    next\n"
            '    edit "port3"\n'
            "        set type physical\n"
            "    next\n"
            '    edit "naf.root"\n'
            "        set type tunnel\n"
            "    next\n"
            "end\n"
        ),
        "get system interface": (
            "== [ port1 ]\n"
            "name: port1   mode: dhcp    ip: 198.51.100.2 255.255.255.252   status: up    type: physical\n"
            "== [ port2 ]\n"
            "name: port2   mode: static    ip: 192.0.2.10 255.255.255.0   status: up    type: physical\n"
            "== [ port3 ]\n"
            "name: port3   mode: static    ip: 0.0.0.0 0.0.0.0   status: up    type: physical\n"
        ),
        "get system interface physical": (
            "== [onboard]\n"
            "    ==[port1]\n"
            "        mode: dhcp\n"
            "        ip: 198.51.100.2 255.255.255.252\n"
            "        status: up\n"
            "        speed: 1000full (Duplex: full)\n"
            "        mac: 00:09:0f:11:22:31\n"
            "    ==[port2]\n"
            "        mode: static\n"
            "        ip: 192.0.2.10 255.255.255.0\n"
            "        status: up\n"
            "        speed: 10000full (Duplex: full)\n"
            "        mac: 00:09:0f:11:22:32\n"
            "    ==[port3]\n"
            "        mode: static\n"
            "        ip: 0.0.0.0 0.0.0.0\n"
            "        status: down\n"
            "        speed: n/a (Duplex: n/a)\n"
            "        mac: 00:09:0f:11:22:33\n"
        ),
    }.get(cmd, "")

    l3, detail = drv.get_interfaces(conn)
    l3_by_if = {row["interface"]: row for row in l3}
    assert "port1" in l3_by_if
    assert l3_by_if["port1"]["ip_address"] == "198.51.100.2 255.255.255.252"
    assert "port2" in l3_by_if
    assert "naf.root" not in detail
    assert detail["port1"]["mac_address"] == "00:09:0f:11:22:31"
    assert detail["port1"]["speed"] == "1Gb/s"
    assert detail["port1"]["duplex"] == "Full"
    assert detail["port1"]["description"] == "WAN-ISP"
    assert detail["port2"]["speed"] == "10Gb/s"
    # Unplugged port3 is operationally down, not falsely up
    assert detail["port3"]["status"] == "down"
    assert detail["port3"]["protocol"] == "down"
    assert detail["port3"]["mac_address"] == "00:09:0f:11:22:33"


def test_fortinet_routing_ecmp_ipsec_recursive_uptime_and_vrf():
    """DG-04: Parse ECMP continuations, IPsec directly-connected static routes, >24h uptime, recursive BGP, and VRF."""
    drv = FortinetDriver(ip="192.0.2.10")
    conn = MagicMock()
    conn.send_command.return_value = (
        "Routing table for VRF=0\n"
        "S*      0.0.0.0/0 [10/0] via 198.51.100.1, wan1, [1/0]\n"
        "                  [10/0] via 203.0.113.1, wan2, [1/0]\n"
        "S       10.20.0.0/16 [10/0] is directly connected, vpn-branch1\n"
        "O       10.30.0.0/24 [110/20] via 192.0.2.2, port1, 2d04h15m\n"
        "B       10.40.0.0/24 [20/0] via 192.0.2.3 (recursive is directly connected, port1), 01w2d03h\n"
        "C       192.0.2.0/24 is directly connected, port1\n"
        "Routing table for VRF=1\n"
        "S       172.16.0.0/16 [10/0] via 172.16.0.1, Guest LAN, 00:15:30, [1/0]\n"
    )
    routes = drv.get_routing_table(conn)
    assert len(routes) == 7

    defaults = [r for r in routes if r["subnet"] == "0.0.0.0/0"]
    assert len(defaults) == 2
    assert {(r["next_hop"], r["interface"], r["protocol"]) for r in defaults} == {
        ("198.51.100.1", "wan1", "S*"),
        ("203.0.113.1", "wan2", "S*"),
    }

    ipsec = next(r for r in routes if r["subnet"] == "10.20.0.0/16")
    assert ipsec["next_hop"] == "Direct"
    assert ipsec["interface"] == "vpn-branch1"
    assert ipsec["protocol"] == "S"

    ospf = next(r for r in routes if r["subnet"] == "10.30.0.0/24")
    assert ospf["interface"] == "port1"
    assert "2d04h15m" not in ospf["interface"]

    bgp = next(r for r in routes if r["subnet"] == "10.40.0.0/24")
    assert bgp["next_hop"] == "192.0.2.3"
    assert bgp["interface"] == "port1"

    vrf1 = next(r for r in routes if r["subnet"] == "172.16.0.0/16")
    assert vrf1["interface"] == "Guest LAN"
    assert vrf1["vrf"] == "1"


def test_fortinet_arp_static_dash_discovery_fortilink_and_safe_prompt():
    """DG-05: Static ARP '-' age parsed cleanly; fortilink alone does not false-positive LLDP; safe find_prompt."""
    drv = FortinetDriver(ip="192.0.2.10")
    conn = MagicMock()
    conn.send_command.side_effect = lambda cmd: {
        "get system status": "command fail\n",
        "get system arp": (
            "Address           Age(min)   Hardware Addr      Interface\n"
            "192.0.2.1         0          bc:24:11:b4:a9:82  port1\n"
            "192.0.2.2         -          fc:33:42:e6:b5:99  GS VoIP\n"
            "192.0.2.3         0          00:00:00:00:00:00  port1\n"
        ),
    }.get(cmd, "")
    conn.find_prompt.side_effect = RuntimeError("timeout")

    # find_prompt failure must not crash get_version
    ver = drv.get_version(conn)
    assert ver["hostname"] == ""

    # Static ARP with '-' age parses MAC & multi-word interface properly, drops 00:00:00:00:00:00
    arp = drv.get_arp_table(conn)
    assert len(arp) == 2
    static_entry = next(a for a in arp if a["ip"] == "192.0.2.2")
    assert static_entry["mac"] == "fc:33:42:e6:b5:99"
    assert static_entry["interface"] == "GS VoIP"
    assert static_entry["age"] == "-"
    assert static_entry["type"] == "static"

    # Default fortilink interface LLDP does not false-positive when global LLDP is disabled
    fg_cfg = (
        "config system global\n"
        "    set lldp-reception disable\n"
        "    set lldp-transmission disable\n"
        "end\n"
        "config system interface\n"
        '    edit "port1"\n'
        "        set type physical\n"
        "    next\n"
        '    edit "fortilink"\n'
        "        set fortilink enable\n"
        "        set lldp-reception enable\n"
        "        set lldp-transmission enable\n"
        "    next\n"
        "end\n"
    )
    dp = drv.get_discovery_protocols(conn, raw_config=fg_cfg, neighbors=[])
    assert dp["lldp"] == "disabled"


def test_fortinet_optics_dom_and_cli_error_logging(caplog):
    """DG-05 / DG-22: Parse DOM telemetry on hardware FortiGate and log warning on VM CLI error."""
    drv = FortinetDriver(ip="192.0.2.10")
    hw_conn = MagicMock()
    hw_conn.send_command.return_value = (
        "Interface port5 - SFP/SFP+\n"
        "  Vendor Name          : FINISAR CORP.\n"
        "  Part No.             : FTLX8574D3BCL\n"
        "  Serial No.           : FNS20010001\n"
        "  Temperature          : 38.5 C\n"
        "  Voltage              : 3.31 V\n"
        "  Optical Tx Power     : -2.4 dBm\n"
        "  Optical Rx Power     : -3.1 dBm\n"
    )
    optics = drv.get_optics(hw_conn)
    assert len(optics) == 1
    assert optics[0]["port"] == "port5"
    assert optics[0]["vendor"] == "FINISAR CORP."
    assert optics[0]["part_number"] == "FTLX8574D3BCL"
    assert optics[0]["temperature_c"] == 38.5
    assert optics[0]["voltage_v"] == 3.31
    assert optics[0]["tx_power_dbm"] == -2.4
    assert optics[0]["rx_power_dbm"] == -3.1

    vm_conn = MagicMock()
    vm_conn.send_command.return_value = "command parse error before 'transceiver'\nCommand fail. Return code -61\n"
    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.fortinet"):
        assert drv.get_optics(vm_conn) == []
    assert any("transceiver" in rec.message.lower() for rec in caplog.records)

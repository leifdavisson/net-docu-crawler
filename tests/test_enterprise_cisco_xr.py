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

"""Regression tests for CiscoXRDriver schema alignment, parsers, and NETCONF/gNMI safety."""

import logging
import sys
import types
from unittest.mock import MagicMock

from net_docu_crawler.drivers.cisco_xr import (
    CiscoXRDriver,
    _parse_xr_arp_line,
    _parse_xr_bgp_summary,
)


def test_cisco_xr_arp_canonical_and_compat_keys():
    """DE-09: XR ARP entries must emit canonical 'ip'/'mac' (plus compat keys) for topology/reports."""
    row = "10.10.0.2       00:05:12   00aa.bbcc.dd02  Dynamic    ARPA  Bundle-Ether1"
    parsed = _parse_xr_arp_line(row)
    assert parsed is not None
    assert parsed["ip"] == "10.10.0.2"
    assert parsed["mac"] == "00:aa:bb:cc:dd:02"
    assert parsed["ip_address"] == "10.10.0.2"
    assert parsed["mac_address"] == "00:aa:bb:cc:dd:02"
    assert parsed["interface"] == "Bundle-Ether1"
    assert parsed["age"] == "00:05:12"
    assert parsed["type"] == "dynamic"


def test_cisco_xr_bgp_remote_as_idle_admin_and_ipv6():
    """DE-10: XR BGP emits remote_as, preserves Idle (Admin) state & uptime, and parses IPv6 peers."""
    raw = (
        "VRF: default\n"
        "Address Family: IPv4 Unicast\n"
        "Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd\n"
        "10.255.0.2        0 65001   12345   12340      100    0    0     2w1d        420\n"
        "10.255.0.3        0 65002       0       0        0    0    0    never Idle (Admin)\n"
        "Address Family: IPv6 Unicast\n"
        "Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd\n"
        "2001:db8::2       0 65001     100     100       50    0    0    1d01h         50\n"
    )
    peers = _parse_xr_bgp_summary(raw)
    assert len(peers) == 3
    by_ip = {p["neighbor_ip"]: p for p in peers}

    assert by_ip["10.255.0.2"]["remote_as"] == "65001"
    assert by_ip["10.255.0.2"]["asn"] == "65001"
    assert by_ip["10.255.0.2"]["state"] == "Established"
    assert by_ip["10.255.0.2"]["prefixes_received"] == 420

    assert by_ip["10.255.0.3"]["remote_as"] == "65002"
    assert by_ip["10.255.0.3"]["uptime"] == "never"
    assert by_ip["10.255.0.3"]["state"] == "Idle (Admin)"

    assert by_ip["2001:db8::2"]["remote_as"] == "65001"
    assert by_ip["2001:db8::2"]["prefixes_received"] == 50


def test_cisco_xr_ospf_isis_bundle_and_optics():
    """DE-10: Accurate OSPF state, IS-IS System-ID parsing, bundle lag_group + 400G/25G, optics type & inventory cache."""
    drv = CiscoXRDriver(ip="10.255.0.1")
    conn = MagicMock()
    responses = {
        "show bgp all all summary": "",
        "show bgp vrf all summary": "",
        "show ospf neighbor": (
            "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
            "10.255.0.2        1   EXSTART/DR      00:00:35    10.10.0.2       Bundle-Ether1\n"
            "10.255.0.3        1   FULL/  -        00:00:35    10.10.0.3       TenGigE0/0/0/1\n"
        ),
        "show isis neighbors": (
            "System Id      Interface        SNPA           State Holdtime Type IETF-NSF\n"
            "core-xr-02     TenGigE0/0/0/0   *PtoP*         Up    27       L2   Capable\n"
        ),
        "show bundle": (
            "Bundle-Ether10\n"
            "  Status: Up\n"
            "    Port                     State           Port ID         B/W, kbps\n"
            "    TwentyFiveGigE0/0/0/1    Active          0x8000, 0x0001  25000000\n"
            "    FourHundredGigE0/0/0/2   Standby         0x8000, 0x0002  400000000\n"
        ),
        "show inventory": (
            'NAME: "TenGigE0/0/0/0", DESCR: "Cisco SFP+ 10GBASE-LR"\nPID: SFP-10G-LR, VID: V01, SN: OPM22011234\n'
        ),
    }
    conn.send_command.side_effect = lambda cmd, **_kw: responses.get(cmd, "")

    peers = drv.get_routing_peers(conn)
    ospf = {p["neighbor_ip"]: p for p in peers if p["protocol"] == "ospf"}
    assert ospf["10.10.0.2"]["state"].upper().startswith("EXSTART")
    assert ospf["10.10.0.3"]["state"].upper().startswith("FULL")
    assert ospf["10.10.0.3"]["interface"] == "TenGigE0/0/0/1"

    isis = [p for p in peers if p["protocol"] == "isis"]
    assert len(isis) == 1
    assert isis[0]["neighbor_ip"] == "core-xr-02"
    assert isis[0]["interface"] == "TenGigE0/0/0/0"
    assert isis[0]["state"] == "Up"

    l2_ops = drv.get_l2_operational(conn)
    assert l2_ops["TwentyFiveGigE0/0/0/1"]["lag_group"] == "Bundle-Ether10"
    assert l2_ops["TwentyFiveGigE0/0/0/1"]["lag_id"] == "Bundle-Ether10"
    assert l2_ops["FourHundredGigE0/0/0/2"]["lag_group"] == "Bundle-Ether10"

    optics = drv.get_optics(conn)
    assert len(optics) == 1
    assert optics[0]["type"] == "Cisco SFP+ 10GBASE-LR"
    assert optics[0]["vendor"] == "Cisco"
    assert "temperature_c" in optics[0] and "voltage_v" in optics[0]


def test_cisco_xr_fhrp_brief_priority_preempt():
    """DE-11: get_fhrp() prefers show hsrp/vrrp brief (with summary fallback) and extracts priority & preempt."""
    drv = CiscoXRDriver(ip="10.255.0.1")
    conn = MagicMock()
    responses = {
        "show hsrp brief": (
            "Interface   Grp  Prio P State   Active addr     Standby addr    Group addr\n"
            "BE1.10       10  110  P Active  local           10.10.0.3       10.10.0.254\n"
        ),
        "show vrrp brief": "% Invalid input detected at '^' marker.\n",
        "show vrrp summary": (
            "Interface   Grp  Prio P State   Master addr     Group addr\n"
            "BE1.20       20  120  - Backup  10.20.0.2       10.20.0.254\n"
        ),
    }
    conn.send_command.side_effect = lambda cmd, **_kw: responses.get(cmd, "")
    fhrp = drv.get_fhrp(conn)
    assert len(fhrp) == 2
    assert fhrp[0]["protocol"] == "HSRP"
    assert fhrp[0]["priority"] == 110
    assert fhrp[0]["preempt"] is True
    assert fhrp[0]["vip"] == "10.10.0.254"
    assert fhrp[1]["protocol"] == "VRRP"
    assert fhrp[1]["priority"] == 120
    assert fhrp[1]["preempt"] is False


def test_cisco_xr_netconf_strict_hostkey_and_gnmi_timeout(monkeypatch):
    """SF-09 / TR-10: NETCONF honors NDC_STRICT_HOST_KEYS & disables agent/keys; gNMI passes timeout."""
    drv = CiscoXRDriver(
        ip="10.255.0.1",
        username="rouser",
        password="pw",
        timeout=12,
        use_netconf=True,
        use_gnmi=True,
    )

    # Fake ncclient.manager module
    nc_calls = []

    class _FakeNCCtx:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, filter=None):
            return types.SimpleNamespace(xml="<data/>")

    def _fake_nc_connect(**kwargs):
        nc_calls.append(kwargs)
        return _FakeNCCtx()

    fake_ncclient = types.ModuleType("ncclient")
    fake_ncclient.manager = types.SimpleNamespace(connect=_fake_nc_connect)
    monkeypatch.setitem(sys.modules, "ncclient", fake_ncclient)

    monkeypatch.setenv("NDC_STRICT_HOST_KEYS", "1")
    xml = drv.fetch_netconf_operational()
    assert xml == "<data/>"
    assert nc_calls[0]["hostkey_verify"] is True
    assert nc_calls[0]["allow_agent"] is False
    assert nc_calls[0]["look_for_keys"] is False
    assert nc_calls[0]["timeout"] == 12

    # Fake pygnmi.client module
    gnmi_init_calls = []
    gnmi_get_calls = []

    class _FakeGNMI:
        def __init__(self, target, username, password, insecure=False, gnmi_timeout=None, grpc_options=None):
            gnmi_init_calls.append({"gnmi_timeout": gnmi_timeout, "grpc_options": grpc_options})

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, path=None, encoding=None, timeout=None):
            gnmi_get_calls.append({"path": path, "encoding": encoding, "timeout": timeout})
            return {"notification": []}

    fake_pygnmi = types.ModuleType("pygnmi")
    fake_pygnmi_client = types.ModuleType("pygnmi.client")
    fake_pygnmi_client.gNMIclient = _FakeGNMI
    monkeypatch.setitem(sys.modules, "pygnmi", fake_pygnmi)
    monkeypatch.setitem(sys.modules, "pygnmi.client", fake_pygnmi_client)

    res = drv.fetch_gnmi_operational()
    assert res == {"notification": []}
    assert gnmi_init_calls[0]["gnmi_timeout"] == 12
    assert gnmi_get_calls[0]["timeout"] == 12


def test_cisco_xr_guarded_commands_log_warnings(caplog):
    """DE-23: IOS-XR command failures are caught and logged at WARNING level rather than crashing."""
    drv = CiscoXRDriver(ip="10.255.0.1")
    conn = MagicMock()
    conn.send_command.side_effect = RuntimeError("timeout")
    conn.find_prompt.return_value = "RP/0/0/CPU0:xr-core#"

    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.cisco_xr"):
        l3, detail = drv.get_interfaces(conn)
        arp = drv.get_arp_table(conn)

    assert l3 == [] and detail == {}
    assert arp == []
    assert any("timeout" in rec.message for rec in caplog.records)

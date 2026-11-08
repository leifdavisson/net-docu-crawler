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

import oui_lookup


def test_normalize_mac():
    assert oui_lookup.normalize_mac("0000.0c12.3456") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("00-00-0c-12-34-56") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("00:00:0c:12:34:56") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("00000c123456") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("") == ""
    assert oui_lookup.normalize_mac("invalid") == "invalid"


def test_cisco_and_meraki_oui():
    assert "Cisco" in oui_lookup.get_vendor("00:00:0C:11:22:33")
    assert "Cisco" in oui_lookup.get_vendor("0001.42aa.bbcc")
    assert "Cisco" in oui_lookup.get_vendor("00:18:0A:11:22:33")  # Meraki Cisco


def test_all_enterprise_network_vendors_oui():
    # Test major enterprise network gear vendors
    vendors_to_test = {
        "00:0B:86:11:22:33": "Aruba/HPE",
        "00:1F:12:AA:BB:CC": "Juniper Networks",
        "00:13:92:11:22:33": "Ruckus Wireless",
        "00:27:22:11:22:33": "Ubiquiti Networks",
        "00:1C:73:01:02:03": "Arista Networks",
        "00:1B:17:AA:BB:CC": "Palo Alto Networks",
        "00:09:0F:11:22:33": "Fortinet",
        "00:04:96:11:22:33": "Extreme Networks",
        "00:0C:42:11:22:33": "MikroTik",
        "00:1C:7F:11:22:33": "Check Point",
        "00:06:B1:11:22:33": "SonicWall",
        "00:01:D7:11:22:33": "F5 Networks",
        "00:14:22:11:22:33": "Dell Networking",
        "00:0F:B5:11:22:33": "Netgear",
        "50:D4:F7:11:22:33": "TP-Link",
        "00:15:77:11:22:33": "Allied Telesis",
    }
    for mac, expected_vendor in vendors_to_test.items():
        detected = oui_lookup.get_vendor(mac)
        assert expected_vendor.lower() in detected.lower(), f"Expected {expected_vendor} for {mac}, got {detected}"


def test_lookup_oui_alias():
    # Verify lookup_oui is identical to get_vendor
    assert oui_lookup.lookup_oui("00:1C:73:01:02:03") == "Arista Networks"


def test_unknown_oui_lookup():
    assert oui_lookup.get_vendor("AA:BB:CC:DD:EE:FF") == "Unknown"

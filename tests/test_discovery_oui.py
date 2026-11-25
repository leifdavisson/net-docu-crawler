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

"""Regression tests for oui_lookup MAC normalization, FHRP/LAA/hypervisor guards, and air-gapped OUI safety."""

import threading
import time
import urllib.error
from unittest.mock import patch

import oui_lookup


def test_normalize_mac_all_formats_and_rejects_non_mac():
    assert oui_lookup.normalize_mac("00:00:0c:12:34:56") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("00-00-0c-12-34-56") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("0000.0c12.3456") == "00:00:0C:12:34:56"
    assert oui_lookup.normalize_mac("001db3-112233") == "00:1D:B3:11:22:33"
    assert oui_lookup.normalize_mac("00000c123456") == "00:00:0C:12:34:56"
    # macOS / BSD short-octet ARP MAC format
    assert oui_lookup.normalize_mac("0:c:29:1:2:3") == "00:0C:29:01:02:03"
    assert oui_lookup.normalize_mac("0-0-c-12-34-56") == "00:00:0C:12:34:56"
    # Non-MAC inputs must NOT be coerced into fake MACs or bogus OUI prefixes
    assert oui_lookup.is_valid_mac("2001:db8::12345") is False
    assert oui_lookup.normalize_mac("2001:db8::12345") == "2001:db8::12345"
    assert oui_lookup.get_oui_prefix("2001:db8::12345") == ""
    assert oui_lookup.get_oui_prefix("Cisco Catalyst 2960") == ""
    assert oui_lookup.get_oui_prefix("invalid") == ""


def test_get_oui_prefix_accepts_lowercase_6hex_prefixes():
    assert oui_lookup.get_oui_prefix("00:00:0c") == "00:00:0C"
    assert oui_lookup.get_oui_prefix("00-1b-17") == "00:1B:17"
    assert oui_lookup.get_oui_prefix("001c73") == "00:1C:73"
    assert oui_lookup.get_oui_prefix("0:c:29:1:2:3") == "00:0C:29"
    assert oui_lookup.get_vendor("00:00:0c") == "Cisco Systems"
    assert oui_lookup.get_vendor("00-1c-73") == "Arista Networks"


def test_laa_multicast_and_expanded_hypervisor_mac_detection():
    assert oui_lookup.is_locally_administered_mac("02:42:ac:11:00:02") is True
    assert oui_lookup.is_locally_administered_mac("52:54:00:11:22:33") is True
    assert oui_lookup.is_locally_administered_mac("00:00:0c:12:34:56") is False
    assert oui_lookup.is_multicast_mac("01:00:5e:00:00:16") is True
    assert oui_lookup.is_multicast_mac("ff:ff:ff:ff:ff:ff") is True
    assert oui_lookup.is_multicast_mac("00:00:0c:12:34:56") is False

    # Expanded hypervisor / container virtual NIC OUIs
    for mac in (
        "bc:24:11:aa:bb:cc",  # Proxmox VE
        "52:54:00:11:22:33",  # QEMU/KVM
        "00:50:56:11:22:33",  # VMware ESXi
        "00:0c:29:11:22:33",  # VMware
        "00:05:69:11:22:33",  # VMware legacy
        "00:1c:14:11:22:33",  # VMware ESXi/NSX
        "00:1c:42:11:22:33",  # Parallels
        "00:1a:4a:11:22:33",  # Red Hat oVirt / KVM
        "00:03:ff:11:22:33",  # MS Virtual PC / Hyper-V
        "00:0f:4b:11:22:33",  # Oracle Virtual Iron / VirtualBox
        "08:00:27:11:22:33",  # VirtualBox
        "0a:00:27:11:22:33",  # VirtualBox Host-Only
        "00:15:5d:11:22:33",  # Hyper-V
        "00:16:3e:11:22:33",  # Xen / XCP-ng
        "50:6b:8d:11:22:33",  # Nutanix AHV
        "02:42:ac:11:00:02",  # Docker bridge
    ):
        assert oui_lookup.is_hypervisor_mac(mac) is True, f"Expected hypervisor MAC: {mac}"

    assert oui_lookup.is_hypervisor_mac("fc:33:42:e6:b5:99") is False


def test_fhrp_virtual_mac_classification():
    # VRRP v2/v3 IPv4 & CARP
    assert oui_lookup.is_fhrp_mac("00:00:5e:00:01:0a") is True
    assert "VRRP" in oui_lookup.classify_fhrp_mac("00:00:5e:00:01:0a")
    assert "VRRP" in oui_lookup.get_vendor("00:00:5e:00:01:0a")

    # VRRP v3 IPv6
    assert oui_lookup.is_fhrp_mac("00:00:5e:00:02:01") is True
    assert "VRRP" in oui_lookup.get_vendor("00:00:5e:00:02:01")

    # Cisco HSRP v1 & v2
    assert oui_lookup.is_fhrp_mac("00:00:0c:07:ac:01") is True
    assert "HSRP" in oui_lookup.classify_fhrp_mac("00:00:0c:07:ac:01")
    assert "HSRP" in oui_lookup.get_vendor("00:00:0c:07:ac:01")
    assert oui_lookup.is_fhrp_mac("00:00:0c:9f:f0:01") is True
    assert "HSRP" in oui_lookup.classify_fhrp_mac("00:00:0c:9f:f0:01")

    # Physical Cisco NIC sharing 00:00:0C OUI is NOT FHRP
    assert oui_lookup.is_fhrp_mac("00:00:0c:12:34:56") is False
    assert oui_lookup.get_vendor("00:00:0c:12:34:56") == "Cisco Systems"

    # Cisco GLBP
    assert oui_lookup.is_fhrp_mac("00:07:b4:00:01:01") is True
    assert "GLBP" in oui_lookup.classify_fhrp_mac("00:07:b4:00:01:01")
    assert oui_lookup.is_fhrp_mac("00:07:b4:11:22:33") is False

    # Fortinet FGCP HA virtual MAC
    assert oui_lookup.is_fhrp_mac("00:09:0f:09:00:01") is True
    assert "FGCP" in oui_lookup.classify_fhrp_mac("00:09:0f:09:00:01")
    assert oui_lookup.is_fhrp_mac("00:09:0f:11:22:33") is False


def test_online_oui_opt_in_default_air_gapped_safe(tmp_path, monkeypatch):
    """SF-10 / DD-10: Default get_vendor() must NEVER trigger external HTTP requests."""
    cache_file = tmp_path / "oui_cache.json"
    monkeypatch.delenv("NET_DOCU_OFFLINE_OUI", raising=False)
    monkeypatch.delenv("NET_DOCU_ONLINE_OUI", raising=False)
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_FILE", str(cache_file))
    monkeypatch.setattr(oui_lookup, "_online_oui_cache", {})
    monkeypatch.setattr(oui_lookup, "_online_cache_loaded", False)
    monkeypatch.setattr(oui_lookup, "_transient_failed_ouis", set())

    with (
        patch("oui_lookup.load_oui_file", return_value=False),
        patch("oui_lookup._fetch_oui_online", return_value="Fortinet, Inc.") as mock_fetch,
    ):
        # Default: strictly offline
        assert oui_lookup.get_vendor("08:5B:0E:11:22:33") == "Unknown"
        assert mock_fetch.call_count == 0

        # Explicit opt-in via env var NET_DOCU_ONLINE_OUI=1
        monkeypatch.setenv("NET_DOCU_ONLINE_OUI", "1")
        assert oui_lookup.get_vendor("08:5B:0E:11:22:33") == "Fortinet, Inc."
        assert mock_fetch.call_count == 1

        # Hard kill-switch NET_DOCU_OFFLINE_OUI=1 overrides even online=True
        monkeypatch.setenv("NET_DOCU_OFFLINE_OUI", "1")
        assert oui_lookup.get_vendor("08:5B:0F:11:22:33", online=True) == "Unknown"
        assert mock_fetch.call_count == 1


def test_online_oui_transient_error_not_persisted_and_nonblocking_lock(tmp_path, monkeypatch):
    """HTTP 429/timeout must not poison oui_cache.json, and network I/O must not hold _oui_cache_lock."""
    cache_file = tmp_path / "oui_cache.json"
    monkeypatch.delenv("NET_DOCU_OFFLINE_OUI", raising=False)
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_FILE", str(cache_file))
    monkeypatch.setattr(oui_lookup, "_online_oui_cache", {})
    monkeypatch.setattr(oui_lookup, "_online_cache_loaded", False)
    monkeypatch.setattr(oui_lookup, "_transient_failed_ouis", set())

    err_429 = urllib.error.HTTPError(
        url="https://api.macvendors.com/08:5B:0E",
        code=429,
        msg="Too Many Requests",
        hdrs=None,
        fp=None,
    )
    with (
        patch("oui_lookup.load_oui_file", return_value=False),
        patch("urllib.request.urlopen", side_effect=err_429) as mock_open,
    ):
        assert oui_lookup._fetch_oui_online("08:5B:0E") == ""
        assert oui_lookup.get_vendor("08:5B:0E:11:22:33", online=True) == "Unknown"
        assert "08:5B:0E" not in oui_lookup._online_oui_cache
        assert not cache_file.exists()
        # Repeated call in same run avoids re-stalling on failed OUI
        calls_after_first = mock_open.call_count
        assert oui_lookup.get_vendor("08:5B:0E:44:55:66", online=True) == "Unknown"
        assert mock_open.call_count == calls_after_first

    # Verify _oui_cache_lock is NOT held during slow _fetch_oui_online network I/O
    monkeypatch.setattr(oui_lookup, "_transient_failed_ouis", set())
    entered_fetch = threading.Event()
    release_fetch = threading.Event()
    lock_was_free = []

    def slow_fetch(prefix: str, timeout: float = 1.5) -> str:
        entered_fetch.set()
        release_fetch.wait(timeout=2.0)
        return "Mock Vendor"

    with (
        patch("oui_lookup.load_oui_file", return_value=False),
        patch("oui_lookup._fetch_oui_online", side_effect=slow_fetch),
    ):
        t = threading.Thread(target=lambda: oui_lookup.get_vendor("08:5B:0E:11:22:33", online=True))
        t.start()
        assert entered_fetch.wait(timeout=2.0)
        acquired = oui_lookup._oui_cache_lock.acquire(timeout=0.5)
        lock_was_free.append(acquired)
        if acquired:
            oui_lookup._oui_cache_lock.release()
        release_fetch.set()
        t.join(timeout=2.0)

    assert lock_was_free == [True]
    assert time.monotonic() > 0


def test_load_oui_file_thread_safe_atomic(tmp_path, monkeypatch):
    sample_oui = tmp_path / "oui.txt"
    sample_oui.write_text(
        "00-22-72   (hex)\t\tAmerican Micro-Fuel Device Corp.\n085B0E     (base 16)\t\tFortinet, Inc.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(oui_lookup, "OUI_FILE", str(sample_oui))
    monkeypatch.setattr(oui_lookup, "_loaded_ouis", {})
    assert oui_lookup.load_oui_file() is True
    assert oui_lookup.get_vendor("00:22:72:11:22:33", online=False) == "American Micro-Fuel Device Corp."
    assert oui_lookup.get_vendor("08:5B:0E:11:22:33", online=False) == "Fortinet, Inc."


def test_bundled_offline_ruckus_and_juniper_ouis():
    assert oui_lookup.get_vendor("60:D0:2C:10:4F:70", online=False) == "Ruckus Wireless"
    assert oui_lookup.get_vendor("10:F0:68:AA:BB:CC", online=False) == "Ruckus Wireless"
    assert oui_lookup.get_vendor("44:AA:50:11:22:33", online=False) == "Juniper Networks"

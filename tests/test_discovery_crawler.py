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

"""Wave 2 regression tests for crawler.py Tier 3 dispatch, vendor-hint override, target/IPv6/port parsing, and credential sorting."""

from unittest.mock import MagicMock, patch

from net_docu_crawler.crawler import (
    CrawlOptions,
    _connect_and_crawl_once,
    _crawl_target_batch,
    _identify_port_vendor,
    _select_hop_targets_for_cidrs,
    _sort_and_scope_credentials,
    _try_driver_credentials,
    crawl_target_with_ports,
    detect_local_subnets,
    expand_targets,
    extract_followable_subnets,
    parse_target_specs,
    parse_target_vendor_spec,
    validate_credentials,
)
from net_docu_crawler.drivers import (
    AristaDriver,
    CiscoDriver,
    JuniperDriver,
    PaloAltoDriver,
)
from net_docu_crawler.topology_resolver import DeviceRegistry


def test_tier3_prompt_inspection_dispatches_correct_driver_on_unknown_target(tmp_path):
    """P0 DD-02: Unknown targets must inspect post-auth prompt (Tier 3) and delegate to the matched OS driver."""
    fake_conn = MagicMock()
    fake_conn.find_prompt.return_value = "admin@PA-5220(active)>"

    cisco_crawl_called = []
    pa_crawl_called = []

    with (
        patch.object(CiscoDriver, "connect", return_value=fake_conn),
        patch.object(CiscoDriver, "crawl", side_effect=lambda c: cisco_crawl_called.append(c) or {"hostname": "bad"}),
        patch.object(
            PaloAltoDriver,
            "crawl",
            side_effect=lambda c: (
                pa_crawl_called.append(c)
                or {"ip": "192.0.2.50", "hostname": "PA-5220", "vendor": "Palo Alto Networks", "status": "success"}
            ),
        ),
    ):
        data, outcome = _connect_and_crawl_once(
            driver_cls=CiscoDriver,
            ip="192.0.2.50",
            port=22,
            transport="ssh",
            cred={"username": "admin", "password": "pw"},
            timeout=5,
            session_log="",
            log_file=str(tmp_path / "exec.log"),
        )

    assert outcome == "success"
    assert data is not None
    assert data["hostname"] == "PA-5220"
    assert data["vendor"] == "Palo Alto Networks"
    assert cisco_crawl_called == []
    assert len(pa_crawl_called) == 1
    assert fake_conn.disconnect.call_count == 1


def test_vendor_hint_overrides_tier1_tier2_misclassifications():
    """DD-04: --vendor-hint (including aliases) must override misclassified Tier 1/2 detections."""
    with patch(
        "net_docu_crawler.crawler.detect_vendor_range",
        return_value=("opnsense", "SSH-2.0-OpenSSH_8.4 FreeBSD-20201028"),
    ):
        v, banner, app, hp, fp = _identify_port_vendor(
            ip="192.0.2.60",
            port=22,
            transport="ssh",
            host_mac="",
            hint_norm="junos",
            last_vendor="unknown",
            timeout=8,
            http_fingerprint=False,
            http_probed=False,
            cached_http_fp=None,
            log_file="",
        )
        assert v == "juniper"
        assert app is None

    # End-to-end crawl_target_with_ports with vendor_hint="junos" when detect_vendor_range returns "cisco"
    juniper_called = []
    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "SSH-2.0-OpenSSH")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch.object(JuniperDriver, "connect", return_value=MagicMock(find_prompt=lambda: "admin@ex4300>")),
        patch.object(
            JuniperDriver,
            "crawl",
            side_effect=lambda _c: (
                juniper_called.append(True) or {"ip": "192.0.2.61", "hostname": "ex4300", "status": "success"}
            ),
        ),
        patch.object(CiscoDriver, "connect") as mock_cisco_conn,
    ):
        res = crawl_target_with_ports(
            ip="192.0.2.61",
            credentials=[{"username": "admin", "password": "pw"}],
            open_ports=[(22, "ssh")],
            vendor_hint="  JUNOS  ",
        )
        assert res is not None and res["hostname"] == "ex4300"
        assert juniper_called == [True]
        assert mock_cisco_conn.call_count == 0


def test_parse_target_specs_ipv6_brackets_port_bounds_and_empty_telnet():
    """DD-05: Bare IPv6 must not split on ':', bracketed [IPv6]:port strips brackets, invalid ports are rejected."""
    ips, explicit = parse_target_specs(
        [
            "2001:db8::1",
            "2001:0db8:0:0::1",  # duplicate canonical IPv6
            "[2001:db8::2]:2222",
            "[2001:db8::3]",
            "192.0.2.10:2222",
            "192.0.2.11:0",  # invalid port 0
            "192.0.2.12:70000",  # invalid port > 65535
            "192.0.2.13:abc",  # non-numeric port
            ":22",  # missing host
            "[2001:db8::4]:99999",  # invalid bracketed port
        ]
    )
    assert ips == ["2001:db8::1", "2001:db8::2", "2001:db8::3", "192.0.2.10"]
    assert explicit == {
        "2001:db8::2": [(2222, "ssh")],
        "192.0.2.10": [(2222, "ssh")],
    }

    # Explicit telnet_ports=[] must not re-enable port 23 as telnet
    ips2, explicit2 = parse_target_specs(["192.0.2.20:23"], ssh_ports=[22, 23], telnet_ports=[])
    assert ips2 == ["192.0.2.20"]
    assert explicit2["192.0.2.20"] == [(23, "ssh")]


def test_expand_targets_cidr_slash31_slash32_slash23_and_invalid_cidr():
    """DD-14: /31, /32, /23 full expansion, malformed CIDR rejection, and canonical seed CIDR dedup."""
    assert expand_targets(["192.0.2.5/32"]) == ["192.0.2.5"]
    assert expand_targets(["192.0.2.0/31"]) == ["192.0.2.0", "192.0.2.1"]
    # /23 (510 usable hosts) must expand completely under default max_hosts_per_cidr=1024
    slash23 = expand_targets(["10.29.0.0/23"])
    assert len(slash23) == 510
    assert slash23[0] == "10.29.0.1"
    assert slash23[-1] == "10.29.1.254"
    # Invalid CIDRs must be skipped, never retained as literal scan targets
    assert expand_targets(["192.0.2.0/99", "not-a-cidr/24", "192.0.2.1"]) == ["192.0.2.1"]


def test_followable_subnets_slash31_and_hop_ipv6_arp_guard():
    """DD-13: extract_followable_subnets includes /31 P2P links and _select_hop_targets_for_cidrs ignores IPv6 ARP."""
    devs = [
        {
            "l3_interfaces": [
                {"interface": "et-0/0/0", "ip_address": "10.250.0.0/31"},
                {"interface": "et-0/0/1", "ip_address": "10.250.0.4/30"},
            ]
        }
    ]
    subnets = extract_followable_subnets(devs, mgmt_only=True)
    assert "10.250.0.0/31" in subnets
    assert "10.250.0.4/30" in subnets

    reg = DeviceRegistry()
    reg.global_arp["fe80::1"] = {"mac": "00:00:0c:11:22:33", "vendor": "Cisco Systems"}
    reg.global_arp["not_an_ip"] = {"mac": "00:00:0c:11:22:34", "vendor": "Cisco Systems"}
    reg.global_arp["10.250.0.1"] = {"mac": "00:23:9c:11:22:33", "vendor": "Juniper Networks"}

    hops = _select_hop_targets_for_cidrs(["10.250.0.0/31"], reg, {"10.250.0.0"})
    assert hops == ["10.250.0.1"]


def test_credential_sorting_lowercase_cisco_vendor_aliases_and_no_fallback_spray():
    """DD-07 / DD-01: Lowercase 'cisco' priority, canonical vendor alias matching, tagged-before-untagged, no spray."""
    # 1. 'cisco' username sorts ahead of 'admin' on Cisco devices
    cisco_creds = [
        {"name": "C-other", "vendor": "cisco", "username": "operator", "password": "p0"},
        {"name": "C-admin", "vendor": "cisco", "username": "admin", "password": "p1"},
        {"name": "C-cisco", "vendor": "cisco", "username": "cisco", "password": "p2"},
    ]
    ordered = _sort_and_scope_credentials(cisco_creds, "cisco", False, "")
    assert [c["username"] for c in ordered] == ["cisco", "admin", "operator"]

    # 2. Vendor-tagged credentials sort ahead of untagged generic credentials
    mixed = [
        {"name": "Generic-Admin", "username": "admin", "password": "gen"},
        {"name": "FG-Netops", "vendor": "fortigate", "username": "netops", "password": "fg"},
    ]
    ordered_fg = _sort_and_scope_credentials(mixed, "fortinet", False, "")
    assert [c["name"] for c in ordered_fg] == ["FG-Netops", "Generic-Admin"]

    # 3. Vendor alias 'hp' / 'procurve' matches 'hpprocurve'
    alias_creds = [
        {"name": "HP-Alias", "vendor": "hp", "username": "manager", "password": "p1"},
        {"name": "Cisco-Only", "vendor": "cisco", "username": "admin", "password": "p2"},
    ]
    scoped_hp = _sort_and_scope_credentials(alias_creds, "hpprocurve", False, "")
    assert [c["name"] for c in scoped_hp] == ["HP-Alias"]

    # 4. When try_all_creds=False and no credential matches detected vendor or untagged, return [] (do not spray)
    unrelated = [
        {"name": "Cisco-1", "vendor": "cisco", "username": "u1", "password": "p1"},
        {"name": "Juniper-1", "vendor": "juniper", "username": "u2", "password": "p2"},
    ]
    assert _sort_and_scope_credentials(unrelated, "fortinet", False, "") == []

    # And on unknown vendor with try_all_creds=False, do not spray HP-only creds onto Cisco/Arista/Juniper drivers
    calls = []
    with patch(
        "net_docu_crawler.crawler._connect_and_crawl_once",
        side_effect=lambda *a, **kw: calls.append(a[0].__name__) or (None, "auth_failed"),
    ):
        _try_driver_credentials(
            ip="192.0.2.99",
            port=22,
            transport="ssh",
            vendor_cand="unknown",
            driver_classes=[CiscoDriver, AristaDriver, JuniperDriver],
            sorted_creds=[{"username": "u_hp", "password": "pw", "vendor": "hp"}],
            try_all_creds=False,
            timeout=5,
            session_log="",
            log_file="",
        )
    assert calls == []

    # validate_credentials canonicalizes vendor aliases
    valid, warnings, errors = validate_credentials(
        [{"name": "HP1", "vendor": "procurve", "username": "manager", "password": "pw"}]
    )
    assert not errors and not warnings
    assert valid[0]["vendor"] == "hpprocurve"


def test_crawl_target_batch_respects_max_workers_and_scales_probe_timeout(tmp_path):
    """DD-06 / DD-19: _crawl_target_batch respects cfg.max_workers (<32) and scales probe timeout; macOS subnet fallback."""
    registry = DeviceRegistry()
    cfg = CrawlOptions(timeout=12, max_workers=4)
    with patch("net_docu_crawler.crawler.scan_subnet_ports", return_value={}) as mock_scan:
        _crawl_target_batch(
            batch_ips=["192.0.2.1", "192.0.2.2"],
            batch_explicit={},
            cfg=cfg,
            credentials=[],
            registry=registry,
            raw_devices=[],
            scanned_ip_set=set(),
            logs_dir=str(tmp_path),
            crawler_log=str(tmp_path / "exec.log"),
        )
        assert mock_scan.call_count == 1
        _, kwargs = mock_scan.call_args
        assert kwargs["max_workers"] <= 4
        assert kwargs["timeout"] >= 1.5

    # macOS ifconfig fallback in detect_local_subnets
    ifconfig_out = (
        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        "\tinet 10.40.50.12 netmask 0xffffff00 broadcast 10.40.50.255\n"
    )
    with (
        patch("net_docu_crawler.crawler.sys.platform", "darwin"),
        patch(
            "net_docu_crawler.crawler.subprocess.run",
            side_effect=[
                FileNotFoundError("ip not found"),
                MagicMock(returncode=0, stdout=ifconfig_out),
            ],
        ),
    ):
        assert detect_local_subnets() == ["10.40.50.0/24"]

    # parse_target_vendor_spec supports meraki, fortinet, aruba, hpprocurve
    assert parse_target_vendor_spec("switch=aruba,firewall=fortigate,ap=meraki") == {
        "switch": "aruba",
        "firewall": "fortinet",
        "ap": "meraki",
    }

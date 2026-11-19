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

"""Tests for zero-blast-radius DNS domain detection and --site folder naming."""

from unittest.mock import patch

from net_docu_crawler.crawler import compute_organized_output_dir
from net_docu_crawler.domain_detector import (
    detect_environment_dns_domain,
    detect_local_dns_suffix,
    domain_to_site_slug,
    extract_device_dns_domains,
)


def test_extract_device_dns_domains_from_configs_and_tls():
    devices = [
        {"hostname": "core-sw01", "raw_config": "hostname core-sw01\nip domain-name norris.k12.ca.us\n"},
        {"hostname": "fw01.norris.k12.ca.us", "model": "*.norris.k12.ca.us"},
        {"hostname": "bad", "raw_config": "ip domain-name localhost\n"},
    ]
    assert extract_device_dns_domains(devices) == ["norris.k12.ca.us"]


def test_domain_to_site_slug():
    assert domain_to_site_slug("norris.k12.ca.us") == "norris"
    assert domain_to_site_slug("localhost") == "lan"
    assert domain_to_site_slug("") == "lan"


def test_detect_local_dns_suffix_windows_ipconfig():
    sample = (
        "Ethernet adapter Ethernet0:\n"
        "   Connection-specific DNS Suffix  . : norris.k12.ca.us\n"
        "   IPv4 Address. . . . . . . . . . . : 10.1.0.50\n"
    )
    with patch("net_docu_crawler.domain_detector.os.name", "nt"):
        with patch("net_docu_crawler.domain_detector.subprocess.run") as mock_run:
            mock_run.return_value.stdout = sample
            assert detect_local_dns_suffix() == "norris.k12.ca.us"


def test_detect_environment_dns_domain_prefers_device_domain():
    res = detect_environment_dns_domain(
        devices=[{"hostname": "sw1", "raw_config": "ip domain-name norris.k12.ca.us\n"}],
        local_suffix="corp.example.com",
    )
    assert res["primary_domain"] == "norris.k12.ca.us"
    assert res["local_dns_suffix"] == "corp.example.com"
    assert res["site_slug"] == "norris"


def test_compute_organized_output_dir_site_auto_and_override():
    with patch("net_docu_crawler.domain_detector.detect_local_dns_suffix", return_value="norris.k12.ca.us"):
        p_auto = compute_organized_output_dir(["10.1.0.1"], base_dir="deliverables", site="auto")
        assert p_auto.endswith("_norris")
    p_explicit = compute_organized_output_dir(["10.1.0.1"], base_dir="deliverables", site="campus-a")
    assert p_explicit.endswith("_campus-a")
    p_legacy = compute_organized_output_dir(["10.1.0.1"], base_dir="deliverables", domain="legacy")
    assert p_legacy.endswith("_legacy")

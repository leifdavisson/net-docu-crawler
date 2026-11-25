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

"""
Regression tests for `net_docu_crawler.drivers.base` covering:
- TR-04: Netmiko 4.x timeout parameters (`conn_timeout`, `banner_timeout`, `auth_timeout`,
  `blocking_timeout`, `session_timeout`, and bounded per-command `read_timeout`)
- TR-07: Guaranteed VTY session cleanup (`connect_session`, `_finalize_connection`, `safe_disconnect`)
- TR-08: Paging-disable verification & `--More--` artifact detection
- TR-15 & RP-01/RP-02/RP-03: Non-breaking `collection_status` & `parse_errors` hooks in `BaseDriver.crawl()`
- SF-11: Multi-vendor secret redaction in `sanitize_raw_config()` & `scrub_known_secrets()`
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from net_docu_crawler.drivers.base import (
    BaseDriver,
    sanitize_raw_config,
)


class _DummySwitchDriver(BaseDriver):
    vendor_name = "DummyVendor"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "terminal length 0"

    def __init__(self, *args, fail_section: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._fail_section = fail_section
        self._mock_conn = MagicMock()

    def connect(self):
        return self._mock_conn

    def get_version(self, conn) -> dict:
        if self._fail_section == "version":
            raise TimeoutError("show version timed out")
        return {
            "hostname": "sw-core-01",
            "model": "TestSwitch-48P",
            "serial": "SN12345678",
            "firmware": "1.0.0",
            "os_type": "dummy_os",
        }

    def get_interfaces(self, conn) -> tuple[list, dict]:
        if self._fail_section == "interfaces":
            raise TimeoutError("show interfaces timed out")
        return (
            [{"interface": "Vlan10", "ip_address": "192.0.2.10/24", "status": "up", "protocol": "up"}],
            {"Gi1/0/1": {"status": "up", "mac_address": "00:11:22:33:44:55", "description": "Uplink"}},
        )

    def get_neighbors(self, conn) -> list[dict]:
        return []

    def get_routing_table(self, conn) -> list[dict]:
        return []

    def get_arp_table(self, conn) -> list[dict]:
        return []

    def get_running_config(self, conn) -> str:
        if self._fail_section == "running_config":
            raise TimeoutError("show running-config timed out")
        return self._safe_send_command(conn, "show running-config")


def test_build_netmiko_params_sets_all_netmiko_v4_timeouts():
    """TR-04: _build_netmiko_params must populate conn_timeout, banner_timeout, auth_timeout, blocking_timeout, session_timeout."""
    drv = _DummySwitchDriver(ip="192.0.2.10", username="admin", password="pw", timeout=7)
    params = drv._build_netmiko_params("cisco_ios")

    assert params["conn_timeout"] == 7
    assert params["banner_timeout"] == 7
    assert params["auth_timeout"] == 7
    assert 10 <= params["blocking_timeout"] <= 60
    assert 30 <= params["session_timeout"] <= 120

    # Even when legacy include_auth_timeout=False is passed (e.g. CiscoSMB), auth_timeout must NEVER be omitted/None
    params_no_flag = drv._build_netmiko_params("cisco_s300", include_auth_timeout=False)
    assert params_no_flag["conn_timeout"] == 7
    assert params_no_flag["auth_timeout"] == 7
    assert params_no_flag["banner_timeout"] == 7

    # Zero read_timeout_override (infinite in Netmiko) must be rejected/clamped
    params_zero = drv._build_netmiko_params("cisco_ios", read_timeout_override=0)
    assert params_zero.get("read_timeout_override") is None or params_zero["read_timeout_override"] > 0


def test_safe_send_command_passes_bounded_read_timeout_to_netmiko_like_conn():
    """TR-04: _safe_send_command forwards a bounded read_timeout when conn.send_command accepts it."""
    recorded: list[tuple[str, float | None]] = []

    class _NetmikoLikeConn:
        def send_command(self, command_string: str, read_timeout: float = 10.0) -> str:
            recorded.append((command_string, read_timeout))
            return "hostname sw-core-01\n"

    drv = _DummySwitchDriver(ip="192.0.2.10", timeout=8)
    conn = _NetmikoLikeConn()

    drv._safe_send_command(conn, "show version")
    drv._safe_send_command(conn, "show running-config")

    assert len(recorded) == 2
    short_cmd, short_to = recorded[0]
    large_cmd, large_to = recorded[1]
    assert short_cmd == "show version"
    assert short_to is not None and 10.0 < short_to <= 60.0
    assert large_cmd == "show running-config"
    assert large_to is not None and large_to >= 30.0 and large_to <= 120.0


def test_connect_session_and_finalize_connection_always_disconnect_on_exception():
    """TR-07: connect_session() and _finalize_connection() must close VTY on every exception path."""
    drv = _DummySwitchDriver(ip="192.0.2.10", username="admin", password="pw", secret="en")

    with pytest.raises(RuntimeError, match="boom"):
        with drv.connect_session() as conn:
            assert conn is drv._mock_conn
            raise RuntimeError("boom")
    assert drv._mock_conn.disconnect.call_count == 1

    # _finalize_connection closes conn if BaseException (e.g. KeyboardInterrupt) happens during enable/paging
    conn2 = MagicMock()
    conn2.enable.side_effect = KeyboardInterrupt("ctrl-c")
    with pytest.raises(KeyboardInterrupt):
        drv._finalize_connection(conn2, enable=True, paging_cmd="terminal length 0")
    assert conn2.disconnect.call_count == 1


def test_paging_verification_and_more_artifact_detection(caplog):
    """TR-08: _verify_paging_disabled detects CLI rejections and _safe_send_command flags --More-- truncation."""
    from net_docu_crawler.drivers.base import detect_paging_artifact

    assert detect_paging_artifact("line1\n--More--\n") is True
    assert detect_paging_artifact("line1\n -- MORE -- \n") is True
    assert detect_paging_artifact("line1\n<--- More --->\n") is True
    assert detect_paging_artifact("interface Gi1/0/1\n description More bandwidth\n") is False

    drv = _DummySwitchDriver(ip="192.0.2.10")
    conn = MagicMock()
    conn.send_command.return_value = "% Invalid input detected at '^' marker."
    with caplog.at_level(logging.WARNING):
        ok = drv._verify_paging_disabled(conn, "no paging")
    assert ok is False
    assert "paging" in caplog.text.lower() or "invalid input" in caplog.text.lower()

    # Refuses config-mode commands inside _verify_paging_disabled (Zero Blast Radius)
    conn_cfg = MagicMock()
    assert drv._verify_paging_disabled(conn_cfg, "config system console\nset output standard\nend") is False
    assert conn_cfg.send_command.call_count == 0

    # _safe_send_command logs warning and records parse error on --More-- output
    conn_more = MagicMock()
    conn_more.send_command.return_value = "hostname sw1\n--More--"
    drv._collection_status = {}
    drv._parse_errors = []
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        out = drv._safe_send_command(conn_more, "show running-config")
    assert "--More--" in out
    assert any("paging" in e["error"].lower() or "more" in e["error"].lower() for e in drv._parse_errors)


def test_crawl_records_collection_status_and_survives_section_failure():
    """TR-15 & RP-01/02/03: BaseDriver.crawl() populates collection_status/parse_errors and survives section failures."""
    drv = _DummySwitchDriver(ip="192.0.2.10", password="MySuperPassword!", fail_section="interfaces")
    conn = MagicMock()
    conn.send_command.return_value = "hostname sw-core-01\nip name-server 192.0.2.53\n"

    data = drv.crawl(conn)

    assert data["hostname"] == "sw-core-01"
    assert "collection_status" in data
    assert "parse_errors" in data
    assert data["collection_status"]["version"] == "ok"
    assert data["collection_status"]["interfaces"] == "command_failed"
    assert data["collection_status"]["running_config"] == "ok"
    # Unoverridden optional hooks on BaseDriver must NOT be falsely marked "ok"
    assert data["collection_status"]["stp"] in ("not_collected", "not_applicable")
    assert data["collection_status"]["fhrp"] in ("not_collected", "not_applicable")
    assert any(err["section"] == "interfaces" and err["stage"] == "command" for err in data["parse_errors"])

    # When running_config fails, config-derived sections must NOT be marked "ok"
    drv2 = _DummySwitchDriver(ip="192.0.2.11", fail_section="running_config")
    data2 = drv2.crawl(MagicMock())
    assert data2["collection_status"]["running_config"] == "command_failed"
    assert data2["collection_status"]["services"] == "command_failed"
    assert data2["collection_status"]["dhcp"] == "command_failed"
    assert data2["collection_status"]["vlans"] == "command_failed"


def test_sanitize_raw_config_redacts_multivendor_secrets():
    """SF-11: sanitize_raw_config covers FortiOS, MikroTik, OpenWrt, OPNsense XML, SNMP, and PEM keys."""
    raw = """
set password ENC SH2abcdef1234567890
set psksecret ENC 998877665544
/user add name=admin password=MikroSecret42
option key 'OpenWrtWifiSecret!'
<bcrypt-hash>$2y$10$abcdef1234567890</bcrypt-hash>
<community>PrivateSnmpComm</community>
snmp-server community "CorpROString" unrestricted
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsecretkeymaterial
-----END RSA PRIVATE KEY-----
"""
    cleaned = sanitize_raw_config(raw)
    for leaked in (
        "SH2abcdef1234567890",
        "998877665544",
        "MikroSecret42",
        "OpenWrtWifiSecret!",
        "$2y$10$abcdef1234567890",
        "PrivateSnmpComm",
        "CorpROString",
        "MIIEowIBAAKCAQEAsecretkeymaterial",
    ):
        assert leaked not in cleaned, f"Secret leaked after sanitization: {leaked}"


def test_detect_cli_error_ignores_benign_large_config_substrings():
    """Large valid running configs containing 'authorization failed' text must not trigger CLI error."""
    from net_docu_crawler.drivers.base import detect_cli_error

    large_cfg = "\n".join(
        ["config system global", "    set hostname FortiGate-VM64-KVM", "end"]
        + [f"    set comment line_{i}" for i in range(40)]
        + ['    set auth-msg "authorization failed"']
    )
    assert detect_cli_error(large_cfg) == ""
    assert detect_cli_error("Command fail. Return code -61\nauthorization failed") == "authorization failed"
    assert detect_cli_error("% Invalid input detected at '^' marker.") == "% invalid input"

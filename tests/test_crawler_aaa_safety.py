# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Regression tests for AAA lockout protection, log redaction, and concurrency in crawler.py (TR-03, TR-13, SF-11)."""

import re
import threading
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from net_docu_crawler.crawler import (
    CrawlOptions,
    _connect_and_crawl_once,
    _crawl_target_batch,
    _log_event,
    _try_driver_credentials,
    crawl_target_with_ports,
)
from net_docu_crawler.drivers import AristaDriver, CiscoDriver, JuniperDriver
from net_docu_crawler.topology_resolver import DeviceRegistry


def test_same_username_multiple_passwords_attempted_at_most_once(tmp_path):
    """TR-03: Never attempt the same username (>1 password or case variant) more than once per target IP."""
    attempts: list[tuple[str, str]] = []
    fake_cls = MagicMock()
    fake_cls.__name__ = "CiscoDriver"

    def _make_driver(**kwargs):
        attempts.append((kwargs["username"], kwargs["password"]))
        inst = MagicMock()
        inst.connect.side_effect = paramiko.AuthenticationException("Authentication failed.")
        return inst

    fake_cls.side_effect = _make_driver

    creds = [
        {"name": "C1", "vendor": "cisco", "username": "admin", "password": "pw1"},
        {"name": "C2", "vendor": "cisco", "username": "admin", "password": "pw2"},
        {"name": "C3", "vendor": "cisco", "username": "Admin", "password": "pw3"},
        {"name": "C4", "vendor": "cisco", "username": "ops", "password": "pw4"},
    ]

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "SSH-2.0-Cisco-1.25")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch.dict("net_docu_crawler.crawler.VENDOR_DRIVER_MAP", {"cisco": fake_cls}),
    ):
        result = crawl_target_with_ports(
            ip="192.0.2.10",
            credentials=creds,
            open_ports=[(22, "ssh")],
            log_file=str(tmp_path / "exec.log"),
            try_all_creds=True,
        )

    assert result["status"] == "unauthenticated"
    assert attempts == [("admin", "pw1"), ("ops", "pw4")]
    assert len({u.strip().lower() for u, _ in attempts}) == len(attempts)


def test_failed_username_not_retried_across_ssh_and_telnet_ports(tmp_path):
    """TR-03: A username rejected on SSH port 22 must NOT be retried on port 2222 SSH or port 23 Telnet."""
    attempts: list[tuple[int, str, str, str]] = []
    fake_cls = MagicMock()
    fake_cls.__name__ = "CiscoDriver"
    fake_cls.supports_telnet = True

    def _make_driver(**kwargs):
        attempts.append((kwargs["port"], kwargs["transport"], kwargs["username"], kwargs["password"]))
        inst = MagicMock()
        inst.connect.side_effect = Exception("Authentication to device failed.")
        return inst

    fake_cls.side_effect = _make_driver

    creds = [
        {"name": "C1", "vendor": "cisco", "username": "admin", "password": "pw1"},
        {"name": "C2", "vendor": "cisco", "username": "backup", "password": "pw2"},
    ]

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch.dict("net_docu_crawler.crawler.VENDOR_DRIVER_MAP", {"cisco": fake_cls}),
    ):
        result = crawl_target_with_ports(
            ip="192.0.2.11",
            credentials=creds,
            open_ports=[(22, "ssh"), (2222, "ssh"), (23, "telnet")],
            log_file=str(tmp_path / "exec.log"),
        )

    assert result["status"] == "unauthenticated"
    assert attempts == [
        (22, "ssh", "admin", "pw1"),
        (22, "ssh", "backup", "pw2"),
    ]


def test_failed_username_not_retried_across_drivers_on_telnet(tmp_path):
    """TR-03: Failed Telnet username must not be retried with other passwords or candidate drivers."""
    calls: list[tuple[str, str, str]] = []

    def fake_attempt(driver_cls, ip, port, transport, cred, timeout, session_log, log_file):
        calls.append((driver_cls.__name__, cred.get("username", ""), cred.get("password", "")))
        return None, "auth_failed"

    creds = [
        {"username": "admin", "password": "bad1"},
        {"username": "admin", "password": "bad2"},
    ]
    with patch("net_docu_crawler.crawler._connect_and_crawl_once", side_effect=fake_attempt):
        _try_driver_credentials(
            ip="192.0.2.12",
            port=23,
            transport="telnet",
            vendor_cand="unknown",
            driver_classes=[CiscoDriver, JuniperDriver, AristaDriver],
            sorted_creds=creds,
            try_all_creds=True,
            timeout=5,
            session_log="",
            log_file=str(tmp_path / "exec.log"),
        )

    assert calls == [("CiscoDriver", "admin", "bad1")]


def test_transport_failure_on_ssh_allows_single_telnet_attempt(tmp_path):
    """Pre-auth TCP/KEX failure on SSH did not consume an AAA attempt, so Telnet still gets 1 attempt."""
    attempts: list[tuple[int, str, str]] = []
    fake_cls = MagicMock()
    fake_cls.__name__ = "CiscoDriver"
    fake_cls.supports_telnet = True

    def _make_driver(**kwargs):
        attempts.append((kwargs["port"], kwargs["transport"], kwargs["username"]))
        inst = MagicMock()
        if kwargs["transport"] == "ssh":
            inst.connect.side_effect = Exception("Incompatible ssh peer (no acceptable kex algorithm)")
        else:
            inst.connect.return_value = MagicMock()
            inst.crawl.return_value = {"ip": "192.0.2.13", "hostname": "SW-LEGACY", "status": "success"}
        return inst

    fake_cls.side_effect = _make_driver

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch.dict("net_docu_crawler.crawler.VENDOR_DRIVER_MAP", {"cisco": fake_cls}),
    ):
        result = crawl_target_with_ports(
            ip="192.0.2.13",
            credentials=[{"vendor": "cisco", "username": "admin", "password": "pw1"}],
            open_ports=[(22, "ssh"), (23, "telnet")],
            log_file=str(tmp_path / "exec.log"),
        )

    assert result["status"] == "success"
    assert result["hostname"] == "SW-LEGACY"
    assert attempts == [(22, "ssh", "admin"), (23, "telnet", "admin")]


def test_post_auth_crawl_exception_does_not_retry_auth_and_disconnects(tmp_path):
    """TR-03: Exceptions raised during post-auth crawl() must never be misclassified as auth_failed."""
    connect_calls: list[tuple[int, str, str]] = []
    fake_conn = MagicMock()

    fake_cls = MagicMock()
    fake_cls.__name__ = "CiscoDriver"
    fake_cls.supports_telnet = True

    def _make_driver(**kwargs):
        connect_calls.append((kwargs["port"], kwargs["transport"], kwargs["username"]))
        inst = MagicMock()
        inst.connect.return_value = fake_conn
        inst.crawl.side_effect = RuntimeError("Invalid output: permission table parse error")
        return inst

    fake_cls.side_effect = _make_driver

    data, outcome = _connect_and_crawl_once(
        driver_cls=fake_cls,
        ip="192.0.2.14",
        port=22,
        transport="ssh",
        cred={"username": "admin", "password": "good"},
        timeout=5,
        session_log="",
        log_file=str(tmp_path / "exec1.log"),
    )
    assert data is None
    assert outcome == "crawl_failed"
    assert fake_conn.disconnect.call_count == 1

    connect_calls.clear()
    fake_conn.reset_mock()

    creds = [
        {"vendor": "cisco", "username": "admin", "password": "good"},
        {"vendor": "cisco", "username": "netadmin", "password": "other"},
        {"vendor": "cisco", "username": "backup", "password": "third"},
    ]
    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch.dict("net_docu_crawler.crawler.VENDOR_DRIVER_MAP", {"cisco": fake_cls}),
    ):
        crawl_target_with_ports(
            ip="192.0.2.14",
            credentials=creds,
            open_ports=[(22, "ssh"), (23, "telnet")],
            log_file=str(tmp_path / "exec2.log"),
        )

    assert connect_calls == [(22, "ssh", "admin")]
    assert fake_conn.disconnect.call_count == 1


def test_bad_host_key_aborts_port_without_burning_credentials(tmp_path):
    """TR-03/TR-09: BadHostKeyException must abort the SSH port without retrying other drivers or credentials."""
    attempts: list[tuple[str, str]] = []

    def _make_driver_cls(name: str):
        cls = MagicMock()
        cls.__name__ = name

        def _make_driver(**kwargs):
            attempts.append((name, kwargs["username"]))
            inst = MagicMock()
            inst.connect.side_effect = paramiko.BadHostKeyException("192.0.2.15", MagicMock(), MagicMock())
            return inst

        cls.side_effect = _make_driver
        return cls

    cisco_cls = _make_driver_cls("CiscoDriver")
    arista_cls = _make_driver_cls("AristaDriver")

    creds = [
        {"username": "admin", "password": "pw1"},
        {"username": "netadmin", "password": "pw2"},
    ]
    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("unknown", "")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch("net_docu_crawler.crawler.CiscoDriver", cisco_cls),
        patch("net_docu_crawler.crawler.AristaDriver", arista_cls),
        patch("net_docu_crawler.crawler.JuniperDriver", _make_driver_cls("JuniperDriver")),
        patch("net_docu_crawler.crawler.FortinetDriver", _make_driver_cls("FortinetDriver")),
    ):
        res = crawl_target_with_ports(
            ip="192.0.2.15",
            credentials=creds,
            open_ports=[(22, "ssh")],
            log_file=str(tmp_path / "exec.log"),
        )

    assert res["status"] == "unsupported"
    assert attempts == [("CiscoDriver", "admin")]


def test_log_event_thread_safe_and_scrubs_secrets(tmp_path):
    """TR-13 & SF-11: _log_event must serialize concurrent appends and redact passwords/secrets/communities."""
    from net_docu_crawler import crawler

    assert hasattr(crawler, "_LOG_EVENT_LOCK")

    # Concurrent write stress test across 16 threads
    concurrent_log = tmp_path / "concurrent.log"
    errors: list[Exception] = []

    def _worker(tid: int) -> None:
        try:
            for seq in range(50):
                _log_event(str(concurrent_log), f"worker-{tid}-seq-{seq}")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_worker, args=(tid,)) for tid in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    lines = concurrent_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 800
    line_re = re.compile(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] worker-\d+-seq-\d+$")
    assert all(line_re.match(line) for line in lines)

    # Secret scrubbing in _log_event and _connect_and_crawl_once failure logs
    secret_log = tmp_path / "secrets.log"
    _log_event(str(secret_log), "SNMP failed community=CorpPrivateRO! token=TopSecretTok99 password=InlinePass88")
    _log_event(str(secret_log), "Literal secret SuperSecretValue42 leaked", secrets=("SuperSecretValue42",))

    fake_cls = MagicMock()
    fake_cls.__name__ = "CiscoDriver"
    fake_inst = MagicMock()
    fake_inst.connect.side_effect = RuntimeError("Failed with UltraSecretPwd! and EnableS3cret#")
    fake_cls.return_value = fake_inst

    _connect_and_crawl_once(
        driver_cls=fake_cls,
        ip="192.0.2.16",
        port=22,
        transport="ssh",
        cred={"username": "netops", "password": "UltraSecretPwd!", "secret": "EnableS3cret#"},
        timeout=5,
        session_log="",
        log_file=str(secret_log),
    )

    # Same-as-username password should redact exception text without corrupting "(User: netops)"
    same_pw_inst = MagicMock()
    same_pw_inst.connect.side_effect = RuntimeError("Bad login for netops")
    fake_cls.return_value = same_pw_inst
    _connect_and_crawl_once(
        driver_cls=fake_cls,
        ip="192.0.2.17",
        port=22,
        transport="ssh",
        cred={"username": "netops", "password": "netops", "secret": ""},
        timeout=5,
        session_log="",
        log_file=str(secret_log),
    )

    content = secret_log.read_text(encoding="utf-8")
    for leaked in (
        "CorpPrivateRO!",
        "TopSecretTok99",
        "InlinePass88",
        "SuperSecretValue42",
        "UltraSecretPwd!",
        "EnableS3cret#",
    ):
        assert leaked not in content
    assert "<REDACTED>" in content
    assert "(User: netops)" in content


def test_crawl_target_batch_releases_in_progress_ips_on_exception(tmp_path):
    """TR-13: _crawl_target_batch must release all unregistered in_progress_ips on unexpected exceptions."""
    registry = DeviceRegistry()
    raw_devices: list[dict] = []
    scanned_ip_set: set[str] = set()
    cfg = CrawlOptions(timeout=2, max_workers=2)

    def fake_crawl(ip, *args, **kwargs):
        return {"ip": ip, "hostname": f"host-{ip}", "status": "success"}

    with (
        patch(
            "net_docu_crawler.crawler.scan_subnet_ports",
            return_value={"192.0.2.20": [(22, "ssh")], "192.0.2.21": [(22, "ssh")]},
        ),
        patch("net_docu_crawler.crawler.crawl_target_with_ports", side_effect=fake_crawl),
        patch.object(registry, "register_device", side_effect=RuntimeError("registry boom")),
        pytest.raises(RuntimeError, match="registry boom"),
    ):
        _crawl_target_batch(
            batch_ips=["192.0.2.20", "192.0.2.21"],
            batch_explicit={},
            cfg=cfg,
            credentials=[],
            registry=registry,
            raw_devices=raw_devices,
            scanned_ip_set=scanned_ip_set,
            logs_dir=str(tmp_path),
            crawler_log=str(tmp_path / "exec.log"),
        )

    assert registry.in_progress_ips == set()

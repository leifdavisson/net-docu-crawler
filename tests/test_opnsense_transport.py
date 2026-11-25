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
Regression tests for OPNsense Paramiko transport hardening (`TR-05`, `TR-06`, `TR-07`, `TR-13`, `TR-14` / `SF-08`):
- `allow_agent=False`, `look_for_keys=False`, `channel_timeout` passed on connect
- `supports_telnet = False` and explicit rejection of non-SSH transport
- Client cleanup on every `connect()` failure path
- Channel/stream closing in `finally`, simultaneous stdout/stderr draining,
  non-zero `recv_exit_status()` logging, and wall-clock deadline enforcement
- Context-manager protocol and thread-safe `AuditedMissingHostKeyPolicy`
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import paramiko
import pytest
from paramiko.ssh_exception import AuthenticationException

from net_docu_crawler.drivers.opnsense import (
    AuditedMissingHostKeyPolicy,
    OPNsenseDriver,
    OPNsenseSSHConnection,
)


class _FakeChannel:
    """Minimal Paramiko Channel double supporting chunked stdout/stderr, exit status, and close tracking."""

    def __init__(
        self,
        stdout_chunks: list[bytes],
        stderr_chunks: list[bytes] | None = None,
        exit_status: int = 0,
        trickle_forever: bool = False,
    ) -> None:
        self._stdout = list(stdout_chunks)
        self._stderr = list(stderr_chunks or [])
        self._exit_status = exit_status
        self._trickle_forever = trickle_forever
        self.timeout: float | None = None
        self.closed = False
        self.exit_status_checked = False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def recv_ready(self) -> bool:
        if self._trickle_forever:
            time.sleep(0.02)
            return True
        return bool(self._stdout)

    def recv(self, _nbytes: int) -> bytes:
        if self._trickle_forever:
            return b"x"
        if self._stdout:
            return self._stdout.pop(0)
        return b""

    def recv_stderr_ready(self) -> bool:
        return bool(self._stderr)

    def recv_stderr(self, _nbytes: int) -> bytes:
        if self._stderr:
            return self._stderr.pop(0)
        return b""

    def exit_status_ready(self) -> bool:
        if self._trickle_forever:
            return False
        return not self._stdout and not self._stderr

    def recv_exit_status(self) -> int:
        self.exit_status_checked = True
        return self._exit_status

    def close(self) -> None:
        self.closed = True


class _FakeStream:
    def __init__(self, channel: _FakeChannel, payload: bytes = b"") -> None:
        self.channel = channel
        self._payload = payload
        self.closed = False

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        self.closed = True


def test_opnsense_connect_disables_agent_keys_sets_channel_timeout_and_closes_on_error():
    """TR-05/TR-06/TR-14: allow_agent=False, look_for_keys=False, channel_timeout, supports_telnet=False, cleanup on fail."""
    assert OPNsenseDriver.supports_telnet is False

    telnet_drv = OPNsenseDriver(ip="192.0.2.1", username="root", password="pw", port=23, transport="telnet")
    with pytest.raises(ValueError, match="SSH"):
        telnet_drv.connect()

    drv = OPNsenseDriver(ip="192.0.2.1", username="root", password="pw", timeout=9)
    mock_client = MagicMock(spec=paramiko.SSHClient)
    with (
        patch("net_docu_crawler.drivers.opnsense.paramiko.SSHClient", return_value=mock_client),
        patch("net_docu_crawler.ssh_compat.connect_paramiko_with_fallback") as mock_connect,
    ):
        conn = drv.connect()
        assert isinstance(conn, OPNsenseSSHConnection)
        assert mock_connect.call_count == 1
        kw = mock_connect.call_args[1]
        assert kw["allow_agent"] is False
        assert kw["look_for_keys"] is False
        assert kw["timeout"] == 9
        assert kw["banner_timeout"] == 9
        assert kw["auth_timeout"] == 9
        assert kw["channel_timeout"] == 9

    # On connect failure, client.close() MUST be invoked so sockets/transport threads do not leak
    fail_client = MagicMock(spec=paramiko.SSHClient)
    with (
        patch("net_docu_crawler.drivers.opnsense.paramiko.SSHClient", return_value=fail_client),
        patch(
            "net_docu_crawler.ssh_compat.connect_paramiko_with_fallback",
            side_effect=AuthenticationException("Auth failed"),
        ),
    ):
        with pytest.raises(AuthenticationException):
            drv.connect()
    assert fail_client.close.call_count >= 1


def test_opnsense_exec_drains_stderr_checks_exit_status_and_closes_channel(caplog, tmp_path):
    """TR-05: exec_command reassembles partial reads, drains stderr, logs non-zero exit status, and closes handles."""
    chan = _FakeChannel(
        stdout_chunks=[b"opnsense-", b"fw.lan\n"],
        stderr_chunks=[b"cat: /conf/config.xml: ", b"Permission denied\n"],
        exit_status=1,
    )
    stdin = _FakeStream(chan)
    stdout = _FakeStream(chan)
    stderr = _FakeStream(chan)

    mock_client = MagicMock(spec=paramiko.SSHClient)
    mock_client.exec_command.return_value = (stdin, stdout, stderr)

    log_file = tmp_path / "opn_session.log"
    conn = OPNsenseSSHConnection(
        mock_client,
        session_log=str(log_file),
        timeout=10,
        no_log={"password": "OpnRootPassword!"},
    )
    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.opnsense"):
        out = conn.send_command("cat /conf/config.xml")

    assert out == "opnsense-fw.lan\n"
    assert chan.exit_status_checked is True
    assert chan.closed is True
    assert stdin.closed is True
    assert stdout.closed is True
    assert stderr.closed is True
    assert conn.last_exit_status == 1
    assert "Permission denied" in conn.last_stderr
    assert "exit status 1" in caplog.text.lower() or "non-zero exit" in caplog.text.lower()


def test_opnsense_exec_enforces_wall_clock_deadline_and_closes_channel():
    """TR-05: trickling remote output must still abort at total wall-clock deadline and close channel."""
    chan = _FakeChannel(stdout_chunks=[], trickle_forever=True)
    stdin = _FakeStream(chan)
    stdout = _FakeStream(chan)
    stderr = _FakeStream(chan)

    mock_client = MagicMock(spec=paramiko.SSHClient)
    mock_client.exec_command.return_value = (stdin, stdout, stderr)

    conn = OPNsenseSSHConnection(mock_client, timeout=1)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        conn.send_command("cat /conf/config.xml", timeout=0.15)
    elapsed = time.monotonic() - t0

    assert elapsed < 1.5
    assert chan.closed is True
    assert stdin.closed is True
    assert stdout.closed is True
    assert stderr.closed is True


def test_opnsense_connection_context_manager_and_secret_scrubbing(tmp_path):
    """TR-07 & SF-11: OPNsenseSSHConnection supports context manager cleanup and scrubs secrets from session log."""
    mock_client = MagicMock(spec=paramiko.SSHClient)
    with pytest.raises(RuntimeError, match="crawl-err"):
        with OPNsenseSSHConnection(mock_client) as conn:
            assert conn.client is mock_client
            raise RuntimeError("crawl-err")
    assert mock_client.close.call_count == 1

    # Session log redacts configured no_log password
    chan = _FakeChannel(stdout_chunks=[b"<password>MySecretOpnPw!</password>\n"], exit_status=0)
    mock_client2 = MagicMock(spec=paramiko.SSHClient)
    mock_client2.exec_command.return_value = (_FakeStream(chan), _FakeStream(chan), _FakeStream(chan))
    log_path = tmp_path / "scrubbed.log"
    conn2 = OPNsenseSSHConnection(
        mock_client2,
        session_log=str(log_path),
        no_log={"password": "MySecretOpnPw!"},
    )
    conn2.send_command("cat /conf/config.xml")
    logged = log_path.read_text(encoding="utf-8")
    assert "MySecretOpnPw!" not in logged
    assert "<REDACTED>" in logged or "********" in logged


def test_audited_host_key_policy_has_lock_and_is_thread_safe():
    """TR-13: AuditedMissingHostKeyPolicy guards _warned_host_keys with a threading.Lock."""
    assert hasattr(AuditedMissingHostKeyPolicy, "_warned_lock")
    assert isinstance(AuditedMissingHostKeyPolicy._warned_lock, type(threading.Lock()))

    AuditedMissingHostKeyPolicy._warned_host_keys.clear()
    fake_key = MagicMock()
    fake_key.get_name.return_value = "ssh-ed25519"
    fake_key.asbytes.return_value = b"test-ed25519-key-bytes"
    client = MagicMock()

    def _warn(idx: int) -> None:
        AuditedMissingHostKeyPolicy().missing_host_key(client, f"192.0.2.{idx % 4}", fake_key)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_warn, i) for i in range(64)]
        for fut in futs:
            fut.result()

    assert len(AuditedMissingHostKeyPolicy._warned_host_keys) == 4

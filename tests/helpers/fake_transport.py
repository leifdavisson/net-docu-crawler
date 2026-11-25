# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Offline Netmiko and Paramiko transport mocks with Zero-Blast-Radius read-only
command enforcement, `--More--` interactive paging simulation, failure injection,
and VTY/SSH session cleanup tracking.

Upstream References:
- Netmiko: https://github.com/ktbyers/netmiko
- Paramiko: https://www.paramiko.org/
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


class ZeroBlastViolationError(AssertionError):
    """Raised when a driver or test attempts to send a write/config/destructive command."""


# Explicitly allowed non-persistent session-scoped commands (see SWARM/command_allowlist.md)
_SESSION_SCOPED_ALLOW_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(?:terminal\s+(?:length\s+0|width\s+\d+|datadump))$", re.IGNORECASE),
    re.compile(r"^(?:no\s+pag(?:e|ing))$", re.IGNORECASE),
    re.compile(
        r"^set\s+cli\s+(?:screen-length\s+0|screen-width\s+\d+|complete-on-space\s+off|pager\s+off|scripting-mode\s+on|terminal\s+width\s+\d+)$",
        re.IGNORECASE,
    ),
    re.compile(r"^(?:enable|exit|quit|logout|cli|a|y|n)$", re.IGNORECASE),
)

# Forbidden mutating, config-mode, or state-clearing CLI verbs/prefixes
_FORBIDDEN_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("config-mode", re.compile(r"(?:^|[;\n|&])\s*conf(?:ig(?:ure)?)?(?:\s|$)", re.IGNORECASE)),
    ("write/save", re.compile(r"(?:^|[;\n|&])\s*(?:write|wr\b|save|copy\s+run)", re.IGNORECASE)),
    ("commit", re.compile(r"(?:^|[;\n|&])\s*(?:commit|uci\s+(?:set|add|del(?:ete)?|commit|revert))\b", re.IGNORECASE)),
    (
        "reload/reboot",
        re.compile(r"(?:^|[;\n|&])\s*(?:reload|reboot|shutdown|poweroff|halt|/system\s+reset)\b", re.IGNORECASE),
    ),
    (
        "clear/delete/erase",
        re.compile(r"(?:^|[;\n|&])\s*(?:clear|delete|erase|format|request\s+system)\b", re.IGNORECASE),
    ),
    (
        "package-mgmt",
        re.compile(r"(?:^|[;\n|&])\s*(?:opkg|apt|apt-get|yum|dnf|pkg)\s+(?:install|remove|upgrade)", re.IGNORECASE),
    ),
    ("set-config", re.compile(r"(?:^|[;\n|&])\s*(?:set|unset|edit)\s+", re.IGNORECASE)),
    ("sudo-shell", re.compile(r"(?:^|[;\n|&])\s*sudo\b", re.IGNORECASE)),
)


def assert_readonly_command(command: str) -> None:
    """
    Validate that ``command`` is strictly read-only or an approved non-persistent
    session-scoped terminal command. Raises ``ZeroBlastViolationError`` otherwise.
    """
    if command == " " or command == "":
        return
    stripped = command.strip()
    if not stripped:
        return

    # Check multi-line commands line by line (e.g. FortiOS `config system console\nset output standard\nend`)
    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    for line in lines:
        if any(pat.match(line) for pat in _SESSION_SCOPED_ALLOW_PATTERNS):
            continue
        for reason, pat in _FORBIDDEN_COMMAND_PATTERNS:
            if pat.search(line):
                raise ZeroBlastViolationError(f"Zero-Blast-Radius violation ({reason}): forbidden command {line!r}")


def parse_transcript_blocks(text: str) -> tuple[str, dict[str, str]]:
    """
    Parse a scrubbed fixture transcript into ``(prompt, commands_map)``.

    Supports:
      1. Canonical ``--- COMMAND: <cmd> ---`` delimited fixtures (with optional
         ``# PROMPT: <prompt>`` metadata header and ``#`` comment preamble).
      2. Raw CLI prompt-delimited logs (``<prompt><cmd>``).
    """
    cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    cleaned = re.sub(r"\[(?:\?[0-9;]*[hl]|[0-9;]*[HJKr])", "", cleaned).replace("\r", "")
    lines = cleaned.splitlines()

    prompt = ""
    for ln in lines[:20]:
        m_prompt = re.match(r"^#\s*PROMPT:\s*(.+?)\s*$", ln)
        if m_prompt:
            prompt = m_prompt.group(1)
            break

    commands: dict[str, str] = {}
    if "--- COMMAND:" in cleaned:
        cur_cmd: str | None = None
        cur_buf: list[str] = []
        for ln in lines:
            m_cmd = re.match(r"^---\s*COMMAND:\s*(.+?)\s*---\s*$", ln)
            if m_cmd:
                if cur_cmd is not None:
                    commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
                cur_cmd = m_cmd.group(1).strip()
                cur_buf = []
            elif cur_cmd is not None:
                cur_buf.append(ln)
        if cur_cmd is not None:
            commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
        return prompt, commands

    # Fallback: prompt-delimited CLI transcript
    base_prompt = ""
    prompt_re = None
    for ln in lines:
        if ln.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\[?[A-Za-z0-9._@:~/-]+\]?)(?:\s*\([^)]+\))?\s*[#>$]\s*([a-zA-Z/].*)$", ln)
        if m:
            base_prompt = m.group(1)
            prompt_re = re.compile(rf"^{re.escape(base_prompt)}(?:\s*\([^)]+\))?\s*[#>$]\s*(.*)$")
            break
    if not prompt_re:
        return prompt, commands

    cur_cmd = None
    cur_buf = []
    for ln in lines:
        m = prompt_re.match(ln)
        if m:
            if cur_cmd is not None:
                while cur_buf and (
                    not cur_buf[-1].strip() or re.match(r"^\{(?:master|backup|linecard):\d+\}$", cur_buf[-1].strip())
                ):
                    cur_buf.pop()
                commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
            cmd_part = m.group(1).strip()
            if not prompt and "(" not in ln.split("#", 1)[0].split(">", 1)[0]:
                sep = "#" if "#" in ln else (">" if ">" in ln else "$")
                prompt = ln.split(sep, 1)[0] + sep
            cur_cmd = cmd_part if cmd_part else None
            cur_buf = []
        elif cur_cmd is not None:
            cur_buf.append(ln)
    if cur_cmd is not None:
        while cur_buf and (
            not cur_buf[-1].strip() or re.match(r"^\{(?:master|backup|linecard):\d+\}$", cur_buf[-1].strip())
        ):
            cur_buf.pop()
        commands[cur_cmd] = "\n".join(cur_buf).strip("\n")

    return prompt, commands


class FakeNetmikoConnection:
    """
    Deterministic offline Netmiko-compatible connection double.

    Features:
      - Exact & case-insensitive command lookup from a dict or scrubbed `.txt` fixture.
      - Strict Zero-Blast-Radius read-only enforcement (default `enforce_readonly=True`).
      - Hard-blocked Netmiko config/write APIs (`config_mode`, `send_config_set`,
        `send_config_from_file`, `save_config`).
      - Simulated `--More--` interactive chunked paging via `write_channel` / `read_channel`.
      - Failure injection (`fail_on_command`, `enable_error`, `disconnect_after`).
      - Lifecycle tracking (`commands_sent`, `disconnected`, `assert_closed()`).
    """

    def __init__(
        self,
        commands: dict[str, str] | None = None,
        *,
        prompt: str = "device#",
        enforce_readonly: bool = True,
        paged_commands: dict[str, list[str]] | None = None,
        pager_prompt: str = "--More-- ",
        fail_on_command: dict[str, Exception] | None = None,
        enable_error: Exception | None = None,
        disconnect_after: int | None = None,
    ) -> None:
        self.commands: dict[str, str] = dict(commands or {})
        self.prompt: str = prompt
        self.base_prompt: str = prompt.rstrip("#>$ ").strip() or "device"
        self.enforce_readonly: bool = enforce_readonly
        self.paged_commands: dict[str, list[str]] = {k: list(v) for k, v in (paged_commands or {}).items()}
        self.pager_prompt: str = pager_prompt
        self.fail_on_command: dict[str, Exception] = dict(fail_on_command or {})
        self.enable_error: Exception | None = enable_error
        self.disconnect_after: int | None = disconnect_after

        self.commands_sent: list[str] = []
        self.raw_writes: list[str] = []
        self.enabled: bool = prompt.rstrip().endswith("#")
        self.disconnected: bool = False
        self.disconnect_count: int = 0
        self.cleanup_called: bool = False

        # Interactive channel state for --More-- pager testing
        self._channel_buffer: str = ""
        self._active_pages: list[str] = []
        self._active_page_idx: int = 0

    @classmethod
    def from_transcript_text(cls, text: str, **kwargs: Any) -> FakeNetmikoConnection:
        prompt, commands = parse_transcript_blocks(text)
        kwargs.setdefault("prompt", prompt or "device#")
        return cls(commands=commands, **kwargs)

    @classmethod
    def from_transcript_file(cls, path: str | Path, **kwargs: Any) -> FakeNetmikoConnection:
        p = Path(path)
        return cls.from_transcript_text(p.read_text(encoding="utf-8"), **kwargs)

    def _lookup_command(self, mapping: dict[str, Any], cmd: str) -> tuple[bool, Any]:
        if cmd in mapping:
            return True, mapping[cmd]
        cmd_l = cmd.lower()
        for k, v in mapping.items():
            if k.lower() == cmd_l:
                return True, v
        return False, None

    def _check_alive(self) -> None:
        if self.disconnected:
            raise ConnectionError("FakeNetmikoConnection is already disconnected")
        if self.disconnect_after is not None and len(self.commands_sent) >= self.disconnect_after:
            self.disconnected = True
            raise ConnectionError("Simulated mid-crawl disconnect")

    def is_alive(self) -> bool:
        return not self.disconnected

    def find_prompt(self, **_kwargs: Any) -> str:
        self._check_alive()
        return self.prompt

    def enable(self, **_kwargs: Any) -> str:
        self._check_alive()
        self.commands_sent.append("enable")
        if self.enable_error is not None:
            raise self.enable_error
        self.enabled = True
        if self.prompt.rstrip().endswith(">"):
            self.prompt = self.prompt.rstrip()[:-1] + "#"
        return self.prompt

    def disable_paging(self, command: str = "terminal length 0", **_kwargs: Any) -> str:
        self._check_alive()
        if self.enforce_readonly:
            assert_readonly_command(command)
        self.commands_sent.append(command)
        return ""

    def send_command(self, command_string: str, **_kwargs: Any) -> str:
        self._check_alive()
        cmd = command_string.strip()
        if self.enforce_readonly:
            assert_readonly_command(cmd)
        self.commands_sent.append(cmd)

        has_err, err = self._lookup_command(self.fail_on_command, cmd)
        if has_err:
            raise err

        has_paged, pages = self._lookup_command(self.paged_commands, cmd)
        if has_paged:
            return "\n".join(pages)

        found, output = self._lookup_command(self.commands, cmd)
        return output if found else ""

    def send_command_timing(self, command_string: str, **kwargs: Any) -> str:
        return self.send_command(command_string, **kwargs)

    # Interactive channel emulation for read-only --More-- pager drainer tests
    def write_channel(self, out_data: str) -> None:
        self._check_alive()
        self.raw_writes.append(out_data)

        # Space advances an active --More-- paged command without mutating state
        if self._active_pages and out_data in (" ", " \r", " \n"):
            self._active_page_idx += 1
            if self._active_page_idx < len(self._active_pages):
                chunk = self._active_pages[self._active_page_idx]
                is_last = self._active_page_idx == len(self._active_pages) - 1
                suffix = f"\n{self.prompt}" if is_last else f"\n{self.pager_prompt}"
                self._channel_buffer += chunk + suffix
                if is_last:
                    self._active_pages = []
                    self._active_page_idx = 0
            return

        # Abort pager with 'q'
        if self._active_pages and out_data.strip().lower() == "q":
            self._active_pages = []
            self._active_page_idx = 0
            self._channel_buffer += f"\n{self.prompt}"
            return

        cmd = out_data.strip()
        if self.enforce_readonly:
            assert_readonly_command(cmd)
        if not cmd:
            self._channel_buffer += f"\n{self.prompt}"
            return

        self.commands_sent.append(cmd)
        has_err, err = self._lookup_command(self.fail_on_command, cmd)
        if has_err:
            raise err

        has_paged, pages = self._lookup_command(self.paged_commands, cmd)
        if has_paged and pages:
            self._active_pages = list(pages)
            self._active_page_idx = 0
            is_last = len(self._active_pages) == 1
            suffix = f"\n{self.prompt}" if is_last else f"\n{self.pager_prompt}"
            self._channel_buffer += f"{cmd}\n{self._active_pages[0]}{suffix}"
            if is_last:
                self._active_pages = []
            return

        found, output = self._lookup_command(self.commands, cmd)
        body = output if found else ""
        self._channel_buffer += f"{cmd}\n{body}\n{self.prompt}"

    def read_channel(self) -> str:
        data = self._channel_buffer
        self._channel_buffer = ""
        return data

    def clear_buffer(self) -> str:
        return self.read_channel()

    # Hard-blocked Netmiko write/config methods (Zero-Blast-Radius)
    def config_mode(self, *_args: Any, **_kwargs: Any) -> str:
        raise ZeroBlastViolationError("Zero-Blast-Radius violation: config_mode() is forbidden")

    def send_config_set(self, *_args: Any, **_kwargs: Any) -> str:
        raise ZeroBlastViolationError("Zero-Blast-Radius violation: send_config_set() is forbidden")

    def send_config_from_file(self, *_args: Any, **_kwargs: Any) -> str:
        raise ZeroBlastViolationError("Zero-Blast-Radius violation: send_config_from_file() is forbidden")

    def save_config(self, *_args: Any, **_kwargs: Any) -> str:
        raise ZeroBlastViolationError("Zero-Blast-Radius violation: save_config() is forbidden")

    def cleanup(self, command: str = "exit") -> None:
        if self.enforce_readonly:
            assert_readonly_command(command)
        self.cleanup_called = True

    def disconnect(self) -> None:
        self.disconnected = True
        self.disconnect_count += 1

    def __enter__(self) -> FakeNetmikoConnection:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.disconnect()

    def assert_closed(self) -> None:
        assert self.disconnected and self.disconnect_count >= 1, (
            "Expected FakeNetmikoConnection.disconnect() to be called (VTY session leak)"
        )

    def assert_only_readonly_commands(self) -> None:
        for cmd in self.commands_sent:
            assert_readonly_command(cmd)


class FakeParamikoChannel:
    """Minimal Paramiko channel double supporting exit status and timeout reads."""

    def __init__(self, exit_status: int = 0) -> None:
        self._exit_status = exit_status
        self.closed = False
        self.timeout: float | None = None

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def recv_exit_status(self) -> int:
        return self._exit_status

    def close(self) -> None:
        self.closed = True


class FakeParamikoStream:
    """Minimal Paramiko stdin/stdout/stderr stream double returning bytes."""

    def __init__(self, data: str | bytes = b"", exit_status: int = 0) -> None:
        self._data = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        self.channel = FakeParamikoChannel(exit_status=exit_status)
        self.closed = False

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        self.closed = True


class FakeParamikoTransport:
    """Minimal Paramiko Transport double for active/close checks."""

    def __init__(self, active: bool = True) -> None:
        self._active = active
        self.closed = False

    def is_active(self) -> bool:
        return self._active and not self.closed

    def close(self) -> None:
        self.closed = True
        self._active = False


class FakeParamikoClient:
    """
    Deterministic offline drop-in double for ``paramiko.SSHClient``.

    Supports:
      - Staged ``connect_side_effects`` for testing 3-stage SSH fallback ladders.
      - Host-key policy capture & optional ``missing_host_key`` callback invocation.
      - Per-command stdout/stderr/exit-status responses & failure injection.
      - Strict Zero-Blast-Radius read-only enforcement on every ``exec_command``.
      - ``close()`` leak detection via ``assert_closed()``.
    """

    def __init__(
        self,
        commands: dict[str, str | tuple[str, str, int]] | None = None,
        *,
        enforce_readonly: bool = True,
        connect_side_effects: list[Exception | None] | None = None,
        fail_on_command: dict[str, Exception] | None = None,
        server_host_key: Any = None,
    ) -> None:
        self.commands: dict[str, str | tuple[str, str, int]] = dict(commands or {})
        self.enforce_readonly: bool = enforce_readonly
        self._connect_side_effects: list[Exception | None] = list(connect_side_effects or [])
        self.fail_on_command: dict[str, Exception] = dict(fail_on_command or {})
        self.server_host_key = server_host_key

        self.host_key_policy: Any = None
        self.system_host_keys_loaded: bool = False
        self.loaded_host_key_files: list[str] = []
        self.connect_calls: list[dict[str, Any]] = []
        self.exec_calls: list[tuple[str, Any]] = []
        self.connected: bool = False
        self.closed: bool = False
        self.close_count: int = 0
        self._transport: FakeParamikoTransport | None = None

    @classmethod
    def from_transcript_file(cls, path: str | Path, **kwargs: Any) -> FakeParamikoClient:
        _prompt, commands = parse_transcript_blocks(Path(path).read_text(encoding="utf-8"))
        return cls(commands=commands, **kwargs)

    def load_system_host_keys(self, filename: str | None = None) -> None:
        self.system_host_keys_loaded = True
        if filename:
            self.loaded_host_key_files.append(filename)

    def load_host_keys(self, filename: str) -> None:
        self.loaded_host_key_files.append(filename)

    def set_missing_host_key_policy(self, policy: Any) -> None:
        self.host_key_policy = policy

    def connect(self, hostname: str, **kwargs: Any) -> None:
        call = {"hostname": hostname, **kwargs}
        self.connect_calls.append(call)

        if self._connect_side_effects:
            outcome = self._connect_side_effects.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome

        if self.server_host_key is not None and self.host_key_policy is not None:
            self.host_key_policy.missing_host_key(self, hostname, self.server_host_key)

        self.connected = True
        self.closed = False
        self._transport = FakeParamikoTransport(active=True)

    def get_transport(self) -> FakeParamikoTransport | None:
        return self._transport

    def exec_command(
        self,
        command: str,
        bufsize: int = -1,
        timeout: float | None = None,
        get_pty: bool = False,
        environment: dict[str, str] | None = None,
    ) -> tuple[FakeParamikoStream, FakeParamikoStream, FakeParamikoStream]:
        _ = (bufsize, get_pty, environment)
        if self.closed:
            raise ConnectionError("FakeParamikoClient is already closed")
        cmd = command.strip()
        if self.enforce_readonly:
            assert_readonly_command(cmd)
        self.exec_calls.append((cmd, timeout))

        if cmd in self.fail_on_command:
            raise self.fail_on_command[cmd]

        resp = self.commands.get(cmd)
        if resp is None:
            for k, v in self.commands.items():
                if k.lower() == cmd.lower():
                    resp = v
                    break

        if isinstance(resp, tuple):
            out_str, err_str, rc = resp
        else:
            out_str, err_str, rc = (resp or ""), "", 0

        return (
            FakeParamikoStream(b"", exit_status=rc),
            FakeParamikoStream(out_str, exit_status=rc),
            FakeParamikoStream(err_str, exit_status=rc),
        )

    def close(self) -> None:
        self.closed = True
        self.connected = False
        self.close_count += 1
        if self._transport is not None:
            self._transport.close()

    def __enter__(self) -> FakeParamikoClient:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def assert_closed(self) -> None:
        assert self.closed and self.close_count >= 1, (
            "Expected FakeParamikoClient.close() to be called (SSH session leak)"
        )

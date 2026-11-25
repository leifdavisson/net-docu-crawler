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
Fortinet Driver: FortiGate Firewalls running FortiOS.
Official Documentation: https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference
"""

import importlib
import logging
import re
import time
from typing import Any

from netmiko.exceptions import ReadTimeout
from netmiko.fortinet.fortinet_ssh import FortinetSSH

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

FORTINET_READONLY_DEVICE_TYPE = "fortinet_readonly"
FORTIOS_VIRTUAL_PSEUDO_PREFIXES = ("naf.", "l2t.", "ssl.", "vsw.", "npu")

_FORTIOS_WRITE_VERBS = frozenset(
    {
        "config",
        "set",
        "unset",
        "delete",
        "purge",
        "execute",
        "edit",
        "append",
        "rename",
        "move",
        "end",
        "next",
        "abort",
        "fnsysctl",
    }
)
_FORTIOS_CLI_ERROR_RE = re.compile(
    r"(?:command parse error|command fail\.?\s*return code|ambiguous command|"
    r"unknown action|invalid command|not enough privileges|entry not found)",
    re.IGNORECASE,
)
_MORE_TAIL_RE = re.compile(r"--More--[ \t]*$", re.IGNORECASE)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_MAC_TOKEN_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ZERO_MAC = "00:00:00:00:00:00"
_UPTIME_SUFFIX_RE = re.compile(
    r",\s*(?:\d{2}:\d{2}:\d{2}|(?=\d+[ywdhms])(?:\d+y)?(?:\d+w)?(?:\d+d)?(?:\d+h)?(?:\d+m)?(?:\d+s)?)$",
    re.IGNORECASE,
)


def _is_fortios_cli_error(raw: str) -> bool:
    """Return True if FortiOS CLI output contains a command syntax, privilege, or runtime error."""
    return bool(raw and _FORTIOS_CLI_ERROR_RE.search(raw))


def _strip_pager_and_ansi(text: str) -> str:
    """Strip ANSI escape sequences, --More-- pager prompts, and CR/backspace erase artifacts."""
    cleaned = _ANSI_ESCAPE_RE.sub("", text)
    cleaned = cleaned.replace("\r\n", "\n")
    # Collapse backspace erase sequences used by interactive terminals
    while "\x08" in cleaned:
        new_cleaned = re.sub(r"[^\n]?\x08", "", cleaned)
        if new_cleaned == cleaned:
            cleaned = cleaned.replace("\x08", "")
            break
        cleaned = new_cleaned
    # FortiOS erases "--More-- " using "\r         \r" before printing the next line
    cleaned = re.sub(r"\r[ \t]*\r", "", cleaned)
    cleaned = re.sub(r"--More--[ \t]*", "", cleaned, flags=re.IGNORECASE)
    # Collapse any residual single-line carriage-return overwrites
    lines = []
    for line in cleaned.split("\n"):
        if "\r" in line:
            parts = [p for p in line.split("\r") if p.strip() != ""]
            line = parts[-1] if parts else ""
        lines.append(line)
    return "\n".join(lines)


def _normalize_fortios_speed(raw_speed: str) -> tuple[str, str]:
    """Convert FortiOS `get system interface physical` speed strings to canonical (speed, duplex)."""
    if not raw_speed:
        return "N/A", "N/A"
    low = raw_speed.lower()
    if "n/a" in low or "auto" in low and not re.search(r"\d", low):
        return "N/A", "N/A"

    duplex = "N/A"
    if "full" in low:
        duplex = "Full"
    elif "half" in low:
        duplex = "Half"

    m_num = re.search(r"(\d+)\s*(?:mbps|mb/s|gbps|gb/s|full|half)?", low)
    if not m_num:
        return "N/A", duplex

    val = int(m_num.group(1))
    if "gb" in low:
        speed = f"{val}Gb/s"
    elif val >= 1000:
        if val % 1000 == 0:
            speed = f"{val // 1000}Gb/s"
        else:
            speed = f"{val / 1000:g}Gb/s"
    elif val > 0:
        speed = f"{val}Mb/s"
    else:
        speed = "N/A"
    return speed, duplex


def _clean_fortios_route_intf(raw_tail: str) -> str:
    """Strip trailing FortiOS uptime, weight/priority brackets, and route state suffixes from interface names."""
    intf = raw_tail.strip()
    while intf:
        prev = intf
        intf = re.sub(r",\s*\[\d+/\d+\]$", "", intf).strip()
        intf = _UPTIME_SUFFIX_RE.sub("", intf).strip()
        intf = re.sub(r",\s*(?:in)?active$", "", intf, flags=re.IGNORECASE).strip()
        if intf == prev:
            break
    return intf


def _classify_lldp_device_type(
    capabilities: str = "", platform: str = "", remote_device: str = "", remote_mac: str = ""
) -> str:
    """Infer canonical neighbor device_type from LLDP capabilities, platform text, and OUI vendor."""
    caps_low = (capabilities or "").lower()
    plat_low = (platform or "").lower()
    name_low = (remote_device or "").lower()
    vendor_low = (oui_lookup.lookup_oui(remote_mac) if remote_mac else "").lower()

    if any(k in caps_low for k in ("wlan", "access point")) or any(
        k in plat_low for k in ("instant", "access point", "aironet", "unifi ap", "fortiap", "ruckus", "meraki mr")
    ):
        return "ap"
    if any(k in caps_low for k in ("telephone", "phone")) or any(
        k in plat_low for k in ("ip phone", "polycom", "yealink", "avaya", "mitel", "sip phone")
    ):
        return "phone"
    if any(k in plat_low for k in ("camera", "axis ", "hikvision", "verkada", "hanwha")):
        return "camera"
    if any(k in plat_low for k in ("fortigate", "palo alto", "pan-os", "opnsense", "pfsense", "srx", "firewall")):
        return "firewall"
    if "router" in caps_low and "bridge" not in caps_low and "switch" not in plat_low:
        return "router"
    if any(
        k in plat_low for k in ("fortiswitch", "procurve", "catalyst", "nexus", "ex2300", "ex3300", "ex4300", "switch")
    ):
        return "switch"
    if not plat_low and any(k in vendor_low for k in ("aruba", "ruckus", "mist", "cambium")):
        if name_low.startswith(("ap", "iap")) or "ap-" in name_low or "-ap" in name_low or "wlan" in caps_low:
            return "ap"
    return "switch"


class ReadOnlyFortinetSSH(FortinetSSH):
    """
    Strictly read-only Netmiko SSH handler for Fortinet FortiOS appliances.

    Zero-Blast-Radius guarantees:
    - Never enters ``config system console`` / ``set output standard`` / ``config global`` / ``end``
      during ``session_preparation``, ``disable_paging``, or ``cleanup``.
    - Preserves modern SSH KEX algorithms passed by the caller (no legacy-only KEX stripping).
    - Hard-blocks all config/write APIs and write-prefixed commands in ``send_command()``.
    - Drains interactive ``--More--`` prompts with a single space bounded by ``read_timeout``,
      total wall-clock deadline, and ``max_pages`` (exiting cleanly with ``q`` on cap).
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Bypass FortinetSSH.__init__ so modern KEX (curve25519-sha256, dh-group14-sha256)
        # are NOT stripped and caller disabled_algorithms is preserved verbatim.
        super(FortinetSSH, self).__init__(*args, **kwargs)

    @staticmethod
    def _assert_readonly_command(command_string: str) -> None:
        """Raise RuntimeError if any clause in command_string attempts a write/config operation."""
        if not command_string:
            return
        for clause in re.split(r"[\r\n;]+", command_string):
            stripped = clause.strip()
            if not stripped:
                continue
            first_word = stripped.split(None, 1)[0].lower()
            if first_word in _FORTIOS_WRITE_VERBS:
                raise RuntimeError(
                    f"Zero-Blast-Radius violation: config/write command '{first_word}' is forbidden on FortiOS"
                )

    def session_preparation(self) -> None:
        """Accept optional post-login banner and learn base prompt without writing any config."""
        data = self._test_channel_read(pattern=f"to accept|{self.prompt_pattern}")
        if "to accept" in data:
            self.write_channel("a\r")
            self._test_channel_read(pattern=self.prompt_pattern)
        self.set_base_prompt()
        self._vdoms = False
        self._original_output_mode = "more"
        self._output_mode = "more"

    def disable_paging(self, *args: Any, **kwargs: Any) -> str:
        """Strict no-op: FortiOS paging is handled read-only inside send_command()."""
        return ""

    def cleanup(self, command: str = "exit") -> None:
        """Gracefully exit the FortiOS CLI without modifying console output mode."""
        safe_cmd = command.strip() if command and command.strip().lower() in ("exit", "quit", "logout") else "exit"
        self._session_log_fin = True
        try:
            self.write_channel(f"{safe_cmd}{self.RETURN}")
        except Exception:
            pass

    def _forbid_write(self, op_name: str) -> Any:
        raise RuntimeError(f"Zero-Blast-Radius violation: {op_name}() is forbidden on read-only FortiOS sessions")

    def config_mode(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("config_mode")

    def send_config_set(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("send_config_set")

    def send_config_from_file(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("send_config_from_file")

    def save_config(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("save_config")

    def _config_global(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("_config_global")

    def _exit_config_global(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("_exit_config_global")

    def send_multiline(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("send_multiline")

    def send_multiline_timing(self, *args: Any, **kwargs: Any) -> str:
        return self._forbid_write("send_multiline_timing")

    def _build_prompt_regex(self, expect_string: str | None = None) -> re.Pattern[str]:
        if expect_string:
            return re.compile(expect_string)
        base = (getattr(self, "base_prompt", "") or "").strip()
        if base:
            return re.compile(rf"(?m)^\s*{re.escape(base)}(?:\s*\([^)]+\))?\s*[#$]\s*$")
        return re.compile(r"(?m)^[^\r\n]+[#$]\s*$")

    def _drain_after_quit(self, prompt_re: re.Pattern[str], timeout_s: float, poll_interval: float) -> None:
        """Drain trailing prompt bytes after sending 'q' to exit the FortiOS pager cleanly."""
        deadline = time.monotonic() + max(0.05, min(timeout_s, 1.0))
        tail = ""
        while time.monotonic() < deadline:
            chunk = self.read_channel()
            if chunk:
                tail += chunk
                cleaned_tail = _strip_pager_and_ansi(tail)
                last_line = cleaned_tail.rsplit("\n", 1)[-1]
                if prompt_re.search(last_line):
                    return
            else:
                time.sleep(min(poll_interval, 0.02))

    def send_command(
        self,
        command_string: str,
        expect_string: str | None = None,
        read_timeout: float = 15.0,
        strip_prompt: bool = True,
        strip_command: bool = True,
        max_pages: int | None = None,
        poll_interval: float = 0.05,
        total_timeout: float | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Execute a strictly read-only FortiOS command and drain any ``--More--`` pager output.
        """
        self._assert_readonly_command(command_string)

        cmd_clean = command_string.rstrip()
        if max_pages is None:
            page_cap = 2000 if cmd_clean.lower().startswith("show full-configuration") else 200
        else:
            page_cap = max(0, int(max_pages))

        eff_read_timeout = max(0.01, float(read_timeout if read_timeout is not None else 15.0))
        if total_timeout is not None:
            eff_total_timeout = max(eff_read_timeout, float(total_timeout))
        elif eff_read_timeout < 1.0:
            eff_total_timeout = max(eff_read_timeout * 4.0, 0.5)
        else:
            eff_total_timeout = max(
                eff_read_timeout * 4.0, 120.0 if "full-configuration" in cmd_clean.lower() else 60.0
            )

        eff_poll = max(0.005, min(float(poll_interval), 0.1))
        prompt_re = self._build_prompt_regex(expect_string)

        self.clear_buffer()
        self.write_channel(f"{cmd_clean}{self.RETURN}")

        buf = ""
        pages_sent = 0
        in_pager = False
        start_t = time.monotonic()
        last_data_t = start_t

        while True:
            chunk = self.read_channel()
            now = time.monotonic()
            if chunk:
                last_data_t = now
                buf += chunk

                # Inspect current trailing line for --More-- pager or CLI prompt
                tail_raw = buf.rsplit("\n", 1)[-1]
                tail_no_ansi = _ANSI_ESCAPE_RE.sub("", tail_raw)
                tail_visible = tail_no_ansi.rsplit("\r", 1)[-1]

                if _MORE_TAIL_RE.search(tail_visible):
                    # Remove the matched trailing --More-- so it cannot re-trigger
                    buf = _MORE_TAIL_RE.sub("", buf)
                    if pages_sent >= page_cap:
                        logger.warning(
                            "[%s] FortiOS command '%s' reached max_pages=%d; exiting pager cleanly with 'q'",
                            getattr(self, "host", "unknown"),
                            cmd_clean,
                            page_cap,
                        )
                        try:
                            self.write_channel("q")
                            self._drain_after_quit(prompt_re, eff_read_timeout, eff_poll)
                        except Exception:
                            pass
                        break
                    in_pager = True
                    pages_sent += 1
                    self.write_channel(" ")
                    continue

                if prompt_re.search(tail_visible):
                    break
            else:
                if (now - last_data_t) >= eff_read_timeout or (now - start_t) >= eff_total_timeout:
                    if in_pager:
                        try:
                            self.write_channel("q")
                        except Exception:
                            pass
                    raise ReadTimeout(
                        f"Timed out waiting for FortiOS prompt on '{cmd_clean}' "
                        f"(read_timeout={eff_read_timeout}s, pages={pages_sent})"
                    )
                time.sleep(eff_poll)

        output = _strip_pager_and_ansi(buf)
        lines = output.split("\n")

        if strip_command and lines:
            # Strip echoed command on the first non-empty line
            idx = 0
            while idx < len(lines) and not lines[idx].strip():
                idx += 1
            if idx < len(lines) and lines[idx].strip() == cmd_clean.strip():
                lines = lines[idx + 1 :]

        if strip_prompt:
            while lines and not lines[-1].strip():
                lines.pop()
            if lines and prompt_re.search(lines[-1]):
                lines.pop()

        return "\n".join(lines).strip("\n")


def _register_readonly_fortinet_driver() -> None:
    """Register ReadOnlyFortinetSSH into Netmiko's ssh_dispatcher module."""
    dispatcher = importlib.import_module("netmiko.ssh_dispatcher")
    dispatcher.CLASS_MAPPER[FORTINET_READONLY_DEVICE_TYPE] = ReadOnlyFortinetSSH
    dispatcher.CLASS_MAPPER_BASE[FORTINET_READONLY_DEVICE_TYPE] = ReadOnlyFortinetSSH
    if FORTINET_READONLY_DEVICE_TYPE not in dispatcher.platforms:
        dispatcher.platforms.append(FORTINET_READONLY_DEVICE_TYPE)


_register_readonly_fortinet_driver()


class FortinetDriver(BaseDriver):
    """
    Driver for Fortinet FortiGate appliances running FortiOS.
    Persona: firewall.
    """

    vendor_name = "Fortinet"
    device_persona = "firewall"
    default_device_type = "firewall"
    supports_telnet = False
    paging_cmd = ""

    def connect(self):
        device = self._build_netmiko_params(FORTINET_READONLY_DEVICE_TYPE, global_delay_factor=2)
        return self.connect_netmiko(device)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "FortiGate Firewall",
            "serial": "Unknown",
            "firmware": "FortiOS",
            "os_type": "fortinet",
            "device_persona": "firewall",
        }
        try:
            raw = conn.send_command("get system status")
            if _is_fortios_cli_error(raw):
                logger.warning("[%s] FortiOS 'get system status' returned CLI error: %s", self.ip, raw.strip()[:160])
            else:
                m_host = re.search(r"Hostname:\s*(\S+)", raw)
                if m_host:
                    info["hostname"] = m_host.group(1)
                m_ver = re.search(r"Version:\s*([^\r\n]+)", raw)
                if m_ver:
                    info["firmware"] = m_ver.group(1).strip()
                    m_mod = re.search(r"(FortiGate[^\s,]+)", m_ver.group(1))
                    if m_mod:
                        info["model"] = m_mod.group(1)
                m_sn = re.search(r"Serial-Number:\s*(\S+)", raw)
                if m_sn:
                    info["serial"] = m_sn.group(1)
        except Exception as exc:
            logger.warning("[%s] FortiOS get system status failed: %s", self.ip, exc)

        if not info["hostname"]:
            prompt = self._safe_find_prompt(conn)
            m_p = re.match(r"^([A-Za-z0-9_-]+)", prompt)
            if m_p and m_p.group(1).lower() not in (
                "authentication",
                "password",
                "login",
                "username",
                "incorrect",
                "failed",
                "denied",
            ):
                info["hostname"] = m_p.group(1)

        return info

    @staticmethod
    def _is_pseudo_interface(name: str) -> bool:
        return not name or name.lower().startswith(FORTIOS_VIRTUAL_PSEUDO_PREFIXES)

    @staticmethod
    def _upsert_l3_interface(l3_interfaces: list[dict], intf: str, ip_str: str, status: str = "up") -> None:
        """Insert or update an L3 interface record without duplicating (interface, ip_address)."""
        if not ip_str or ip_str.startswith("0.0.0.0"):
            return
        for row in l3_interfaces:
            if row["interface"] == intf:
                if row["ip_address"] == ip_str:
                    row["status"] = status
                    row["protocol"] = status
                    return
        l3_interfaces.append(
            {
                "interface": intf,
                "ip_address": ip_str,
                "status": status,
                "protocol": status,
            }
        )

    def _merge_get_system_interface(self, raw: str, l3_interfaces: list[dict], interfaces_detail: dict) -> None:
        """Merge runtime IP/status from `get system interface` (covers DHCP/PPPoE/dynamic IPs)."""
        if not raw or _is_fortios_cli_error(raw):
            return
        cur_intf: str | None = None
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            m_hdr = re.match(r"^==\s*\[\s*(.+?)\s*\]$", line)
            if m_hdr:
                cand = m_hdr.group(1).strip()
                cur_intf = None if self._is_pseudo_interface(cand) else cand
                continue

            m_name = re.search(r"\bname:\s*(\S+)", line)
            if m_name:
                cand = m_name.group(1).strip()
                if not self._is_pseudo_interface(cand):
                    cur_intf = cand
                else:
                    cur_intf = None
                    continue

            if not cur_intf:
                continue

            entry = interfaces_detail.setdefault(
                cur_intf,
                {
                    "status": "up",
                    "protocol": "up",
                    "description": "",
                    "mac_address": "",
                    "speed": "N/A",
                    "duplex": "N/A",
                },
            )
            m_status = re.search(r"\bstatus:\s*(up|down)\b", line, re.IGNORECASE)
            if m_status:
                st = m_status.group(1).lower()
                entry["status"] = st
                entry["protocol"] = st

            m_ip = re.search(r"\bip:\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m_ip and m_ip.group(1) != "0.0.0.0":
                self._upsert_l3_interface(
                    l3_interfaces, cur_intf, f"{m_ip.group(1)} {m_ip.group(2)}", status=entry["status"]
                )

    def _merge_get_system_interface_physical(
        self, raw: str, l3_interfaces: list[dict], interfaces_detail: dict
    ) -> None:
        """Merge hardware link carrier, speed, duplex, and MAC from `get system interface physical`."""
        if not raw or _is_fortios_cli_error(raw):
            return
        cur_intf: str | None = None
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Sub-blocks look like `==[port1]`, group headers look like `== [onboard]`
            m_sub = re.match(r"^==\s*\[\s*([^\]]+?)\s*\]$", line)
            if m_sub:
                cand = m_sub.group(1).strip()
                if cand.lower() in ("onboard", "mgmt", "npu", "virtual", "switch", "aggregate", "vlan"):
                    cur_intf = None
                    continue
                if self._is_pseudo_interface(cand):
                    cur_intf = None
                    continue
                cur_intf = cand
                interfaces_detail.setdefault(
                    cur_intf,
                    {
                        "status": "down",
                        "protocol": "down",
                        "description": "",
                        "mac_address": "",
                        "speed": "N/A",
                        "duplex": "N/A",
                    },
                )
                continue

            if not cur_intf:
                continue

            entry = interfaces_detail[cur_intf]
            m_status = re.match(r"^status:\s*(up|down)\b", line, re.IGNORECASE)
            if m_status:
                st = m_status.group(1).lower()
                entry["status"] = st
                entry["protocol"] = st
                for row in l3_interfaces:
                    if row["interface"] == cur_intf:
                        row["status"] = st
                        row["protocol"] = st
                continue

            m_speed = re.match(r"^speed:\s*(.+)$", line, re.IGNORECASE)
            if m_speed:
                spd, dup = _normalize_fortios_speed(m_speed.group(1))
                entry["speed"] = spd
                entry["duplex"] = dup
                continue

            m_mac = re.match(r"^mac:\s*([0-9a-fA-F:.-]+)", line, re.IGNORECASE)
            if m_mac:
                norm_mac = oui_lookup.normalize_mac(m_mac.group(1)).lower()
                if norm_mac and norm_mac != _ZERO_MAC:
                    entry["mac_address"] = norm_mac
                continue

            m_ip = re.match(r"^ip:\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
            if m_ip and m_ip.group(1) != "0.0.0.0":
                self._upsert_l3_interface(
                    l3_interfaces, cur_intf, f"{m_ip.group(1)} {m_ip.group(2)}", status=entry["status"]
                )

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        try:
            raw = conn.send_command("show system interface")
            if _is_fortios_cli_error(raw):
                logger.warning(
                    "[%s] FortiOS 'show system interface' returned CLI error: %s", self.ip, raw.strip()[:160]
                )
            else:
                current_intf = None
                for line in raw.splitlines():
                    line = line.strip()
                    m_edit = re.match(r'^edit\s+"([^"]+)"$|^edit\s+(\S+)$', line)
                    if m_edit:
                        cand = (m_edit.group(1) or m_edit.group(2) or "").strip()
                        if self._is_pseudo_interface(cand):
                            current_intf = None
                            continue
                        current_intf = cand
                        interfaces_detail[current_intf] = {
                            "status": "up",
                            "protocol": "up",
                            "description": "",
                            "mac_address": "",
                            "speed": "N/A",
                            "duplex": "N/A",
                        }
                    elif line.startswith("set ip ") and current_intf:
                        parts = line.split()
                        if len(parts) >= 3 and parts[2] != "0.0.0.0":
                            current_ip = parts[2]
                            mask = parts[3] if len(parts) > 3 else ""
                            self._upsert_l3_interface(
                                l3_interfaces,
                                current_intf,
                                f"{current_ip} {mask}".strip(),
                                status=interfaces_detail[current_intf]["status"],
                            )
                    elif line.startswith("set description ") and current_intf:
                        interfaces_detail[current_intf]["description"] = (
                            line.split("set description", 1)[1].strip().strip('"')
                        )
                    elif line.startswith("set alias ") and current_intf:
                        if not interfaces_detail[current_intf]["description"]:
                            interfaces_detail[current_intf]["description"] = (
                                line.split("set alias", 1)[1].strip().strip('"')
                            )
                    elif line.startswith("set vlanid ") and current_intf:
                        vlan_val = line.split("set vlanid", 1)[1].strip().strip('"')
                        if vlan_val.isdigit():
                            interfaces_detail[current_intf]["vlan"] = int(vlan_val)
                    elif "set status down" in line and current_intf:
                        interfaces_detail[current_intf]["status"] = "down"
                        interfaces_detail[current_intf]["protocol"] = "down"
                        for row in l3_interfaces:
                            if row["interface"] == current_intf:
                                row["status"] = "down"
                                row["protocol"] = "down"
        except Exception as exc:
            logger.warning("[%s] FortiOS show system interface failed: %s", self.ip, exc)

        # Merge operational state (DHCP/runtime IPs, physical carrier, speed, duplex, MAC)
        for op_cmd, merger in (
            ("get system interface", self._merge_get_system_interface),
            ("get system interface physical", self._merge_get_system_interface_physical),
        ):
            try:
                op_raw = conn.send_command(op_cmd)
                if _is_fortios_cli_error(op_raw):
                    logger.warning("[%s] FortiOS '%s' returned CLI error: %s", self.ip, op_cmd, op_raw.strip()[:160])
                elif op_raw:
                    merger(op_raw, l3_interfaces, interfaces_detail)
            except Exception as exc:
                logger.warning("[%s] FortiOS '%s' failed: %s", self.ip, op_cmd, exc)

        return l3_interfaces, interfaces_detail

    @staticmethod
    def _finalize_lldp_neighbor(entry: dict[str, str], capabilities: str) -> dict[str, str]:
        """Apply OUI fallback and device_type classification before emitting a neighbor entry."""
        remote_mac = entry.get("remote_mac", "")
        if not entry.get("platform") and remote_mac:
            vendor = oui_lookup.lookup_oui(remote_mac)
            if vendor and vendor != "Unknown":
                entry["platform"] = vendor
                entry["remote_platform"] = vendor
        entry["device_type"] = _classify_lldp_device_type(
            capabilities=capabilities,
            platform=entry.get("platform", ""),
            remote_device=entry.get("remote_device", ""),
            remote_mac=remote_mac,
        )
        return entry

    @staticmethod
    def _parse_lldp_blocks(raw: str) -> list[dict]:
        neighbors: list[dict] = []
        current: dict[str, str] = {}
        current_caps = ""

        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            m_port = re.match(
                r"^(?:VDOM:\s*[^,]+,\s*)?(?:Local\s+)?(?:Port|Interface)\s*:\s*(\S+)", line, re.IGNORECASE
            )
            if m_port:
                if current.get("local_port") and current.get("remote_device"):
                    neighbors.append(FortinetDriver._finalize_lldp_neighbor(current, current_caps))
                current = {
                    "local_port": m_port.group(1).strip().rstrip(","),
                    "remote_device": "",
                    "remote_port": "",
                    "remote_ip": "",
                    "remote_mac": "",
                    "platform": "",
                    "remote_platform": "",
                    "device_type": "switch",
                }
                current_caps = ""
                continue

            if not current:
                continue

            low = line.lower()
            if low.startswith("chassis id:"):
                val = line.split(":", 1)[1].strip()
                if _MAC_TOKEN_RE.match(val):
                    norm_mac = oui_lookup.normalize_mac(val).lower()
                    if norm_mac and norm_mac != _ZERO_MAC:
                        current["remote_mac"] = norm_mac
                if val and not current["remote_device"]:
                    current["remote_device"] = val
            elif low.startswith("system name:"):
                sys_name = line.split(":", 1)[1].strip()
                if sys_name:
                    if "." in sys_name and not _IPV4_RE.match(sys_name) and not _MAC_TOKEN_RE.match(sys_name):
                        sys_name = sys_name.split(".", 1)[0]
                    current["remote_device"] = sys_name
            elif low.startswith("port id:"):
                current["remote_port"] = line.split(":", 1)[1].strip()
            elif low.startswith(("management address:", "mgmt ip:", "management ip:", "ip address:")):
                val = line.split(":", 1)[1].strip()
                m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", val)
                if m_ip:
                    current["remote_ip"] = m_ip.group(1)
            elif low.startswith("system description:"):
                desc = line.split(":", 1)[1].strip()[:80]
                current["platform"] = desc
                current["remote_platform"] = desc
            elif low.startswith(("system capabilities:", "capabilities:")):
                current_caps = line.split(":", 1)[1].strip()

        if current.get("local_port") and current.get("remote_device"):
            neighbors.append(FortinetDriver._finalize_lldp_neighbor(current, current_caps))
        return neighbors

    @staticmethod
    def _parse_lldp_summary(raw: str) -> list[dict]:
        """Parse tabular `diagnose lldprx neighbor summary` output as fallback when details is unavailable."""
        neighbors: list[dict] = []
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line or line.lower().startswith(("port", "vdom", "total", "---", "===")):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            # Common summary format: <local_port> <chassis_id_or_mac> <port_id> [system_name]
            local_port = parts[0]
            if not re.match(r"^[A-Za-z][A-Za-z0-9_./-]*$", local_port):
                continue
            chassis = parts[1]
            remote_port = parts[2]
            remote_device = parts[3] if len(parts) >= 4 else chassis
            if "." in remote_device and not _IPV4_RE.match(remote_device) and not _MAC_TOKEN_RE.match(remote_device):
                remote_device = remote_device.split(".", 1)[0]
            remote_mac = oui_lookup.normalize_mac(chassis).lower() if _MAC_TOKEN_RE.match(chassis) else ""
            entry = {
                "local_port": local_port,
                "remote_device": remote_device,
                "remote_port": remote_port,
                "remote_ip": "",
                "remote_mac": remote_mac if remote_mac != _ZERO_MAC else "",
                "platform": "",
                "remote_platform": "",
                "device_type": "switch",
            }
            neighbors.append(FortinetDriver._finalize_lldp_neighbor(entry, ""))
        return neighbors

    def get_neighbors(self, conn) -> list[dict]:
        commands = (
            "diagnose lldprx neighbor details",
            "diagnose lldprx neighbor summary",
            "diagnose switch-controller switch-info lldp neighbors-detail",
            "diagnose snmp sysinfo lldp neighbor",
            "diagnose lldp neighbor list",
            "get switch lldp neighbors-summary",
        )
        errors: list[str] = []
        succeeded_cleanly = False

        for cmd in commands:
            try:
                raw = conn.send_command(cmd)
                if not raw:
                    continue
                if _is_fortios_cli_error(raw):
                    errors.append(f"{cmd}: {raw.strip().splitlines()[0][:80]}")
                    continue
                succeeded_cleanly = True
                parsed = self._parse_lldp_blocks(raw)
                if not parsed and "summary" in cmd:
                    parsed = self._parse_lldp_summary(raw)
                if parsed:
                    self._discovery_protocols = {
                        "lldp": "enabled",
                        "cdp": "unsupported",
                        "mndp": "unsupported",
                        "notes": "",
                    }
                    return parsed
            except Exception as exc:
                errors.append(f"{cmd}: {exc}")
                logger.warning("[%s] FortiOS LLDP command '%s' failed: %s", self.ip, cmd, exc)

        if errors and not succeeded_cleanly:
            logger.warning(
                "[%s] FortiOS LLDP discovery failed across all probed commands (%d errors): %s",
                self.ip,
                len(errors),
                "; ".join(errors[:3]),
            )
        return []

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        if neighbors:
            return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}

        cfg = raw_config or ""
        cfg_low = cfg.lower()

        if "config system global" in cfg_low or "config system interface" in cfg_low:
            lldp_enabled = False
            section = ""
            cur_intf = ""
            cur_is_fortilink = False
            cur_intf_lldp = False

            for raw_line in cfg.splitlines():
                line = raw_line.strip().lower()
                if not line:
                    continue
                if line == "config system global":
                    section = "global"
                    continue
                if line == "config system interface":
                    section = "interface"
                    cur_intf = ""
                    cur_is_fortilink = False
                    cur_intf_lldp = False
                    continue
                if line == "end":
                    if section == "interface" and cur_intf and cur_intf_lldp and not cur_is_fortilink:
                        lldp_enabled = True
                    section = ""
                    cur_intf = ""
                    continue

                if section == "global":
                    if "set lldp-transmission enable" in line or "set lldp-reception enable" in line:
                        lldp_enabled = True
                elif section == "interface":
                    m_edit = re.match(r'^edit\s+"([^"]+)"$|^edit\s+(\S+)$', line)
                    if m_edit:
                        cur_intf = (m_edit.group(1) or m_edit.group(2) or "").strip()
                        cur_is_fortilink = cur_intf == "fortilink"
                        cur_intf_lldp = False
                    elif line == "next":
                        if cur_intf and cur_intf_lldp and not cur_is_fortilink:
                            lldp_enabled = True
                        cur_intf = ""
                        cur_is_fortilink = False
                        cur_intf_lldp = False
                    elif cur_intf:
                        if "set fortilink enable" in line:
                            cur_is_fortilink = True
                        if "set lldp-transmission enable" in line or "set lldp-reception enable" in line:
                            cur_intf_lldp = True

            if lldp_enabled:
                return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}
        elif "set lldp-transmission enable" in cfg_low or "set lldp-reception enable" in cfg_low:
            return {"lldp": "enabled", "cdp": "unsupported", "mndp": "unsupported", "notes": ""}

        return {
            "lldp": "disabled",
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": "FortiOS LLDP TX/RX is disabled by default; enable per-interface or globally.",
        }

    @staticmethod
    def _parse_route_rhs(rest: str) -> tuple[str, str] | None:
        """Parse the right-hand side of a FortiOS route or ECMP continuation line into (next_hop, interface)."""
        rhs = rest.strip()
        # Recursive BGP/static route: `[20/0] via 192.0.2.3 (recursive is directly connected, port1), 01w2d03h`
        m_rec = re.match(
            r"^(?:\[\d+/\d+\]\s+)?via\s+(\d+\.\d+\.\d+\.\d+)\s*\(recursive[^)]*,\s*([^),]+)\)",
            rhs,
            re.IGNORECASE,
        )
        if m_rec:
            return m_rec.group(1), m_rec.group(2).strip()

        # Directly connected (including static/IPsec routes with [AD/metric]):
        # `[10/0] is directly connected, vpn-branch1` or `is directly connected, port1`
        m_conn = re.match(r"^(?:\[\d+/\d+\]\s+)?is\s+directly\s+connected,\s*(.+)$", rhs, re.IGNORECASE)
        if m_conn:
            return "Direct", _clean_fortios_route_intf(m_conn.group(1))

        # Standard next-hop route: `[10/0] via 198.51.100.1, wan1, [1/0]`
        m_via = re.match(r"^(?:\[\d+/\d+\]\s+)?via\s+(\d+\.\d+\.\d+\.\d+),\s*(.+)$", rhs, re.IGNORECASE)
        if m_via:
            return m_via.group(1), _clean_fortios_route_intf(m_via.group(2))

        return None

    def get_routing_table(self, conn) -> list[dict]:
        routes: list[dict] = []
        try:
            raw = conn.send_command("get router info routing-table all")
            if _is_fortios_cli_error(raw):
                logger.warning(
                    "[%s] FortiOS 'get router info routing-table all' returned CLI error: %s",
                    self.ip,
                    raw.strip()[:160],
                )
                return routes

            current_vrf: str | None = None
            last_proto = ""
            last_subnet = ""

            for raw_line in raw.splitlines():
                stripped = raw_line.strip()
                if not stripped:
                    continue

                m_vrf = re.match(r"^Routing\s+table\s+for\s+VRF\s*=\s*(\S+)", stripped, re.IGNORECASE)
                if m_vrf:
                    current_vrf = m_vrf.group(1)
                    last_proto = ""
                    last_subnet = ""
                    continue

                # Primary route line: `S*      0.0.0.0/0 [10/0] via 198.51.100.1, wan1, [1/0]`
                m_primary = re.match(r"^([A-Z][A-Z0-9*>\s]{0,6}?)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(.+)$", stripped)
                if m_primary:
                    proto = m_primary.group(1).strip()
                    subnet = m_primary.group(2)
                    parsed_rhs = self._parse_route_rhs(m_primary.group(3))
                    if parsed_rhs:
                        last_proto = proto
                        last_subnet = subnet
                        entry: dict[str, str] = {
                            "subnet": subnet,
                            "next_hop": parsed_rhs[0],
                            "interface": parsed_rhs[1],
                            "protocol": proto,
                        }
                        if current_vrf is not None:
                            entry["vrf"] = current_vrf
                        routes.append(entry)
                    continue

                # Indented ECMP continuation line carrying previous (proto, subnet)
                if last_proto and last_subnet and (raw_line[:1].isspace() or stripped.startswith("[")):
                    parsed_rhs = self._parse_route_rhs(stripped)
                    if parsed_rhs:
                        entry = {
                            "subnet": last_subnet,
                            "next_hop": parsed_rhs[0],
                            "interface": parsed_rhs[1],
                            "protocol": last_proto,
                        }
                        if current_vrf is not None:
                            entry["vrf"] = current_vrf
                        routes.append(entry)

            if raw.strip() and not routes:
                logger.warning("[%s] FortiOS routing table output parsed 0 routes", self.ip)
        except Exception as exc:
            logger.warning("[%s] FortiOS get router info routing-table all failed: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries: list[dict] = []
        try:
            raw = conn.send_command("get system arp")
            if _is_fortios_cli_error(raw):
                logger.warning("[%s] FortiOS 'get system arp' returned CLI error: %s", self.ip, raw.strip()[:160])
                return arp_entries

            for line in raw.splitlines():
                parts = line.split()
                if len(parts) < 3 or not _IPV4_RE.match(parts[0]):
                    continue
                # Locate MAC token explicitly so static Age="-" and 3-column outputs both parse cleanly
                mac_idx = None
                for idx in (2, 1):
                    if idx < len(parts) and _MAC_TOKEN_RE.match(parts[idx]):
                        mac_idx = idx
                        break
                if mac_idx is None:
                    continue

                mac = oui_lookup.normalize_mac(parts[mac_idx]).lower()
                if not mac or mac == _ZERO_MAC:
                    continue

                age = parts[1] if mac_idx == 2 else ""
                entry_type = "static" if age == "-" else "dynamic"
                intf = " ".join(parts[mac_idx + 1 :]) if len(parts) > mac_idx + 1 else ""
                arp_entries.append(
                    {
                        "ip": parts[0],
                        "mac": mac,
                        "interface": intf,
                        "age": age,
                        "type": entry_type,
                        "vendor": oui_lookup.lookup_oui(mac),
                    }
                )
        except Exception as exc:
            logger.warning("[%s] FortiOS get system arp failed: %s", self.ip, exc)
        return arp_entries

    def get_optics(self, conn) -> list[dict]:
        optics: list[dict] = []
        try:
            raw = conn.send_command("get system interface transceiver")
            if _is_fortios_cli_error(raw):
                logger.warning(
                    "[%s] FortiOS 'get system interface transceiver' returned CLI error: %s",
                    self.ip,
                    raw.strip()[:160],
                )
                return optics

            cur_entry: dict[str, Any] = {}
            for line in raw.splitlines():
                m_if = re.match(r"^Interface\s+([A-Za-z0-9_.-]+)\s+-", line.strip(), re.IGNORECASE)
                if m_if:
                    if cur_entry:
                        optics.append(cur_entry)
                    cur_entry = {
                        "port": m_if.group(1),
                        "vendor": "Fortinet",
                        "part_number": "Unknown",
                        "serial": "Unknown",
                        "type": "SFP",
                        "tx_power_dbm": None,
                        "rx_power_dbm": None,
                        "temperature_c": None,
                        "voltage_v": None,
                    }
                elif cur_entry:
                    m_vn = re.search(r"Vendor Name\s*:\s*(.+)", line, re.IGNORECASE)
                    m_pn = re.search(r"Part No\.\s*:\s*(\S+)", line, re.IGNORECASE)
                    m_sn = re.search(r"Serial No\.\s*:\s*(\S+)", line, re.IGNORECASE)
                    m_temp = re.search(r"Temperature\s*:\s*(-?\d+(?:\.\d+)?)", line, re.IGNORECASE)
                    m_volt = re.search(r"Voltage\s*:\s*(-?\d+(?:\.\d+)?)", line, re.IGNORECASE)
                    m_tx = re.search(r"(?:Optical\s+)?Tx\s+Power\s*:\s*(-?\d+(?:\.\d+)?)", line, re.IGNORECASE)
                    m_rx = re.search(r"(?:Optical\s+)?Rx\s+Power\s*:\s*(-?\d+(?:\.\d+)?)", line, re.IGNORECASE)
                    if m_vn:
                        cur_entry["vendor"] = m_vn.group(1).strip()
                    if m_pn:
                        cur_entry["part_number"] = m_pn.group(1).strip()
                    if m_sn:
                        cur_entry["serial"] = m_sn.group(1).strip()
                    if m_temp:
                        cur_entry["temperature_c"] = float(m_temp.group(1))
                    if m_volt:
                        cur_entry["voltage_v"] = float(m_volt.group(1))
                    if m_tx:
                        cur_entry["tx_power_dbm"] = float(m_tx.group(1))
                    if m_rx:
                        cur_entry["rx_power_dbm"] = float(m_rx.group(1))
            if cur_entry:
                optics.append(cur_entry)
        except Exception as exc:
            logger.warning("[%s] FortiOS get system interface transceiver failed: %s", self.ip, exc)
        return optics

    def get_running_config(self, conn) -> str:
        raw = self._safe_send_command(conn, "show full-configuration")
        if _is_fortios_cli_error(raw):
            logger.warning("[%s] FortiOS 'show full-configuration' returned CLI error: %s", self.ip, raw.strip()[:160])
        return raw

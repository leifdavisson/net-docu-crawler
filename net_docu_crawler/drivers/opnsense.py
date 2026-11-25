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
OPNsense Driver: Next-generation open-source firewalls based on FreeBSD.
Parses system details, ifconfig interfaces, routing table, ARP table, and config.xml.

Official Upstream Documentation & References:
- OPNsense: https://docs.opnsense.org/
- Paramiko: https://www.paramiko.org/
"""

import base64
import hashlib
import ipaddress
import logging
import os
import re
import threading
import time

import paramiko

import oui_lookup
from net_docu_crawler.drivers._lldpd import parse_lldpd_json
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

OPNSENSE_PSEUDO_INTERFACES = ("lo", "enc", "pflog", "pfsync")
_STRICT_HOST_KEY_ENV_VAR = "NDC_STRICT_HOST_KEYS"
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_SMBIOS_PLACEHOLDER_SERIALS = frozenset(
    {
        "0",
        "none",
        "not specified",
        "default string",
        "to be filled by o.e.m.",
        "system serial number",
        "chassis serial number",
        "n/a",
        "unknown",
    }
)


def _format_host_key_fingerprint(key: paramiko.PKey) -> str:
    """Computes an OpenSSH-style ``SHA256:<base64>`` host-key fingerprint for audit logs."""
    try:
        raw_bytes = key.asbytes()
        if isinstance(raw_bytes, (bytes, bytearray)):
            digest = base64.b64encode(hashlib.sha256(raw_bytes).digest()).decode("ascii").rstrip("=")
            return f"SHA256:{digest}"
    except (OSError, TypeError, ValueError, AttributeError) as exc:
        logger.debug("Unable to compute SSH host-key SHA-256 fingerprint: %s", exc)
    return "SHA256:unavailable"


class AuditedMissingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Explicit host-key policy for read-only discovery of unprovisioned/ephemeral network
    appliances not yet recorded in system ``known_hosts``.

    Unlike ``paramiko.AutoAddPolicy``, this policy NEVER mutates or persists untrusted
    host keys into ``SSHClient``'s host-key store, and always emits a structured warning
    recording the peer hostname, algorithm, and SHA-256 fingerprint. Known hosts loaded
    via ``load_system_host_keys()`` are still strictly verified against key changes by
    Paramiko before this policy is ever consulted; set ``strict_host_key_checking=True``
    or ``NDC_STRICT_HOST_KEYS=1`` to enforce ``paramiko.RejectPolicy()`` for unknown hosts.
    """

    _warned_host_keys: set[tuple[str, str]] = set()
    _warned_lock = threading.Lock()

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        key_type = key.get_name() if hasattr(key, "get_name") else "unknown"
        fingerprint = _format_host_key_fingerprint(key)
        cache_key = (str(hostname), fingerprint)
        with self._warned_lock:
            if cache_key in self._warned_host_keys:
                return
            if len(self._warned_host_keys) < 4096:
                self._warned_host_keys.add(cache_key)
        logger.warning(
            "Unverified SSH host key for %s (%s %s) during read-only OPNsense discovery; "
            "set strict_host_key_checking=True or %s=1 to reject unknown hosts.",
            hostname,
            key_type,
            fingerprint,
            _STRICT_HOST_KEY_ENV_VAR,
        )


def _close_quietly(resource: object) -> None:
    if resource is None:
        return
    close_fn = getattr(resource, "close", None)
    if callable(close_fn):
        try:
            close_fn()
        except Exception as exc:
            logger.debug("Ignoring close() error on OPNsense SSH resource: %s", exc)


class OPNsenseSSHConnection:
    """
    Non-interactive SSH client wrapper for OPNsense / FreeBSD bypassing `/usr/local/etc/rc.initial` menu traps.
    Enforces a strict total wall-clock deadline, drains stdout and stderr simultaneously to prevent SSH window
    deadlocks, inspects remote exit status, and closes every channel/stream in `finally`.
    """

    def __init__(
        self,
        client: paramiko.SSHClient,
        session_log: str = "",
        timeout: int | float = 15,
        no_log: dict[str, str] | None = None,
    ):
        self.client = client
        self.session_log = session_log
        self.timeout = max(1.0, float(timeout)) if timeout else 15.0
        self.no_log: dict[str, str] = {k: v for k, v in (no_log or {}).items() if isinstance(v, str) and v}
        self._log_lock = threading.Lock()
        self.last_exit_status: int | None = None
        self.last_stderr: str = ""

    def __enter__(self) -> "OPNsenseSSHConnection":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()

    def _scrub_text(self, text: str) -> str:
        if not text:
            return ""
        out = text
        for secret in self.no_log.values():
            if secret:
                out = out.replace(secret, "********")
        return out

    @staticmethod
    def _supports_channel_polling(chan: object) -> bool:
        if chan is None or hasattr(chan, "_mock_return_value"):
            return False
        required = ("recv_ready", "recv", "recv_stderr_ready", "recv_stderr", "exit_status_ready", "recv_exit_status")
        return all(callable(getattr(chan, attr, None)) for attr in required)

    @staticmethod
    def _read_channel_bounded(chan, deadline: float, cmd: str) -> tuple[bytes, bytes, int | None]:
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        exit_status: int | None = None

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"OPNsense exec_command timed out waiting for {cmd!r}")

            if callable(getattr(chan, "settimeout", None)):
                chan.settimeout(min(0.25, remaining))

            progressed = False
            while chan.recv_ready():
                chunk = chan.recv(65536)
                if not chunk:
                    break
                stdout_buf.extend(chunk)
                progressed = True
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"OPNsense exec_command exceeded wall-clock deadline for {cmd!r}")

            while chan.recv_stderr_ready():
                err_chunk = chan.recv_stderr(65536)
                if not err_chunk:
                    break
                stderr_buf.extend(err_chunk)
                progressed = True
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"OPNsense exec_command exceeded wall-clock deadline for {cmd!r}")

            if chan.exit_status_ready():
                while chan.recv_ready():
                    chunk = chan.recv(65536)
                    if not chunk:
                        break
                    stdout_buf.extend(chunk)
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"OPNsense exec_command exceeded wall-clock deadline for {cmd!r}")
                while chan.recv_stderr_ready():
                    err_chunk = chan.recv_stderr(65536)
                    if not err_chunk:
                        break
                    stderr_buf.extend(err_chunk)
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"OPNsense exec_command exceeded wall-clock deadline for {cmd!r}")
                exit_status = int(chan.recv_exit_status())
                break

            if not progressed:
                sleep_for = min(0.02, max(0.0, deadline - time.monotonic()))
                if sleep_for > 0:
                    time.sleep(sleep_for)

        return bytes(stdout_buf), bytes(stderr_buf), exit_status

    def send_command(self, cmd: str, timeout: int | float | None = None) -> str:
        eff_timeout = float(timeout) if (timeout is not None and timeout > 0) else max(self.timeout, 15.0)
        deadline = time.monotonic() + eff_timeout
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=eff_timeout)
        chan = getattr(stdout, "channel", None)
        output = ""
        err_text = ""
        exit_status: int | None = None

        try:
            _close_quietly(stdin)
            if self._supports_channel_polling(chan):
                out_bytes, err_bytes, exit_status = self._read_channel_bounded(chan, deadline, cmd)
                output = out_bytes.decode("utf-8", errors="ignore")
                err_text = err_bytes.decode("utf-8", errors="ignore")
            else:
                if chan is not None and callable(getattr(chan, "settimeout", None)):
                    chan.settimeout(eff_timeout)
                raw_out = stdout.read()
                output = (
                    raw_out.decode("utf-8", errors="ignore")
                    if isinstance(raw_out, (bytes, bytearray))
                    else str(raw_out or "")
                )
                raw_err = stderr.read() if callable(getattr(stderr, "read", None)) else b""
                err_text = raw_err.decode("utf-8", errors="ignore") if isinstance(raw_err, (bytes, bytearray)) else ""
        finally:
            _close_quietly(stdin)
            _close_quietly(stdout)
            _close_quietly(stderr)
            _close_quietly(chan)

        self.last_exit_status = exit_status
        self.last_stderr = err_text

        if exit_status is not None and exit_status != 0:
            logger.warning(
                "OPNsense command %r returned non-zero exit status %d (stderr: %s)",
                cmd,
                exit_status,
                self._scrub_text(err_text.strip())[:200],
            )
        elif err_text.strip():
            logger.debug("OPNsense command %r stderr: %s", cmd, self._scrub_text(err_text.strip())[:200])

        if self.session_log:
            safe_out = self._scrub_text(output)
            try:
                with self._log_lock:
                    with open(self.session_log, "a", encoding="utf-8") as f:
                        f.write(f"\n--- COMMAND: {cmd} ---\n{safe_out}\n")
            except OSError as exc:
                logger.debug("Failed writing OPNsense session log %s: %s", self.session_log, exc)
        return output

    def disconnect(self):
        _close_quietly(self.client)


class OPNsenseDriver(BaseDriver):
    """
    Driver for OPNsense firewalls running on FreeBSD.
    Persona: firewall / gateway / router.
    """

    vendor_name = "OPNsense"
    device_persona = "firewall"
    default_device_type = "firewall"
    paging_cmd = ""
    supports_telnet = False

    def __init__(
        self,
        ip: str,
        username: str = "",
        password: str = "",
        secret: str = "",
        timeout: int = 10,
        session_log: str = "",
        port: int | None = None,
        transport: str = "ssh",
        strict_host_key_checking: bool | None = None,
        known_hosts_path: str | None = None,
    ):
        super().__init__(
            ip=ip,
            username=username,
            password=password,
            secret=secret,
            timeout=timeout,
            session_log=session_log,
            port=port,
            transport=transport,
        )
        if strict_host_key_checking is None:
            env_val = os.environ.get(_STRICT_HOST_KEY_ENV_VAR, "").strip().lower()
            strict_host_key_checking = env_val in {"1", "true", "yes", "on"}
        self.strict_host_key_checking = strict_host_key_checking
        self.known_hosts_path = known_hosts_path

    def connect(self):
        if self.transport != "ssh":
            raise ValueError(f"OPNsenseDriver only supports SSH transport (got {self.transport!r})")

        from net_docu_crawler.ssh_compat import connect_paramiko_with_fallback

        client = paramiko.SSHClient()
        try:
            try:
                client.load_system_host_keys()
            except OSError as exc:
                logger.warning("Unable to load system SSH known_hosts for OPNsense target %s: %s", self.ip, exc)

            if self.known_hosts_path:
                client.load_host_keys(self.known_hosts_path)

            if self.strict_host_key_checking:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(AuditedMissingHostKeyPolicy())

            connect_paramiko_with_fallback(
                client,
                hostname=self.ip,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                channel_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except BaseException:
            _close_quietly(client)
            raise

        no_log = {k: v for k, v in (("password", self.password), ("secret", self.secret)) if v}
        return OPNsenseSSHConnection(client, session_log=self.session_log, timeout=self.timeout, no_log=no_log)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "opnsense",
            "model": "OPNsense Gateway",
            "serial": "Unknown",
            "firmware": "OPNsense",
            "os_type": "opnsense",
            "device_persona": self.device_persona,
        }
        try:
            h = (conn.send_command("hostname") or "").strip()
            if h:
                info["hostname"] = h
        except Exception as exc:
            logger.warning("OPNsense hostname query failed on %s: %s", self.ip, exc)

        try:
            raw_ver = (conn.send_command("opnsense-version") or "").strip()
            if raw_ver:
                info["firmware"] = raw_ver
        except Exception as exc:
            logger.warning("OPNsense firmware version query failed on %s: %s", self.ip, exc)

        try:
            prod = (conn.send_command("kenv smbios.system.product 2>/dev/null") or "").strip()
            if prod:
                info["model"] = f"OPNsense ({prod})"
            ser = (conn.send_command("kenv smbios.system.serial 2>/dev/null") or "").strip()
            if ser and ser.lower() not in _SMBIOS_PLACEHOLDER_SERIALS:
                info["serial"] = ser
        except Exception as exc:
            logger.warning("OPNsense SMBIOS kenv query failed on %s: %s", self.ip, exc)

        return info

    def _parse_ifconfig_netmask(self, parts: list[str], header: str, intf_name: str) -> int:
        """Extract IPv4 prefix length from a FreeBSD `ifconfig -a` `inet` line (normal or P2P `-->`)."""
        if "netmask" in parts:
            idx = parts.index("netmask")
            if idx + 1 < len(parts):
                mask_tok = parts[idx + 1]
                if _IPV4_RE.match(mask_tok):
                    try:
                        return ipaddress.IPv4Network(f"0.0.0.0/{mask_tok}").prefixlen
                    except ValueError as exc:
                        logger.warning(
                            "Invalid OPNsense dotted netmask %r on %s (%s); defaulting to /24: %s",
                            mask_tok,
                            self.ip,
                            intf_name,
                            exc,
                        )
                        return 24
                try:
                    return bin(int(mask_tok, 16)).count("1")
                except ValueError as exc:
                    logger.warning(
                        "Invalid OPNsense hex netmask %r on %s (%s); defaulting to /24: %s",
                        mask_tok,
                        self.ip,
                        intf_name,
                        exc,
                    )
                    return 24
        if "-->" in parts or "POINTOPOINT" in header:
            return 32
        return 24

    def _parse_ifconfig_output(self, raw: str) -> tuple[list[dict], dict[str, dict], list[dict]]:
        """Parse FreeBSD `ifconfig -a` into `(l3_interfaces, interfaces_detail, carp_fhrp)`."""
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        carp_fhrp: list[dict] = []

        blocks = re.split(r"\n(?=[a-zA-Z0-9_.\-]+:)", raw or "")
        for block in blocks:
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0]
            m_intf = re.match(r"^([a-zA-Z0-9_.\-]+):", header)
            if not m_intf:
                continue
            intf_name = m_intf.group(1)
            if intf_name.lower().startswith(OPNSENSE_PSEUDO_INTERFACES):
                continue

            admin_up = "<UP," in header or "<UP>" in header
            m_mtu = re.search(r"\bmtu\s+(\d+)", header)
            mtu = int(m_mtu.group(1)) if m_mtu else None

            desc = ""
            mac = ""
            link_status = ""
            speed = ""
            duplex = ""
            inet_addrs: list[str] = []
            block_l3: list[dict] = []
            vhid_vips: dict[str, str] = {}
            carp_lines: list[tuple[str, str, int]] = []

            for line in lines[1:]:
                line_s = line.strip()
                if line_s.startswith("description:"):
                    desc = line_s.split("description:", 1)[1].strip()
                elif line_s.startswith("ether "):
                    eth_parts = line_s.split()
                    if len(eth_parts) >= 2:
                        mac = oui_lookup.normalize_mac(eth_parts[1].strip()).lower()
                elif line_s.startswith("status:"):
                    link_status = line_s.split("status:", 1)[1].strip().lower()
                elif line_s.startswith("media:"):
                    m_media = re.search(r"\(([^)]+)\)", line_s)
                    if m_media:
                        media_val = m_media.group(1).strip()
                        if media_val.lower() != "none":
                            m_dup = re.search(r"<(full-duplex|half-duplex)>", media_val, re.IGNORECASE)
                            if m_dup:
                                duplex = m_dup.group(1).lower()
                            spd_tok = re.sub(r"<[^>]+>", "", media_val).strip()
                            if spd_tok:
                                speed = spd_tok
                elif line_s.startswith("carp:"):
                    m_carp = re.match(
                        r"^carp:\s*(\S+)\s+vhid\s+(\d+)(?:.*?advskew\s+(\d+))?",
                        line_s,
                        re.IGNORECASE,
                    )
                    if m_carp:
                        carp_state = m_carp.group(1).upper()
                        carp_vhid = m_carp.group(2)
                        carp_skew = int(m_carp.group(3)) if m_carp.group(3) else 0
                        carp_lines.append((carp_state, carp_vhid, carp_skew))
                elif line_s.startswith("inet "):
                    parts = line_s.split()
                    if len(parts) < 2:
                        continue
                    ip_val = parts[1]
                    if ip_val.startswith("127."):
                        continue
                    prefix_len = self._parse_ifconfig_netmask(parts, header, intf_name)
                    full_ip = f"{ip_val}/{prefix_len}"
                    if "vhid" in parts:
                        v_idx = parts.index("vhid")
                        if v_idx + 1 < len(parts):
                            vhid_vips[parts[v_idx + 1]] = full_ip
                    inet_addrs.append(full_ip)
                    block_l3.append(
                        {
                            "interface": intf_name,
                            "ip_address": full_ip,
                            "status": "up",
                            "protocol": "up",
                        }
                    )

            if not admin_up or link_status in ("no carrier", "down", "inactive"):
                status = "down"
            else:
                status = "up"

            for row in block_l3:
                row["status"] = status
                row["protocol"] = status
                l3_interfaces.append(row)

            primary_ip = inet_addrs[0] if inet_addrs else ""
            detail: dict = {
                "ip_address": primary_ip,
                "status": status,
                "mac_address": mac,
                "description": desc,
            }
            if mtu is not None:
                detail["mtu"] = mtu
            if speed:
                detail["speed"] = speed
            if duplex:
                detail["duplex"] = duplex
            interfaces_detail[intf_name] = detail

            for carp_state, carp_vhid, carp_skew in carp_lines:
                carp_fhrp.append(
                    {
                        "protocol": "carp",
                        "group": carp_vhid,
                        "interface": intf_name,
                        "vip": vhid_vips.get(carp_vhid, primary_ip),
                        "priority": carp_skew,
                        "state": carp_state,
                    }
                )

        return l3_interfaces, interfaces_detail, carp_fhrp

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces: list[dict] = []
        interfaces_detail: dict[str, dict] = {}
        carp_fhrp: list[dict] = []
        try:
            raw = conn.send_command("ifconfig -a")
            l3_interfaces, interfaces_detail, carp_fhrp = self._parse_ifconfig_output(raw)
        except Exception as exc:
            logger.warning("OPNsense interface discovery failed on %s: %s", self.ip, exc)
        self._last_l3_interfaces = l3_interfaces
        self._last_interfaces_detail = interfaces_detail
        self._last_carp_fhrp = carp_fhrp
        self._ifconfig_cached = True
        return l3_interfaces, interfaces_detail

    def get_fhrp(self, conn) -> list[dict]:
        """Return live CARP redundancy state parsed from read-only `ifconfig -a` (reusing cached crawl output)."""
        if getattr(self, "_ifconfig_cached", False):
            return list(getattr(self, "_last_carp_fhrp", []))
        try:
            raw = conn.send_command("ifconfig -a")
            _, _, carp_fhrp = self._parse_ifconfig_output(raw)
            self._last_carp_fhrp = carp_fhrp
            self._ifconfig_cached = True
            return list(carp_fhrp)
        except Exception as exc:
            logger.warning("OPNsense CARP FHRP discovery failed on %s: %s", self.ip, exc)
            return []

    def get_neighbors(self, conn) -> list[dict]:
        neighbors: list[dict] = []
        lldp_status = "unknown"
        notes = ""
        try:
            raw = (conn.send_command("lldpctl -f json 2>/dev/null") or "").strip()
            if raw.startswith("{"):
                parsed_nbrs, ok = parse_lldpd_json(raw, default_device_type="switch", log=logger, ip=self.ip)
                if ok:
                    lldp_status = "enabled"
                    neighbors.extend(parsed_nbrs)
                else:
                    lldp_status = "unknown"
                    notes = "lldpctl returned unparseable JSON output."
            else:
                chk = (conn.send_command("command -v lldpctl >/dev/null 2>&1 || echo __NO_LLDPD__") or "").strip()
                if "__NO_LLDPD__" in chk:
                    lldp_status = "not_installed"
                    notes = "lldpd (os-lldpd plugin) is not installed on OPNsense."
                else:
                    lldp_status = "disabled"
                    notes = "lldpctl returned no JSON output; lldpd service may be stopped."
        except Exception as exc:
            logger.warning("OPNsense LLDP query failed on %s: %s", self.ip, exc)
        self._discovery_protocols = {
            "lldp": lldp_status,
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": notes,
        }
        return neighbors

    def _resolve_truncated_netif(self, netif: str, subnet: str) -> str:
        """Restore 12-char truncated FreeBSD `netstat -rn` Netif names (e.g. `vtnet0_vlan1` -> `vtnet0_vlan10`)."""
        known = set(getattr(self, "_last_interfaces_detail", {}).keys())
        if not known or netif in known:
            return netif

        try:
            target_net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            target_net = None

        if target_net is not None:
            for l3 in getattr(self, "_last_l3_interfaces", []):
                intf_cand = str(l3.get("interface") or "")
                ip_cand = str(l3.get("ip_address") or "")
                if not intf_cand.startswith(netif) or "/" not in ip_cand:
                    continue
                try:
                    if ipaddress.ip_interface(ip_cand).network == target_net:
                        return intf_cand
                except ValueError:
                    continue

        if len(netif) >= 12:
            matches = [k for k in known if k.startswith(netif)]
            if len(matches) == 1:
                return matches[0]
        return netif

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("netstat -rnW -f inet")
            if "Destination" not in (raw or ""):
                raw = conn.send_command("netstat -rn -f inet")
            lines = (raw or "").strip().splitlines()
            start = False
            netif_idx = 3
            for line in lines:
                if "Destination" in line and "Gateway" in line:
                    start = True
                    hdr_cols = line.split()
                    if "Netif" in hdr_cols:
                        netif_idx = hdr_cols.index("Netif")
                    continue
                if not start or not line.strip():
                    continue
                parts = line.split()
                if len(parts) > netif_idx:
                    dst = parts[0]
                    gw = parts[1]
                    flags = parts[2]
                    netif = parts[netif_idx]
                    if dst == "127.0.0.1" or netif.startswith("lo"):
                        continue
                    if dst == "default":
                        subnet = "0.0.0.0/0"
                    elif _IPV4_RE.match(dst):
                        subnet = f"{dst}/32"
                    else:
                        subnet = dst
                    netif = self._resolve_truncated_netif(netif, subnet)
                    if gw.startswith("link#") or _MAC_RE.match(gw):
                        proto = "connected"
                    elif "S" in flags:
                        proto = "static"
                    elif "G" in flags:
                        proto = "dynamic"
                    else:
                        proto = "connected"
                    routes.append(
                        {
                            "subnet": subnet,
                            "protocol": proto,
                            "next_hop": gw,
                            "interface": netif,
                        }
                    )
        except Exception as exc:
            logger.warning("OPNsense routing table query failed on %s: %s", self.ip, exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("arp -an") or ""
            for line in raw.strip().splitlines():
                m = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+([a-zA-Z0-9_.\-]+)", line)
                if m:
                    ip_val = m.group(1)
                    mac_val = oui_lookup.normalize_mac(m.group(2)).lower()
                    intf_val = m.group(3)
                    if mac_val and mac_val != "(incomplete)":
                        arp_type = "static" if " permanent" in line.lower() else "dynamic"
                        arp_entries.append(
                            {
                                "ip": ip_val,
                                "mac": mac_val,
                                "interface": intf_val,
                                "type": arp_type,
                                "vendor": oui_lookup.lookup_oui(mac_val),
                            }
                        )
        except Exception as exc:
            logger.warning("OPNsense ARP table query failed on %s: %s", self.ip, exc)
        return arp_entries

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("cat /conf/config.xml")
        except Exception as exc:
            logger.warning("OPNsense config.xml retrieval failed on %s: %s", self.ip, exc)
            return ""

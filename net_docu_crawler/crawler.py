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
Net-Docu-Crawler: Unified Multi-Vendor Network Infrastructure Discovery Engine.
Orchestrates zero-blast-radius discovery across Cisco, Juniper, Aruba, Palo Alto,
Arista, MikroTik, Fortinet, FRRouting, OPNsense, and OpenWrt environments.
Supports local broadcast domains and routed L3 subnets across firewalls and gateways.
"""

import argparse
import datetime
import glob
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace

import paramiko
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

import oui_lookup
import report_generator
from net_docu_crawler.drivers import (
    VENDOR_DRIVER_MAP,
    AristaDriver,
    CiscoDriver,
    FortinetDriver,
    JuniperDriver,
    canonicalize_vendor,
    resolve_driver_for_vendor,
    resolve_vendor_for_driver,
)
from net_docu_crawler.drivers.base import sanitize_raw_config
from net_docu_crawler.drivers.detector import (
    classify_non_network_appliance,
    detect_vendor_range,
    get_arp_table_entries,
    get_mac_from_system_arp,
    infer_vendor_from_http,
    inspect_prompt_os,
    is_hypervisor_mac,
    probe_appliance_ports,
    probe_http_fingerprint,
    probe_snmp_sysinfo,
    resolve_prompt_vendor,
    scan_subnet_ports,
)
from net_docu_crawler.topology_resolver import DeviceRegistry

logger = logging.getLogger(__name__)

_VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "wg", "tailscale")


def _parse_bsd_ifconfig_subnets(stdout: str) -> list[str]:
    """Parse active non-virtual IPv4 subnets from macOS / BSD `ifconfig` output."""
    subnets: list[str] = []
    cur_iface = ""
    for line in stdout.splitlines():
        m_if = re.match(r"^([A-Za-z0-9_.-]+):\s+flags=", line)
        if m_if:
            cur_iface = m_if.group(1)
            continue
        if not cur_iface or cur_iface.startswith(_VIRTUAL_IFACE_PREFIXES):
            continue
        m_inet = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]{8}|\d+\.\d+\.\d+\.\d+)", line)
        if not m_inet:
            continue
        ip_str, mask_raw = m_inet.group(1), m_inet.group(2)
        try:
            if mask_raw.lower().startswith("0x"):
                mask_int = int(mask_raw, 16)
                mask_str = str(ipaddress.IPv4Address(mask_int))
            else:
                mask_str = mask_raw
            net = ipaddress.IPv4Interface(f"{ip_str}/{mask_str}").network
            if 22 <= net.prefixlen <= 31 and not net.is_loopback and str(net) not in subnets:
                subnets.append(str(net))
        except ValueError as exc:
            logger.debug("Skipping invalid BSD/macOS IPv4 interface %s/%s: %s", ip_str, mask_raw, exc)
    return subnets


def detect_local_subnets() -> list[str]:
    """
    Auto-detect active local physical IPv4 subnets (e.g., 192.168.1.0/24),
    excluding loopback and virtual/container bridges. Falls back to 192.168.1.0/24.
    """
    subnets: list[str] = []
    try:
        if sys.platform == "win32":
            proc = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3, check=False)
            if proc.returncode == 0:
                cur_ip = ""
                for line in proc.stdout.splitlines():
                    m_ip = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if m_ip:
                        cur_ip = m_ip.group(1)
                        continue
                    m_mask = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    if m_mask and cur_ip:
                        try:
                            net = ipaddress.IPv4Interface(f"{cur_ip}/{m_mask.group(1)}").network
                            if 22 <= net.prefixlen <= 31 and not net.is_loopback and str(net) not in subnets:
                                subnets.append(str(net))
                        except ValueError as exc:
                            logger.debug(
                                "Skipping invalid Windows IPv4 interface %s/%s: %s", cur_ip, m_mask.group(1), exc
                            )
                        cur_ip = ""
        else:
            try:
                proc = subprocess.run(
                    ["ip", "-o", "-4", "addr", "show", "scope", "global"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
            except FileNotFoundError:
                proc = None
            if proc is not None and proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 4 or "inet" not in parts:
                        continue
                    ifname = parts[1].rstrip(":")
                    if ifname.startswith(_VIRTUAL_IFACE_PREFIXES):
                        continue
                    inet_idx = parts.index("inet")
                    if inet_idx + 1 >= len(parts):
                        continue
                    cidr = parts[inet_idx + 1]
                    try:
                        net = ipaddress.IPv4Interface(cidr).network
                        if 22 <= net.prefixlen <= 31 and str(net) not in subnets:
                            subnets.append(str(net))
                    except ValueError as exc:
                        logger.debug("Skipping invalid local IPv4 CIDR %r: %s", cidr, exc)
            if not subnets:
                ifc_proc = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3, check=False)
                if ifc_proc.returncode == 0:
                    subnets.extend(_parse_bsd_ifconfig_subnets(ifc_proc.stdout))
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("Local subnet auto-detection failed: %s", exc)
    return subnets[:1] if subnets else ["192.168.1.0/24"]


def get_default_targets() -> list[str]:
    """Resolve default crawl targets from `NET_DOCU_TARGETS` or lazy local subnet detection."""
    env_targets = os.environ.get("NET_DOCU_TARGETS", "")
    if env_targets.strip():
        return [t.strip() for t in env_targets.split(",") if t.strip()]
    return detect_local_subnets()


class _LazyDefaultTargets(list):
    """
    List subclass that defers `detect_local_subnets()` subprocess execution until
    default targets are actually read, keeping module import side-effect-free.
    """

    def __init__(self) -> None:
        super().__init__()
        self._loaded = False

    def _ensure(self) -> None:
        if not self._loaded:
            self._loaded = True
            super().clear()
            super().extend(get_default_targets())

    def __iter__(self):
        self._ensure()
        return super().__iter__()

    def __len__(self) -> int:
        self._ensure()
        return super().__len__()

    def __getitem__(self, index):
        self._ensure()
        return super().__getitem__(index)

    def __bool__(self) -> bool:
        self._ensure()
        return super().__len__() > 0

    def __eq__(self, other: object) -> bool:
        self._ensure()
        return super().__eq__(other)

    def __repr__(self) -> str:
        self._ensure()
        return super().__repr__()

    def copy(self) -> list[str]:
        self._ensure()
        return list(super().__iter__())


DEFAULT_TARGETS: list[str] = _LazyDefaultTargets()


def _try_canonical_ip(raw_host: str) -> str | None:
    """Return canonical IPv4/IPv6 literal string if `raw_host` is a valid IP address, else None."""
    s = (raw_host or "").strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    if not s or "/" in s:
        return None
    base, sep, zone = s.partition("%")
    try:
        addr = ipaddress.ip_address(base)
    except ValueError:
        return None
    return f"{addr}%{zone}" if sep and zone and addr.version == 6 else str(addr)


def expand_targets(targets: list[str], max_hosts_per_cidr: int = 1024) -> list[str]:
    """
    Expands individual IP addresses, hostnames, and CIDR subnets (e.g., 172.16.1.0/24, /23, /22, /31, /32).
    Prevents accidental explosion of large network masks (/16 or /8) and drops malformed CIDRs.
    """
    expanded: list[str] = []
    seen: set[str] = set()

    for item in targets:
        item = item.strip()
        if not item:
            continue

        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                num_hosts = network.num_addresses
                if num_hosts > max_hosts_per_cidr + 2:
                    print(
                        f"[!] Warning: Subnet {item} has {num_hosts} addresses. "
                        f"Limiting expansion to first {max_hosts_per_cidr} hosts."
                    )
                count = 0
                for host in network.hosts():
                    if count >= max_hosts_per_cidr:
                        break
                    ip_str = str(host)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        expanded.append(ip_str)
                        count += 1
            except ValueError as e:
                print(f"[!] Failed to parse CIDR {item}: {e}. Skipping invalid CIDR target.")
                logger.warning("Skipping invalid CIDR target %r: %s", item, e)
        else:
            canon_ip = _try_canonical_ip(item)
            target_val = canon_ip if canon_ip is not None else item
            if target_val not in seen:
                seen.add(target_val)
                expanded.append(target_val)

    return expanded


def load_credentials(path: str = "credentials.json") -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _normalize_vendor_tag(raw_vendor: str | None) -> str:
    """Resolve a vendor tag or alias to its canonical key in `VENDOR_DRIVER_MAP`, or `""` if unknown."""
    norm = (raw_vendor or "").strip().lower()
    if not norm:
        return ""
    if norm in VENDOR_DRIVER_MAP:
        drv_cls = VENDOR_DRIVER_MAP[norm]
        return resolve_vendor_for_driver(drv_cls) or norm
    return canonicalize_vendor(norm)


def validate_credentials(entries: object, source: str = "credentials.json") -> tuple[list[dict], list[str], list[str]]:
    """
    Validates parsed credential profiles and removes exact duplicates.
    Returns (valid_entries, warnings, errors).
    """
    warnings: list[str] = []
    errors: list[str] = []
    valid_entries: list[dict] = []

    if not isinstance(entries, list):
        errors.append(f"{source}: top-level JSON must be a list of credential objects, got {type(entries).__name__}.")
        return valid_entries, warnings, errors

    known_keys = {"name", "vendor", "username", "password", "secret", "enable_secret"}
    seen: dict[tuple[str, str, str, str], str] = {}
    for idx, item in enumerate(entries):
        label = f"{source}[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{label}: expected JSON object, got {type(item).__name__}.")
            continue

        name = item.get("name", label)
        if not isinstance(name, str) or not name.strip():
            name = label

        for extra_k in item:
            if extra_k not in known_keys:
                warnings.append(
                    f"{name}: unrecognized key '{extra_k}' (expected name, vendor, username, password, secret)."
                )

        username = item.get("username")
        if not isinstance(username, str) or not username.strip():
            errors.append(f"{name}: missing or empty 'username' string.")
            continue
        username_clean = username.strip()

        password = item.get("password", "")
        if not isinstance(password, str):
            errors.append(f"{name}: 'password' must be a string, got {type(password).__name__}.")
            continue

        secret = item.get("secret", "")
        if secret is None:
            secret = ""
        if not isinstance(secret, str):
            errors.append(f"{name}: 'secret' must be a string, got {type(secret).__name__}.")
            continue

        has_legacy_enable_secret = "enable_secret" in item
        legacy_secret = item.get("enable_secret", "")
        if legacy_secret is None:
            legacy_secret = ""
        if not isinstance(legacy_secret, str):
            errors.append(f"{name}: 'enable_secret' must be a string, got {type(legacy_secret).__name__}.")
            continue
        if has_legacy_enable_secret:
            warnings.append(f"{name}: 'enable_secret' is deprecated; use canonical 'secret' instead.")
        if secret and legacy_secret and secret != legacy_secret:
            errors.append(f"{name}: conflicting 'secret' and 'enable_secret' values; use 'secret' only.")
            continue
        effective_secret = secret or legacy_secret

        vendor = item.get("vendor", "")
        if vendor is None:
            vendor = ""
        if not isinstance(vendor, str):
            errors.append(f"{name}: 'vendor' must be a string, got {type(vendor).__name__}.")
            continue
        vendor_raw = vendor.strip().lower()
        vendor_canon = _normalize_vendor_tag(vendor_raw)
        if vendor_raw and not vendor_canon:
            warnings.append(
                f"{name}: unknown vendor tag '{vendor}' (not in VENDOR_DRIVER_MAP; will not get vendor-priority sorting)."
            )
        vendor_norm = vendor_canon or vendor_raw

        dedup_key = (vendor_norm, username_clean, password, effective_secret)
        if dedup_key in seen:
            warnings.append(
                f"{name}: duplicate of '{seen[dedup_key]}' (vendor={vendor_norm or 'any'}, username={username_clean!r}) — skipping."
            )
            continue
        seen[dedup_key] = name

        normalized = dict(item)
        normalized.pop("enable_secret", None)
        normalized["username"] = username_clean
        normalized["password"] = password
        if "secret" in item or has_legacy_enable_secret or effective_secret:
            normalized["secret"] = effective_secret
        if vendor_norm:
            normalized["vendor"] = vendor_norm
        valid_entries.append(normalized)

    return valid_entries, warnings, errors


def load_and_validate_credentials(
    credentials_path: str | list[str] | tuple[str, ...] = "credentials.json",
) -> tuple[list[dict], list[str], list[str]]:
    """
    Loads and validates one or more credential JSON files before a crawl starts.
    Returns (valid_entries, warnings, errors).
    """
    paths = list(credentials_path) if isinstance(credentials_path, (list, tuple)) else [credentials_path]
    all_raw: list[dict] = []
    warnings: list[str] = []
    errors: list[str] = []

    for path in paths:
        if not os.path.exists(path):
            errors.append(f"Credential file not found: {path}")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {path} (line {e.lineno}, col {e.colno}): {e.msg}")
            continue
        except OSError as e:
            errors.append(f"Failed to read {path}: {e}")
            continue

        valid, w, err = validate_credentials(data, source=path)
        all_raw.extend(valid)
        warnings.extend(w)
        errors.extend(err)

    # Cross-file deduplication if multiple credential files were supplied
    if len(paths) > 1 and all_raw:
        all_raw, w_cross, _ = validate_credentials(all_raw, source="merged_credentials")
        warnings.extend(w_cross)

    if not all_raw and not errors:
        errors.append("No valid credential profiles found.")

    return all_raw, warnings, errors


_LOG_EVENT_LOCK = threading.Lock()
_INLINE_SECRET_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|enable_secret|passphrase|community|token|api[_-]?key|auth[_-]?pwd|priv[_-]?pwd|pre-shared-key)\s*[=:]\s*)(\S+)"
)
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)


def _scrub_log_message(msg: str, secrets: Iterable[str] = ()) -> str:
    """Redact inline secret key/value pairs, private keys, and known credential literals from event logs."""
    if not msg:
        return ""
    scrubbed = _PEM_BLOCK_RE.sub("<REDACTED_PRIVATE_KEY>", str(msg))
    scrubbed = _INLINE_SECRET_RE.sub(r"\1<REDACTED>", scrubbed)
    unique_secrets = sorted({s for s in secrets if isinstance(s, str) and s}, key=len, reverse=True)
    for secret_val in unique_secrets:
        scrubbed = scrubbed.replace(secret_val, "<REDACTED>")
    return scrubbed


def _log_event(log_path: str, msg: str, secrets: Iterable[str] = ()):
    if not log_path:
        return
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_msg = _scrub_log_message(msg, secrets=secrets)
    try:
        with _LOG_EVENT_LOCK:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {safe_msg}\n")
    except OSError as exc:
        logger.debug("Failed to append crawler event to %s: %s", log_path, exc)


def crawl_target(
    ip: str,
    credentials: list[dict],
    timeout: int = 8,
    session_log: str = "",
    log_file: str = "",
) -> dict | None:
    """Compatibility wrapper delegating single-target SSH crawls to `crawl_target_with_ports()`."""
    res = crawl_target_with_ports(
        ip=ip,
        credentials=credentials,
        timeout=timeout,
        session_log=session_log,
        log_file=log_file,
        open_ports=[(22, "ssh")],
    )
    if res and res.get("status") == "success":
        return res
    return None


def parse_target_specs(
    targets: list[str],
    ssh_ports: list[int] | None = None,
    telnet_ports: list[int] | None = None,
) -> tuple[list[str], dict[str, list[tuple[int, str]]]]:
    """
    Parse target specifications supporting plain IPv4/IPv6 addresses, CIDRs,
    `host:port`, and bracketed `[ipv6]:port` syntax. Validates ports in 1..65535.
    Returns `(expanded_ips, explicit_ports_by_ip)`.
    """
    eff_ssh = ssh_ports if ssh_ports is not None else [22]
    eff_telnet = telnet_ports if telnet_ports is not None else [23]
    ssh_set = {p for p in eff_ssh if isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535}
    telnet_set = {p for p in eff_telnet if isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535}
    default_telnet_23 = telnet_ports is None
    expanded_ips: list[str] = []
    seen_ips: set[str] = set()
    explicit_ports: dict[str, list[tuple[int, str]]] = {}

    def _add_explicit(host_val: str, port_num: int) -> None:
        transport = (
            "telnet"
            if (port_num in telnet_set or (default_telnet_23 and port_num == 23)) and port_num not in ssh_set
            else "ssh"
        )
        if host_val not in seen_ips:
            seen_ips.add(host_val)
            expanded_ips.append(host_val)
        explicit_ports.setdefault(host_val, [])
        if (port_num, transport) not in explicit_ports[host_val]:
            explicit_ports[host_val].append((port_num, transport))

    for raw in targets:
        t = raw.strip()
        if not t:
            continue

        # 1. Bracketed IPv6: `[2001:db8::1]:2222` or `[2001:db8::1]`
        if t.startswith("["):
            m_bport = re.fullmatch(r"\[([^\[\]]+)\]:(\d+)", t)
            if m_bport:
                host_inner, port_str = m_bport.group(1).strip(), m_bport.group(2)
                port = int(port_str)
                canon = _try_canonical_ip(host_inner)
                if not canon or not (1 <= port <= 65535):
                    logger.warning("Skipping invalid bracketed IPv6 target %r", t)
                    continue
                _add_explicit(canon, port)
                continue
            m_bonly = re.fullmatch(r"\[([^\[\]]+)\]", t)
            if m_bonly:
                canon = _try_canonical_ip(m_bonly.group(1).strip())
                if not canon:
                    logger.warning("Skipping invalid bracketed IPv6 target %r", t)
                    continue
                if canon not in seen_ips:
                    seen_ips.add(canon)
                    expanded_ips.append(canon)
                continue
            logger.warning("Skipping malformed bracketed target %r", t)
            continue

        # 2. Bare IPv4 / IPv6 literal (without port or CIDR)
        if "/" not in t:
            canon_ip = _try_canonical_ip(t)
            if canon_ip is not None:
                if canon_ip not in seen_ips:
                    seen_ips.add(canon_ip)
                    expanded_ips.append(canon_ip)
                continue

        # 3. Unbracketed `host:port` (single colon, no slash)
        if ":" in t and "/" not in t:
            if t.count(":") != 1:
                logger.warning("Skipping invalid target specification %r", t)
                continue
            host, port_str = t.rsplit(":", 1)
            host = host.strip()
            if not host or not port_str.isdigit():
                logger.warning("Skipping malformed host:port target %r", t)
                continue
            port = int(port_str)
            if not (1 <= port <= 65535):
                logger.warning("Skipping target %r with out-of-range TCP port %d (must be 1..65535)", t, port)
                continue
            canon_host = _try_canonical_ip(host) or host
            _add_explicit(canon_host, port)
            continue

        # 4. CIDR subnet or hostname
        for ip in expand_targets([t]):
            if ip not in seen_ips:
                seen_ips.add(ip)
                expanded_ips.append(ip)

    return expanded_ips, explicit_ports


def build_partial_device_record(
    ip: str,
    mac: str = "",
    vendor: str = "Unknown",
    banner: str = "",
    port: int = 22,
    transport: str = "ssh",
    status: str = "unauthenticated",
    device_type: str = "unknown",
    model_override: str = "",
) -> dict:
    """
    Build a partial normalized `device_data` record for reachable hosts that
    could not be authenticated or lack a supported driver, so they appear in
    `asset_inventory.csv` and reports.
    """
    if transport == "arp":
        mgmt_method = "ARP/OUI"
    elif transport == "http":
        mgmt_method = "HTTP" if port == 80 else f"HTTP:{port}"
    elif transport == "https":
        mgmt_method = "HTTPS" if port == 443 else f"HTTPS:{port}"
    elif transport == "telnet":
        mgmt_method = "Telnet" if port == 23 else f"Telnet:{port}"
    else:
        mgmt_method = "SSH" if port == 22 else f"SSH:{port}"

    oui_vendor = oui_lookup.get_vendor(mac) if mac else ""
    if vendor and vendor.lower() != "unknown":
        resolved_vendor = vendor
    elif oui_vendor and oui_vendor.lower() != "unknown":
        resolved_vendor = oui_vendor
    else:
        resolved_vendor = "Unknown"

    clean_banner = banner.strip().replace("\r", " ").replace("\n", " ") if banner else ""
    if device_type == "unknown":
        app_class = classify_non_network_appliance(vendor_oui=oui_vendor, banner=clean_banner)
        if app_class:
            device_type, auto_model = app_class
            if not model_override:
                model_override = auto_model

    if model_override:
        model = model_override
    elif clean_banner:
        model = clean_banner[:60]
    elif resolved_vendor != "Unknown":
        model = f"{resolved_vendor} Device"
    else:
        model = "Unknown"

    from net_docu_crawler.schema import stamp_schema_v2

    return stamp_schema_v2(
        {
            "ip": ip,
            "status": status,
            "mgmt_method": mgmt_method,
            "vendor": resolved_vendor,
            "device_type": device_type,
            "device_persona": "appliance" if device_type in ("av_control", "camera", "display") else "unknown",
            "hostname": ip,
            "model": model,
            "serial": "Unknown",
            "firmware": "Unknown",
            "mac_address": mac.lower() if mac else "",
            "l3_interfaces": [],
            "interfaces_detail": {},
            "neighbors": [],
            "routes": [],
            "arp_table": [],
            "mac_table": [],
            "vlans": {},
            "stp": {"enabled": False, "is_root": False, "vlans": {}},
            "services": {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []},
            "raw_config": "",
        }
    )


_GENERIC_HTTP_LABELS = frozenset(
    {
        "index",
        "index.html",
        "index.htm",
        "home",
        "login",
        "welcome",
        "webserver",
        "web server",
        "http",
        "https",
        "nginx",
        "apache",
        "lighttpd",
        "boa",
        "mini_httpd",
        "thttpd",
        "400 bad request",
        "401 unauthorized",
        "401 authorization required",
        "403 forbidden",
        "404 not found",
        "error",
        "redirect",
        "document moved",
    }
)


def _sanitize_http_model_label(fp: dict | None) -> str:
    """Extract a meaningful hardware/product label from an HTTP/TLS fingerprint, filtering generic web titles."""
    if not fp:
        return ""
    for candidate in (fp.get("title"), fp.get("server"), fp.get("cert_cn")):
        val = str(candidate or "").strip()
        if not val:
            continue
        low = val.lower()
        if low in _GENERIC_HTTP_LABELS:
            continue
        if low.startswith(("401 ", "403 ", "404 ", "500 ", "502 ", "503 ")):
            continue
        # Reject 16+ char pure hex hashes (e.g. session/CSRF/MD5 page titles)
        if len(val) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", val):
            continue
        return val[:60]
    return ""


def _resolve_candidate_drivers(vendor_cand: str, credentials: list[dict]) -> list[type]:
    """Return ordered driver classes to try for a detected vendor or unknown target."""
    cand_canon = _normalize_vendor_tag(vendor_cand) or (vendor_cand or "").strip().lower()
    if cand_canon in VENDOR_DRIVER_MAP:
        return [VENDOR_DRIVER_MAP[cand_canon]]
    cred_vendors = []
    for c in credentials:
        cv = _normalize_vendor_tag(c.get("vendor")) or str(c.get("vendor") or "").strip().lower()
        if cv and cv not in ("opnsense", "openwrt"):
            cred_vendors.append(cv)
    preferred = [VENDOR_DRIVER_MAP[v] for v in cred_vendors if v in VENDOR_DRIVER_MAP]
    default_order = [CiscoDriver, AristaDriver, JuniperDriver, FortinetDriver]
    return list(dict.fromkeys(preferred + default_order))


def _sort_and_scope_credentials(
    credentials: list[dict],
    vendor_cand: str,
    try_all_creds: bool,
    log_file: str,
) -> list[dict]:
    """Order and filter candidate credentials for the detected vendor to prevent AAA lockouts."""
    sorted_creds = list(credentials)
    cand_canon = _normalize_vendor_tag(vendor_cand) or (vendor_cand or "").strip().lower()

    if cand_canon in ("opnsense", "openwrt"):
        sorted_creds.sort(key=lambda c: 0 if str(c.get("username") or "").lower() == "root" else 1)
    elif cand_canon == "frrouting":
        sorted_creds.sort(
            key=lambda c: (
                0
                if str(c.get("username") or "").lower() == "frr"
                else (1 if str(c.get("username") or "").lower() == "root" else 2)
            )
        )
    elif cand_canon in ("cisco", "ciscosmb", "cisco_xr"):
        sorted_creds.sort(
            key=lambda c: (
                0
                if str(c.get("username") or "").lower() == "cisco"
                else (1 if str(c.get("username") or "").lower() == "admin" else 2)
            )
        )
    elif cand_canon == "juniper":
        sorted_creds.sort(
            key=lambda c: (
                0
                if str(c.get("username") or "").lower() == "root"
                else (1 if str(c.get("username") or "").lower() == "admin" else 2)
            )
        )
    elif cand_canon == "hpprocurve":
        sorted_creds.sort(
            key=lambda c: (
                0
                if str(c.get("username") or "").lower() == "manager"
                else (1 if str(c.get("username") or "").lower() == "admin" else 2)
            )
        )
    else:
        sorted_creds.sort(key=lambda c: 0 if str(c.get("username") or "").lower() == "admin" else 1)

    if cand_canon and cand_canon != "unknown":

        def _vendor_priority(cred: dict) -> int:
            cv = _normalize_vendor_tag(cred.get("vendor")) or str(cred.get("vendor") or "").strip().lower()
            if cv == cand_canon:
                return 0
            if not cv:
                return 1
            return 2

        sorted_creds.sort(key=_vendor_priority)
        if not try_all_creds:
            scoped_creds = [
                c
                for c in sorted_creds
                if not c.get("vendor")
                or (_normalize_vendor_tag(c.get("vendor")) or str(c.get("vendor") or "").strip().lower()) == cand_canon
            ]
            if scoped_creds:
                sorted_creds = scoped_creds
            else:
                _log_event(
                    log_file,
                    f"No credentials tagged '{cand_canon}' or untagged (and --try-all-creds is disabled); skipping {len(sorted_creds)} unrelated profiles to prevent AAA lockout.",
                )
                return []
    return sorted_creds


def _remove_empty_session_log(session_log: str) -> None:
    """Delete ``session_log`` if it exists on disk with 0 bytes after a failed connection attempt."""
    if not session_log:
        return
    try:
        if os.path.isfile(session_log) and os.path.getsize(session_log) == 0:
            os.remove(session_log)
    except OSError as exc:
        logger.debug("Unable to remove empty session log %s: %s", session_log, exc)


_HOST_KEY_ERROR_SUBSTRINGS: tuple[str, ...] = (
    "bad host key",
    "host key verification failed",
    "host key for server",
    "not found in known_hosts",
)
_TRANSPORT_ERROR_SUBSTRINGS: tuple[str, ...] = (
    "incompatible",
    "no acceptable host key",
    "no acceptable kex",
    "error reading ssh protocol banner",
    "connection refused",
    "connection reset",
    "timed out",
    "tcp connection to device failed",
)
_AUTH_ERROR_SUBSTRINGS: tuple[str, ...] = (
    "auth",
    "password",
    "login",
    "denied",
    "permission",
    "credential",
    "invalid",
    "userauth",
    "too many authentication failures",
)


def _classify_connect_error(exc: Exception) -> str:
    """Classify a `driver.connect()` exception into `auth_failed`, `transport_failed`, or `driver_failed`."""
    if isinstance(exc, (NetmikoAuthenticationException, paramiko.AuthenticationException)):
        return "auth_failed"
    err_msg = str(exc).lower()
    if isinstance(exc, paramiko.BadHostKeyException) or any(k in err_msg for k in _HOST_KEY_ERROR_SUBSTRINGS):
        return "transport_failed"
    if isinstance(exc, (NetmikoTimeoutException, TimeoutError, ConnectionError)) or any(
        k in err_msg for k in _TRANSPORT_ERROR_SUBSTRINGS
    ):
        return "transport_failed"
    if any(k in err_msg for k in _AUTH_ERROR_SUBSTRINGS):
        return "auth_failed"
    return "driver_failed"


def _build_driver_instance(
    driver_cls: type,
    ip: str,
    user: str,
    pwd: str,
    secret: str,
    timeout: int,
    session_log: str,
    port: int,
    transport: str,
    *,
    netconf: bool = False,
    netconf_port: int = 830,
    gnmi: bool = False,
    gnmi_port: int = 57400,
    gnmi_insecure: bool = False,
):
    """Instantiate `driver_cls`, forwarding NETCONF/gNMI options when supported (e.g. CiscoXRDriver)."""
    kwargs: dict[str, object] = {
        "ip": ip,
        "username": user,
        "password": pwd,
        "secret": secret,
        "timeout": timeout,
        "session_log": session_log,
        "port": port,
        "transport": transport,
    }
    if getattr(driver_cls, "__name__", "") == "CiscoXRDriver":
        kwargs.update(
            {
                "use_netconf": netconf,
                "netconf_port": netconf_port,
                "use_gnmi": gnmi,
                "gnmi_port": gnmi_port,
                "gnmi_insecure": gnmi_insecure,
            }
        )
    return driver_cls(**kwargs)


def _connect_and_crawl_once(
    driver_cls: type,
    ip: str,
    port: int,
    transport: str,
    cred: dict,
    timeout: int,
    session_log: str,
    log_file: str,
    netconf: bool = False,
    netconf_port: int = 830,
    gnmi: bool = False,
    gnmi_port: int = 57400,
    gnmi_insecure: bool = False,
) -> tuple[dict | None, str]:
    """Execute a single driver connection and crawl attempt; returns `(data, outcome)`."""
    user = cred.get("username", "")
    pwd = cred.get("password", "")
    secret = cred.get("secret", "")
    _log_event(log_file, f"Connecting to {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user})...")
    try:
        driver = _build_driver_instance(
            driver_cls,
            ip,
            user,
            pwd,
            secret,
            timeout,
            session_log,
            port,
            transport,
            netconf=netconf,
            netconf_port=netconf_port,
            gnmi=gnmi,
            gnmi_port=gnmi_port,
            gnmi_insecure=gnmi_insecure,
        )
        conn = driver.connect()
    except Exception as e:
        _remove_empty_session_log(session_log)
        safe_err = _scrub_log_message(str(e), secrets=(pwd, secret))
        _log_event(
            log_file,
            f"Connection attempt failed on {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user}): {safe_err}",
        )
        return None, _classify_connect_error(e)

    try:
        succ_msg = f"Successfully connected to {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user})"
        print(f"[+] {succ_msg}")
        _log_event(log_file, succ_msg)

        # Tier 3: Post-Auth Safe Prompt Inspection before sending vendor CLI commands
        raw_prompt = ""
        find_p = getattr(conn, "find_prompt", None)
        if callable(find_p):
            try:
                p_val = find_p()
                if isinstance(p_val, str):
                    raw_prompt = p_val
            except Exception:
                raw_prompt = ""
        if not raw_prompt:
            bp = getattr(conn, "base_prompt", "")
            if isinstance(bp, str):
                raw_prompt = bp
        if raw_prompt.strip():
            prompt_os = inspect_prompt_os(raw_prompt)
            prompt_vendor = resolve_prompt_vendor(raw_prompt)
            if prompt_vendor == "unknown" and driver_cls.__name__ == "CiscoDriver":
                cleaned_p = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", raw_prompt).strip()
                last_p = [ln.strip() for ln in cleaned_p.splitlines() if ln.strip()][-1] if cleaned_p else ""
                if re.search(
                    r"^(?:\[[^\[\]\s@]+@[^\[\]\s]+\s+[^\]]+\]|[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+:[^>\r\n]*)\s*[#$]\s*$",
                    last_p,
                ):
                    prompt_vendor = "frrouting"
                    prompt_os = "linux_frr"
            if prompt_vendor != "unknown":
                target_cls = resolve_driver_for_vendor(prompt_vendor)
                if isinstance(target_cls, type) and target_cls is not driver_cls:
                    _log_event(
                        log_file,
                        f"Tier 3 prompt inspection ({raw_prompt.strip()!r} -> {prompt_os}) switched driver "
                        f"{driver_cls.__name__} -> {target_cls.__name__} on {ip}:{port}",
                    )
                    driver = _build_driver_instance(
                        target_cls,
                        ip,
                        user,
                        pwd,
                        secret,
                        timeout,
                        session_log,
                        port,
                        transport,
                        netconf=netconf,
                        netconf_port=netconf_port,
                        gnmi=gnmi,
                        gnmi_port=gnmi_port,
                        gnmi_insecure=gnmi_insecure,
                    )
                    paging_cmd = getattr(driver, "paging_cmd", "")
                    if paging_cmd and hasattr(conn, "send_command"):
                        try:
                            conn.send_command(paging_cmd)
                        except Exception as pg_exc:
                            logger.debug("[%s] Tier 3 paging disable '%s' failed: %s", ip, paging_cmd, pg_exc)

        data = driver.crawl(conn)
        if netconf and callable(getattr(driver, "fetch_netconf_operational", None)):
            nc_xml = driver.fetch_netconf_operational()
            if nc_xml:
                data["netconf_operational"] = nc_xml
        if gnmi and callable(getattr(driver, "fetch_gnmi_operational", None)):
            gnmi_data = driver.fetch_gnmi_operational()
            if gnmi_data:
                data["gnmi_operational"] = gnmi_data
    except Exception as crawl_exc:
        safe_err = _scrub_log_message(str(crawl_exc), secrets=(pwd, secret))
        _log_event(
            log_file,
            f"Crawl failed after authentication on {ip}:{port} ({transport}) with {driver_cls.__name__} (User: {user}): {safe_err}",
        )
        return None, "crawl_failed"
    finally:
        try:
            disconnect = getattr(conn, "disconnect", None) or getattr(conn, "close", None)
            if callable(disconnect):
                disconnect()
        except Exception as disc_exc:
            logger.debug("Disconnect cleanup failed for %s: %s", ip, disc_exc)

    _log_event(log_file, f"Crawl completed successfully for {ip} (Hostname: {data.get('hostname')})")
    return data, "success"


def _try_driver_credentials(
    ip: str,
    port: int,
    transport: str,
    vendor_cand: str,
    driver_classes: list[type],
    sorted_creds: list[dict],
    try_all_creds: bool,
    timeout: int,
    session_log: str,
    log_file: str,
    attempted_users: set[str] | None = None,
    stop_host: list[bool] | None = None,
    netconf: bool = False,
    netconf_port: int = 830,
    gnmi: bool = False,
    gnmi_port: int = 57400,
    gnmi_insecure: bool = False,
) -> tuple[dict | None, bool]:
    """Attempt authentication and crawl across candidate driver classes and credentials.

    Enforces strict AAA lockout protection: at most ONE authentication attempt per
    normalized username per target IP across passwords, drivers, and transports/ports.
    """
    saw_auth_failure = False
    user_ledger: set[str] = attempted_users if attempted_users is not None else set()
    for driver_cls in driver_classes:
        if transport == "telnet" and not getattr(driver_cls, "supports_telnet", True):
            continue
        driver_creds = sorted_creds
        if vendor_cand == "unknown" and not try_all_creds:
            drv_vendor = resolve_vendor_for_driver(driver_cls)
            if drv_vendor:
                driver_creds = [
                    c
                    for c in sorted_creds
                    if not c.get("vendor")
                    or (_normalize_vendor_tag(c.get("vendor")) or str(c.get("vendor") or "").strip().lower())
                    == drv_vendor
                ]
        for cred in driver_creds:
            user = cred.get("username", "")
            if not user:
                continue
            user_key = user.strip().lower()
            if not user_key or user_key in user_ledger:
                continue
            telemetry_kwargs = {}
            if netconf or gnmi or netconf_port != 830 or gnmi_port != 57400 or gnmi_insecure:
                telemetry_kwargs = {
                    "netconf": netconf,
                    "netconf_port": netconf_port,
                    "gnmi": gnmi,
                    "gnmi_port": gnmi_port,
                    "gnmi_insecure": gnmi_insecure,
                }
            data, outcome = _connect_and_crawl_once(
                driver_cls,
                ip,
                port,
                transport,
                cred,
                timeout,
                session_log,
                log_file,
                **telemetry_kwargs,
            )
            if outcome == "success":
                return data, saw_auth_failure
            if outcome == "crawl_failed":
                user_ledger.add(user_key)
                if stop_host is not None:
                    stop_host.append(True)
                return None, saw_auth_failure
            if outcome == "auth_failed":
                saw_auth_failure = True
                user_ledger.add(user_key)
                continue
            if outcome == "transport_failed":
                return None, saw_auth_failure
            user_ledger.add(user_key)
            break
    return None, saw_auth_failure


def _identify_port_vendor(
    ip: str,
    port: int,
    transport: str,
    host_mac: str,
    hint_norm: str,
    last_vendor: str,
    timeout: int,
    http_fingerprint: bool,
    http_probed: bool,
    cached_http_fp: dict | None,
    log_file: str,
) -> tuple[str, str, tuple[str, str] | None, bool, dict | None]:
    """Identify vendor or non-network appliance for an open `(port, transport)` target."""
    vendor_cand, banner = detect_vendor_range(
        ip, mac=host_mac, port=port, timeout=min(float(timeout), 3.0), transport=transport
    )
    hint_canon = _normalize_vendor_tag(hint_norm)
    if hint_norm and not hint_canon:
        logger.warning("Ignoring unrecognized vendor_hint %r for %s:%d", hint_norm, ip, port)
    if hint_canon:
        if vendor_cand != hint_canon:
            _log_event(
                log_file,
                f"Target {ip}:{port} ({transport}) -> vendor_hint={hint_canon!r} overriding detected vendor={vendor_cand!r}",
            )
        return hint_canon, banner, None, http_probed, cached_http_fp
    if vendor_cand == "unsupported_appliance":
        _log_event(
            log_file,
            f"Target {ip}:{port} ({transport}) -> non-network appliance ({banner!r}); skipping SSH/Telnet login.",
        )
        return vendor_cand, banner, None, http_probed, cached_http_fp
    if vendor_cand == "unknown":
        if http_fingerprint and not http_probed:
            cached_http_fp = probe_http_fingerprint(ip, timeout=min(float(timeout), 1.5))
            http_probed = True
            if cached_http_fp:
                _log_event(log_file, f"Target {ip}:{port} HTTP/TLS probe -> {cached_http_fp}")
        http_vendor = infer_vendor_from_http(cached_http_fp)
        if http_vendor != "unknown":
            vendor_cand = http_vendor
            _log_event(log_file, f"Target {ip}:{port} HTTP/TLS fingerprint identified vendor={vendor_cand}")
        else:
            app_ports = probe_appliance_ports(ip, timeout=min(float(timeout), 0.3))
            oui_v = oui_lookup.get_vendor(host_mac) if host_mac else ""
            app_class = classify_non_network_appliance(
                vendor_oui=oui_v, banner=banner, http_fp=cached_http_fp, open_app_ports=app_ports
            )
            if app_class:
                _log_event(
                    log_file,
                    f"Target {ip}:{port} ({transport}) -> non-network appliance ({app_class[1]}, ports={app_ports}); skipping SSH/Telnet login.",
                )
                return "unsupported_appliance", banner, app_class, http_probed, cached_http_fp
    if vendor_cand == "unknown" and last_vendor in VENDOR_DRIVER_MAP:
        vendor_cand = last_vendor
    return vendor_cand, banner, None, http_probed, cached_http_fp


def crawl_target_with_ports(
    ip: str,
    credentials: list[dict],
    timeout: int = 8,
    session_log: str = "",
    log_file: str = "",
    open_ports: list[tuple[int, str]] | None = None,
    mac: str = "",
    http_fingerprint: bool = True,
    vendor_hint: str = "",
    try_all_creds: bool = False,
    netconf: bool = False,
    netconf_port: int = 830,
    gnmi: bool = False,
    gnmi_port: int = 57400,
    gnmi_insecure: bool = False,
) -> dict | None:
    """Probe a target across its discovered open `(port, transport)` pairs and return normalized `device_data`."""
    ports_to_try = sorted(
        open_ports if open_ports else [(22, "ssh")], key=lambda pt: (0 if pt[1] == "ssh" else 1, pt[0])
    )
    host_mac = mac or get_mac_from_system_arp(ip)
    hint_norm = vendor_hint.strip().lower()
    last_vendor, last_banner = "unknown", ""
    last_port, last_transport = ports_to_try[0]
    last_app_class: tuple[str, str] | None = None
    cached_http_fp: dict | None = None
    http_probed, saw_auth_failure = False, False
    attempted_users: set[str] = set()
    stop_host: list[bool] = []

    for port, transport in ports_to_try:
        vendor_cand, banner, app_class, http_probed, cached_http_fp = _identify_port_vendor(
            ip,
            port,
            transport,
            host_mac,
            hint_norm,
            last_vendor,
            timeout,
            http_fingerprint,
            http_probed,
            cached_http_fp,
            log_file,
        )
        last_vendor, last_banner, last_port, last_transport = vendor_cand, banner, port, transport
        if vendor_cand == "unsupported_appliance":
            last_app_class = app_class
            break
        _log_event(
            log_file,
            f"Target {ip}:{port} ({transport}) -> vendor={vendor_cand}, mac={host_mac or 'none'}, banner={banner!r}",
        )
        driver_classes = _resolve_candidate_drivers(vendor_cand, credentials)
        sorted_creds = _sort_and_scope_credentials(credentials, vendor_cand, try_all_creds, log_file)
        data, port_auth_fail = _try_driver_credentials(
            ip,
            port,
            transport,
            vendor_cand,
            driver_classes,
            sorted_creds,
            try_all_creds,
            timeout,
            session_log,
            log_file,
            attempted_users=attempted_users,
            stop_host=stop_host,
            netconf=netconf,
            netconf_port=netconf_port,
            gnmi=gnmi,
            gnmi_port=gnmi_port,
            gnmi_insecure=gnmi_insecure,
        )
        if port_auth_fail:
            saw_auth_failure = True
        if data is not None:
            return data
        if stop_host:
            break

    _remove_empty_session_log(session_log)
    status = "unauthenticated" if (last_vendor in VENDOR_DRIVER_MAP and saw_auth_failure) else "unsupported"
    fail_msg = f"Could not authenticate or connect to {ip} (recording partial inventory status={status})"
    print(f"[-] {fail_msg}")
    _log_event(log_file, fail_msg)
    dev_type = last_app_class[0] if last_app_class else "unknown"
    model_ovr = last_app_class[1] if last_app_class else ""
    partial = build_partial_device_record(
        ip, host_mac, last_vendor, last_banner, last_port, last_transport, status, dev_type, model_ovr
    )
    if http_probed:
        partial["_http_fp"] = cached_http_fp
    return partial


_MGMT_IFACE_RE = re.compile(
    r"(?:mgmt|manage|infra|switch|sw[_-]|core|dist|loopback|^lo0|p2p|transit|uplink|default_vlan|^vlan\.?1$)",
    re.IGNORECASE,
)

_NON_INFRA_OUI_KEYWORDS: tuple[str, ...] = (
    "apple",
    "dell",
    "lenovo",
    "intel",
    "samsung",
    "google",
    "sonos",
    "roku",
    "crestron",
    "extron",
    "hikvision",
    "axis",
    "brother",
    "canon",
    "epson",
    "xerox",
    "ricoh",
    "lexmark",
    "polycom",
    "yealink",
    "grandstream",
    "ring",
    "nest",
    "raspberry",
    "microsoft",
    "vmware",
)


def _parse_cidr_list(raw_cidrs: list[str] | None) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for raw in raw_cidrs or []:
        try:
            nets.append(ipaddress.IPv4Network(raw.strip(), strict=False))
        except ValueError as exc:
            logger.debug("Ignoring invalid CIDR %r in subnet filter list: %s", raw, exc)
    return nets


def extract_followable_subnets(
    devices: list[dict],
    allow_cgnat: bool = False,
    allow_public: bool = False,
    include_routes: bool = True,
    min_prefix: int = 22,
    max_prefix: int = 31,
    mgmt_only: bool = False,
    subnet_include: list[str] | None = None,
    subnet_exclude: list[str] | None = None,
) -> list[str]:
    """
    Extract connected IPv4 subnets from crawled devices (`l3_interfaces`, plus `routes` when `include_routes=True`).
    Enforces a strict RFC 1918 boundary by default: skips 0.0.0.0/0, loopback, link-local,
    multicast, CGNAT (100.64.0.0/10 unless `allow_cgnat`), and public IPs (unless `allow_public`).
    """
    cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
    include_nets = _parse_cidr_list(subnet_include)
    exclude_nets = _parse_cidr_list(subnet_exclude)
    discovered: list[str] = []
    seen: set[str] = set()

    def _consider(raw_cidr: str, iface_name: str = ""):
        s = (raw_cidr or "").strip()
        if not s or s == "0.0.0.0/0":
            return
        if " " in s and "/" not in s:
            parts = s.split()
            if len(parts) == 2:
                s = f"{parts[0]}/{parts[1]}"
        if "/" not in s:
            return
        try:
            net = ipaddress.IPv4Interface(s).network
        except ValueError as exc:
            logger.debug("Ignoring non-CIDR interface/route entry %r: %s", s, exc)
            return
        if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
            return
        if not (min_prefix <= net.prefixlen <= max_prefix):
            return
        is_cgnat = net.overlaps(cgnat_net)
        if is_cgnat:
            if not (allow_cgnat or allow_public):
                return
        elif not net.is_private and not allow_public:
            return
        if mgmt_only and net.prefixlen < 30 and not _MGMT_IFACE_RE.search(iface_name or ""):
            return
        if include_nets and not any(net.overlaps(inc) for inc in include_nets):
            return
        if exclude_nets and any(net.overlaps(exc) for exc in exclude_nets):
            return
        key = str(net)
        if key not in seen:
            seen.add(key)
            discovered.append(key)

    for dev in devices:
        for iface in dev.get("l3_interfaces", []):
            _consider(iface.get("ip_address", ""), iface.get("interface", ""))
        if include_routes:
            for route in dev.get("routes", []):
                _consider(route.get("subnet", ""), route.get("interface", ""))

    return discovered


def _safe_ipv4_in_network(ip_str: str, net: ipaddress.IPv4Network) -> bool:
    """Return True if `ip_str` is a valid IPv4 address inside `net` (ignoring IPv6 or malformed strings)."""
    try:
        return ipaddress.IPv4Address(ip_str) in net
    except ValueError:
        return False


def _select_hop_targets_for_cidrs(
    cidrs: list[str],
    registry: DeviceRegistry,
    scanned_ip_set: set[str],
    arp_only: bool = False,
) -> list[str]:
    """
    Use harvested ARP tables to target known-live hosts inside connected subnets
    instead of blindly scanning 250+ dead IPs per VLAN.
    When `arp_only=True`, never falls back to full CIDR sweeps and skips known
    non-infrastructure endpoint OUIs (Apple, printers, cameras, AV controllers).
    When `arp_only=False` and ARP tables exist, prunes empty `/24`–`/22` subnets
    while still allowing `/29`–`/31` transit links.
    """
    selected: list[str] = []
    seen: set[str] = set(scanned_ip_set)
    arp_ips = list(registry.global_arp.keys())
    has_global_arp = bool(arp_ips)

    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as exc:
            logger.debug("Skipping invalid hop CIDR %r: %s", cidr, exc)
            continue
        arp_hits = [ip for ip in arp_ips if _safe_ipv4_in_network(ip, net)]
        if arp_hits:
            for ip in arp_hits:
                if ip in seen:
                    continue
                if arp_only:
                    arp_entry = registry.global_arp.get(ip)
                    if isinstance(arp_entry, dict):
                        oui_l = str(arp_entry.get("vendor") or "").lower()
                        if not oui_l or oui_l == "unknown":
                            mac = str(arp_entry.get("mac") or "")
                            oui_l = oui_lookup.lookup_oui(mac).lower() if mac else ""
                    elif isinstance(arp_entry, str) and arp_entry:
                        oui_l = oui_lookup.lookup_oui(arp_entry).lower()
                    else:
                        oui_l = ""
                    if oui_l and any(k in oui_l for k in _NON_INFRA_OUI_KEYWORDS):
                        continue
                seen.add(ip)
                selected.append(ip)
        elif arp_only:
            continue
        elif has_global_arp and net.prefixlen < 29:
            # Zero-ARP subnet pruning: avoid sweeping 254+ dead IPs on empty VLANs
            continue
        else:
            for ip in expand_targets([cidr]):
                if ip not in seen:
                    seen.add(ip)
                    selected.append(ip)
    return selected


def extract_neighbor_ips(
    devices: list[dict],
    registry: DeviceRegistry | None = None,
    allow_cgnat: bool = False,
    allow_public: bool = False,
) -> list[str]:
    """
    Extract unique management IPv4 addresses of CDP/LLDP infrastructure neighbors
    from crawled devices (using explicit `remote_ip` or `registry.resolve_neighbor_ip()`).
    Enforces RFC 1918 boundary unless `allow_cgnat` / `allow_public` is set.
    """
    cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
    discovered: list[str] = []
    seen: set[str] = set()

    for dev in devices:
        if dev.get("status", "success") != "success":
            continue
        for nbr in dev.get("neighbors", []):
            if str(nbr.get("device_type", "")).lower() == "ap":
                continue
            cand_ip = str(nbr.get("remote_ip", "")).strip()
            if not cand_ip and registry is not None:
                cand_ip = (
                    registry.resolve_neighbor_ip(
                        neighbor_mac=nbr.get("remote_mac", ""),
                        neighbor_name=nbr.get("remote_device", ""),
                    )
                    or ""
                )
            if not cand_ip or cand_ip in seen:
                continue
            try:
                addr = ipaddress.IPv4Address(cand_ip)
            except ValueError as exc:
                logger.debug("Skipping non-IPv4 neighbor address %r: %s", cand_ip, exc)
                continue
            if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                continue
            if addr in cgnat_net:
                if not (allow_cgnat or allow_public):
                    continue
            elif not addr.is_private and not allow_public:
                continue
            seen.add(cand_ip)
            discovered.append(cand_ip)

    return discovered


def compute_organized_output_dir(
    targets: list[str],
    base_dir: str = "deliverables",
    site: str = "auto",
    domain: str = "",
) -> str:
    """
    Computes a structured directory path: <base_dir>/<Subnet>_<TimeStamp>_<site>/
    Example: deliverables/192.168.1.0-24_20261107_221530_lan
    """
    from net_docu_crawler.domain_detector import detect_local_dns_suffix, domain_to_site_slug

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scope_slug = "multi_target"
    if targets:
        for t in targets:
            if "/" in t:
                scope_slug = t.strip().replace("/", "-").replace(":", "-")
                break
        if scope_slug == "multi_target" and targets:
            if any("192.168.1." in t for t in targets):
                scope_slug = "192.168.1.0-24"
            else:
                scope_slug = targets[0].strip().replace("/", "-").replace(":", "-")

    label = (domain or site or "auto").strip()
    if not label or label.lower() == "auto":
        label = domain_to_site_slug(detect_local_dns_suffix(), fallback="lan")

    folder_name = f"{scope_slug}_{ts}_{label}"
    return os.path.join(base_dir, folder_name)


@dataclass
class CrawlOptions:
    """Typed configuration for `crawl_network()` discovery, scope boundaries, and deliverable options."""

    targets: list[str] = field(default_factory=list)
    credentials_path: str | list[str] = "credentials.json"
    output_dir: str = ""
    organize: bool = True
    site: str = "auto"
    domain: str = ""
    sanitize_passwords: bool = False
    timeout: int = 8
    ssh_ports: list[int] | None = None
    telnet_ports: list[int] | None = None
    max_workers: int = 16
    http_fingerprint: bool = True
    snmp: bool = False
    snmp_community: str = "public"
    follow_subnets: bool = False
    follow_arp_only: bool = False
    mgmt_subnets_only: bool = False
    subnet_include: list[str] | None = None
    subnet_exclude: list[str] | None = None
    follow_routes: bool = False
    follow_neighbors: bool = True
    max_hops: int = 1
    allow_cgnat: bool = False
    allow_public_subnets: bool = False
    target_vendor: str = ""
    vendor_hint: str = ""
    try_all_creds: bool = False
    save_baseline: str = ""
    compare_baseline: str = ""
    retry_failed: str = ""
    netconf: bool = False
    netconf_port: int = 830
    gnmi: bool = False
    gnmi_port: int = 57400
    gnmi_insecure: bool = False


# Alias for callers referencing either CrawlOptions or CrawlConfig
CrawlConfig = CrawlOptions

_CRAWL_OPTION_DEFAULTS: dict[str, object] = {
    "credentials_path": "credentials.json",
    "output_dir": "",
    "organize": True,
    "site": "auto",
    "domain": "",
    "sanitize_passwords": False,
    "timeout": 8,
    "ssh_ports": None,
    "telnet_ports": None,
    "max_workers": 16,
    "http_fingerprint": True,
    "snmp": False,
    "snmp_community": "public",
    "follow_subnets": False,
    "follow_arp_only": False,
    "mgmt_subnets_only": False,
    "subnet_include": None,
    "subnet_exclude": None,
    "follow_routes": False,
    "follow_neighbors": True,
    "max_hops": 1,
    "allow_cgnat": False,
    "allow_public_subnets": False,
    "target_vendor": "",
    "vendor_hint": "",
    "try_all_creds": False,
    "save_baseline": "",
    "compare_baseline": "",
    "retry_failed": "",
    "netconf": False,
    "netconf_port": 830,
    "gnmi": False,
    "gnmi_port": 57400,
    "gnmi_insecure": False,
}


def _resolve_crawl_options(
    targets: list[str] | CrawlOptions | None,
    config: CrawlOptions | None,
    overrides: dict[str, object],
) -> CrawlOptions:
    """Merge an optional `CrawlOptions` instance with any explicitly passed `crawl_network` arguments."""
    if isinstance(targets, CrawlOptions) and config is None:
        base_cfg = replace(targets)
        explicit_targets: list[str] | None = None
    elif config is not None:
        base_cfg = replace(config)
        explicit_targets = list(targets) if targets is not None else None
    else:
        return CrawlOptions(targets=list(targets or []), **overrides)

    if explicit_targets is not None:
        base_cfg.targets = explicit_targets
    for key, val in overrides.items():
        if val != _CRAWL_OPTION_DEFAULTS[key]:
            setattr(base_cfg, key, val)
    return base_cfg


def _load_retry_failed_targets(retry_failed: str) -> tuple[list[str], list[dict]]:
    """Load retryable targets from `failed_hosts.json` and merge any sibling prior-success dataset."""
    with open(retry_failed, encoding="utf-8") as f:
        failed_entries = json.load(f)
    retry_ips: list[str] = []
    skipped_unsupported = 0
    for entry in failed_entries:
        if isinstance(entry, str):
            retry_ips.append(entry)
        elif isinstance(entry, dict) and entry.get("ip"):
            if entry.get("status") == "unsupported":
                skipped_unsupported += 1
                continue
            retry_ips.append(entry["ip"])
    if not retry_ips and isinstance(failed_entries, list):
        retry_ips = [e["ip"] for e in failed_entries if isinstance(e, dict) and e.get("ip")]
        skipped_unsupported = 0
    if skipped_unsupported:
        print(
            f"[+] Loaded {len(retry_ips)} retry target(s) from {retry_failed} (skipped {skipped_unsupported} unsupported)."
        )
    else:
        print(f"[+] Loaded {len(retry_ips)} retry target(s) from {retry_failed}.")
    if not retry_ips:
        print("[!] No retryable hosts found in failed_hosts.json.")
        return [], []

    prior_success_devices: list[dict] = []
    sibling_dataset = os.path.join(os.path.dirname(os.path.abspath(retry_failed)), "net_docu_crawler_dataset.json")
    if os.path.isfile(sibling_dataset):
        try:
            with open(sibling_dataset, encoding="utf-8") as df:
                prior_data = json.load(df)
            retry_ip_set = set(retry_ips)
            if isinstance(prior_data, list):
                prior_success_devices = [
                    d
                    for d in prior_data
                    if isinstance(d, dict)
                    and d.get("status", "success") == "success"
                    and d.get("ip") not in retry_ip_set
                ]
                if prior_success_devices:
                    print(
                        f"[+] Merging {len(prior_success_devices)} previously succeeded device(s) from {sibling_dataset}."
                    )
        except Exception as exc:
            print(f"[!] Could not load prior dataset {sibling_dataset} for merge: {exc}")
    return retry_ips, prior_success_devices


def _resolve_run_output_dir(cfg: CrawlOptions, targets: list[str]) -> tuple[str, bool, str, str]:
    """Determine `(run_output_dir, is_organized, logs_dir, crawler_log)` and ensure directories exist."""
    if cfg.organize:
        base = cfg.output_dir if (cfg.output_dir and cfg.output_dir != "auto") else "deliverables"
        run_output_dir = compute_organized_output_dir(targets, base_dir=base, site=cfg.site, domain=cfg.domain)
        is_organized = True
    elif not cfg.output_dir or cfg.output_dir == "auto":
        run_output_dir = "docs/net_docu_crawler"
        is_organized = False
    else:
        run_output_dir = cfg.output_dir
        is_organized = False

    os.makedirs(run_output_dir, exist_ok=True)
    logs_dir = os.path.join(run_output_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    crawler_log = os.path.join(logs_dir, "crawler_execution.log")
    return run_output_dir, is_organized, logs_dir, crawler_log


def _crawl_target_batch(
    batch_ips: list[str],
    batch_explicit: dict[str, list[tuple[int, str]]],
    cfg: CrawlOptions,
    credentials: list[dict],
    registry: DeviceRegistry,
    raw_devices: list[dict],
    scanned_ip_set: set[str],
    logs_dir: str,
    crawler_log: str,
) -> None:
    """Pre-scan a batch of target IPs for open management ports and crawl reachable devices concurrently."""
    if not batch_ips:
        return
    eff_ssh = cfg.ssh_ports if cfg.ssh_ports is not None else [22]
    eff_telnet = cfg.telnet_ports if cfg.telnet_ports is not None else [23]
    scanned_ip_set.update(batch_ips)
    print(f"[+] Pre-scanning {len(batch_ips)} target(s) for SSH {eff_ssh} / Telnet {eff_telnet}...")
    _log_event(crawler_log, f"Pre-scanning {len(batch_ips)} targets: {batch_ips}")

    scan_ips = [ip for ip in batch_ips if ip not in batch_explicit]
    probe_timeout = min(max(float(cfg.timeout) * (0.25 if len(scan_ips) <= 4 else 0.15), 0.8), 3.0)
    probe_workers = max(1, min(cfg.max_workers, len(scan_ips))) if scan_ips else 1
    open_ports_map = (
        scan_subnet_ports(scan_ips, eff_ssh, eff_telnet, timeout=probe_timeout, max_workers=probe_workers)
        if scan_ips
        else {}
    )
    open_ports_map.update(batch_explicit)

    reachable = [ip for ip in batch_ips if open_ports_map.get(ip)]
    print(f"[+] Found {len(reachable)} reachable host(s) with open management ports.")
    _log_event(crawler_log, f"Reachable targets ({len(reachable)}): {reachable}")

    targets_to_crawl = []
    for ip in reachable:
        if not registry.start_crawl(ip):
            print(f"[*] Skipping {ip}: already registered as alias/SVI of a crawled device.")
            _log_event(crawler_log, f"Skipping {ip}: already registered as alias/SVI of a crawled device.")
            continue
        targets_to_crawl.append(ip)
    if not targets_to_crawl:
        return

    batch_secrets = tuple(
        s
        for c in credentials
        for s in (c.get("password", ""), c.get("secret", ""))
        if isinstance(s, str) and len(s) >= 4
    )
    registered_ips: set[str] = set()
    try:
        with ThreadPoolExecutor(max_workers=max(1, min(cfg.max_workers, len(targets_to_crawl)))) as pool:
            future_to_ip = {
                pool.submit(
                    crawl_target_with_ports,
                    ip,
                    credentials,
                    timeout=cfg.timeout,
                    session_log=os.path.join(logs_dir, f"{ip.replace(':', '_')}_raw_session.log"),
                    log_file=crawler_log,
                    open_ports=open_ports_map.get(ip),
                    mac=registry.get_arp_mac(ip),
                    http_fingerprint=cfg.http_fingerprint,
                    vendor_hint=cfg.vendor_hint,
                    try_all_creds=cfg.try_all_creds,
                    netconf=cfg.netconf,
                    netconf_port=cfg.netconf_port,
                    gnmi=cfg.gnmi,
                    gnmi_port=cfg.gnmi_port,
                    gnmi_insecure=cfg.gnmi_insecure,
                ): ip
                for ip in targets_to_crawl
            }
            results_by_ip: dict[str, dict | None] = {}
            for fut in as_completed(future_to_ip):
                ip = future_to_ip[fut]
                try:
                    results_by_ip[ip] = fut.result()
                except Exception as exc:
                    safe_exc = _scrub_log_message(str(exc), secrets=batch_secrets)
                    _log_event(crawler_log, f"Unhandled worker exception for {ip}: {safe_exc}")
                    results_by_ip[ip] = None

        for ip in targets_to_crawl:
            device_data = results_by_ip.get(ip)
            if device_data:
                registry.register_device(device_data)
                registered_ips.add(ip)
                raw_devices.append(device_data)
    finally:
        for ip in targets_to_crawl:
            if ip not in registered_ips:
                registry.release_crawl(ip)


def _discover_neighbor_and_subnet_hops(
    raw_devices: list[dict],
    registry: DeviceRegistry,
    scanned_ip_set: set[str],
    scanned_cidrs: set[str],
    cfg: CrawlOptions,
    credentials: list[dict],
    logs_dir: str,
    crawler_log: str,
) -> None:
    """Follow CDP/LLDP neighbor management IPs and optional connected L3 subnets across hops."""
    if cfg.follow_neighbors and not cfg.retry_failed:
        for hop in range(1, max(1, cfg.max_hops) + 1):
            nbr_ips = [
                ip
                for ip in extract_neighbor_ips(
                    raw_devices,
                    registry=registry,
                    allow_cgnat=cfg.allow_cgnat,
                    allow_public=cfg.allow_public_subnets,
                )
                if ip not in scanned_ip_set
            ]
            if not nbr_ips:
                break
            print(f"[+] Neighbor Hop {hop}: queuing {len(nbr_ips)} CDP/LLDP neighbor IP(s): {nbr_ips}")
            _log_event(crawler_log, f"Neighbor Hop {hop} queuing IPs: {nbr_ips}")
            _crawl_target_batch(
                nbr_ips, {}, cfg, credentials, registry, raw_devices, scanned_ip_set, logs_dir, crawler_log
            )

    if (cfg.follow_subnets or cfg.follow_arp_only) and cfg.max_hops > 0:
        for hop in range(1, cfg.max_hops + 1):
            candidate_cidrs = extract_followable_subnets(
                raw_devices,
                allow_cgnat=cfg.allow_cgnat,
                allow_public=cfg.allow_public_subnets,
                include_routes=cfg.follow_routes,
                mgmt_only=cfg.mgmt_subnets_only,
                subnet_include=cfg.subnet_include,
                subnet_exclude=cfg.subnet_exclude,
            )
            new_cidrs = [c for c in candidate_cidrs if c not in scanned_cidrs]
            if not new_cidrs:
                break
            scanned_cidrs.update(new_cidrs)
            hop_ips = _select_hop_targets_for_cidrs(
                new_cidrs,
                registry,
                scanned_ip_set,
                arp_only=cfg.follow_arp_only,
            )
            if not hop_ips:
                break
            print(f"[+] Hop {hop}: following {len(new_cidrs)} subnet(s) ({len(hop_ips)} target IP(s)): {new_cidrs}")
            _log_event(crawler_log, f"Hop {hop} following subnets ({len(hop_ips)} IPs): {new_cidrs}")
            _crawl_target_batch(
                hop_ips, {}, cfg, credentials, registry, raw_devices, scanned_ip_set, logs_dir, crawler_log
            )


def _append_local_arp_inventory(
    raw_devices: list[dict],
    registry: DeviceRegistry,
    scanned_ip_set: set[str],
) -> None:
    """Include local ARP-visible hosts within the scanned scope that had no open SSH/Telnet ports."""
    arp_entries = get_arp_table_entries()
    for arp_ip, arp_mac in arp_entries.items():
        if scanned_ip_set and arp_ip not in scanned_ip_set:
            continue
        if not registry.start_crawl(arp_ip):
            continue
        try:
            arp_rec = build_partial_device_record(
                ip=arp_ip,
                mac=arp_mac,
                vendor="Unknown",
                banner="",
                port=0,
                transport="arp",
                status="discovered",
            )
            registry.register_device(arp_rec)
            raw_devices.append(arp_rec)
        except BaseException:
            registry.release_crawl(arp_ip)
            raise


def _enrich_partial_devices_http(raw_devices: list[dict], cfg: CrawlOptions) -> list[dict]:
    """Enrich partial/ARP-discovered hosts via read-only HTTP/HTTPS banner and TLS cert fingerprinting."""
    partial_devs = [d for d in raw_devices if d.get("status") in ("discovered", "unauthenticated", "unsupported")]
    if cfg.http_fingerprint and partial_devs:
        to_probe = [d for d in partial_devs if "_http_fp" not in d]
        probed_results: dict[int, dict | None] = {}
        if to_probe:
            with ThreadPoolExecutor(max_workers=min(cfg.max_workers, len(to_probe))) as pool:
                http_futs = {
                    pool.submit(probe_http_fingerprint, d["ip"], timeout=min(float(cfg.timeout), 1.5)): d
                    for d in to_probe
                }
                for fut in as_completed(http_futs):
                    dev = http_futs[fut]
                    try:
                        probed_results[id(dev)] = fut.result()
                    except Exception as exc:
                        logger.debug("HTTP fingerprint probe failed for %s: %s", dev.get("ip"), exc)
                        probed_results[id(dev)] = None

        for dev in partial_devs:
            fp = dev.pop("_http_fp", None) if "_http_fp" in dev else probed_results.get(id(dev))
            if not fp:
                continue
            label = _sanitize_http_model_label(fp)
            if label and (dev.get("model") in ("Unknown", "") or dev.get("model", "").endswith(" Device")):
                dev["model"] = label
            if dev.get("status") == "discovered":
                scheme = fp["scheme"].upper()
                port = fp["port"]
                dev["mgmt_method"] = scheme if port in (80, 443) else f"{scheme}:{port}"
                dev["status"] = "unsupported"
    else:
        for dev in partial_devs:
            dev.pop("_http_fp", None)
    return partial_devs


def _enrich_partial_devices_snmp(partial_devs: list[dict], cfg: CrawlOptions) -> None:
    """Enrich partial devices via optional SNMPv2c sysDescr/sysName and GetBulk MIB fallback."""
    if not (cfg.snmp and partial_devs):
        return
    with ThreadPoolExecutor(max_workers=min(cfg.max_workers, len(partial_devs))) as pool:
        snmp_futs = {
            pool.submit(
                probe_snmp_sysinfo, d["ip"], community=cfg.snmp_community, timeout=min(float(cfg.timeout), 1.5)
            ): d
            for d in partial_devs
        }
        for fut in as_completed(snmp_futs):
            dev = snmp_futs[fut]
            try:
                info = fut.result()
            except Exception as exc:
                safe_exc = _scrub_log_message(str(exc), secrets=(cfg.snmp_community,))
                logger.debug("SNMP sysinfo probe failed for %s: %s", dev.get("ip"), safe_exc)
                info = None
            if not info:
                continue
            if info.get("sysName") and dev.get("hostname") == dev.get("ip"):
                dev["hostname"] = info["sysName"]
            if info.get("sysDescr"):
                dev["model"] = info["sysDescr"][:60]
            if dev.get("status") == "discovered":
                dev["mgmt_method"] = "SNMP"
                dev["status"] = "unsupported"

    from net_docu_crawler.snmp_collector import collect_snmp_fallback

    unauth_infra = [d for d in partial_devs if d.get("status") == "unauthenticated"]
    if not unauth_infra:
        return
    with ThreadPoolExecutor(max_workers=min(cfg.max_workers, len(unauth_infra))) as pool:
        fb_futs = {
            pool.submit(
                collect_snmp_fallback, d["ip"], community=cfg.snmp_community, timeout=min(float(cfg.timeout), 2.0)
            ): d
            for d in unauth_infra
        }
        for fut in as_completed(fb_futs):
            dev = fb_futs[fut]
            try:
                fb = fut.result() or {}
            except Exception as exc:
                safe_exc = _scrub_log_message(str(exc), secrets=(cfg.snmp_community,))
                logger.debug("SNMPv2c fallback collection failed for %s: %s", dev.get("ip"), safe_exc)
                fb = {}
            if fb.get("interfaces_detail"):
                dev["interfaces_detail"] = fb["interfaces_detail"]
                dev["mgmt_method"] = "SNMPv2c-Fallback"
            if fb.get("lldp_remote_names"):
                dev.setdefault("neighbors", []).extend(
                    [
                        {
                            "local_port": f"ifIndex-{n.get('index', '')}",
                            "remote_device": n.get("remote_device", ""),
                            "remote_port": "",
                            "remote_ip": "",
                            "remote_mac": "",
                            "platform": "",
                            "device_type": "switch",
                            "link_confidence": "one-way",
                        }
                        for n in fb["lldp_remote_names"]
                        if n.get("remote_device")
                    ]
                )


def _execute_crawl(cfg: CrawlOptions) -> list[dict]:
    """Execute network discovery and deliverable generation for a resolved `CrawlOptions` config."""
    targets = list(cfg.targets)
    prior_success_devices: list[dict] = []
    if cfg.retry_failed:
        targets, prior_success_devices = _load_retry_failed_targets(cfg.retry_failed)
        if not targets:
            return []

    credentials, cred_warnings, cred_errors = load_and_validate_credentials(cfg.credentials_path)
    for w in cred_warnings:
        print(f"[!] Credential warning: {w}")
    for err in cred_errors:
        print(f"[-] Credential error: {err}")
    if cred_errors:
        raise ValueError(
            f"Credential validation failed ({len(cred_errors)} error(s)). Fix {cfg.credentials_path} and retry."
        )

    run_output_dir, is_organized, logs_dir, crawler_log = _resolve_run_output_dir(cfg, targets)
    print(f"[+] Validated and loaded {len(credentials)} credential profile(s) from {cfg.credentials_path}")
    _log_event(
        crawler_log, f"Validated and loaded {len(credentials)} credential profile(s) from {cfg.credentials_path}"
    )
    for w in cred_warnings:
        _log_event(crawler_log, f"Credential warning: {w}")

    expanded_targets, explicit_ports = parse_target_specs(
        targets, ssh_ports=cfg.ssh_ports, telnet_ports=cfg.telnet_ports
    )
    raw_devices: list[dict] = []
    registry = DeviceRegistry()
    scanned_ip_set: set[str] = set()
    scanned_cidrs: set[str] = set()
    for t in targets:
        if "/" in t:
            t_clean = t.strip()
            try:
                scanned_cidrs.add(str(ipaddress.ip_network(t_clean, strict=False)))
            except ValueError:
                scanned_cidrs.add(t_clean)

    for prior_dev in prior_success_devices:
        registry.register_device(prior_dev)
        raw_devices.append(prior_dev)
        if prior_dev.get("ip"):
            scanned_ip_set.add(prior_dev["ip"])

    _crawl_target_batch(
        expanded_targets, explicit_ports, cfg, credentials, registry, raw_devices, scanned_ip_set, logs_dir, crawler_log
    )
    _discover_neighbor_and_subnet_hops(
        raw_devices, registry, scanned_ip_set, scanned_cidrs, cfg, credentials, logs_dir, crawler_log
    )
    _append_local_arp_inventory(raw_devices, registry, scanned_ip_set)
    partial_devs = _enrich_partial_devices_http(raw_devices, cfg)
    _enrich_partial_devices_snmp(partial_devs, cfg)

    return render_deliverables_from_dataset(
        raw_devices=raw_devices,
        registry=registry,
        run_output_dir=run_output_dir,
        targets=targets,
        is_organized=is_organized,
        sanitize_passwords=cfg.sanitize_passwords,
        target_vendor=cfg.target_vendor,
        save_baseline=cfg.save_baseline,
        compare_baseline=cfg.compare_baseline,
        logs_dir=logs_dir,
    )


def crawl_network(
    targets: list[str] | CrawlOptions | None = None,
    credentials_path: str | list[str] = "credentials.json",
    output_dir: str = "",
    organize: bool = True,
    site: str = "auto",
    domain: str = "",
    sanitize_passwords: bool = False,
    timeout: int = 8,
    ssh_ports: list[int] | None = None,
    telnet_ports: list[int] | None = None,
    max_workers: int = 16,
    http_fingerprint: bool = True,
    snmp: bool = False,
    snmp_community: str = "public",
    follow_subnets: bool = False,
    follow_arp_only: bool = False,
    mgmt_subnets_only: bool = False,
    subnet_include: list[str] | None = None,
    subnet_exclude: list[str] | None = None,
    follow_routes: bool = False,
    follow_neighbors: bool = True,
    max_hops: int = 1,
    allow_cgnat: bool = False,
    allow_public_subnets: bool = False,
    target_vendor: str = "",
    vendor_hint: str = "",
    try_all_creds: bool = False,
    save_baseline: str = "",
    compare_baseline: str = "",
    retry_failed: str = "",
    netconf: bool = False,
    netconf_port: int = 830,
    gnmi: bool = False,
    gnmi_port: int = 57400,
    gnmi_insecure: bool = False,
    config: CrawlOptions | None = None,
) -> list[dict]:
    """
    Crawl target network devices and generate full documentation deliverables.
    Accepts either a `CrawlOptions` (`config=...`) dataclass or legacy positional/keyword arguments.
    """
    overrides: dict[str, object] = {
        "credentials_path": credentials_path,
        "output_dir": output_dir,
        "organize": organize,
        "site": site,
        "domain": domain,
        "sanitize_passwords": sanitize_passwords,
        "timeout": timeout,
        "ssh_ports": ssh_ports,
        "telnet_ports": telnet_ports,
        "max_workers": max_workers,
        "http_fingerprint": http_fingerprint,
        "snmp": snmp,
        "snmp_community": snmp_community,
        "follow_subnets": follow_subnets,
        "follow_arp_only": follow_arp_only,
        "mgmt_subnets_only": mgmt_subnets_only,
        "subnet_include": subnet_include,
        "subnet_exclude": subnet_exclude,
        "follow_routes": follow_routes,
        "follow_neighbors": follow_neighbors,
        "max_hops": max_hops,
        "allow_cgnat": allow_cgnat,
        "allow_public_subnets": allow_public_subnets,
        "target_vendor": target_vendor,
        "vendor_hint": vendor_hint,
        "try_all_creds": try_all_creds,
        "save_baseline": save_baseline,
        "compare_baseline": compare_baseline,
        "retry_failed": retry_failed,
        "netconf": netconf,
        "netconf_port": netconf_port,
        "gnmi": gnmi,
        "gnmi_port": gnmi_port,
        "gnmi_insecure": gnmi_insecure,
    }
    cfg = _resolve_crawl_options(targets=targets, config=config, overrides=overrides)
    return _execute_crawl(cfg)


def _prune_empty_session_logs(logs_dir: str) -> None:
    """Remove any 0-byte ``*_raw_session.log`` files left in ``logs_dir``."""
    if not logs_dir or not os.path.isdir(logs_dir):
        return
    for fname in os.listdir(logs_dir):
        if not fname.endswith("_raw_session.log"):
            continue
        _remove_empty_session_log(os.path.join(logs_dir, fname))


def _sanitize_session_logs(logs_dir: str):
    """Redact credentials/secrets from raw Netmiko/Paramiko session transcripts when --sanitize-passwords is enabled."""
    if not logs_dir or not os.path.isdir(logs_dir):
        return
    for fname in os.listdir(logs_dir):
        if not fname.endswith("_raw_session.log"):
            continue
        fpath = os.path.join(logs_dir, fname)
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                raw_txt = f.read()
            cleaned = sanitize_raw_config(raw_txt)
            if cleaned != raw_txt:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(cleaned)
        except OSError as exc:
            logger.debug("Failed to sanitize session log %s: %s", fpath, exc)


def enrich_devices_from_dhcp_reservations(raw_devices: list[dict]) -> list[dict]:
    """
    Cross-reference discovered/unauthenticated/unsupported hosts against DHCP
    static reservations extracted from crawled firewalls/routers/switches so
    APs, WLCs, NVRs, and printers inherit their real reservation hostnames.
    """
    by_ip: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}
    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        dhcp = dev.get("dhcp") or {}
        for res in dhcp.get("reservations", []):
            hostname = str(res.get("hostname") or "").strip()
            if not hostname:
                continue
            ip_val = str(res.get("ip") or "").strip()
            mac_val = oui_lookup.normalize_mac(str(res.get("mac") or "")).lower()
            info = {"hostname": hostname, "pool": str(res.get("pool") or "").strip()}
            if ip_val and ip_val not in by_ip:
                by_ip[ip_val] = info
            if mac_val and mac_val not in by_mac:
                by_mac[mac_val] = info

    if not by_ip and not by_mac:
        return raw_devices

    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        status = str(dev.get("status") or "").lower()
        cur_host = str(dev.get("hostname") or "").strip()
        ip_val = str(dev.get("ip") or "").strip()
        mac_val = oui_lookup.normalize_mac(str(dev.get("mac_address") or "")).lower()
        needs_name = (
            status in ("discovered", "unauthenticated", "unsupported")
            or not cur_host
            or cur_host in ("Unknown", ip_val)
            or cur_host.startswith("ARP_")
        )
        if not needs_name:
            continue
        match = by_ip.get(ip_val) or (by_mac.get(mac_val) if mac_val else None)
        if not match:
            continue
        dev["hostname"] = match["hostname"]
        dev["canonical_hostname"] = match["hostname"]
        if not dev.get("model") or dev.get("model") in ("Unknown", "N/A"):
            pool = match.get("pool", "")
            dev["model"] = f"DHCP Reservation ({pool})" if pool else "DHCP Reservation"

    return raw_devices


def parse_target_vendor_spec(raw_spec: str) -> dict[str, str]:
    """
    Parse `--target-vendor` into a persona->vendor map.
    Supports:
      - '' / 'none' / 'discovery' -> {} (pure discovery, no target configs)
      - 'juniper' -> {'default': 'juniper'}
      - 'switch=juniper,ap=aruba,firewall=fortinet' -> {'switch': 'juniper', 'ap': 'aruba', 'firewall': 'fortinet'}
    """
    spec = (raw_spec or "").strip().lower()
    if not spec or spec in ("none", "discovery", "unknown", "tbd"):
        return {}
    aliases = {
        "junos": "juniper",
        "juniper": "juniper",
        "cisco": "cisco",
        "ios": "cisco",
        "ios-xe": "cisco",
        "meraki": "meraki",
        "arista": "arista",
        "eos": "arista",
        "aruba": "aruba",
        "hp": "hpprocurve",
        "procurve": "hpprocurve",
        "hpprocurve": "hpprocurve",
        "fortinet": "fortinet",
        "fortigate": "fortinet",
    }
    if "=" not in spec:
        mapped = aliases.get(spec)
        if not mapped:
            print(f"[!] Warning: Unrecognized --target-vendor '{raw_spec}'. Skipping target config generation.")
            return {}
        return {"default": mapped}

    out: dict[str, str] = {}
    for part in spec.split(","):
        if "=" not in part:
            continue
        persona, vend = [x.strip().lower() for x in part.split("=", 1)]
        mapped = aliases.get(vend)
        if mapped and persona:
            out[persona] = mapped
        elif vend:
            print(f"[!] Warning: Unrecognized vendor '{vend}' for persona '{persona}' in --target-vendor.")
    return out


def _stitch_dataset_topology(raw_devices: list[dict], registry: DeviceRegistry) -> None:
    """Cross-resolve neighbor IPs/personas from crawled devices and Global ARP, then stitch topology edges."""
    try:
        from net_docu_crawler.topology_renderer import classify_neighbor_node
    except ImportError:
        classify_neighbor_node = None

    crawled_devs = [d for d in raw_devices if isinstance(d, dict) and d.get("status", "success") == "success"]
    crawled_by_ip = {d["ip"]: d for d in crawled_devs if d.get("ip")}
    crawled_by_host: dict[str, dict] = {}
    crawled_hosts_lc: set[str] = set()
    crawled_ips: set[str] = set()
    crawled_macs: set[str] = set()
    for d in crawled_devs:
        if d.get("ip"):
            crawled_ips.add(str(d["ip"]).strip())
        for l3 in d.get("l3_interfaces") or []:
            ip_tok = str((l3 or {}).get("ip_address") or "").split("/")[0].split()[0].strip()
            if ip_tok and ip_tok not in ("N/A", "unassigned", "0.0.0.0") and not ip_tok.startswith(("127.", "128.0.")):
                crawled_ips.add(ip_tok)
        b_mac = oui_lookup.normalize_mac(str(d.get("mac_address") or "")).lower().strip()
        if b_mac and b_mac != "00:00:00:00:00:00":
            crawled_macs.add(b_mac)
        for pinfo in (d.get("interfaces_detail") or {}).values():
            pmac = oui_lookup.normalize_mac(str((pinfo or {}).get("mac_address") or "")).lower().strip()
            if pmac and pmac != "00:00:00:00:00:00":
                crawled_macs.add(pmac)
        for h_key in (d.get("hostname", ""), d.get("canonical_hostname", "")):
            if h_key:
                hl = h_key.lower()
                hs = h_key.split(".")[0].lower()
                crawled_by_host[hl] = d
                crawled_by_host[hs] = d
                crawled_hosts_lc.add(hl)
                crawled_hosts_lc.add(hs)

    def _populate_links() -> None:
        registry.links.clear()
        for device_data in raw_devices:
            if not isinstance(device_data, dict):
                continue
            local_host = device_data.get("hostname") or device_data.get("ip", "")
            for nbr in device_data.get("neighbors", []):
                if not nbr.get("remote_ip"):
                    resolved_ip = registry.resolve_neighbor_ip(
                        neighbor_mac=nbr.get("remote_mac", ""),
                        neighbor_name=nbr.get("remote_device", ""),
                    )
                    if resolved_ip:
                        nbr["remote_ip"] = resolved_ip

                if nbr.get("l2_accuracy") != "l3_next_hop_egress":
                    canon_r = registry.resolve_canonical_hostname(
                        nbr.get("remote_device", ""),
                        remote_mac=nbr.get("remote_mac", ""),
                        remote_ip=nbr.get("remote_ip", ""),
                    )
                    if canon_r:
                        nbr["remote_device"] = canon_r

                matched_dev = crawled_by_ip.get(nbr.get("remote_ip", ""))
                if not matched_dev and nbr.get("remote_device"):
                    r_key = nbr["remote_device"].split(".")[0].lower()
                    matched_dev = crawled_by_host.get(r_key)

                if matched_dev:
                    if matched_dev.get("device_type"):
                        nbr["device_type"] = matched_dev["device_type"]
                    if not nbr.get("platform"):
                        plat_label = f"{matched_dev.get('vendor', '')} {matched_dev.get('model', '')}".strip()
                        nbr["platform"] = plat_label
                        nbr["remote_platform"] = plat_label

                n_type = (nbr.get("device_type") or "").lower()
                if classify_neighbor_node is not None:
                    cls_role = classify_neighbor_node(
                        nbr.get("remote_device", ""),
                        nbr,
                        crawled_hosts_lc=crawled_hosts_lc,
                        crawled_ips=crawled_ips,
                        crawled_macs=crawled_macs,
                    )
                elif matched_dev or nbr.get("l2_accuracy") in ("wan_carrier_arp_route", "l3_next_hop_egress"):
                    cls_role = n_type if n_type in ("firewall", "router", "isp", "ap") else "crawled_infra"
                elif n_type == "ap":
                    cls_role = "ap"
                elif n_type in ("switch", "router", "firewall", "wlc", "bridge", "isp"):
                    cls_role = n_type if n_type in ("firewall", "router", "isp") else "uncrawled_switch"
                else:
                    cls_role = "endpoint"

                local_is_ap = (
                    device_data.get("device_type") or device_data.get("device_persona") or ""
                ).lower() == "ap"
                remote_is_ap = cls_role == "ap" or (
                    matched_dev is not None
                    and (matched_dev.get("device_type") or matched_dev.get("device_persona") or "").lower() == "ap"
                )
                if local_is_ap or remote_is_ap:
                    l_class = "wireless_ap"
                elif cls_role in ("crawled_infra", "uncrawled_switch", "firewall", "router", "isp"):
                    l_class = "infra_uplink"
                else:
                    l_class = "edge_endpoint"

                l2_acc = str(nbr.get("l2_accuracy") or "").strip().lower()
                conf = str(nbr.get("link_confidence") or "").strip()
                if l2_acc == "wan_carrier_arp_route":
                    link_type = "wan_carrier"
                    transport_type = str(nbr.get("transport_type") or "metro_ethernet")
                    evidence = "wan_carrier_arp_route"
                elif l2_acc == "l3_next_hop_egress":
                    link_type = "l3_egress"
                    transport_type = str(nbr.get("transport_type") or "l3_egress")
                    evidence = "l3_next_hop_egress"
                elif l2_acc == "mac_inferred":
                    link_type = "mac_inferred"
                    transport_type = str(nbr.get("transport_type") or "mac_inferred")
                    evidence = "mac_inferred"
                elif l2_acc in ("virtual_passthrough", "multi_neighbor_port"):
                    link_type = "virtual_passthrough"
                    transport_type = str(nbr.get("transport_type") or "virtual_passthrough")
                    evidence = "passthrough"
                else:
                    link_type = "physical"
                    transport_type = str(nbr.get("transport_type") or "direct_l2_uplink")
                    evidence = "confirmed_lldp" if conf == "two-way" else "unidirectional_lldp"

                registry.add_bidirectional_link(
                    local_node=local_host,
                    local_port=nbr.get("local_port", ""),
                    remote_node=nbr.get("remote_device", ""),
                    remote_port=nbr.get("remote_port", ""),
                    link_type=link_type,
                    link_class=l_class,
                    transport_type=transport_type,
                    evidence=evidence,
                )

    _populate_links()
    registry.reconcile_reciprocal_neighbors(raw_devices)
    registry.infer_mac_table_links(raw_devices)
    registry.infer_wan_and_gateway_links(raw_devices)
    registry.detect_l2_anomalies(raw_devices)
    _populate_links()


def _update_latest_run_pointer(run_output_dir: str) -> None:
    """Update the `deliverables/latest` symlink (or Windows junction / `latest.txt` fallback)."""
    latest_link = os.path.join(os.path.dirname(run_output_dir), "latest")
    try:
        if os.path.islink(latest_link):
            os.unlink(latest_link)
        elif os.path.exists(latest_link):
            if os.path.isdir(latest_link):
                try:
                    os.rmdir(latest_link)
                except OSError:
                    shutil.rmtree(latest_link)
            else:
                os.remove(latest_link)
        os.symlink(os.path.basename(run_output_dir), latest_link, target_is_directory=True)
        print(f"[+] Updated symlink: {latest_link} -> {os.path.basename(run_output_dir)}")
    except OSError as exc:
        logger.debug("Symlink update failed for %s (%s); trying platform fallback.", latest_link, exc)
        junction_created = False
        if os.name == "nt":
            try:
                subprocess.run(
                    ["cmd", "/c", "mklink", "/J", os.path.abspath(latest_link), os.path.abspath(run_output_dir)],
                    check=True,
                    capture_output=True,
                )
                print(f"[+] Updated junction: {latest_link} -> {os.path.basename(run_output_dir)}")
                junction_created = True
            except (OSError, subprocess.SubprocessError) as j_exc:
                logger.debug("Failed to create Windows junction %s: %s", latest_link, j_exc)
                junction_created = False
        if not junction_created:
            try:
                latest_txt = os.path.join(os.path.dirname(run_output_dir), "latest.txt")
                with open(latest_txt, "w", encoding="utf-8") as f:
                    f.write(os.path.basename(run_output_dir) + "\n")
                print(f"[+] Recorded latest run pointer: {latest_txt} -> {os.path.basename(run_output_dir)}")
            except OSError as txt_exc:
                logger.debug("Failed to write latest.txt pointer in %s: %s", run_output_dir, txt_exc)


def _write_standard_deliverables(
    devices_dict: dict[str, dict],
    raw_devices: list[dict],
    trunk_audit: dict | None,
    run_output_dir: str,
    scope_label: str,
    primary_domain: str,
    target_vendor: str,
    json_path: str,
    norm_dir: str,
    mig_dir: str,
    rep_dir: str,
) -> None:
    """Render core Markdown/CSV/script deliverables and mirror them into layered folders."""
    blueprint_path = os.path.join(run_output_dir, "Network_Analysis.md")
    report_generator.generate_master_network_analysis_migration_blueprint(
        devices_dict, output_path=blueprint_path, scope=scope_label, dns_domain=primary_domain
    )
    print(f"[+] Generated master migration blueprint: {blueprint_path}")

    runbook_path = os.path.join(run_output_dir, "cutover_runbook.md")
    report_generator.generate_cutover_runbook(devices_dict, output_path=runbook_path, scope=scope_label)
    print(f"[+] Generated cutover runbook: {runbook_path}")

    smoke_path = os.path.join(run_output_dir, "validate_cutover.sh")
    report_generator.generate_cutover_validation_script(devices_dict, output_path=smoke_path)
    print(f"[+] Generated cutover validation smoke script: {smoke_path}")

    rep_path = os.path.join(run_output_dir, "net_docu_crawler_live_report.md")
    report_generator.generate_network_analysis_report(devices_dict, output_path=rep_path, dns_domain=primary_domain)
    print(f"[+] Generated network analysis report: {rep_path}")

    inv_path = os.path.join(run_output_dir, "asset_inventory.csv")
    report_generator.generate_asset_inventory(devices_dict, output_path=inv_path, infra_only=True)
    print(f"[+] Generated asset inventory CSV: {inv_path}")

    cable_path = os.path.join(run_output_dir, "migration_cabling_matrix.csv")
    report_generator.generate_cabling_matrix(devices_dict, output_path=cable_path)
    print(f"[+] Generated cabling matrix CSV: {cable_path}")

    endpoint_path = os.path.join(run_output_dir, "port_mac_endpoint_mapping.csv")
    report_generator.generate_port_endpoint_mapping(devices_dict, output_path=endpoint_path)
    print(f"[+] Generated port-to-endpoint mapping CSV: {endpoint_path}")

    l2_path = os.path.join(run_output_dir, "L2_network_diagrams.md")
    report_generator.generate_l2_diagram(devices_dict, output_path=l2_path)
    print(f"[+] Generated Layer 2 diagram: {l2_path}")

    l3_path = os.path.join(run_output_dir, "L3_network_diagrams.md")
    report_generator.generate_l3_diagram(devices_dict, output_path=l3_path)
    print(f"[+] Generated Layer 3 diagram: {l3_path}")

    trans_path = os.path.join(run_output_dir, "cisco_to_target_translation.md")
    report_generator.generate_protocol_translation(devices_dict, output_path=trans_path)
    print(f"[+] Generated configuration translation guide: {trans_path}")

    trunk_rep_path = os.path.join(run_output_dir, "trunk_vlan_audit.md")
    report_generator.generate_trunk_audit_report(
        trunk_audit if trunk_audit is not None else raw_devices, output_path=trunk_rep_path, devices=devices_dict
    )
    print(f"[+] Generated trunk VLAN audit report: {trunk_rep_path}")

    followup_path = os.path.join(run_output_dir, "manual_followup_report.md")
    report_generator.generate_manual_followup_report(
        devices_dict,
        output_path=followup_path,
        trunk_audit=trunk_audit,
    )
    print(f"[+] Generated manual follow-up report: {followup_path}")

    topo_html_path = os.path.join(run_output_dir, "topology_interactive.html")
    report_generator.generate_interactive_topology_html(
        devices_dict,
        output_path=topo_html_path,
        trunk_audit=trunk_audit,
    )
    print(f"[+] Generated interactive topology viewer: {topo_html_path}")

    bom_path = os.path.join(run_output_dir, "bom_hardware_sizing.csv")
    report_generator.generate_bom_hardware_sizing(
        devices_dict, output_path=bom_path, target_vendor=target_vendor or "juniper"
    )
    print(f"[+] Generated BOM & hardware sizing CSV: {bom_path}")

    _layer_copies = [
        (json_path, os.path.join(norm_dir, "devices.json")),
        (inv_path, os.path.join(mig_dir, "asset_inventory.csv")),
        (cable_path, os.path.join(mig_dir, "cabling_matrix.csv")),
        (bom_path, os.path.join(mig_dir, "bom_hardware_sizing.csv")),
        (smoke_path, os.path.join(mig_dir, "validate_cutover.sh")),
        (blueprint_path, os.path.join(rep_dir, "Network_Analysis.md")),
        (runbook_path, os.path.join(rep_dir, "cutover_runbook.md")),
        (l2_path, os.path.join(rep_dir, "L2_network_diagrams.md")),
        (l3_path, os.path.join(rep_dir, "L3_network_diagrams.md")),
        (trans_path, os.path.join(rep_dir, "protocol_translation_matrix.md")),
        (trunk_rep_path, os.path.join(rep_dir, "trunk_vlan_audit.md")),
        (followup_path, os.path.join(rep_dir, "manual_followup_report.md")),
        (topo_html_path, os.path.join(rep_dir, "topology_interactive.html")),
    ]
    for src_p, dst_p in _layer_copies:
        if os.path.isfile(src_p):
            shutil.copy2(src_p, dst_p)


def _write_optional_migration_deliverables(
    devices_dict: dict[str, dict],
    run_output_dir: str,
    target_vendor: str,
    save_baseline: str,
    compare_baseline: str,
) -> None:
    """Generate optional target-vendor CLI migration configs and pre/post-cutover baseline diffs."""
    target_map = parse_target_vendor_spec(target_vendor)
    if target_map:
        for persona_key, tv in target_map.items():
            suffix = tv if persona_key == "default" else f"{persona_key}_{tv}"
            target_cfg_path = os.path.join(run_output_dir, f"target_migration_{suffix}.md")
            scoped_devs = (
                devices_dict
                if persona_key == "default"
                else {
                    ip: d
                    for ip, d in devices_dict.items()
                    if (d.get("device_persona") or d.get("device_type", "")).lower() == persona_key
                }
            )
            if scoped_devs:
                report_generator.generate_target_migration_configs(
                    scoped_devs, target_vendor=tv, output_path=target_cfg_path
                )
                print(f"[+] Generated target vendor migration configs ({suffix}): {target_cfg_path}")

    if save_baseline:
        report_generator.save_baseline_state(devices_dict, output_path=save_baseline)
        print(f"[+] Saved pre-cutover baseline state to: {save_baseline}")

    if compare_baseline:
        ver_path = os.path.join(run_output_dir, "migration_verification_report.md")
        report_generator.compare_baseline_state(devices_dict, baseline_path=compare_baseline, output_path=ver_path)
        print(f"[+] Generated post-cutover verification diff report: {ver_path}")


def _export_dataset_and_failed_hosts(
    raw_devices: list[dict],
    run_output_dir: str,
    sanitize_passwords: bool,
    logs_dir: str,
) -> str:
    """Optionally sanitize secrets, then write `net_docu_crawler_dataset.json` and `failed_hosts.json`."""
    _prune_empty_session_logs(logs_dir or os.path.join(run_output_dir, "logs"))
    if sanitize_passwords:
        print("[+] Sanitizing passwords and pre-shared keys in configuration backups and session logs...")
        for dev in raw_devices:
            if dev.get("raw_config"):
                dev["raw_config"] = sanitize_raw_config(dev["raw_config"])
        _sanitize_session_logs(logs_dir or os.path.join(run_output_dir, "logs"))

    json_path = os.path.join(run_output_dir, "net_docu_crawler_dataset.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(raw_devices, f, indent=2)
    print(f"[+] Saved crawl dataset to: {json_path}")

    failed_hosts = [
        {
            "ip": dev.get("ip", ""),
            "status": dev.get("status", "unknown"),
            "vendor": dev.get("vendor", "Unknown"),
            "device_type": dev.get("device_type", "unknown"),
            "mgmt_method": dev.get("mgmt_method", ""),
            "model": dev.get("model", ""),
            "mac_address": dev.get("mac_address", ""),
        }
        for dev in raw_devices
        if dev.get("status") in ("unauthenticated", "unsupported")
    ]
    failed_path = os.path.join(run_output_dir, "failed_hosts.json")
    with open(failed_path, "w", encoding="utf-8") as f:
        json.dump(failed_hosts, f, indent=2)
    if failed_hosts:
        print(f"[+] Saved {len(failed_hosts)} failed/partial host(s) to: {failed_path}")
    return json_path


def _prepare_layered_dirs_and_quality_report(
    raw_devices: list[dict],
    run_output_dir: str,
) -> tuple[dict | None, dict, str, str, str]:
    """Run dataset correlation, DNS detection, and quality gate report generation."""
    from net_docu_crawler.correlator import correlate_dataset
    from net_docu_crawler.domain_detector import detect_environment_dns_domain
    from net_docu_crawler.quality_gates import evaluate_quality_gates, write_quality_report

    corr_result = correlate_dataset(raw_devices)
    trunk_audit = corr_result.get("trunk_audit") if isinstance(corr_result, dict) else None
    dns_info = detect_environment_dns_domain(raw_devices)
    quality_report = evaluate_quality_gates(raw_devices, trunk_audit=trunk_audit)
    for k_src, k_dst in (
        ("primary_domain", "dns_domain"),
        ("local_dns_suffix", "local_dns_suffix"),
        ("device_domains", "device_domains"),
    ):
        if dns_info[k_src]:
            quality_report[k_dst] = dns_info[k_src]

    manifest_dir = os.path.join(run_output_dir, "00_manifest")
    norm_dir = os.path.join(run_output_dir, "02_normalized")
    corr_dir = os.path.join(run_output_dir, "03_correlated")
    mig_dir = os.path.join(run_output_dir, "04_migration")
    rep_dir = os.path.join(run_output_dir, "05_reports")
    for d in (manifest_dir, norm_dir, corr_dir, mig_dir, rep_dir):
        os.makedirs(d, exist_ok=True)
    write_quality_report(quality_report, manifest_dir)
    print(
        f"[+] Quality Gates: {'PASS' if quality_report['passed'] else 'FAIL'} (see {os.path.join(manifest_dir, 'data_quality_report.md')})"
    )
    return trunk_audit, dns_info, norm_dir, mig_dir, rep_dir


def _extract_device_owned_ips(dev: dict) -> set[str]:
    """Return all non-loopback IPv4 addresses owned by a crawled device (`ip` + `l3_interfaces`)."""
    owned: set[str] = set()
    primary = str(dev.get("ip") or "").strip()
    if primary:
        owned.add(primary)
    for l3 in dev.get("l3_interfaces", []) or []:
        if not isinstance(l3, dict):
            continue
        raw_ip = str(l3.get("ip_address") or "").strip()
        ip_tok = raw_ip.split("/")[0].split()[0].strip()
        if ip_tok and ip_tok not in ("N/A", "unassigned", "0.0.0.0") and not ip_tok.startswith(("127.", "128.0.")):
            owned.add(ip_tok)
    return owned


def _is_statically_configured_ip(dev: dict) -> bool:
    """Return True if `dev['ip']` appears as an explicit static address in `raw_config`."""
    ip = str(dev.get("ip") or "").strip()
    cfg = str(dev.get("raw_config") or "")
    if not ip or not cfg:
        return False
    return bool(
        f"address={ip}/" in cfg
        or re.search(rf"\bip\s+address\s+{re.escape(ip)}\b", cfg)
        or f"<ipaddr>{ip}</ipaddr>" in cfg
    )


def reconcile_and_deduplicate_dataset(raw_devices: list[dict]) -> list[dict]:
    """
    Reconcile swarm member metadata (e.g., Aruba Instant AP serials/LLDP from Virtual Controller)
    and deduplicate redundant records when a multi-IP device (secondary/DHCP + static IP, or
    Aruba VC IP + Master AP IP) was crawled across multiple addresses in the same batch.
    Mutates `raw_devices` in place and returns it.
    """
    swarm_aps_by_ip: dict[str, dict] = {}
    swarm_aps_by_name: dict[str, dict] = {}
    swarm_lldp_by_name: dict[str, list[dict]] = {}

    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        for ap in dev.get("swarm_aps", []) or []:
            if not isinstance(ap, dict):
                continue
            if ap.get("ip"):
                swarm_aps_by_ip[str(ap["ip"])] = ap
            if ap.get("name"):
                swarm_aps_by_name[str(ap["name"]).lower()] = ap
        for ap_name, nbrs in (dev.get("swarm_lldp") or {}).items():
            if ap_name and isinstance(nbrs, list) and nbrs:
                swarm_lldp_by_name.setdefault(str(ap_name).lower(), nbrs)

    for dev in raw_devices:
        if not isinstance(dev, dict) or dev.get("status") != "success":
            continue
        ip_val = str(dev.get("ip") or "").strip()
        host_low = str(dev.get("hostname") or "").strip().lower()
        ap_meta = swarm_aps_by_ip.get(ip_val) or swarm_aps_by_name.get(host_low)
        if ap_meta:
            ap_ser = str(ap_meta.get("serial") or "").strip()
            if ap_ser and ap_ser != "Unknown" and str(dev.get("serial") or "Unknown") in ("", "Unknown"):
                dev["serial"] = ap_ser
        if not dev.get("neighbors") and host_low in swarm_lldp_by_name:
            dev["neighbors"] = [dict(n) for n in swarm_lldp_by_name[host_low]]

    # Deduplicate concurrent `success` crawls of two IPs on the exact same router/appliance
    kept_success: list[dict] = []
    non_success: list[dict] = []
    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        if dev.get("status") != "success":
            non_success.append(dev)
            continue
        dev_mac = oui_lookup.normalize_mac(str(dev.get("mac_address") or "")).lower().strip()
        dev_ips = _extract_device_owned_ips(dev)
        dup_idx: int | None = None
        for idx, prev in enumerate(kept_success):
            prev_mac = oui_lookup.normalize_mac(str(prev.get("mac_address") or "")).lower().strip()
            if not dev_mac or dev_mac != prev_mac or dev.get("vendor") != prev.get("vendor"):
                continue
            prev_ips = _extract_device_owned_ips(prev)
            if dev.get("ip") in prev_ips and prev.get("ip") in dev_ips:
                dup_idx = idx
                break
        if dup_idx is None:
            kept_success.append(dev)
        elif _is_statically_configured_ip(dev) and not _is_statically_configured_ip(kept_success[dup_idx]):
            kept_success[dup_idx] = dev

    # Drop partial (`unauthenticated`/`unsupported`/`discovered`) shadows of already-authenticated devices
    success_owned_ips: set[str] = set()
    success_hw_macs: set[str] = set()
    for dev in kept_success:
        success_owned_ips.update(_extract_device_owned_ips(dev))
        mac = oui_lookup.normalize_mac(str(dev.get("mac_address") or "")).lower().strip()
        if mac and mac != "00:00:00:00:00:00" and not is_hypervisor_mac(mac):
            success_hw_macs.add(mac)

    kept_partials: list[dict] = []
    for dev in non_success:
        ip_val = str(dev.get("ip") or "").strip()
        mac = oui_lookup.normalize_mac(str(dev.get("mac_address") or "")).lower().strip()
        if ip_val in success_owned_ips:
            continue
        if mac and not is_hypervisor_mac(mac) and mac in success_hw_macs:
            continue
        kept_partials.append(dev)

    raw_devices[:] = kept_success + kept_partials
    return raw_devices


def render_deliverables_from_dataset(
    raw_devices: list[dict],
    registry: DeviceRegistry | None = None,
    run_output_dir: str = "docs/net_docu_crawler",
    targets: list[str] | None = None,
    is_organized: bool = False,
    sanitize_passwords: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
    logs_dir: str = "",
) -> list[dict]:
    """
    Resolve topology links, optionally sanitize secrets (including raw session logs),
    export JSON/failed_hosts.json, and generate all Markdown/CSV/script deliverables.
    Can be called live after `crawl_network()` or offline via `--from-dataset`.
    """
    os.makedirs(run_output_dir, exist_ok=True)
    enrich_devices_from_dhcp_reservations(raw_devices)
    reconcile_and_deduplicate_dataset(raw_devices)
    prior_arp = dict(registry.global_arp) if registry is not None else {}
    registry = DeviceRegistry()
    registry.global_arp.update(prior_arp)
    for dev in raw_devices:
        if isinstance(dev, dict):
            registry.register_device(dev)

    _stitch_dataset_topology(raw_devices, registry)
    trunk_audit, dns_info, norm_dir, mig_dir, rep_dir = _prepare_layered_dirs_and_quality_report(
        raw_devices, run_output_dir
    )

    confirmed_count = sum(1 for lk in registry.links if lk["status"] == "confirmed")
    print(f"\n[+] Processed {len(raw_devices)} network devices!")
    print(f"[+] Unique devices in registry: {len(registry.devices)}")
    print(f"[+] Discovered topology links: {len(registry.links)} ({confirmed_count} bidirectional confirmed)")

    json_path = _export_dataset_and_failed_hosts(raw_devices, run_output_dir, sanitize_passwords, logs_dir)
    devices_dict = {dev["ip"]: dev for dev in registry.devices.values()}
    t_list = targets or []
    scope_label = (
        t_list[0]
        if len(t_list) == 1
        else ("192.168.1.0/24" if any("192.168.1." in t for t in t_list) else "Multi-Target Campus")
    )

    _write_standard_deliverables(
        devices_dict,
        raw_devices,
        trunk_audit,
        run_output_dir,
        scope_label,
        dns_info["primary_domain"],
        target_vendor,
        json_path,
        norm_dir,
        mig_dir,
        rep_dir,
    )
    _write_optional_migration_deliverables(devices_dict, run_output_dir, target_vendor, save_baseline, compare_baseline)
    if is_organized:
        _update_latest_run_pointer(run_output_dir)

    report_generator.export_layered_csvs(
        raw_devices, registry, run_output_dir, source_logs_dir=logs_dir, trunk_audit=trunk_audit
    )
    return raw_devices


def render_from_dataset_file(
    dataset_path: str,
    output_dir: str = "",
    sanitize_passwords: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
) -> list[dict]:
    """
    Offline mode (`--from-dataset`): load an existing `net_docu_crawler_dataset.json`
    and re-run topology resolution + all deliverable generators with zero network traffic.
    """
    with open(dataset_path, encoding="utf-8") as f:
        raw_devices = json.load(f)
    if not isinstance(raw_devices, list):
        raise ValueError(f"Expected JSON list in dataset {dataset_path}, got {type(raw_devices).__name__}")
    target_dir = (
        output_dir
        if (output_dir and output_dir not in ("auto", "docs/net_docu_crawler"))
        else os.path.dirname(os.path.abspath(dataset_path))
    )
    print(f"[+] Loaded {len(raw_devices)} device record(s) from {dataset_path} (offline render -> {target_dir})")
    return render_deliverables_from_dataset(
        raw_devices=raw_devices,
        run_output_dir=target_dir,
        sanitize_passwords=sanitize_passwords,
        target_vendor=target_vendor,
        save_baseline=save_baseline,
        compare_baseline=compare_baseline,
    )


class LogReplayConnection:
    """
    Offline Netmiko-compatible connection adapter that replays recorded CLI
    command outputs from `<ip>_raw_session.log` files without touching the network.
    """

    def __init__(self, log_text: str):
        self.commands: dict[str, str] = {}
        self.prompt: str = ""
        self._parse_log(log_text)

    def _parse_log(self, log_text: str) -> None:
        cleaned = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", log_text)
        cleaned = re.sub(r"\[(?:\?[0-9;]*[hl]|[0-9;]*[HJKr])", "", cleaned).replace("\r", "")
        lines = cleaned.splitlines()
        if "--- COMMAND: " in cleaned:
            cur_cmd: str | None = None
            cur_buf: list[str] = []
            for ln in lines:
                m_opn = re.match(r"^---\s*COMMAND:\s*(.+?)\s*---\s*$", ln)
                if m_opn:
                    if cur_cmd is not None:
                        self.commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
                    cur_cmd = m_opn.group(1).strip()
                    cur_buf = []
                elif cur_cmd is not None:
                    cur_buf.append(ln)
            if cur_cmd is not None:
                self.commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
            return

        base_prompt = ""
        prompt_re = None
        for ln in lines:
            m = re.match(r"^(\[?[A-Za-z0-9._@:~/-]+\]?)(?:\s*\([^)]+\))?\s*[#>$]\s*([a-zA-Z/].*)$", ln)
            if m:
                base_prompt = m.group(1)
                prompt_re = re.compile(rf"^{re.escape(base_prompt)}(?:\s*\([^)]+\))?\s*[#>$]\s*(.*)$")
                break
        if not prompt_re:
            return

        cur_cmd: str | None = None
        cur_buf: list[str] = []
        for ln in lines:
            m = prompt_re.match(ln)
            if m:
                if cur_cmd is not None:
                    while cur_buf and (
                        not cur_buf[-1].strip()
                        or re.match(r"^\{(?:master|backup|linecard):\d+\}$", cur_buf[-1].strip())
                    ):
                        cur_buf.pop()
                    self.commands[cur_cmd] = "\n".join(cur_buf).strip("\n")
                cmd_part = m.group(1).strip()
                if not self.prompt and "(" not in ln.split("#", 1)[0].split(">", 1)[0]:
                    sep = "#" if "#" in ln else (">" if ">" in ln else "$")
                    self.prompt = ln.split(sep, 1)[0] + sep
                cur_cmd = cmd_part if cmd_part else None
                cur_buf = []
            elif cur_cmd is not None:
                cur_buf.append(ln)
        if cur_cmd is not None:
            while cur_buf and (
                not cur_buf[-1].strip() or re.match(r"^\{(?:master|backup|linecard):\d+\}$", cur_buf[-1].strip())
            ):
                cur_buf.pop()
            self.commands[cur_cmd] = "\n".join(cur_buf).strip("\n")

    def send_command(self, command_string: str, **kwargs) -> str:
        cmd = command_string.strip()
        if cmd in self.commands:
            return self.commands[cmd]
        cmd_l = cmd.lower()
        for k, v in self.commands.items():
            if k.lower() == cmd_l:
                return v
        return ""

    def find_prompt(self) -> str:
        return self.prompt or "device#"

    def enable(self) -> None:
        return None

    def disconnect(self) -> None:
        return None


def _infer_vendor_from_log(log_text: str, existing_vendor: str = "") -> str:
    ev = (existing_vendor or "").lower()
    _alias = {
        "juniper_junos": "juniper",
        "juniper": "juniper",
        "cisco_ios": "cisco",
        "cisco_xe": "cisco",
        "cisco_nxos": "cisco",
        "cisco_xr": "cisco_xr",
        "cisco": "cisco",
        "arista_eos": "arista",
        "arista": "arista",
        "mikrotik_routeros": "mikrotik",
        "mikrotik": "mikrotik",
        "fortinet": "fortinet",
        "opnsense": "opnsense",
        "openwrt": "openwrt",
        "hpprocurve": "hpprocurve",
        "aruba": "aruba",
        "paloalto": "paloalto",
        "frrouting": "frrouting",
    }
    low = log_text.lower()
    if "/conf/config.xml" in low or "opnsense-version" in low or "<opnsense>" in low:
        return "opnsense"
    if "get system status" in low or "config system global" in low or "config-version=fgt" in low or "fortios" in low:
        return "fortinet"
    if "junos" in low or "show chassis hardware" in low:
        return "juniper"
    if (
        "arubaos" in low
        or "aruba operating system" in low
        or "virtual-controller-ip" in low
        or "show ap debug lldp" in low
    ):
        return "aruba"
    if "procurve" in low or "arubaos-s" in low or "show power-over-ethernet brief" in low or "hp j" in low:
        return "hpprocurve"
    if re.search(r"\b(?:arista|veos|ceos)\b", low) or "eos-" in low:
        return "arista"
    if "/system identity" in low or "/ip route print" in low or "mikrotik routeros" in low:
        return "mikrotik"
    if "ubus call" in low or "uci export" in low or "openwrt" in low:
        return "openwrt"
    if "frrouting" in low or "vtysh" in low or "ip -j addr" in low:
        return "frrouting"
    if "fortigate" in low or "config system interface" in low:
        return "fortinet"
    if "opnsense" in low:
        return "opnsense"
    if "mikrotik" in low:
        return "mikrotik"
    if "cisco ios" in low or "show ip interface brief" in low or "show cdp neighbors detail" in low:
        return "cisco"
    if ev in _alias:
        return _alias[ev]
    if "juniper" in ev or "junos" in ev:
        return "juniper"
    if "procurve" in ev or "arubaos-s" in ev or "hp " in ev:
        return "hpprocurve"
    return "cisco"


def _reparse_single_session_log(lf: str, existing_by_ip: dict[str, dict]) -> tuple[str, dict | None]:
    """Replay a single `<ip>_raw_session.log` file through its detected vendor driver."""
    ip = os.path.basename(lf).replace("_raw_session.log", "")
    with open(lf, encoding="utf-8", errors="ignore") as f:
        log_text = f.read()

    conn = LogReplayConnection(log_text)
    if len(conn.commands) < 2:
        prev = existing_by_ip.get(ip)
        if prev:
            if prev.get("hostname") in ("authentication", "Password", "Login", "Username", ""):
                prev["status"] = "unauthenticated"
                prev["hostname"] = prev.get("ip", ip)
            return ip, prev
        return ip, None

    prev = existing_by_ip.get(ip, {})
    vendor = _infer_vendor_from_log(log_text, prev.get("vendor", ""))
    driver_cls = resolve_driver_for_vendor(vendor, default=CiscoDriver) or CiscoDriver
    driver = driver_cls(ip)
    print(f"[+] Re-parsing {ip} ({vendor}) from {os.path.basename(lf)} ({len(conn.commands)} commands)")
    dev = driver.crawl(conn)
    dev["ip"] = ip
    if not dev.get("mac_address") and prev.get("mac_address"):
        dev["mac_address"] = prev["mac_address"]
    for extra_k in ("http_title", "http_server", "ssh_banner", "open_ports", "discovery_source"):
        if prev.get(extra_k) and not dev.get(extra_k):
            dev[extra_k] = prev[extra_k]
    return ip, dev


def reparse_logs_dir(
    run_dir: str,
    output_dir: str = "",
    sanitize_passwords: bool = False,
    target_vendor: str = "",
    save_baseline: str = "",
    compare_baseline: str = "",
) -> list[dict]:
    """
    Offline mode (`--reparse-logs`): replay `logs/*_raw_session.log` in `run_dir`
    through the latest vendor drivers and regenerate all deliverables with zero
    network traffic, preserving partial/ARP-discovered entries from any existing
    `net_docu_crawler_dataset.json`.
    """
    run_abs = os.path.abspath(run_dir)
    logs_dir = os.path.join(run_abs, "logs") if os.path.isdir(os.path.join(run_abs, "logs")) else run_abs
    dataset_path = os.path.join(run_abs, "net_docu_crawler_dataset.json")
    target_out = output_dir if (output_dir and output_dir not in ("auto", "docs/net_docu_crawler")) else run_abs

    existing_by_ip: dict[str, dict] = {}
    existing_order: list[str] = []
    if os.path.isfile(dataset_path):
        with open(dataset_path, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, list):
            for rec in loaded:
                if isinstance(rec, dict) and rec.get("ip"):
                    ip_k = str(rec["ip"])
                    existing_by_ip[ip_k] = rec
                    existing_order.append(ip_k)

    log_files = sorted(glob.glob(os.path.join(logs_dir, "*_raw_session.log")))
    if not log_files:
        raise FileNotFoundError(f"No *_raw_session.log files found in {logs_dir}")

    reparsed_by_ip: dict[str, dict] = {}
    for lf in log_files:
        ip, dev = _reparse_single_session_log(lf, existing_by_ip)
        if dev is not None:
            reparsed_by_ip[ip] = dev

    merged: list[dict] = []
    seen: set[str] = set()
    for ip in existing_order:
        merged.append(reparsed_by_ip[ip] if ip in reparsed_by_ip else existing_by_ip[ip])
        seen.add(ip)
    for ip, dev in reparsed_by_ip.items():
        if ip not in seen:
            merged.append(dev)

    return render_deliverables_from_dataset(
        raw_devices=merged,
        run_output_dir=target_out,
        sanitize_passwords=sanitize_passwords,
        target_vendor=target_vendor,
        save_baseline=save_baseline,
        compare_baseline=compare_baseline,
        logs_dir=logs_dir,
    )


def format_duration(seconds: float) -> str:
    """Format elapsed seconds with a human-readable days/hours/minutes breakdown when >= 60s."""
    total = max(0.0, float(seconds))
    if total < 60:
        return f"{total:.2f} seconds"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days >= 1:
        parts.append(f"{int(days)}d")
    if hours >= 1 or parts:
        parts.append(f"{int(hours)}h")
    if minutes >= 1 or parts:
        parts.append(f"{int(minutes)}m")
    parts.append(f"{secs:.2f}s")
    return f"{total:.2f} seconds ({' '.join(parts)})"


def _add_core_cli_args(parser: argparse.ArgumentParser) -> None:
    """Register target, credential, transport, and output directory CLI flags."""
    parser.add_argument(
        "--targets",
        nargs="+",
        default=DEFAULT_TARGETS,
        help="List of target IPs or CIDRs to crawl (e.g., 172.16.1.0/24)",
    )
    parser.add_argument(
        "--credentials",
        nargs="+",
        default=["credentials.json"],
        help="Path(s) to credentials JSON file(s) (tried in order)",
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help="Flat output directory when --no-organize is used (default: docs/net_docu_crawler), or custom base directory when organized (default: deliverables/)",
    )
    organize_group = parser.add_mutually_exclusive_group()
    organize_group.add_argument(
        "--organize",
        action="store_true",
        help="(Default) Store deliverables in a structured folder: deliverables/<Subnet>_<TimeStamp>_<site>/",
    )
    organize_group.add_argument(
        "--no-organize",
        action="store_true",
        help="Write flat output directly to --output-dir without creating a <Subnet>_<TimeStamp>_<site> subfolder",
    )
    parser.add_argument(
        "--site",
        "--domain",
        dest="site",
        default="auto",
        help="Site/run folder label for organized deliverables (default: auto-detected from DNS suffix, fallback 'lan')",
    )
    parser.add_argument(
        "--sanitize-passwords",
        action="store_true",
        help="Redact passwords, pre-shared keys, and SNMP communities in configurations and exports",
    )
    parser.add_argument("--timeout", type=int, default=8, help="Connection timeout in seconds")
    parser.add_argument(
        "--ssh-ports",
        nargs="+",
        type=int,
        default=[22],
        help="SSH ports to probe during subnet discovery (default: 22)",
    )
    parser.add_argument(
        "--telnet-ports",
        nargs="+",
        type=int,
        default=[23],
        help="Telnet ports to probe during subnet discovery (default: 23)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=16,
        help="Maximum concurrent device crawl workers (default: 16)",
    )
    parser.add_argument(
        "--no-http-fingerprint",
        action="store_true",
        help="Disable default HTTP/HTTPS banner and TLS certificate fingerprinting for unauthenticated/ARP hosts",
    )
    parser.add_argument(
        "--snmp",
        action="store_true",
        help="Enable opt-in read-only SNMPv2c sysDescr/sysName enrichment for unauthenticated/ARP hosts",
    )
    parser.add_argument(
        "--snmp-community",
        default="public",
        help="SNMPv2c community string when --snmp is enabled (default: public)",
    )


def _add_scope_cli_args(parser: argparse.ArgumentParser) -> None:
    """Register L3 hop discovery and subnet scope filtering CLI flags."""
    parser.add_argument(
        "--follow-subnets",
        action="store_true",
        help="Follow directly connected RFC 1918 subnets discovered from crawled routers/firewalls (prunes empty /24+ subnets when ARP tables exist)",
    )
    parser.add_argument(
        "--follow-arp-only",
        action="store_true",
        help="Only follow live ARP-discovered infrastructure IPs inside connected subnets (never sweeps empty subnets; skips known endpoint OUIs)",
    )
    parser.add_argument(
        "--mgmt-subnets-only",
        action="store_true",
        help="When following subnets, restrict to management/infrastructure/transit SVIs and /30-/31 P2P links",
    )
    parser.add_argument(
        "--subnet-include",
        nargs="+",
        default=None,
        help="Only follow subnets overlapping these CIDRs (e.g. --subnet-include 10.250.0.0/16 172.31.0.0/16)",
    )
    parser.add_argument(
        "--subnet-exclude",
        nargs="+",
        default=None,
        help="Exclude subnets overlapping these CIDRs when following subnets",
    )
    parser.add_argument(
        "--follow-routes",
        action="store_true",
        help="When --follow-subnets is enabled, also follow non-connected routing-table subnets",
    )
    parser.add_argument(
        "--no-follow-neighbors",
        action="store_true",
        help="Disable automatic crawling of CDP/LLDP neighbor management IPs discovered on crawled devices",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=1,
        help="Maximum L3 subnet hops when --follow-subnets is enabled (default: 1)",
    )
    parser.add_argument(
        "--allow-cgnat",
        action="store_true",
        help="Allow --follow-subnets to follow CGNAT (100.64.0.0/10) ranges (ISP/lab override)",
    )
    parser.add_argument(
        "--allow-public-subnets",
        action="store_true",
        help="Allow --follow-subnets to follow non-RFC1918 public subnets (explicit ISP override)",
    )


def _add_mode_cli_args(parser: argparse.ArgumentParser) -> None:
    """Register migration target, vendor hint, baseline, and offline mode CLI flags."""
    parser.add_argument(
        "--target-vendor",
        default="",
        help="Generate staged target-vendor migration CLI configs (cisco, juniper, arista, aruba, hpprocurve, meraki, or persona=vendor pairs such as switch=juniper,ap=aruba)",
    )
    parser.add_argument(
        "--vendor-hint",
        default="",
        help="Fallback vendor driver hint when OUI/SSH banner is unknown (e.g., cisco, cisco_xr, ciscosmb, juniper, arista, hpprocurve, aruba, fortinet, paloalto, mikrotik, opnsense, openwrt, frrouting)",
    )
    parser.add_argument(
        "--try-all-creds",
        action="store_true",
        help="Try all credential profiles even when a specific vendor is detected (not recommended for lockout-protected devices)",
    )
    parser.add_argument(
        "--no-online-oui",
        action="store_true",
        help="Disable online OUI lookup fallback for unseen MAC prefixes (air-gapped mode)",
    )
    parser.add_argument(
        "--save-baseline", default="", help="Save pre-cutover baseline state JSON to the specified path"
    )
    parser.add_argument(
        "--compare-baseline",
        default="",
        help="Compare current crawl against a saved baseline JSON and generate migration_verification_report.md",
    )
    parser.add_argument(
        "--retry-failed",
        default="",
        help="Path to failed_hosts.json from a prior run to retry unauthenticated hosts only",
    )
    parser.add_argument(
        "--from-dataset",
        default="",
        help="Offline mode: regenerate all deliverables from an existing net_docu_crawler_dataset.json",
    )
    parser.add_argument(
        "--reparse-logs",
        default="",
        help="Offline mode: replay logs/*_raw_session.log in a run directory through the latest drivers and regenerate all deliverables",
    )
    parser.add_argument(
        "--validate-credentials",
        action="store_true",
        help="Validate --credentials JSON file(s) and exit without running a crawl",
    )
    parser.add_argument(
        "--netconf",
        action="store_true",
        help="Enable opt-in read-only NETCONF enrichment for supported platforms (requires ncclient)",
    )
    parser.add_argument(
        "--netconf-port",
        type=int,
        default=830,
        help="NETCONF SSH port when --netconf is enabled (default: 830)",
    )
    parser.add_argument(
        "--gnmi",
        action="store_true",
        help="Enable opt-in read-only gNMI Get() enrichment for supported platforms (requires pygnmi)",
    )
    parser.add_argument(
        "--gnmi-port",
        type=int,
        default=57400,
        help="gNMI gRPC port when --gnmi is enabled (default: 57400)",
    )
    parser.add_argument(
        "--gnmi-insecure",
        action="store_true",
        help="Skip TLS verification for gNMI connections (lab/self-signed certs only)",
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Auto-install missing required Python dependencies on pre-flight startup (when invoked via net_crawler.py)",
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Net-Docu-Crawler Multi-Vendor Network Discovery")
    _add_core_cli_args(parser)
    _add_scope_cli_args(parser)
    _add_mode_cli_args(parser)
    return parser


def main():
    args = _build_arg_parser().parse_args()

    if args.install_deps:
        from net_docu_crawler.dependency_checker import ensure_dependencies

        if not ensure_dependencies(auto_install=True, prompt=False):
            sys.exit(1)

    if args.validate_credentials:
        creds, warnings, errors = load_and_validate_credentials(args.credentials)
        for w in warnings:
            print(f"[!] Credential warning: {w}")
        for err in errors:
            print(f"[-] Credential error: {err}")
        if errors:
            sys.exit(1)
        print(f"[+] Validated {len(creds)} credential profile(s) from {args.credentials}")
        return

    if args.no_online_oui:
        os.environ["NET_DOCU_OFFLINE_OUI"] = "1"

    t_start = time.time()
    try:
        if args.reparse_logs:
            reparse_logs_dir(
                run_dir=args.reparse_logs,
                output_dir=args.output_dir,
                sanitize_passwords=args.sanitize_passwords,
                target_vendor=args.target_vendor,
                save_baseline=args.save_baseline,
                compare_baseline=args.compare_baseline,
            )
            print(f"\n[+] Offline log re-parse completed in {format_duration(time.time() - t_start)}")
            return

        if args.from_dataset:
            render_from_dataset_file(
                dataset_path=args.from_dataset,
                output_dir=args.output_dir,
                sanitize_passwords=args.sanitize_passwords,
                target_vendor=args.target_vendor,
                save_baseline=args.save_baseline,
                compare_baseline=args.compare_baseline,
            )
            print(f"\n[+] Offline deliverable regeneration completed in {format_duration(time.time() - t_start)}")
            return

        options = CrawlOptions(
            targets=args.targets,
            credentials_path=args.credentials,
            output_dir=args.output_dir,
            organize=not args.no_organize,
            site=args.site,
            sanitize_passwords=args.sanitize_passwords,
            timeout=args.timeout,
            ssh_ports=args.ssh_ports,
            telnet_ports=args.telnet_ports,
            max_workers=args.workers,
            http_fingerprint=not args.no_http_fingerprint,
            snmp=args.snmp,
            snmp_community=args.snmp_community,
            follow_subnets=args.follow_subnets,
            follow_arp_only=args.follow_arp_only,
            mgmt_subnets_only=args.mgmt_subnets_only,
            subnet_include=args.subnet_include,
            subnet_exclude=args.subnet_exclude,
            follow_routes=args.follow_routes,
            follow_neighbors=not args.no_follow_neighbors,
            max_hops=args.max_hops,
            allow_cgnat=args.allow_cgnat,
            allow_public_subnets=args.allow_public_subnets,
            target_vendor=args.target_vendor,
            vendor_hint=args.vendor_hint,
            try_all_creds=args.try_all_creds,
            save_baseline=args.save_baseline,
            compare_baseline=args.compare_baseline,
            retry_failed=args.retry_failed,
            netconf=args.netconf,
            netconf_port=args.netconf_port,
            gnmi=args.gnmi,
            gnmi_port=args.gnmi_port,
            gnmi_insecure=args.gnmi_insecure,
        )
        crawl_network(config=options)
    except ValueError:
        sys.exit(1)
    print(f"\n[+] Total crawl and documentation runtime: {format_duration(time.time() - t_start)}")


if __name__ == "__main__":
    main()

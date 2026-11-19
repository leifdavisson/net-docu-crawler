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

"""
Zero-blast-radius DNS domain / suffix detection from local OS state and
already-collected device configurations and TLS certificates.
"""

from __future__ import annotations

import collections
import os
import re
import socket
import subprocess

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_VALID_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)+$")
_IGNORED_DOMAINS = {"localdomain", "localhost", "local", "internal", "home.arpa", "invalid"}


def _clean_domain(raw: str) -> str:
    """Normalize and validate a candidate DNS domain string."""
    val = (raw or "").strip().strip(".").lower()
    if val.startswith("*."):
        val = val[2:]
    if not val or val in _IGNORED_DOMAINS or _IPV4_RE.match(val):
        return ""
    if not _VALID_DOMAIN_RE.match(val):
        return ""
    return val


def detect_local_dns_suffix() -> str:
    """
    Detect the local workstation's DNS suffix without sending network packets.
    Checks Windows `ipconfig`, POSIX `/etc/resolv.conf`, and `socket.getfqdn()`.
    """
    if os.name == "nt":
        try:
            res = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                m = re.search(r"Connection-specific DNS Suffix[^:]*:\s*(.+)$", line, re.IGNORECASE)
                if m:
                    dom = _clean_domain(m.group(1))
                    if dom:
                        return dom
        except Exception:
            pass
    else:
        try:
            if os.path.isfile("/etc/resolv.conf"):
                with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        s = line.strip()
                        if s.startswith(("domain ", "search ")):
                            for token in s.split()[1:]:
                                dom = _clean_domain(token)
                                if dom:
                                    return dom
        except Exception:
            pass

    try:
        fqdn = socket.getfqdn()
        if "." in fqdn:
            dom = _clean_domain(fqdn.split(".", 1)[1])
            if dom:
                return dom
    except Exception:
        pass
    return ""


def extract_device_dns_domains(devices: list[dict] | None) -> list[str]:
    """Extract unique DNS domain names observed in crawled configs, hostnames, and TLS banners."""
    counts: collections.Counter[str] = collections.Counter()
    for dev in devices or []:
        if not isinstance(dev, dict):
            continue
        cfg = dev.get("raw_config") or ""
        if cfg:
            for pat in (
                r"(?im)^\s*ip\s+domain[- ]name\s+(\S+)",
                r"(?im)^\s*set\s+system\s+domain-name\s+(\S+)",
                r"(?im)^\s*domain-name\s+([^\s;]+)",
            ):
                for m in re.finditer(pat, cfg):
                    dom = _clean_domain(m.group(1).strip("\"'"))
                    if dom:
                        counts[dom] += 2

        for host_key in ("canonical_hostname", "hostname"):
            h = (dev.get(host_key) or "").strip()
            if "." in h and not _IPV4_RE.match(h):
                dom = _clean_domain(h.split(".", 1)[1])
                if dom:
                    counts[dom] += 1

        model = (dev.get("model") or "").strip()
        if model.startswith("*.") or ("." in model and " " not in model):
            dom = _clean_domain(model)
            if dom:
                counts[dom] += 1

    return [dom for dom, _ in counts.most_common()]


def domain_to_site_slug(domain: str, fallback: str = "lan") -> str:
    """Convert a DNS domain like `norris.k12.ca.us` into a safe short folder slug (`norris`)."""
    cleaned = _clean_domain(domain)
    if not cleaned:
        return fallback
    first = re.sub(r"[^a-z0-9_-]+", "-", cleaned.split(".", 1)[0]).strip("-")
    return first or fallback


def detect_environment_dns_domain(
    devices: list[dict] | None = None,
    local_suffix: str | None = None,
) -> dict:
    """
    Combine local workstation DNS suffix and crawled device domains into a canonical
    environment DNS summary dictionary.
    """
    local = _clean_domain(local_suffix) if local_suffix is not None else detect_local_dns_suffix()
    dev_domains = extract_device_dns_domains(devices)
    primary = dev_domains[0] if dev_domains else local
    return {
        "primary_domain": primary,
        "local_dns_suffix": local,
        "device_domains": dev_domains,
        "site_slug": domain_to_site_slug(primary or local, fallback="lan"),
    }

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
Zero-Blast-Radius Hardware & Operating System Pre-Identification Gate.
Cascades across:
  Tier 1: MAC OUI Vendor Range (0 network packets, instant; skips hypervisor virtual OUIs)
  Tier 2: SSH Transport Banner (TCP 22 pre-auth banner)
  Tier 3: Post-Auth Safe Prompt Inspection
  Tier 4: Safest Single Probe Command (e.g., distinguishing IOS vs NX-OS vs XR)
"""

import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import oui_lookup

logger = logging.getLogger(__name__)

# Virtual NIC OUIs assigned by hypervisors and container runtimes.
# A virtual NIC MAC identifies the hypervisor, NOT the guest network OS, so Tier 1 must cascade to Tier 2.
_DEFAULT_HYPERVISOR_OUI_PREFIXES = {
    "BC:24:11",  # Proxmox Server Solutions GmbH
    "52:54:00",  # QEMU / KVM VirtIO
    "52:54:AB",  # QEMU / KVM variant
    "54:52:00",  # QEMU / KVM / libvirt variant
    "00:50:56",  # VMware ESX / vSphere
    "00:0C:29",  # VMware Workstation / ESXi
    "00:05:69",  # VMware Legacy
    "00:1C:14",  # VMware ESXi / NSX
    "00:1C:42",  # Parallels / Virtuozzo
    "00:1A:4A",  # Qumranet / Red Hat oVirt / KVM
    "00:03:FF",  # Microsoft Virtual PC / Hyper-V legacy
    "00:0F:4B",  # Oracle Virtual Iron / VirtualBox
    "08:00:27",  # Oracle VirtualBox
    "0A:00:27",  # Oracle VirtualBox Host-Only
    "00:15:5D",  # Microsoft Hyper-V
    "00:16:3E",  # Xen / XCP-ng
    "50:6B:8D",  # Nutanix AHV
    "02:42:AC",  # Docker bridge default
}
HYPERVISOR_OUI_PREFIXES = set(getattr(oui_lookup, "HYPERVISOR_OUI_PREFIXES", ())) | _DEFAULT_HYPERVISOR_OUI_PREFIXES


def _normalize_arp_mac(mac: str) -> str:
    """Normalize colon/dash MACs (including BSD/macOS short-octet `0:0:c:12:34:56`) to lowercase `aa:bb:cc:dd:ee:ff`."""
    if not mac:
        return ""
    s = mac.strip()
    m = re.fullmatch(
        r"([0-9a-fA-F]{1,2})([:-])([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})\2"
        r"([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})",
        s,
    )
    if m:
        return ":".join(m.group(i).zfill(2).lower() for i in (1, 3, 4, 5, 6, 7))
    return oui_lookup.normalize_mac(s).lower()


def is_hypervisor_mac(mac: str) -> bool:
    """Returns True if the MAC address belongs to a virtualized hypervisor NIC OUI."""
    if not mac:
        return False
    prefix = oui_lookup.get_oui_prefix(mac)
    return prefix in HYPERVISOR_OUI_PREFIXES


def is_fhrp_mac(mac: str) -> bool:
    """Returns True if `mac` is a recognized FHRP/HA virtual gateway MAC (VRRP, CARP, HSRP, GLBP, FGCP)."""
    if not mac:
        return False
    helper = getattr(oui_lookup, "is_fhrp_mac", None)
    if callable(helper):
        return bool(helper(mac))
    norm = _normalize_arp_mac(mac).upper()
    parts = norm.split(":")
    if len(parts) != 6:
        return False
    o0, o1, o2, o3, o4, _o5 = parts
    if (o0, o1, o2, o3) == ("00", "00", "5E", "00") and o4 in ("01", "02"):
        return True
    if (o0, o1, o2, o3, o4) == ("00", "00", "0C", "07", "AC"):
        return True
    if (o0, o1, o2, o3) == ("00", "00", "0C", "9F") and o4.startswith("F"):
        return True
    if (o0, o1, o2, o3) == ("00", "07", "B4", "00"):
        return True
    if (o0, o1, o2, o3) == ("00", "09", "0F", "09"):
        return True
    return False


def is_locally_administered_mac(mac: str) -> bool:
    """Returns True if the IEEE U/L (locally administered) bit is set on the MAC address."""
    if not mac:
        return False
    helper = getattr(oui_lookup, "is_locally_administered_mac", None)
    if callable(helper):
        return bool(helper(mac))
    prefix = oui_lookup.get_oui_prefix(mac)
    if len(prefix) < 2:
        return False
    try:
        return (int(prefix[:2], 16) & 0x02) != 0
    except ValueError:
        return False


def is_multicast_mac(mac: str) -> bool:
    """Returns True if the IEEE I/G (multicast/broadcast) bit is set on the MAC address."""
    if not mac:
        return False
    helper = getattr(oui_lookup, "is_multicast_mac", None)
    if callable(helper):
        return bool(helper(mac))
    prefix = oui_lookup.get_oui_prefix(mac)
    if len(prefix) < 2:
        return False
    try:
        return (int(prefix[:2], 16) & 0x01) != 0
    except ValueError:
        return False


def _validate_port(port: int) -> int:
    """Validate TCP/UDP port range (1..65535), raising ValueError on invalid or boolean ports."""
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Port must be an integer between 1 and 65535, got {port!r}")
    return port


def _resolve_socket_target(ip: str, port: int, socktype: int) -> tuple[int, tuple]:
    """
    Resolve an IPv4 literal, IPv6 literal (bare or bracketed), or hostname into a
    `(address_family, sockaddr)` pair after validating `port` in 1..65535.
    """
    valid_port = _validate_port(port)
    host = (ip or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1].strip()
    if not host:
        raise ValueError("Target host/IP must not be empty")

    zone_base = host.split("%", 1)[0]
    try:
        addr_obj = ipaddress.ip_address(zone_base)
    except ValueError:
        infos = socket.getaddrinfo(host, valid_port, socket.AF_UNSPEC, socktype)
        if not infos:
            raise OSError(f"Unable to resolve target host {host!r}") from None
        return infos[0][0], infos[0][4]

    if addr_obj.version == 4:
        return socket.AF_INET, (str(addr_obj), valid_port)
    if "%" in host:
        infos = socket.getaddrinfo(host, valid_port, socket.AF_INET6, socktype)
        if infos:
            return infos[0][0], infos[0][4]
    return socket.AF_INET6, (str(addr_obj), valid_port, 0, 0)


def probe_tcp_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Fast, zero-blast dual-stack TCP connect check to verify if a management port is open."""
    try:
        family, sockaddr = _resolve_socket_target(ip, port, socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        logger.debug("Invalid TCP probe target %s:%r: %s", ip, port, exc)
        return False

    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        return s.connect_ex(sockaddr) == 0
    except (OSError, ValueError, OverflowError) as exc:
        logger.debug("TCP port probe failed for %s:%d: %s", ip, port, exc)
        return False
    finally:
        s.close()


def scan_host_ports(
    ip: str,
    ssh_ports: list[int] | None = None,
    telnet_ports: list[int] | None = None,
    timeout: float = 0.8,
) -> list[tuple[int, str]]:
    """Probes a single host for open SSH and Telnet ports, returning [(port, protocol)]."""
    ssh_list = ssh_ports if ssh_ports is not None else [22]
    telnet_list = telnet_ports if telnet_ports is not None else [23]
    open_services: list[tuple[int, str]] = []
    for p in ssh_list:
        if probe_tcp_port(ip, p, timeout=timeout):
            open_services.append((p, "ssh"))
    for p in telnet_list:
        if probe_tcp_port(ip, p, timeout=timeout):
            open_services.append((p, "telnet"))
    return open_services


def scan_subnet_ports(
    ips: list[str],
    ssh_ports: list[int] | None = None,
    telnet_ports: list[int] | None = None,
    timeout: float = 0.8,
    max_workers: int = 32,
) -> dict[str, list[tuple[int, str]]]:
    """
    Parallel TCP port pre-filter across a list of target IPs.
    Returns {ip: [(port, protocol), ...]} for hosts with at least one open management port.
    """
    results: dict[str, list[tuple[int, str]]] = {}
    if not ips:
        return results
    workers = min(max_workers, max(1, len(ips)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(scan_host_ports, ip, ssh_ports, telnet_ports, timeout): ip for ip in ips}
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                open_ports = fut.result()
                if open_ports:
                    results[ip] = open_ports
            except Exception as exc:
                logger.debug("Subnet port scan worker failed for %s: %s", ip, exc)
    return results


def _is_valid_arp_unicast_ipv4(ip_addr: str) -> bool:
    """Returns True when ``ip_addr`` is a valid non-loopback, non-multicast IPv4 address."""
    try:
        ip_obj = ipaddress.IPv4Address(ip_addr)
    except ValueError as exc:
        logger.debug("Skipping malformed ARP IPv4 entry %r: %s", ip_addr, exc)
        return False
    return not (ip_obj.is_multicast or ip_obj.is_loopback)


def get_arp_table_entries() -> dict[str, str]:
    """
    Read the local OS ARP cache (`/proc/net/arp` on Linux, `arp -a` on Windows,
    `arp -an` on macOS/BSD) and return `{ip: mac}` for complete unicast entries.
    """
    entries: dict[str, str] = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    # Skip incomplete / failed ARP entries (flags == 0x0)
                    if parts[2].lower() == "0x0":
                        continue
                    ip_addr, mac = parts[0], _normalize_arp_mac(parts[3])
                    if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                        continue
                    if not _is_valid_arp_unicast_ipv4(ip_addr):
                        continue
                    entries[ip_addr] = mac
        except OSError as exc:
            logger.debug("Unable to read /proc/net/arp: %s", exc)
    elif sys.platform == "win32":
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=3, errors="ignore")
            for line in out.splitlines():
                m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\S+", line)
                if not m:
                    continue
                ip_addr, mac = m.group(1), _normalize_arp_mac(m.group(2))
                if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    continue
                if not _is_valid_arp_unicast_ipv4(ip_addr):
                    continue
                entries[ip_addr] = mac
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("Windows arp -a cache lookup failed: %s", exc)
    else:
        try:
            out = subprocess.check_output(["arp", "-an"], text=True, timeout=3, errors="ignore")
            for line in out.splitlines():
                m = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b",
                    line,
                )
                if not m:
                    continue
                ip_addr, mac = m.group(1), _normalize_arp_mac(m.group(2))
                if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    continue
                if not _is_valid_arp_unicast_ipv4(ip_addr):
                    continue
                entries[ip_addr] = mac
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("BSD/macOS arp -an cache lookup failed: %s", exc)
    return entries


def _build_unverified_probe_tls_context() -> ssl.SSLContext:
    """
    Constructs an isolated TLS client context strictly for unauthenticated, read-only
    banner and X.509 ``CommonName`` fingerprinting in ``probe_http_fingerprint()``.

    Security Boundary: Network appliances (switches, wireless APs, firewalls, printers,
    and iDRAC/iLO BMCs) overwhelmingly serve self-signed or device-serial certificates
    on RFC 1918 management IPs. ``ssl.CERT_NONE`` is intentionally confined to this
    helper; zero credentials, session cookies, or state-changing payloads are ever
    transmitted over this socket.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # nosec B501 - strictly unauthenticated read-only banner/cert CN probe
    return ctx


def _extract_peer_cert_cn(tls_sock: ssl.SSLSocket, ip: str, port: int) -> str:
    """Extracts the X.509 Subject CommonName from an unverified appliance TLS handshake."""
    try:
        der_cert = tls_sock.getpeercert(binary_form=True)
        if not der_cert:
            return ""
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der_cert)
        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if cn_attrs:
            cert_cn = str(cn_attrs[0].value).strip()
            logger.debug("Extracted unverified TLS peer certificate CN=%r from %s:%d", cert_cn, ip, port)
            return cert_cn
    except (ssl.SSLError, ValueError, OSError) as exc:
        logger.debug("Failed parsing X.509 peer certificate on %s:%d: %s", ip, port, exc)
    return ""


def probe_http_fingerprint(
    ip: str,
    ports: tuple[int, ...] = (443, 80, 8443, 8080),
    timeout: float = 1.0,
) -> dict | None:
    """
    Read-only HTTP/HTTPS banner and TLS certificate probe for headless/web-managed
    devices (switches, APs, printers, NAS, iDRAC/iLO). Returns fingerprint dict or None.
    """
    host_clean = (ip or "").strip().strip("[]")
    host_hdr = f"[{host_clean}]" if ":" in host_clean else host_clean
    for port in ports:
        if not probe_tcp_port(ip, port, timeout=min(timeout, 0.7)):
            continue
        try:
            family, sockaddr = _resolve_socket_target(ip, port, socket.SOCK_STREAM)
        except (OSError, ValueError) as exc:
            logger.debug("Invalid HTTP probe target %s:%r: %s", ip, port, exc)
            continue
        scheme = "https" if port in (443, 8443) else "http"
        server_hdr = ""
        title = ""
        cert_cn = ""
        raw_sock = socket.socket(family, socket.SOCK_STREAM)
        conn_sock: socket.socket = raw_sock
        try:
            raw_sock.settimeout(timeout)
            raw_sock.connect(sockaddr)
            if scheme == "https":
                logger.debug("Performing unverified read-only HTTPS fingerprint probe on %s:%d", ip, port)
                ctx = _build_unverified_probe_tls_context()
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host_clean)
                conn_sock = tls_sock
                cert_cn = _extract_peer_cert_cn(tls_sock, ip, port)
            req = f"GET / HTTP/1.0\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore")
            conn_sock.sendall(req)
            chunks = []
            total = 0
            deadline = time.monotonic() + max(float(timeout), 0.1)
            while total < 8192:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                conn_sock.settimeout(remaining)
                try:
                    data = conn_sock.recv(2048)
                except TimeoutError as exc:
                    logger.debug("HTTP fingerprint read timed out after %d bytes on %s:%d: %s", total, ip, port, exc)
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
            resp_text = b"".join(chunks).decode("utf-8", errors="ignore")
            m_srv = re.search(r"^Server:\s*(.+)$", resp_text, re.IGNORECASE | re.MULTILINE)
            if m_srv:
                server_hdr = m_srv.group(1).strip()
            m_title = re.search(r"<title[^>]*>([^<]+)</title>", resp_text, re.IGNORECASE | re.DOTALL)
            if m_title:
                title = " ".join(m_title.group(1).split())[:80]
            return {
                "port": port,
                "scheme": scheme,
                "server": server_hdr,
                "title": title,
                "cert_cn": cert_cn,
            }
        except (OSError, ssl.SSLError, ValueError, OverflowError) as exc:
            logger.debug("HTTP/HTTPS fingerprint probe failed on %s:%d: %s", ip, port, exc)
        finally:
            try:
                conn_sock.close()
            except OSError as exc:
                logger.debug("Error closing HTTP fingerprint probe socket on %s:%d: %s", ip, port, exc)
    return None


def infer_vendor_from_http(fp: dict | None) -> str:
    """
    Infers a network OS vendor key from a `probe_http_fingerprint()` result
    (title, server header, or TLS certificate Common Name).
    """
    if not fp:
        return "unknown"
    title = str(fp.get("title", "")).lower()
    server = str(fp.get("server", "")).lower()
    cert_cn = str(fp.get("cert_cn", "")).lower()
    combined = f"{title} {server} {cert_cn}"

    if any(k in combined for k in ("fortinet", "fortigate", "fortios")) or re.search(
        r"\b(?:fg|fgt)\d+[a-z0-9-]*\b", cert_cn
    ):
        return "fortinet"
    if any(
        k in combined for k in ("sg300", "sg350", "sg500", "cbs250", "cbs350", "cisco small business", "goahead-webs")
    ):
        return "ciscosmb"
    if any(k in combined for k in ("arista", "veos", "ceos")):
        return "arista"
    if "cisco" in combined:
        return "cisco"
    if any(k in combined for k in ("procurve", "hewlett-packard", "hp switch", "ehttp")):
        return "hpprocurve"
    if "aruba" in combined:
        return "aruba"
    if "opnsense" in combined:
        return "opnsense"
    if "openwrt" in combined or "luci" in combined:
        return "openwrt"
    if "mikrotik" in combined or "routeros" in combined:
        return "mikrotik"
    if "juniper" in combined or "junos" in combined:
        return "juniper"
    if "palo alto" in combined or "pan-os" in combined:
        return "paloalto"
    return "unknown"


# Non-network appliance ports inspired by casting-diag (https://github.com/leifdavisson/casting-diag)
APPLIANCE_PROBE_PORTS: tuple[int, ...] = (41794, 41795, 7236, 7000, 5000, 8008, 8000, 554, 9100)


def probe_appliance_ports(ip: str, timeout: float = 0.25) -> list[int]:
    """
    Lightweight, read-only dual-stack TCP connect probe for common AV/display/camera/printer appliance ports:
    41794/41795 (Crestron CIP/CTP), 7236 (Miracast/Airtame), 7000/5000 (AirPlay),
    8008 (Google Cast), 8000 (Newline/Hikvision SDK), 554 (RTSP Camera), 9100 (JetDirect Printer).
    """
    open_ports: list[int] = []
    for port in APPLIANCE_PROBE_PORTS:
        if probe_tcp_port(ip, port, timeout=timeout):
            open_ports.append(port)
    return open_ports


def classify_non_network_appliance(
    vendor_oui: str = "",
    banner: str = "",
    http_fp: dict | None = None,
    open_app_ports: list[int] | None = None,
) -> tuple[str, str] | None:
    """
    Classifies non-network appliances (AV controllers, wireless displays, IP cameras,
    Windows hosts) from OUI, SSH/Telnet banner, HTTP fingerprint, and open appliance ports.
    Returns (device_type, model_label) or None if no appliance signature matches.
    """
    oui_l = (vendor_oui or "").lower()
    banner_l = (banner or "").lower()
    server_l = str((http_fp or {}).get("server", "")).lower()
    title_l = str((http_fp or {}).get("title", "")).lower()
    ports = set(open_app_ports or [])

    if "crestron" in banner_l or "crestron" in oui_l or 41794 in ports or 41795 in ports:
        return ("av_control", "Crestron AV Controller")
    if any(k in (banner_l + " " + oui_l + " " + server_l + " " + title_l) for k in ("extron", "biamp", "q-sys", "amx")):
        return ("av_control", "AV Controller")
    if "hikvision" in oui_l or "app-webs" in server_l or ("webs" in server_l and (554 in ports or 8000 in ports)):
        return ("camera", "Hikvision IP Camera")
    if 7236 in ports:
        return ("display", "Miracast / Airtame Display")
    if 7000 in ports or (5000 in ports and "airplay" in (server_l + " " + title_l)):
        return ("display", "Apple AirPlay Display")
    if 8008 in ports:
        return ("display", "Google Cast Display")
    if 554 in ports:
        return ("camera", "RTSP IP Camera")
    if 9100 in ports or any(
        k in (server_l + " " + title_l + " " + oui_l)
        for k in ("jetdirect", "laserjet", "cups", "epson", "canon", "brother", "xerox", "ricoh", "lexmark", "kyocera")
    ):
        return ("printer", "Network Printer")
    if any(k in (server_l + " " + title_l) for k in ("proxmox", "idrac", "ilo", "synology", "qnap", "esxi", "vmware")):
        return ("server", "Server / Hypervisor / NAS")
    if "openssh_for_windows" in banner_l:
        return ("server", "Windows Host (OpenSSH)")
    if "axis" in oui_l or "axis" in title_l:
        return ("camera", "Axis IP Camera")
    if "apple" in oui_l:
        return ("workstation", "Apple Host / Mac")
    if "ruckus" in oui_l:
        return ("ap", "Ruckus Wireless AP")
    return None


def _ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _encode_oid(oid: tuple[int, ...]) -> bytes:
    body = bytearray([oid[0] * 40 + oid[1]])
    for arc in oid[2:]:
        if arc == 0:
            body.append(0)
        else:
            parts = []
            while arc > 0:
                parts.append(arc & 0x7F)
                arc >>= 7
            parts.reverse()
            for idx, p in enumerate(parts):
                body.append(p | (0x80 if idx < len(parts) - 1 else 0))
    return _ber_tlv(0x06, bytes(body))


def _decode_snmp_strings(data: bytes) -> list[str]:
    """Extract OCTET STRING (tag 0x04) values from an SNMPv2c GetResponse payload."""
    strings: list[str] = []
    i = 0
    n = len(data)
    while i < n:
        tag = data[i]
        i += 1
        if i >= n:
            break
        lb = data[i]
        i += 1
        if lb & 0x80:
            num_octets = lb & 0x7F
            if i + num_octets > n:
                break
            length = int.from_bytes(data[i : i + num_octets], "big")
            i += num_octets
        else:
            length = lb
        if i + length > n:
            break
        val = data[i : i + length]
        if tag == 0x04:
            strings.append(val.decode("utf-8", errors="ignore").strip())
            i += length
        elif tag in (0x30, 0xA2):
            continue
        else:
            i += length
    return strings


def probe_snmp_sysinfo(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 1.0,
) -> dict | None:
    """
    Lightweight read-only SNMPv2c GetRequest for `sysDescr.0` (1.3.6.1.2.1.1.1.0)
    and `sysName.0` (1.3.6.1.2.1.1.5.0). Zero external dependencies.
    """
    vb1 = _ber_tlv(0x30, _encode_oid((1, 3, 6, 1, 2, 1, 1, 1, 0)) + b"\x05\x00")
    vb2 = _ber_tlv(0x30, _encode_oid((1, 3, 6, 1, 2, 1, 1, 5, 0)) + b"\x05\x00")
    varbinds = _ber_tlv(0x30, vb1 + vb2)
    pdu = _ber_tlv(
        0xA0,  # GetRequest-PDU
        _ber_tlv(0x02, b"\x01")  # request-id = 1
        + _ber_tlv(0x02, b"\x00")  # error-status = 0
        + _ber_tlv(0x02, b"\x00")  # error-index = 0
        + varbinds,
    )
    pkt = _ber_tlv(
        0x30,
        _ber_tlv(0x02, b"\x01")  # version = 1 (SNMPv2c)
        + _ber_tlv(0x04, community.encode("utf-8"))
        + pdu,
    )
    try:
        family, sockaddr = _resolve_socket_target(ip, port, socket.SOCK_DGRAM)
    except (OSError, ValueError) as exc:
        logger.debug("Invalid SNMP probe target %s:%r: %s", ip, port, exc)
        return None
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(pkt, sockaddr)
        resp, _addr = sock.recvfrom(4096)
        octet_strings = _decode_snmp_strings(resp)
        # First octet string is community echo; subsequent are sysDescr, sysName
        values = [s for s in octet_strings if s and s != community]
        if not values:
            return None
        return {
            "sysDescr": values[0] if len(values) >= 1 else "",
            "sysName": values[1] if len(values) >= 2 else "",
        }
    except (OSError, ValueError, OverflowError) as exc:
        logger.debug("SNMPv2c sysinfo probe failed on %s:%d: %s", ip, port, exc)
        return None
    finally:
        sock.close()


def _extract_ssh_identification_line(buf: bytes) -> str:
    """
    Extract the RFC 4253 Section 4.2 SSH identification line (`SSH-...`) from a raw buffer,
    ignoring any server pre-banner lines and discarding trailing binary KEXINIT bytes.
    """
    for raw_line in buf.splitlines():
        clean = raw_line.split(b"\r", 1)[0]
        if clean.startswith(b"SSH-"):
            return clean.decode("utf-8", errors="ignore").strip()
    return ""


def get_ssh_banner(ip: str, port: int = 22, timeout: float = 3.0) -> str:
    """
    Reads the RFC 4253 SSH transport identification string without authenticating.
    Scans past optional pre-banner lines and fragmented reads within a strict deadline.
    """
    try:
        family, sockaddr = _resolve_socket_target(ip, port, socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        logger.debug("Invalid SSH banner target %s:%r: %s", ip, port, exc)
        return ""

    s = socket.socket(family, socket.SOCK_STREAM)
    banner = ""
    try:
        s.settimeout(timeout)
        s.connect(sockaddr)
        buf = b""
        deadline = time.monotonic() + max(float(timeout), 0.1)
        for _ in range(8):
            if len(buf) >= 4096:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            s.settimeout(remaining)
            try:
                chunk = s.recv(1024)
            except TimeoutError as exc:
                logger.debug("SSH pre-auth banner read timed out on %s:%d: %s", ip, port, exc)
                break
            if not chunk:
                break
            buf += chunk
            # Check complete lines (terminated by newline) for an RFC 4253 SSH-... identification string
            if b"\n" in buf:
                complete_part = buf.rsplit(b"\n", 1)[0]
                ssh_line = _extract_ssh_identification_line(complete_part)
                if ssh_line:
                    return ssh_line
        ssh_line = _extract_ssh_identification_line(buf)
        if ssh_line:
            return ssh_line
        if buf:
            raw_line = buf.split(b"\n", 1)[0].split(b"\r", 1)[0]
            banner = raw_line.decode("utf-8", errors="ignore").strip()[:256]
    except (OSError, ValueError, OverflowError) as exc:
        logger.debug("SSH pre-auth banner read failed on %s:%d: %s", ip, port, exc)
    finally:
        s.close()
    return banner


def get_telnet_banner(ip: str, port: int = 23, timeout: float = 3.0) -> str:
    """
    Reads the initial Telnet login banner without authenticating, stripping Telnet IAC
    negotiation sequences (0xFF <cmd> <opt>) cleanly.
    """
    try:
        family, sockaddr = _resolve_socket_target(ip, port, socket.SOCK_STREAM)
    except (OSError, ValueError) as exc:
        logger.debug("Invalid Telnet banner target %s:%r: %s", ip, port, exc)
        return ""

    s = socket.socket(family, socket.SOCK_STREAM)
    banner = ""
    try:
        s.settimeout(timeout)
        s.connect(sockaddr)
        raw = b""
        deadline = time.monotonic() + max(float(timeout), 0.1)
        # Read initial negotiation + banner chunks
        for _ in range(2):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            s.settimeout(remaining)
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                raw += chunk
                # If only IAC bytes arrived, decline options so server sends banner
                if all(b >= 240 or b in (1, 3, 24, 31, 32, 33, 34, 35, 36, 39) for b in chunk[:6]):
                    s.sendall(b"\xff\xfc\x18\xff\xfc\x1f\r\n")
            except TimeoutError as exc:
                logger.debug("Telnet banner chunk read timed out on %s:%d: %s", ip, port, exc)
                break
        # Strip 3-byte Telnet IAC commands (0xFF, cmd, opt) and 2-byte commands
        cleaned = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == 0xFF and i + 1 < len(raw):
                cmd = raw[i + 1]
                if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(raw):
                    i += 3
                else:
                    i += 2
            else:
                cleaned.append(raw[i])
                i += 1
        banner = cleaned.decode("utf-8", errors="ignore")
        banner = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", banner).strip()
    except (OSError, ValueError, OverflowError) as exc:
        logger.debug("Telnet banner probe failed on %s:%d: %s", ip, port, exc)
    finally:
        s.close()
    return banner


def get_mac_from_system_arp(ip: str) -> str:
    """Reads the local host ARP cache (/proc/net/arp on Linux, or system `arp` on Windows/macOS/BSD) with 0 packet overhead."""
    target_ip = (ip or "").strip()
    if not target_ip:
        return ""

    # 1. Linux /proc/net/arp (fast zero-packet file read)
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == target_ip:
                        if parts[2].lower() == "0x0":
                            continue
                        mac = _normalize_arp_mac(parts[3])
                        if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                            return mac
        except OSError as exc:
            logger.debug("Failed reading /proc/net/arp for %s: %s", target_ip, exc)

    # 2. Windows / macOS / BSD system ARP cache table
    ip_boundary_re = re.compile(rf"(?<![0-9a-fA-F.:]){re.escape(target_ip)}(?![0-9a-fA-F.:])")
    mac_re = re.compile(r"(?<![0-9a-fA-F:-])([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})(?![0-9a-fA-F:-])")
    try:
        cmd = ["arp", "-a", target_ip] if sys.platform.startswith("win") else ["arp", "-n", target_ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if not ip_boundary_re.search(line):
                    continue
                m = mac_re.search(line)
                if m:
                    mac = _normalize_arp_mac(m.group(1))
                    if mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                        return mac
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("System arp command lookup failed for %s: %s", target_ip, exc)

    return ""


def _match_vendor_from_oui(vendor_oui: str) -> str:
    """Maps a normalized IEEE OUI vendor name string to a canonical driver candidate key."""
    v = (vendor_oui or "").strip().lower()
    if not v or v == "unknown":
        return "unknown"
    # Excluded cloud-only platform: never misclassify Meraki as CLI Cisco IOS
    if "meraki" in v:
        return "unknown"
    if "cisco" in v:
        return "cisco"
    if "juniper" in v:
        return "juniper"
    # Official IEEE Aruba OUI name is "Aruba, a Hewlett Packard Enterprise Company" -> check Aruba before HP
    if "aruba" in v:
        return "aruba"
    # "Hewlett Packard Enterprise" spans Aruba AOS-CX switches and HPE ProLiant/iLO servers -> cascade to Tier 2
    if "hewlett packard enterprise" in v:
        return "unknown"
    if any(h in v for h in ("hewlett packard", "procurve")):
        return "hpprocurve"
    if "hpe" in v:
        return "aruba"
    if "palo alto" in v:
        return "paloalto"
    if "fortinet" in v:
        return "fortinet"
    if "arista" in v:
        return "arista"
    if "mikrotik" in v:
        return "mikrotik"
    return "unknown"


_MOCANA_NON_HP_OUI_KEYWORDS: tuple[str, ...] = (
    "cisco",
    "ruckus",
    "brocade",
    "netgear",
    "d-link",
    "avaya",
)


def _match_vendor_from_banner(banner_lower: str, current_candidate: str, oui_vendor: str = "") -> str:
    """Refines or classifies a vendor candidate from a lowercase SSH/Telnet banner string."""
    if not banner_lower:
        return current_candidate

    # Non-network appliances must override even a prior OUI guess
    if "crestron" in banner_lower or "openssh_for_windows" in banner_lower:
        return "unsupported_appliance"

    if any(
        k in banner_lower
        for k in (
            "sg300",
            "sg350",
            "sg500",
            "cbs250",
            "cbs350",
            "cisco small business",
            "cisco_s300",
            "openssh_7.3p1.rl",
        )
    ) or banner_lower.endswith(".rl"):
        return "ciscosmb"

    # Explicit vendor-specific SSH/Telnet banner tokens refine both "unknown" and generic "cisco"
    if any(k in banner_lower for k in ("procurve", "hewlett packard", "hp j")):
        return "hpprocurve"
    if "aruba" in banner_lower:
        return "aruba"
    if "fortissh" in banner_lower or "fortigate" in banner_lower or "vb-mt" in banner_lower:
        return "fortinet"
    if "junos" in banner_lower or "juniper" in banner_lower:
        return "juniper"
    if "panos" in banner_lower or "paloalto" in banner_lower:
        return "paloalto"
    if "rosssh" in banner_lower or "mikrotik" in banner_lower:
        return "mikrotik"
    if "arista" in banner_lower:
        return "arista"
    if "frrouting" in banner_lower:
        return "frrouting"
    if "opnsense" in banner_lower:
        return "opnsense"
    if "openwrt" in banner_lower:
        return "openwrt"

    if current_candidate != "unknown":
        return current_candidate

    if "mocana" in banner_lower:
        oui_l = (oui_vendor or "").lower()
        if oui_l and any(k in oui_l for k in _MOCANA_NON_HP_OUI_KEYWORDS):
            return "unknown"
        return "hpprocurve"
    if "cisco" in banner_lower or "user access verification" in banner_lower:
        return "cisco"

    # Generic OpenSSH OS strings (Debian/Ubuntu/FreeBSD) and Dropbear are shared by
    # Linux servers, Juniper Junos, pfSense, TrueNAS, UniFi, cameras, and phones -> leave "unknown"
    # so HTTP/TLS fingerprinting, appliance guards, Tier 3 prompt inspection, or --vendor-hint resolve safely.
    return "unknown"


def detect_vendor_range(
    ip: str,
    mac: str = "",
    port: int = 22,
    timeout: float = 3.0,
    transport: str = "ssh",
) -> tuple[str, str]:
    """
    Identifies high-level vendor range and transport banner:
    Returns: (vendor_candidate, banner_string)
    """
    candidate = "unknown"
    oui_vendor = ""

    # Tier 1: MAC Address OUI check (instant, 0 network packets; bypassed for hypervisor,
    # FHRP/HA virtual gateway, locally-administered, and multicast MACs).
    if not mac:
        mac = get_mac_from_system_arp(ip)

    if mac and not (
        is_hypervisor_mac(mac) or is_fhrp_mac(mac) or is_locally_administered_mac(mac) or is_multicast_mac(mac)
    ):
        oui_vendor = oui_lookup.lookup_oui(mac).lower()
        candidate = _match_vendor_from_oui(oui_vendor)

    # Tier 2: Transport Banner inspection (runs when MAC is unknown, across an L3 gateway,
    # on a VM/FHRP/LAA NIC, or to refine generic Cisco OUI matches into Cisco Small Business)
    banner = ""
    if candidate in ("unknown", "cisco"):
        if transport == "telnet":
            banner = get_telnet_banner(ip, port=port, timeout=timeout)
        else:
            banner = get_ssh_banner(ip, port=port, timeout=timeout)
        candidate = _match_vendor_from_banner(banner.lower(), candidate, oui_vendor=oui_vendor)

    return candidate, banner


PROMPT_OS_TO_VENDOR: dict[str, str] = {
    "cisco_ios": "cisco",
    "cisco_nxos": "cisco",
    "cisco_xr": "cisco_xr",
    "juniper_junos": "juniper",
    "aruba_os": "aruba",
    "paloalto_panos": "paloalto",
    "fortinet": "fortinet",
    "mikrotik": "mikrotik",
    "arista": "arista",
    "hpprocurve": "hpprocurve",
    "openwrt": "openwrt",
    "opnsense": "opnsense",
}


def inspect_prompt_os(prompt: str) -> str:
    """
    Tier 3: Analyzes the raw CLI prompt string to detect the target OS before sending commands.
    Returns: 'cisco_ios' | 'cisco_nxos' | 'cisco_xr' | 'juniper_junos' | 'aruba_os' | 'paloalto_panos'
             | 'fortinet' | 'mikrotik' | 'arista' | 'hpprocurve' | 'openwrt' | 'opnsense'
             | 'prompt_switch_standard' | 'unknown'
    """
    if not prompt:
        return "unknown"
    # Strip ANSI escape sequences and inspect the final non-empty prompt line (handles Junos `{master:0}\nuser@host>`)
    cleaned = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", prompt)
    lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
    if not lines:
        return "unknown"
    line = lines[-1]

    # MikroTik RouterOS prompt: [admin@MikroTik] > or [admin@MikroTik] /ip address> (never Linux `[root@host ~]#`)
    if re.search(r"^\[[^\[\]\s@]+@[^\[\]\s]+\]\s*(?:/[^>]*)?>\s*$", line):
        return "mikrotik"

    # Cisco IOS-XR prompt format: RP/0/0/CPU0:hostname#, RP/0/RSP0/CPU0:asr9k#, RP/0/RP0/CPU0:ncs.nyc#, LC/0/0/CPU0:lc#
    if re.search(r"^(?:RP|LC)/\d+/(?:(?:RSP|RP|LC)?\d+)/CPU\d+:[A-Za-z0-9_.-]+(?:\([^)]*\))?[#>]\s*$", line):
        return "cisco_xr"

    # Palo Alto PAN-OS prompt format: admin@PA-220>, admin@PA-5220(active)>, admin@hq-fw01(active)>
    if re.search(
        r"^[A-Za-z0-9_.-]+@(?:PA-[A-Za-z0-9_.-]+(?:\([A-Za-z0-9_-]+\))?|"
        r"[A-Za-z0-9_.-]+\((?:active|passive|active-primary|active-secondary|suspended|initial)\))[>#]\s*$",
        line,
        re.IGNORECASE,
    ):
        return "paloalto_panos"

    # OpenWrt prompt format: root@OpenWrt:~# or root@OpenWrt:/#
    if re.search(r"^[A-Za-z0-9_.-]+@OpenWrt[~/#:]", line, re.IGNORECASE) or ("openwrt" in line.lower()):
        return "openwrt"

    # OPNsense prompt format: root@opnsense:~ #
    if "opnsense" in line.lower():
        return "opnsense"

    # Juniper JunOS prompt format: username@hostname> or username@hostname# or username@hostname%
    if re.search(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+[>%#]\s*$", line):
        return "juniper_junos"

    # HP ProCurve / ArubaOS-S switch prompt format (checked before Fortinet so `ProCurve #` isn't stolen)
    if re.search(r"^(?:procurve|hp-)[A-Za-z0-9_.-]*(?:\s*\(config[^\)]*\))?\s*[>#]\s*$", line, re.IGNORECASE):
        return "hpprocurve"

    # Fortinet FortiOS prompt format: FortiGate-60F #, FortiGate-60F $ (read-only), FG-01 (vdom) #, fw1.corp #
    if (
        re.search(r"^(?:Forti|FG)[A-Za-z0-9_.-]+(?:\s+\([A-Za-z0-9_.-]+\))?\s*[#$]\s*$", line, re.IGNORECASE)
        or re.search(r"^[A-Za-z0-9_.-]+\s+\((?!config\b)[A-Za-z0-9_.-]+\)\s*[#$]\s*$", line, re.IGNORECASE)
        or re.search(r"^[A-Za-z0-9_.-]+\s+[#$]\s*$", line)
    ):
        return "fortinet"

    # Arista / Cisco / NX-OS VDC / Aruba switch prompt format: hostname> or hostname# (supports dotted FQDNs)
    if re.search(r"^[A-Za-z0-9_.-]+(?:\s*\(config[^\)]*\))?[>#]\s*$", line):
        if "arista" in line.lower():
            return "arista"
        return "prompt_switch_standard"

    return "unknown"


def resolve_prompt_vendor(prompt: str) -> str:
    """Maps a raw post-auth CLI prompt string to a canonical `DRIVER_REGISTRY` vendor key or `'unknown'`."""
    os_token = inspect_prompt_os(prompt)
    return PROMPT_OS_TO_VENDOR.get(os_token, "unknown")

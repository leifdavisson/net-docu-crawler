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
Zero-Blast-Radius Hardware & Operating System Pre-Identification Gate.
Cascades across:
  Tier 1: MAC OUI Vendor Range (0 network packets, instant; skips hypervisor virtual OUIs)
  Tier 2: SSH Transport Banner (TCP 22 pre-auth banner)
  Tier 3: Post-Auth Safe Prompt Inspection
  Tier 4: Safest Single Probe Command (e.g., distinguishing IOS vs NX-OS vs XR)
"""

import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import oui_lookup

# Virtual NIC OUIs assigned by hypervisors (Proxmox, QEMU/KVM, VMware, VirtualBox, Hyper-V, Xen).
# A virtual NIC MAC identifies the hypervisor, NOT the guest network OS, so Tier 1 must cascade to Tier 2.
HYPERVISOR_OUI_PREFIXES = {
    "BC:24:11",  # Proxmox Server Solutions GmbH
    "52:54:00",  # QEMU / KVM VirtIO
    "00:50:56",  # VMware ESX / vSphere
    "00:0C:29",  # VMware Workstation / ESXi
    "00:05:69",  # VMware Legacy
    "08:00:27",  # Oracle VirtualBox
    "00:15:5D",  # Microsoft Hyper-V
    "00:16:3E",  # Xen / XCP-ng
}


def is_hypervisor_mac(mac: str) -> bool:
    """Returns True if the MAC address belongs to a virtualized hypervisor NIC OUI."""
    if not mac:
        return False
    prefix = oui_lookup.get_oui_prefix(mac)
    return prefix in HYPERVISOR_OUI_PREFIXES


def probe_tcp_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Fast, zero-blast TCP connect check to verify if a management port is open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
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
    ssh_list = ssh_ports if ssh_ports is not None else [22, 2222]
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
            except Exception:
                pass
    return results


def get_arp_table_entries() -> dict[str, str]:
    """
    Read the local OS ARP cache (`/proc/net/arp` on Linux) and return `{ip: mac}`
    for complete unicast entries (excluding 00:00:00:00:00:00 and multicast/broadcast).
    """
    entries: dict[str, str] = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ip_addr, mac = parts[0], parts[3].lower()
                    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                        continue
                    try:
                        ip_obj = ipaddress.IPv4Address(ip_addr)
                        if ip_obj.is_multicast or ip_obj.is_loopback:
                            continue
                    except ValueError:
                        continue
                    entries[ip_addr] = mac
        except Exception:
            pass
    elif sys.platform == "win32":
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=3, errors="ignore")
            for line in out.splitlines():
                m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\S+", line)
                if not m:
                    continue
                ip_addr, mac = m.group(1), m.group(2).replace("-", ":").lower()
                if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    continue
                try:
                    ip_obj = ipaddress.IPv4Address(ip_addr)
                    if ip_obj.is_multicast or ip_obj.is_loopback:
                        continue
                except ValueError:
                    continue
                entries[ip_addr] = mac
        except Exception:
            pass
    return entries


def probe_http_fingerprint(
    ip: str,
    ports: tuple[int, ...] = (443, 80, 8443, 8080),
    timeout: float = 1.0,
) -> dict | None:
    """
    Read-only HTTP/HTTPS banner and TLS certificate probe for headless/web-managed
    devices (switches, APs, printers, NAS, iDRAC/iLO). Returns fingerprint dict or None.
    """
    for port in ports:
        if not probe_tcp_port(ip, port, timeout=min(timeout, 0.7)):
            continue
        scheme = "https" if port in (443, 8443) else "http"
        server_hdr = ""
        title = ""
        cert_cn = ""
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        conn_sock = raw_sock
        try:
            raw_sock.connect((ip, port))
            if scheme == "https":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn_sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
                try:
                    der_cert = conn_sock.getpeercert(binary_form=True)
                    if der_cert:
                        from cryptography import x509

                        cert = x509.load_der_x509_certificate(der_cert)
                        cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        if cn_attrs:
                            cert_cn = str(cn_attrs[0].value).strip()
                except Exception:
                    pass
            req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode("ascii")
            conn_sock.sendall(req)
            chunks = []
            total = 0
            while total < 8192:
                try:
                    data = conn_sock.recv(2048)
                except TimeoutError:
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
        except Exception:
            continue
        finally:
            try:
                conn_sock.close()
            except Exception:
                pass
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (ip, port))
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
    except Exception:
        return None
    finally:
        sock.close()


def get_ssh_banner(ip: str, port: int = 22, timeout: float = 3.0) -> str:
    """Reads the SSH transport identification string directly from the remote server without authenticating."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((ip, port))
        raw = s.recv(1024)
        banner = raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    finally:
        s.close()
    return banner


def get_telnet_banner(ip: str, port: int = 23, timeout: float = 3.0) -> str:
    """
    Reads the initial Telnet login banner without authenticating, stripping Telnet IAC
    negotiation sequences (0xFF <cmd> <opt>) cleanly.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    banner = ""
    try:
        s.connect((ip, port))
        raw = b""
        # Read initial negotiation + banner chunks
        for _ in range(2):
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                raw += chunk
                # If only IAC bytes arrived, decline options so server sends banner
                if all(b >= 240 or b in (1, 3, 24, 31, 32, 33, 34, 35, 36, 39) for b in chunk[:6]):
                    s.sendall(b"\xff\xfc\x18\xff\xfc\x1f\r\n")
            except TimeoutError:
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
        banner = cleaned.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    finally:
        s.close()
    return banner


def get_mac_from_system_arp(ip: str) -> str:
    """Reads the local host ARP cache (/proc/net/arp on Linux, or system `arp -a` on Windows/macOS) with 0 packet overhead."""
    # 1. Linux /proc/net/arp (fast zero-packet file read)
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.lower()
        except Exception:
            pass

    # 2. Windows / macOS / BSD system ARP cache table
    try:
        cmd = ["arp", "-a", ip] if sys.platform.startswith("win") else ["arp", "-n", ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if ip in line:
                    m = re.search(
                        r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                        line,
                    )
                    if m:
                        return oui_lookup.normalize_mac(m.group(1)).lower()
    except Exception:
        pass

    return ""


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

    # Tier 1: MAC Address OUI check (instant, 0 network packets; bypassed for hypervisor virtual NICs)
    if not mac:
        mac = get_mac_from_system_arp(ip)

    if mac and not is_hypervisor_mac(mac):
        vendor_oui = oui_lookup.lookup_oui(mac).lower()
        if "cisco" in vendor_oui:
            candidate = "cisco"
        elif "juniper" in vendor_oui:
            candidate = "juniper"
        elif any(h in vendor_oui for h in ["hewlett packard", "procurve"]):
            candidate = "hpprocurve"
        elif any(h in vendor_oui for h in ["aruba", "hpe"]):
            candidate = "aruba"
        elif "palo alto" in vendor_oui:
            candidate = "paloalto"
        elif "fortinet" in vendor_oui:
            candidate = "fortinet"
        elif "arista" in vendor_oui:
            candidate = "arista"
        elif "mikrotik" in vendor_oui:
            candidate = "mikrotik"

    # Tier 2: Transport Banner inspection (runs when MAC is unknown, across an L3 gateway, or on a VM NIC)
    banner = ""
    if candidate == "unknown":
        if transport == "telnet":
            banner = get_telnet_banner(ip, port=port, timeout=timeout)
        else:
            banner = get_ssh_banner(ip, port=port, timeout=timeout)
        banner_lower = banner.lower()

        if any(k in banner_lower for k in ("mocana", "procurve", "hewlett packard", "hp j")):
            candidate = "hpprocurve"
        elif any(
            k in banner_lower
            for k in ("sg300", "sg350", "sg500", "cbs250", "cbs350", "cisco small business", "cisco_s300")
        ):
            candidate = "ciscosmb"
        elif "cisco" in banner_lower or "user access verification" in banner_lower:
            candidate = "cisco"
        elif "aruba" in banner_lower:
            candidate = "aruba"
        elif "fortissh" in banner_lower or "fortigate" in banner_lower or "vb-mt" in banner_lower:
            candidate = "fortinet"
        elif "junos" in banner_lower or "juniper" in banner_lower:
            candidate = "juniper"
        elif "panos" in banner_lower or "paloalto" in banner_lower:
            candidate = "paloalto"
        elif "rosssh" in banner_lower or "mikrotik" in banner_lower:
            candidate = "mikrotik"
        elif "arista" in banner_lower:
            candidate = "arista"
        elif "debian" in banner_lower or "ubuntu" in banner_lower:
            candidate = "frrouting"
        elif "freebsd" in banner_lower or "opnsense" in banner_lower:
            candidate = "opnsense"
        elif "dropbear" in banner_lower or "openwrt" in banner_lower:
            candidate = "openwrt"

    return candidate, banner


def inspect_prompt_os(prompt: str) -> str:
    """
    Tier 3: Analyzes the raw CLI prompt string to detect the target OS before sending commands.
    Returns: 'cisco_ios' | 'cisco_nxos' | 'cisco_xr' | 'juniper_junos' | 'aruba_os' | 'paloalto_panos'
             | 'fortinet' | 'mikrotik' | 'arista' | 'openwrt' | 'opnsense' | 'prompt_switch_standard' | 'unknown'
    """
    prompt = prompt.strip()

    # MikroTik RouterOS prompt: [admin@MikroTik] > or [admin@MikroTik] /ip>
    if re.search(r"^\[.+@.+\]\s*[>/#]", prompt):
        return "mikrotik"

    # Cisco XR prompt format: RP/0/0/CPU0:hostname# or LC/0/0/CPU0:line-card#
    if re.search(r"^(?:RP|LC)/\d+/\d+/CPU\d+:[A-Za-z0-9_-]+[#>]", prompt):
        return "cisco_xr"

    # Palo Alto prompt format: admin@PA-220> or admin@hostname#
    if re.search(r"^[A-Za-z0-9_.-]+@PA-[A-Za-z0-9_.-]+[>#]\s*$", prompt, re.IGNORECASE):
        return "paloalto_panos"

    # OpenWrt prompt format: root@OpenWrt:~# or root@gateway:/#
    if re.search(r"^[A-Za-z0-9_.-]+@OpenWrt[~/#:]", prompt, re.IGNORECASE) or ("openwrt" in prompt.lower()):
        return "openwrt"

    # OPNsense prompt format: root@opnsense:~ # or root@gateway:~%
    if "opnsense" in prompt.lower():
        return "opnsense"

    # Juniper JunOS prompt format: username@hostname> or username@hostname# or username@hostname%
    if re.search(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+[>%#]\s*$", prompt):
        return "juniper_junos"

    # Fortinet FortiOS prompt format: FortiGate-60F # or FG-01 (vdom) #
    if (
        re.search(r"^(?:Forti|FG)[A-Za-z0-9_-]+.*#\s*$", prompt, re.IGNORECASE)
        or re.search(r"^[A-Za-z0-9_-]+\s+\([A-Za-z0-9_-]+\)\s*#\s*$", prompt)
        or re.search(r"^[A-Za-z0-9_-]+\s+#\s*$", prompt)
    ):
        return "fortinet"

    # HP ProCurve / ArubaOS-S switch prompt format: ProCurve# or HP-2920#
    if re.search(r"^(?:procurve|hp-)[A-Za-z0-9_-]*(?:\s*\(config[^\)]*\))?[>#]\s*$", prompt, re.IGNORECASE):
        return "hpprocurve"

    # Arista / Cisco switch prompt format: hostname> or hostname#
    if re.search(r"^[A-Za-z0-9_-]+(?:\s*\(config[^\)]*\))?[>#]\s*$", prompt):
        if "arista" in prompt.lower():
            return "arista"
        return "prompt_switch_standard"

    return "unknown"

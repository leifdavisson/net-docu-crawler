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

import os
import re
import socket
import subprocess
import sys

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


def detect_vendor_range(ip: str, mac: str = "", port: int = 22, timeout: float = 3.0) -> tuple[str, str]:
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
        elif any(h in vendor_oui for h in ["aruba", "hewlett packard", "hpe"]):
            candidate = "aruba"
        elif "palo alto" in vendor_oui:
            candidate = "paloalto"
        elif "fortinet" in vendor_oui:
            candidate = "fortinet"
        elif "arista" in vendor_oui:
            candidate = "arista"
        elif "mikrotik" in vendor_oui:
            candidate = "mikrotik"

    # Tier 2: SSH Transport Banner inspection (runs when MAC is unknown, across an L3 gateway, or on a VM NIC)
    banner = ""
    if candidate == "unknown":
        banner = get_ssh_banner(ip, port=port, timeout=timeout)
        banner_lower = banner.lower()

        if "cisco" in banner_lower:
            candidate = "cisco"
        elif "aruba" in banner_lower:
            candidate = "aruba"
        elif "fortissh" in banner_lower or "fortigate" in banner_lower or "vb-mt" in banner_lower:
            candidate = "fortinet"
        elif "panos" in banner_lower or "paloalto" in banner_lower:
            candidate = "paloalto"
        elif "junos" in banner_lower:
            candidate = "juniper"
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

    # Arista / Cisco switch prompt format: hostname> or hostname#
    if re.search(r"^[A-Za-z0-9_-]+(?:\s*\(config[^\)]*\))?[>#]\s*$", prompt):
        if "arista" in prompt.lower():
            return "arista"
        return "prompt_switch_standard"

    return "unknown"

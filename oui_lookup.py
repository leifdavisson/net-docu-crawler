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

import json
import os
import re
import tempfile
import threading
import urllib.error
import urllib.request

# Bundled comprehensive offline database of enterprise network equipment vendor OUIs.
# Zero external web requests required: safe for isolated, air-gapped management VLANs.
COMMON_OUIS = {
    # Cisco Systems
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems",
    "00:01:63": "Cisco Systems",
    "00:01:64": "Cisco Systems",
    "00:01:96": "Cisco Systems",
    "00:01:97": "Cisco Systems",
    "00:02:16": "Cisco Systems",
    "00:02:17": "Cisco Systems",
    "00:02:4A": "Cisco Systems",
    "00:02:4B": "Cisco Systems",
    "00:02:B9": "Cisco Systems",
    "00:02:BA": "Cisco Systems",
    "00:02:FC": "Cisco Systems",
    "00:02:FD": "Cisco Systems",
    "00:03:31": "Cisco Systems",
    "00:03:32": "Cisco Systems",
    "00:03:6B": "Cisco Systems",
    "00:03:6C": "Cisco Systems",
    "00:03:E3": "Cisco Systems",
    "00:03:E4": "Cisco Systems",
    "00:04:4D": "Cisco Systems",
    "00:04:4E": "Cisco Systems",
    "00:04:9A": "Cisco Systems",
    "00:04:9B": "Cisco Systems",
    "00:04:C0": "Cisco Systems",
    "00:04:C1": "Cisco Systems",
    "00:04:DD": "Cisco Systems",
    "00:04:DE": "Cisco Systems",
    "00:05:00": "Cisco Systems",
    "00:05:31": "Cisco Systems",
    "00:05:32": "Cisco Systems",
    "00:05:5E": "Cisco Systems",
    "00:05:5F": "Cisco Systems",
    "00:05:9A": "Cisco Systems",
    "00:05:9B": "Cisco Systems",
    "00:06:28": "Cisco Systems",
    "00:06:29": "Cisco Systems",
    "00:06:52": "Cisco Systems",
    "00:06:53": "Cisco Systems",
    "00:07:0D": "Cisco Systems",
    "00:07:0E": "Cisco Systems",
    "00:07:50": "Cisco Systems",
    "00:07:51": "Cisco Systems",
    "00:07:84": "Cisco Systems",
    "00:07:85": "Cisco Systems",
    "00:07:B3": "Cisco Systems",
    "00:07:B4": "Cisco Systems",
    "00:07:EC": "Cisco Systems",
    "00:07:ED": "Cisco Systems",
    "00:08:20": "Cisco Systems",
    "00:08:21": "Cisco Systems",
    "00:08:7C": "Cisco Systems",
    "00:08:7D": "Cisco Systems",
    "00:08:A3": "Cisco Systems",
    "00:08:A4": "Cisco Systems",
    "00:08:E2": "Cisco Systems",
    "00:08:E3": "Cisco Systems",
    "00:09:43": "Cisco Systems",
    "00:09:44": "Cisco Systems",
    "00:09:7B": "Cisco Systems",
    "00:09:7C": "Cisco Systems",
    "00:09:B6": "Cisco Systems",
    "00:09:B7": "Cisco Systems",
    "00:09:E8": "Cisco Systems",
    "00:09:E9": "Cisco Systems",
    "00:0A:41": "Cisco Systems",
    "00:0A:42": "Cisco Systems",
    "00:0A:8A": "Cisco Systems",
    "00:0A:8B": "Cisco Systems",
    "00:0A:B7": "Cisco Systems",
    "00:0A:B8": "Cisco Systems",
    "00:0A:F3": "Cisco Systems",
    "00:0A:F4": "Cisco Systems",
    "00:0B:45": "Cisco Systems",
    "00:0B:46": "Cisco Systems",
    "00:0B:85": "Cisco Systems",
    "00:0B:FC": "Cisco Systems",
    "00:11:20": "Cisco Systems",
    "00:11:21": "Cisco Systems",
    "00:11:5C": "Cisco Systems",
    "00:11:5D": "Cisco Systems",
    "00:11:92": "Cisco Systems",
    "00:11:93": "Cisco Systems",
    "00:11:BB": "Cisco Systems",
    "00:11:BC": "Cisco Systems",
    "00:12:00": "Cisco Systems",
    "00:12:01": "Cisco Systems",
    "00:12:43": "Cisco Systems",
    "00:12:44": "Cisco Systems",
    "00:12:7F": "Cisco Systems",
    "00:12:80": "Cisco Systems",
    "00:12:D9": "Cisco Systems",
    "00:12:DA": "Cisco Systems",
    "00:13:19": "Cisco Systems",
    "00:13:1A": "Cisco Systems",
    "00:13:5F": "Cisco Systems",
    "00:13:60": "Cisco Systems",
    "00:13:7F": "Cisco Systems",
    "00:13:80": "Cisco Systems",
    "00:13:C3": "Cisco Systems",
    "00:13:C4": "Cisco Systems",
    "00:14:1B": "Cisco Systems",
    "00:14:1C": "Cisco Systems",
    "00:14:69": "Cisco Systems",
    "00:14:6A": "Cisco Systems",
    "00:14:A8": "Cisco Systems",
    "00:14:A9": "Cisco Systems",
    "00:14:F1": "Cisco Systems",
    "00:14:F2": "Cisco Systems",
    "00:15:2B": "Cisco Systems",
    "00:15:2C": "Cisco Systems",
    "00:15:62": "Cisco Systems",
    "00:15:63": "Cisco Systems",
    "00:15:C6": "Cisco Systems",
    "00:15:C7": "Cisco Systems",
    "00:15:FA": "Cisco Systems",
    "00:15:FB": "Cisco Systems",
    "00:16:46": "Cisco Systems",
    "00:16:47": "Cisco Systems",
    "00:16:9C": "Cisco Systems",
    "00:16:9D": "Cisco Systems",
    "00:16:C7": "Cisco Systems",
    "00:16:C8": "Cisco Systems",
    "00:17:0E": "Cisco Systems",
    "00:17:0F": "Cisco Systems",
    "00:17:3B": "Cisco Systems",
    "00:17:59": "Cisco Systems",
    "00:17:5A": "Cisco Systems",
    "00:17:94": "Cisco Systems",
    "00:17:95": "Cisco Systems",
    "00:17:DF": "Cisco Systems",
    "00:17:E0": "Cisco Systems",
    "00:18:18": "Cisco Systems",
    "00:18:19": "Cisco Systems",
    "00:18:73": "Cisco Systems",
    "00:18:74": "Cisco Systems",
    "00:18:B9": "Cisco Systems",
    "00:18:BA": "Cisco Systems",
    "00:19:06": "Cisco Systems",
    "00:19:07": "Cisco Systems",
    "00:19:2F": "Cisco Systems",
    "00:19:30": "Cisco Systems",
    "00:19:55": "Cisco Systems",
    "00:19:56": "Cisco Systems",
    "00:19:A9": "Cisco Systems",
    "00:19:AA": "Cisco Systems",
    "00:19:E7": "Cisco Systems",
    "00:19:E8": "Cisco Systems",
    "00:1A:2F": "Cisco Systems",
    "00:1A:30": "Cisco Systems",
    "00:1A:6C": "Cisco Systems",
    "00:1A:6D": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:1A:A2": "Cisco Systems",
    "00:1A:E2": "Cisco Systems",
    "00:1A:E3": "Cisco Systems",
    "00:1B:0C": "Cisco Systems",
    "00:1B:0D": "Cisco Systems",
    "00:1B:2A": "Cisco Systems",
    "00:1B:2B": "Cisco Systems",
    "00:1B:53": "Cisco Systems",
    "00:1B:54": "Cisco Systems",
    "00:1B:8F": "Cisco Systems",
    "00:1B:90": "Cisco Systems",
    "00:1B:D4": "Cisco Systems",
    "00:1B:D5": "Cisco Systems",
    "00:1C:0E": "Cisco Systems",
    "00:1C:0F": "Cisco Systems",
    "00:1C:57": "Cisco Systems",
    "00:1C:58": "Cisco Systems",
    "00:1C:B0": "Cisco Systems",
    "00:1C:B1": "Cisco Systems",
    "00:1D:45": "Cisco Systems",
    "00:1D:46": "Cisco Systems",
    "00:1D:70": "Cisco Systems",
    "00:1D:71": "Cisco Systems",
    "00:1D:A1": "Cisco Systems",
    "00:1D:A2": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:1E:14": "Cisco Systems",
    "00:1E:49": "Cisco Systems",
    "00:1E:4A": "Cisco Systems",
    "00:1E:79": "Cisco Systems",
    "00:1E:7A": "Cisco Systems",
    "00:1E:BD": "Cisco Systems",
    "00:1E:BE": "Cisco Systems",
    "00:1E:F6": "Cisco Systems",
    "00:1E:F7": "Cisco Systems",
    "00:1F:26": "Cisco Systems",
    "00:1F:27": "Cisco Systems",
    "00:1F:6C": "Cisco Systems",
    "00:1F:6D": "Cisco Systems",
    "00:1F:9D": "Cisco Systems",
    "00:1F:9E": "Cisco Systems",
    "00:1F:CA": "Cisco Systems",
    "00:1F:CB": "Cisco Systems",
    "00:21:1B": "Cisco Systems",
    "00:21:1C": "Cisco Systems",
    "00:21:55": "Cisco Systems",
    "00:21:56": "Cisco Systems",
    "00:21:A0": "Cisco Systems",
    "00:21:A1": "Cisco Systems",
    "00:21:D7": "Cisco Systems",
    "00:21:D8": "Cisco Systems",
    "00:22:55": "Cisco Systems",
    "00:22:56": "Cisco Systems",
    "00:22:90": "Cisco Systems",
    "00:22:91": "Cisco Systems",
    "00:22:BD": "Cisco Systems",
    "00:22:BE": "Cisco Systems",
    "00:23:04": "Cisco Systems",
    "00:23:05": "Cisco Systems",
    "00:23:33": "Cisco Systems",
    "00:23:34": "Cisco Systems",
    "00:23:5D": "Cisco Systems",
    "00:23:5E": "Cisco Systems",
    "00:23:AB": "Cisco Systems",
    "00:23:AC": "Cisco Systems",
    "00:23:EA": "Cisco Systems",
    "00:23:EB": "Cisco Systems",
    "00:24:13": "Cisco Systems",
    "00:24:14": "Cisco Systems",
    "00:24:50": "Cisco Systems",
    "00:24:51": "Cisco Systems",
    "00:24:97": "Cisco Systems",
    "00:24:98": "Cisco Systems",
    "00:24:C3": "Cisco Systems",
    "00:24:C4": "Cisco Systems",
    "00:24:F7": "Cisco Systems",
    "00:24:F8": "Cisco Systems",
    "00:25:45": "Cisco Systems",
    "00:25:46": "Cisco Systems",
    "00:25:83": "Cisco Systems",
    "00:25:84": "Cisco Systems",
    "00:25:B4": "Cisco Systems",
    "00:25:B5": "Cisco Systems",
    "00:26:0A": "Cisco Systems",
    "00:26:0B": "Cisco Systems",
    "00:26:43": "Cisco Systems",
    "00:26:44": "Cisco Systems",
    "00:26:98": "Cisco Systems",
    "00:26:99": "Cisco Systems",
    "00:26:CB": "Cisco Systems",
    "00:26:CC": "Cisco Systems",
    "00:26:F2": "Cisco Systems",
    "00:26:F3": "Cisco Systems",
    "00:27:0C": "Cisco Systems",
    "00:27:0D": "Cisco Systems",
    "00:42:68": "Cisco Systems",
    "00:50:0F": "Cisco Systems",
    "00:50:14": "Cisco Systems",
    "00:50:2A": "Cisco Systems",
    "00:50:3E": "Cisco Systems",
    "00:50:50": "Cisco Systems",
    "00:50:53": "Cisco Systems",
    "00:50:54": "Cisco Systems",
    "00:50:73": "Cisco Systems",
    "00:50:80": "Cisco Systems",
    "00:50:A2": "Cisco Systems",
    "00:50:BD": "Cisco Systems",
    "00:50:D1": "Cisco Systems",
    "00:50:E2": "Cisco Systems",
    "00:50:F0": "Cisco Systems",
    "00:60:09": "Cisco Systems",
    "00:60:2F": "Cisco Systems",
    "00:60:3E": "Cisco Systems",
    "00:60:47": "Cisco Systems",
    "00:60:5C": "Cisco Systems",
    "00:60:70": "Cisco Systems",
    "00:90:21": "Cisco Systems",
    "00:90:5F": "Cisco Systems",
    "00:90:6D": "Cisco Systems",
    "00:90:86": "Cisco Systems",
    "00:90:AB": "Cisco Systems",
    "00:90:BF": "Cisco Systems",
    "00:90:F2": "Cisco Systems",
    "00:D0:02": "Cisco Systems",
    "00:D0:03": "Cisco Systems",
    "00:D0:58": "Cisco Systems",
    "00:D0:79": "Cisco Systems",
    "00:D0:97": "Cisco Systems",
    "00:D0:BA": "Cisco Systems",
    "00:D0:BB": "Cisco Systems",
    "00:D0:BC": "Cisco Systems",
    "00:D0:C0": "Cisco Systems",
    "00:D0:D3": "Cisco Systems",
    "00:D0:E0": "Cisco Systems",
    "00:D0:FF": "Cisco Systems",
    "00:E0:14": "Cisco Systems",
    "00:E0:1E": "Cisco Systems",
    "00:E0:34": "Cisco Systems",
    "00:E0:4F": "Cisco Systems",
    "00:E0:8F": "Cisco Systems",
    "00:E0:A3": "Cisco Systems",
    "00:E0:B0": "Cisco Systems",
    "00:E0:FE": "Cisco Systems",
    "04:27:58": "Cisco Systems",
    "04:62:73": "Cisco Systems",
    "04:DA:D2": "Cisco Systems",
    "08:1F:71": "Cisco Systems",
    "08:96:AD": "Cisco Systems",
    "0C:27:24": "Cisco Systems",
    "10:BD:18": "Cisco Systems",
    "18:8B:45": "Cisco Systems",
    "28:52:61": "Cisco Systems",
    "38:ED:18": "Cisco Systems",
    "40:55:39": "Cisco Systems",
    "50:06:04": "Cisco Systems",
    "58:97:BD": "Cisco Systems",
    "5C:5B:35": "Cisco Systems",
    "70:38:EE": "Cisco Systems",
    "84:78:AC": "Cisco Systems",
    "A0:3D:6F": "Cisco Systems",
    "B4:14:89": "Cisco Systems",
    "C8:F9:F9": "Cisco Systems",
    "E4:C7:22": "Cisco Systems",
    # Cisco Meraki
    "00:18:0A": "Cisco Meraki",
    "0C:8D:DB": "Cisco Meraki",
    "34:56:FE": "Cisco Meraki",
    "88:15:44": "Cisco Meraki",
    "E0:55:3D": "Cisco Meraki",
    # Aruba Networks / Hewlett Packard Enterprise (HPE)
    "00:0B:86": "Aruba/HPE",
    "00:0F:20": "Aruba/HPE",
    "00:11:0A": "Aruba/HPE",
    "00:16:35": "Aruba/HPE",
    "00:17:A4": "Aruba/HPE",
    "00:1A:1E": "Aruba/HPE",
    "00:1E:0B": "Aruba/HPE",
    "00:22:64": "Aruba/HPE",
    "00:25:B3": "Aruba/HPE",
    "20:A6:CD": "Aruba/HPE",
    "24:DE:C6": "Aruba/HPE",
    "2C:76:8A": "Aruba/HPE",
    "40:E3:D6": "Aruba/HPE",
    "70:10:5C": "Aruba/HPE",
    "94:B4:0F": "Aruba/HPE",
    "A0:D3:C1": "Aruba/HPE",
    "C8:CB:B8": "Aruba/HPE",
    # Juniper Networks
    "00:05:85": "Juniper Networks",
    "00:10:DB": "Juniper Networks",
    "00:12:1E": "Juniper Networks",
    "00:14:F6": "Juniper Networks",
    "00:19:E2": "Juniper Networks",
    "00:1F:12": "Juniper Networks",
    "00:21:59": "Juniper Networks",
    "00:24:DC": "Juniper Networks",
    "00:26:88": "Juniper Networks",
    "2C:6B:F5": "Juniper Networks",
    "3C:61:04": "Juniper Networks",
    "3C:94:D5": "Juniper Networks",
    "44:AA:50": "Juniper Networks",
    "54:E0:32": "Juniper Networks",
    "80:71:1D": "Juniper Networks",
    "84:18:88": "Juniper Networks",
    "D4:04:CD": "Juniper Networks",
    "FC:33:42": "Juniper Networks",
    # Ruckus Wireless / Brocade / CommScope
    "00:13:92": "Ruckus Wireless",
    "00:1D:2E": "Ruckus Wireless",
    "00:24:82": "Ruckus Wireless",
    "10:F0:68": "Ruckus Wireless",
    "2C:E6:CC": "Ruckus Wireless",
    "58:93:96": "Ruckus Wireless",
    "60:D0:2C": "Ruckus Wireless",
    "74:3E:2B": "Ruckus Wireless",
    "8C:0C:90": "Ruckus Wireless",
    "C0:8A:DE": "Ruckus Wireless",
    # Ubiquiti Networks (UniFi, EdgeMAX)
    "00:15:6D": "Ubiquiti Networks",
    "00:27:22": "Ubiquiti Networks",
    "04:18:D6": "Ubiquiti Networks",
    "18:E8:29": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "60:E3:27": "Ubiquiti Networks",
    "74:83:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "80:2A:A8": "Ubiquiti Networks",
    "90:17:AC": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "DC:9F:DB": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks",
    # Arista Networks
    "00:1C:73": "Arista Networks",
    "28:99:3A": "Arista Networks",
    "74:83:EF": "Arista Networks",
    "98:5A:EB": "Arista Networks",
    "D8:B1:90": "Arista Networks",
    # Palo Alto Networks
    "00:1B:17": "Palo Alto Networks",
    "08:30:6B": "Palo Alto Networks",
    "08:66:1F": "Palo Alto Networks",
    "D4:1D:71": "Palo Alto Networks",
    "D4:F4:BE": "Palo Alto Networks",
    "F4:0F:1B": "Palo Alto Networks",
    # Fortinet (FortiGate, FortiSwitch, FortiAP)
    "00:09:0F": "Fortinet",
    "00:21:07": "Fortinet",
    "04:D5:90": "Fortinet",
    "70:4C:A5": "Fortinet",
    "84:B1:53": "Fortinet",
    "90:6C:AC": "Fortinet",
    # Extreme Networks (Enterasys, Avaya, Aerohive)
    "00:01:30": "Extreme Networks",
    "00:04:96": "Extreme Networks",
    "00:1F:45": "Extreme Networks",
    "00:E0:2B": "Extreme Networks",
    "40:A6:77": "Extreme Networks",
    # Dell Networking / Force10
    "00:01:E8": "Dell Networking",
    "00:14:22": "Dell Networking",
    "00:1D:09": "Dell Networking",
    "00:25:64": "Dell Networking",
    "14:18:77": "Dell Networking",
    "24:B6:FD": "Dell Networking",
    "A4:1F:72": "Dell Networking",
    "F8:DB:88": "Dell Networking",
    # MikroTik (RouterBOARD, Cloud Router Switch)
    "00:0C:42": "MikroTik",
    "2C:C8:1B": "MikroTik",
    "48:8F:5A": "MikroTik",
    "64:D1:54": "MikroTik",
    "B8:69:F4": "MikroTik",
    "CC:2D:E0": "MikroTik",
    # Check Point Software Technologies
    "00:1C:7F": "Check Point",
    "00:90:FB": "Check Point",
    # SonicWall
    "00:06:B1": "SonicWall",
    "00:17:C5": "SonicWall",
    "18:B1:69": "SonicWall",
    "2C:B8:ED": "SonicWall",
    # F5 Networks (BIG-IP)
    "00:01:D7": "F5 Networks",
    "00:23:E9": "F5 Networks",
    "00:90:7F": "F5 Networks",
    # Netgear (Commercial / ProSAFE Managed)
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:1E:2A": "Netgear",
    "20:4E:7F": "Netgear",
    "44:94:FC": "Netgear",
    # TP-Link (Omada Enterprise / JetStream)
    "00:31:92": "TP-Link",
    "14:EB:B6": "TP-Link",
    "50:C7:BF": "TP-Link",
    "50:D4:F7": "TP-Link",
    "70:4F:57": "TP-Link",
    "E4:C3:2A": "TP-Link",
    # Allied Telesis
    "00:00:F4": "Allied Telesis",
    "00:15:77": "Allied Telesis",
    "00:1A:EB": "Allied Telesis",
    # Enterprise VoIP & Infrastructure (VoIP Phones on Voice VLANs)
    "00:04:F2": "Polycom",
    "64:16:7F": "Polycom",
    "00:15:65": "Yealink",
    "80:5E:C0": "Yealink",
    # Virtualization & Hypervisor Virtual NICs (Proxmox, QEMU/KVM, VMware, VirtualBox, Hyper-V, Xen, Parallels, oVirt, Nutanix, Docker)
    "BC:24:11": "Proxmox Server Solutions GmbH",
    "52:54:00": "QEMU/KVM Virtual NIC",
    "52:54:AB": "QEMU/KVM Virtual NIC",
    "54:52:00": "QEMU/KVM Virtual NIC",
    "00:50:56": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:05:69": "VMware, Inc.",
    "00:1C:14": "VMware, Inc.",
    "00:1C:42": "Parallels, Inc.",
    "00:1A:4A": "Qumranet / Red Hat KVM (oVirt)",
    "00:03:FF": "Microsoft Virtual PC / Hyper-V",
    "00:0F:4B": "Oracle Virtual Iron / VirtualBox",
    "08:00:27": "Oracle VirtualBox",
    "0A:00:27": "Oracle VirtualBox Host-Only",
    "00:15:5D": "Microsoft Hyper-V",
    "00:16:3E": "Xen Virtual NIC",
    "50:6B:8D": "Nutanix AHV",
    "02:42:AC": "Docker Container Virtual NIC",
}

# Virtual NIC OUIs assigned by hypervisors and container bridges.
# A virtual NIC MAC identifies the hypervisor/runtime rather than the guest network OS.
HYPERVISOR_OUI_PREFIXES: frozenset[str] = frozenset(
    {
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
)

# Optional local IEEE OUI database file path
OUI_FILE = "oui.txt"
# Persistent cache for opt-in online OUI lookups so each unseen OUI is queried at most once
OUI_CACHE_FILE = "oui_cache.json"
_oui_cache_lock = threading.Lock()
_oui_file_lock = threading.Lock()
_online_oui_cache: dict[str, str] = {}
_online_cache_loaded = False
_transient_failed_ouis: set[str] = set()

_MAC_SEP_6_RE = re.compile(
    r"^([0-9a-fA-F]{1,2})([:-])([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})\2"
    r"([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})$"
)
_MAC_CISCO_DOT_RE = re.compile(r"^([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})$")
_MAC_HP_PAIR_RE = re.compile(r"^([0-9a-fA-F]{6})[:-]([0-9a-fA-F]{6})$")
_MAC_BARE_12_RE = re.compile(r"^[0-9a-fA-F]{12}$")
_OUI_SEP_3_RE = re.compile(r"^([0-9a-fA-F]{1,2})([:-])([0-9a-fA-F]{1,2})\2([0-9a-fA-F]{1,2})$")
_OUI_BARE_6_RE = re.compile(r"^[0-9a-fA-F]{6}$")


def _parse_mac_octets(mac_str) -> list[str] | None:
    """Parse a valid 48-bit MAC string into 6 uppercase two-hex-digit octets, or None."""
    if not mac_str or not isinstance(mac_str, str):
        return None
    s = mac_str.strip()
    if not s:
        return None

    m6 = _MAC_SEP_6_RE.match(s)
    if m6:
        return [m6.group(i).zfill(2).upper() for i in (1, 3, 4, 5, 6, 7)]

    mc = _MAC_CISCO_DOT_RE.match(s)
    if mc:
        h = (mc.group(1) + mc.group(2) + mc.group(3)).upper()
        return [h[i : i + 2] for i in range(0, 12, 2)]

    mhp = _MAC_HP_PAIR_RE.match(s)
    if mhp:
        h = (mhp.group(1) + mhp.group(2)).upper()
        return [h[i : i + 2] for i in range(0, 12, 2)]

    if _MAC_BARE_12_RE.match(s):
        h = s.upper()
        return [h[i : i + 2] for i in range(0, 12, 2)]

    return None


def is_valid_mac(mac_str) -> bool:
    """Returns True if `mac_str` parses cleanly as a 48-bit IEEE 802 MAC address."""
    return _parse_mac_octets(mac_str) is not None


def normalize_mac(mac_str):
    """
    Normalizes a valid 48-bit MAC address string into AA:BB:CC:DD:EE:FF format.
    Accepts:
    - aabb.ccdd.eeff (Cisco dot format)
    - aabbcc-ddeeff (HP ProCurve format)
    - aa:bb:cc:dd:ee:ff / AA:BB:CC:DD:EE:FF / 0:c:29:1:2:3 (colon, including BSD short-octet)
    - aa-bb-cc-dd-ee-ff / 0-c-29-1-2-3 (dash)
    - aabbccddeeff (bare 12 hex digits)
    Returns malformed/non-MAC inputs unchanged (or "" for empty input).
    """
    if not mac_str:
        return ""
    octets = _parse_mac_octets(mac_str)
    if octets is None:
        return mac_str  # Return as-is if malformed
    return ":".join(octets)


def get_oui_prefix(mac_str) -> str:
    """Extracts the uppercase 24-bit OUI prefix (AA:BB:CC) from a valid MAC address or 3-octet OUI."""
    if not mac_str or not isinstance(mac_str, str):
        return ""
    octets = _parse_mac_octets(mac_str)
    if octets is not None:
        return ":".join(octets[:3])

    s = mac_str.strip()
    m3 = _OUI_SEP_3_RE.match(s)
    if m3:
        return ":".join(m3.group(i).zfill(2).upper() for i in (1, 3, 4))
    if _OUI_BARE_6_RE.match(s):
        h = s.upper()
        return f"{h[0:2]}:{h[2:4]}:{h[4:6]}"
    return ""


def is_multicast_mac(mac_str) -> bool:
    """Returns True if the IEEE I/G (multicast/broadcast) bit (bit 0 of first octet) is set."""
    prefix = get_oui_prefix(mac_str)
    if not prefix:
        return False
    return (int(prefix[:2], 16) & 0x01) != 0


def is_locally_administered_mac(mac_str) -> bool:
    """Returns True if the IEEE U/L (locally administered) bit (bit 1 of first octet) is set."""
    prefix = get_oui_prefix(mac_str)
    if not prefix:
        return False
    return (int(prefix[:2], 16) & 0x02) != 0


def is_hypervisor_mac(mac_str) -> bool:
    """Returns True if the MAC address belongs to a known hypervisor/container virtual NIC OUI."""
    prefix = get_oui_prefix(mac_str)
    return bool(prefix and prefix in HYPERVISOR_OUI_PREFIXES)


def classify_fhrp_mac(mac_str) -> str:
    """
    Identifies well-known First-Hop Redundancy Protocol (FHRP) and HA cluster virtual MACs:
    - VRRP v2/v3 IPv4 & CARP (RFC 5798): 00:00:5E:00:01:xx
    - VRRP v3 IPv6 (RFC 5798):          00:00:5E:00:02:xx
    - Cisco HSRP v1:                    00:00:0C:07:AC:xx
    - Cisco HSRP v2:                    00:00:0C:9F:F0:00 - 00:00:0C:9F:FF:FF
    - Cisco GLBP:                       00:07:B4:00:xx:yy
    - Fortinet FGCP HA:                 00:09:0F:09:xx:yy
    Returns a descriptive label or "" if not a recognized FHRP/HA virtual MAC.
    """
    octets = _parse_mac_octets(mac_str)
    if octets is None:
        return ""
    o0, o1, o2, o3, o4, _o5 = octets
    if (o0, o1, o2, o3, o4) == ("00", "00", "5E", "00", "01"):
        return "VRRP / CARP Virtual MAC (IANA)"
    if (o0, o1, o2, o3, o4) == ("00", "00", "5E", "00", "02"):
        return "VRRPv3 IPv6 Virtual MAC (IANA)"
    if (o0, o1, o2, o3, o4) == ("00", "00", "0C", "07", "AC"):
        return "Cisco HSRP v1 Virtual MAC"
    if (o0, o1, o2, o3) == ("00", "00", "0C", "9F") and o4.startswith("F"):
        return "Cisco HSRP v2 Virtual MAC"
    if (o0, o1, o2, o3) == ("00", "07", "B4", "00"):
        return "Cisco GLBP Virtual MAC"
    if (o0, o1, o2, o3) == ("00", "09", "0F", "09"):
        return "Fortinet FGCP HA Virtual MAC"
    return ""


def is_fhrp_mac(mac_str) -> bool:
    """Returns True if `mac_str` is a recognized FHRP/HA virtual gateway MAC address."""
    return bool(classify_fhrp_mac(mac_str))


# Global cache for dynamic OUI lookups loaded from file
_loaded_ouis: dict[str, str] = {}


def load_oui_file() -> bool:
    """Loads an optional local IEEE OUI text file if already present on disk (thread-safe, atomic, never downloads)."""
    global _loaded_ouis
    if _loaded_ouis:
        return True

    with _oui_file_lock:
        if _loaded_ouis:
            return True

        if not os.path.exists(OUI_FILE):
            return False

        pattern = re.compile(r"^([0-9a-fA-F]{2})[-:]([0-9a-fA-F]{2})[-:]([0-9a-fA-F]{2})\s+\(hex\)\s+(.+)$")
        pattern_flat = re.compile(r"^([0-9a-fA-F]{6})\s+\(base 16\)\s+(.+)$")
        parsed: dict[str, str] = {}

        try:
            with open(OUI_FILE, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    match = pattern.match(line)
                    if match:
                        prefix = f"{match.group(1)}:{match.group(2)}:{match.group(3)}".upper()
                        parsed[prefix] = match.group(4).strip()
                        continue
                    match_flat = pattern_flat.match(line)
                    if match_flat:
                        h = match_flat.group(1)
                        prefix = f"{h[0:2]}:{h[2:4]}:{h[4:6]}".upper()
                        parsed[prefix] = match_flat.group(2).strip()
        except OSError:
            return False
        _loaded_ouis = parsed
        return bool(_loaded_ouis)


def _load_online_cache() -> None:
    global _online_oui_cache, _online_cache_loaded
    if _online_cache_loaded:
        return
    _online_cache_loaded = True
    if not os.path.exists(OUI_CACHE_FILE):
        return
    try:
        with open(OUI_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _online_oui_cache = {str(k).upper(): str(v) for k, v in data.items()}
    except (OSError, json.JSONDecodeError, ValueError):
        pass


def _save_online_cache() -> None:
    """Atomically persists `_online_oui_cache` to `OUI_CACHE_FILE`."""
    try:
        cache_dir = os.path.dirname(os.path.abspath(OUI_CACHE_FILE)) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".oui_cache_", suffix=".tmp", dir=cache_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(_online_oui_cache, f, indent=2, sort_keys=True)
            os.replace(tmp_path, OUI_CACHE_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except OSError:
        pass


def _is_globally_administered_unicast(prefix: str) -> bool:
    """Returns True if the OUI prefix is a valid unicast, globally-administered IEEE OUI."""
    try:
        first_octet = int(prefix.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    # Bit 0 = multicast, Bit 1 = locally administered
    return (first_octet & 0x03) == 0


def _is_online_lookup_enabled(online: bool | None) -> bool:
    """
    Determine whether external api.macvendors.com lookup is allowed.
    Offline by default for air-gapped safety:
    - NET_DOCU_OFFLINE_OUI=1/true/yes is a hard kill-switch overriding all callers.
    - Explicit `online=True` / `online=False` takes precedence when not killed by env.
    - Default (`online=None`) is False unless `NET_DOCU_ONLINE_OUI=1/true/yes` is set.
    """
    if os.environ.get("NET_DOCU_OFFLINE_OUI", "").strip().lower() in ("1", "true", "yes"):
        return False
    if online is not None:
        return bool(online)
    return os.environ.get("NET_DOCU_ONLINE_OUI", "").strip().lower() in ("1", "true", "yes")


def _fetch_oui_online(prefix: str, timeout: float = 1.5) -> str:
    """
    Queries api.macvendors.com for an unseen OUI prefix.
    Returns vendor name on 200, 'Unknown' on 404, and '' on transient errors
    (429/5xx/timeout/network failure) so transient outages never poison oui_cache.json.
    """
    url = f"https://api.macvendors.com/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "Net-Docu-Crawler/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                vendor = resp.read().decode("utf-8", errors="ignore").strip()
                if vendor:
                    return vendor
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "Unknown"
        return ""
    except Exception:
        return ""
    return ""


def get_vendor(mac_str, online: bool | None = None):
    """
    Returns the manufacturer/vendor name for a MAC address.
    Strictly offline by default (safe for air-gapped management VLANs):
    1. Identifies recognized FHRP / HA virtual MACs (VRRP, CARP, HSRP, GLBP, FGCP).
    2. Checks the built-in enterprise network vendor dictionary (`COMMON_OUIS`).
    3. Checks the local IEEE OUI text database (`oui.txt`, if present on disk).
    4. Checks the persistent `oui_cache.json` for previously cached OUIs.
    5. Only when explicitly opted in (`online=True` or `NET_DOCU_ONLINE_OUI=1`, and
       `NET_DOCU_OFFLINE_OUI` is not set), queries api.macvendors.com outside the
       cache lock for unseen globally-administered unicast OUIs and caches the result.
    Returns 'Unknown' if not identified.
    """
    if not mac_str:
        return "Unknown"

    # 1. FHRP / HA virtual gateway MACs take precedence over generic OUI labels
    fhrp_label = classify_fhrp_mac(mac_str)
    if fhrp_label:
        return fhrp_label

    prefix = get_oui_prefix(mac_str)
    if not prefix:
        return "Unknown"

    # 2. Prioritize built-in enterprise network dictionary (instant in-memory lookup)
    if prefix in COMMON_OUIS:
        return COMMON_OUIS[prefix]

    # 3. Check local IEEE file if already on disk
    if load_oui_file():
        if prefix in _loaded_ouis:
            return _loaded_ouis[prefix]

    # 4. Check persistent cache of previously queried OUIs
    with _oui_cache_lock:
        _load_online_cache()
        if prefix in _online_oui_cache:
            return _online_oui_cache[prefix]
        already_failed = prefix in _transient_failed_ouis

    # 5. Opt-in online lookup for unseen globally-administered unicast OUIs (I/O outside lock)
    if not already_failed and _is_online_lookup_enabled(online) and _is_globally_administered_unicast(prefix):
        vendor = _fetch_oui_online(prefix)
        with _oui_cache_lock:
            _load_online_cache()
            if prefix in _online_oui_cache:
                return _online_oui_cache[prefix]
            if vendor:
                _online_oui_cache[prefix] = vendor
                _save_online_cache()
                return vendor
            _transient_failed_ouis.add(prefix)

    return "Unknown"


# Convenient alias
lookup_oui = get_vendor

if __name__ == "__main__":
    test_macs = ["00:00:0c:12:34:56", "00-1B-17-00-11-22", "001d.2e33.4455", "24a4.3c11.2233", "11:22:33:44:55:66"]
    for mac in test_macs:
        print(f"MAC: {mac} -> Normalized: {normalize_mac(mac)} -> Vendor: {get_vendor(mac)}")

<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->

# MikroTik RouterOS Driver Specification

* **Driver Class**: [`MikroTikDriver`](../../net_docu_crawler/drivers/mikrotik.py)
* **Supported Platforms**: RouterOS v6, RouterOS v7, Cloud Hosted Router (CHR), RouterBOARD
* **Upstream Netmiko Device Type**: `mikrotik_routeros` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Official Documentation**: [MikroTik RouterOS CLI Reference](https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface)

---

## 1. Connection Mechanics & Pagination

MikroTik RouterOS uses a hierarchical command syntax. [Netmiko](https://github.com/ktbyers/netmiko) connects over SSH with `+ct511w4098h` terminal width/color suppression, and `without-paging` disables interactive pager pauses on long `print` outputs. Pre-auth SSH identification identifies the banner substring `ROSSSH`.

## 2. Read-Only RBAC Configuration

Create a dedicated read-only operator group and user with SSH login permitted (`ssh`, `read`, `test`) and all write/reboot/policy permissions denied:
```routeros
/user group add name=read-only policy=read,test,ssh,api,!local,!telnet,!ftp,!reboot,!write,!policy,!password,!web,!sniff,!sensitive
/user add name=crawler group=read-only password="<password>"
```

## 3. Discovered Data Mapping

| Data Element | RouterOS Command | Description |
| :--- | :--- | :--- |
| **System Info & Identity** | `/system identity print`<br>`/system resource print`<br>`/system routerboard print` | Extracts device identity, RouterOS version, hardware platform, and RouterBOARD serial number |
| **Hardware MAC & Interface States** | `/interface ethernet print detail without-paging`<br>`/interface print detail without-paging` | Extracts physical Ethernet & logical interface link states and chassis MAC addresses (bypassing hypervisor OUI traps) |
| **L3 Interfaces** | `/ip address print detail without-paging` | Extracts IPv4 addresses with CIDR masks and interface bindings |
| **Topology Neighbors** | `/ip neighbor print detail without-paging` | Extracts MNDP, CDP, and LLDP discovered neighbors |
| **Routing Table** | `/ip route print detail without-paging` | Extracts active dynamic, static, and default route next-hops |
| **ARP Table** | `/ip arp print detail without-paging` | Layer 3 ARP table with MAC addresses and interface names |
| **Optics & SFP Telemetry** | `/interface ethernet monitor [find where name~"sfp"] once` | Non-blocking single-shot SFP vendor, part number, serial, TX/RX dBm, and temperature |
| **Config Backup** | `/export compact` | Read-only compact configuration backup |

## 4. Platform Gotchas & Safety
* **Token Stripping**: RouterOS prints key-value tokens with surrounding quotes (e.g., `identity="Host"`). Net-Docu-Crawler automatically sanitizes quotes so hostnames and remote device identifiers match cross-vendor LLDP registries cleanly.
* **Hypervisor OUI Bypass**: CHR virtual machines running on Proxmox or ESXi emit virtual NIC prefixes (`BC:24:11` or `00:50:56`). Pre-auth SSH banner inspection (`ROSSSH`) cascades identification to Tier 2 to accurately detect MikroTik RouterOS.

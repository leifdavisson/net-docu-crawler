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
* **Upstream Netmiko Device Type**: `mikrotik_routeros`
* **Official Documentation**: [MikroTik RouterOS CLI Reference](https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface)

---

## 1. Connection Mechanics & Pagination

MikroTik RouterOS uses a hierarchical command syntax. Commands executed over non-interactive SSH or with `without-paging` execute without terminal pauses. Pre-auth SSH identification identifies the banner substring `ROSSSH`.

## 2. Read-Only RBAC Configuration

Create a dedicated read-only operator group and user for crawling:
```routeros
/user group add name=read-only policy=read,test,api,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!password,!web,!sniff,!sensitive
/user add name=crawler group=read-only password="<password>"
```

## 3. Discovered Data Mapping

| Data Element | RouterOS Command | Description |
| :--- | :--- | :--- |
| **System Info & Identity** | `/system identity print detail`<br>`/system resource print` | Extracts device identity, RouterOS version, and hardware platform |
| **L3 Interfaces** | `/ip address print detail` | Extracts IPv4 addresses with CIDR masks and interface bindings |
| **Physical Interface Stats** | `/interface print detail` | Extracts interface running states, MTUs, and MAC addresses |
| **Hardware MAC Address** | `/interface ethernet print detail` | Extracts physical chassis MAC address (bypassing hypervisor OUI traps) |
| **Topology Neighbors** | `/ip neighbor print detail` | Extracts MNDP, CDP, and LLDP discovered neighbors |
| **Routing Table** | `/ip route print detail` | Extracts active dynamic, static, and default route next-hops |
| **ARP Table** | `/ip arp print detail` | Layer 3 ARP table with MAC addresses and interface names |
| **Config Backup** | `/export compact` | Read-only compact configuration backup |

## 4. Platform Gotchas & Safety
* **Token Stripping**: RouterOS prints key-value tokens with surrounding quotes (e.g., `identity="Host"`). Net-Docu-Crawler automatically sanitizes quotes so hostnames and remote device identifiers match cross-vendor LLDP registries cleanly.
* **Hypervisor OUI Bypass**: CHR virtual machines running on Proxmox or ESXi emit virtual NIC prefixes (`BC:24:11` or `00:50:56`). Pre-auth SSH banner inspection (`ROSSSH`) cascades identification to Tier 2 to accurately detect MikroTik RouterOS.

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

# FRRouting (FRR) Driver Specification

* **Driver Class**: [`FRRDriver`](../../net_docu_crawler/drivers/frr.py)
* **Supported Platforms**: FRRouting 7.x, 8.x, 9.x, 10.x running on Linux (Debian, Ubuntu, Alpine), with safe read-only Linux host fallback when `vtysh` is absent
* **Upstream Netmiko Device Type**: `linux` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Official Documentation**: [FRRouting Official User Guide](https://docs.frrouting.org/)

---

## 1. Connection Mechanics & Transport

FRRouting runs as a modular routing daemon suite on top of the Linux kernel. Net-Docu-Crawler connects using a standard SSH shell session (`linux` [Netmiko](https://github.com/ktbyers/netmiko) driver) and leverages `vtysh` unified CLI and native Linux networking commands (`ip -j`).

## 2. Operator Access & RBAC

The discovery operator requires permission to execute `vtysh` and read interface/routing state:
```bash
# Add operator to frrvty group
sudo usermod -aG frrvty crawler
```

## 3. Discovered Data Mapping

| Data Element | Primary FRR Command | Plain-Linux Fallback (No `vtysh`) | Notes |
| :--- | :--- | :--- | :--- |
| **System Info & Version** | `hostname -s`, `vtysh -c 'show version'` | `hostname -s`, `cat /etc/os-release` | Extracts FRR daemon version or Linux distro release |
| **L3 & Physical Interfaces** | `vtysh -c 'show interface json'` | `ip -s -j link show`, `ip -j -4 addr show` | Native JSON interface inventory, MACs, counters, and CIDRs |
| **Topology Neighbors** | `lldpcli show neighbors -f json` | `lldpcli show neighbors -f json` | Discovered LLDP neighbors via `lldpd` |
| **Routing Table** | `vtysh -c 'show ip route json'` | `ip -j route show` | Consolidated kernel and FRR protocol routes |
| **ARP Table** | `ip -j neigh show` | `ip -j neigh show` | Layer 3 neighbor table with learned MACs |
| **Config Backup** | `vtysh -c 'show running-config'` | N/A | Integrated FRR daemon running configuration |

## 4. Platform Gotchas & Safety
* **vtysh Single Command Execution**: Executing `vtysh -c '<cmd>'` avoids entering an interactive VTY shell, eliminating prompt hang risks and ensuring strict read-only execution.

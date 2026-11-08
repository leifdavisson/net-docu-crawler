<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>

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

# Cisco Systems Driver Specification

[Open cisco.md](cisco.md)

* **Driver Class**: [`CiscoDriver`](../../net_docu_crawler/drivers/cisco.py)
* **Supported Platforms**: Cisco Catalyst (IOS/IOS-XE), Nexus (NX-OS), Service Provider (IOS-XR)
* **Upstream Netmiko Device Types**: `cisco_ios`, `cisco_nxos`, `cisco_xr`
* **Official Documentation**: [Cisco IOS / IOS-XE Command References](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html)

---

## 1. Connection Mechanics & Pagination

Cisco devices default to 24-line pagination on interactive VTY lines. Before executing discovery commands, the driver sends:
```cisco
terminal length 0
```
On NX-OS and IOS-XR, `terminal length 0` and `terminal width 511` are supported.

## 2. Minimum Required RBAC Privilege Level

The operator account requires read-only execution privilege (Privilege Level 15 or Level 1 with parser view access):
```cisco
privilege exec level 1 show running-config
privilege exec level 1 show cdp neighbors detail
privilege exec level 1 show lldp neighbors detail
privilege exec level 1 show ip interface brief
privilege exec level 1 show ip route
privilege exec level 1 show ip arp
privilege exec level 1 show mac address-table
privilege exec level 1 show inventory
```

## 3. Discovered Data Mapping

| Data Element | IOS / IOS-XE Command | NX-OS Command | IOS-XR Command |
| :--- | :--- | :--- | :--- |
| **System Info & Serial** | `show version`, `show inventory` | `show version`, `show inventory` | `show version`, `show inventory` |
| **L3 Interfaces** | `show ip interface brief` | `show ip interface brief` | `show ipv4 interface brief` |
| **Physical Interface Stats** | `show interfaces` | `show interface` | `show interfaces` |
| **Topology Neighbors** | `show cdp neighbors detail`<br>`show lldp neighbors detail` | `show cdp neighbors detail`<br>`show lldp neighbors detail` | `show cdp neighbors detail`<br>`show lldp neighbors detail` |
| **Routing Table** | `show ip route` | `show ip route` | `show route` |
| **ARP Table** | `show ip arp` | `show ip arp` | `show arp` |
| **MAC Address Table** | `show mac address-table` | `show mac address-table` | `show l2vpn forwarding bridge-domain ...` |
| **Running Config Backup** | `show running-config` | `show running-config` | `show running-config` |

## 4. Troubleshooting & Gotchas
* **Nexus Prompt Formatting**: NX-OS prompts may include VDC indicators (e.g., `switch(vdc-1)#`). Netmiko automatically handles VDC prompts if `cisco_nxos` is selected.
* **CDP Disabled**: If `no cdp run` is active, the driver falls back to `show lldp neighbors detail`. If both are disabled, Stage 2 ARP table harvesting is used to identify adjacent switches by management MAC OUI.

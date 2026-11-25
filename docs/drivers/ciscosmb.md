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

# Cisco Small Business Driver (`CiscoSMBDriver`)

- **Driver Class**: [`CiscoSMBDriver`](../../net_docu_crawler/drivers/ciscosmb.py)
- **Netmiko Device Type**: `cisco_s300` (SSH) / `cisco_s300_telnet` (Telnet) ([Netmiko](https://github.com/ktbyers/netmiko))
- **Supported Models**: CLI-capable Cisco Small Business managed switches (`SG250`, `SG300`, `SG350`, `SG500`, `CBS250`, `CBS350`)
- **Official Documentation**: [Cisco Small Business 300 Series Command Reference](https://www.cisco.com/c/en/us/support/switches/small-business-300-series-managed-switches/products-command-reference-list.html)

## Read-Only Operational Commands

| Telemetry Category | Read-Only Command |
| :--- | :--- |
| Pagination Disable | `terminal datadump` |
| System / Hostname / MAC | `show system` |
| Model / Serial Number | `show system id`, `show version` |
| L3 & Physical Interfaces | `show ip interface`, `show interfaces status` |
| L2 Trunk & LAG Telemetry | `show interfaces switchport`, `show interfaces port-channel` |
| Neighbors | `show lldp neighbors` |
| Routing & ARP | `show ip route`, `show arp` |
| Switching / STP / MACs | `show spanning-tree`, `show mac address-table` |
| PoE & Optics | `show power inline`, `show fiber-ports optical-transceiver` |
| Configuration Backup | `show running-config` |

> [!NOTE]
> Web-only / unmanaged Cisco Small Business models (`SG110`, `SG200`, `CBS110`) do not expose an SSH/Telnet CLI and are documented passively via LLDP, ARP/OUI, HTTP/TLS fingerprinting, and optional SNMP.

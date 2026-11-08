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

# Arista Networks Driver Specification

[Open arista.md](arista.md)

* **Driver Class**: [`AristaDriver`](../../net_docu_crawler/drivers/arista.py)
* **Supported Platforms**: Arista 7000-Series, vEOS, cEOS, Fixed & Modular Spine/Leaf Switches
* **Upstream Netmiko Device Type**: `arista_eos`
* **Official Documentation**: [Arista EOS Manual & CLI Documentation](https://www.arista.com/en/um-eos)

---

## 1. Connection Mechanics & Pagination

Arista EOS switches support disabling interactive pagination via:
```eos
terminal length 0
```
Furthermore, Arista EOS natively generates structured JSON across almost all operational show commands via the `| json` pipe, allowing deterministic, zero-regex parsing.

## 2. Privileged Exec & Read-Only RBAC

Arista EOS separates unprivileged exec (`>`) from privileged exec (`#`). The driver issues `conn.enable()` using the optional secret password if configured:
```eos
enable
```
Recommended read-only operator authorization:
```eos
username crawler role network-operator secret 0 <password>
```

## 3. Discovered Data Mapping

| Data Element | Primary Native JSON Command | Text Fallback |
| :--- | :--- | :--- |
| **System Info & Serial** | `show version \| json` | `show version` |
| **L3 Interfaces** | `show ip interface brief \| json` | `show ip interface brief` |
| **Physical Interface Stats** | `show interfaces status \| json` | `show interfaces status` |
| **Topology Neighbors** | `show lldp neighbors detail \| json` | `show lldp neighbors detail` |
| **Routing Table** | `show ip route \| json` | `show ip route` |
| **ARP Table** | `show ip arp \| json` | `show ip arp` |
| **MAC Address Table** | `show mac address-table \| json` | `show mac address-table` |
| **Optics & DOM Telemetry** | `show interfaces transceiver \| json` | `show interfaces transceiver` |
| **PoE Inline Wattage** | `show power inline \| json` | `show power inline` |
| **Running Config Backup** | `show running-config` | `show running-config` |

## 4. Platform Gotchas & Safety
* **JSON Pipeline Performance**: Passing `| json` dramatically reduces CPU load on the Arista control plane because the EOS internal Sysdb schema is serialized directly to JSON without string formatting.
* **Secret Escalation**: If privileged exec is required to read `show running-config`, ensure `secret` is populated in `credentials.json`.

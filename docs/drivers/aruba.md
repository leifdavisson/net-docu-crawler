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

# Aruba Networks / HPE Driver Specification

[Open aruba.md](aruba.md)

* **Driver Class**: [`ArubaDriver`](../../net_docu_crawler/drivers/aruba.py)
* **Supported Platforms**: Aruba Instant AP (IAP clusters), Mobility Controllers, ArubaOS-CX switches, legacy ProCurve switches
* **Upstream Netmiko Device Types**: `aruba_os` (IAP/Controllers), `aruba_osswitch` (CX/ProCurve)
* **Official Documentation**: [ArubaOS-CX CLI Reference Guide](https://www.arubanetworks.com/techdocs/AOS-CX/)

---

## 1. Connection Mechanics & Pagination

Aruba switches and APs use the following pagination disable commands:
* **AOS-CX & ProCurve**: `no page`
* **Aruba Instant AP (IAP)**: Does not paginate short commands; long diagnostics support `no page`.

## 2. Instant AP (IAP) Cluster Discovery

Aruba Instant APs operate as a cooperative virtual cluster where one AP acts as the Virtual Controller (VC / Master):
* The driver executes `show aps` to discover all cluster member APs, their radio channels, operational status, and serial numbers.
* LLDP neighbor information is collected via:
  ```text
  show ap debug lldp info
  ```
  This identifies the physical switch chassis and port powering each AP via PoE.
* Connected wireless client associations and SSIDs are inventoried via:
  ```text
  show clients
  show network
  ```

## 3. Command Mapping

| Data Element | Aruba Instant AP (IAP) | ArubaOS-CX Switch |
| :--- | :--- | :--- |
| **System Info & Serial** | `show version`, `show aps` | `show system`, `show version` |
| **Interfaces** | Bridge interface (`br0`) | `show interface brief` |
| **Topology Neighbors** | `show ap debug lldp info` | `show lldp info remote-device detail` |
| **ARP Table** | `show arp` | `show arp` |
| **Client & WLAN Data** | `show clients`, `show network` | N/A (Switch Persona) |
| **Configuration Backup** | `show running-config` | `show running-config` |

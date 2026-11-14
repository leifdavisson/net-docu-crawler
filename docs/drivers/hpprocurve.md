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

# HP ProCurve / ArubaOS-S Driver Specification

Driver Class: [`HPProCurveDriver`](../../net_docu_crawler/drivers/hpprocurve.py)  
Official Documentation: [ArubaOS-S 16.10 Management and Configuration Guide](https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm)  
Supported Hardware: HP ProCurve 2500, 2600, 2800, 2900, 2910, 2920, 2930, 3500yl, 3800, 5400zl/5400R series switches running Provision / ArubaOS-S 14.x, 15.x, and 16.x.

---

## 1. Zero-Blast Read-Only Telemetry Commands

| Audit Category | Executed Command | Description |
| :--- | :--- | :--- |
| **System Version & Chassis** | `show system`<br>`show modules`<br>`show version` | Extracts system hostname, software revision (e.g. `WB.16.10.0025`), serial number, base chassis MAC address, and model. |
| **Layer 3 Interfaces & SVIs** | `show ip` | Parses active IP addresses, CIDR subnet masks, and VLAN associations. |
| **Physical Interface Telemetry** | `show interfaces brief`<br>`show name` | Gathers link up/down operational status, speed, duplex, and port description names. |
| **Layer 2 Discovery (LLDP & CDP)** | `show lldp info remote-device`<br>`show cdp neighbor detail` | Deterministically maps adjacent switches, routers, and wireless APs across physical ports. |
| **Routing Table** | `show ip route` | Discovers static, connected, and default gateway routes (`0.0.0.0/0`). |
| **ARP & MAC Table** | `show arp`<br>`show mac-address` | Extracts connected IP-to-MAC bindings and forwarding database entries. |
| **Spanning Tree (STP)** | `show spanning-tree` | Determines spanning tree enable state, root bridge priority, and root MAC address. |
| **Configuration Backup** | `show running-config` (fallback `show config`) | Captures non-destructive configuration snapshot without altering flash memory. |

---

## 2. Transport & Legacy SSH Fallback Mechanics

* **Netmiko Device Type**: `hp_procurve`
* **Paging Suppression**: `no page` (universally supported across Provision / ArubaOS-S versions 11.x through 16.10).
* **Legacy KEX / Cipher Resilience**:
  * Older Provision / ArubaOS-S switches (versions 14.x and early 15.x) implement embedded SSH servers (e.g. Mocana SSH) supporting only legacy key exchange algorithms (`diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`) and host key algorithms (`ssh-rsa`).
  * Modern [Paramiko](https://www.paramiko.org/) and `cryptography` libraries disable SHA-1 and 1024-bit DH groups by default.
  * `HPProCurveDriver` connects via `BaseDriver.safe_netmiko_connect()`, which automatically catches `IncompatiblePeer` negotiation exceptions and immediately reconnects with legacy algorithm allowances (`disabled_algorithms=dict()`, `disable_sha2_fix=False`, `ssh_strict=False`).

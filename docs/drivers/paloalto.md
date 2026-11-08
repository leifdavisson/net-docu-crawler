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

# Palo Alto Networks Driver Specification

[Open paloalto.md](paloalto.md)

* **Driver Class**: [`PaloAltoDriver`](../../net_docu_crawler/drivers/paloalto.py)
* **Supported Platforms**: PA-Series Firewalls (PA-220, PA-400, PA-800, PA-3200, PA-5200, VM-Series)
* **Upstream Netmiko Device Type**: `paloalto_panos`
* **Device Persona**: `firewall`
* **Official Documentation**: [Palo Alto Networks PAN-OS CLI Reference](https://docs.paloaltonetworks.com/pan-os)

---

## 1. Connection Mechanics & Pagination

PAN-OS uses the command:
```panos
set cli pager off
```
Netmiko applies this command upon connecting with `device_type="paloalto_panos"`. The driver also re-asserts `set cli pager off` prior to executing config queries.

## 2. Firewall Persona Considerations

Palo Alto firewalls operate primarily as Layer 3 routers with Security Zones and Virtual Systems:
* **No STP / MAC Tables**: Firewalls do not maintain traditional switchport spanning-tree tables or Layer 2 bridge domains on routed ports.
* **Gateway ARP Harvesting**: Because firewalls act as default gateways for corporate VLANs and DMZs, their ARP tables (`show arp all`) are rich sources of downstream infrastructure discovery.
* **LLDP Protocol**: When enabled, `show lldp neighbors all` surfaces adjacent core and distribution switches.

## 3. Discovered Data Mapping

| Data Element | PAN-OS CLI Command | Notes |
| :--- | :--- | :--- |
| **System Info & Serial** | `show system info` | Hostname, model, chassis serial, PAN-OS software version |
| **L3 Interfaces** | `show interface all` | Ethernet, VLAN, Loopback, and Tunnel interfaces |
| **Topology Neighbors** | `show lldp neighbors all` | Adjacent switches advertising LLDP |
| **Routing Table** | `show routing route` | Active routing table across all Virtual Routers |
| **ARP Table** | `show arp all` | Gateway ARP cache with IP-to-MAC bindings |
| **Configuration Backup** | `show config running` | Complete firewall XML/CLI configuration |

## 4. Minimum Read-Only Admin Role

Create a custom admin role with read-only CLI privileges:
```panos
set mgt-config users netcrawler permissions role-based custom superreader
```

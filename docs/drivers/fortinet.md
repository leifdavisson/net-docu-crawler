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

# Fortinet FortiOS Driver Specification

[Open fortinet.md](fortinet.md)

* **Driver Class**: [`FortinetDriver`](../../net_docu_crawler/drivers/fortinet.py)
* **Supported Platforms**: FortiGate Firewalls (FortiGate 40F through 3000F, VM)
* **Upstream Netmiko Device Type**: `fortinet`
* **Device Persona**: `firewall`
* **Official Documentation**: [Fortinet FortiOS CLI Reference](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference)

---

## 1. Connection Mechanics & Pagination

FortiOS controls terminal pagination through system console configuration:
```text
config system console
    set output standard
end
```
Setting `output standard` instructs FortiOS to stream command output continuously without stopping at page breaks. Netmiko executes this automatically on session startup.

## 2. Firewall Persona & Gateway Role

In enterprise campus and branch architectures, FortiGates frequently serve as:
* **The Layer 3 Gateway & Inter-VLAN Router**: Running `get system arp` produces the comprehensive list of all active network endpoints, switches, and access points.
* **VDOM Support**: FortiGates configured with Virtual Domains (VDOMs) present prompts such as `FG-Core (root) #`. The driver regex accounts for VDOM prompt decoration.
* **FortiLink Integration**: FortiSwitches and FortiAPs managed via FortiLink can be surfaced via FortiOS topology queries.

## 3. Discovered Data Mapping

| Data Element | FortiOS CLI Command | Notes |
| :--- | :--- | :--- |
| **System Info & Serial** | `get system status` | Hostname, model, chassis serial, firmware version |
| **L3 Interfaces** | `show system interface` | Physical ports, VLAN sub-interfaces, and IP addresses |
| **Topology Neighbors** | `diagnose snmp sysinfo lldp neighbor` | LLDP neighbor chassis and port IDs |
| **Routing Table** | `get router info routing-table all` | Active RIB table (Static, OSPF, BGP, Connected) |
| **ARP Table** | `get system arp` | IP-to-MAC resolution table across all interfaces |
| **Configuration Backup** | `show full-configuration` | Complete declarative FortiOS configuration |

## 4. Minimum Read-Only Admin Profile

In FortiOS, create a read-only admin profile:
```text
config system accprofile
    edit "ReadOnlyAuditor"
        set comments "Automated Discovery Read-Only"
        set secfabread enable
        set ftviewgrp read
        set authgrp read
        set sysgrp read
        set netgrp read
        set loggrp read
        set vpngrp read
        set utmgrp read
        set wanoptgrp read
        set wifi read
    next
end
```

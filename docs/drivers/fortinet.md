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

# Fortinet FortiOS Driver Specification

* **Driver Class**: [`FortinetDriver`](../../net_docu_crawler/drivers/fortinet.py)
* **Supported Platforms**: FortiGate Firewalls (FortiGate 40F through 3000F, VM)
* **Upstream Transport**: Strictly read-only `ReadOnlyFortinetSSH` subclass over [Netmiko](https://github.com/ktbyers/netmiko) (`fortinet`) & [Paramiko](https://www.paramiko.org/)
* **Device Persona**: `firewall`
* **Official Documentation**: [Fortinet FortiOS CLI Reference](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference)

---

## 1. Zero-Blast-Radius Connection Mechanics & Read-Only Paging

> [!IMPORTANT]
> **No Configuration-Mode Paging Writes**: Upstream Netmiko's default `FortinetSSH` enters global configuration mode to modify console pagination and reverts it on disconnect, which violates **Zero Blast Radius**, triggers SIEM/FortiManager config-change events, and fails under read-only admin profiles (`sysgrp read`).

`FortinetDriver` avoids all configuration-mode commands by using **`ReadOnlyFortinetSSH`**:
1. **No Config Mode**: Overrides `session_preparation()`, `disable_paging()`, and `cleanup()` so zero configuration commands are ever sent on connect or disconnect, and hard-blocks write APIs (`config_mode`, `send_config_set`, `send_config_from_file`, `save_config`).
2. **Bounded Read-Only `--More--` Pager Drainer**: Streams multi-page outputs (such as `show full-configuration`) by sending non-mutating space (`" "`) keystrokes on `--More--` prompts, stripping terminal overwrite artifacts cleanly, and enforcing per-page timeouts plus a hard page-count ceiling so VTY sessions never hang.
3. **SSH Compatibility**: Delegates KEX/cipher negotiation to the 3-stage SSH compatibility ladder in [`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py) without stripping modern KEX algorithms, and disables Telnet (`supports_telnet = False`).

## 2. Firewall Persona & Gateway Role

In enterprise campus and branch architectures, FortiGates frequently serve as:
* **The Layer 3 Gateway & Inter-VLAN Router**: Running `get system arp` produces the comprehensive list of all active network endpoints, switches, and access points.
* **VDOM Support**: FortiGates configured with Virtual Domains (VDOMs) present prompts such as `FG-Core (root) #`. The driver prompt handling accounts for VDOM prompt decoration.
* **FortiLink Integration**: FortiSwitches and FortiAPs managed via FortiLink can be surfaced via FortiOS topology queries.

## 3. Discovered Data Mapping

| Data Element | FortiOS CLI Command | Notes |
| :--- | :--- | :--- |
| **System Info & Serial** | `get system status` | Hostname, model, chassis serial, firmware version |
| **L3 Interfaces** | `show system interface` | Physical ports, VLAN sub-interfaces (including names with spaces, `set alias`, `set vlanid`), and IP addresses; filters pseudo-interfaces (`naf.*`, `l2t.*`, `ssl.*`, `vsw.*`, `npu*`) |
| **Topology Neighbors** | `diagnose snmp sysinfo lldp neighbor` (fallbacks: `diagnose lldp neighbor list`, `get switch lldp neighbors-summary`) | LLDP neighbor chassis and port IDs |
| **Routing Table** | `get router info routing-table all` | Active RIB table (Static, OSPF, BGP, Connected) |
| **ARP Table** | `get system arp` | IP-to-MAC resolution table across all interfaces |
| **Optics & Transceivers** | `get system interface transceiver` | SFP/SFP+/QSFP vendor, part number, and serial inventory |
| **Configuration Backup & DHCP** | `show full-configuration` | Complete declarative FortiOS config including `config system dhcp server` pools & `reserved-address` entries |

## 4. Minimum Read-Only Admin Profile

In FortiOS, create a strictly read-only admin profile (no `read-write` console privileges required):
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

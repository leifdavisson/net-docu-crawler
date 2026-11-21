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

# Cisco Systems Driver Specification

* **Driver Class**: [`CiscoDriver`](../../net_docu_crawler/drivers/cisco.py)
* **Supported Platforms**: Cisco Catalyst (IOS/IOS-XE), Nexus (NX-OS), Service Provider (IOS-XR)
* **Upstream Netmiko Device Types**: `cisco_ios`, `cisco_nxos`, `cisco_xr` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Official Documentation**: [Cisco IOS & NX-OS Documentation](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html)

---

## 1. Connection Mechanics, SSH Compatibility & Pagination

Cisco devices default to 24-line pagination on interactive VTY lines. Before executing discovery commands, the driver sends:
```cisco
terminal length 0
```
On NX-OS and IOS-XR, `terminal length 0` and `terminal width 511` are supported.

### 3-Stage SSH Compatibility Ladder (`ssh_compat.py`)

`CiscoDriver` connects via `BaseDriver.safe_netmiko_connect()`, which delegates to [`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py) ([Paramiko](https://www.paramiko.org/), [Netmiko](https://github.com/ktbyers/netmiko), [pyca/cryptography](https://cryptography.io/)):
1. **Stage 1 (Standard + Hardened KEX)**: Registers RFC 8731 `curve25519-sha256` and RFC 3526 `diffie-hellman-group18-sha512` prior to handshake for hardened IOS-XE / NX-OS peers.
2. **Stage 2 (Legacy KEX & `LegacyDSSKey` / `ssh-dss`)**: On `IncompatiblePeer` or negotiation errors, registers read-only `LegacyDSSKey` (`ssh-dss`) and legacy KEX/CBC ciphers/HMAC-SHA1 preferences, retrying with `disabled_algorithms={}`, `disable_sha2_fix=False`, and `ssh_strict=False` (keeping `rsa-sha2-256`/`512` intact).
3. **Stage 3 (`disable_sha2_fix=True`)**: If Stage 2 still fails negotiation, retries with `disable_sha2_fix=True` for legacy IOS 12.x/15.x peers supporting only `ssh-rsa` SHA-1 host keys.

## 2. Minimum Required RBAC Privilege Level

The operator account requires read-only execution privilege (Privilege Level 15 or Level 1 with parser view access):
```cisco
privilege exec level 1 show running-config
privilege exec level 1 show cdp neighbors detail
privilege exec level 1 show lldp neighbors detail
privilege exec level 1 show ip interface brief
privilege exec level 1 show interfaces trunk
privilege exec level 1 show etherchannel summary
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
| **L2 Trunk & LAG Telemetry** | `show interfaces trunk`<br>`show etherchannel summary` | `show interfaces trunk`<br>`show etherchannel summary` | N/A |
| **Topology Neighbors** | `show cdp neighbors detail`<br>`show lldp neighbors detail` | `show cdp neighbors detail`<br>`show lldp neighbors detail` | `show cdp neighbors detail`<br>`show lldp neighbors detail` |
| **Routing Table** | `show ip route` | `show ip route` | `show route` |
| **ARP Table** | `show ip arp` | `show ip arp` | `show arp` |
| **MAC Address Table** | `show mac address-table` | `show mac address-table` | `show l2vpn forwarding bridge-domain ...` |
| **Running Config Backup** | `show running-config` | `show running-config` | `show running-config` |

### Trunk VLAN Mismatch & L2 Intent Extraction

For Issue #2 Trunk VLAN Mismatch Detection ([`net_docu_crawler/trunk_audit.py`](../../net_docu_crawler/trunk_audit.py)), `CiscoDriver.get_l2_operational()` and [`migration_parsers.py`](../../net_docu_crawler/migration_parsers.py) combine strictly read-only `show interfaces trunk` telemetry with `show running-config` stanzas:
- Parses operational trunk `mode`, `encapsulation` (`dot1q`, `isl`, `negotiate`), `native_vlan`, `allowed_vlans`, and forwarding/active VLANs (`Vlans in spanning tree forwarding state and not pruned`) into `trunk_active_vlans` and `oper_mode="trunk"`.
- Concatenates multi-line `switchport trunk allowed vlan add <spec>` lines without overwriting earlier VLAN ranges.
- Detects `switchport mode dynamic auto|desirable` (`TRK-007`), `switchport mode dot1q-tunnel` (`INFO_QINQ_BOUNDARY`), global `vlan dot1q tag native` / per-port `switchport trunk native vlan tag` (`native_vlan_tagged`), and synthesizes L3 dot1Q subinterfaces (`interface Gi0/0.10` with `encapsulation dot1Q <id> [native]`) onto the parent port (`is_subinterface_bundle=True`).

## 4. Troubleshooting & Gotchas
* **Nexus Prompt Formatting**: NX-OS prompts may include VDC indicators (e.g., `switch(vdc-1)#`). Netmiko automatically handles VDC prompts if `cisco_nxos` is selected.
* **L2 Switch SVIs & Default Gateway**: When `ip routing` is disabled on L2 switches, `CiscoDriver` backfills `/prefix` masks from `show interfaces` (`Internet address is X.X.X.X/Y`) into `l3_interfaces` and maps `Default gateway is <ip>` from `show ip route` to `0.0.0.0/0`.
* **CDP Disabled**: If `no cdp run` is active, the driver falls back to `show lldp neighbors detail`. If both are disabled, Stage 2 ARP table harvesting is used to identify adjacent switches by management MAC OUI.

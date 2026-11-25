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

# Juniper Networks Driver Specification

* **Driver Class**: [`JuniperDriver`](../../net_docu_crawler/drivers/juniper.py)
* **Supported Platforms**: Juniper EX Series (EX2200, EX3300, EX4300), QFX Series, MX Series, SRX Branch Gateways
* **Upstream Netmiko Device Type**: `juniper_junos` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Official Documentation**: [Juniper Junos Documentation](https://www.juniper.net/documentation/product/us/en/junos-os/) & [JunOS Automation & Scripting](https://www.juniper.net/documentation/us/en/software/junos/automation-scripting/)

---

## 1. Connection Mechanics, SSH Compatibility & Pagination

JunOS does not recognize Cisco's `terminal length 0`. Sending it triggers a `% Syntax error`. Instead, JunOS requires:
```junos
set cli screen-length 0
set cli screen-width 0
```
[Netmiko](https://github.com/ktbyers/netmiko) applies this automatically when connecting with `device_type="juniper_junos"`.

### 3-Stage SSH Compatibility Ladder (`ssh_compat.py`)

`JuniperDriver` connects via `BaseDriver.safe_netmiko_connect()` -> [`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py) ([Paramiko](https://www.paramiko.org/), [pyca/cryptography](https://cryptography.io/)):
1. **Stage 1 (Standard + Hardened KEX)**: Pre-registers RFC 8731 `curve25519-sha256` and RFC 3526 `diffie-hellman-group18-sha512` for hardened Junos SSH daemons.
2. **Stage 2 (Legacy KEX & `LegacyDSSKey` / `ssh-dss`)**: On `IncompatiblePeer` or KEX/host-key negotiation failure (e.g., legacy Junos 9.x–12.x EX/SRX switches), registers read-only `LegacyDSSKey` (`ssh-dss`) and legacy KEX/CBC/HMAC-SHA1 algorithms while keeping `disable_sha2_fix=False`.
3. **Stage 3 (`disable_sha2_fix=True`)**: If Stage 2 fails negotiation, retries with `disable_sha2_fix=True` for `ssh-rsa` SHA-1-only peers.

## 2. Native JSON Architecture (`| display json`) & L2 Trunk Telemetry

JunOS natively supports serialized JSON output across all operational commands. [`JuniperDriver`](../../net_docu_crawler/drivers/juniper.py) takes advantage of this for deterministic parsing:

```junos
show version | display json
show chassis hardware | display json
show chassis mac-addresses
show interfaces terse | display json
show interfaces
show lldp neighbors detail | display json
show ethernet-switching interfaces | display json
show lacp interfaces | display json
show spanning-tree bridge | display json
show spanning-tree interface | display json
show dot1x interface | display json
show route | display json
show arp no-resolve | display json
show poe controller | display json
show poe interface | display json
show ethernet-switching table | display json
show interfaces diagnostics optics | display json
show configuration | display set
```

If a legacy JunOS release (e.g., JunOS < 14.2) does not support JSON serialization on a specific command, the driver automatically catches the exception and falls back to regular expression parsing (including text fallback for `show ethernet-switching interfaces`).

### Trunk VLAN Mismatch Normalization (`port_profiles` & `trunk_audit.py`)
- `show ethernet-switching interfaces` (`| display json` and text fallback) populates `oper_mode` (`"trunk"` / `"access"`) and `trunk_active_vlans`, while `show lacp interfaces` resolves member interfaces to `ae*` aggregate bundles.
- In [`migration_parsers.py`](../../net_docu_crawler/migration_parsers.py), Junos trunk interfaces without `native-vlan-id` set `native_vlan="none"` and `native_vlan_tagged=True` (since Junos drops or treats untagged ingress differently unless `native-vlan-id` is configured); interfaces with `native-vlan-id <id>` record `native_vlan=<id>` and `native_vlan_tagged=False`.
- L3 `vlan-tagging` subinterface units (`set interfaces ge-0/0/1 unit 10 vlan-id 10`) are synthesized onto the parent port with `is_subinterface_bundle=True` so [Cisco](cisco.md) dot1Q subinterface trunks and Junos `vlan-tagging` uplinks compare accurately in [`trunk_audit.py`](../../net_docu_crawler/trunk_audit.py).

## 3. The LLDP Neighbor IP Challenge & ARP Resolution

On Juniper switches, `show lldp neighbors detail` frequently returns the remote switch's chassis MAC address or port description, but may omit the neighbor's IPv4 management address if the neighbor does not advertise the optional Management Address TLV.

To resolve this without manual operator intervention:
1. The driver extracts the remote chassis MAC address from LLDP.
2. The [`DeviceRegistry`](../../net_docu_crawler/topology_resolver.py) cross-references this MAC address against the harvested **Global ARP Cache** collected from the core router or firewall.
3. Once matched, the neighbor's IPv4 management address is automatically populated, allowing the crawler to continue its Breadth-First Search (BFS) graph traversal.

## 4. Legacy Junos 9.x–13.x Compatibility Notes

Junos releases prior to **14.2** (including **Junos 9.x** on EX3200/EX4200/EX2200) do not support `| display json`. [`JuniperDriver`](../../net_docu_crawler/drivers/juniper.py) automatically falls back to standard CLI text parsing for:
- `show version` (matches both `Junos: <ver>` and `JUNOS Base OS boot [<ver>]`)
- `show chassis hardware` & `show chassis mac-addresses`
- `show interfaces terse` (including legacy `vlan.X` SVIs prior to ELS `irb.X`)
- `show lldp neighbors detail` (including APs without `System name`, resolved via `Chassis id` + [`oui_lookup.py`](../../oui_lookup.py))
- `show spanning-tree bridge` (`Root ID` vs `Bridge ID` comparison)
- `show route table inet.0` and `show arp no-resolve`
- `show poe controller`, `show poe interface`, `show ethernet-switching table`, and `show configuration | display set`

> [!TIP]
> Avoid using the `root` account for automated crawls on Junos 9.x—`root` drops into the FreeBSD `csh` shell (`root@switch%`) rather than the operational `>` CLI. Use a dedicated read-only user class as shown below.

## 5. Minimum Read-Only JunOS User Class

```junos
set system login class read-only-auditor permissions [ view view-configuration ]
set system login user netcrawler class read-only-auditor authentication plain-text-password
```

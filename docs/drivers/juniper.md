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

# Juniper Networks Driver Specification

* **Driver Class**: [`JuniperDriver`](../../net_docu_crawler/drivers/juniper.py)
* **Supported Platforms**: Juniper EX Series (EX2200, EX3300, EX4300), QFX Series, MX Series, SRX Branch Gateways
* **Upstream Netmiko Device Type**: `juniper_junos`
* **Official Documentation**: [Juniper JunOS Automation & Scripting](https://www.juniper.net/documentation/us/en/software/junos/automation-scripting/)

---

## 1. Connection Mechanics & Pagination

JunOS does not recognize Cisco's `terminal length 0`. Sending it triggers a `% Syntax error`. Instead, JunOS requires:
```junos
set cli screen-length 0
set cli screen-width 0
```
Netmiko applies this automatically when connecting with `device_type="juniper_junos"`.

## 2. Native JSON Architecture (`| display json`)

JunOS natively supports serialized JSON output across all operational commands. [`JuniperDriver`](../../net_docu_crawler/drivers/juniper.py) takes advantage of this for 100% deterministic parsing:

```junos
show version | display json
show chassis hardware | display json
show interfaces terse | display json
show lldp neighbors detail | display json
show route | display json
show arp no-resolve | display json
show ethernet-switching table | display json
```

If a legacy JunOS release (e.g., JunOS < 12.x) does not support JSON serialization on a specific command, the driver automatically catches the exception and falls back to regular expression parsing.

## 3. The LLDP Neighbor IP Challenge & ARP Resolution

On Juniper switches, `show lldp neighbors detail` frequently returns the remote switch's chassis MAC address or port description, but may omit the neighbor's IPv4 management address if the neighbor does not advertise the optional Management Address TLV.

To resolve this without manual operator intervention:
1. The driver extracts the remote chassis MAC address from LLDP.
2. The [`DeviceRegistry`](../../net_docu_crawler/topology_resolver.py) cross-references this MAC address against the harvested **Global ARP Cache** collected from the core router or firewall.
3. Once matched, the neighbor's IPv4 management address is automatically populated, allowing the crawler to continue its Breadth-First Search (BFS) graph traversal.

## 4. Minimum Read-Only JunOS User Class

```junos
set system login class read-only-auditor permissions [ view view-configuration ]
set system login user netcrawler class read-only-auditor authentication plain-text-password
```

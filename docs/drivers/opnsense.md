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

# OPNsense Driver Documentation

## Overview
The **OPNsense Driver** ([`OPNsenseDriver`](../../net_docu_crawler/drivers/opnsense.py)) enables `Net-Docu-Crawler` to safely document and map [OPNsense](https://opnsense.org/) perimeter security firewalls, multi-WAN edge routers, and VPN gateways running on [FreeBSD](https://www.freebsd.org/).

* **Driver Class**: [`OPNsenseDriver`](../../net_docu_crawler/drivers/opnsense.py)
* **Official Project Homepage**: [https://opnsense.org/](https://opnsense.org/)
* **Official Documentation**: [https://docs.opnsense.org/](https://docs.opnsense.org/)
* **GitHub Repository**: [https://github.com/opnsense](https://github.com/opnsense)
* **Underlying SSH Engine**: [Paramiko](https://www.paramiko.org/) (`exec_command` via [`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py))

---

## Zero-Blast-Radius Architecture
OPNsense console logins present an interactive administrative menu (`0) Logout ... 8) Shell`). Interactive PTY sessions can trap automated scripts in menu loops.

To enforce strict **Zero-Blast-Radius** isolation:
1. **Non-Interactive Execution**: `OPNsenseDriver` establishes direct SSH command execution channels via [Paramiko](https://www.paramiko.org/), executing commands non-interactively without allocating a PTY or triggering the `/usr/local/etc/rc.initial` console menu.
2. **Read-Only Safety**: All discovery probes are strictly non-mutating informational commands (`ifconfig -a`, `netstat -rnW -f inet`, `arp -an`, `kenv`, `cat /conf/config.xml`).
3. **Hardware & VM Support**: Compatible with physical appliances (DEC series), custom bare-metal servers, and virtual machines (KVM, Proxmox, VMware ESXi).

---

## Discovered Telemetry & Commands

| Subsystem | Command | Parsed Attributes |
| :--- | :--- | :--- |
| **System Info** | `hostname`, `opnsense-version`, `kenv smbios.system.product 2>/dev/null`, `kenv smbios.system.serial 2>/dev/null` | FQDN, OPNsense release, hardware model, and SMBIOS chassis serial (rejecting placeholder VM strings). |
| **Interfaces** | `ifconfig -a` | Physical ports (`vtnetX`, `igbX`), 802.1Q SVIs (`vtnet0_vlan10`), status (UP/DOWN), MAC addresses, IPv4/CIDR prefixes, description tags; filters pseudo-interfaces (`lo*`, `enc*`, `pflog*`, `pfsync*`). |
| **Neighbors** | `lldpctl -f json 2>/dev/null` | LLDP neighbor topology if the `os-lldpd` plugin is active. |
| **Routing** | `netstat -rnW -f inet` *(fallback: `netstat -rn -f inet`)* | Active routing table, default gateways, connected subnets, static route flags (restoring untruncated `Netif` names). |
| **ARP Table** | `arp -an` | Active ARP entries mapped with IEEE OUI manufacturer resolution via [`oui_lookup.py`](../../oui_lookup.py). |
| **Configuration** | `cat /conf/config.xml` | Authoritative OPNsense XML configuration backup (firewall rules, NAT, aliases, DHCP pools). |

---

## Configuration & Credentials

Add an entry for OPNsense in `credentials.json`:
```json
{
  "name": "OPNsense-Core-Gateway",
  "vendor": "opnsense",
  "username": "root",
  "password": "YOUR_ROOT_PASSWORD",
  "secret": ""
}
```

> [!NOTE]
> Ensure SSH is enabled under **System > Settings > Administration > Secure Shell** in the OPNsense WebGUI. Root login via password or SSH public key is supported.

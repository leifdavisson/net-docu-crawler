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

# Aruba Networks / HPE Driver Specification

* **Driver Class**: [`ArubaDriver`](../../net_docu_crawler/drivers/aruba.py)
* **Supported Platforms**: Aruba Instant AP (IAP clusters), Mobility Controllers, ArubaOS-CX (AOS-CX) switches
* **Upstream Netmiko Device Types**: `aruba_os` (IAP/Controllers), AOS-CX CLI ([Netmiko](https://github.com/ktbyers/netmiko))
* **Official Documentation**: [HPE Aruba AOS-CX Documentation](https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm) & [Aruba Instant Documentation](https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm)

---

## 1. Connection Mechanics, SSH Compatibility & Pagination

Aruba switches and APs use the following pagination disable commands:
* **AOS-CX**: `no page`
* **Aruba Instant AP (IAP)**: Does not paginate short commands; long diagnostics support `no page`.

### 3-Stage SSH Compatibility Ladder (`ssh_compat.py`)

`ArubaDriver` connects via `BaseDriver.safe_netmiko_connect()` -> [`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py) ([Paramiko](https://www.paramiko.org/), [pyca/cryptography](https://cryptography.io/)):
1. **Stage 1 (Standard + Hardened KEX)**: Pre-registers RFC 8731 `curve25519-sha256` and RFC 3526 `diffie-hellman-group18-sha512`.
2. **Stage 2 (Legacy KEX & `LegacyDSSKey` / `ssh-dss`)**: On SSH negotiation failure, registers read-only `LegacyDSSKey` (`ssh-dss`) and legacy KEX/CBC/HMAC-SHA1 algorithms while retaining `disable_sha2_fix=False`.
3. **Stage 3 (`disable_sha2_fix=True`)**: Falls back to `disable_sha2_fix=True` for legacy `ssh-rsa` SHA-1-only peers.

## 2. Persona Auto-Detection: IAP Cluster vs. AOS-CX Switch

- **AOS-CX Switch Detection**: When `show version` reports `ArubaOS-CX` or `AOS-CX`, `ArubaDriver` sets `device_persona="switch"`, `device_type="switch"`, and `os_type="aruba_aoscx"`.
- **Instant AP (IAP) Clusters**: One AP acts as the Virtual Controller (VC / Master):
  * `show aps` discovers all cluster member APs, radio channels, operational status, and serial numbers.
  * `show ap debug lldp info` identifies the physical switch chassis and port powering each AP via PoE.
  * `show clients` and `show network` inventory wireless associations and SSIDs.

## 3. Command Mapping

| Data Element | Aruba Instant AP (IAP) | ArubaOS-CX Switch |
| :--- | :--- | :--- |
| **System Info & Serial** | `show version`, `show aps` | `show system`, `show version` |
| **Interfaces** | Bridge interface (`br0`) | `show interface brief` |
| **L2 Trunk & LAG Telemetry** | Graceful no-op (AP Persona) | `show interface trunk`<br>`show lacp interfaces` |
| **Topology Neighbors** | `show ap debug lldp info` | `show lldp info remote-device detail` |
| **ARP Table** | `show arp` | `show arp` |
| **Client & WLAN Data** | `show clients`, `show network` | N/A (Switch Persona) |
| **Configuration Backup** | `show running-config` | `show running-config` |

### AOS-CX Trunk Configuration & Operational Parsing
For Issue #2 Trunk VLAN Mismatch Detection ([`net_docu_crawler/trunk_audit.py`](../../net_docu_crawler/trunk_audit.py)), [`migration_parsers.py`](../../net_docu_crawler/migration_parsers.py) parses AOS-CX interface stanzas (`vlan trunk native <id>`, `vlan trunk native tag`, `vlan trunk allowed <spec>`, `vlan access <id>`, `lag <id>`) and `ArubaDriver.get_l2_operational()` harvests operational trunk VLANs and LACP LAG memberships via `show interface trunk` and `show lacp interfaces`.

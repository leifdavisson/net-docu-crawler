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

# HP ProCurve / ArubaOS-S Driver Specification

* **Driver Class**: [`HPProCurveDriver`](../../net_docu_crawler/drivers/hpprocurve.py)
* **Official Documentation**: [ArubaOS-S 16.10 Management and Configuration Guide](https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm)
* **Upstream Netmiko Device Type**: `hp_procurve` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Supported Hardware**: HP ProCurve 2500, 2600, 2800, 2900, 2910, 2920, 2930, 3500yl, 3800, 5400zl/5400R series switches running Provision / ArubaOS-S 14.x, 15.x, and 16.x.

---

## 1. Zero-Blast Read-Only Telemetry Commands

| Audit Category | Executed Command | Description |
| :--- | :--- | :--- |
| **System Version & Chassis** | `show system`<br>`show modules` | Extracts system hostname, software revision (e.g. `WB.16.10.0025`), serial number, base chassis MAC address, and model *(falls back to running-config SKU header if chassis line is absent)*. |
| **Layer 3 Interfaces & SVIs** | `show ip` | Parses active IP addresses, CIDR subnet masks, and VLAN associations. |
| **Physical Interface Telemetry** | `show interfaces brief`<br>`show name` | Gathers link up/down operational status, speed, duplex, and port description names. |
| **L2 Trunk, LAG & 802.1X Telemetry** | `show trunks`<br>`show lacp`<br>`show vlans ports all`<br>`show port-access authenticator` | Extracts `Trk*` LAG memberships, LACP mode (`active`/`passive`/`on`), operational trunk VLAN membership (`tagged`/`untagged`), and 802.1X authentication state. |
| **Layer 2 Discovery (LLDP & CDP)** | `show lldp info remote-device`<br>`show lldp info remote-device detail`<br>`show cdp neighbor detail` | Deterministically maps adjacent switches, routers, and wireless APs across physical ports (enriching truncated summary names with detail output and falling back to CDP). |
| **Routing Table** | `show ip route` | Discovers static, connected, and default gateway routes (`0.0.0.0/0`). |
| **ARP & MAC Table** | `show arp`<br>`show mac-address` | Extracts connected IP-to-MAC bindings and forwarding database entries. |
| **Spanning Tree (STP)** | `show spanning-tree`<br>`show spanning-tree detail` | Determines spanning tree enable state, root bridge priority, root MAC address, and per-port STP state/role. |
| **PoE & Optics Telemetry** | `show power-over-ethernet brief`<br>`show interfaces transceiver` | Collects chassis/per-port PoE budgets, draw/allocated wattage, PSU redundancy, and SFP/SFP+ transceiver inventory. |
| **Configuration Backup** | `show running-config` (fallback `show config`) | Captures non-destructive configuration snapshot without altering flash memory. |

### Trunk VLAN Mismatch Normalization (`migration_parsers.py` & `trunk_audit.py`)
In ArubaOS-S / Provision, VLAN membership is declared inside `vlan <id>` stanzas (`tagged <ports>` / `untagged <ports>`). [`migration_parsers.py`](../../net_docu_crawler/migration_parsers.py) and `HPProCurveDriver.get_l2_operational()` populate `admin_mode`, `oper_mode`, `trunk_active_vlans`, `encapsulation="dot1q"`, and `native_vlan_tagged=True` whenever a trunk port carries tagged VLANs with no `untagged` native VLAN.

---

## 2. Transport & 3-Stage Legacy SSH Compatibility Ladder (`ssh_compat.py`)

* **Netmiko Device Type**: `hp_procurve` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Paging Suppression**: `no page` (universally supported across Provision / ArubaOS-S versions 11.x through 16.10).
* **Legacy KEX / Host Key Resilience**:
  * Older Provision / ArubaOS-S switches (versions 14.x and early 15.x) implement embedded SSH servers (e.g., Mocana SSH) supporting only legacy key exchange algorithms (`diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`), CBC ciphers (`aes128-cbc`, `3des-cbc`), and legacy host key algorithms (`ssh-dss`, `ssh-rsa` SHA-1).
  * Modern [Paramiko](https://www.paramiko.org/) and [pyca/cryptography](https://cryptography.io/) disable SHA-1, DSS, and 1024-bit DH groups by default.
  * `HPProCurveDriver` connects via `BaseDriver.safe_netmiko_connect()` -> [`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py):
    1. **Stage 1**: Registers RFC 8731 `curve25519-sha256` and RFC 3526 `diffie-hellman-group18-sha512` and attempts standard connection.
    2. **Stage 2**: On `IncompatiblePeer` or negotiation failure, enables read-only `LegacyDSSKey` (`ssh-dss` verified via `cryptography` DSA + SHA-1) and legacy KEX/CBC/MAC algorithms, retrying with `disabled_algorithms={}`, `disable_sha2_fix=False`, and `ssh_strict=False`.
    3. **Stage 3**: If Stage 2 still fails negotiation, retries with `disable_sha2_fix=True` for `ssh-rsa` SHA-1-only switches.

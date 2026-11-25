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

# Cisco IOS-XR Driver Specification

* **Driver Class**: [`CiscoXRDriver`](../../net_docu_crawler/drivers/cisco_xr.py)
* **Supported Platforms**: Cisco ASR 9000, NCS 5000/5500, CRS, XRv9000, and 8000 Series core/edge routers
* **Upstream Netmiko Device Type**: `cisco_xr` ([Netmiko](https://github.com/ktbyers/netmiko))
* **Device Persona**: `router`
* **Official Documentation**: [Cisco IOS-XR Software Documentation](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xr-software/tsd-products-support-series-home.html)

---

## 1. Connection Mechanics, Auto-Delegation & Pagination

`CiscoXRDriver` can be selected directly (`--vendor-hint cisco_xr`, `iosxr`, or `xr`) or invoked automatically when [`CiscoDriver`](../../net_docu_crawler/drivers/cisco.py) detects `IOS-XR` / `IOS XR` in `show version` or an `RP/0/0/CPU0:` / `LC/...` prompt.

Before running operational queries, [Netmiko](https://github.com/ktbyers/netmiko) applies session-scoped terminal settings (`terminal width 511` and `terminal length 0`) over the 3-stage SSH compatibility ladder ([`net_docu_crawler/ssh_compat.py`](../../net_docu_crawler/ssh_compat.py), [Paramiko](https://www.paramiko.org/)).

---

## 2. Read-Only Operational Command Mapping

| Data Element | IOS-XR CLI Command | Notes |
| :--- | :--- | :--- |
| **System Info & Serial** | `show version`, `show inventory` | Hostname (prompt fallback), chassis PID/serial, IOS-XR release |
| **L3 Interfaces** | `show ipv4 interface brief` | IPv4 addresses with `/prefix` backfilled from `show interfaces` |
| **Physical Interface Stats** | `show interfaces` | Oper/admin state, MAC addresses, MTU/counters, CIDR masks |
| **Bundle / LAG Telemetry** | `show bundle` | `Bundle-Ether*` aggregate bundles and member LACP states |
| **Topology Neighbors** | `show lldp neighbors detail`, `show cdp neighbors detail` | LLDP/CDP peer discovery and protocol enablement tracking |
| **Routing Table** | `show route` | Active RIB entries |
| **Routing Peers** | `show bgp all all summary` (fallback `show bgp vrf all summary`), `show ospf neighbor`, `show isis neighbors` | Per-VRF/AFI BGP peers plus OSPF and IS-IS adjacencies |
| **VRFs** | `show vrf all detail` | VRF names, RDs, import/export route-targets, and member interfaces |
| **MPLS / LDP** | `show mpls ldp neighbor brief`, `show mpls ldp interface`, `show mpls forwarding-table` | LDP peer sessions, enabled interfaces, and label forwarding rows |
| **FHRP (HSRP / VRRP)** | `show hsrp summary`, `show vrrp summary` *(or `brief`)* | Active/standby FHRP groups and virtual IPs |
| **ARP Table** | `show arp` | IPv4-to-MAC resolution with OUI enrichment |
| **Optics Inventory** | `show inventory` | SFP/QSFP/XFP/CFP transceivers, PIDs, and serial numbers |
| **Configuration Backup** | `show running-config` | Full read-only declarative running configuration |

---

## 3. Optional Read-Only NETCONF & gNMI Enrichment

`CiscoXRDriver` includes strictly read-only operational helpers (`fetch_netconf_operational()` using [ncclient](https://github.com/ncclient/ncclient) `<get>` and `fetch_gnmi_operational()` using [pygnmi](https://github.com/akarneliuk/pygnmi) `Get()`). Install optional dependencies via:

```bash
pip install -e ".[xr]"
```

Neither helper ever issues `<edit-config>`, `<commit>`, or gNMI `Set()` calls.

---

## 4. Minimum Read-Only RBAC Task Group

Assign a read-only IOS-XR usergroup (e.g., built-in `read-only-tg`) with read-only permissions across `basic-services`, `interface`, `cdp`, `bgp`, `ospf`, `isis`, `mpls-ldp`, and `config-services`:

```cisco
username netcrawler
 group read-only-tg
 secret <password>
!
```

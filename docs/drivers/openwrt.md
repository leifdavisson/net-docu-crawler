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

# OpenWrt Driver Documentation

## Overview
The **OpenWrt Driver** ([`OpenWrtDriver`](../../net_docu_crawler/drivers/openwrt.py)) empowers `Net-Docu-Crawler` to extract topologies, interface configurations, wireless associations, and unified routing data from [OpenWrt](https://openwrt.org/) routers, residential gateways, access points, and mesh nodes.

* **Driver Class**: [`OpenWrtDriver`](../../net_docu_crawler/drivers/openwrt.py)
* **Official Project Homepage**: [https://openwrt.org/](https://openwrt.org/)
* **Official Documentation**: [https://openwrt.org/docs/start](https://openwrt.org/docs/start)
* **GitHub Repository**: [https://github.com/openwrt/openwrt](https://github.com/openwrt/openwrt)
* **Underlying SSH Engine**: [Netmiko](https://github.com/ktbyers/netmiko) (`linux` device type against [Dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) or OpenSSH)

---

## Zero-Blast-Radius Design & Fallback Strategy
OpenWrt installations span a wide range of architectures (ARM64, MIPS, x86_64, RISC-V) running the lightweight [Dropbear SSH](https://matt.ucc.asn.au/dropbear/dropbear.html) server or OpenSSH.

The `OpenWrtDriver` implements a dual-layer extraction model:
1. **Primary Layer (Native JSON RPC / `ubus`)**: Uses OpenWrt's native micro-bus system (`ubus`) to fetch machine-readable structured JSON without text parsing fragility:
   * `ubus call system board`: Model name, architecture, board revision, OpenWrt release.
   * `ubus call network.interface dump`: L3 logical interfaces, physical device bindings (`br-lan`, `eth0`), IP addresses, netmasks, protocol types.
   * `ubus call hostapd.* get_clients`: Associated wireless clients and stations.
2. **Fallback Layer (POSIX / BusyBox / Sysfs)**: If `ubus` permissions are restricted or commands are unavailable on older builds:
   * `cat /proc/sys/kernel/hostname || hostname`, `cat /etc/openwrt_release`, and `cat /proc/cpuinfo` for platform metadata.
   * `ip -d address show || ip address show` for interface states, IP addresses, and MAC addresses.
   * `cat /proc/net/arp` for local ARP neighbor discovery.
   * `ip route show || route -n` for kernel routing tables.
3. **Unified Configuration Export**:
   * Uses `uci export` (falling back to `head -n 1000 /etc/config/*`) to export the Unified Configuration Interface (UCI) state spanning `/etc/config/network`, `/etc/config/wireless`, `/etc/config/firewall`, and `/etc/config/dhcp`.

---

## Discovered Telemetry & Commands

| Subsystem | Primary Command | Fallback Command | Parsed Attributes |
| :--- | :--- | :--- | :--- |
| **System Info** | `ubus call system board` | `cat /proc/sys/kernel/hostname \|\| hostname`, `cat /etc/openwrt_release`, `cat /proc/cpuinfo` | Hostname, hardware model, target architecture, OpenWrt version. |
| **Interfaces** | `ubus call network.interface dump` | `ip -d address show \|\| ip address show` | Logical interfaces (`lan`, `wan`), bridge members, IP/CIDR prefixes, physical MAC addresses. |
| **Neighbors** | `lldpcli show neighbors -f json` | `ubus call hostapd.* get_clients` | LLDP neighbors (if `lldpd` package is installed) and connected Wi-Fi clients. |
| **Routing** | `ip route show` | `route -n` | Default gateway, connected subnets, static routes. |
| **ARP Table** | `cat /proc/net/arp` | — | IP-to-MAC resolution with automatic vendor OUI lookup. |
| **Configuration** | `uci export` | `head -n 1000 /etc/config/*` | Complete declarative UCI configuration snapshot. |

---

## Configuration & Setup

Add an entry for your OpenWrt router in `credentials.json`:
```json
{
  "name": "OpenWrt-Home-Router",
  "vendor": "openwrt",
  "username": "root",
  "password": "YOUR_OPENWRT_PASSWORD",
  "secret": ""
}
```

> [!TIP]
> To enable standard LLDP discovery between OpenWrt and upstream managed switches (e.g., Juniper, Cisco, Arista), install the lightweight `lldpd` package on OpenWrt:
> ```sh
> opkg update && opkg install lldpd
> /etc/init.d/lldpd enable && /etc/init.d/lldpd start
> ```

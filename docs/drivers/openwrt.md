# OpenWrt Driver Documentation

<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
GNU Affero General Public License v3.0 (AGPLv3)
-->

## Overview
The **OpenWrt Driver** empowers `Net-Docu-Crawler` to extract topologies, interface configurations, wireless associations, and unified routing data from [OpenWrt](https://openwrt.org/) routers, residential gateways, access points, and mesh nodes.

* **Official Project Homepage**: [https://openwrt.org/](https://openwrt.org/)
* **Official Documentation**: [https://openwrt.org/docs/start](https://openwrt.org/docs/start)
* **GitHub Repository**: [https://github.com/openwrt/openwrt](https://github.com/openwrt/openwrt)
* **Underlying SSH Engine**: [Netmiko](https://github.com/ktbyers/netmiko) (Dropbear SSH client)

---

## Zero-Blast-Radius Design & Fallback Strategy
OpenWrt installations span a wide range of architectures (ARM64, MIPS, x86_64, RISC-V) running the lightweight [Dropbear SSH](https://matt.ucc.asn.au/dropbear/dropbear.html) server or OpenSSH.

The `OpenWrtDriver` implements a dual-layer extraction model:
1. **Primary Layer (Native JSON RPC / `ubus`)**: Uses OpenWrt's native micro-bus system (`ubus`) to fetch machine-readable structured JSON without text parsing fragility:
   * `ubus call system board`: Model name, architecture, board revision, OpenWrt release.
   * `ubus call network.interface dump`: L3 logical interfaces, physical device bindings (`br-lan`, `eth0`), IP addresses, netmasks, protocol types.
   * `ubus call hostapd.* get_clients`: Associated wireless clients and stations.
2. **Fallback Layer (POSIX / BusyBox / Sysfs)**: If `ubus` permissions are restricted or commands are unavailable on older builds:
   * `cat /etc/openwrt_release` and `cat /proc/cpuinfo` for platform metadata.
   * `ip address show` and `/sys/class/net/` for interface states and MAC addresses.
   * `cat /proc/net/arp` for local ARP neighbor discovery.
   * `ip route show` or `route -n` for kernel routing tables.
3. **Unified Configuration Export**:
   * Uses `uci export` to export the full Unified Configuration Interface (UCI) state spanning `/etc/config/network`, `/etc/config/wireless`, `/etc/config/firewall`, and `/etc/config/dhcp`.

---

## Discovered Telemetry & Commands

| Subsystem | Primary Command | Fallback Command | Parsed Attributes |
| :--- | :--- | :--- | :--- |
| **System Info** | `ubus call system board` | `cat /etc/openwrt_release` | Hostname, hardware model, target architecture, OpenWrt version. |
| **Interfaces** | `ubus call network.interface dump` | `ip -d address show` | Logical interfaces (`lan`, `wan`), bridge members, IP/CIDR prefixes, physical MAC addresses. |
| **Neighbors** | `lldpcli show neighbors -f json` | `ubus call hostapd.* get_clients` | LLDP neighbors (if `lldpd` package is installed) and connected Wi-Fi clients. |
| **Routing** | `ip route show` | `route -n` | Default gateway, connected subnets, static routes. |
| **ARP Table** | `cat /proc/net/arp` | `ip -j neigh show` | IP-to-MAC resolution with automatic vendor OUI lookup. |
| **Configuration** | `uci export` | `cat /etc/config/*` | Complete declarative UCI configuration snapshot. |

---

## Configuration & Setup

Add an entry for your OpenWrt router in `credentials.json`:
```json
{
  "name": "OpenWrt-Home-Router",
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

# OPNsense Driver Documentation

<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
GNU Affero General Public License v3.0 (AGPLv3)
-->

## Overview
The **OPNsense Driver** enables `Net-Docu-Crawler` to safely document and map [OPNsense](https://opnsense.org/) perimeter security firewalls, multi-WAN edge routers, and VPN gateways running on [FreeBSD](https://www.freebsd.org/).

* **Official Project Homepage**: [https://opnsense.org/](https://opnsense.org/)
* **Official Documentation**: [https://docs.opnsense.org/](https://docs.opnsense.org/)
* **GitHub Repository**: [https://github.com/opnsense](https://github.com/opnsense)
* **Underlying SSH Engine**: [Paramiko](https://www.paramiko.org/) / [Netmiko](https://github.com/ktbyers/netmiko)

---

## Zero-Blast-Radius Architecture
OPNsense console logins present an interactive administrative menu (`0) Logout ... 8) Shell`). Interactive PTY sessions can trap automated scripts in menu loops.

To enforce strict **Zero-Blast-Radius** isolation:
1. **Non-Interactive Execution**: `OPNsenseDriver` establishes direct SSH command execution channels via [Paramiko](https://www.paramiko.org/), executing commands non-interactively without allocating a PTY or triggering the `/usr/local/etc/rc.initial` console menu.
2. **Read-Only Safety**: All discovery probes are strictly non-mutating informational commands (`ifconfig -a`, `netstat -rn`, `arp -an`, `kenv`, `cat /conf/config.xml`).
3. **Hardware & VM Support**: Compatible with physical appliances (DEC series), custom bare-metal servers, and virtual machines (KVM, Proxmox, VMware ESXi).

---

## Discovered Telemetry & Commands

| Subsystem | Command | Parsed Attributes |
| :--- | :--- | :--- |
| **System Info** | `hostname`, `opnsense-version`, `kenv smbios.system.product` | FQDN, OPNsense release, FreeBSD patch level, hypervisor hardware serial. |
| **Interfaces** | `ifconfig -a` | Physical ports (`vtnetX`, `igbX`), 802.1Q SVIs (`vtnet0_vlan10`), status (UP/DOWN), MAC addresses, IPv4/CIDR prefixes, description tags. |
| **Neighbors** | `lldpctl -f json 2>/dev/null` | LLDP neighbor topology if the `lldpd` plugin is active. |
| **Routing** | `netstat -rn -f inet` | Active routing table, default gateways, connected subnets, static route flags. |
| **ARP Table** | `arp -an` | Active ARP entries mapped with IEEE OUI manufacturer resolution via [`oui_lookup.py`](../../oui_lookup.py). |
| **Configuration** | `cat /conf/config.xml` | Authoritative OPNsense XML configuration backup (firewall rules, NAT, aliases, DHCP pools). |

---

## Configuration & Credentials

Add an entry for OPNsense in `credentials.json`:
```json
{
  "name": "OPNsense-Core-Gateway",
  "username": "root",
  "password": "YOUR_ROOT_PASSWORD",
  "secret": ""
}
```

> [!NOTE]
> Ensure SSH is enabled under **System > Settings > Administration > Secure Shell** in the OPNsense WebGUI. Root login via password or SSH public key is supported.

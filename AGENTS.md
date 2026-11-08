<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Net-Docu-Crawler Agent Guide

`Net-Docu-Crawler` exists for one purpose: **truthful, vendor-neutral physical (L1/L2) and logical (L3/L4-7) network documentation with zero blast radius**. Every change must improve fidelity between actual live network state and generated deliverables in `docs/net_docu_crawler/` without injecting vendor bias, synthetic assumptions, or control-plane risk.

---

## 1. Operational Guardrails & Zero-Blast-Radius Protocol

- **Strictly Read-Only Telemetry**: Issue exclusively read-only operational state queries (`show`, `get`, `ubus call`, `uci export`, `ifconfig`, `cat /conf/config.xml`). Treat core network gateways (e.g., [OPNsense](https://docs.opnsense.org/)) as live production infrastructure with zero-impact queries.
- **Licensing & Attribution**: Apply **GNU AGPLv3** (`AGPL-3.0-or-later`) headers to every module and link external tools/vendors directly to their official documentation ([Netmiko](https://github.com/ktbyers/netmiko), [Paramiko](https://www.paramiko.org/), [netaddr](https://netaddr.readthedocs.io/)).
- **Local Git Workflow**: Keep commits local unless the user explicitly authorizes `git push`.

All target interaction flows through [`detector.py`](net_docu_crawler/drivers/detector.py) and [`BaseDriver`](net_docu_crawler/drivers/base.py):

1. **4-Tier Pre-Identification Cascade (`detector.py`)**:
   - **Tier 1 (Local ARP OUI)**: Zero-packet lookup via `/proc/net/arp` + [`oui_lookup.py`](oui_lookup.py). **Hypervisor OUI Bypass**: Virtual NIC prefixes (`BC:24:11` Proxmox, `52:54:00` QEMU/KVM, `00:50:56`/`00:0C:29`/`00:05:69` VMware, `08:00:27` VirtualBox, `00:15:5D` Hyper-V, `00:16:3E` Xen) identify the hypervisor rather than the guest OS (`is_hypervisor_mac()`). Always cascade virtual NICs and remote L3 targets (where local ARP holds only the gateway MAC) to Tier 2.
   - **Tier 2 (TCP 22 SSH Banner)**: Pre-auth banner socket read (`ROSSSH` -> [MikroTik RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface), `FreeBSD` -> [OPNsense](https://docs.opnsense.org/), `Dropbear` -> [OpenWrt](https://openwrt.org/docs/start), `FortiSSH` -> [Fortinet FortiOS](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference), `Debian`/`Ubuntu` -> [FRRouting](https://docs.frrouting.org/)).
   - **Tier 3 (Post-Auth Prompt)**: `inspect_prompt_os()` matches OS prompt grammar before sending CLI commands.
   - **Tier 4 (Single Read-Only Version Probe)**: Distinguishes sub-OS families (e.g., [Cisco IOS vs NX-OS vs IOS-XR](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html)).
2. **Transport & Console-Menu Safety**:
   - Use [Netmiko](https://github.com/ktbyers/netmiko) `ConnectHandler` for CLI-native network operating systems; call `conn.enable()` when privileged exec is required for `show running-config` (e.g., [Arista EOS](https://www.arista.com/en/um-eos)).
   - Use non-interactive [Paramiko](https://www.paramiko.org/) `exec_command` (`OPNsenseSSHConnection`) for appliances whose interactive PTY spawns a numbered console menu (`/usr/local/etc/rc.initial` on OPNsense/pfSense).
3. **Anti-Lockout Credential Ordering (`crawler.py`)**:
   - Sort candidate credentials by detected vendor before connecting so appliances with strict fail2ban/AAA lockout thresholds authenticate on the first attempt and abort non-auth socket failures immediately.

---

## 2. Canonical `device_data` Contract & Persona Alignment

Every [`BaseDriver`](net_docu_crawler/drivers/base.py) subclass returns a normalized dictionary from `crawl(conn)` consumed by [`DeviceRegistry`](net_docu_crawler/topology_resolver.py) and [`report_generator.py`](report_generator.py). Maintain strict alignment on every field:

| Key | Type & Format | Alignment Invariant |
| :--- | :--- | :--- |
| `device_type` & `device_persona` | `"switch"` \| `"router"` \| `"firewall"` \| `"ap"` \| `"wlc"` | Classify hardware accurately (e.g., Cisco 891/ISR/ASR and Junos MX -> `"router"`; Junos SRX, FortiGate, PAN-OS, OPNsense -> `"firewall"`). L2 audits such as Spanning Tree (`STP`) apply exclusively to `"switch"` personas (or devices where `stp["enabled"]` is `True`). |
| `serial` | `str` (`"Unknown"` when unavailable) | Emit real hardware/SMBIOS serials only. Use `"Unknown"` when an OS/container lacks a unique serial. `DeviceRegistry` rejects `PLACEHOLDER_SERIALS` (`"Not Specified"`, `"0"`, `"Default string"`, `"Unknown"`) and `GENERIC_DEFAULT_HOSTNAMES` (`"OpenWrt"`, `"MikroTik"`, `"opnsense"`) so cloned VMs and containers across routed subnets (`172.16.1.0/24`) fall back to unique MAC or `IP_<addr>` without overwriting each other. |
| `mac_address` | Lowercase `aa:bb:cc:dd:ee:ff` | Extract directly from device interfaces/chassis commands first (`show chassis mac-addresses`, `/interface ethernet print detail`, `ip address show`, `ifconfig -a`) so crawls across L3 gateways succeed without relying on scanner-local `/proc/net/arp`. |
| `l3_interfaces` | `list[{"interface", "ip_address", "status", "protocol"}]` | Preserve exact subnet masks/CIDRs (`"100.64.224.70/19"`, `"192.168.1.3/24"`, `"192.168.1.252 255.255.255.0"`). Exclude `127.0.0.0/8` loopbacks and internal switch fabric addresses (`128.0.0.0/16` on [Juniper Junos](https://www.juniper.net/documentation/product/us/en/junos-os/)). |
| `interfaces_detail` | `dict[port_name, {"status", "mac_address", "description", "speed", "duplex"}]` | Include physical and real routed/VLAN interfaces only. Filter kernel/PFE pseudo-devices (`bme*`, `jsrv*`, `pfe-*`, `pfh-*`, `vme`, `dsc`, `mtun` on Junos; `naf.*`, `l2t.*`, `ssl.*` on FortiOS; `pflog*`, `pfsync*`, `enc*` on OPNsense; `lo` on Linux) so port utilization percentages and `migration_cabling_matrix.csv` reflect real cabling. |
| `neighbors` | `list[{"local_port", "remote_device", "remote_port", "remote_ip", "remote_mac", "platform", "device_type"}]` | Resolve `local_port` to physical interface names (strip Junos `.0` unit suffixes; prefer `lldp-local-interface` over numeric SNMP port indexes like `515`). Strip surrounding quotes from CLI key-value tokens (e.g., RouterOS `identity="Host"`). When wireless APs omit the optional LLDP `System Description` TLV, fall back to LLDP capability flags and `oui_lookup.lookup_oui(remote_mac)` so `platform` and `device_type="ap"` still populate the Wireless Overlay and cabling matrix. |
| `routes` | `list[{"subnet", "protocol", "next_hop", "interface"}]` | Normalize default routes to `"0.0.0.0/0"` and deduplicate active vs ECMP/shadow entries cleanly. |
| `stp` | `{"enabled": bool, "is_root": bool, "vlans": dict}` | Implement `get_stp(conn)` on L2 switching drivers (`CiscoDriver`, `JuniperDriver`, `AristaDriver`). |
| `services` | `{"dns_servers", "ntp_servers", "radius_servers", "tacacs_servers"}` | Parsed automatically from `raw_config` via `extract_services_from_config()` in `base.py`; extend that parser whenever adding a new configuration syntax. |

---

## 3. Topology & Deliverable Truthfulness Rules

When modifying [`topology_resolver.py`](net_docu_crawler/topology_resolver.py), [`crawler.py`](net_docu_crawler/crawler.py), or [`report_generator.py`](report_generator.py):

- **Bidirectional Link Stitching**: Pass canonical hostnames (`device_data["hostname"]`) — never `SER_...` registry keys — into `DeviceRegistry.add_bidirectional_link()` so `(NodeA, PortA, NodeB, PortB)` and `(NodeB, PortB, NodeA, PortA)` converge into a single `"confirmed"` edge.
- **Global ARP & Crawled-Device Neighbor Enrichment**: Cross-reference `remote_mac` and `remote_device` through `registry.resolve_neighbor_ip()` and crawled device records after target crawling completes so MAC-only LLDP neighbors (such as [Aruba Instant](https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm) APs on Junos switches) gain management IPs and exact models in `L2_network_diagrams.md`.
- **Mermaid Node Preservation**: Track crawled hostnames in a dedicated `defined_nodes` set inside `generate_l2_diagram()` (`devices` is keyed by IP address, whereas neighbor `node_b` is a hostname) so neighbor links keep crawled `<br/>(Model)` labels and `ap` / `firewall` / `router` / `root` styling intact.
- **L3 CIDR & Conflict Accuracy**: Parse interface networks with [netaddr](https://netaddr.readthedocs.io/) (`parse_interface_network()`). Multiple distinct devices holding unique IPs inside the same `192.168.1.0/24` prefix represent normal L2/L3 broadcast adjacency; flag conflicts only on:
  1. Duplicate host IPs (`ip1 == ip2`) across interfaces or devices,
  2. Overlapping subnets assigned to two distinct routed interfaces of the *same* router/firewall, or
  3. Unequal overlapping CIDR masks across devices (e.g., `192.168.1.0/24` vs `192.168.1.128/25`).

---

## 4. Workflow: Adding or Updating a Vendor Driver

Execute these steps in order:

1. **Implement Driver (`net_docu_crawler/drivers/<vendor>.py`)**: Subclass [`BaseDriver`](net_docu_crawler/drivers/base.py) with GNU AGPLv3 header and official vendor CLI doc link. Prefer native structured JSON (`| display json`, `| json`, `ubus call`, `-f json`) with regex/POSIX fallback.
   - *Done when*: All 7 abstract methods (plus `get_stp()` if switching and `extract_services_from_config()` support in `base.py`) satisfy every invariant in the Canonical `device_data` Contract above.
2. **Wire Identification & Registry (`detector.py`, `drivers/__init__.py`, `crawler.py`)**: Add hardware OUIs to `oui_lookup.py` (excluding virtual NIC OUIs), SSH banner and prompt signatures to `detector.py`, and driver mappings to `DRIVER_REGISTRY` and `VENDOR_DRIVER_MAP`.
   - *Done when*: `get_driver(ip, vendor_hint="<vendor>")` and `detect_vendor_range()` resolve the driver across both physical OUI and VM SSH-banner paths.
3. **Prove Offline & Deliverable Parity (`tests/test_drivers.py`, `tests/test_deliverable_consistency.py`)**: Add realistic CLI output mocks (including quoted strings, loopback/pseudo-interfaces, and hypervisor MACs) and run report generation against the output.
   - *Done when*: `pytest` and `ruff check .` pass with zero warnings, and every generated deliverable in `docs/net_docu_crawler/` matches `net_docu_crawler_dataset.json` with zero unstripped quotes, zero pseudo-interface leaks, and zero false-positive STP/CIDR alarms.
4. **Document Vendor Specifics (`docs/drivers/<vendor>.md` & `docs/drivers/overview.md`)**: Record exact read-only commands, transport mechanism, and platform gotchas with backlinks to official vendor docs.
   - *Done when*: `docs/drivers/overview.md` and `docs/drivers/<vendor>.md` link to the new driver class in `net_docu_crawler/drivers/<vendor>.py`.

---

## 5. Disclosed Reference

- **Per-vendor command matrices & transport notes**: [`docs/drivers/overview.md`](docs/drivers/overview.md) (`cisco.md`, `juniper.md`, `aruba.md`, `paloalto.md`, `fortinet.md`, `opnsense.md`, `openwrt.md`).
- **Junior operator VTY & AAA troubleshooting playbook**: [`docs/junior_operator_playbook.md`](docs/junior_operator_playbook.md).
- **Live deliverable parity assertions**: [`tests/test_deliverable_consistency.py`](tests/test_deliverable_consistency.py).
- **Virtual testbed architecture & blueprint**: [`docs/proxmox_lab_and_driver_roadmap.md`](docs/proxmox_lab_and_driver_roadmap.md).

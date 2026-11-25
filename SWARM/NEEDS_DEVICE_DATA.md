<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Consolidated `NEEDS-DEVICE-DATA` Live Hardware Capture Checklist

All **148 confirmed** P0, P1, P2, and P3 findings in [`SWARM/FINDINGS.md`](FINDINGS.md) have been fixed, regression-tested offline against documentation-backed fixtures (`tests/fixtures/*.txt`), and merged into `swarm/integration` (**484 passed, 0 failed, 9 skipped**).

The remaining **3 `NEEDS-DEVICE-DATA` ledger entries** (`SF-13`, `RP-16`, `TV-07`) and their associated per-platform sub-items represent live-device output variations that were not present in the existing lab/field recordings (`docs/net_docu_crawler/logs/` and `deliverables/`) and are currently covered in CI by synthetic documentation-backed fixtures tagged `SYNTHETIC-DOC-BACKED`.

Every command listed below is **strictly read-only** (zero configuration writes, zero state mutations) and complies with [`SWARM/command_allowlist.md`](command_allowlist.md) and [`AGENTS.md`](../AGENTS.md).

---

## 1. Summary of `NEEDS-DEVICE-DATA` Ledger IDs

| Finding ID | Severity | Area | Summary | Current CI Coverage |
| :--- | :--- | :--- | :--- | :--- |
| `SF-13` | P1 | Fortinet Multi-VDOM & Pager Byte Sequences | Exact `--More--` erasure/ANSI byte sequences on FortiOS 6.4/7.0/7.2/7.4 under `show full-configuration`, multi-VDOM visibility under read-only `accprofile` (`sysgrp read`) without `config global`, and non-interactive `exec_command` behavior under `set post-login-banner enable`. | `tests/test_edge_fortinet.py` (simulated multi-page `--More--` drainer, ANSI/backspace stripping, `max_pages` safety cap, zero-write assertions) + `tests/fixtures/fortinet_fortios.txt`. |
| `RP-16` | P2 | Multi-Vendor Route AD, Non-Root Arista STP, FHRP/VRF/MVC Fixtures | Exact CLI/JSON field shapes for route administrative distance/preference across all vendors, non-root Arista EOS `show spanning-tree \| json`, active multi-vendor FHRP/VRF configs, and OPNsense 24+/25+ MVC `<Syslog>` / `<DHCRelay>` XML blocks. | `tests/test_report_fixes.py`, `tests/test_enterprise_juniper_arista.py`, `tests/test_oss_opnsense_parsers.py` (`SYNTHETIC-DOC-BACKED` fixtures). |
| `TV-07` | P2 | Real Hardware Transcript Coverage for 7 Platforms | Scrubbed real hardware/VM session logs for Cisco Catalyst IOS-XE switch, Cisco NX-OS, Cisco IOS-XR, Cisco SMB (SG300/SG350/CBS350), HPE Aruba AOS-CX, Palo Alto PAN-OS, and OpenWrt 23.05/24.10. | `tests/fixtures/{cisco_ios_xe,cisco_nxos,cisco_xr,ciscosmb,aruba_aoscx,paloalto_panos,openwrt}.txt` + `tests/test_fixture_hygiene.py`. |

---

## 2. Platform-by-Platform Read-Only Capture Checklist

When capturing outputs from live lab or production hardware, scrub all passwords, hashes, private keys, SNMP community strings, and public IPs before committing under `tests/fixtures/` (enforced automatically by `tests/test_fixture_hygiene.py`).

### 2.1 Fortinet FortiOS 6.4 / 7.0 / 7.2 / 7.4 (`SF-13`, `DG-NDD`)
- **Documentation Reference**: [Fortinet FortiOS CLI Reference](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference)
- **Target Configurations**:
  1. FortiGate with default console pagination (`output more`), `set post-login-banner enable`, and a least-privilege read-only `accprofile` (`sysgrp read`, result prompt `$`).
  2. Multi-VDOM FortiGate (`vdom-mode multi-vdom` or `split-vdom`) with hardware SFP/SFP+ transceivers, active FortiLink/LLDP neighbors, and ECMP/IPsec/BGP/OSPF routes.
- **Exact Read-Only Commands to Capture**:
  ```text
  get system status
  get system interface
  get system interface physical
  show system interface
  diagnose lldprx neighbor details
  diagnose lldprx neighbor summary
  diagnose switch-controller switch-info lldp neighbors-detail
  get router info routing-table all
  get system arp
  get system interface transceiver
  show full-configuration
  ```
- **What to Verify**:
  - Raw byte sequence around `--More--` prompt and spacebar (`" "`) overwrite (`\r         \r` vs `\x08` vs `\x1b[K`) in `ReadOnlyFortinetSSH.send_command()`.
  - Scope of `get system status`, `get system interface`, and `show full-configuration` under `sysgrp read` when multi-VDOM is enabled without entering `config global`.

### 2.2 Cisco Catalyst IOS-XE 16.x / 17.x (`TV-07`, `DE-NDD-1`)
- **Documentation Reference**: [Cisco IOS-XE Command Reference](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html)
- **Target Configurations**: Catalyst 9200/9300/3850 stack with active PoE+ devices, SFP+ DOM optics, 802.1Q trunks, Port-Channels, Rapid-PVST+/MST, and both CDP and non-Cisco LLDP neighbors.
- **Exact Read-Only Commands to Capture**:
  ```text
  show version
  show inventory
  show ip interface brief
  show interfaces
  show cdp neighbors detail
  show lldp neighbors detail
  show lldp neighbors
  show spanning-tree
  show ip route
  show ip arp
  show power inline
  show mac address-table
  show interfaces transceiver
  show interfaces trunk
  show etherchannel summary
  show running-config
  ```

### 2.3 Cisco Nexus NX-OS 9.3 / 10.x (`TV-07`, `DE-NDD-2`)
- **Documentation Reference**: [Cisco Nexus 9000 NX-OS Command Reference](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-command-reference-list.html)
- **Target Configurations**: Nexus 9300/9500 with vPC / Port-Channels, multi-VRF routing (`ubest/mbest`), HSRP/VRRP, and SFP28/QSFP28 DOM transceivers.
- **Exact Read-Only Commands to Capture**:
  ```text
  show version
  show inventory
  show ip interface brief
  show interfaces
  show cdp neighbors detail
  show lldp neighbors detail
  show lldp neighbors
  show spanning-tree
  show ip route
  show ip arp
  show mac address-table
  show interfaces transceiver
  show interfaces trunk
  show port-channel summary
  show running-config
  ```

### 2.4 Cisco IOS-XR 7.x / 24.x (`TV-07`, `DE-NDD-3`)
- **Documentation Reference**: [Cisco IOS-XR Command Reference](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xr-software/products-command-reference-list.html)
- **Target Configurations**: ASR9k / NCS5500 / 8000 (`RP/0/RSP0/CPU0:...` and `RP/0/RP0/CPU0:...` prompts) with `Bundle-Ether` LAGs, BGP/OSPF/IS-IS neighbors, HSRP/VRRP, MPLS LDP, and VRFs.
- **Exact Read-Only Commands to Capture**:
  ```text
  show version
  show inventory
  show ipv4 interface brief
  show interfaces
  show lldp neighbors detail
  show cdp neighbors detail
  show route
  show arp
  show hsrp brief
  show vrrp brief
  show bundle
  show bgp all all summary
  show bgp vrf all summary
  show ospf neighbor
  show isis neighbors
  show vrf all detail
  show mpls ldp neighbor brief
  show mpls ldp interface
  show mpls forwarding-table
  show running-config
  ```

### 2.5 Cisco SMB SG300 / SG350 / CBS350 (`TV-07`, `DE-NDD-4`)
- **Documentation Reference**: [Cisco Business 350 Series CLI Guide](https://www.cisco.com/c/en/us/support/switches/business-350-series-managed-switches/products-command-reference-list.html)
- **Target Configurations**: SG350/CBS350 with space-delimited `vlan 10` SVIs, PoE ports, LAG port ranges (`gi1/0/23-24`), and LLDP/CDP neighbors.
- **Exact Read-Only Commands to Capture**:
  ```text
  show system
  show system id
  show version
  show ip interface
  show interfaces status
  show lldp neighbors
  show ip route
  show arp
  show spanning-tree
  show power inline
  show mac address-table
  show fiber-ports optical-transceiver
  show interfaces switchport
  show interfaces port-channel
  show running-config
  ```

### 2.6 Palo Alto Networks PAN-OS 10.1 / 11.x (`TV-07`, `DG-NDD-1`)
- **Documentation Reference**: [PAN-OS CLI Quick Start](https://docs.paloaltonetworks.com/pan-os)
- **Target Configurations**: PA-Series or VM-Series in Active/Passive HA (`admin@hq-fw01(active)>`), multiple Virtual Routers, AE aggregate interfaces, subinterfaces, and LLDP neighbors.
- **Exact Read-Only Commands to Capture**:
  ```text
  show system info
  show high-availability state
  show interface all
  show lldp neighbors all
  show routing route
  show arp all
  show config running
  ```

### 2.7 HPE Aruba AOS-CX 10.10–10.13 & Aruba Instant 8.6–8.11 (`TV-07`, `DG-NDD-3..4`)
- **Documentation Reference**: [HPE Aruba Networking AOS-CX CLI Reference](https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm) & [Aruba Instant CLI Reference](https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm)
- **Target Configurations**:
  - AOS-CX 6100/6200/6300/8325 switch with LAGs, VLAN trunks (`vlan trunk native` / `vlan trunk allowed`), MSTP, PoE, and SFP+ transceivers.
  - Aruba Instant IAP cluster with multiple APs and associated wireless clients.
- **Exact Read-Only Commands to Capture (AOS-CX)**:
  ```text
  show version
  show system
  show ip interface brief
  show interface brief
  show lldp neighbor-info detail
  show ip route
  show arp
  show spanning-tree
  show mac-address-table
  show power-over-ethernet brief
  show interface transceiver
  show interface trunk
  show lacp interfaces
  show running-config
  ```
- **Exact Read-Only Commands to Capture (Aruba IAP)**:
  ```text
  show version
  show aps
  show ip interface brief
  show ap debug lldp info
  show ip route
  show arp
  show clients
  show configuration
  ```

### 2.8 Juniper Junos ELS (18.x–23.4) & Arista EOS (4.28–4.37) (`RP-16`, `DE-NDD-5..6`)
- **Documentation Reference**: [Juniper Junos OS Documentation](https://www.juniper.net/documentation/product/us/en/junos-os/) & [Arista EOS User Manual](https://www.arista.com/en/um-eos)
- **Target Configurations**:
  - Arista EOS switch acting as a **non-root** STP bridge (`isRootBridge: false` with root port and root path cost populated in `show spanning-tree | json`), active `Port-Channel` LAG (`show port-channel | json`), PoE ports (`show power inline | json`), and multi-VRF routing.
  - Juniper EX/QFX with QSFP28 multi-lane optics (`show interfaces diagnostics optics | display json`), active LACP `ae*` bundles (`show lacp interfaces | display json`), and VSTP/MSTP instances.
- **Exact Read-Only Commands to Capture (Arista EOS)**:
  ```text
  show version | json
  show hostname | json
  show ip interface | json
  show interfaces | json
  show lldp neighbors detail | json
  show spanning-tree | json
  show ip route | json
  show ip arp | json
  show power inline | json
  show mac address-table | json
  show interfaces transceiver | json
  show interfaces trunk | json
  show port-channel | json
  show running-config
  ```

### 2.9 OpenWrt 23.05 / 24.10 & OPNsense 24+ / 25+ (`TV-07`, `RP-16`, `DO-NDD-1..4`)
- **Documentation Reference**: [OpenWrt Documentation](https://openwrt.org/docs/start) & [OPNsense Documentation](https://docs.opnsense.org/)
- **Target Configurations**:
  - OpenWrt 23.05/24.10 router/AP with dual-band `hostapd.*` radios, `lldpd`, PPPoE or WireGuard L3 interfaces, and bridge VLAN filtering.
  - OPNsense 24+/25+ HA firewall with active CARP VIPs (`MASTER`/`BACKUP` in `ifconfig -a`), dotted VLANs (`igb0.10`), Point-to-Point tunnels (`ovpnc1` / `wg0`), active `lldpctl -f json` peers, and MVC `<OPNsense><Syslog>` / `<DHCRelay>` XML stanzas.
- **Exact Read-Only Commands to Capture (OpenWrt)**:
  ```text
  ubus call system board 2>/dev/null
  ubus call network.interface dump 2>/dev/null
  ip -d address show 2>/dev/null
  lldpcli show neighbors -f json 2>/dev/null
  ubus call hostapd.* get_clients 2>/dev/null
  ip route show 2>/dev/null
  cat /proc/net/arp 2>/dev/null
  uci export 2>/dev/null
  ```
- **Exact Read-Only Commands to Capture (OPNsense)**:
  ```text
  hostname
  opnsense-version
  kenv smbios.system.product 2>/dev/null
  kenv smbios.system.serial 2>/dev/null
  ifconfig -a
  lldpctl -f json 2>/dev/null
  netstat -rnW -f inet
  arp -an
  cat /conf/config.xml
  ```

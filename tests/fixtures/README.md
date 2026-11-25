<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Offline CLI Test Fixtures (`tests/fixtures/`)

All fixtures in this directory are **strictly scrubbed, read-only CLI transcripts** stored as `.txt` files (never `.log`, `.json`, `.cfg`, or `.conf`, complying with `.gitignore` and `.github/workflows/ci.yml` secret/log hygiene checks).

## Hygiene & Scrubbing Rules
Enforced automatically by [`tests/test_fixture_hygiene.py`](../test_fixture_hygiene.py):
- **Zero secrets**: no plaintext passwords, password hashes (`$1$`, `$5$`, `$6$`, `$9$`, `ENC`), private keys/certificates, SNMP community strings, or `credentials.json`.
- **Zero real customer/lab PII**: all IPs use RFC 1918 / RFC 5737 test subnets (`10.10.x.x`, `198.51.100.x`, `100.64.224.x`); domains use `lab.example.invalid`; MACs use vendor-OUI-preserving synthetic host octets.
- **Zero write commands**: no `config system console`, `configure terminal`, `commit`, `write memory`, or mutating commands.

## Fixture Inventory & Provenance

| Vendor Directory | File | Provenance | Upstream Reference |
| :--- | :--- | :--- | :--- |
| `cisco/` | `ios_router.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (Cisco 891 IOS 15.0) | [Cisco IOS Docs](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html) |
| `cisco/` | `ios_catalyst_core_synthetic.txt` | `SYNTHETIC-DOC-BACKED` (`NEEDS-DEVICE-DATA`: Catalyst IOS-XE switch) | [Cisco IOS-XE Docs](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html) |
| `cisco_xr/` | `iosxr_router_synthetic.txt` | `SYNTHETIC-DOC-BACKED` (`NEEDS-DEVICE-DATA`: IOS-XR) | [Cisco IOS-XR Docs](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xr-software/tsd-products-support-series-home.html) |
| `ciscosmb/` | `ciscosmb_sg350_synthetic.txt` | `SYNTHETIC-DOC-BACKED` (`NEEDS-DEVICE-DATA`: SG300/SG350/CBS) | [Cisco SMB 350 Docs](https://www.cisco.com/c/en/us/support/switches/small-business-350-series-managed-switches/series.html) |
| `juniper/` | `junos_ex2300.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (EX2300-C-12P Junos 23.4R2 JSON) | [Juniper Junos Docs](https://www.juniper.net/documentation/product/us/en/junos-os/) |
| `aruba/` | `iap_ap215.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (Aruba Instant AP-215 8.6) | [Aruba Instant Docs](https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm) |
| `aruba/` | `aoscx_switch_synthetic.txt` | `SYNTHETIC-DOC-BACKED` (`NEEDS-DEVICE-DATA`: ArubaOS-CX) | [ArubaOS-CX Docs](https://www.arubanetworks.com/techdocs/AOS-CX/) |
| `hpprocurve/` | `procurve_2920.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (HP 2920-24G-PoE+ WB.16.10) | [HPE ArubaOS-Switch Docs](https://www.arubanetworks.com/techdocs/AOS-Switch/16.10/) |
| `arista/` | `veos_switch.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (Arista vEOS-lab JSON) | [Arista EOS Docs](https://www.arista.com/en/um-eos) |
| `fortinet/` | `fortigate_edge.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (FortiGate-VM64 v7.4, config writes removed) | [Fortinet FortiOS CLI](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference) |
| `mikrotik/` | `routeros_chr.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (MikroTik CHR RouterOS 7.16) | [MikroTik RouterOS CLI](https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface) |
| `opnsense/` | `opnsense_gateway.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (OPNsense 24.7 FreeBSD) | [OPNsense Docs](https://docs.opnsense.org/) |
| `frr/` | `frr_router.txt` | `SCRUBBED-FROM-LAB-CAPTURE` (FRRouting 10.x Linux) | [FRRouting Docs](https://docs.frrouting.org/) |
| `paloalto/` | `panos_firewall_synthetic.txt` | `SYNTHETIC-DOC-BACKED` (`NEEDS-DEVICE-DATA`: PAN-OS) | [Palo Alto PAN-OS Docs](https://docs.paloaltonetworks.com/pan-os) |
| `openwrt/` | `openwrt_router_synthetic.txt` | `SYNTHETIC-DOC-BACKED` (`NEEDS-DEVICE-DATA`: OpenWrt) | [OpenWrt Docs](https://openwrt.org/docs/start) |

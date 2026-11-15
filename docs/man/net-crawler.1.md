<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NET-CRAWLER(1) — Net-Docu-Crawler Manual

## NAME

**net_crawler.py** — read-only, vendor-neutral multi-vendor network topology discovery and documentation generator

## SYNOPSIS

```bash
python3 net_crawler.py [OPTIONS]
```

## DESCRIPTION

`Net-Docu-Crawler` performs strictly read-only operational state discovery across heterogeneous network infrastructure ([Cisco IOS/IOS-XE/NX-OS/IOS-XR/SMB](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html), [Juniper Junos](https://www.juniper.net/documentation/product/us/en/junos-os/), [HP ProCurve / ArubaOS-S](https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm), [Arista EOS](https://www.arista.com/en/um-eos), [Fortinet FortiOS](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference), [Palo Alto PAN-OS](https://docs.paloaltonetworks.com/), [MikroTik RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface), [OPNsense](https://docs.opnsense.org/), [OpenWrt](https://openwrt.org/docs/start), and [FRRouting](https://docs.frrouting.org/)) using [Netmiko](https://github.com/ktbyers/netmiko), [Paramiko](https://www.paramiko.org/), and [netaddr](https://netaddr.readthedocs.io/), and generates L1/L2/L3 diagrams, cabling matrices, BOMs, and cutover validation scripts.

---

## OPTIONS

### Target & Credential Selection

- `--targets IP_OR_CIDR [IP_OR_CIDR ...]`
  List of seed IPv4 addresses or CIDRs to crawl (e.g. `10.1.0.1`, `172.16.1.0/24`).
- `--credentials PATH [PATH ...]`
  One or more credentials JSON files tried in vendor-prioritized order (default: `credentials.json`).
- `--validate-credentials`
  Validate `--credentials` JSON file(s) and exit without running a crawl.
- `--try-all-creds`
  Try every credential profile even when a specific vendor is detected (not recommended for lockout-protected appliances).
- `--vendor-hint VENDOR`
  Fallback vendor driver hint when OUI/SSH banner is unknown (e.g. `fortinet`, `ciscosmb`, `cisco`, `juniper`, `hpprocurve`).

### Multi-Hop Discovery & Smart Subnet Filtering

- `--no-follow-neighbors`
  Disable automatic crawling of CDP/LLDP neighbor management IPs discovered on crawled devices.
- `--follow-subnets`
  Follow directly connected RFC 1918 subnets discovered from crawled routers/firewalls/L3 switches. Automatically prunes empty `/24`–`/22` subnets when ARP tables exist so quiet VLANs are not brute-force scanned.
- `--follow-arp-only`
  Only follow live ARP-discovered infrastructure IPs inside connected subnets. Never sweeps empty subnets and automatically skips known non-infrastructure endpoint OUIs (Apple, printers, IP cameras, AV controllers, VoIP phones).
- `--mgmt-subnets-only`
  When following subnets, restrict expansion to management/infrastructure/transit SVIs (`mgmt`, `infra`, `switch`, `core`, `dist`, `loopback`, `p2p`, `transit`, `uplink`) and `/30`–`/31` point-to-point links.
- `--subnet-include CIDR [CIDR ...]`
  Only follow subnets overlapping these CIDRs (e.g. `--subnet-include 10.250.0.0/16 172.31.0.0/16`).
- `--subnet-exclude CIDR [CIDR ...]`
  Exclude subnets overlapping these CIDRs when following subnets.
- `--follow-routes`
  When `--follow-subnets` or `--follow-arp-only` is enabled, also follow non-connected routing-table subnets.
- `--max-hops N`
  Maximum L3 subnet hops when following subnets (default: `1`).
- `--allow-cgnat`
  Allow subnet/neighbor following into CGNAT (`100.64.0.0/10`) ranges.
- `--allow-public-subnets`
  Allow subnet/neighbor following into non-RFC1918 public subnets (explicit ISP override).

### Transport, Fingerprinting & Concurrency

- `--timeout SECONDS`
  SSH/Telnet connection timeout in seconds (default: `8`).
- `--ssh-ports PORT [PORT ...]`
  SSH ports to probe during discovery (default: `22`).
- `--telnet-ports PORT [PORT ...]`
  Telnet ports to probe during discovery (default: `23`).
- `--workers N`
  Maximum concurrent device crawl workers (default: `16`).
- `--no-http-fingerprint`
  Disable HTTP/HTTPS banner and TLS certificate fingerprinting for unauthenticated/ARP-discovered hosts.
- `--snmp`
  Enable opt-in read-only SNMPv2c `sysDescr`/`sysName` enrichment for unauthenticated/ARP hosts.
- `--snmp-community COMMUNITY`
  SNMPv2c community string when `--snmp` is enabled (default: `public`).
- `--no-online-oui`
  Disable online OUI lookup fallback for unseen MAC prefixes (air-gapped environments).

### Output, Sanitization & Migration

- `--output-dir DIR`
  Flat output directory when `--no-organize` is used, or custom base directory when organized (default flat path: `docs/net_docu_crawler`, default organized base: `deliverables/`).
- `--organize`
  (Default) Store deliverables under `deliverables/<Target>_<Timestamp>_<domain>/`.
- `--no-organize`
  Write flat output directly to `--output-dir` without creating a timestamped subfolder.
- `--domain SUFFIX`
  Domain suffix for organized report folders (default: `lan`).
- `--sanitize-passwords`
  Redact passwords, pre-shared keys, and SNMP communities in saved configurations, logs, and exports.
- `--target-vendor VENDOR`
  Generate staged target-vendor migration CLI configs (`cisco`, `juniper`, `arista`, `hpprocurve`).

### Baseline Verification & Offline Modes

- `--save-baseline PATH`
  Save pre-cutover baseline state JSON to `PATH`.
- `--compare-baseline PATH`
  Compare the current crawl against a saved baseline JSON and generate `migration_verification_report.md`.
- `--retry-failed PATH`
  Path to `failed_hosts.json` from a prior run to retry `unauthenticated` hosts only (skips `unsupported` endpoints).
- `--from-dataset PATH`
  Offline mode: regenerate all deliverables from an existing `net_docu_crawler_dataset.json`.
- `--reparse-logs RUN_DIR`
  Offline mode: replay `logs/*_raw_session.log` in `RUN_DIR` through the latest vendor drivers and regenerate all deliverables with zero network traffic.

---

## EXAMPLES

### 1. Fast, Clean Production Campus Crawl (Recommended)

Crawl from the core switch, follow CDP/LLDP neighbors, and only probe live ARP-discovered infrastructure IPs across management/transit subnets:

```bash
python3 net_crawler.py \
  --targets 10.1.0.1 \
  --follow-arp-only \
  --mgmt-subnets-only \
  --max-hops 3 \
  --workers 12 \
  --timeout 10 \
  --sanitize-passwords
```

### 2. Scoped Multi-Site Crawl with Explicit Subnet Allowlist

```bash
python3 net_crawler.py \
  --targets 10.1.0.1 \
  --follow-arp-only \
  --subnet-include 10.250.0.0/16 172.31.0.0/16 \
  --max-hops 3 \
  --sanitize-passwords
```

### 3. Offline Log Replay After a Driver Upgrade

```bash
python3 net_crawler.py --reparse-logs deliverables/10.1.0.1_20261114_195759_lan/
```

---

## GENERATED DELIVERABLES

| File | Description |
| :--- | :--- |
| `net_docu_crawler_dataset.json` | Canonical normalized JSON inventory for all crawled and discovered nodes |
| `net_docu_crawler_live_report.md` | Layered L1/L2/L3 audit, port utilization, PoE budgets, STP, and CIDR checks |
| `Network_Analysis.md` | Master architecture, hardware/optics inventory, and migration blueprint |
| `L2_network_diagrams.md` | Mermaid L2 topology diagrams (confirmed links, STP root, wireless overlay) |
| `L3_network_diagrams.md` | Mermaid L3 routed/SVI subnet & next-hop diagrams |
| `asset_inventory.csv` | Device inventory CSV (`Hostname`, `IP`, `MAC`, `Device Type`, `Model`, `Role`) |
| `migration_cabling_matrix.csv` | Port-to-port uplink & AP cabling matrix |
| `port_mac_endpoint_mapping.csv` | Switchport-to-MAC/OUI endpoint mapping |
| `bom_hardware_sizing.csv` | Hardware replacement & PoE/optics sizing BOM |
| `validate_cutover.sh` / `.ps1` | Read-only post-cutover smoke test scripts |
| `failed_hosts.json` | Unauthenticated/unsupported host log for `--retry-failed` |

---

## SEE ALSO

- Troff man page: [`docs/man/net-crawler.1`](net-crawler.1)
- Driver reference: [`docs/drivers/overview.md`](../drivers/overview.md)

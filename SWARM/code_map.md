<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Net-Docu-Crawler Code Map & End-to-End Data Paths

## 1. Entry Points & Execution Lifecycle

| Entry Point | File | Invocation | Behavior |
| :--- | :--- | :--- | :--- |
| Script CLI | `net_crawler.py` (37 LOC) | `python3 net_crawler.py ...` | Checks `--install-deps`, calls `dependency_checker.ensure_dependencies()`, dispatches to `net_docu_crawler.crawler.main()`. |
| Package Module | `net_docu_crawler/__main__.py` (31 LOC) | `python3 -m net_docu_crawler ...` | Identical pre-flight dependency check -> `net_docu_crawler.crawler.main()`. |
| Console Entry Point | `pyproject.toml` (`net-crawler`) | `net-crawler ...` | Directly invokes `net_docu_crawler.crawler:main` (bypasses `dependency_checker`). |
| Shell Wrappers | `run.sh`, `run.ps1`, `setup_windows.ps1` | Operator shell scripts | Environment bootstrap + CLI execution wrappers. |
| Offline Modes | `net_docu_crawler/crawler.py` | `--from-dataset`, `--reparse-logs`, `--retry-failed` | Re-renders deliverables from `net_docu_crawler_dataset.json`, re-parses raw `logs/*_raw_session.log`, or retries `failed_hosts.json`. |

### End-to-End Pipeline (`crawler.py`)

1. **CLI & Config**: `_build_arg_parser()` -> `main()` -> `load_and_validate_credentials()` + `parse_target_specs()` / `detect_local_subnets()` / `expand_targets()`.
2. **Pre-Flight Port Scan & 4-Tier Detection**: `detector.scan_subnet_ports()` -> `_identify_port_vendor()` (`detector.detect_vendor_range()`: Tier 1 `/proc/net/arp` + `oui_lookup` with `is_hypervisor_mac()` bypass; Tier 2 TCP SSH/Telnet banner; Tier 3 `inspect_prompt_os()`; Tier 4 OS probe).
3. **Session & Driver Execution**: `_resolve_candidate_drivers()` + `_sort_and_scope_credentials()` -> `_connect_and_crawl_once()` -> `<Driver>.connect()` via [Netmiko](https://github.com/ktbyers/netmiko) / `ssh_compat.connect_netmiko_with_fallback()` (or [Paramiko](https://www.paramiko.org/) `exec_command` for OPNsense) -> `BaseDriver.crawl(conn)` -> `schema.stamp_schema_v2()`.
4. **Hop Expansion & Passive Enrichment**: `_discover_neighbor_and_subnet_hops()`, `_append_local_arp_inventory()`, `_enrich_partial_devices_http()` (`detector.probe_http_fingerprint()`), `_enrich_partial_devices_snmp()` (`snmp_collector.collect_snmp_fallback()`).
5. **Deduplication, Stitching & Correlation**: `reconcile_and_deduplicate_dataset()` -> `enrich_devices_from_dhcp_reservations()` -> `_stitch_dataset_topology()` (`DeviceRegistry.register_device()`, `resolve_neighbor_ip()`, `add_bidirectional_link()`, `reconcile_reciprocal_neighbors()`) -> `correlator.correlate_dataset()` (`correlate_device_ports()`, `compute_stp_root_consensus()`, `trunk_audit.evaluate_trunk_mismatches()`, `build_l3_svi_table()`).
6. **Quality Gates & Deliverable Rendering**: `quality_gates.evaluate_quality_gates()` -> `_write_standard_deliverables()` + `_write_optional_migration_deliverables()` + `export_layered_csvs()` + `topology_renderer.render_topology_deliverables()` (`report_generator.py`, `diagram_validator.py`, `target_adapters.py`).

---

## 2. Module Inventory (~31,064 LOC)

### Core Engine & Utilities

| Module | LOC | Responsibility |
| :--- | ---: | :--- |
| `net_docu_crawler/crawler.py` | 3,054 | CLI parser, credential loader/validator, multi-threaded crawl orchestrator, hop expansion, log sanitizer/reparser, deliverable export coordination. |
| `net_docu_crawler/ssh_compat.py` | 635 | 3-stage SSH compatibility ladder (`KexGroup18SHA512`, `LegacyDSSKey`, `disable_sha2_fix`), `LazySessionLog`, Netmiko & Paramiko fallback wrappers. |
| `net_docu_crawler/drivers/detector.py` | 805 | TCP port scanner, local ARP reader, HTTP/TLS fingerprinting, SNMPv2c sysinfo probe, non-network appliance classifier, 4-tier vendor/OS detector. |
| `oui_lookup.py` | 793 | Bundled offline IEEE OUI table (`COMMON_OUIS`), optional `oui.txt` loader, persistent `oui_cache.json` + optional online `api.macvendors.com` fallback, MAC normalizer. |
| `net_docu_crawler/snmp_collector.py` | 194 | Dependency-free BER SNMPv2c `GetBulk` collector (`sysDescr`, `sysName`, `ifTable`/`ifXTable`, LLDP remote table) for `--snmp` passive enrichment. |
| `net_docu_crawler/domain_detector.py` | 156 | Local OS DNS suffix + crawled device FQDN/config domain detector for organized output directory naming. |
| `net_docu_crawler/dependency_checker.py` | 127 | Pre-flight import check and interactive/auto `pip` installer (`netmiko`, `paramiko`, `netaddr`). |
| `net_docu_crawler/__init__.py` | 52 | Lazy package attribute exports (`__version__ = "2.0.0"`). |

### Drivers & Parsing (`net_docu_crawler/drivers/` + `parser.py` + `migration_parsers.py`)

| Module | LOC | Driver Class / Scope | Official Docs Reference |
| :--- | ---: | :--- | :--- |
| `net_docu_crawler/drivers/__init__.py` | 157 | `DRIVER_REGISTRY` (13 classes / 22 aliases), `VENDOR_DRIVER_MAP`, `DRIVER_VENDOR_MAP`, `get_driver()`. | — |
| `net_docu_crawler/drivers/base.py` | 627 | `BaseDriver` ABC (`crawl()` template method, `_safe_*` helpers), `extract_services_from_config()`, `sanitize_raw_config()`. | [Netmiko](https://github.com/ktbyers/netmiko) |
| `net_docu_crawler/drivers/cisco.py` | 583 | `CiscoDriver` (IOS, IOS-XE, NX-OS; delegates IOS-XR if detected in `crawl()`). | [Cisco IOS/NX-OS](https://www.cisco.com/c/en/us/support/ios-nx-os-software/index.html) |
| `net_docu_crawler/drivers/cisco_xr.py` | 579 | `CiscoXRDriver` (IOS-XR CLI + optional read-only NETCONF `ncclient` / gNMI `pygnmi`). *(Note: 13th driver; `README.md` currently says 12.)* | [Cisco IOS-XR](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xr-software/tsd-products-support-series-home.html) |
| `net_docu_crawler/drivers/ciscosmb.py` | 462 | `CiscoSMBDriver` (`cisco_s300`: SG250/SG300/SG350/SG500/CBS250/CBS350). | [Cisco SMB 300](https://www.cisco.com/c/en/us/support/switches/small-business-300-series-managed-switches/products-command-reference-list.html) |
| `net_docu_crawler/drivers/juniper.py` | 1,320 | `JuniperDriver` (`juniper_junos` JSON-first + text fallbacks; EX/QFX/MX/SRX). | [Juniper Junos OS](https://www.juniper.net/documentation/product/us/en/junos-os/) |
| `net_docu_crawler/drivers/arista.py` | 725 | `AristaDriver` (`arista_eos` JSON-first + text fallbacks). | [Arista EOS](https://www.arista.com/en/um-eos) |
| `net_docu_crawler/drivers/hpprocurve.py` | 859 | `HPProCurveDriver` (`hp_procurve` + `_CleanProCurveConn` ANSI/VT100 stripper). | [HPE ArubaOS-S](https://www.arubanetworks.com/techdocs/AOS-S/16.10/MWG/content/home.htm) |
| `net_docu_crawler/drivers/aruba.py` | 530 | `ArubaDriver` (`aruba_os`: Aruba Instant AP + Aruba AOS-CX dual-mode). | [Aruba AOS-CX](https://www.arubanetworks.com/techdocs/AOS-CX/help_portal/Content/home.htm) / [Instant](https://www.arubanetworks.com/techdocs/ArubaDocPortal/content/cons-instant-home.htm) |
| `net_docu_crawler/drivers/fortinet.py` | 307 | `FortinetDriver` (`fortinet` FortiGate FortiOS). | [FortiOS CLI Ref](https://docs.fortinet.com/document/fortigate/hardware/fortios-cli-reference) |
| `net_docu_crawler/drivers/paloalto.py` | 211 | `PaloAltoDriver` (`paloalto_panos` PAN-OS). | [PAN-OS Docs](https://docs.paloaltonetworks.com/pan-os) |
| `net_docu_crawler/drivers/mikrotik.py` | 347 | `MikroTikDriver` (`mikrotik_routeros` v6/v7). | [MikroTik RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/8519681/Command+Line+Interface) |
| `net_docu_crawler/drivers/opnsense.py` | 431 | `OPNsenseDriver` + `OPNsenseSSHConnection` (Paramiko `exec_command`) + `AuditedMissingHostKeyPolicy`. | [OPNsense Docs](https://docs.opnsense.org/) |
| `net_docu_crawler/drivers/openwrt.py` | 346 | `OpenWrtDriver` (`linux` + `ubus` JSON / `uci` / `ip` / `lldpcli`). | [OpenWrt Docs](https://openwrt.org/docs/start) |
| `net_docu_crawler/drivers/frr.py` | 315 | `FRRDriver` (`linux` + `vtysh -c` JSON + `ip -j` + `lldpcli`). | [FRRouting Docs](https://docs.frrouting.org/) |
| `parser.py` | 1,031 | Shared Cisco/EOS CLI text parsers (`parse_show_version`, `parse_show_inventory`, `parse_ip_interface_brief`, `parse_show_interfaces`, `parse_cdp/lldp_neighbors_detail`, `parse_spanning_tree`, `parse_show_ip_route`, `parse_services`, `parse_show_ip_arp`, `parse_mac_address_table`, `classify_device_type`). | — |
| `net_docu_crawler/migration_parsers.py` | 1,303 | Config-based parsers run in `BaseDriver.crawl()`: `extract_vlans()`, `extract_port_profiles()`, `extract_vrfs_and_acls()`, `extract_routing_peers_and_fhrp_from_config()`, `extract_dhcp_config()`, `extract_firewall_nat_vpn()`. | — |

### Topology, Correlation & Reporting

| Module | LOC | Responsibility |
| :--- | ---: | :--- |
| `net_docu_crawler/schema.py` | 172 | Schema v2.0 contract (`stamp_schema_v2`, `classify_record_class`, `normalize_tri_state`, `build_empty_port_record`, `build_empty_poe_summary`, `infer_site_code`). |
| `net_docu_crawler/topology_resolver.py` | 1,654 | `DeviceRegistry` (chassis dedupe, global ARP enrichment, bidirectional link stitching, reciprocal neighbor reconciliation, L2/L3 gap/MAC inference), `normalize_hostname()`, `normalize_interface()`. |
| `net_docu_crawler/correlator.py` | 325 | `correlate_device_ports()` (joins `interfaces_detail` + `port_profiles` + `poe` + `optics` + `neighbors` + `mac_table` + `vlans` into `dev["ports"]`), `compute_stp_root_consensus()`, `build_l3_svi_table()`, `correlate_dataset()`. |
| `net_docu_crawler/trunk_audit.py` | 1,982 | Cross-vendor `TrunkPortState` builder, LAG/subinterface bundle normalization, undirected trunk edge correlation, rules `TRK-001`–`TRK-007` + boundary diagnostics (`evaluate_trunk_mismatches()`). |
| `net_docu_crawler/topology_renderer.py` | 4,463 | Graph model builder (`build_topology_graph_model`, `_build_l3_graph`) and `InteractiveHTMLTopologyRenderer` (`render_topology_deliverables`). |
| `net_docu_crawler/quality_gates.py` | 292 | P0/P1 data quality gates (`GATE_CABLING_VLAN_EMPTY`, `GATE_POE_CONTRADICTION`, `GATE_STP_ROOT_EVIDENCE`, `GATE_TRUNK_NATIVE_UNKNOWN`, `GATE_TRUNK_VLAN_MISMATCH`) + `data_quality_report.md` / `collection_manifest.json`. |
| `net_docu_crawler/diagram_validator.py` | 45 | Mermaid 11.x syntax validator (`validate_mermaid_block`). |
| `net_docu_crawler/target_adapters.py` | 75 | Target-vendor CLI migration config generator (`render_device_target_config` for Juniper/Cisco/Arista/Aruba/ProCurve). |
| `report_generator.py` | 6,039 | All Markdown/CSV/JSON/shell deliverables: `Network_Analysis.md`, `L2_network_diagrams.md`, `L3_network_diagrams.md`, `net_docu_crawler_live_report.md`, `trunk_vlan_audit.md`, `asset_inventory.csv`, `bom_hardware_sizing.csv`, `migration_cabling_matrix.csv`, `port_mac_endpoint_mapping.csv`, `cisco_to_target_translation.md`, `validate_cutover.sh`, layered `00_manifest`..`05_reports` exports, baseline diffing. |

---

## 3. Feature Data Paths (`Driver -> Command -> Parser -> Model -> Report`)

### 3.1 Interfaces (`l3_interfaces` & `interfaces_detail`)
- **Drivers & Commands**:
  - `CiscoDriver`: `show ip interface brief`, `show interfaces` -> `parser.parse_ip_interface_brief()`, `parser.parse_show_interfaces()`
  - `CiscoXRDriver`: `show ipv4 interface brief`, `show interfaces` -> XR internal parsers
  - `CiscoSMBDriver`: `show ip interface`, `show interfaces status` -> SMB regex parsers
  - `JuniperDriver`: `show interfaces terse | display json` (text fallback), `show interfaces` -> Junos JSON/text parsers
  - `AristaDriver`: `show ip interface | json`, `show interfaces | json` (text fallbacks: `show ip interface brief`, `show interfaces`) -> EOS JSON / `parser.py`
  - `HPProCurveDriver`: `show ip`, `show name`, `show interfaces brief` -> ProCurve table parsers
  - `ArubaDriver`: `show ip interface brief`, `show interface brief` (AOS-CX) / `show aps` (IAP)
  - `FortinetDriver`: `show system interface` -> FortiOS `edit` block parser
  - `PaloAltoDriver`: `show interface all` -> PAN-OS tabular parser
  - `MikroTikDriver`: `/interface ethernet print detail`, `/ip address print detail` -> RouterOS key-value parser
  - `OPNsenseDriver`: `ifconfig -a` -> FreeBSD ifconfig parser
  - `OpenWrtDriver`: `ubus call network.interface dump`, `ip -d address show` -> JSON/iproute2 parser
  - `FRRDriver`: `vtysh -c 'show interface json'`, fallback `ip -s -j link show` + `ip -j -4 addr show`
- **Model**: `device_data["l3_interfaces"]` (`list[{interface, ip_address, status, protocol}]`), `device_data["interfaces_detail"]` (`dict[port, {status, admin_status, mac_address, description, speed, duplex, mtu, ...}]`) -> joined into `device_data["ports"]` by `correlator.correlate_device_ports()`.
- **Reports**: `report_generator.py` (`migration_cabling_matrix.csv`, `02_normalized/interfaces.csv`, `03_correlated/port_hygiene_summary.csv`, `net_docu_crawler_live_report.md` L1/L2 utilization/descriptions/errors, `L3_network_diagrams.md`, `Network_Analysis.md` cabling/MTU, `bom_hardware_sizing.csv`).

### 3.2 VLANs (`vlans`)
- **Drivers & Commands**: No dedicated operational `show vlan` command on any driver! Populated exclusively from `get_running_config(conn)` (`show running-config`, `show configuration | display set`, `show full-configuration`, `show config running`, `/export compact`, `cat /conf/config.xml`, `uci export`, `vtysh -c 'show running-config'`).
- **Parser**: `migration_parsers.extract_vlans(raw_config, vendor)` (supports Cisco/Arista/ProCurve `vlan <id>` blocks and Junos `set vlans` / brace `vlans { ... }` blocks; no parser for FortiOS/OPNsense/OpenWrt/MikroTik/PAN-OS VLANs).
- **Model**: `device_data["vlans"]` (`dict[vlan_id, {id, name, svi_interface, voice, description}]`).
- **Reports**: `02_normalized/vlans.csv`, `03_correlated/vlan_propagation.csv`, `Network_Analysis.md` VLAN table, `L3_network_diagrams.md`, `trunk_audit.py` known VLAN DB.

### 3.3 SVIs / IRBs (`l3_svi_table`)
- **Drivers & Commands**: Derived from `get_interfaces(conn)` (`l3_interfaces`) + `get_running_config(conn)` (`vlans`) + DHCP relays (`dhcp["relays"]`).
- **Parser & Correlator**: `correlator.build_l3_svi_table(raw_devices)` matches `l3_interfaces` (`Vlan*`, `Vl*`, `irb.*`, `DEFAULT_VLAN`, or `vlans[vid]["svi_interface"]`) and computes CIDR via `ipaddress.IPv4Interface`. Also `report_generator.parse_interface_network()` uses [netaddr](https://netaddr.readthedocs.io/).
- **Model**: Returned in `correlate_dataset()["l3_svi_table"]` (not persisted on individual device dicts, recomputed during report export).
- **Reports**: `02_normalized/l3_svi_map.csv`, `03_correlated/vlan_propagation.csv`, `Network_Analysis.md` VLAN/SVI section (`_render_blueprint_vlan_and_trunk_section`), `L3_network_diagrams.md`, `topology_renderer._build_l3_graph()`.

### 3.4 Trunks / Native VLAN / LAG (`port_profiles`, `ports`, `trunk_audit`)
- **Drivers & Commands**:
  - Config intent (`get_running_config()`): `migration_parsers.extract_port_profiles()` (Cisco/Arista/CiscoSMB, Aruba AOS-CX, HP ProCurve, Juniper Junos including `interface-range` & L3 subinterfaces).
  - Live operational (`get_l2_operational()`):
    - `CiscoDriver`: `show interfaces trunk`, `show etherchannel summary`
    - `CiscoXRDriver`: `show bundle`
    - `CiscoSMBDriver`: `show interfaces switchport`, `show interfaces port-channel`
    - `JuniperDriver`: `show ethernet-switching interfaces | display json` (+ text), `show lacp interfaces | display json`, `show spanning-tree interface | display json`, `show dot1x interface | display json`
    - `AristaDriver`: `show interfaces trunk | json` (+ text), `show port-channel summary | json` (+ text)
    - `ArubaDriver`: `show interface trunk`, `show lacp interfaces` (AOS-CX only)
    - `HPProCurveDriver`: `show trunks`, `show lacp`, `show vlans ports all`, `show spanning-tree detail`, `show port-access authenticator`
    - `FortinetDriver`, `PaloAltoDriver`, `MikroTikDriver`, `OPNsenseDriver`, `OpenWrtDriver`, `FRRDriver`: default empty `{}`.
- **Correlator & Audit**: `BaseDriver.crawl()` merges `get_l2_operational()` into `device_data["port_profiles"]` -> `correlator.correlate_device_ports()` populates `dev["ports"]` -> `trunk_audit.evaluate_trunk_mismatches()` evaluates `TRK-001`–`TRK-007`.
- **Reports**: `trunk_vlan_audit.md` (`05_reports/trunk_vlan_audit.md`), `03_correlated/trunk_audit.json`, `03_correlated/trunk_mismatches.csv`, `Network_Analysis.md`, `net_docu_crawler_live_report.md`, `00_manifest/data_quality_report.md` (`GATE_TRUNK_*`).

### 3.5 Spanning Tree (`stp`)
- **Drivers & Commands**:
  - `CiscoDriver`: `show spanning-tree` -> `parser.parse_spanning_tree()`
  - `CiscoSMBDriver`: `show spanning-tree` -> `parser.parse_spanning_tree()`
  - `JuniperDriver`: `show spanning-tree bridge | display json` (+ text)
  - `AristaDriver`: `show spanning-tree | json` (+ text `parser.parse_spanning_tree()`)
  - `HPProCurveDriver`: `show spanning-tree`
  - All other drivers (`CiscoXR`, `Aruba`, `Fortinet`, `PaloAlto`, `MikroTik`, `OPNsense`, `OpenWrt`, `FRR`): default `BaseDriver.get_stp()` -> `{"enabled": False, "vlans": {}}`.
- **Model & Correlator**: `device_data["stp"]` (`{enabled, is_root, root_bridge, vlans, ...}`) -> `correlator.compute_stp_root_consensus()` sets `is_verified_campus_root` and `root_scope`.
- **Reports**: `net_docu_crawler_live_report.md` (`_render_stp_audit_section`), `Network_Analysis.md` (`_render_blueprint_stp_section`), `L2_network_diagrams.md` (root styling), `topology_renderer.py`, `quality_gates.py` (`GATE_STP_ROOT_EVIDENCE`).

### 3.6 Neighbor Discovery — LLDP / CDP / MNDP (`neighbors`, `discovery_protocols`)
- **Drivers & Commands**:
  - `CiscoDriver`: `show cdp neighbors detail`, `show lldp neighbors detail`, `show lldp neighbors` -> `parser.parse_cdp_neighbors_detail()`, `parser.parse_lldp_neighbors_detail()`
  - `CiscoXRDriver`: `show lldp neighbors detail`, `show cdp neighbors detail`
  - `CiscoSMBDriver`: `show lldp neighbors`
  - `JuniperDriver`: `show lldp neighbors detail | display json` (+ text), `show lldp neighbors | display json` (+ text)
  - `AristaDriver`: `show lldp neighbors detail | json`
  - `HPProCurveDriver`: `show lldp info remote-device`, `show lldp info remote-device detail`, `show cdp neighbor detail`
  - `ArubaDriver`: `show lldp neighbor-info detail` (AOS-CX) / `show ap debug lldp info` (IAP)
  - `FortinetDriver`: `diagnose snmp sysinfo lldp neighbor`, `diagnose lldp neighbor list`, `get switch lldp neighbors-summary`
  - `PaloAltoDriver`: `show lldp neighbors all`
  - `MikroTikDriver`: `/ip neighbor print detail` (MNDP/CDP/LLDP)
  - `OPNsenseDriver`: `lldpctl -f json` (+ `command -v lldpctl`)
  - `OpenWrtDriver`: `lldpcli show neighbors -f json` (+ `command -v lldpcli`), `ubus call hostapd.* get_clients`
  - `FRRDriver`: `lldpcli show neighbors -f json` (+ `command -v lldpcli`)
- **Model & Resolver**: `device_data["neighbors"]`, `device_data["discovery_protocols"]` -> stitched in `crawler._stitch_dataset_topology()` via `DeviceRegistry.add_bidirectional_link()`, `resolve_neighbor_ip()`, `reconcile_reciprocal_neighbors()`.
- **Reports**: `L2_network_diagrams.md`, `migration_cabling_matrix.csv`, `02_normalized/neighbors.csv`, `03_correlated/physical_links.csv`, `Network_Analysis.md` Section 1.1 & cabling, interactive HTML topology (`topology_renderer.py`).

### 3.7 ARP Table (`arp_table`, `global_arp`)
- **Drivers & Commands**:
  - `CiscoDriver`: `show ip arp` (`parser.parse_show_ip_arp`)
  - `CiscoXRDriver`: `show arp`
  - `CiscoSMBDriver`: `show arp`
  - `JuniperDriver`: `show arp no-resolve | display json` (+ text)
  - `AristaDriver`: `show ip arp | json` (+ text)
  - `HPProCurveDriver`: `show arp`
  - `ArubaDriver`: `show arp` (AOS-CX) / `show clients` (IAP)
  - `FortinetDriver`: `get system arp`
  - `PaloAltoDriver`: `show arp all`
  - `MikroTikDriver`: `/ip arp print detail`
  - `OPNsenseDriver`: `arp -an`
  - `OpenWrtDriver`: `cat /proc/net/arp`
  - `FRRDriver`: `ip -j neigh show`
- **Model & Resolver**: `device_data["arp_table"]` (`list[{ip, mac, interface, age, type, vendor}]`) -> ingested into `DeviceRegistry.global_arp` for MAC-to-IP neighbor resolution and endpoint enrichment.
- **Reports**: `port_mac_endpoint_mapping.csv`, `asset_inventory.csv` (passive endpoints), `L2_network_diagrams.md` (neighbor IP resolution), `crawler._select_hop_targets_for_cidrs()`.

### 3.8 MAC Forwarding Tables (`mac_table`)
- **Drivers & Commands**:
  - `CiscoDriver`: `show mac address-table` (`parser.parse_mac_address_table`)
  - `CiscoSMBDriver`: `show mac address-table`
  - `JuniperDriver`: `show ethernet-switching table | display json` (+ text)
  - `AristaDriver`: `show mac address-table | json` (+ text)
  - `HPProCurveDriver`: `show mac-address`
  - All other drivers: default `BaseDriver.get_mac_table()` -> `[]`.
- **Model & Correlator**: `device_data["mac_table"]` -> port MAC counts in `correlator.correlate_device_ports()` (`edge_mac_count` / `trunk_mac_count`) + MAC-inferred links in `topology_resolver.py`.
- **Reports**: `port_mac_endpoint_mapping.csv`, `03_correlated/endpoint_attachment.csv`, `Network_Analysis.md` (`_render_blueprint_mac_mapping_section`).

### 3.9 Routes, Routing Peers, VRFs & MPLS (`routes`, `routing_peers`, `vrfs`, `mpls`)
- **Drivers & Commands**:
  - **Routes (`get_routing_table`)**: `Cisco` (`show ip route`), `CiscoXR` (`show route`), `CiscoSMB` (`show ip route`), `Juniper` (`show route | display json` / `show route table inet.0`), `Arista` (`show ip route | json` / `show ip route`), `HPProCurve` (`show ip route`), `Aruba` (`show ip route` on AOS-CX only), `Fortinet` (`get router info routing-table all`), `PaloAlto` (`show routing route`), `MikroTik` (`/ip route print detail`), `OPNsense` (`netstat -rnW -f inet` / `netstat -rn -f inet`), `OpenWrt` (`ip route show || route -n`), `FRR` (`vtysh -c 'show ip route json'` / `ip -j route show`).
  - **Live Routing Peers / VRFs / MPLS**: Only `CiscoXRDriver` implements `get_routing_peers()` (`show bgp all all summary`, `show bgp vrf all summary`, `show ospf neighbor`, `show isis neighbors`), `get_vrfs()` (`show vrf all detail`), and `get_mpls_ldp()` (`show mpls ldp neighbor brief`, `show mpls ldp interface`, `show mpls forwarding-table`). All other drivers fall back to config-only parsing via `migration_parsers.extract_routing_peers_and_fhrp_from_config()` and `extract_vrfs_and_acls()`.
- **Model**: `device_data["routes"]`, `device_data["routing_peers"]`, `device_data["vrfs"]`, `device_data["mpls"]`.
- **Reports**: `L3_network_diagrams.md`, `net_docu_crawler_live_report.md` (`_render_routing_protocols_and_tables_section`, `_render_poe_and_control_plane_section`), `Network_Analysis.md` (`_render_blueprint_fhrp_and_routing_section`), `topology_renderer._build_l3_graph()`.

### 3.10 DHCP & DHCP Relay (`dhcp`, `services["dhcp_relays"]`)
- **Drivers & Commands**: No dedicated live DHCP operational command; parsed from `get_running_config(conn)`.
- **Parsers**:
  - `migration_parsers.extract_dhcp_config(raw_config, vendor)` -> `device_data["dhcp"] = {"pools": [...], "reservations": [...], "relays": [{"interface", "helper_ip"}]}` (Cisco/Arista, HP ProCurve, Junos, OPNsense XML, OpenWrt UCI, FortiOS).
  - `base.extract_services_from_config(raw_config)` -> `device_data["services"]["dhcp_relays"]` (flat list of helper IPs).
- **Correlator & Enricher**: `correlator.build_l3_svi_table()` joins `dhcp["relays"]` onto SVI rows; `crawler.enrich_devices_from_dhcp_reservations()` enriches passive/unauthenticated endpoints with DHCP hostnames.
- **Reports**: `Network_Analysis.md` (`_render_blueprint_dhcp_relay_section`), `net_docu_crawler_live_report.md` (`_render_dhcp_and_port_intent_section`), `02_normalized/l3_svi_map.csv`.

### 3.11 FHRP — HSRP / VRRP / CARP (`fhrp`)
- **Drivers & Commands**:
  - Live operational (`get_fhrp()`): Only `CiscoXRDriver` (`show hsrp summary`, `show vrrp summary`). All other drivers inherit default `[]`.
  - Config fallback: `migration_parsers.extract_routing_peers_and_fhrp_from_config()` parses Cisco/Arista `standby`/`vrrp` interface lines and OPNsense `<virtualip><vip>` CARP/IPAlias XML.
- **Model**: `device_data["fhrp"]` (`list[{protocol, group, interface, vip, priority, state}]`).
- **Reports**: `Network_Analysis.md` (`_render_blueprint_fhrp_and_routing_section`), `net_docu_crawler_live_report.md` (`_render_poe_and_control_plane_section`), `L3_network_diagrams.md`.

### 3.12 Infrastructure Services (`services`: DNS, NTP, RADIUS, TACACS+, Syslog, SNMP)
- **Drivers & Commands**: Parsed from `get_running_config(conn)` via `BaseDriver.get_services()` -> `base.extract_services_from_config(raw_config)`. *(Note: `parser.parse_services()` also exists in `parser.py` for legacy/direct Cisco parsing.)*
- **Model**: `device_data["services"]` (`{dns_servers, ntp_servers, radius_servers, tacacs_servers, dhcp_relays, syslog_servers, snmp_servers}`).
- **Reports**: `net_docu_crawler_live_report.md` (`_render_l4_l7_services_and_gaps_section`), `Network_Analysis.md` Section 10 (`_render_blueprint_security_and_services_section`), `migration_config_variables.json`.

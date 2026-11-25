<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Phase 3 File-Lock & Merge-Wave Plan

To guarantee **zero merge conflicts** and **zero concurrent edits to the same file** during Phase 3, every tracked file is assigned to exactly one agent per wave. Shared touchpoint files (`net_docu_crawler/crawler.py`, `net_docu_crawler/drivers/base.py`, `net_docu_crawler/drivers/opnsense.py`, `tests/test_drivers.py`) are strictly serialized across merge waves: the next wave owner MUST branch/rebase from `swarm/integration` **after** the prior wave merges and `@integrator` announces lock release.

---

## 1. Exclusive File Ownership (Parallel-Safe Across Workers)

| Agent | Branch Namespace | Exclusively Owned Source Files | Exclusively Owned Test / Harness Files |
| :--- | :--- | :--- | :--- |
| `integrator` | `swarm/integration` | `SWARM/**` | — |
| `test-verifier` | `swarm/test-verifier/*` | `.gitignore` *(fixture exception only)* | `tests/conftest.py`, `tests/fixtures/**`, `tests/helpers/**`, `tests/test_e2e_offline_pipeline.py`, `tests/test_fixture_hygiene.py`, `tests/test_deliverable_consistency.py`, `tests/test_drivers.py` *(shared legacy suite)* |
| `transport` | `swarm/transport/*` | `net_docu_crawler/ssh_compat.py` | `tests/test_ssh_compat.py`, `tests/test_transport_*.py`, `tests/test_crawler_aaa_safety.py` |
| `discovery` | `swarm/discovery/*` | `net_docu_crawler/drivers/detector.py`, `oui_lookup.py`, `net_docu_crawler/drivers/__init__.py`, `net_docu_crawler/target_adapters.py`, `net_docu_crawler/snmp_collector.py` | `tests/test_oui.py`, `tests/test_snmp_collector.py`, `tests/test_target_adapters.py`, `tests/test_discovery_*.py`, `tests/test_detector_*.py`, `tests/test_target_parsing.py` |
| `drivers-enterprise` | `swarm/drivers-enterprise/*` | `net_docu_crawler/drivers/cisco.py`, `net_docu_crawler/drivers/cisco_xr.py`, `net_docu_crawler/drivers/ciscosmb.py`, `net_docu_crawler/drivers/juniper.py`, `net_docu_crawler/drivers/arista.py`, `parser.py` | `tests/test_cisco_xr.py`, `tests/test_parser.py`, `tests/test_drivers_enterprise.py` |
| `drivers-edge` | `swarm/drivers-edge/*` | `net_docu_crawler/drivers/fortinet.py`, `net_docu_crawler/drivers/paloalto.py`, `net_docu_crawler/drivers/aruba.py`, `net_docu_crawler/drivers/hpprocurve.py` | `tests/test_drivers_edge.py` |
| `drivers-oss` | `swarm/drivers-oss/*` | `net_docu_crawler/drivers/mikrotik.py`, `net_docu_crawler/drivers/openwrt.py`, `net_docu_crawler/drivers/frr.py`, `net_docu_crawler/drivers/_lldpd.py` *(new shared helper if added)* | `tests/test_drivers_oss.py` |
| `topology` | `swarm/topology/*` | `net_docu_crawler/topology_resolver.py`, `net_docu_crawler/correlator.py`, `net_docu_crawler/trunk_audit.py`, `net_docu_crawler/topology_renderer.py`, `net_docu_crawler/domain_detector.py` | `tests/test_topology_resolver.py`, `tests/test_correlator.py`, `tests/test_trunk_audit.py`, `tests/test_topology_renderer.py`, `tests/test_topology_gaps.py`, `tests/test_domain_detector.py`, `tests/test_trunk_vendor_parsers.py` |
| `reports` | `swarm/reports/*` | `report_generator.py`, `net_docu_crawler/schema.py`, `net_docu_crawler/quality_gates.py`, `net_docu_crawler/diagram_validator.py`, `net_docu_crawler/migration_parsers.py` | `tests/test_reports.py`, `tests/test_report_generator_audit.py`, `tests/test_schema.py`, `tests/test_quality_gates.py`, `tests/test_diagram_validator.py`, `tests/test_migration_blueprint.py`, `tests/test_trunk_reporting.py`, `tests/test_report_truthfulness.py`, `tests/test_csv_and_markdown_escaping.py` |
| `docs-config` | `swarm/docs-config/*` | `README.md`, `CONTRIBUTING.md`, `docs/junior_operator_playbook.md`, `docs/windows_operator_guide.md`, `docs/man/net-crawler.1.md`, `docs/drivers/*.md`, `docs/proxmox_lab_and_driver_roadmap.md`, `credentials.example.json`, `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `run.sh`, `run.ps1`, `setup_windows.ps1`, `net_crawler.py`, `net_docu_crawler/__main__.py`, `net_docu_crawler/__init__.py`, `net_docu_crawler/dependency_checker.py` | `tests/test_dependency_checker.py`, `tests/test_credentials_cli.py`, `tests/test_docs_consistency.py`, `tests/test_packaging_consistency.py` |
| `safety-reviewer` | *(Read-Only Veto)* | **NONE** — strictly read-only reviewer; `integrator` commits `SWARM/command_allowlist.md` on its behalf. | **NONE** |

---

## 2. Serialized Locks for Shared Touchpoint Files

Only **one** agent may hold a lock on a shared file at any time. Handoff occurs only after `@integrator` merges the preceding wave into `swarm/integration` and posts lock release.

| Shared File | Wave 1 Lock Holder | Wave 2 Lock Holder | Wave 3 Lock Holder |
| :--- | :--- | :--- | :--- |
| `net_docu_crawler/drivers/base.py` | `transport` (`_build_netmiko_params` 4.x timeouts, paging verification hook, `sanitize_raw_config()` multi-vendor secret coverage, `supports_telnet`) | `reports` (`collection_status` / `parse_errors` telemetry contract in `crawl()`, `extract_services_from_config()` fixes) | — |
| `net_docu_crawler/drivers/opnsense.py` | `transport` (`OPNsenseSSHConnection`, Paramiko `allow_agent`/`look_for_keys`/timeout/stderr/exit-status/cleanup, `connect()`, `supports_telnet = False`) | `drivers-oss` (data-collection commands & parsers: `ifconfig`, `arp`, `lldpctl` via shared helper, `netstat`) | — |
| `net_docu_crawler/crawler.py` | `transport` (AAA 1-attempt-per-username host-scoped cap, `connect()` vs `crawl()` error separation, thread-safe `_log_event()` + secret scrubbing, `_crawl_target_batch` `in_progress_ips` cleanup) | `discovery` (IPv6/port target parsing, dual-stack TCP probe timeout, Tier 3 `inspect_prompt_os()` wiring, `--vendor-hint` override, vendor-alias credential sorting, lazy `DEFAULT_TARGETS`, `/31` & IPv6 hop guards) | `docs-config` (`enable_secret` alias & strict `validate_credentials()`, `--netconf`/`--gnmi`/`--install-deps`/`--organize`/`--output-dir`/`--target-vendor` CLI wiring) |
| `report_generator.py` *(topology helper sync)* | `topology` exposes canonical `normalize_interface`, `infer_interface_speed`, `dedupe_devices`, `detect_cidr_overlaps` in `topology_resolver.py` (does NOT edit `report_generator.py`) | `reports` imports/delegates to those canonical helpers inside `report_generator.py` alongside `RP-01`..`RP-16` | — |
| `tests/test_drivers.py` | `test-verifier` (shared legacy suite updates, e.g. `TV-06` 13-driver contract test & `DO-24` stale mock alignment; individual driver agents put new regression tests in `tests/test_drivers_<group>.py`) | — | — |

---

## 3. Lock Protocol Rules

1. **No Unlisted Edits**: No worker may modify a file outside its row in Section 1 or its active wave in Section 2 without first requesting a lock transfer through `@integrator`.
2. **Safety & Verification Gates**: Every fix branch MUST pass `@safety-reviewer` veto inspection (zero write-capable commands, no leaked secrets, no weakened timeouts/AAA protections, no `scratch/` or `credentials.json`) and `@test-verifier` verification (`ruff check .`, `ruff format --check .`, `pytest -v` with regression tests failing before fix and passing after) before `@integrator` merges it into `swarm/integration`.
3. **Never Touch `main` or Secrets**: `credentials.json`, `/home/leifdavisson/projects/net-docu-crawler`, and branch `main` are permanently read-only / off-limits to all agents.

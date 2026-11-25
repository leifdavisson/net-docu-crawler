<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Phase 3 File-Lock & Merge-Wave Plan

To guarantee **zero merge conflicts** and **zero concurrent edits to the same file** during Phase 3, every tracked file is assigned to exactly one agent per wave. Shared touchpoint files (`net_docu_crawler/crawler.py`, `net_docu_crawler/drivers/base.py`, `net_docu_crawler/drivers/opnsense.py`, `tests/test_drivers.py`) are strictly serialized across merge waves: the next wave owner MUST branch/rebase from `swarm/integration` **after** the prior wave merges.

---

## 1. Exclusive File Ownership (Parallel-Safe Across Workers)

| Agent | Branch Namespace | Exclusively Owned Source Files | Exclusively Owned Test Files |
| :--- | :--- | :--- | :--- |
| `integrator` | `swarm/integration` | `SWARM/**` | — |
| `transport` | `swarm/transport/*` | `net_docu_crawler/ssh_compat.py` | `tests/test_ssh_compat.py`, `tests/test_transport.py` *(new)* |
| `discovery` | `swarm/discovery/*` | `net_docu_crawler/drivers/detector.py`, `oui_lookup.py`, `net_docu_crawler/drivers/__init__.py`, `net_docu_crawler/target_adapters.py`, `net_docu_crawler/snmp_collector.py` | `tests/test_oui.py`, `tests/test_snmp_collector.py`, `tests/test_target_adapters.py`, `tests/test_discovery.py` *(new)* |
| `drivers-enterprise` | `swarm/drivers-enterprise/*` | `net_docu_crawler/drivers/cisco.py`, `net_docu_crawler/drivers/cisco_xr.py`, `net_docu_crawler/drivers/ciscosmb.py`, `net_docu_crawler/drivers/juniper.py`, `net_docu_crawler/drivers/arista.py`, `parser.py` | `tests/test_cisco_xr.py`, `tests/test_parser.py`, `tests/test_drivers_enterprise.py` *(new)* |
| `drivers-edge` | `swarm/drivers-edge/*` | `net_docu_crawler/drivers/fortinet.py`, `net_docu_crawler/drivers/paloalto.py`, `net_docu_crawler/drivers/aruba.py`, `net_docu_crawler/drivers/hpprocurve.py` | `tests/test_drivers_edge.py` *(new)* |
| `drivers-oss` | `swarm/drivers-oss/*` | `net_docu_crawler/drivers/mikrotik.py`, `net_docu_crawler/drivers/openwrt.py`, `net_docu_crawler/drivers/frr.py` | `tests/test_drivers_oss.py` *(new)* |
| `topology` | `swarm/topology/*` | `net_docu_crawler/topology_resolver.py`, `net_docu_crawler/correlator.py`, `net_docu_crawler/trunk_audit.py`, `net_docu_crawler/topology_renderer.py`, `net_docu_crawler/domain_detector.py` | `tests/test_topology_resolver.py`, `tests/test_correlator.py`, `tests/test_trunk_audit.py`, `tests/test_topology_renderer.py`, `tests/test_topology_gaps.py`, `tests/test_domain_detector.py`, `tests/test_trunk_vendor_parsers.py` |
| `reports` | `swarm/reports/*` | `report_generator.py`, `net_docu_crawler/schema.py`, `net_docu_crawler/quality_gates.py`, `net_docu_crawler/diagram_validator.py`, `net_docu_crawler/migration_parsers.py` | `tests/test_reports.py`, `tests/test_report_generator_audit.py`, `tests/test_schema.py`, `tests/test_quality_gates.py`, `tests/test_diagram_validator.py`, `tests/test_migration_blueprint.py`, `tests/test_trunk_reporting.py` |
| `docs-config` | `swarm/docs-config/*` | `README.md`, `docs/junior_operator_playbook.md`, `docs/man/net-crawler.1.md`, `docs/drivers/*.md`, `credentials.example.json`, `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `net_crawler.py`, `net_docu_crawler/__main__.py`, `net_docu_crawler/dependency_checker.py` | `tests/test_dependency_checker.py`, `tests/test_docs_config.py` *(new)* |
| `test-verifier` | `swarm/test-verifier/*` | *(No production code edits)* | `tests/fixtures/**`, `tests/helpers/**`, `tests/test_e2e_pipeline.py` *(new)*, `tests/test_deliverable_consistency.py`, `tests/test_drivers.py` *(shared legacy suite)* |
| `safety-reviewer` | *(Read-Only Veto)* | **NONE** — strictly read-only reviewer; `integrator` commits `SWARM/command_allowlist.md` on its behalf. | **NONE** |

---

## 2. Serialized Locks for Shared Touchpoint Files

Only **one** agent may hold a lock on a shared file at any time. Handoff occurs only after `@integrator` merges the preceding branch into `swarm/integration` and posts lock release.

| Shared File | Wave 1 Lock Holder | Wave 2 Lock Holder | Wave 3 Lock Holder |
| :--- | :--- | :--- | :--- |
| `net_docu_crawler/drivers/base.py` | `transport` (timeouts, session lifecycle, paging verification, `_safe_*` helpers) | `reports` (`collection_status` / `parse_errors` telemetry contract in `crawl()`) | `drivers-*` *(only if `extract_services_from_config()` needs vendor syntax additions; sequential by approval)* |
| `net_docu_crawler/drivers/opnsense.py` | `transport` (`OPNsenseSSHConnection`, Paramiko channel timeout/stderr/cleanup, `connect()`) | `drivers-oss` (data-collection commands & parsers: `ifconfig`, `arp`, `lldpctl`, `netstat`) | — |
| `net_docu_crawler/crawler.py` | `transport` (session try/finally, AAA lockout caps, thread-safety) | `discovery` (target/CIDR parsing, port pre-check, `_identify_port_vendor`, credential ordering) | `docs-config` (CLI flags wiring & `credentials.json` schema/alias validation) |
| `tests/test_drivers.py` | `test-verifier` (shared harness/fixture alignment; individual driver agents add new regression tests in their own `tests/test_drivers_<group>.py` to avoid lock contention) | — | — |

---

## 3. Lock Protocol Rules

1. **No Unlisted Edits**: No worker may modify a file outside its row in Section 1 or its active wave in Section 2 without first requesting a lock transfer through `@integrator`.
2. **Safety Gate**: Every fix branch MUST pass `@safety-reviewer` veto inspection (zero write-capable commands, no leaked secrets, no weakened timeouts/AAA protections) and `@test-verifier` verification (`ruff check .` + `pytest -v` with regression tests) before `@integrator` merges it into `swarm/integration`.
3. **Never Touch `main` or Secrets**: `credentials.json`, `/home/leifdavisson/projects/net-docu-crawler`, and branch `main` are permanently read-only / off-limits to all agents.

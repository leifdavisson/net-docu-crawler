<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Swarm Phase 1 Baseline Report

## 1. Repository & Branch State

- **Integration Branch**: `swarm/integration` (branched from `HEAD` `1f2cdc6`, tag `v1.0.0`)
- **Base Commit**: `1f2cdc6 feat(topology,drivers): add interactive renderer, IOS-XR driver, and L2/L3 topology gap support`
- **Worktree Path**: `/home/leifdavisson/.gemini/antigravity-cli/worktrees/ee6d99e7-90e0-42dd-9485-7e2a66403d70/swarm-integrator-e6c6b2ea`
- **Parent Repository (`main`) Read-Only Status**: `/home/leifdavisson/projects/net-docu-crawler` has uncommitted WIP changes (not touched by this swarm):
  - Modified (7 tracked files, `+512 / -50` lines):
    - `net_docu_crawler/crawler.py`
    - `net_docu_crawler/drivers/detector.py`
    - `net_docu_crawler/topology_renderer.py`
    - `oui_lookup.py`
    - `tests/test_drivers.py`
    - `tests/test_oui.py`
    - `tests/test_topology_renderer.py`
  - Untracked (1 file):
    - `tests/conftest.py` (adds autouse `_hermetic_offline_oui_lookup` fixture forcing `NET_DOCU_OFFLINE_OUI=1` and isolated OUI cache paths)
- **Worktree WIP Cleanup (Phase 3 Pre-Flight)**: Per `@coordinator` `#24`, our worktree's inherited unstaged WIP was cleaned (`git checkout -- . && git clean -fd`) so `swarm/integration` starts cleanly atop `1f2cdc6` + `SWARM/` commits (`3a359f9`, `8743ac1`), while parent `/home/leifdavisson/projects/net-docu-crawler` remains untouched.

---

## 2. Static Analysis Baseline (`ruff`)

Command: `ruff check .` (using [Ruff](https://docs.astral.sh/ruff/))

| State | Exit Code | Errors / Warnings |
| :--- | :---: | :--- |
| Pre-clean worktree (inherited WIP) | `0` | `0` (`All checks passed!`) |
| Clean `swarm/integration` (`1f2cdc6` + `SWARM/`) | `0` | `0` (`All checks passed!`) |

---

## 3. Unit Test Baseline (`pytest`)

Command: `pytest -v` (using [pytest](https://docs.pytest.org/) `9.0.3` on Python `3.14.8`, Linux)

### 3.1 Clean `swarm/integration` Baseline (`1f2cdc6` + `SWARM/`, Post-Cleanup)

| Metric | Count |
| :--- | :---: |
| Collected | `242` |
| Passed | `230` |
| Failed | `3` *(pre-existing offline missing-OUI failures on clean `1f2cdc6`)* |
| Skipped | `9` |
| Duration | `13.24s` |
| Exit Code | `1` |

**Pre-existing clean-`1f2cdc6` offline OUI failures** (pass only when untracked `oui.txt`/live `api.macvendors.com` or parent WIP `COMMON_OUIS` is present; resolved by Wave 1 `swarm/discovery/oui-and-mac-guards`):
1. `tests/test_drivers.py::test_juniper_neighbors_port_priority_and_text_classification` — OUI `60:D0:2C` (`Ruckus Wireless`) absent from `1f2cdc6` `COMMON_OUIS`.
2. `tests/test_drivers.py::test_wan_gateway_synthesis_and_reciprocal_port_resolution` — OUI `44:AA:50` (`Juniper Networks`) absent from `1f2cdc6` `COMMON_OUIS`.
3. `tests/test_reports.py::test_l2_and_l3_norris_multi_site_link_types_conflicts_and_wireless_overlay` — OUIs `60:D0:2C` & `10:F0:68` (`Ruckus Wireless`) absent from `1f2cdc6` `COMMON_OUIS`.

### 3.2 Initial Inherited-WIP Worktree Snapshot (Pre-Cleanup Reference)

| Metric | Count |
| :--- | :--- |
| Collected | `245` |
| Passed | `236` |
| Failed | `0` |
| Skipped | `9` |
| Duration | `9.97s` |
| Exit Code | `0` |

### Per-File Breakdown

| Test File | Passed | Failed | Skipped |
| :--- | :---: | :---: | :---: |
| `tests/test_cisco_xr.py` | 4 | 0 | 0 |
| `tests/test_correlator.py` | 3 | 0 | 0 |
| `tests/test_deliverable_consistency.py` | 1 | 0 | 9 |
| `tests/test_dependency_checker.py` | 7 | 0 | 0 |
| `tests/test_diagram_validator.py` | 1 | 0 | 0 |
| `tests/test_domain_detector.py` | 6 | 0 | 0 |
| `tests/test_drivers.py` | 77 | 0 | 0 |
| `tests/test_migration_blueprint.py` | 10 | 0 | 0 |
| `tests/test_oui.py` | 9 | 0 | 0 |
| `tests/test_parser.py` | 12 | 0 | 0 |
| `tests/test_quality_gates.py` | 2 | 0 | 0 |
| `tests/test_report_generator_audit.py` | 5 | 0 | 0 |
| `tests/test_reports.py` | 13 | 0 | 0 |
| `tests/test_schema.py` | 4 | 0 | 0 |
| `tests/test_snmp_collector.py` | 2 | 0 | 0 |
| `tests/test_ssh_compat.py` | 12 | 0 | 0 |
| `tests/test_target_adapters.py` | 2 | 0 | 0 |
| `tests/test_topology_gaps.py` | 4 | 0 | 0 |
| `tests/test_topology_renderer.py` | 8 | 0 | 0 |
| `tests/test_topology_resolver.py` | 7 | 0 | 0 |
| `tests/test_trunk_audit.py` | 34 | 0 | 0 |
| `tests/test_trunk_reporting.py` | 4 | 0 | 0 |
| `tests/test_trunk_vendor_parsers.py` | 9 | 0 | 0 |
| **Total** | **236** | **0** | **9** |

### Skipped Test Inventory (`tests/test_deliverable_consistency.py`)

All 9 skips are environment-gated live-deliverable assertions:
1. Lines `60`, `106`, `133`, `160`, `181`, `201`, `219`, `284` (8 skips): `"Full live crawl deliverables (>=8 devices) not present in docs/net_docu_crawler/"`
2. Line `257` (1 skip): `"Local lab backup not present"`

---

## 4. Guardrail Attestation

- Zero live network connections or device probes performed.
- `credentials.json` was never read, printed, logged, or staged.
- Parent repository `/home/leifdavisson/projects/net-docu-crawler` was inspected read-only (`git status --short`) and never modified.
- All swarm work occurs strictly on local branch `swarm/integration` (no commits to `main`, no pushes).

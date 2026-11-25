<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Phase 1 Findings: `test-verifier` (Role 8 — Test & Verification)

Source: Swarm Board `#13` (`test-verifier`, 2026-11-24 20:13:24)

## 1. Baseline & Existing Test Inventory

- **Gates (worktree @ `1f2cdc6` + inherited WIP)**:
  - `ruff check .`: **PASS** (`All checks passed!`)
  - `ruff format --check .`: **PASS** (`85 files already formatted`)
  - `pytest -v`: **236 passed, 9 skipped, 0 failed** (245 collected across 23 test files; 226 `def test_*` functions, 19 parametrized expansions).
- **Test Modules (`tests/`)**:
  - Drivers/Transport/Discovery: `test_drivers.py` (**3,367 lines, 77 tests** — monolithic; mixes drivers, detector, crawler, topology), `test_ssh_compat.py` (11), `test_trunk_vendor_parsers.py` (9), `test_oui.py` (9), `test_dependency_checker.py` (7), `test_domain_detector.py` (6), `test_cisco_xr.py` (4), `test_snmp_collector.py` (2). **No `test_crawler*.py`** exists.
  - Topology/Correlation/Schema: `test_trunk_audit.py` (16 / 34 items), `test_topology_renderer.py` (8), `test_topology_resolver.py` (7), `test_topology_gaps.py` (4), `test_schema.py` (4), `test_correlator.py` (3), `test_quality_gates.py` (2), `test_diagram_validator.py` (1).
  - Reports/Parsers/Deliverables: `test_reports.py` (13), `test_parser.py` (12), `test_migration_blueprint.py` (10), `test_deliverable_consistency.py` (10 — **9 skipped**), `test_report_generator_audit.py` (5), `test_trunk_reporting.py` (4), `test_target_adapters.py` (2).
  - Harness: `tests/conftest.py` isolates `oui_lookup` offline only; **no `tests/fixtures/` directory** and **no shared Netmiko/Paramiko mock helpers** exist.
- **Why `test_deliverable_consistency.py` skips (8 on parent repo / 9 on clean CI/worktree)**:
  - 8 tests use `@requires_live_dataset` requiring gitignored `docs/net_docu_crawler/net_docu_crawler_dataset.json` with `>=8` devices and hardcoded lab IPs (`192.168.1.1`, `.3`, `.215`, `.251-.254`) + `opnsense` (parent repo has only 3 devices there, clean CI has none).
  - 9th test (`test_backup_configs_preserved`) requires gitignored `scratch/fortios_Lab_LD2_backup.conf` (exists on parent repo -> 8 skips; absent in CI/worktrees -> 9 skips).
  - **Bug at `test_deliverable_consistency.py:312-313`**: two `expand_targets` dedup assertions are stranded inside the skipped `test_layered_deliverables_structure()` instead of `test_expand_targets_cidr_routed_subnets()`.

## 2. Recorded Transcript & Fixture Inventory

**Vendors WITH real recorded transcripts (require scrubbing: domains, hashes, certs/keys, SNMP communities, real hostnames/IPs -> RFC 5737/1918 + RFC 7042 MACs before committing as `.txt` fixtures)**:

| Vendor / Driver | Source Transcripts Available | Scrubbing Flags |
| :--- | :--- | :--- |
| `cisco` (IOS router) | `docs/net_docu_crawler/logs/192.168.1.250_raw_session.log` (22.6 KB, 15 cmds, `Cisco-Test-Router`) | `enc_pw_hash`, `real_domain` |
| `juniper` (EX2300/EX3400/EX4600) | `testbed/01_raw/desktop-switch__192.168.1.3_raw_session.log` (209 KB, 26 cmds); `norris/logs/172.31.1.81` (EX3400, 721 KB) & `10.250.6.2` (EX4600, 6.8 MB) | `enc_pw_hash`, `snmp_comm`, `real_domain`, customer site names |
| `aruba` (IAP AP-215) | `testbed/01_raw/Office__192.168.1.4_raw_session.log` (12.4 KB, 6 cmds), `Backyard`, `Garage` | `snmp_comm`, `real_domain` |
| `hpprocurve` (2920/5412zl/2530) | `docs/net_docu_crawler/logs/192.168.1.220_raw_session.log` (13 KB, 2920); `norris/01_raw/DO-Main-BLDG__10.1.0.1` (142 KB, 5412zl) & `MOT-Office-SW` (94 KB, 2530) | `snmp_comm`, customer site names |
| `arista` (vEOS-lab) | `testbed/01_raw/Arista-Test-Switch__192.168.1.253_raw_session.log` (13.5 KB, 19 cmds) | Clean lab transcript (anonymize IPs) |
| `fortinet` (FortiGate-VM64) | `testbed/01_raw/FortiGate-VM64-KVM__192.168.1.252_raw_session.log` (1.13 MB, 14 cmds — **contains live `config system console` write!**) | `enc_pw_hash`, `priv_key_cert`, `snmp_comm`, strip `config system console` & trim full-config |
| `mikrotik` (CHR ROS7) | `testbed/01_raw/MikroTik__192.168.1.251_raw_session.log` (8.9 KB, 9 cmds) | Clean lab transcript (anonymize IPs/MACs) |
| `opnsense` (FreeBSD) | `testbed/01_raw/opnsense.<redacted>__192.168.1.1_raw_session.log` (90 KB, 10 `--- COMMAND:` blocks) | `enc_pw_hash`, `real_domain`, trim `config.xml` |
| `frr` (+ plain Debian Linux) | `testbed/01_raw/FRR-Router-01__192.168.1.254_raw_session.log` (8.8 KB, 5 cmds) + `librenms__192.168.1.166` (5.1 KB, 6 cmds) | Anonymize IPs |

**Vendors LACKING real transcripts (`NEEDS-DEVICE-DATA` -> synthetic official-doc-backed fixtures in Phase 3)**:
- `cisco` Catalyst L2/L3 switch (IOS/IOS-XE) & **NX-OS** (only IOS router transcript exists)
- `cisco_xr` (IOS-XR)
- `ciscosmb` (SG300/SG350/CBS)
- `aruba` **AOS-CX** switch mode (only IAP AP-215 exists)
- `paloalto` (PAN-OS)
- `openwrt` (ubus/uci)

## 3. Phase 3 Test-Harness, Mock & E2E Plan (`swarm/test-verifier/harness-fixtures-e2e`)

1. **Fixture Layout (`tests/fixtures/<vendor>/*.txt`, NEVER `*.log`)**:
   - Store scrubbed transcripts under `tests/fixtures/<vendor>/` using `.txt` (and `.xml` if needed) to comply with `.github/workflows/ci.yml:25` (`git ls-files '*.log'` hard-fails CI) and `.gitignore:15-26` (ignores `*.json`, `*.log`, `*.cfg`, `*.conf`; if JSON fixtures are needed, add `!tests/fixtures/**/*.json`).
   - Add `tests/test_fixture_hygiene.py` guard asserting zero secrets/hashes/private keys/real domains/write-commands exist inside `tests/fixtures/`.
2. **Reusable Transport Mock Helpers (`tests/helpers/mock_transport.py`)**:
   - `FakeNetmikoConnection`: command-map or scrubbed-transcript replay supporting `send_command`, `send_command_timing`, `find_prompt`, `enable`, `read_channel`/`write_channel` with simulated `--More--` / `-- MORE --` chunked paging, failure injection (`NetmikoTimeoutException`, `NetmikoAuthenticationException`, `ReadTimeout`, mid-crawl drop), **strict read-only command allowlist enforcer**, and `disconnect()` tracking to catch VTY leaks.
   - `FakeParamikoClient` / `FakeParamikoChannel`: mocks `SSHClient.connect`, `exec_command` `(stdin, stdout, stderr)` with exit-status & timeout simulation, host-key policy invocation, and `close()` leak checks.
   - Extend `tests/conftest.py` to also stub `get_mac_from_system_arp` -> `""` by default (hermetic offline CI parity).
3. **Offline Mixed-Vendor End-to-End Replay Test (`tests/test_e2e_offline_pipeline.py`)**:
   - Replays scrubbed/doc-backed fixtures through real driver `.crawl(fake_conn)` (enforcing read-only allowlist + `disconnect()`) for a 4-tier mixed-vendor topology (Cisco Catalyst Core + Juniper EX Access + Aruba IAP AP-215 + FortiGate Edge Firewall) through `reconcile_and_deduplicate_dataset()` -> `_stitch_dataset_topology()` -> `correlate_dataset()` -> `render_deliverables_from_dataset()`.
   - Verifies all deliverables & invariants (`L2_network_diagrams.md`, `L3_network_diagrams.md`, `Network_Analysis.md`, CSVs, interactive HTML, `00_manifest/`..`05_reports/`, `evaluate_quality_gates()`).
   - Fixes `test_deliverable_consistency.py:312-313` stranded assertions.
4. **Phase 4/5 Verification Gate Protocol**:
   - Re-run `ruff check .`, `ruff format --check .`, and `pytest -v` on every fix branch & every merge into `swarm/integration`; require regression test failing before fix / passing after, monotonic pass count increase, zero new skips or read-only violations.

## 4. Test-Infrastructure Findings (`TV-*`)

| ID | Severity | Area | File:Line | Symptom | Root Cause | Evidence (test/fixture/log) | Status (CONFIRMED/SUSPECTED/NEEDS-DEVICE-DATA) | Fix Branch | Test Added |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| TV-01 | P1 | Test Harness / Deliverable Parity | `tests/test_deliverable_consistency.py:54-313` | 9/10 deliverable consistency tests skip in clean CI/worktrees (8/10 on parent repo); lines 312-313 (`expand_targets` dedup checks) are unreachable inside skipped `test_layered_deliverables_structure()` | Hardcoded gitignored local paths (`docs/net_docu_crawler/`, `scratch/fortios_Lab_LD2_backup.conf`) & lab IPs; misplaced assertions at L312-313 | `pytest -v`: `236 passed, 9 skipped` (all 9 in `test_deliverable_consistency.py`) | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | `tests/test_e2e_offline_pipeline.py` + fix `test_deliverable_consistency.py:312-313` |
| TV-02 | P1 | CI / Fixture Hygiene | `.gitignore:15-26`, `.github/workflows/ci.yml:25-30` | Adding `.log`/`.json`/`.cfg`/`.conf` fixtures under `tests/fixtures/` is silently ignored by `.gitignore` or hard-fails CI (`git ls-files '*.log'`) | Global secret/log ignore & CI guard rules predate `tests/fixtures/` | `.gitignore` ignores `*.json`, `*.log`, `*.cfg`, `*.conf`; `ci.yml:25` fails on any tracked `*.log` | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | Use `.txt`/`.xml` fixtures (+ optional `!tests/fixtures/**/*.json`) + `test_fixture_hygiene.py` |
| TV-03 | P1 | Transport Mocks / Safety Gate | `tests/test_drivers.py` (63 `MagicMock`s, 0 allowlist/pager tests) | CI does not catch read-only violations (e.g. FortiGate `config system console`), `--More--` paging hangs, or missing `disconnect()`/`close()` VTY cleanup | Driver unit tests mock `send_command` lambdas directly, bypassing transport lifecycle, paging, and command safety checks | Live `FortiGate-VM64-KVM__192.168.1.252_raw_session.log` ran `config system console` twice while `pytest` passed; 0 refs to `--More--` or `disable_paging` across `tests/*.py` | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | `tests/helpers/mock_transport.py` (`FakeNetmikoConnection` + `FakeParamikoClient` with read-only & disconnect guards) |
| TV-04 | P1 | End-to-End Coverage | `tests/` (missing offline E2E replay) | No offline E2E test replays multi-vendor CLI outputs through `driver.crawl()` -> topology stitching -> correlation -> report/Mermaid/CSV generation | Drivers, correlator, and report generator are tested separately with hand-crafted dicts (`test_drivers.py:1758` starts from pre-built JSON) | Inventory of all 23 test files (245 items): 0 mixed-vendor transcript-to-deliverable E2E tests | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | `tests/test_e2e_offline_pipeline.py` |
| TV-05 | P2 | Test Hermeticity | `tests/conftest.py:9-21`, `net_docu_crawler/drivers/base.py:551-552` | Driver tests with empty MACs on RFC1918 IPs (`192.168.1.5`/`.6`) can read host `/proc/net/arp` or invoke `arp -a`, causing dev vs CI drift | `conftest.py` isolates `oui_lookup` only, not `get_mac_from_system_arp()` called by `BaseDriver.crawl()` | `tests/conftest.py:9-21` vs `base.py:551-552` | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | Hermetic autouse ARP stub in `tests/conftest.py` |
| TV-06 | P2 | Driver Contract Parity | `tests/test_drivers.py:826-848` | `test_all_10_drivers_session_log_and_interface` only tests 11/13 registered drivers, omitting `CiscoSMBDriver` and `CiscoXRDriver` | Hardcoded driver list out of sync with `DRIVER_VENDOR_MAP` (`drivers/__init__.py:67-81`) | `tests/test_drivers.py:826-848` (11 drivers) vs `drivers/__init__.py:67-81` (13 drivers) | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | Parametrized contract test over all `DRIVER_VENDOR_MAP` entries |
| TV-07 | P2 | Fixture Coverage | `tests/fixtures/` (missing 6 OS/platform captures) | No real recorded transcripts exist for Cisco Catalyst switch (IOS-XE), Cisco NX-OS, Cisco IOS-XR, Cisco SMB, ArubaOS-CX, Palo Alto PAN-OS, or OpenWrt | Lab/field captures (`norris`, `testbed`, `lan`) only covered Cisco IOS router, Junos EX, HP ProCurve, Aruba IAP, Arista vEOS, FortiGate, MikroTik, OPNsense, FRR/Debian | Automated scan of all `deliverables/` & `docs/net_docu_crawler/logs/` transcripts returned 0 hits for those platforms | NEEDS-DEVICE-DATA | `swarm/test-verifier/harness-fixtures-e2e` | Synthetic doc-backed fixtures tagged `SYNTHETIC-DOC-BACKED` + real-capture wishlist |
| TV-08 | P3 | Test Organization / Crawler Coverage | `tests/test_drivers.py` (3,367 lines), missing `tests/test_crawler.py` | Crawler orchestration (`_connect_and_crawl_once`, `_crawl_target_batch`, `_stitch_dataset_topology`, `reconcile_and_deduplicate_dataset`, `LogReplayConnection`) lacks dedicated failure/concurrency tests | Tests accumulated in monolithic `test_drivers.py`; `LogReplayConnection` (`crawler.py:2487`) only tested by 2 cases | `tests/` file inventory: 0 `test_crawler*.py`, `test_drivers.py` = 3,367 lines | CONFIRMED | `swarm/test-verifier/harness-fixtures-e2e` | `tests/test_crawler_orchestration.py` (failure injection, VTY cleanup, lockout safety) |

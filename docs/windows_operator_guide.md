<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Windows & Remote Prod Operator Guide

Quick-reference runbook for running [`Net-Docu-Crawler`](../README.md) from a Windows jump host or remote production workstation.

---

## 1. Initial Setup (PowerShell)

**Recommended (automated check + `.venv` install for Python 3.10–3.12):**

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1        # assess only
powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1 -Fix   # assess + fix into .venv
```

**Manual setup (PowerShell):**

```powershell
# Clone or pull latest updates
git pull origin main

# Create and activate virtual environment (.venv)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package + `net-crawler` CLI (runtime-only alternative: `pip install -r requirements.txt`)
pip install -e .
```

Or launch the interactive operator wrapper:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\run.ps1
```

---

## 2. Validate `credentials.json` Before Crawling

Always validate your credential profiles before scanning production infrastructure to catch typos or missing vendor tags early:

```powershell
.\.venv\Scripts\python.exe net_crawler.py --validate-credentials --credentials credentials.json
```

Tagging each profile with `"vendor"` (e.g., `"fortinet"`, `"cisco"`, `"cisco_xr"`, `"ciscosmb"`, `"juniper"`) ensures the crawler only tries vendor-matching credentials first and prevents AAA/fail2ban lockouts. Use `"secret"` (not deprecated `"enable_secret"`) for Cisco/Arista privileged enable passwords.

---

## 3. Standard Campus / Multi-VLAN Crawl

```powershell
.\.venv\Scripts\python.exe net_crawler.py --targets 10.29.0.1/23 --follow-subnets --max-hops 2 --organize
```

- Deliverables are saved to `deliverables/<target>_<timestamp>_<site>/`.
- Raw CLI session transcripts and `crawler_execution.log` are saved under `deliverables/<run>/logs/`.
- Any `unauthenticated` or `unsupported` targets are exported to `deliverables/<run>/failed_hosts.json` and `00_manifest/failures.csv`.

---

## 4. Retrying Failed Hosts (`--retry-failed`)

After adding missing credentials to `credentials.json`, retry **only** the `unauthenticated` hosts from the previous run without re-scanning the entire subnet:

```powershell
.\.venv\Scripts\python.exe net_crawler.py --retry-failed deliverables\<run>\failed_hosts.json --organize
```

---

## 5. Useful Flags

| Flag | Purpose |
| :--- | :--- |
| `--vendor-hint <vendor>` | Fallback vendor driver hint when OUI/SSH banner identification returns `unknown` (e.g., `juniper`, `ciscosmb`, `cisco_xr`, `fortinet`, `frrouting`). |
| `--try-all-creds` | Override vendor credential scoping when testing unknown/untagged devices (not recommended on AAA lockout-protected infrastructure). |
| `--no-online-oui` | Disable IEEE/macvendors online OUI fallback on air-gapped networks. |
| `--sanitize-passwords` | Scrub secrets and PSKs from saved `raw_config` backups and raw session logs. |

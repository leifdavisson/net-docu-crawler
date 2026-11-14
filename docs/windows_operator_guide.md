<!--
Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Windows & Remote Prod Operator Guide

Quick-reference runbook for running [`Net-Docu-Crawler`](../README.md) from a Windows jump host or remote production workstation.

---

## 1. Initial Setup (PowerShell)

```powershell
# Clone or pull latest updates
git pull origin feature/windows-setup

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

Or launch the interactive operator wrapper:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\run.ps1
```

---

## 2. Validate `credentials.json` Before Crawling

Always validate your credential profiles before scanning production infrastructure to catch typos or missing vendor tags early:

```powershell
.\venv\Scripts\python.exe net_crawler.py --validate-credentials --credentials credentials.json
```

Tagging each profile with `"vendor"` (e.g., `"fortinet"`, `"cisco"`, `"ciscosmb"`, `"juniper"`) ensures the crawler only tries vendor-matching credentials first and prevents AAA/fail2ban lockouts.

---

## 3. Standard Campus / Multi-VLAN Crawl

```powershell
.\venv\Scripts\python.exe net_crawler.py --targets 10.29.0.1/23 --follow-subnets --max-hops 2 --organize
```

- Deliverables are saved to `deliverables/<target>_<timestamp>/`.
- Raw CLI session transcripts and `crawler_execution.log` are saved under `deliverables/<run>/logs/`.
- Any `unauthenticated` or `unsupported` targets are exported to `deliverables/<run>/failed_hosts.json`.

---

## 4. Retrying Failed Hosts (`--retry-failed`)

After adding missing credentials to `credentials.json`, retry **only** the `unauthenticated` hosts from the previous run without re-scanning the entire subnet:

```powershell
.\venv\Scripts\python.exe net_crawler.py --retry-failed deliverables\<run>\failed_hosts.json --organize
```

---

## 5. Useful Flags

| Flag | Purpose |
| :--- | :--- |
| `--vendor-hint <vendor>` | Force a specific driver (e.g., `juniper`, `ciscosmb`, `fortinet`) for isolated single-vendor targets. |
| `--try-all-creds` | Override vendor credential scoping when testing unknown/untagged devices. |
| `--no-online-oui` | Disable IEEE/macvendors online OUI fallback on air-gapped networks. |
| `--sanitize-passwords` | Scrub secrets and PSKs from saved `raw_config` backups. |

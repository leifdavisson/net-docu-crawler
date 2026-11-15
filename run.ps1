# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

$ErrorActionPreference = "Stop"

$Py = if (Test-Path ".\venv\Scripts\python.exe") { ".\venv\Scripts\python.exe" } else { "python" }

Write-Host "=== Net-Docu-Crawler Operator Wrapper ===" -ForegroundColor Cyan
Write-Host "1) Validate credentials.json"
Write-Host "2) Run organized crawl (--follow-subnets --max-hops 2)"
Write-Host "3) Retry failed hosts (--retry-failed)"
Write-Host "4) Update repo (git pull)"
Write-Host "5) Regenerate deliverables from dataset (--from-dataset)"
Write-Host "q) Quit"

$choice = Read-Host "Select an option"
if ([string]::IsNullOrWhiteSpace($choice) -or $choice -eq "q") { exit 0 }

switch ($choice) {
    "1" {
        & $Py net_crawler.py --validate-credentials
    }
    "2" {
        $targets = Read-Host "Enter target IP or CIDR (e.g. 10.29.0.1/23)"
        if ([string]::IsNullOrWhiteSpace($targets)) { exit 0 }
        & $Py net_crawler.py --targets $targets.Split(" ") --follow-subnets --max-hops 2 --organize
    }
    "3" {
        $failedPath = Read-Host "Path to failed_hosts.json"
        if ([string]::IsNullOrWhiteSpace($failedPath)) { exit 0 }
        & $Py net_crawler.py --retry-failed $failedPath --organize
    }
    "4" {
        git pull
    }
    "5" {
        $datasetPath = Read-Host "Path to net_docu_crawler_dataset.json"
        if ([string]::IsNullOrWhiteSpace($datasetPath)) { exit 0 }
        & $Py net_crawler.py --from-dataset $datasetPath
    }
    default {
        Write-Host "Unknown option: $choice" -ForegroundColor Yellow
        exit 1
    }
}

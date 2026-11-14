#!/usr/bin/env bash
# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

PY="python3"
if [[ -x "./venv/bin/python" ]]; then
    PY="./venv/bin/python"
fi

echo "=== Net-Docu-Crawler Operator Wrapper ==="
echo "1) Validate credentials.json"
echo "2) Run organized crawl (--follow-subnets --max-hops 2)"
echo "3) Retry failed hosts (--retry-failed)"
echo "4) Update repo (git pull)"
echo "q) Quit"

if ! read -r -p "Select an option: " choice; then
    exit 0
fi

case "$choice" in
    1)
        "$PY" net_crawler.py --validate-credentials
        ;;
    2)
        if ! read -r -p "Enter target IP or CIDR (e.g. 10.29.0.1/23): " targets || [[ -z "$targets" ]]; then
            exit 0
        fi
        # shellcheck disable=SC2086
        "$PY" net_crawler.py --targets $targets --follow-subnets --max-hops 2 --organize
        ;;
    3)
        if ! read -r -p "Path to failed_hosts.json: " failed_path || [[ -z "$failed_path" ]]; then
            exit 0
        fi
        "$PY" net_crawler.py --retry-failed "$failed_path" --organize
        ;;
    4)
        git pull
        ;;
    q|Q|"")
        exit 0
        ;;
    *)
        echo "Unknown option: $choice"
        exit 1
        ;;
esac

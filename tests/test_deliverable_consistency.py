# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Automated Deliverable and Backup Consistency Verification Test Suite.
Validates parity between live crawled data, generated reports, CSV inventories,
and configuration backups when present on disk (skipped in clean CI runners).
"""

import csv
import json
import os
import re

import pytest

from net_docu_crawler.crawler import expand_targets

DATASET_PATH = "docs/net_docu_crawler/net_docu_crawler_dataset.json"
ASSET_CSV_PATH = "docs/net_docu_crawler/asset_inventory.csv"
CABLING_CSV_PATH = "docs/net_docu_crawler/migration_cabling_matrix.csv"
L2_DIAGRAM_PATH = "docs/net_docu_crawler/L2_network_diagrams.md"
L3_DIAGRAM_PATH = "docs/net_docu_crawler/L3_network_diagrams.md"
LIVE_REPORT_PATH = "docs/net_docu_crawler/net_docu_crawler_live_report.md"
TRANSLATION_REPORT_PATH = "docs/net_docu_crawler/cisco_to_target_translation.md"
BLUEPRINT_PATH = "docs/net_docu_crawler/Network_Analysis.md"
SMOKE_SCRIPT_PATH = "docs/net_docu_crawler/validate_cutover.sh"
PORT_ENDPOINT_CSV_PATH = "docs/net_docu_crawler/port_mac_endpoint_mapping.csv"
FORTIOS_BACKUP_PATH = "scratch/fortios_Lab_LD2_backup.conf"

requires_live_dataset = pytest.mark.skipif(
    not os.path.exists(DATASET_PATH),
    reason="Live crawl deliverables not present on disk (gitignored in CI)",
)


@requires_live_dataset
def test_dataset_structure_and_completeness():
    assert os.path.exists(DATASET_PATH), f"Dataset file missing: {DATASET_PATH}"
    with open(DATASET_PATH, encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, list), "Dataset root must be a list of device records"
    assert len(data) >= 8, f"Expected at least 8 crawled devices, found {len(data)}"

    crawled_ips = set()
    for dev in data:
        ip = dev.get("ip")
        assert ip, "Device must have a valid IP address"
        crawled_ips.add(ip)

        assert dev.get("hostname"), f"Device {ip} has empty hostname"
        assert dev.get("vendor"), f"Device {ip} has empty vendor"
        assert dev.get("model"), f"Device {ip} has empty model"
        assert dev.get("mac_address"), f"Device {ip} has empty MAC address"
        assert dev.get("status") == "success", f"Device {ip} status is not success"

        for nbr in dev.get("neighbors", []):
            assert '"' not in nbr.get("remote_device", ""), f"Unstripped quote in neighbor remote_device on {ip}: {nbr}"

        raw_cfg = dev.get("raw_config", "")
        assert raw_cfg and len(raw_cfg) > 50, f"Device {ip} has missing or truncated raw_config"
        assert "privileged mode required" not in raw_cfg.lower(), (
            f"Device {ip} failed to enter enable mode for config capture"
        )
        assert "% invalid input" not in raw_cfg.lower(), f"Device {ip} config contains syntax error output"

    expected_ips = {
        "192.168.1.1",
        "192.168.1.3",
        "192.168.1.215",
        "192.168.1.250",
        "192.168.1.251",
        "192.168.1.252",
        "192.168.1.253",
        "192.168.1.254",
    }
    missing = expected_ips - crawled_ips
    assert not missing, f"Missing expected target devices in dataset: {missing}"


@requires_live_dataset
def test_asset_inventory_csv_consistency():
    assert os.path.exists(ASSET_CSV_PATH), f"Asset inventory missing: {ASSET_CSV_PATH}"
    with open(DATASET_PATH, encoding="utf-8") as f:
        dataset = json.load(f)

    dataset_ips = {d["ip"] for d in dataset}

    with open(ASSET_CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == len(dataset), f"CSV row count ({len(rows)}) must match dataset ({len(dataset)})"

    csv_ips = set()
    for row in rows:
        ip = row["IP Address"]
        csv_ips.add(ip)
        assert re.match(r"^\d+\.\d+\.\d+\.\d+$", ip), f"Malformed IP: {ip}"
        assert row["Hostname"], f"Empty hostname for {ip}"
        assert row["MAC Address"] and row["MAC Address"] != "Unknown", f"Unresolved MAC for {ip}"
        assert row["Model"] and row["Model"] != "Unknown", f"Unresolved Model for {ip}"
        assert row["Firmware"], f"Empty firmware for {ip}"

    assert csv_ips == dataset_ips, "CSV IP set does not match dataset IP set"


@requires_live_dataset
def test_cabling_matrix_csv_consistency():
    assert os.path.exists(CABLING_CSV_PATH), f"Cabling matrix missing: {CABLING_CSV_PATH}"
    with open(CABLING_CSV_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) > 0, "Cabling matrix CSV cannot be empty"
    source_hosts = {row["Source Hostname"] for row in rows}
    source_ports = {row["Source Port"] for row in rows}

    # Internal Junos / FortiOS / FreeBSD pseudo-interfaces must never pollute physical cabling matrix
    for pseudo in ("bme0", "jsrv", "naf.root", "ssl.root", "pflog0", "pfsync0"):
        assert pseudo not in source_ports, f"Kernel pseudo-interface {pseudo} leaked into cabling matrix"

    # Neighbor hostnames must not contain unstripped quotes
    for row in rows:
        assert '"' not in row["Neighbor Hostname"], f"Unstripped quote in Cabling Matrix row: {row}"

    with open(DATASET_PATH, encoding="utf-8") as f:
        dataset = json.load(f)

    dataset_hosts = {d["hostname"] for d in dataset}
    overlap = source_hosts.intersection(dataset_hosts)
    assert len(overlap) >= 5, f"Expected at least 5 known hostnames in cabling matrix, got {len(overlap)}"


@requires_live_dataset
def test_l3_diagram_consistency():
    assert os.path.exists(L3_DIAGRAM_PATH), f"L3 diagram file missing: {L3_DIAGRAM_PATH}"
    with open(L3_DIAGRAM_PATH, encoding="utf-8") as f:
        content = f.read()

    assert "```mermaid" in content, "L3 diagram must contain a mermaid diagram"
    assert "graph TD" in content or "flowchart TD" in content
    assert "128.0.0.0" not in content, "Internal Junos 128.0.0.x fabric address leaked into L3 diagram"

    with open(DATASET_PATH, encoding="utf-8") as f:
        dataset = json.load(f)

    for dev in dataset:
        host = dev.get("hostname")
        assert host in content, f"Hostname {host} missing from Layer 3 diagram document"

    assert "Authoritative VLAN, Subnet & SVI Map" in content
    assert "192.168.1.0/24" in content


@requires_live_dataset
def test_l2_diagram_consistency():
    assert os.path.exists(L2_DIAGRAM_PATH), f"L2 diagram file missing: {L2_DIAGRAM_PATH}"
    with open(L2_DIAGRAM_PATH, encoding="utf-8") as f:
        content = f.read()

    assert "```mermaid" in content, "L2 diagram must contain a mermaid diagram"
    assert '\\"' not in content.split("## Wireless Overlay")[0] or "ext_" not in content.split('\\"', 1)[0]
    assert "Total Discovered Access Points:" in content, (
        "Wireless APs discovered via LLDP must populate Wireless Overlay"
    )

    with open(DATASET_PATH, encoding="utf-8") as f:
        dataset = json.load(f)

    for dev in dataset:
        host = dev.get("hostname")
        assert host in content, f"Hostname {host} missing from Layer 2 diagram document"


@requires_live_dataset
def test_live_report_and_translation_integrity():
    assert os.path.exists(LIVE_REPORT_PATH), f"Live report missing: {LIVE_REPORT_PATH}"
    assert os.path.exists(TRANSLATION_REPORT_PATH), f"Translation guide missing: {TRANSLATION_REPORT_PATH}"

    with open(LIVE_REPORT_PATH, encoding="utf-8") as f:
        report = f.read()
    assert "# Layered Network Analysis Report" in report
    assert "192.168.1.1" in report
    assert "opnsense" in report.lower()
    assert not re.search(r"\*\*opnsense[^*]*\*\*: \*\*Spanning Tree is DISABLED\*\*", report, re.IGNORECASE)
    assert "Identical subnet range `192.168.1.0/24`" not in report

    with open(TRANSLATION_REPORT_PATH, encoding="utf-8") as f:
        trans = f.read()
    assert "Cisco-to-Target Protocol Translation" in trans


@requires_live_dataset
def test_master_network_analysis_migration_blueprint_and_smoke_script_consistency():
    assert os.path.exists(BLUEPRINT_PATH), f"Master Migration Blueprint missing: {BLUEPRINT_PATH}"
    assert os.path.exists(SMOKE_SCRIPT_PATH), f"Cutover smoke script missing: {SMOKE_SCRIPT_PATH}"
    assert os.access(SMOKE_SCRIPT_PATH, os.X_OK), f"Smoke test script is not executable: {SMOKE_SCRIPT_PATH}"

    with open(BLUEPRINT_PATH, encoding="utf-8") as f:
        bp = f.read()

    assert "# Network Migration Analysis Blueprint" in bp
    assert "## 1. Executive Summary & Current Hardware Estate" in bp
    assert "## 2. Physical Layer 1/2 Cabling, Optics & MTU Matrix" in bp
    assert "## 3. Power over Ethernet (PoE) Budget" in bp
    assert "## 4. Layer 2 VLANs, 802.1Q Trunks" in bp
    assert "## 5. DHCP Relay & IP Helper Addresses" in bp
    assert "## 6. Spanning Tree (STP)" in bp
    assert "## 7. First-Hop Redundancy Protocols" in bp
    assert "## 8. Layer 3 Subnets, Routing Boundaries" in bp
    assert "## 10. Infrastructure Services" in bp
    assert "## 12. Maintenance Window Cutover Runbook & Rollback Plan" in bp
    assert "### 2.3 Optical Transceiver & Digital Optical Monitoring" in bp
    assert "### 2.4 Port-to-Endpoint MAC Address Mapping" in bp
    assert "192.168.1.1" in bp
    assert "opnsense" in bp.lower()

    with open(SMOKE_SCRIPT_PATH, encoding="utf-8") as f:
        smoke = f.read()

    assert "#!/usr/bin/env bash" in smoke
    assert 'check_ping "192.168.1.1"' in smoke
    assert "check_port" in smoke

    assert os.path.exists(PORT_ENDPOINT_CSV_PATH)
    with open(PORT_ENDPOINT_CSV_PATH, encoding="utf-8") as f:
        csv_head = f.readline()
    assert "Switch Hostname,Switch IP,Port,VLAN,MAC Address,OUI Vendor" in csv_head


@pytest.mark.skipif(not os.path.exists(FORTIOS_BACKUP_PATH), reason="Local lab backup not present")
def test_backup_configs_preserved():
    assert os.path.exists(FORTIOS_BACKUP_PATH), f"FortiOS backup missing: {FORTIOS_BACKUP_PATH}"
    fgt_size = os.path.getsize(FORTIOS_BACKUP_PATH)
    assert fgt_size > 500000, f"FortiOS backup unexpectedly small ({fgt_size} bytes)"

    with open(FORTIOS_BACKUP_PATH, encoding="utf-8", errors="ignore") as f:
        sample = f.read(2048)
    assert "config-version=" in sample or "FortiGate" in sample, "Invalid FortiOS backup content"


def test_expand_targets_cidr_routed_subnets():
    assert expand_targets(["192.168.1.1", "192.168.1.3"]) == ["192.168.1.1", "192.168.1.3"]

    p2p = expand_targets(["172.16.1.0/30"])
    assert p2p == ["172.16.1.1", "172.16.1.2"]

    dmz = expand_targets(["172.16.1.0/24"])
    assert len(dmz) == 254
    assert dmz[0] == "172.16.1.1"
    assert dmz[-1] == "172.16.1.254"

    # Large /16 subnet must actually cap expansion at max_hosts_per_cidr
    capped = expand_targets(["10.0.0.0/16"], max_hosts_per_cidr=16)
    assert len(capped) == 16

    dedup = expand_targets(["192.168.1.1", "192.168.1.1", "172.16.1.1"])
    assert dedup == ["192.168.1.1", "172.16.1.1"]

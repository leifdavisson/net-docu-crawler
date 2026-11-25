# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Offline end-to-end mixed-vendor replay test.

Drives scrubbed/doc-backed CLI transcripts for a realistic 4-tier enterprise topology:
  - Cisco Catalyst Core Switch (`sw-core-01`, `10.10.1.2`)
  - Juniper EX Access Switch (`sw-access-01`, `10.10.1.10`)
  - Aruba Instant AP (`ap-floor1-01`, `10.10.1.20`)
  - FortiGate Edge Firewall (`fw-edge-01`, `10.10.1.1`)

Replays every device through its real vendor driver using `FakeNetmikoConnection`
(enforcing Zero-Blast-Radius read-only commands + session disconnect), then runs
`render_deliverables_from_dataset()` into `tmp_path` and validates all generated
L2/L3 Mermaid diagrams, `Network_Analysis.md`, CSV matrices, and layered outputs.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

from net_docu_crawler.crawler import render_deliverables_from_dataset
from net_docu_crawler.diagram_validator import validate_mermaid_block
from net_docu_crawler.drivers import ArubaDriver, CiscoDriver, FortinetDriver, JuniperDriver
from tests.helpers.fake_transport import FakeNetmikoConnection

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"


def _extract_mermaid_blocks(markdown_text: str) -> list[str]:
    return re.findall(r"```mermaid\s*\n(.*?)```", markdown_text, flags=re.DOTALL)


def test_offline_mixed_vendor_e2e_replay_and_deliverables(tmp_path: Path):
    """Replay 4 mixed-vendor fixtures end-to-end into L2/L3 diagrams, blueprint, and CSVs."""
    topology_spec = [
        (FortinetDriver, "10.10.1.1", FIXTURES_ROOT / "fortinet" / "fortigate_edge.txt"),
        (CiscoDriver, "10.10.1.2", FIXTURES_ROOT / "cisco" / "ios_catalyst_core_synthetic.txt"),
        (JuniperDriver, "10.10.1.10", FIXTURES_ROOT / "juniper" / "junos_ex2300.txt"),
        (ArubaDriver, "10.10.1.20", FIXTURES_ROOT / "aruba" / "iap_ap215.txt"),
    ]

    crawled_devices: list[dict] = []
    for driver_cls, ip, fixture_path in topology_spec:
        with FakeNetmikoConnection.from_transcript_file(fixture_path, enforce_readonly=True) as conn:
            dev = driver_cls(ip=ip).crawl(conn)
        conn.assert_closed()
        conn.assert_only_readonly_commands()
        crawled_devices.append(dev)

    assert len(crawled_devices) == 4
    by_ip = {d["ip"]: d for d in crawled_devices}
    assert by_ip["10.10.1.1"]["hostname"] == "fw-edge-01"
    assert by_ip["10.10.1.2"]["hostname"] == "sw-core-01"
    assert by_ip["10.10.1.10"]["hostname"] == "sw-access-01"
    assert by_ip["10.10.1.20"]["hostname"] == "ap-floor1-01"

    # Pseudo-interfaces and Junos internal 128.0.0.x fabric must never enter crawled device data
    assert "naf.root" not in by_ip["10.10.1.1"]["interfaces_detail"]
    assert "ssl.root" not in by_ip["10.10.1.1"]["interfaces_detail"]
    assert "bme0" not in by_ip["10.10.1.10"]["interfaces_detail"]
    assert all("128.0.0." not in i.get("ip_address", "") for i in by_ip["10.10.1.10"]["l3_interfaces"])

    out_dir = tmp_path / "e2e_deliverables"
    out_dir.mkdir(parents=True, exist_ok=True)
    render_deliverables_from_dataset(
        raw_devices=crawled_devices,
        run_output_dir=str(out_dir),
        sanitize_passwords=True,
    )

    # 1. Core deliverables and layered directories exist
    expected_files = [
        "net_docu_crawler_dataset.json",
        "asset_inventory.csv",
        "migration_cabling_matrix.csv",
        "port_mac_endpoint_mapping.csv",
        "L2_network_diagrams.md",
        "L3_network_diagrams.md",
        "Network_Analysis.md",
        "net_docu_crawler_live_report.md",
        "topology_interactive.html",
        "00_manifest/collection_manifest.json",
        "00_manifest/data_quality_report.md",
        "02_normalized/devices.json",
        "03_correlated/physical_links.csv",
        "04_migration/asset_inventory.csv",
        "05_reports/Network_Analysis.md",
    ]
    for rel in expected_files:
        assert (out_dir / rel).is_file(), f"Missing E2E deliverable: {rel}"

    # 2. Asset inventory matches all 4 crawled devices
    with open(out_dir / "asset_inventory.csv", encoding="utf-8") as f:
        asset_rows = list(csv.DictReader(f))
    assert {r["IP Address"] for r in asset_rows} == {"10.10.1.1", "10.10.1.2", "10.10.1.10", "10.10.1.20"}
    assert {r["Device Type"].lower() for r in asset_rows} == {"firewall", "switch", "access point"}
    for row in asset_rows:
        assert row["Hostname"]
        assert row["Model"] and row["Model"] != "Unknown"

    # 3. Cabling matrix contains zero pseudo-interfaces or unstripped neighbor quotes
    with open(out_dir / "migration_cabling_matrix.csv", encoding="utf-8") as f:
        cabling_rows = list(csv.DictReader(f))
    assert len(cabling_rows) > 0
    forbidden_pseudo = {"bme0", "jsrv", "naf.root", "ssl.root", "pflog0", "pfsync0", "enc0", "dsc", "mtun", "lo0"}
    for row in cabling_rows:
        assert row["Source Port"] not in forbidden_pseudo
        assert '"' not in row.get("Neighbor Hostname", "")
        assert row["Source Hostname"] in {"fw-edge-01", "sw-core-01", "sw-access-01", "ap-floor1-01"}

    # 4. L2 & L3 diagrams contain all 4 devices, valid Mermaid syntax, and zero fabric leaks
    l2_txt = (out_dir / "L2_network_diagrams.md").read_text(encoding="utf-8")
    l3_txt = (out_dir / "L3_network_diagrams.md").read_text(encoding="utf-8")
    for md_name, md_txt in [("L2_network_diagrams.md", l2_txt), ("L3_network_diagrams.md", l3_txt)]:
        blocks = _extract_mermaid_blocks(md_txt)
        assert blocks, f"No mermaid diagram block found in {md_name}"
        for blk in blocks:
            errs = validate_mermaid_block(blk)
            assert errs == [], f"Mermaid validation errors in {md_name}: {errs}"
        for host in ("fw-edge-01", "sw-core-01", "sw-access-01", "ap-floor1-01"):
            assert host in md_txt, f"Expected {host} in {md_name}"

    assert "128.0.0." not in l3_txt
    assert "10.10.1.0/24" in l3_txt
    assert "198.51.100.0/30" in l3_txt
    assert "Total Discovered Access Points:" in l2_txt

    # 5. Live report & Network_Analysis.md avoid false STP alarms on firewall/AP and false /24 overlaps
    live_txt = (out_dir / "net_docu_crawler_live_report.md").read_text(encoding="utf-8")
    analysis_txt = (out_dir / "Network_Analysis.md").read_text(encoding="utf-8")
    assert not re.search(r"\*\*(?:fw-edge-01|ap-floor1-01)\*\*:\s*\*\*Spanning Tree is DISABLED\*\*", live_txt, re.I)
    assert "Identical subnet range `10.10.1.0/24`" not in live_txt
    assert "# Network Migration Analysis Blueprint" in analysis_txt
    for host in ("fw-edge-01", "sw-core-01", "sw-access-01", "ap-floor1-01"):
        assert host in analysis_txt

    # 6. Quality & Truthfulness gates: Zero premature checkmarks, zero pseudo-interfaces leaked to reports
    runbook_txt = (out_dir / "cutover_runbook.md").read_text(encoding="utf-8")
    assert "- [x]" not in analysis_txt, "Network_Analysis.md checklist must not contain premature '- [x]' marks"
    assert "- [x]" not in runbook_txt, "cutover_runbook.md checklist must not contain premature '- [x]' marks"
    assert "- [ ] **Configuration & Dataset Backup**" in runbook_txt
    assert "- [ ] **Cabling & Optics Staging**" in runbook_txt
    for doc in (analysis_txt, runbook_txt, l2_txt, l3_txt):
        for pseudo in forbidden_pseudo:
            assert pseudo not in doc, f"Pseudo-interface {pseudo} leaked into generated deliverable"

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
Automated Output Quality Gates & Contradiction Detector (Phase 5).
Prevents silent shipping of blank cabling-matrix VLANs, PoE budget contradictions,
or unverified STP root assertions, and emits `00_manifest/data_quality_report.md`.
"""

import json
import os
from collections import Counter


def evaluate_quality_gates(raw_devices: list[dict]) -> dict:
    """Evaluate correlated `raw_devices` against P0 cutover-readiness gates."""
    funnel = Counter(d.get("record_class", "unknown") for d in raw_devices)
    infra = [d for d in raw_devices if d.get("record_class") == "crawled_infra" or d.get("status") == "success"]

    gates: list[dict] = []
    total_ports = 0
    known_mode = 0
    known_vlan = 0
    known_native_on_trunk = 0
    trunk_ports = 0

    poe_contradictions: list[str] = []
    stp_missing_root: list[str] = []

    for dev in infra:
        host = dev.get("hostname") or dev.get("ip", "")
        ports = dev.get("ports", {}) or {}
        active_ports = sum(1 for p in ports.values() if p.get("oper_state") == "up")

        for p in ports.values():
            total_ports += 1
            if p.get("mode") not in ("", "unknown"):
                known_mode += 1
            if p.get("access_vlan") or p.get("allowed_vlans"):
                known_vlan += 1
            if p.get("mode") == "trunk":
                trunk_ports += 1
                if p.get("native_vlan") not in ("", "unknown"):
                    known_native_on_trunk += 1

        poe = dev.get("poe") or {}
        tot_w = float(poe.get("total_power_watts", 0.0) or 0.0)
        deliv = int(poe.get("poe_delivering_ports", 0) or 0)
        if (deliv > 0 and tot_w == 0.0 and not poe.get("budget_unreported")) or (
            active_ports > 0 and deliv > active_ports
        ):
            poe_contradictions.append(f"{host} (budget={tot_w}W, delivering={deliv}, active_ports={active_ports})")

        stp = dev.get("stp") or {}
        if stp.get("is_root") and not stp.get("root_bridge"):
            stp_missing_root.append(host)

    gates.append(
        {
            "gate": "GATE_CABLING_VLAN_EMPTY",
            "severity": "P0",
            "status": "PASS" if (total_ports == 0 or known_vlan > 0) else "FAIL",
            "detail": f"{known_vlan}/{total_ports} ports have resolved access or allowed VLANs.",
        }
    )
    gates.append(
        {
            "gate": "GATE_POE_CONTRADICTION",
            "severity": "P0",
            "status": "FAIL" if poe_contradictions else "PASS",
            "detail": ", ".join(poe_contradictions) if poe_contradictions else "No PoE budget/port contradictions.",
        }
    )
    gates.append(
        {
            "gate": "GATE_STP_ROOT_EVIDENCE",
            "severity": "P0",
            "status": "FAIL" if stp_missing_root else "PASS",
            "detail": (
                f"Missing root_bridge on: {', '.join(stp_missing_root)}"
                if stp_missing_root
                else "All STP root claims backed by root_bridge ID."
            ),
        }
    )
    gates.append(
        {
            "gate": "GATE_TRUNK_NATIVE_UNKNOWN",
            "severity": "P1",
            "status": "WARN" if (trunk_ports > 0 and known_native_on_trunk < trunk_ports) else "PASS",
            "detail": f"{known_native_on_trunk}/{trunk_ports} trunk ports have resolved native VLAN.",
        }
    )

    p0_failed = any(g["severity"] == "P0" and g["status"] == "FAIL" for g in gates)
    return {
        "passed": not p0_failed,
        "gates": gates,
        "funnel": {
            "total_records": len(raw_devices),
            "crawled_infra": funnel.get("crawled_infra", 0),
            "unauthenticated_infra": funnel.get("unauthenticated_infra", 0),
            "unsupported_appliance": funnel.get("unsupported_appliance", 0),
            "passive_endpoint": funnel.get("passive_endpoint", 0),
        },
        "port_confidence": {
            "total_ports": total_ports,
            "known_mode_pct": round((known_mode / total_ports * 100.0), 1) if total_ports else 0.0,
            "known_vlan_pct": round((known_vlan / total_ports * 100.0), 1) if total_ports else 0.0,
            "known_trunk_native_pct": round((known_native_on_trunk / trunk_ports * 100.0), 1) if trunk_ports else 100.0,
        },
    }


def write_quality_report(report: dict, manifest_dir: str) -> None:
    """Write `collection_manifest.json` and `data_quality_report.md` into `manifest_dir`."""
    os.makedirs(manifest_dir, exist_ok=True)
    with open(os.path.join(manifest_dir, "collection_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    lines = [
        "# Data Quality & Cutover-Readiness Gate Report",
        "",
        f"**Overall P0 Gate Status**: `{'PASS' if report['passed'] else 'FAIL'}`",
    ]
    if report.get("dns_domain"):
        lines.append(f"**Detected DNS Domain**: `{report['dns_domain']}`")
    lines.extend(
        [
            "",
            "## Discovery Funnel",
            "| Category | Count |",
            "| :--- | :--- |",
        ]
    )
    for k, v in report["funnel"].items():
        lines.append(f"| `{k}` | {v} |")

    lines.extend(
        [
            "",
            "## Quality Gates",
            "| Gate | Severity | Status | Detail |",
            "| :--- | :--- | :--- | :--- |",
        ]
    )
    for g in report["gates"]:
        lines.append(f"| `{g['gate']}` | {g['severity']} | **{g['status']}** | {g['detail']} |")

    pc = report["port_confidence"]
    lines.extend(
        [
            "",
            "## Per-Port Configuration Confidence",
            f"- Total Profiled Ports: **{pc['total_ports']}**",
            f"- Known Mode: **{pc['known_mode_pct']}%**",
            f"- Known VLAN(s): **{pc['known_vlan_pct']}%**",
            f"- Known Trunk Native VLAN: **{pc['known_trunk_native_pct']}%**",
        ]
    )
    with open(os.path.join(manifest_dir, "data_quality_report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

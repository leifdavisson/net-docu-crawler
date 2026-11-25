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

from net_docu_crawler.drivers.base import detect_cli_error
from net_docu_crawler.schema import (
    APPLIANCE_TYPES,
    CRITICAL_COLLECTION_SECTIONS,
    normalize_collection_status,
)


def _is_crawled_infra_record(dev: dict) -> bool:
    """Return True only for crawled network infrastructure (never unsupported_appliance/server hosts)."""
    if not isinstance(dev, dict):
        return False
    rc = str(dev.get("record_class") or "").strip().lower()
    if rc:
        return rc == "crawled_infra"
    status = str(dev.get("status") or "").strip().lower()
    if status != "success":
        return False
    dtype = str(dev.get("device_type") or dev.get("device_persona") or "").strip().lower()
    return dtype not in APPLIANCE_TYPES


def evaluate_quality_gates(raw_devices: list[dict], trunk_audit: dict | None = None) -> dict:
    """Evaluate correlated `raw_devices` against P0/P1 cutover-readiness gates."""
    if trunk_audit is None:
        from net_docu_crawler.trunk_audit import evaluate_trunk_mismatches

        trunk_audit = evaluate_trunk_mismatches(raw_devices)
    trunk_summary = dict((trunk_audit or {}).get("summary") or {})

    funnel = Counter(d.get("record_class", "unknown") for d in raw_devices if isinstance(d, dict))
    infra = [d for d in raw_devices if _is_crawled_infra_record(d)]

    gates: list[dict] = []
    total_ports = 0
    known_mode = 0
    known_vlan = 0
    known_native_on_trunk = 0
    trunk_ports = 0

    poe_contradictions: list[str] = []
    stp_missing_root: list[str] = []
    critical_collection_failures: list[str] = []
    optional_collection_failures: list[str] = []
    section_state_counts: dict[str, dict[str, int]] = {}
    total_parse_errors = 0
    has_explicit_collection_status = False

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

        cs_raw = dev.get("collection_status")
        if isinstance(cs_raw, dict) and cs_raw:
            has_explicit_collection_status = True
            for sec, raw_st in cs_raw.items():
                st_norm = normalize_collection_status(raw_st)
                bucket = section_state_counts.setdefault(str(sec), {})
                bucket[st_norm] = bucket.get(st_norm, 0) + 1
                if st_norm in ("command_failed", "parse_failed"):
                    label = f"{host}:{sec} ({st_norm})"
                    if sec in CRITICAL_COLLECTION_SECTIONS:
                        critical_collection_failures.append(label)
                    else:
                        optional_collection_failures.append(label)
        p_errs = dev.get("parse_errors")
        if isinstance(p_errs, list):
            total_parse_errors += len(p_errs)

    if total_ports == 0:
        cabling_vlan_status = "NOT_EVALUATED"
        cabling_vlan_detail = "0 profiled ports evaluated across crawled infrastructure."
    elif known_vlan > 0:
        cabling_vlan_status = "PASS"
        cabling_vlan_detail = f"{known_vlan}/{total_ports} ports have resolved access or allowed VLANs."
    else:
        cabling_vlan_status = "FAIL"
        cabling_vlan_detail = f"0/{total_ports} ports have resolved access or allowed VLANs."

    gates.append(
        {
            "gate": "GATE_CABLING_VLAN_EMPTY",
            "severity": "P0",
            "status": cabling_vlan_status,
            "detail": cabling_vlan_detail,
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
            "status": (
                "NOT_EVALUATED" if trunk_ports == 0 else ("WARN" if known_native_on_trunk < trunk_ports else "PASS")
            ),
            "detail": (
                "0 trunk ports evaluated."
                if trunk_ports == 0
                else f"{known_native_on_trunk}/{trunk_ports} trunk ports have resolved native VLAN."
            ),
        }
    )

    crit_cnt = int(trunk_summary.get("critical_count", 0) or 0)
    high_cnt = int(trunk_summary.get("high_count", 0) or 0)
    med_cnt = int(trunk_summary.get("medium_count", 0) or 0)
    low_cnt = int(trunk_summary.get("low_count", 0) or 0)
    total_findings = int(trunk_summary.get("total_findings", len((trunk_audit or {}).get("findings") or [])) or 0)
    edges_eval = int(
        trunk_summary.get(
            "total_trunk_edges_evaluated",
            trunk_summary.get("edges_evaluated", trunk_summary.get("total_edges", 0)),
        )
        or 0
    )
    if crit_cnt + high_cnt > 0:
        trunk_mismatch_status = "WARN"
        trunk_mismatch_detail = (
            f"Detected {crit_cnt} CRITICAL and {high_cnt} HIGH trunk VLAN mismatch(es) "
            f"across {edges_eval} evaluated trunk link(s) "
            f"({total_findings} total finding(s): {crit_cnt} CRITICAL, {high_cnt} HIGH, {med_cnt} MEDIUM, {low_cnt} LOW)."
        )
    elif edges_eval == 0:
        trunk_mismatch_status = "NOT_EVALUATED"
        trunk_mismatch_detail = (
            f"0 trunk links evaluated ({total_findings} finding(s)); no inter-switch trunks audited."
        )
    else:
        trunk_mismatch_status = "PASS"
        trunk_mismatch_detail = (
            f"0 CRITICAL/HIGH trunk VLAN mismatches across {edges_eval} evaluated trunk link(s) "
            f"({total_findings} total finding(s))."
        )
    gates.append(
        {
            "gate": "GATE_TRUNK_VLAN_MISMATCH",
            "severity": "P1",
            "status": trunk_mismatch_status,
            "detail": trunk_mismatch_detail,
        }
    )

    if critical_collection_failures:
        coll_sev, coll_status = "P0", "FAIL"
        coll_detail = (
            f"Critical telemetry collection failed on {len(critical_collection_failures)} section(s): "
            f"{', '.join(critical_collection_failures[:8])}"
        )
    elif optional_collection_failures or total_parse_errors > 0:
        coll_sev, coll_status = "P1", "WARN"
        coll_detail = (
            f"{len(optional_collection_failures)} optional section failure(s) and "
            f"{total_parse_errors} parse error(s): {', '.join(optional_collection_failures[:8]) or 'see parse_errors'}"
        )
    elif has_explicit_collection_status:
        coll_sev, coll_status = "P1", "PASS"
        coll_detail = "All collected telemetry sections completed without command/parse failures."
    else:
        coll_sev, coll_status = "P1", "NOT_EVALUATED"
        coll_detail = "Legacy dataset without per-section collection_status metadata."

    gates.append(
        {
            "gate": "GATE_COLLECTION_INTEGRITY",
            "severity": coll_sev,
            "status": coll_status,
            "detail": coll_detail,
        }
    )

    unauthenticated_devices: list[dict] = []
    command_header_mismatches: list[dict] = []
    for dev in raw_devices:
        if not isinstance(dev, dict):
            continue
        ip = str(dev.get("ip") or "")
        st = str(dev.get("status") or "").strip().lower()
        hn = str(dev.get("hostname") or ip).strip()
        if st == "unauthenticated":
            unauthenticated_devices.append(
                {
                    "ip": ip,
                    "hostname": hn,
                    "vendor": str(dev.get("vendor") or "Unknown"),
                    "mac_address": str(dev.get("mac_address") or ""),
                    "model": str(dev.get("model") or ""),
                }
            )
        elif _is_crawled_infra_record(dev):
            reasons: list[str] = []
            if not hn or hn == ip or hn.lower() == "unknown":
                reasons.append("hostname unresolved (header/version parse mismatch)")
            if not (dev.get("interfaces_detail") or {}):
                reasons.append("0 interfaces parsed (command/driver mismatch)")
            cfg_marker = detect_cli_error(str(dev.get("raw_config") or ""))
            if cfg_marker:
                reasons.append(f"CLI error in config output (`{cfg_marker}`)")
            if reasons:
                command_header_mismatches.append(
                    {
                        "ip": ip,
                        "hostname": hn or ip,
                        "vendor": str(dev.get("vendor") or "Unknown"),
                        "reasons": "; ".join(reasons),
                    }
                )

    p0_failed = any(g["severity"] == "P0" and g["status"] == "FAIL" for g in gates)
    return {
        "passed": not p0_failed,
        "gates": gates,
        "trunk_audit_summary": trunk_summary,
        "unauthenticated_devices": unauthenticated_devices,
        "command_header_mismatches": command_header_mismatches,
        "collection_coverage": {
            "sections": section_state_counts,
            "critical_failures": critical_collection_failures,
            "optional_failures": optional_collection_failures,
            "parse_error_count": total_parse_errors,
        },
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

    unauth = report.get("unauthenticated_devices") or []
    mismatches = report.get("command_header_mismatches") or []
    if unauth or mismatches:
        lines.extend(["", "## Unauthenticated Devices & Command/Header Mismatches"])
    if unauth:
        lines.extend(
            [
                "",
                f"### Unauthenticated Devices ({len(unauth)})",
                "| IP Address | Hostname | Vendor / OUI | MAC Address | Banner / Model |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for u in unauth:
            lines.append(
                f"| `{u['ip']}` | **{u['hostname']}** | {u['vendor']} | `{u['mac_address'] or 'N/A'}` | `{u['model'] or 'N/A'}` |"
            )
    if mismatches:
        lines.extend(
            [
                "",
                f"### Crawled Command / Header Mismatches ({len(mismatches)})",
                "| IP Address | Hostname | Vendor | Mismatch Detail |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for m in mismatches:
            lines.append(f"| `{m['ip']}` | **{m['hostname']}** | {m['vendor']} | {m['reasons']} |")

    with open(os.path.join(manifest_dir, "data_quality_report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

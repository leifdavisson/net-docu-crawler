# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
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
Regression tests for Wave 1 Branch 2 (`swarm/reports/mermaid-csv-cutover-security`):
RP-11 (Mermaid escaping & diagram_validator strictness),
RP-12 (CSV int-list TypeError, newline/formula sanitization, non-infra filtering & MD escaping),
RP-13 / SF-12 (Bash & PowerShell injection hardening in validate_cutover.sh / .ps1).
"""

import csv
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report_generator
from net_docu_crawler.diagram_validator import validate_mermaid_block
from net_docu_crawler.topology_resolver import DeviceRegistry


def test_mermaid_safe_text_and_slug_neutralize_special_chars():
    """RP-11: _mermaid_safe_text neutralizes trailing \\, |, #, ;, `, %%, [], {}; _mermaid_slug avoids reserved words."""
    # Trailing backslash must never emit '\"' inside Mermaid node definitions
    safe_bs = report_generator._mermaid_safe_text("Uplink\\")
    assert not safe_bs.endswith("\\")
    assert validate_mermaid_block(f'flowchart LR\n  sw_0["{safe_bs}"]\n') == []

    # Edge-breaking & syntax-breaking special characters must all be neutralized
    hostile = 'SW[Core]{1} | Rack #3; `md` %% comment "quoted" \\'
    safe = report_generator._mermaid_safe_text(hostile)
    for forbidden in ("[", "]", "{", "}", "|", "#", ";", "`", "%%", '"', "\\"):
        assert forbidden not in safe, f"Unescaped {forbidden!r} remained in {safe!r}"
    block = f'flowchart LR\n  sw_0["{safe}"]\n  sw_0 -->|"Gi0/1 {safe}"| sw_1["Peer"]\n'
    assert validate_mermaid_block(block) == []

    # Reserved Mermaid keywords must never be returned bare by _mermaid_slug
    for kw in ("end", "subgraph", "class", "click", "style", "default", "graph", "flowchart"):
        slug = report_generator._mermaid_slug(kw)
        assert slug != kw, f"Reserved Mermaid keyword {kw!r} returned bare by _mermaid_slug"


def test_diagram_validator_strict_checks():
    """RP-11: diagram_validator detects | in edge labels, mid-line %%, backticks, unbalanced subgraph, reserved IDs, linkStyle bounds, >50k chars."""
    # 1. Unescaped pipe inside edge label
    assert validate_mermaid_block('flowchart LR\n  a["A"] -->|"Gi0/1 | Uplink"| b["B"]\n')

    # 2. Mid-line %% comment
    assert validate_mermaid_block('flowchart LR\n  a["A %% breaks"]\n')

    # 3. Backtick inside quoted label
    assert validate_mermaid_block('flowchart LR\n  a["Host `cmd`"]\n')

    # 4. Unbalanced subgraph / end
    assert validate_mermaid_block('flowchart LR\n  subgraph S1 ["Site"]\n    a["A"]\n')
    assert validate_mermaid_block('flowchart LR\n  a["A"]\n  end\n')

    # 5. Reserved keyword used as bare node ID
    assert validate_mermaid_block('flowchart LR\n  end["Router"]\n')

    # 6. Out-of-bounds linkStyle index
    assert validate_mermaid_block('flowchart LR\n  a["A"] --> b["B"]\n  linkStyle 5 stroke:#333;\n')

    # 7. Exceeding Mermaid default 50,000-char maxTextSize
    huge = "flowchart LR\n" + ('  a["' + ("x" * 100) + '"]\n') * 520
    assert validate_mermaid_block(huge)


def test_l3_site_diagram_no_strip_br_corruption_and_dup_ip_spacing_and_stadium_compaction(tmp_path):
    """RP-11: .strip('<br/>') must not truncate 'Lab'/'Server'; dup_ip retains space; stadium ext_*([ compacted."""
    # Verify stadium ext_*([ nodes are compacted when oversized
    big_stadium = ["```mermaid", "flowchart LR", '  sw_0["Core"]']
    big_stadium.extend([f'  ext_{i}(["WAN-Cloud-{i}-' + ("x" * 180) + '"])' for i in range(250)])
    big_stadium.append("```")
    compacted = report_generator._compact_mermaid_block_if_oversized(big_stadium, max_chars=2000)
    joined = "\n".join(compacted)
    assert "ext_summary" in joined
    assert len(joined) <= 2500

    # Verify site-scoped L3 diagram does not truncate descriptions ending in 'b'/'r' (e.g. 'Lab', 'Server')
    # and preserves space before '(duplicate_ip)' in conflict nodes
    devices = {}
    for idx in range(1, 13):
        site = "S1" if idx <= 6 else "S2"
        ip = f"10.{idx}.0.1"
        devices[ip] = {
            "ip": ip,
            "hostname": f"{site}-RTR-{idx}",
            "site_code": site,
            "status": "success",
            "device_type": "router",
            "device_persona": "router",
            "l3_interfaces": [
                {"interface": "Vlan10", "ip_address": f"10.{idx}.10.1/24", "status": "up"},
                *([{"interface": "Vlan99", "ip_address": "172.23.2.1/24", "status": "up"}] if idx in (1, 7) else []),
            ],
            "vlans": {"10": {"id": "10", "name": "Lab", "description": "Server"}},
            "routes": [{"subnet": "0.0.0.0/0", "protocol": "Static", "next_hop": "10.1.0.254", "interface": "Vlan10"}],
            "interfaces_detail": {"Gi0/0": {"status": "up"}},
            "neighbors": [],
        }

    l3_path = tmp_path / "L3.md"
    report_generator.generate_l3_diagram(devices, str(l3_path))
    l3_txt = l3_path.read_text(encoding="utf-8")
    assert "Server" in l3_txt
    assert 'Serve"' not in l3_txt
    assert "172.23.2.0/24 (172.23.2.1)" in l3_txt
    assert "172.23.2.0/24(172.23.2.1)" not in l3_txt
    for blk in re.findall(r"```mermaid\n(.*?)```", l3_txt, re.DOTALL):
        assert validate_mermaid_block(blk) == []


def test_csv_int_vlan_list_no_typeerror_newline_formula_sanitization_and_infra_filter(tmp_path):
    """RP-12 & RP-10: interfaces.csv/svi_routes.csv handle int lists; CSVs collapse newlines, neutralize formulas, exclude servers."""
    sw = {
        "ip": "10.0.0.1",
        "hostname": "SW-01",
        "status": "success",
        "record_class": "crawled_infra",
        "device_type": "switch",
        "device_persona": "switch",
        "vendor": "Cisco",
        "model": "=CMD|' /C calc'!A0",
        "interfaces_detail": {
            "Gi1/0/1": {
                "status": "up",
                "description": "Line1\nLine2\r\n=SUM(A1:A2)",
                "speed": "1Gb/s",
                "duplex": "Full",
            }
        },
        "ports": {
            "Gi1/0/1": {
                "hostname": "SW-01",
                "interface": "Gi1/0/1",
                "oper_state": "up",
                "mode": "trunk",
                "allowed_vlans": [10, 20, 30],  # ints! Previously raised TypeError
                "hygiene_disposition": "REVIEW",
                "hygiene_reason": "+malicious\nmultiline",
            }
        },
        "vlans": {"10": {"id": "10", "name": "@VLAN_FORMULA"}},
        "l3_interfaces": [{"interface": "Vlan10", "ip_address": "10.0.10.1/24", "status": "up"}],
        "dhcp": {"relays": [{"interface": "Vlan10", "helper_ip": "10.0.0.50"}]},
        "poe": {"total_power_watts": 370.0, "used_power_watts": 45.0, "poe_delivering_ports": 1},
        "neighbors": [
            {
                "local_port": "Gi1/0/1",
                "remote_device": "-2+3;calc",
                "remote_port": "eth0",
                "platform": "LineA\nLineB",
            }
        ],
    }
    server_host = {
        "ip": "10.0.0.12",
        "hostname": "pve",
        "status": "success",
        "record_class": "unsupported_appliance",
        "device_type": "server",
        "device_persona": "server",
        "interfaces_detail": {"vmbr0": {"status": "up", "description": "Proxmox bridge"}},
        "ports": {"vmbr0": {"hostname": "pve", "interface": "vmbr0", "oper_state": "up", "mode": "unknown"}},
    }
    devices_dict = {"10.0.0.1": sw, "10.0.0.12": server_host}

    # 1. Layered CSVs must NOT raise TypeError on int allowed_vlans, must exclude pve server, and sanitize newlines/formulas
    reg = DeviceRegistry()
    reg.register_device(sw)
    report_generator.export_layered_csvs([sw, server_host], reg, str(tmp_path))

    iface_csv = tmp_path / "02_normalized" / "interfaces.csv"
    raw_lines = iface_csv.read_text(encoding="utf-8").splitlines()
    assert len(raw_lines) == 2  # Header + 1 SW-01 row only (no pve, no embedded newline splits!)
    with open(iface_csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["hostname"] == "SW-01"
    assert rows[0]["allowed_vlans"] == "10,20,30"
    assert "\n" not in rows[0]["hygiene_reason"]
    assert rows[0]["hygiene_reason"].startswith("'")

    # vlans.csv formula neutralized
    with open(tmp_path / "02_normalized" / "vlans.csv", encoding="utf-8") as f:
        vrows = list(csv.DictReader(f))
    assert vrows[0]["vlan_name"].startswith("'")

    # 2. migration_cabling_matrix.csv must exclude pve server and collapse newlines/neutralize formula
    cabling_csv = tmp_path / "migration_cabling_matrix.csv"
    report_generator.generate_cabling_matrix(devices_dict, str(cabling_csv))
    c_lines = cabling_csv.read_text(encoding="utf-8").splitlines()
    assert len(c_lines) == 2
    with open(cabling_csv, encoding="utf-8") as f:
        crows = list(csv.DictReader(f))
    assert crows[0]["Source Hostname"] == "SW-01"
    assert "\n" not in crows[0]["Description"]
    assert crows[0]["Neighbor Hostname"].startswith("'")

    # 3. asset_inventory.csv neutralizes formula in Model
    asset_csv = tmp_path / "asset_inventory.csv"
    report_generator.generate_asset_inventory(devices_dict, str(asset_csv))
    with open(asset_csv, encoding="utf-8") as f:
        arows = {r["IP Address"]: r for r in csv.DictReader(f)}
    assert arows["10.0.0.1"]["Model"].startswith("'")

    # 4. Markdown cell escaping helper
    escaped = report_generator._escape_md_cell("Port A | Uplink\nLine2")
    assert "\\|" in escaped
    assert "\n" not in escaped


def test_cutover_scripts_prevent_bash_and_powershell_injection(tmp_path):
    """RP-13 / SF-12: Malicious hostnames/IPs cannot inject commands into validate_cutover.sh or validate_cutover.ps1."""
    devices = {
        "192.168.1.1": {
            "ip": "192.168.1.1",
            "hostname": 'SW$(touch /tmp/pwned);`id`"$(whoami)"\necho INJECTED',
            "status": "success",
            "device_type": "switch",
            "device_persona": "switch",
            "l3_interfaces": [{"interface": "Vlan1", "ip_address": "192.168.1.1/24"}],
            "services": {"dns_servers": ["1.1.1.1", '8.8.8.8"; touch /tmp/pwned #']},
        },
        "192.168.1.12": {
            "ip": "192.168.1.12",
            "hostname": "pve-server",
            "status": "success",
            "record_class": "unsupported_appliance",
            "device_type": "server",
            "device_persona": "server",
        },
    }
    sh_path = tmp_path / "validate_cutover.sh"
    report_generator.generate_cutover_validation_script(devices, str(sh_path))
    sh_code = sh_path.read_text(encoding="utf-8")
    ps1_code = (tmp_path / "validate_cutover.ps1").read_text(encoding="utf-8")

    # Bash script must pass `bash -n` syntax check and contain zero unescaped $() / backticks / raw newlines
    proc = subprocess.run(["bash", "-n", str(sh_path)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"bash -n failed: {proc.stderr}"
    assert "\necho INJECTED" not in sh_code
    assert 'check_port "192.168.1.1" 22 "' in sh_code
    phase3_sh = sh_code.split("Phase 3:")[1].split("Validation Summary")[0]
    assert r"\$(" in phase3_sh
    assert r"\`" in phase3_sh
    assert "8.8.8.8" not in sh_code  # Invalid DNS IP with shell injection payload rejected

    # PowerShell script must escape $, `, " and reject newline/bad IP injection and exclude non-infra server
    assert "\necho INJECTED" not in ps1_code
    phase3_ps = ps1_code.split("Phase 3:")[1].split("Validation Summary")[0]
    assert "`$(" in phase3_ps
    assert "``id``" in phase3_ps
    assert "pve-server" not in phase3_ps
    assert "8.8.8.8" not in ps1_code

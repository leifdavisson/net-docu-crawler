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

"""Regression tests for documentation, packaging, credential schema docs, and driver-doc parity."""

import json
import re
from pathlib import Path

from net_docu_crawler.crawler import validate_credentials
from net_docu_crawler.drivers import DRIVER_VENDOR_MAP

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text(encoding="utf-8")


def _parse_pyproject_dep_lists(toml_text: str) -> tuple[set[str], set[str]]:
    """Parse [project].dependencies and [project.optional-dependencies].dev (Python 3.10+ safe)."""
    try:
        import tomllib  # type: ignore[import-not-found]

        data = tomllib.loads(toml_text)
        return (
            set(data["project"]["dependencies"]),
            set(data["project"]["optional-dependencies"]["dev"]),
        )
    except ModuleNotFoundError:
        m_core = re.search(r"dependencies\s*=\s*\[([^\]]+)\]", toml_text, re.DOTALL)
        m_dev = re.search(r"\[project\.optional-dependencies\].*?dev\s*=\s*\[([^\]]+)\]", toml_text, re.DOTALL)
        assert m_core and m_dev
        return (
            set(re.findall(r'"([^"]+)"', m_core.group(1))),
            set(re.findall(r'"([^"]+)"', m_dev.group(1))),
        )


def _parse_requirements_file(rel_path: str) -> set[str]:
    reqs: set[str] = set()
    for raw_line in _read(rel_path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-r "):
            continue
        reqs.add(line)
    return reqs


def test_fortinet_docs_no_config_mode_paging():
    """CD-01: Fortinet docs must never prescribe global config writes for paging."""
    for rel_path in (
        "docs/drivers/fortinet.md",
        "docs/drivers/overview.md",
        "docs/proxmox_lab_and_driver_roadmap.md",
    ):
        text = _read(rel_path)
        assert "config system console" not in text, f"{rel_path} still documents config-mode paging write"
        assert "set output standard" not in text, f"{rel_path} still documents set output standard write"

    fg_doc = _read("docs/drivers/fortinet.md")
    assert "ReadOnlyFortinetSSH" in fg_doc
    assert "--More--" in fg_doc
    assert "get system interface transceiver" in fg_doc


def test_mikrotik_rbac_allows_ssh():
    """CD-06 & CD-14: MikroTik RBAC snippet must allow SSH and match actual RouterOS commands."""
    mt_doc = _read("docs/drivers/mikrotik.md")
    assert "!ssh" not in mt_doc, "MikroTik RBAC snippet blocks SSH with !ssh"
    assert re.search(r"policy=[^\r\n]*\bssh\b", mt_doc), "MikroTik RBAC snippet must include ssh policy"
    assert "/system identity print detail" not in mt_doc
    assert "/system identity print" in mt_doc
    assert "/system routerboard print" in mt_doc
    assert "/interface print detail without-paging" in mt_doc
    assert '/interface ethernet monitor [find where name~"sfp"] once' in mt_doc


def test_pyproject_dev_extra_matches_requirements_dev():
    """CD-11: pyproject.toml core & dev dependencies must match requirements.txt & requirements-dev.txt."""
    core_pyproject, dev_pyproject = _parse_pyproject_dep_lists(_read("pyproject.toml"))

    core_req = _parse_requirements_file("requirements.txt")
    dev_req = _parse_requirements_file("requirements-dev.txt")

    assert core_pyproject == core_req
    assert dev_pyproject == dev_req
    assert any(dep.startswith("mypy") for dep in dev_pyproject)
    assert any(dep.startswith("pre-commit") for dep in dev_pyproject)


def test_install_docs_consistent_venv_and_python_versions():
    """CD-12: Install docs must consistently reference .venv and Windows Python 3.10-3.12."""
    playbook = _read("docs/junior_operator_playbook.md")
    win_guide = _read("docs/windows_operator_guide.md")
    readme = _read("README.md")

    assert "3.13, 3.14" not in playbook, "Windows playbook must not claim Python 3.13/3.14 is prebuilt-wheel ready"
    assert "3.10" in playbook and "3.12" in playbook
    assert ".venv" in readme
    assert ".venv" in playbook
    assert ".venv" in win_guide
    assert r".\venv\Scripts" not in win_guide, "Windows operator guide should use .venv matching setup_windows.ps1"
    assert "pip install -e ." in readme


def test_credentials_docs_use_canonical_secret_schema():
    """CD-02: Playbook & driver credential examples must use canonical secret + vendor schema."""
    playbook = _read("docs/junior_operator_playbook.md")
    # Playbook JSON template must show canonical "secret" field matching credentials.example.json
    assert '"secret"' in playbook
    assert '"vendor"' in playbook
    assert '"enable_secret": ""' not in playbook

    for rel_path, expected_vendor in (
        ("docs/drivers/openwrt.md", "openwrt"),
        ("docs/drivers/opnsense.md", "opnsense"),
    ):
        doc = _read(rel_path)
        assert f'"vendor": "{expected_vendor}"' in doc, f"{rel_path} credential example missing vendor tag"

    # Verify credentials.example.json itself passes validation with canonical vendor tags
    example_data = json.loads(_read("credentials.example.json"))
    valid, warnings, errors = validate_credentials(example_data, source="credentials.example.json")
    assert errors == []
    assert warnings == []
    assert len(valid) == len(example_data)
    canonical_vendors = set(DRIVER_VENDOR_MAP.values())
    for entry in valid:
        assert "enable_secret" not in entry
        assert entry.get("vendor") in canonical_vendors


def test_aruba_doc_commands_match_driver():
    """CD-13: docs/drivers/aruba.md commands must match net_docu_crawler/drivers/aruba.py."""
    aruba_doc = _read("docs/drivers/aruba.md")
    assert "show lldp info remote-device detail" not in aruba_doc
    assert "show lldp neighbor-info detail" in aruba_doc
    assert "show network" not in aruba_doc
    assert "show configuration" in aruba_doc
    assert "show ip interface brief" in aruba_doc
    assert "show ip route" in aruba_doc
    assert "show interface transceiver" in aruba_doc


def test_all_drivers_documented_and_commands_match():
    """CD-14: All 13 drivers (including CiscoXRDriver) must be documented accurately against driver code."""
    expected_driver_docs = {
        "cisco": ("docs/drivers/cisco.md", "cisco.py"),
        "cisco_xr": ("docs/drivers/cisco_xr.md", "cisco_xr.py"),
        "ciscosmb": ("docs/drivers/ciscosmb.md", "ciscosmb.py"),
        "juniper": ("docs/drivers/juniper.md", "juniper.py"),
        "arista": ("docs/drivers/arista.md", "arista.py"),
        "hpprocurve": ("docs/drivers/hpprocurve.md", "hpprocurve.py"),
        "aruba": ("docs/drivers/aruba.md", "aruba.py"),
        "mikrotik": ("docs/drivers/mikrotik.md", "mikrotik.py"),
        "fortinet": ("docs/drivers/fortinet.md", "fortinet.py"),
        "paloalto": ("docs/drivers/paloalto.md", "paloalto.py"),
        "opnsense": ("docs/drivers/opnsense.md", "opnsense.py"),
        "openwrt": ("docs/drivers/openwrt.md", "openwrt.py"),
        "frrouting": ("docs/drivers/frr.md", "frr.py"),
    }
    assert set(DRIVER_VENDOR_MAP.values()) == set(expected_driver_docs.keys())

    overview = _read("docs/drivers/overview.md")
    readme = _read("README.md")

    for _vendor, (doc_rel, py_name) in expected_driver_docs.items():
        doc_path = REPO_ROOT / doc_rel
        assert doc_path.is_file(), f"Missing driver documentation: {doc_rel}"
        doc_text = doc_path.read_text(encoding="utf-8")
        assert f"net_docu_crawler/drivers/{py_name}" in doc_text, f"{doc_rel} missing link to {py_name}"
        assert Path(doc_rel).name in overview, f"docs/drivers/overview.md missing link to {doc_rel}"
        assert f"net_docu_crawler/drivers/{py_name}" in readme, f"README.md missing link to {py_name}"

    # Specific per-driver command accuracy checks (unescape markdown table pipes `\|`)
    arista_doc = _read("docs/drivers/arista.md").replace(r"\|", "|")
    assert "show ip interface | json" in arista_doc
    assert "show interfaces | json" in arista_doc
    assert "show interfaces status" not in arista_doc
    assert "show hostname | json" in arista_doc
    assert "show spanning-tree | json" in arista_doc
    assert "show interfaces trunk | json" in arista_doc
    assert "show port-channel summary | json" in arista_doc

    cisco_doc = _read("docs/drivers/cisco.md")
    assert "cisco_xr.md" in cisco_doc
    assert "CiscoXRDriver" in cisco_doc
    assert "show l2vpn forwarding" not in cisco_doc

    xr_doc = _read("docs/drivers/cisco_xr.md")
    for cmd in (
        "show ipv4 interface brief",
        "show bundle",
        "show vrf all detail",
        "show mpls ldp neighbor brief",
        "show bgp all all summary",
    ):
        assert cmd in xr_doc

    ciscosmb_doc = _read("docs/drivers/ciscosmb.md")
    assert "generic_telnet" not in ciscosmb_doc
    assert "show interfaces switchport" in ciscosmb_doc
    assert "show interfaces port-channel" in ciscosmb_doc

    hp_doc = _read("docs/drivers/hpprocurve.md")
    assert "`show version`" not in hp_doc
    assert "show vlans ports all" in hp_doc
    assert "show power-over-ethernet brief" in hp_doc
    assert "show interfaces transceiver" in hp_doc
    assert "show lldp info remote-device detail" in hp_doc

    frr_doc = _read("docs/drivers/frr.md")
    assert "ip -s -j link show" in frr_doc
    assert "vtysh -c 'show interface json'" in frr_doc

    openwrt_doc = _read("docs/drivers/openwrt.md")
    assert "ip -j neigh show" not in openwrt_doc
    assert "head -n 1000 /etc/config/*" in openwrt_doc

    opnsense_doc = _read("docs/drivers/opnsense.md")
    assert "kenv smbios.system.serial" in opnsense_doc
    assert "netstat -rnW -f inet" in opnsense_doc

    assert "13 Multi-Vendor Read-Only Drivers" in readme
    assert "CiscoSMBDriver" in overview
    assert "CiscoXRDriver" in overview
    arista_rows = [line for line in overview.splitlines() if "Arista Networks" in line]
    assert arista_rows and any("terminal length 0" in row for row in arista_rows)


def test_deliverables_and_cli_docs_accuracy():
    """CD-05, CD-08, CD-09, CD-15: Deliverables, CLI options, and safety notes must match runtime behavior."""
    readme = _read("README.md")
    manpage = _read("docs/man/net-crawler.1.md")
    overview = _read("docs/drivers/overview.md")
    win_guide = _read("docs/windows_operator_guide.md")
    playbook = _read("docs/junior_operator_playbook.md")

    # asset_inventory.csv is infra_only=True; unauthenticated/unsupported hosts go to failures.csv / failed_hosts.json
    assert "including unauthenticated, unsupported, and ARP-discovered hosts" not in readme
    assert "00_manifest/failures.csv" in readme
    assert "cutover_runbook.md" in readme
    assert "manual_followup_report.md" in readme
    assert "topology_interactive.html" in readme

    for artifact in (
        "cutover_runbook.md",
        "trunk_vlan_audit.md",
        "manual_followup_report.md",
        "topology_interactive.html",
        "cisco_to_target_translation.md",
    ):
        assert artifact in manpage, f"docs/man/net-crawler.1.md missing deliverable {artifact}"

    assert "ip:port" in manpage
    assert "--netconf" in manpage
    assert "--gnmi" in manpage
    assert "--install-deps" in manpage
    assert "`fortinet`, `meraki`" not in manpage, "manpage must not advertise unsupported --target-vendor fortinet"
    assert "asset_inventory.csv` and `port_mac_endpoint_mapping.csv`" not in overview

    # Windows guide must not contradict fallback semantics of --vendor-hint
    assert "Force a specific driver" not in win_guide

    # Playbook must reflect both SSH/Telnet default probing and accurate AAA guidance
    assert "only attempts SSH logins" not in playbook
    assert "cisco_xr" in playbook


def test_docs_have_agpl_spdx_and_backlinks():
    """CD-16: Docs must include AGPLv3 SPDX headers and official upstream backlinks per AGENTS.md."""
    spdx_required = [
        "README.md",
        "CONTRIBUTING.md",
        "docs/junior_operator_playbook.md",
        "docs/windows_operator_guide.md",
        "docs/man/net-crawler.1.md",
        "docs/proxmox_lab_and_driver_roadmap.md",
        "docs/drivers/overview.md",
        "docs/drivers/arista.md",
        "docs/drivers/aruba.md",
        "docs/drivers/cisco.md",
        "docs/drivers/cisco_xr.md",
        "docs/drivers/ciscosmb.md",
        "docs/drivers/fortinet.md",
        "docs/drivers/frr.md",
        "docs/drivers/hpprocurve.md",
        "docs/drivers/juniper.md",
        "docs/drivers/mikrotik.md",
        "docs/drivers/openwrt.md",
        "docs/drivers/opnsense.md",
        "docs/drivers/paloalto.md",
    ]
    for rel_path in spdx_required:
        head = "\n".join(_read(rel_path).splitlines()[:20])
        assert "SPDX-License-Identifier: AGPL-3.0-or-later" in head, f"Missing AGPLv3 SPDX header in {rel_path}"

    netmiko_docs = [
        "docs/drivers/arista.md",
        "docs/drivers/aruba.md",
        "docs/drivers/cisco.md",
        "docs/drivers/cisco_xr.md",
        "docs/drivers/ciscosmb.md",
        "docs/drivers/fortinet.md",
        "docs/drivers/frr.md",
        "docs/drivers/hpprocurve.md",
        "docs/drivers/juniper.md",
        "docs/drivers/mikrotik.md",
        "docs/drivers/openwrt.md",
        "docs/drivers/paloalto.md",
        "docs/junior_operator_playbook.md",
    ]
    for rel_path in netmiko_docs:
        assert "https://github.com/ktbyers/netmiko" in _read(rel_path), f"Missing Netmiko backlink in {rel_path}"

    playbook = _read("docs/junior_operator_playbook.md")
    assert "https://www.paramiko.org/" in playbook
    assert "https://netaddr.readthedocs.io/" in playbook

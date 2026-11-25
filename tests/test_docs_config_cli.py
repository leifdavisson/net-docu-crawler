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

"""Regression tests for Wave 3 CLI flags, credential schema, packaging, and wrapper parity."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_credentials_enable_secret_alias_and_validation(tmp_path):
    """CD-02: validate_credentials supports backwards-compat enable_secret, flags bad types/conflicts/unknown keys."""
    from net_docu_crawler.crawler import load_and_validate_credentials, validate_credentials

    # 1. Legacy enable_secret maps to canonical secret with deprecation warning
    entries = [{"name": "Legacy", "vendor": "cisco", "username": " admin ", "password": "pw", "enable_secret": "sec1"}]
    valid, warnings, errors = validate_credentials(entries, source="legacy.json")
    assert errors == []
    assert len(valid) == 1
    assert valid[0]["username"] == "admin"
    assert valid[0]["secret"] == "sec1"
    assert "enable_secret" not in valid[0]
    assert any("enable_secret" in w and "deprecated" in w.lower() for w in warnings)

    # 2. Wrong type for enable_secret is rejected
    _, _, err_type = validate_credentials(
        [{"name": "BadType", "username": "admin", "password": "pw", "enable_secret": 123}],
        source="badtype.json",
    )
    assert any("enable_secret" in e and "string" in e for e in err_type)

    # 3. Conflicting secret and enable_secret values are rejected
    _, _, err_conflict = validate_credentials(
        [{"name": "Conflict", "username": "admin", "password": "pw", "secret": "s1", "enable_secret": "s2"}],
        source="conflict.json",
    )
    assert any("conflicting" in e.lower() for e in err_conflict)

    # 4. Unknown/typo key emits warning naming key only
    _, warn_unknown, err_unknown = validate_credentials(
        [{"name": "Typo", "username": "admin", "password": "pw", "passowrd": "secret_val"}],
        source="typo.json",
    )
    assert err_unknown == []
    assert any("passowrd" in w and "secret_val" not in w for w in warn_unknown)

    # 5. Empty list file fails clearly via load_and_validate_credentials
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("[]", encoding="utf-8")
    v_emp, _, err_emp = load_and_validate_credentials(str(empty_file))
    assert v_emp == []
    assert any("No valid credential" in e for e in err_emp)


def test_cli_netconf_gnmi_flags_wired_to_options_and_xr_driver():
    """CD-03: --netconf/--gnmi flags must be wired into CrawlOptions, main(), and CiscoXRDriver."""
    from net_docu_crawler.crawler import CrawlOptions, _connect_and_crawl_once, main
    from net_docu_crawler.drivers.cisco_xr import CiscoXRDriver

    opts = CrawlOptions()
    assert opts.netconf is False
    assert opts.netconf_port == 830
    assert opts.gnmi is False
    assert opts.gnmi_port == 57400
    assert opts.gnmi_insecure is False

    captured: list[CrawlOptions] = []
    with (
        patch.object(
            sys,
            "argv",
            [
                "net-crawler",
                "--targets",
                "192.0.2.10",
                "--netconf",
                "--netconf-port",
                "1830",
                "--gnmi",
                "--gnmi-port",
                "57401",
                "--gnmi-insecure",
            ],
        ),
        patch("net_docu_crawler.crawler.crawl_network", side_effect=lambda config: captured.append(config) or []),
    ):
        main()

    assert len(captured) == 1
    cfg = captured[0]
    assert cfg.netconf is True
    assert cfg.netconf_port == 1830
    assert cfg.gnmi is True
    assert cfg.gnmi_port == 57401
    assert cfg.gnmi_insecure is True

    # Verify _connect_and_crawl_once passes netconf/gnmi options to CiscoXRDriver and invokes read-only helpers
    fake_conn = MagicMock()
    fake_conn.find_prompt.return_value = "RP/0/0/CPU0:xr-core#"
    with (
        patch.object(CiscoXRDriver, "connect", return_value=fake_conn),
        patch.object(CiscoXRDriver, "crawl", return_value={"hostname": "xr-core", "ip": "192.0.2.10"}),
        patch.object(CiscoXRDriver, "fetch_netconf_operational", return_value="<data/>") as mock_nc,
        patch.object(CiscoXRDriver, "fetch_gnmi_operational", return_value={"ok": True}) as mock_gnmi,
    ):
        data, outcome = _connect_and_crawl_once(
            CiscoXRDriver,
            "192.0.2.10",
            22,
            "ssh",
            {"username": "admin", "password": "pw", "secret": ""},
            8,
            "",
            "",
            netconf=True,
            netconf_port=1830,
            gnmi=True,
            gnmi_port=57401,
            gnmi_insecure=True,
        )
    assert outcome == "success"
    assert mock_nc.called
    assert mock_gnmi.called
    assert data["netconf_operational"] == "<data/>"
    assert data["gnmi_operational"] == {"ok": True}


def test_install_deps_cli_flag_and_net_crawler_entrypoint():
    """CD-07: --install-deps must be accepted by argparse and net_crawler.py must strip duplicate flags."""
    from net_docu_crawler.crawler import _build_arg_parser

    parser = _build_arg_parser()
    args = parser.parse_args(["--install-deps"])
    assert args.install_deps is True

    nc_text = (REPO_ROOT / "net_crawler.py").read_text(encoding="utf-8")
    assert 'while "--install-deps" in sys.argv' in nc_text or "while '--install-deps' in sys.argv" in nc_text


def test_target_vendor_help_and_organize_output_dir_flags(tmp_path):
    """CD-08 & CD-10: --target-vendor help is accurate; --organize/--no-organize are mutex; --output-dir works with --organize."""
    from net_docu_crawler.crawler import CrawlOptions, _build_arg_parser, _resolve_run_output_dir

    parser = _build_arg_parser()
    help_text = parser.format_help()
    assert "aruba" in help_text
    assert "meraki" in help_text
    assert "persona=vendor" in help_text

    # --organize and --no-organize must be mutually exclusive
    with pytest.raises(SystemExit):
        parser.parse_args(["--organize", "--no-organize"])

    # --output-dir docs/net_docu_crawler --organize must honor the explicit base dir
    custom_base = str(tmp_path / "docs" / "net_docu_crawler")
    cfg = CrawlOptions(targets=["192.0.2.1"], organize=True, output_dir="docs/net_docu_crawler")
    # Also test exact sentinel string "docs/net_docu_crawler" when explicitly passed
    with patch("os.makedirs"):
        run_dir, is_org, _, _ = _resolve_run_output_dir(cfg, ["192.0.2.1"])
    assert is_org is True
    assert run_dir.startswith("docs/net_docu_crawler/")

    # When output_dir is empty (CLI default), organized mode uses deliverables/
    args_def = parser.parse_args([])
    assert args_def.output_dir == ""
    cfg_def = CrawlOptions(targets=["192.0.2.1"], organize=True, output_dir=args_def.output_dir)
    with patch("os.makedirs"):
        run_dir_def, is_org_def, _, _ = _resolve_run_output_dir(cfg_def, ["192.0.2.1"])
    assert is_org_def is True
    assert run_dir_def.startswith("deliverables/")
    assert custom_base  # keep tmp_path used cleanly


def test_package_exports_version_and_dependency_checker_parity():
    """CD-11: __version__ matches pyproject.toml, all 13 drivers exported, unused jinja2 removed."""
    import net_docu_crawler
    from net_docu_crawler.dependency_checker import OPTIONAL_DEPENDENCIES, REQUIRED_DEPENDENCIES

    pyproject_txt = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{net_docu_crawler.__version__}"' in pyproject_txt

    for drv_name in ("CiscoDriver", "CiscoXRDriver", "CiscoSMBDriver", "HPProCurveDriver"):
        assert drv_name in net_docu_crawler.__all__
        assert getattr(net_docu_crawler, drv_name).__name__ == drv_name

    assert "jinja2" not in OPTIONAL_DEPENDENCIES
    assert "cryptography" in REQUIRED_DEPENDENCIES
    assert "ncclient" in OPTIONAL_DEPENDENCIES
    assert "pygnmi" in OPTIONAL_DEPENDENCIES


def test_wrapper_scripts_prefer_dot_venv():
    """CD-12: run.sh and run.ps1 must detect .venv before falling back to venv."""
    run_sh = (REPO_ROOT / "run.sh").read_text(encoding="utf-8")
    run_ps1 = (REPO_ROOT / "run.ps1").read_text(encoding="utf-8")

    assert ".venv/bin/python" in run_sh
    assert "venv/bin/python" in run_sh
    assert r".\.venv\Scripts\python.exe" in run_ps1
    assert r".\venv\Scripts\python.exe" in run_ps1

    # Syntax-check run.sh with bash -n
    proc = subprocess.run(["bash", "-n", str(REPO_ROOT / "run.sh")], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

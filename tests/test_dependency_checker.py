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
Unit tests for DependencyChecker and automated pre-flight self-healing.
"""

from unittest.mock import patch

from net_docu_crawler.dependency_checker import (
    check_dependencies,
    ensure_dependencies,
    install_missing_dependencies,
)


def test_check_dependencies_clean_environment():
    status = check_dependencies()
    # In active dev/test environment, core dependencies (netmiko, paramiko, netaddr) are present
    assert status["missing_required"] == []


def test_check_dependencies_with_missing_simulation():
    with patch("importlib.import_module", side_effect=ImportError("No module named 'fake_lib'")):
        status = check_dependencies()
        assert len(status["missing_required"]) >= 3
        assert "netmiko" in status["missing_required"]
        assert "paramiko" in status["missing_required"]
        assert "netaddr" in status["missing_required"]


def test_ensure_dependencies_already_met():
    with patch("net_docu_crawler.dependency_checker.check_dependencies", return_value={"missing_required": []}):
        assert ensure_dependencies(auto_install=False, prompt=False) is True


def test_ensure_dependencies_non_interactive_aborts_cleanly():
    with patch(
        "net_docu_crawler.dependency_checker.check_dependencies", return_value={"missing_required": ["netmiko"]}
    ):
        with patch("sys.stdin.isatty", return_value=False):
            assert ensure_dependencies(auto_install=False, prompt=True) is False


def test_install_missing_dependencies_mock():
    with patch("subprocess.check_call", return_value=0) as mock_call:
        res = install_missing_dependencies(["netmiko", "paramiko"])
        assert res is True
        assert mock_call.called

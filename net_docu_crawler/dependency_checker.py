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
Pre-Flight Dependency Verification and Self-Healing Engine for Net-Docu-Crawler.
Verifies critical networking and serialization libraries (netmiko, paramiko, netaddr)
and provides automated installation and human-friendly diagnostics without crashing.
"""

import importlib
import subprocess
import sys

REQUIRED_DEPENDENCIES = {
    "netmiko": "netmiko>=4.0.0",
    "paramiko": "paramiko>=3.0.0",
    "netaddr": "netaddr>=0.8.0",
}

OPTIONAL_DEPENDENCIES = {
    "jinja2": "jinja2>=3.0.0",
    "ruff": "ruff>=0.1.0",
    "pytest": "pytest>=7.0.0",
}


def check_dependencies() -> dict[str, list[str]]:
    """
    Checks if required and optional dependencies are importable in the current environment.
    Returns: {"missing_required": list[str], "missing_optional": list[str]}
    """
    missing_required = []
    missing_optional = []

    for mod_name, _spec in REQUIRED_DEPENDENCIES.items():
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing_required.append(mod_name)

    for mod_name, _spec in OPTIONAL_DEPENDENCIES.items():
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing_optional.append(mod_name)

    return {
        "missing_required": missing_required,
        "missing_optional": missing_optional,
    }


def install_missing_dependencies(packages: list[str]) -> bool:
    """
    Installs missing dependencies using the current Python pip executable.
    Returns True on success, False otherwise.
    """
    if not packages:
        return True

    print(
        f"\n[+] Net-Docu-Crawler Self-Healing: Installing {len(packages)} missing package(s): {', '.join(packages)}..."
    )
    specs = [REQUIRED_DEPENDENCIES.get(p, p) for p in packages]
    cmd = [sys.executable, "-m", "pip", "install", *specs]
    try:
        subprocess.check_call(cmd)
        print("[+] Dependencies successfully installed!\n")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Automated dependency installation failed (exit code {e.returncode}).")
        return False


def ensure_dependencies(auto_install: bool = False, prompt: bool = True) -> bool:
    """
    Guarantees required dependencies exist before starting crawler discovery.
    If dependencies are missing:
      - If auto_install is True: Installs automatically.
      - If prompt is True and session is interactive: Prompts user to install.
      - Otherwise: Prints clean remediation instructions and returns False.
    """
    status = check_dependencies()
    missing = status["missing_required"]
    if not missing:
        return True

    print("\n" + "=" * 70)
    print(" [!] Net-Docu-Crawler: Missing Required Python Dependencies")
    print("=" * 70)
    for pkg in missing:
        print(f"  * {pkg} ({REQUIRED_DEPENDENCIES.get(pkg, pkg)})")
    print("=" * 70)

    if auto_install:
        return install_missing_dependencies(missing)

    # If interactive terminal and user prompt enabled
    if prompt and sys.stdin.isatty():
        try:
            reply = (
                input("\n[?] Would you like to automatically install missing dependencies now? [Y/n]: ").strip().lower()
            )
            if reply in ("", "y", "yes"):
                return install_missing_dependencies(missing)
        except (KeyboardInterrupt, EOFError):
            print("\n[-] Aborted by user.")
            return False

    print("\n[!] To install required packages manually, run:")
    print(f"    {sys.executable} -m pip install -r requirements.txt")
    print("    or:")
    print("    pip install -e .\n")
    return False

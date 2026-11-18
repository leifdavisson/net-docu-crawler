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
Mermaid Diagram Syntax Validator (Phase 6).
Catches common Mermaid 11.x parse errors (e.g., escaped `\"` inside node labels,
unbalanced quotes, missing diagram header) during report generation.
"""

import re

_VALID_HEADERS = ("graph ", "flowchart ", "sequencediagram", "statediagram", "classdiagram", "erdiagram")


def validate_mermaid_block(mermaid_text: str) -> list[str]:
    """Return a list of syntax error strings (empty list means valid)."""
    errors: list[str] = []
    lines = [ln.strip() for ln in (mermaid_text or "").splitlines() if ln.strip() and not ln.strip().startswith("%%")]
    if not lines:
        return ["Empty Mermaid diagram"]

    if not lines[0].lower().startswith(_VALID_HEADERS):
        errors.append(f"Invalid Mermaid header: {lines[0]!r}")

    for idx, ln in enumerate(lines, start=1):
        if '\\"' in ln:
            errors.append(f"Line {idx}: escaped quote '\\\"' inside Mermaid label: {ln}")
        if ln.count('"') % 2 != 0:
            errors.append(f"Line {idx}: unbalanced double quotes: {ln}")
        if re.search(r"<(?!br\s*/?>)[a-zA-Z][^>]*>", ln):
            errors.append(f"Line {idx}: unsupported HTML tag in Mermaid label: {ln}")

    return errors

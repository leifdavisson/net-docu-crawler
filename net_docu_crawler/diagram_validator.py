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
_MAX_MERMAID_TEXT_SIZE = 50000
_RESERVED_NODE_IDS = frozenset(
    {
        "end",
        "subgraph",
        "class",
        "click",
        "style",
        "classdef",
        "linkstyle",
        "default",
        "graph",
        "flowchart",
        "direction",
    }
)
_EDGE_ARROW_RE = re.compile(r"(?:-->|==>|\-\.\->|---|~~~|\-\.\-)")
_EDGE_LABEL_RE = re.compile(r'\|"([^"]*)"\|')
_QUOTED_STR_RE = re.compile(r'"[^"]*"')
_NODE_DEF_ID_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*(?:\(\[|\[|\(\(|\(|\{\{|\{)")
_LINK_STYLE_RE = re.compile(r"^linkStyle\s+(\d+)\b")


def validate_mermaid_block(mermaid_text: str) -> list[str]:
    """Return a list of syntax error strings (empty list means valid)."""
    errors: list[str] = []
    raw_text = mermaid_text or ""
    if len(raw_text) > _MAX_MERMAID_TEXT_SIZE:
        errors.append(f"Mermaid block exceeds maxTextSize ({len(raw_text)} > {_MAX_MERMAID_TEXT_SIZE} chars)")

    lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip() and not ln.strip().startswith("%%")]
    if not lines:
        return ["Empty Mermaid diagram"]

    if not lines[0].lower().startswith(_VALID_HEADERS):
        errors.append(f"Invalid Mermaid header: {lines[0]!r}")

    subgraph_depth = 0
    edge_count = 0
    link_style_indices: list[tuple[int, int]] = []

    for idx, ln in enumerate(lines, start=1):
        if '\\"' in ln:
            errors.append(f"Line {idx}: escaped quote '\\\"' inside Mermaid label: {ln}")
        if ln.count('"') % 2 != 0:
            errors.append(f"Line {idx}: unbalanced double quotes: {ln}")
        if re.search(r"<(?!br\s*/?>)[a-zA-Z][^>]*>", ln):
            errors.append(f"Line {idx}: unsupported HTML tag in Mermaid label: {ln}")
        if "%%" in ln:
            errors.append(f"Line {idx}: mid-line '%%' comment inside Mermaid statement: {ln}")

        # Check inside quoted strings for backticks or unescaped pipes in edge labels
        for m_q in _QUOTED_STR_RE.finditer(ln):
            inner = m_q.group(0)[1:-1]
            if "`" in inner:
                errors.append(f"Line {idx}: unescaped backtick inside Mermaid label: {ln}")

        for m_edge_lbl in _EDGE_LABEL_RE.finditer(ln):
            if "|" in m_edge_lbl.group(1):
                errors.append(f"Line {idx}: unescaped '|' inside Mermaid edge label: {ln}")

        low = ln.lower()
        if low.startswith("subgraph ") or low == "subgraph":
            subgraph_depth += 1
        elif low == "end":
            subgraph_depth -= 1
            if subgraph_depth < 0:
                errors.append(f"Line {idx}: unmatched 'end' without opening 'subgraph'")
                subgraph_depth = 0

        # Check bare reserved Mermaid keywords used as node definitions
        m_nid = _NODE_DEF_ID_RE.match(ln)
        if m_nid and m_nid.group(1).lower() in _RESERVED_NODE_IDS:
            errors.append(f"Line {idx}: reserved Mermaid keyword used as node ID {m_nid.group(1)!r}: {ln}")

        # Count edges & capture linkStyle indices
        m_ls = _LINK_STYLE_RE.match(ln)
        if m_ls:
            link_style_indices.append((idx, int(m_ls.group(1))))
        elif (
            idx > 1
            and not low.startswith(("classdef ", "class ", "style ", "subgraph ", "direction "))
            and _EDGE_ARROW_RE.search(_QUOTED_STR_RE.sub('""', ln))
        ):
            edge_count += 1

    if subgraph_depth > 0:
        errors.append(f"Unclosed subgraph block(s): {subgraph_depth} missing 'end' statement(s)")

    for ls_line, ls_idx in link_style_indices:
        if ls_idx >= edge_count:
            errors.append(f"Line {ls_line}: linkStyle index {ls_idx} out of bounds for {edge_count} edge(s)")

    return errors

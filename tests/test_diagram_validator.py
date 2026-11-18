# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net_docu_crawler.diagram_validator import validate_mermaid_block


def test_validate_mermaid_block():
    good = 'flowchart LR\n  sw_0["DO-Main-BLDG<br/>(HP 5412zl)"]\n  sw_0 ==>|"B1"| sw_1\n'
    assert validate_mermaid_block(good) == []

    bad_escape = 'graph TD\n  sub_1(["172.31.1.0/24 (\\"VLAN3019\\")"])\n'
    errs = validate_mermaid_block(bad_escape)
    assert len(errs) == 1
    assert "escaped quote" in errs[0]

    bad_quotes = 'flowchart LR\n  sw_0["unclosed]\n'
    assert len(validate_mermaid_block(bad_quotes)) == 1

# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reusable offline transport mocks and read-only enforcement helpers for pytest."""

from tests.helpers.fake_transport import (
    FakeNetmikoConnection,
    FakeParamikoChannel,
    FakeParamikoClient,
    FakeParamikoStream,
    FakeParamikoTransport,
    ZeroBlastViolationError,
    assert_readonly_command,
    parse_transcript_blocks,
)

__all__ = [
    "FakeNetmikoConnection",
    "FakeParamikoChannel",
    "FakeParamikoClient",
    "FakeParamikoStream",
    "FakeParamikoTransport",
    "ZeroBlastViolationError",
    "assert_readonly_command",
    "parse_transcript_blocks",
]

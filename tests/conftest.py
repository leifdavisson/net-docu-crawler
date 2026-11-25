# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Pytest harness configuration guaranteeing hermetic offline execution across
local developer machines and clean GitHub Actions CI runners.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import oui_lookup
from net_docu_crawler.drivers import base as drivers_base

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _hermetic_offline_oui_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Prevent unit tests from depending on untracked local `oui.txt` or `oui_cache.json`
    files or making live HTTP requests to api.macvendors.com unless explicitly mocked.
    """

    def _block_live_oui_http(*_args, **_kwargs):
        raise OSError("Live HTTP OUI lookup blocked in hermetic offline pytest harness")

    monkeypatch.setattr(oui_lookup.urllib.request, "urlopen", _block_live_oui_http)
    monkeypatch.setattr(oui_lookup, "OUI_FILE", "__nonexistent_hermetic_oui.txt__")
    monkeypatch.setattr(oui_lookup, "OUI_CACHE_FILE", "__nonexistent_hermetic_oui_cache.json__")
    monkeypatch.setattr(oui_lookup, "_loaded_ouis", {})
    monkeypatch.setattr(oui_lookup, "_online_oui_cache", {})
    monkeypatch.setattr(oui_lookup, "_online_cache_loaded", True)


@pytest.fixture(autouse=True)
def _hermetic_offline_base_arp(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Prevent `BaseDriver.crawl()` from reading the host machine's `/proc/net/arp`
    or spawning `arp -a` when a mocked driver returns an empty base MAC address.
    Direct unit tests of `detector.get_mac_from_system_arp` remain unaffected.
    """
    monkeypatch.setattr(drivers_base, "get_mac_from_system_arp", lambda _ip: "")


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the root path to committed scrubbed/doc-backed CLI fixtures."""
    return FIXTURES_ROOT

# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Tests for fixture hygiene, offline transport mocks (`FakeNetmikoConnection`,
`FakeParamikoClient`), hermetic test isolation, and 13-driver contract parity.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from net_docu_crawler.drivers import (
    DRIVER_VENDOR_MAP,
    AristaDriver,
    ArubaDriver,
    CiscoDriver,
    CiscoSMBDriver,
    CiscoXRDriver,
    FortinetDriver,
    FRRDriver,
    HPProCurveDriver,
    JuniperDriver,
    MikroTikDriver,
    OpenWrtDriver,
    OPNsenseDriver,
    PaloAltoDriver,
)
from net_docu_crawler.drivers.opnsense import OPNsenseSSHConnection
from tests.helpers.fake_transport import (
    FakeNetmikoConnection,
    FakeParamikoClient,
    ZeroBlastViolationError,
    assert_readonly_command,
    parse_transcript_blocks,
)

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"

_FORBIDDEN_FIXTURE_EXTENSIONS = {".log", ".json", ".cfg", ".conf"}
_FORBIDDEN_FIXTURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-or-cert", re.compile(r"BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?(?:PRIVATE\s+KEY|CERTIFICATE)")),
    ("unix-password-hash", re.compile(r"\$(?:1|2a|2b|5|6|9)\$[A-Za-z0-9./]{8,}")),
    ("fortios-enc-blob", re.compile(r"\bENC\s+[A-Za-z0-9+/=]{16,}")),
    ("cisco-type7-secret", re.compile(r"\b(?:password|secret)\s+[5789]\s+[A-Za-z0-9$./+=]{8,}", re.IGNORECASE)),
    ("snmp-community", re.compile(r"\bsnmp-server\s+community\s+(?!<REDACTED>)\S+", re.IGNORECASE)),
    ("real-domain-leak", re.compile(r"(?:andrews\.best|norris\.k12\.ca\.us)", re.IGNORECASE)),
    ("personal-ssid-leak", re.compile(r"\bNacho(?:-IoT|-Trusted|Wireless)\b", re.IGNORECASE)),
    ("fortinet-console-write", re.compile(r"^\s*config\s+system\s+console\b", re.IGNORECASE | re.MULTILINE)),
)


def test_fixture_directory_hygiene_and_zero_secrets():
    """Every committed fixture must be a scrubbed `.txt` with zero secrets, PII, or write commands."""
    all_files = [p for p in FIXTURES_ROOT.rglob("*") if p.is_file()]
    txt_files = [p for p in all_files if p.suffix == ".txt"]
    assert len(txt_files) >= 14, f"Expected >=14 vendor fixtures, found {len(txt_files)}"

    for path in all_files:
        assert path.name != "credentials.json", f"Forbidden file committed: {path}"
        assert path.suffix.lower() not in _FORBIDDEN_FIXTURE_EXTENSIONS, (
            f"Fixture {path} uses forbidden extension {path.suffix} (CI blocks *.log; .gitignore blocks *.json/*.cfg/*.conf)"
        )

    for txt_path in txt_files:
        content = txt_path.read_text(encoding="utf-8")
        assert "# Fixture provenance:" in content, f"Missing provenance header in {txt_path}"

        for label, pattern in _FORBIDDEN_FIXTURE_PATTERNS:
            assert not pattern.search(content), f"Fixture {txt_path} failed hygiene check ({label})"

        _prompt, commands = parse_transcript_blocks(content)
        assert len(commands) >= 3, f"Fixture {txt_path} parsed fewer than 3 CLI commands"
        for cmd in commands:
            assert_readonly_command(cmd)


@pytest.mark.parametrize(
    "allowed_cmd",
    [
        "show version",
        "show running-config",
        "get system status",
        "diagnose snmp sysinfo lldp neighbor",
        "terminal length 0",
        "terminal width 511",
        "terminal datadump",
        "no page",
        "no paging",
        "set cli screen-length 0",
        "set cli screen-width 511",
        "set cli complete-on-space off",
        "set cli pager off",
        "vtysh -c 'show ip route json'",
        "ubus call system board 2>/dev/null",
        "uci export 2>/dev/null",
        "cat /conf/config.xml",
        "enable",
        "exit",
        "quit",
        "logout",
        " ",
    ],
)
def test_readonly_guard_allows_safe_commands(allowed_cmd: str):
    assert_readonly_command(allowed_cmd)


@pytest.mark.parametrize(
    "forbidden_cmd",
    [
        "config system console\nset output standard\nend",
        "config global",
        "configure terminal",
        "conf t",
        "write memory",
        "copy running-config startup-config",
        "commit",
        "reload",
        "reboot",
        "clear arp-cache",
        "delete flash:vlan.dat",
        "uci set network.lan.ipaddr=10.0.0.1",
        "uci commit",
        "opkg install lldpd",
        "/system reset-configuration",
        "set output standard",
        "sudo -s",
    ],
)
def test_readonly_guard_blocks_write_commands(forbidden_cmd: str):
    with pytest.raises(ZeroBlastViolationError):
        assert_readonly_command(forbidden_cmd)


def test_fake_netmiko_connection_paging_failures_and_lifecycle():
    conn = FakeNetmikoConnection(
        commands={"show version": "Version 1.0"},
        paged_commands={"show full-configuration": ["page-1-line", "page-2-line", "page-3-final"]},
        fail_on_command={"show broken": TimeoutError("simulated read timeout")},
        prompt="fw-edge-01 #",
    )

    assert conn.find_prompt() == "fw-edge-01 #"
    assert conn.send_command("show version") == "Version 1.0"

    # Interactive --More-- paging simulation
    conn.write_channel("show full-configuration\n")
    chunk1 = conn.read_channel()
    assert "page-1-line" in chunk1 and "--More--" in chunk1
    conn.write_channel(" ")
    chunk2 = conn.read_channel()
    assert "page-2-line" in chunk2 and "--More--" in chunk2
    conn.write_channel(" ")
    chunk3 = conn.read_channel()
    assert "page-3-final" in chunk3 and "fw-edge-01 #" in chunk3

    # Failure injection
    with pytest.raises(TimeoutError, match="simulated read timeout"):
        conn.send_command("show broken")

    # Write/config APIs hard-blocked
    with pytest.raises(ZeroBlastViolationError):
        conn.send_command("config system console")
    with pytest.raises(ZeroBlastViolationError):
        conn.send_config_set(["hostname pwned"])
    with pytest.raises(ZeroBlastViolationError):
        conn.config_mode()
    with pytest.raises(ZeroBlastViolationError):
        conn.save_config()

    # Leak detection catches unclosed connections
    with pytest.raises(AssertionError, match="VTY session leak"):
        conn.assert_closed()

    conn.disconnect()
    conn.assert_closed()
    conn.assert_only_readonly_commands()


def test_fake_paramiko_client_opnsense_fixture_and_lifecycle():
    client = FakeParamikoClient.from_transcript_file(
        FIXTURES_ROOT / "opnsense" / "opnsense_gateway.txt",
        connect_side_effects=[TimeoutError("stage1"), None],
    )

    with pytest.raises(TimeoutError):
        client.connect("10.10.3.1", username="root", password="pw", timeout=5)
    client.connect("10.10.3.1", username="root", password="pw", timeout=5)
    assert client.get_transport() is not None and client.get_transport().is_active()

    ssh_conn = OPNsenseSSHConnection(client)
    driver = OPNsenseDriver(ip="10.10.3.1")
    data = driver.crawl(ssh_conn)

    assert data["hostname"].startswith("gw-opnsense-01")
    assert data["serial"] == "OPNLAB00007"
    assert any(i["ip_address"].startswith("100.64.224.70/19") for i in data["l3_interfaces"])
    assert "pflog0" not in data["interfaces_detail"]
    assert "pfsync0" not in data["interfaces_detail"]

    with pytest.raises(ZeroBlastViolationError):
        client.exec_command("reboot")

    with pytest.raises(AssertionError, match="SSH session leak"):
        client.assert_closed()

    ssh_conn.disconnect()
    client.assert_closed()


def test_all_registered_drivers_contract_and_session_log():
    """Verify every registered driver in DRIVER_VENDOR_MAP implements the canonical BaseDriver contract."""
    assert len(DRIVER_VENDOR_MAP) >= 13
    for driver_cls, canonical_vendor in DRIVER_VENDOR_MAP.items():
        drv = driver_cls(ip="10.10.99.1", session_log="/tmp/ndc_contract_test.log")
        assert canonical_vendor
        assert drv.session_log == "/tmp/ndc_contract_test.log"
        for method in (
            "connect",
            "crawl",
            "get_version",
            "get_interfaces",
            "get_neighbors",
            "get_stp",
            "get_poe",
            "get_mac_table",
            "get_optics",
        ):
            assert callable(getattr(drv, method)), f"{driver_cls.__name__} missing {method}()"


@pytest.mark.parametrize(
    ("driver_cls", "ip", "fixture_rel", "expected_host"),
    [
        (CiscoDriver, "10.10.1.2", "cisco/ios_catalyst_core_synthetic.txt", "sw-core-01"),
        (CiscoDriver, "10.10.2.1", "cisco/ios_router.txt", "rtr-branch-01"),
        (CiscoXRDriver, "10.10.8.1", "cisco_xr/iosxr_router_synthetic.txt", "rtr-xr-01"),
        (CiscoSMBDriver, "10.10.7.10", "ciscosmb/ciscosmb_sg350_synthetic.txt", "sw-smb-01"),
        (JuniperDriver, "10.10.1.10", "juniper/junos_ex2300.txt", "sw-access-01"),
        (ArubaDriver, "10.10.1.20", "aruba/iap_ap215.txt", "ap-floor1-01"),
        (ArubaDriver, "10.10.1.35", "aruba/aoscx_switch_synthetic.txt", "sw-aoscx-01"),
        (HPProCurveDriver, "10.10.1.30", "hpprocurve/procurve_2920.txt", "sw-procurve-01"),
        (AristaDriver, "10.10.1.31", "arista/veos_switch.txt", "sw-eos-01"),
        (FortinetDriver, "10.10.1.1", "fortinet/fortigate_edge.txt", "fw-edge-01"),
        (MikroTikDriver, "10.10.2.2", "mikrotik/routeros_chr.txt", "rtr-mikrotik-01"),
        (FRRDriver, "10.10.4.1", "frr/frr_router.txt", "rtr-frr-01"),
        (PaloAltoDriver, "10.10.5.1", "paloalto/panos_firewall_synthetic.txt", "fw-panos-01"),
        (OpenWrtDriver, "10.10.6.1", "openwrt/openwrt_router_synthetic.txt", "rtr-openwrt-01"),
    ],
)
def test_every_vendor_fixture_crawls_readonly_cleanly(driver_cls, ip: str, fixture_rel: str, expected_host: str):
    """Replay each committed vendor fixture through its driver with strict Zero-Blast-Radius enforcement."""
    with FakeNetmikoConnection.from_transcript_file(FIXTURES_ROOT / fixture_rel, enforce_readonly=True) as conn:
        data = driver_cls(ip=ip).crawl(conn)
    conn.assert_closed()
    conn.assert_only_readonly_commands()
    assert data["status"] == "success"
    assert data["hostname"].startswith(expected_host)
    assert data["raw_config"]


def test_conftest_hermetic_offline_oui_and_base_arp_isolation():
    """Verify tests/conftest.py prevents host ARP reads and online OUI lookups during driver crawls."""
    import oui_lookup
    from net_docu_crawler.drivers import base as drivers_base

    assert drivers_base.get_mac_from_system_arp("192.168.1.1") == ""
    assert oui_lookup.get_vendor("AA:BB:CC:11:22:33") == "Unknown"

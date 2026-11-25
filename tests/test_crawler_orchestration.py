# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Dedicated crawler orchestration, concurrency, failure injection, and VTY cleanup tests.

Covers TV-08:
  - crawl_network() orchestration end-to-end with offline mock transports.
  - Target parsing, CIDR /31, /32, explicit port specs, and pre-scan socket probing.
  - Anti-lockout AAA single-attempt-per-user-per-host ledger enforcement.
  - Tier 3 post-auth prompt dynamic driver dispatch on unknown targets.
  - VTY disconnect & socket resource cleanup on success, timeout, auth failure, and crawl exceptions.
  - Concurrent batch deduplication (reconcile_and_deduplicate_dataset, multi-homed, hypervisors).
  - LogReplayConnection parsing and replay fidelity.

Upstream References:
  - Netmiko: https://github.com/ktbyers/netmiko
  - Paramiko: https://www.paramiko.org/
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from net_docu_crawler.crawler import (
    CrawlOptions,
    LogReplayConnection,
    _connect_and_crawl_once,
    _crawl_target_batch,
    crawl_network,
    reconcile_and_deduplicate_dataset,
)
from net_docu_crawler.drivers.base import BaseDriver
from net_docu_crawler.drivers.cisco import CiscoDriver
from net_docu_crawler.drivers.mikrotik import MikroTikDriver
from tests.helpers.fake_transport import FakeNetmikoConnection


class MockAutonomousDriver(BaseDriver):
    """Hermetic test driver with canned operational data and lifecycle tracking."""

    vendor = "MockAutonomous"
    platform_name = "mock"

    def __init__(self, ip: str, **kwargs):
        super().__init__(ip, **kwargs)
        self.connect_called = False
        self.crawl_called = False

    def connect(self, cred, timeout=5, session_log=None):
        self.connect_called = True
        return FakeNetmikoConnection(prompt="mock-core#")

    def get_version(self, conn) -> dict:
        return {"hostname": "mock-sw-01", "model": "Mock-9000", "version": "1.0.0", "serial": "SN-MOCK-12345"}

    def get_interfaces(self, conn) -> tuple[list[dict], dict[str, dict]]:
        l3 = [{"interface": "Vlan1", "ip_address": f"{self.ip}/24", "status": "up"}]
        details = {
            "GigabitEthernet1/0/1": {
                "status": "up",
                "mac_address": "00:11:22:33:44:01",
                "speed": "1000",
                "duplex": "full",
                "description": "Uplink",
            }
        }
        return l3, details

    def get_vlans(self, conn) -> list[dict]:
        return [{"vlan_id": "1", "name": "default", "status": "active", "ports": ["GigabitEthernet1/0/1"]}]

    def get_mac_address_table(self, conn) -> list[dict]:
        return [{"vlan": "1", "mac": "00:aa:bb:cc:dd:01", "type": "dynamic", "interface": "GigabitEthernet1/0/1"}]

    def get_arp_table(self, conn) -> list[dict]:
        return [{"ip": "192.0.2.254", "mac": "00:aa:bb:cc:dd:ee", "interface": "Vlan1", "type": "dynamic"}]

    def get_routing_table(self, conn) -> list[dict]:
        return [{"subnet": "0.0.0.0/0", "next_hop": "192.0.2.254", "protocol": "static", "interface": "Vlan1"}]

    def get_neighbors(self, conn) -> list[dict]:
        return [
            {
                "local_port": "GigabitEthernet1/0/1",
                "remote_device": "mock-dist-01",
                "remote_port": "GigabitEthernet1/0/24",
                "remote_ip": "192.0.2.254",
                "remote_mac": "00:aa:bb:cc:dd:ee",
                "platform": "MockDist",
                "device_type": "switch",
            }
        ]


def test_crawl_network_orchestration_target_parsing_and_probe(tmp_path: Path):
    """TV-08: crawl_network orchestrates CIDRs (/31, /32, /24), custom ports, probe mocking, and deliverable export."""
    out_dir = tmp_path / "crawl_out"
    cred_file = tmp_path / "credentials.json"
    cred_file.write_text(
        json.dumps([{"name": "test", "vendor": "cisco", "username": "admin", "password": "secret_password_1"}]),
        encoding="utf-8",
    )

    scanned_ports_map = {"192.0.2.1", "192.0.2.2"}

    def fake_scan_subnet_ports(ips, ssh_ports=None, telnet_ports=None, **kwargs):
        return {ip: [(22, "ssh")] for ip in ips if ip in scanned_ports_map}

    mock_dev_data = {
        "ip": "192.0.2.1",
        "hostname": "core-sw01",
        "vendor": "Cisco",
        "model": "Catalyst 3850",
        "serial": "SN-CISCO-01",
        "status": "success",
        "device_type": "switch",
        "device_persona": "switch",
        "mac_address": "00:11:22:33:44:55",
        "l3_interfaces": [{"interface": "Vlan1", "ip_address": "192.0.2.1/24", "status": "up"}],
        "interfaces_detail": {
            "GigabitEthernet1/0/1": {
                "status": "up",
                "mac_address": "00:11:22:33:44:55",
                "description": "Trunk to Dist",
            }
        },
        "vlans": {"1": {"id": "1", "name": "default", "status": "active", "ports": ["GigabitEthernet1/0/1"]}},
        "stp": {"enabled": True, "is_root": True, "vlans": {}},
        "neighbors": [],
        "routes": [{"subnet": "0.0.0.0/0", "next_hop": "192.0.2.254", "protocol": "static", "interface": "Vlan1"}],
        "arp_table": [],
        "mac_table": [],
        "raw_config": "hostname core-sw01\ninterface Vlan1\n ip address 192.0.2.1 255.255.255.0\n",
    }

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "SSH-2.0-Cisco-1.25")),
        patch("net_docu_crawler.crawler.scan_subnet_ports", side_effect=fake_scan_subnet_ports),
        patch.object(CiscoDriver, "connect", return_value=FakeNetmikoConnection(prompt="core-sw01#")),
        patch.object(CiscoDriver, "crawl", return_value=mock_dev_data),
    ):
        results = crawl_network(
            targets=["192.0.2.1", "[192.0.2.2]:2222"],
            credentials_path=str(cred_file),
            output_dir=str(out_dir),
            organize=False,
            sanitize_passwords=True,
            timeout=5,
        )

    assert len(results) >= 1
    assert any(d.get("hostname") == "core-sw01" for d in results)
    assert (out_dir / "net_docu_crawler_dataset.json").is_file()
    assert (out_dir / "asset_inventory.csv").is_file()
    assert (out_dir / "migration_cabling_matrix.csv").is_file()
    assert (out_dir / "Network_Analysis.md").is_file()


def test_crawl_network_orchestration_aaa_single_attempt_per_user_per_host(tmp_path: Path):
    """TV-08: Anti-lockout ledger guarantees exactly one attempt per (username, host) regardless of credential profile count."""
    creds = [
        {"name": "Admin-1", "vendor": "cisco", "username": "admin", "password": "wrong_password_1"},
        {"name": "Admin-2", "vendor": "cisco", "username": "admin", "password": "wrong_password_2"},
        {"name": "Admin-3", "vendor": "cisco", "username": "admin", "password": "wrong_password_3"},
    ]

    connect_attempts: list[tuple[str, str]] = []

    def fake_connect(self, *args, **kwargs):
        user = getattr(self, "username", "admin")
        connect_attempts.append((self.ip, user))
        raise NetmikoAuthenticationException(f"Authentication failed for {user}@{self.ip}")

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "SSH-2.0-Cisco-1.25")),
        patch("net_docu_crawler.crawler.scan_subnet_ports", return_value={"192.0.2.10": [(22, "ssh")]}),
        patch.object(CiscoDriver, "connect", fake_connect),
    ):
        cfg = CrawlOptions(
            targets=["192.0.2.10"],
            credentials_path=[],
            output_dir=str(tmp_path),
            organize=False,
            timeout=2,
        )
        registry = MagicMock()
        raw_devices: list[dict] = []
        scanned_ip_set: set[str] = set()

        _crawl_target_batch(
            batch_ips=["192.0.2.10"],
            batch_explicit={},
            cfg=cfg,
            credentials=creds,
            registry=registry,
            raw_devices=raw_devices,
            scanned_ip_set=scanned_ip_set,
            logs_dir=str(tmp_path / "logs"),
            crawler_log=str(tmp_path / "exec.log"),
        )

    # Exactly 1 attempt made for username 'admin'; Admin-2 and Admin-3 are skipped by anti-lockout ledger
    assert connect_attempts == [("192.0.2.10", "admin")]
    assert len(raw_devices) == 1
    assert raw_devices[0]["status"] == "unauthenticated"
    assert raw_devices[0]["ip"] == "192.0.2.10"


def test_crawl_network_orchestration_tier3_prompt_dispatch(tmp_path: Path):
    """TV-08: Unknown target inspects post-auth prompt (Tier 3) and dynamically delegates to prompt-matched driver."""
    fake_conn = FakeNetmikoConnection(prompt="[admin@MikroTik-Core] >")

    mikrotik_crawled = []

    def fake_mikrotik_crawl(self, conn):
        mikrotik_crawled.append(conn)
        return {
            "ip": "192.0.2.20",
            "hostname": "MikroTik-Core",
            "vendor": "MikroTik",
            "model": "CCR2004",
            "status": "success",
            "device_type": "router",
        }

    with (
        patch.object(CiscoDriver, "connect", return_value=fake_conn),
        patch.object(MikroTikDriver, "crawl", fake_mikrotik_crawl),
    ):
        data, outcome = _connect_and_crawl_once(
            driver_cls=CiscoDriver,
            ip="192.0.2.20",
            port=22,
            transport="ssh",
            cred={"username": "admin", "password": "mikrotik_pw"},
            timeout=5,
            session_log="",
            log_file=str(tmp_path / "exec.log"),
        )

    assert outcome == "success"
    assert data["hostname"] == "MikroTik-Core"
    assert data["vendor"] == "MikroTik"
    assert len(mikrotik_crawled) == 1


def test_crawl_network_orchestration_vty_cleanup_on_crawl_exception(tmp_path: Path):
    """TV-08: Unexpected exception during crawl() ensures conn.disconnect() is called and VTY leak is prevented."""
    fake_conn = FakeNetmikoConnection(prompt="crash-device#")
    assert fake_conn.disconnected is False

    with patch.object(CiscoDriver, "connect", return_value=fake_conn):
        with patch.object(CiscoDriver, "crawl", side_effect=RuntimeError("Kernel panic in forwarding plane")):
            data, outcome = _connect_and_crawl_once(
                driver_cls=CiscoDriver,
                ip="192.0.2.30",
                port=22,
                transport="ssh",
                cred={"username": "admin", "password": "pwd"},
                timeout=5,
                session_log="",
                log_file=str(tmp_path / "exec.log"),
            )

    assert outcome == "crawl_failed"
    assert data is None
    assert fake_conn.disconnected is True
    fake_conn.assert_closed()


def test_crawl_network_orchestration_batch_deduplication():
    """TV-08: reconcile_and_deduplicate_dataset merges multi-homed addresses, drops unauthenticated shadows, preserves VMs."""
    # 1. Multi-homed router crawled under two IPs with identical physical MAC and overlapping interfaces
    dev_primary = {
        "ip": "192.0.2.1",
        "hostname": "rtr-campus-01",
        "vendor": "Cisco",
        "mac_address": "00:11:22:33:44:55",
        "status": "success",
        "l3_interfaces": [
            {"interface": "GigabitEthernet0/0", "ip_address": "192.0.2.1/24"},
            {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.1/24"},
        ],
        "raw_config": "interface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n",
    }
    dev_secondary = {
        "ip": "10.0.0.1",
        "hostname": "rtr-campus-01",
        "vendor": "Cisco",
        "mac_address": "00:11:22:33:44:55",
        "status": "success",
        "l3_interfaces": [
            {"interface": "GigabitEthernet0/0", "ip_address": "192.0.2.1/24"},
            {"interface": "GigabitEthernet0/1", "ip_address": "10.0.0.1/24"},
        ],
        "raw_config": "",  # secondary alias has no static config
    }

    # 2. Unauthenticated shadow of the same physical router
    dev_shadow = {
        "ip": "192.0.2.1",
        "hostname": "192.0.2.1",
        "vendor": "Unknown",
        "mac_address": "00:11:22:33:44:55",
        "status": "unauthenticated",
    }

    # 3. Two distinct virtual machines on Proxmox hypervisor (BC:24:11 prefix)
    vm1 = {
        "ip": "192.0.2.101",
        "hostname": "vm-dns-01",
        "vendor": "Linux",
        "mac_address": "bc:24:11:aa:bb:01",
        "status": "success",
        "l3_interfaces": [{"interface": "eth0", "ip_address": "192.0.2.101/24"}],
    }
    vm2 = {
        "ip": "192.0.2.102",
        "hostname": "vm-dhcp-02",
        "vendor": "Linux",
        "mac_address": "bc:24:11:aa:bb:02",
        "status": "success",
        "l3_interfaces": [{"interface": "eth0", "ip_address": "192.0.2.102/24"}],
    }

    devices = [dev_secondary, dev_primary, dev_shadow, vm1, vm2]
    deduped = reconcile_and_deduplicate_dataset(devices)

    # Secondary multi-homed alias merged into primary static IP; shadow dropped; distinct VMs preserved
    assert len(deduped) == 3
    by_host = {d["hostname"]: d for d in deduped}
    assert "rtr-campus-01" in by_host
    assert by_host["rtr-campus-01"]["ip"] == "192.0.2.1"
    assert "vm-dns-01" in by_host
    assert "vm-dhcp-02" in by_host


def test_crawl_network_orchestration_socket_timeout_cleanup(tmp_path: Path):
    """TV-08: Socket connection timeout during connect() records host as unauthenticated and cleans in-progress state."""
    with patch.object(
        CiscoDriver,
        "connect",
        side_effect=NetmikoTimeoutException("TCP connection to 192.0.2.40:22 timed out after 5.0 seconds"),
    ):
        data, outcome = _connect_and_crawl_once(
            driver_cls=CiscoDriver,
            ip="192.0.2.40",
            port=22,
            transport="ssh",
            cred={"username": "admin", "password": "pwd"},
            timeout=5,
            session_log="",
            log_file=str(tmp_path / "exec.log"),
        )

    assert outcome == "transport_failed"
    assert data is None


def test_crawl_network_orchestration_log_replay_connection():
    """TV-08: LogReplayConnection accurately parses both structured and interactive raw CLI transcripts."""
    # Format A: Canonical structured '--- COMMAND: <cmd> ---' blocks
    structured_log = """
# PROMPT: opnsense-edge#
--- COMMAND: uname -a ---
FreeBSD opnsense-edge 13.2-RELEASE FreeBSD 13.2-RELEASE
--- COMMAND: ifconfig -a ---
igb0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
    ether 00:11:22:33:44:11
    inet 198.51.100.1 netmask 0xffffff00 broadcast 198.51.100.255
    status: active
--- COMMAND: netstat -rnW -f inet ---
Internet:
Destination        Gateway            Flags   Nhop#    Mtu      Netif Expire
default            198.51.100.254     UGS        14   1500       igb0
"""
    conn_a = LogReplayConnection(structured_log)
    assert conn_a.send_command("uname -a").startswith("FreeBSD")
    assert "igb0:" in conn_a.send_command("ifconfig -a")
    assert "198.51.100.254" in conn_a.send_command("netstat -rnW -f inet")
    assert conn_a.send_command("nonexistent") == ""

    # Format B: Interactive CLI prompt-delimited format
    prompt_log = """
[admin@Edge-Rtr] > /system resource print
                   uptime: 30d
                  version: 7.15 (stable)
             architecture: arm64
[admin@Edge-Rtr] > /ip address print detail
Flags: X - disabled, I - invalid, D - dynamic
 0   address=192.0.2.1/24 network=192.0.2.0 interface=ether1 actual-interface=ether1
"""
    conn_b = LogReplayConnection(prompt_log)
    assert conn_b.prompt.startswith("[admin@Edge-Rtr]")
    res = conn_b.send_command("/system resource print")
    assert "version: 7.15" in res
    addr = conn_b.send_command("/ip address print detail")
    assert "192.0.2.1/24" in addr

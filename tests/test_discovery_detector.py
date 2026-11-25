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

"""Regression tests for detector banner classification, RFC 4253 reads, Tier 3 prompts, dual-stack probes, ARP, and driver registry."""

import socket
from unittest.mock import MagicMock, patch

import net_docu_crawler.drivers as drivers_pkg
from net_docu_crawler.drivers import (
    AristaDriver,
    ArubaDriver,
    CiscoDriver,
    CiscoSMBDriver,
    CiscoXRDriver,
    FortinetDriver,
    HPProCurveDriver,
    JuniperDriver,
    MikroTikDriver,
    PaloAltoDriver,
    get_driver,
    resolve_driver_for_vendor,
)
from net_docu_crawler.drivers.detector import (
    _match_vendor_from_banner,
    _match_vendor_from_oui,
    detect_vendor_range,
    get_arp_table_entries,
    get_mac_from_system_arp,
    get_ssh_banner,
    inspect_prompt_os,
    is_hypervisor_mac,
    probe_http_fingerprint,
    probe_snmp_sysinfo,
    probe_tcp_port,
)


def test_generic_openssh_and_dropbear_banners_do_not_misclassify():
    """DD-03: Debian/Ubuntu/FreeBSD OpenSSH and Dropbear banners must not auto-classify as FRR/OPNsense/OpenWrt."""
    assert _match_vendor_from_banner("ssh-2.0-openssh_9.2p1 debian-2+deb12u3", "unknown") == "unknown"
    assert _match_vendor_from_banner("ssh-2.0-openssh_8.9p1 ubuntu-3ubuntu0.10", "unknown") == "unknown"
    assert _match_vendor_from_banner("ssh-2.0-openssh_8.4 freebsd-20201028", "unknown") == "unknown"
    assert _match_vendor_from_banner("ssh-2.0-dropbear_2022.83", "unknown") == "unknown"
    assert _match_vendor_from_banner("ssh-2.0-dropbear_2024.86", "unknown", oui_vendor="Ubiquiti Networks") == "unknown"

    # Explicit vendor identifiers still match
    assert _match_vendor_from_banner("ssh-2.0-opnsense-24.7", "unknown") == "opnsense"
    assert _match_vendor_from_banner("ssh-2.0-openwrt-23.05", "unknown") == "openwrt"
    assert _match_vendor_from_banner("ssh-2.0-frrouting", "unknown") == "frrouting"
    assert _match_vendor_from_banner("ssh-2.0-rosssh", "unknown") == "mikrotik"
    assert _match_vendor_from_banner("ssh-2.0-fortissh", "unknown") == "fortinet"


def test_rfc4253_multiline_ssh_banner_and_cisco_oui_refinement():
    """DD-16: RFC 4253 pre-banner lines and fragmented reads must still recover SSH-2.0-... line."""
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b"Authorized access only\r\n",
        b"All sessions are logged.\r\nSSH-2.0-Cisco-",
        b"1.25\r\n\x00\x00\x01\xd4",
    ]
    with patch("net_docu_crawler.drivers.detector.socket.socket", return_value=mock_sock):
        assert get_ssh_banner("10.0.0.1", port=22, timeout=2.0) == "SSH-2.0-Cisco-1.25"

    # Unsupported appliance or explicit non-Cisco banner must override generic Cisco OUI candidate
    assert _match_vendor_from_banner("ssh-2.0-crestronssh", "cisco") == "unsupported_appliance"
    assert _match_vendor_from_banner("ssh-2.0-openssh_for_windows_8.1", "cisco") == "unsupported_appliance"
    assert _match_vendor_from_banner("ssh-2.0-arista-eos", "cisco") == "arista"
    assert _match_vendor_from_banner("ssh-2.0-cisco-sg350", "cisco") == "ciscosmb"
    assert _match_vendor_from_banner("ssh-2.0-openssh_7.3p1.rl", "cisco") == "ciscosmb"


def test_inspect_prompt_os_hardened_and_resolve_prompt_vendor():
    """DD-02 / DD-11: Fix prompt regex false positives/misses and provide canonical vendor mapping."""
    from net_docu_crawler.drivers.detector import resolve_prompt_vendor

    # RHEL / CentOS / Linux bracket prompts must NOT match MikroTik
    assert inspect_prompt_os("[root@rhel9 ~]#") == "unknown"
    assert inspect_prompt_os("[admin@rocky8 /etc]$") == "unknown"
    assert inspect_prompt_os("[admin@MikroTik] >") == "mikrotik"
    assert inspect_prompt_os("[admin@MikroTik] /ip address>") == "mikrotik"

    # Cisco IOS-XR RSP/RP/LC slots & dotted hostnames
    assert inspect_prompt_os("RP/0/RSP0/CPU0:asr9k-core#") == "cisco_xr"
    assert inspect_prompt_os("RP/0/RP0/CPU0:ncs5500.nyc#") == "cisco_xr"
    assert inspect_prompt_os("LC/0/0/CPU0:line-card-01#") == "cisco_xr"

    # Palo Alto HA & non-PA hostnames
    assert inspect_prompt_os("admin@PA-220>") == "paloalto_panos"
    assert inspect_prompt_os("admin@PA-5220(active)>") == "paloalto_panos"
    assert inspect_prompt_os("admin@hq-fw01(active)>") == "paloalto_panos"
    assert inspect_prompt_os("admin@hq-fw02(passive)>") == "paloalto_panos"

    # HP ProCurve must NOT be stolen by Fortinet space-# rule
    assert inspect_prompt_os("ProCurve #") == "hpprocurve"
    assert inspect_prompt_os("HP-2920 #") == "hpprocurve"
    assert inspect_prompt_os("ProCurve-2530#") == "hpprocurve"

    # Fortinet read-only '$' and VDOM '#' prompts + dotted hostname
    assert inspect_prompt_os("FortiGate-60F #") == "fortinet"
    assert inspect_prompt_os("FortiGate-60F $") == "fortinet"
    assert inspect_prompt_os("FG-Edge (root) #") == "fortinet"
    assert inspect_prompt_os("FG-Edge (vdom1) $") == "fortinet"
    assert inspect_prompt_os("fw1.corp #") == "fortinet"

    # Multiline Juniper prompt & dotted switch/Arista hostnames
    assert inspect_prompt_os("{master:0}\nadmin@ex4300>") == "juniper_junos"
    assert inspect_prompt_os("root@branch-gw:~#") == "unknown"
    assert inspect_prompt_os("sw01.corp#") == "prompt_switch_standard"
    assert inspect_prompt_os("N9K-Core-VDC1#") == "prompt_switch_standard"
    assert inspect_prompt_os("Arista-Leaf1.dc1#") == "arista"

    # Canonical vendor resolver for Tier 3 dispatch
    assert resolve_prompt_vendor("RP/0/RSP0/CPU0:asr9k-core#") == "cisco_xr"
    assert resolve_prompt_vendor("admin@PA-5220(active)>") == "paloalto"
    assert resolve_prompt_vendor("{master:0}\nadmin@ex4300>") == "juniper"
    assert resolve_prompt_vendor("FortiGate-60F $") == "fortinet"
    assert resolve_prompt_vendor("[admin@MikroTik] >") == "mikrotik"
    assert resolve_prompt_vendor("ProCurve #") == "hpprocurve"
    assert resolve_prompt_vendor("Arista-Leaf1#") == "arista"
    assert resolve_prompt_vendor("[root@rhel9 ~]#") == "unknown"


def test_oui_matching_aruba_hpe_meraki_and_fhrp_laa_hypervisor_bypass():
    """DD-08 / DD-09: Fix Aruba/HPE/Meraki OUI matching and bypass Tier 1 for FHRP/LAA/hypervisor MACs."""
    assert _match_vendor_from_oui("aruba, a hewlett packard enterprise company") == "aruba"
    assert _match_vendor_from_oui("aruba/hpe") == "aruba"
    assert _match_vendor_from_oui("hewlett packard enterprise") == "unknown"
    assert _match_vendor_from_oui("hewlett packard") == "hpprocurve"
    assert _match_vendor_from_oui("cisco meraki") == "unknown"
    assert _match_vendor_from_oui("cisco systems") == "cisco"

    # Expanded hypervisor OUIs
    assert is_hypervisor_mac("00:1c:14:11:22:33") is True  # VMware ESXi/NSX
    assert is_hypervisor_mac("00:1c:42:11:22:33") is True  # Parallels
    assert is_hypervisor_mac("00:1a:4a:11:22:33") is True  # oVirt/KVM
    assert is_hypervisor_mac("02:42:ac:11:00:02") is True  # Docker

    # HSRP virtual MAC (00:00:0C:07:AC:01) must bypass Cisco OUI lock and cascade to Tier 2
    with patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-Arista") as mock_ssh:
        vendor, _ = detect_vendor_range("10.0.0.1", mac="00:00:0c:07:ac:01")
        assert vendor == "arista"
        assert mock_ssh.call_count == 1

    # VRRP/CARP virtual MAC (00:00:5E:00:01:01) must cascade to Tier 2
    with patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-Junos") as mock_ssh:
        vendor, _ = detect_vendor_range("10.0.0.2", mac="00:00:5e:00:01:01")
        assert vendor == "juniper"
        assert mock_ssh.call_count == 1

    # LAA MAC (e.g. Proxmox LXC / container) must cascade to Tier 2
    with patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-ROSSSH") as mock_ssh:
        vendor, _ = detect_vendor_range("10.0.0.3", mac="02:11:22:33:44:55")
        assert vendor == "mikrotik"
        assert mock_ssh.call_count == 1


def test_system_arp_exact_ip_boundary_bsd_short_octets_and_linux_incomplete_flag(tmp_path):
    """DD-12: Exact IP boundary in ARP lookup, BSD/macOS short-octet MACs, and incomplete ARP filtering."""
    win_arp = (
        "Interface: 192.168.1.50 --- 0x10\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic\n"
        "  192.168.1.1           00-00-0c-12-34-56     dynamic\n"
    )
    with (
        patch("net_docu_crawler.drivers.detector.os.path.exists", return_value=False),
        patch("net_docu_crawler.drivers.detector.sys.platform", "win32"),
        patch(
            "net_docu_crawler.drivers.detector.subprocess.run",
            return_value=MagicMock(returncode=0, stdout=win_arp),
        ),
    ):
        assert get_mac_from_system_arp("192.168.1.1") == "00:00:0c:12:34:56"
        assert get_mac_from_system_arp("192.168.1.10") == "aa:bb:cc:dd:ee:ff"

    bsd_arp = "? (192.168.1.1) at 0:0:c:12:34:56 on en0 ifscope [ethernet]\n"
    with (
        patch("net_docu_crawler.drivers.detector.os.path.exists", return_value=False),
        patch("net_docu_crawler.drivers.detector.sys.platform", "darwin"),
        patch(
            "net_docu_crawler.drivers.detector.subprocess.run",
            return_value=MagicMock(returncode=0, stdout=bsd_arp),
        ),
    ):
        assert get_mac_from_system_arp("192.168.1.1") == "00:00:0c:12:34:56"

    bsd_table = (
        "? (192.168.1.1) at 0:0:c:12:34:56 on en0 ifscope [ethernet]\n"
        "? (192.168.1.2) at (incomplete) on en0 ifscope [ethernet]\n"
        "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n"
    )
    with (
        patch("net_docu_crawler.drivers.detector.os.path.exists", return_value=False),
        patch("net_docu_crawler.drivers.detector.sys.platform", "darwin"),
        patch("net_docu_crawler.drivers.detector.subprocess.check_output", return_value=bsd_table),
    ):
        assert get_arp_table_entries() == {"192.168.1.1": "00:00:0c:12:34:56"}

    # Linux /proc/net/arp must skip flags == 0x0 (incomplete/stale)
    fake_proc = tmp_path / "arp"
    fake_proc.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         00:00:0c:12:34:56     *        eth0\n"
        "192.168.1.2      0x1         0x0         00:00:0c:99:88:77     *        eth0\n",
        encoding="utf-8",
    )
    with (
        patch("net_docu_crawler.drivers.detector.os.path.exists", return_value=True),
        patch("builtins.open", side_effect=lambda _p, *a, **kw: fake_proc.open(*a, **kw)),
    ):
        assert get_arp_table_entries() == {"192.168.1.1": "00:00:0c:12:34:56"}


def test_dual_stack_ipv6_port_validation_and_socket_cleanup():
    """DD-05 / DD-06: Validate port bounds (no OverflowError), support IPv6 AF_INET6, and always close sockets."""
    # Invalid ports must fail gracefully without creating any socket or raising OverflowError
    with patch("net_docu_crawler.drivers.detector.socket.socket") as mock_no_sock:
        assert probe_tcp_port("10.0.0.1", 0) is False
        assert probe_tcp_port("10.0.0.1", -1) is False
        assert probe_tcp_port("10.0.0.1", 70000) is False
        assert get_ssh_banner("10.0.0.1", port=70000) == ""
        assert probe_snmp_sysinfo("10.0.0.1", port=70000) is None
        assert mock_no_sock.call_count == 0

    # IPv6 literal (bare and bracketed) uses AF_INET6
    created_families = []

    def fake_socket(family, socktype, *args, **kwargs):
        created_families.append((family, socktype))
        sock = MagicMock()
        sock.connect_ex.return_value = 0
        sock.recv.side_effect = [b"SSH-2.0-OpenSSH_9.6\r\n", b""]
        return sock

    with patch("net_docu_crawler.drivers.detector.socket.socket", side_effect=fake_socket):
        assert probe_tcp_port("2001:db8::1", 22) is True
        assert probe_tcp_port("[2001:db8::1]", 22) is True
        assert get_ssh_banner("2001:db8::1", 22) == "SSH-2.0-OpenSSH_9.6"

    assert all(fam == socket.AF_INET6 for fam, _ in created_families)

    # HTTP fingerprint over IPv6 formats Host header with brackets
    sent_reqs = []

    def fake_http_sock(family, socktype, *args, **kwargs):
        sock = MagicMock()
        sock.connect_ex.return_value = 0
        sock.sendall.side_effect = lambda data: sent_reqs.append(data)
        sock.recv.side_effect = [b"HTTP/1.0 200 OK\r\nServer: nginx\r\n\r\n<title>Router</title>", b""]
        return sock

    with patch("net_docu_crawler.drivers.detector.socket.socket", side_effect=fake_http_sock):
        fp = probe_http_fingerprint("2001:db8::1", ports=(80,))
        assert fp is not None and fp["title"] == "Router"
    assert any(b"Host: [2001:db8::1]\r\n" in r for r in sent_reqs)

    # Socket must still close if settimeout raises ValueError (negative timeout)
    leak_sock = MagicMock()
    leak_sock.settimeout.side_effect = ValueError("Timeout value out of range")
    with patch("net_docu_crawler.drivers.detector.socket.socket", return_value=leak_sock):
        assert probe_tcp_port("10.0.0.1", 22, timeout=-5.0) is False
    assert leak_sock.close.call_count == 1


def test_driver_registry_aliases_canonicalize_strip_and_exports():
    """DD-04 / DD-18: Vendor aliases, canonicalize_vendor, get_driver whitespace strip, and __all__ exports."""
    from net_docu_crawler.drivers import canonicalize_vendor

    assert resolve_driver_for_vendor("junos") is JuniperDriver
    assert resolve_driver_for_vendor("juniper_junos") is JuniperDriver
    assert resolve_driver_for_vendor("fortigate") is FortinetDriver
    assert resolve_driver_for_vendor("fortios") is FortinetDriver
    assert resolve_driver_for_vendor("panos") is PaloAltoDriver
    assert resolve_driver_for_vendor("eos") is AristaDriver
    assert resolve_driver_for_vendor("arista_eos") is AristaDriver
    assert resolve_driver_for_vendor("ios") is CiscoDriver
    assert resolve_driver_for_vendor("cisco_nxos") is CiscoDriver
    assert resolve_driver_for_vendor("ios-xr") is CiscoXRDriver
    assert resolve_driver_for_vendor("routeros") is MikroTikDriver
    assert resolve_driver_for_vendor("aruba_cx") is ArubaDriver
    assert resolve_driver_for_vendor("hp_procurve") is HPProCurveDriver
    assert resolve_driver_for_vendor("cbs350") is CiscoSMBDriver

    assert canonicalize_vendor("  JUNOS  ") == "juniper"
    assert canonicalize_vendor("hp") == "hpprocurve"
    assert canonicalize_vendor("procurve") == "hpprocurve"
    assert canonicalize_vendor("frr") == "frrouting"
    assert canonicalize_vendor("fortigate") == "fortinet"
    assert canonicalize_vendor("sg300") == "ciscosmb"
    assert canonicalize_vendor("iosxr") == "cisco_xr"
    assert canonicalize_vendor("unknown_vendor") == ""

    with patch("net_docu_crawler.drivers.detect_vendor_range") as mock_det:
        drv = get_driver("10.0.0.1", vendor_hint="  JUNOS  ")
        assert isinstance(drv, JuniperDriver)
        assert mock_det.call_count == 0

    assert "CiscoXRDriver" in drivers_pkg.__all__
    assert "canonicalize_vendor" in drivers_pkg.__all__

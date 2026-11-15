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
Unit tests for Net-Docu-Crawler multi-vendor drivers, services parser, and zero-blast detector.
"""

from unittest.mock import MagicMock, patch

from net_docu_crawler.drivers import (
    AristaDriver,
    ArubaDriver,
    CiscoDriver,
    FortinetDriver,
    FRRDriver,
    HPProCurveDriver,
    JuniperDriver,
    MikroTikDriver,
    OpenWrtDriver,
    OPNsenseDriver,
    PaloAltoDriver,
    get_driver,
)
from net_docu_crawler.drivers.base import extract_services_from_config
from net_docu_crawler.drivers.detector import (
    detect_vendor_range,
    get_mac_from_system_arp,
    inspect_prompt_os,
    is_hypervisor_mac,
)


def test_get_mac_from_system_arp_windows_fallback():
    windows_arp_output = """
Interface: 192.168.1.50 --- 0x10
  Internet Address      Physical Address      Type
  192.168.1.1           fc-33-42-e6-b5-99     dynamic
  192.168.1.250         00-00-0c-12-34-56     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = windows_arp_output

    with patch("os.path.exists", return_value=False):
        with patch("sys.platform", "win32"):
            with patch("subprocess.run", return_value=mock_proc):
                mac = get_mac_from_system_arp("192.168.1.1")
                assert mac == "fc:33:42:e6:b5:99"
                mac_cisco = get_mac_from_system_arp("192.168.1.250")
                assert mac_cisco == "00:00:0c:12:34:56"
                assert get_mac_from_system_arp("192.168.1.99") == ""


def test_detector_prompt_inspection():
    assert inspect_prompt_os("RP/0/0/CPU0:core-router#") == "cisco_xr"
    assert inspect_prompt_os("LC/0/0/CPU0:line-card-01#") == "cisco_xr"
    assert inspect_prompt_os("admin@switch01>") == "juniper_junos"
    assert inspect_prompt_os("root@ex3300#") == "juniper_junos"
    assert inspect_prompt_os("admin@PA-220>") == "paloalto_panos"
    assert inspect_prompt_os("admin@PA-5200#") == "paloalto_panos"
    assert inspect_prompt_os("FortiGate-60F #") == "fortinet"
    assert inspect_prompt_os("FG-Edge (root) #") == "fortinet"
    assert inspect_prompt_os("root@OpenWrt:~#") == "openwrt"
    assert inspect_prompt_os("root@opnsense:~ #") == "opnsense"
    assert inspect_prompt_os("[admin@MikroTik] >") == "mikrotik"
    assert inspect_prompt_os("Switch-Core#") == "prompt_switch_standard"


def test_detector_vendor_range_oui():
    vendor, _ = detect_vendor_range("192.168.1.100", mac="00:00:0c:12:34:56")
    assert vendor == "cisco"

    vendor, _ = detect_vendor_range("192.168.1.101", mac="fc:33:42:e6:b5:99")
    assert vendor == "juniper"

    vendor, _ = detect_vendor_range("192.168.1.102", mac="40:e3:d6:c1:31:26")
    assert vendor == "aruba"

    vendor, _ = detect_vendor_range("192.168.1.103", mac="08:66:1f:11:22:33")
    assert vendor == "paloalto"

    vendor, _ = detect_vendor_range("192.168.1.104", mac="70:4c:a5:00:11:22")
    assert vendor == "fortinet"


def test_hypervisor_mac_cascades_to_ssh_banner():
    assert is_hypervisor_mac("bc:24:11:b4:a9:82")  # Proxmox
    assert is_hypervisor_mac("52:54:00:11:22:33")  # QEMU/KVM
    assert is_hypervisor_mac("00:50:56:aa:bb:cc")  # VMware
    assert not is_hypervisor_mac("fc:33:42:e6:b5:99")  # Physical Juniper

    with patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-ROSSSH"):
        vendor, banner = detect_vendor_range("172.16.1.10", mac="bc:24:11:fd:10:28")
        assert vendor == "mikrotik"
        assert banner == "SSH-2.0-ROSSSH"


def test_factory_get_driver():
    c_driver = get_driver("10.0.0.1", vendor_hint="cisco")
    assert isinstance(c_driver, CiscoDriver)
    assert c_driver.paging_cmd == "terminal length 0"

    j_driver = get_driver("10.0.0.2", vendor_hint="juniper")
    assert isinstance(j_driver, JuniperDriver)
    assert j_driver.paging_cmd == "set cli screen-length 0"

    a_driver = get_driver("10.0.0.3", vendor_hint="aruba")
    assert isinstance(a_driver, ArubaDriver)

    p_driver = get_driver("10.0.0.4", vendor_hint="paloalto")
    assert isinstance(p_driver, PaloAltoDriver)
    assert p_driver.device_persona == "firewall"

    f_driver = get_driver("10.0.0.5", vendor_hint="fortinet")
    assert isinstance(f_driver, FortinetDriver)
    assert f_driver.device_persona == "firewall"

    opn_driver = get_driver("10.0.0.6", vendor_hint="opnsense")
    assert isinstance(opn_driver, OPNsenseDriver)
    assert opn_driver.device_persona == "firewall"

    owrt_driver = get_driver("10.0.0.7", vendor_hint="openwrt")
    assert isinstance(owrt_driver, OpenWrtDriver)
    assert owrt_driver.device_persona == "router"

    arista_driver = get_driver("10.0.0.8", vendor_hint="arista")
    assert isinstance(arista_driver, AristaDriver)

    mt_driver = get_driver("10.0.0.9", vendor_hint="mikrotik")
    assert isinstance(mt_driver, MikroTikDriver)

    frr_driver = get_driver("10.0.0.10", vendor_hint="frrouting")
    assert isinstance(frr_driver, FRRDriver)


def test_paloalto_driver_mock():
    driver = PaloAltoDriver(ip="192.168.1.5")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show system info": "hostname: PA-Corp-FW\nmodel: PA-220\nserial: 012345678901\nsw-version: 10.2.3\nmac-address: 08:66:1f:aa:bb:cc\n",
        "show interface all": "ethernet1/1  10.0.0.1/24  up  up\nethernet1/2  192.168.1.1/24  up  up\n",
        "show lldp neighbors all": "Interface: ethernet1/1\nSystem Name: Core-Switch-01\nPort ID: GigabitEthernet1/0/1\nManagement Address: 10.0.0.2\n",
        "show routing route": "0.0.0.0/0  192.168.1.254  A  ethernet1/2\n10.0.0.0/24  0.0.0.0  C  ethernet1/1\n",
        "show arp all": "10.0.0.2  00:00:0c:99:88:77  ethernet1/1\n",
        "show config running": "<config><system><hostname>PA-Corp-FW</hostname><dnsserver>8.8.8.8</dnsserver></system></config>\n",
    }.get(cmd, "")
    mock_conn.find_prompt.return_value = "admin@PA-Corp-FW>"

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "PA-Corp-FW"
    assert data["model"] == "PA-220"
    assert data["serial"] == "012345678901"
    assert data["firmware"] == "PAN-OS 10.2.3"
    assert len(data["l3_interfaces"]) == 2
    assert len(data["neighbors"]) == 1
    assert data["neighbors"][0]["remote_device"] == "Core-Switch-01"
    assert len(data["routes"]) == 2
    assert len(data["arp_table"]) == 1
    assert "8.8.8.8" in data["services"]["dns_servers"]


def test_fortinet_driver_mock_and_pseudo_filtering():
    driver = FortinetDriver(ip="192.168.1.6")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "get system status": "Hostname: FG-Edge-01\nVersion: FortiGate-60F v7.2.4,build1396\nSerial-Number: FGT60FTK21000000\n",
        "show system interface": (
            'edit "port1"\n set ip 192.168.1.99 255.255.255.0\n set description "Uplink"\nnext\n'
            'edit "naf.root"\n set status up\nnext\n'
            'edit "ssl.root"\n set status up\nnext\n'
        ),
        "diagnose snmp sysinfo lldp neighbor": "Port: port1\nChassis ID: 00:00:0c:11:22:33\nPort ID: Gi1/0/24\n",
        "get router info routing-table all": "S* 0.0.0.0/0 [10/0] via 192.168.1.1, port1\n",
        "get system arp": "192.168.1.10  fc:33:42:e6:b5:99  port1\n",
        "show full-configuration": (
            "config system global\n set hostname FG-Edge-01\nend\n"
            "config system dns\n set primary 9.9.9.9\nend\n"
            "config system ntp\n set ntpsync enable\nend\n"
        ),
    }.get(cmd, "")
    mock_conn.find_prompt.return_value = "FG-Edge-01 #"

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "FG-Edge-01"
    assert data["model"] == "FortiGate-60F"
    assert data["serial"] == "FGT60FTK21000000"
    assert "port1" in data["interfaces_detail"]
    assert "naf.root" not in data["interfaces_detail"]
    assert "ssl.root" not in data["interfaces_detail"]
    assert len(data["l3_interfaces"]) == 1
    assert len(data["neighbors"]) == 1
    assert len(data["routes"]) == 1
    assert len(data["arp_table"]) == 1
    assert data["arp_table"][0]["vendor"] == "Juniper Networks"
    assert data["services"]["dns_servers"] == ["9.9.9.9"]
    assert data["services"]["ntp_servers"] == ["fortiguard"]


def test_juniper_driver_physical_ports_and_fabric_filtering():
    driver = JuniperDriver(ip="192.168.1.3")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show version | display json": '{"software-information": [{"host-name": [{"data": "core-switch-01"}], "product-model": [{"data": "ex2300-c-12p"}], "junos-version": [{"data": "23.4R2"}]}]}',
        "show chassis hardware | display json": '{"chassis-inventory": [{"chassis": [{"serial-number": [{"data": "CW0217120312"}]}]}]}',
        "show chassis mac-addresses": "Public base address     fc:33:42:e6:b5:80\n",
        "show interfaces terse | display json": """{
            "interface-information": [{
                "physical-interface": [
                    {"name": [{"data": "ge-0/0/3"}], "admin-status": [{"data": "up"}], "oper-status": [{"data": "up"}], "logical-interface": []},
                    {"name": [{"data": "bme0"}], "admin-status": [{"data": "up"}], "oper-status": [{"data": "up"}], "logical-interface": [
                        {"name": [{"data": "bme0.0"}], "oper-status": [{"data": "up"}], "address-family": [{"address-family-name": [{"data": "inet"}], "interface-address": [{"ifa-local": [{"data": "128.0.0.1/2"}]}]}]}
                    ]},
                    {"name": [{"data": "irb"}], "admin-status": [{"data": "up"}], "oper-status": [{"data": "up"}], "logical-interface": [
                        {"name": [{"data": "irb.0"}], "oper-status": [{"data": "up"}], "address-family": [{"address-family-name": [{"data": "inet"}], "interface-address": [{"ifa-local": [{"data": "192.168.1.3"}], "ifa-destination": [{"data": "192.168.1.0/24"}]}]}]}
                    ]}
                ]
            }]
        }""",
        "show lldp neighbors detail | display json": """{
            "lldp-neighbors-information": [{
                "lldp-neighbor-information": [
                    {
                        "lldp-local-port-id": [{"data": "515"}],
                        "lldp-local-interface": [{"data": "ge-0/0/3.0"}],
                        "lldp-remote-system-name": [{"data": "ap-office-01"}],
                        "lldp-remote-port-id": [{"data": "eth0"}],
                        "lldp-remote-chassis-id": [{"data": "40:e3:d6:c1:31:26"}],
                        "lldp-remote-system-description": [{"data": "ArubaOS (MODEL: 215), Version 8.6.0.25"}]
                    },
                    {
                        "lldp-local-port-id": [{"data": "517"}],
                        "lldp-local-interface": [{"data": "ge-0/0/5.0"}],
                        "lldp-remote-system-name": [{"data": "ap-warehouse-01"}],
                        "lldp-remote-port-id": [{"data": "40:e3:d6:c1:2d:a4"}],
                        "lldp-remote-chassis-id": [{"data": "40:e3:d6:c1:2d:a4"}]
                    }
                ]
            }]
        }""",
        "show spanning-tree bridge | display json": '{"stp-bridge-parameters-information": [{"enabled-protocol": [{"data": "RSTP"}]}]}',
        "show route | display json": '{"route-information": [{"route-table": [{"table-name": [{"data": "inet.0"}], "rt": [{"rt-destination": [{"data": "0.0.0.0/0"}], "rt-entry": [{"protocol-name": [{"data": "Static"}], "nh": [{"to": [{"data": "192.168.1.1"}], "via": [{"data": "irb.0"}]}]}]}]}]}]}',
        "show arp no-resolve | display json": '{"arp-table-information": [{"arp-table-entry": [{"ip-address": [{"data": "192.168.1.215"}], "mac-address": [{"data": "40:e3:d6:c1:31:26"}], "interface-name": [{"data": "irb.0"}]}]}]}',
        "show configuration | display set": "set system host-name core-switch-01\nset system name-server 192.168.1.1\nset system ntp server 0.juniper.pool.ntp.org\n",
    }.get(cmd, "")

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "core-switch-01"
    assert data["mac_address"] == "fc:33:42:e6:b5:80"
    assert "bme0" not in data["interfaces_detail"]
    assert "ge-0/0/3" in data["interfaces_detail"]
    assert len(data["l3_interfaces"]) == 1
    assert data["l3_interfaces"][0]["ip_address"] == "192.168.1.3/24"
    assert data["neighbors"][0]["local_port"] == "ge-0/0/3"  # Not SNMP index 515!
    assert data["neighbors"][0]["device_type"] == "ap"
    assert "ArubaOS" in data["neighbors"][0]["platform"]
    # Aruba IAP omitting System Description TLV still resolves as AP via OUI
    assert data["neighbors"][1]["local_port"] == "ge-0/0/5"
    assert data["neighbors"][1]["device_type"] == "ap"
    assert "aruba" in data["neighbors"][1]["platform"].lower()
    assert data["stp"]["enabled"] is True
    assert data["services"]["dns_servers"] == ["192.168.1.1"]


def test_opnsense_driver_mock():
    driver = OPNsenseDriver(ip="192.168.1.1")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd, timeout=15: {
        "hostname": "opnsense.local\n",
        "opnsense-version": "OPNsense 25.7.11_9 (amd64)\n",
        "kenv smbios.system.product 2>/dev/null": "Standard PC (Q35 + ICH9, 2009)\n",
        "kenv smbios.system.serial 2>/dev/null": "VM-OPN-12345\n",
        "ifconfig -a": """vtnet0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\toptions=800b8<VLAN_MTU,VLAN_HWTAGGING,JUMBO_MTU,VLAN_HWCSUM,LINKSTATE>
\tether bc:24:11:b4:a9:82
\tinet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255
vtnet1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether bc:24:11:00:11:22
\tinet 100.64.0.2 netmask 0xfffffe00 broadcast 100.64.1.255
pflog0: flags=100<PROMISC> metric 0 mtu 33152
""",
        "lldpctl -f json 2>/dev/null": "{}",
        "netstat -rn -f inet": """Routing tables

Internet:
Destination        Gateway            Flags     Netif Expire
default            100.64.0.1         UGS      vtnet1
127.0.0.1          link#4             UH         lo0
192.168.1.0/24     link#1             U        vtnet0
""",
        "arp -an": "? (192.168.1.3) at fc:33:42:e6:b5:99 on vtnet0 expires in 1200 seconds [ethernet]\n",
        "cat /conf/config.xml": "<opnsense><system><hostname>opnsense</hostname><dnsserver>1.1.1.1</dnsserver><timeservers>0.opnsense.pool.ntp.org</timeservers></system></opnsense>\n",
    }.get(cmd, "")

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "opnsense.local"
    assert "25.7.11_9" in data["firmware"]
    assert data["mac_address"] == "bc:24:11:b4:a9:82"
    assert "pflog0" not in data["interfaces_detail"]
    assert len(data["l3_interfaces"]) == 2
    assert len(data["routes"]) == 2
    assert data["routes"][0]["subnet"] == "0.0.0.0/0"
    assert len(data["arp_table"]) == 1
    assert data["arp_table"][0]["vendor"] == "Juniper Networks"
    assert data["services"]["dns_servers"] == ["1.1.1.1"]
    assert data["services"]["ntp_servers"] == ["0.opnsense.pool.ntp.org"]
    assert "<opnsense>" in data["raw_config"]


def test_openwrt_driver_mock():
    driver = OpenWrtDriver(ip="192.168.1.2")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "ubus call system board 2>/dev/null": '{"kernel": "5.15.137", "hostname": "OpenWrt-Core", "model": "FriendlyElec NanoPi R4S", "release": {"description": "OpenWrt 23.05.2 r23630", "version": "23.05.2"}}',
        "ubus call network.interface dump 2>/dev/null": '{"interface": [{"interface": "loopback", "up": true, "device": "lo", "ipv4-address": [{"address": "127.0.0.1", "mask": 8}]}, {"interface": "lan", "up": true, "device": "br-lan", "ipv4-address": [{"address": "192.168.1.2", "mask": 24}]}, {"interface": "wan", "up": true, "device": "eth0", "ipv4-address": [{"address": "10.10.10.2", "mask": 24}]}]}',
        "ip -d address show 2>/dev/null || ip address show 2>/dev/null": """1: lo: <LOOPBACK,UP,LOWER_UP>
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:e0:4c:68:01:02 brd ff:ff:ff:ff:ff:ff
3: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 00:e0:4c:68:01:01 brd ff:ff:ff:ff:ff:ff
""",
        "lldpcli show neighbors -f json 2>/dev/null": '{"lldp": {"interface": [{"eth0": {"chassis": {"name": {"value": "EdgeRouter"}}, "port": {"id": {"value": "eth1"}}}}]}}',
        "ubus call hostapd.* get_clients 2>/dev/null": "{}",
        "ip route show 2>/dev/null || route -n 2>/dev/null": """default via 10.10.10.1 dev eth0 proto static
10.10.10.0/24 dev eth0 proto kernel scope link src 10.10.10.2
192.168.1.0/24 dev br-lan proto static scope link src 192.168.1.2
""",
        "cat /proc/net/arp 2>/dev/null": """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.3      0x1         0x2         fc:33:42:e6:b5:99     *        br-lan
""",
        "uci export 2>/dev/null": "package network\n\nconfig interface 'loopback'\n\toption device 'lo'\n\toption proto 'static'\nlist server '0.openwrt.pool.ntp.org'\n",
    }.get(cmd, "")

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "OpenWrt-Core"
    assert data["serial"] == "Unknown"  # Never static placeholder!
    assert data["model"] == "FriendlyElec NanoPi R4S"
    assert "23.05.2" in data["firmware"]
    assert "lo" not in data["interfaces_detail"]
    assert len(data["l3_interfaces"]) == 2
    assert len(data["neighbors"]) == 1
    assert data["neighbors"][0]["remote_device"] == "EdgeRouter"
    assert len(data["routes"]) == 3
    assert len(data["arp_table"]) == 1
    assert data["arp_table"][0]["vendor"] == "Juniper Networks"
    assert "0.openwrt.pool.ntp.org" in data["services"]["ntp_servers"]


def test_arista_driver_mock():
    driver = AristaDriver(ip="192.168.1.253")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show version | json": '{"modelName": "vEOS-lab", "internalVersion": "4.37.0F", "serialNumber": "SN-ARISTA-01"}',
        "show hostname | json": '{"hostname": "arista-veos-01", "fqdn": "arista-veos-01.lan"}',
        "show ip interface | json": '{"interfaces": {"Management1": {"interfaceAddress": {"primaryIp": {"address": "192.168.1.253", "maskLen": 24}}, "lineProtocolStatus": "up", "physicalAddress": "bc:24:11:84:1a:90", "description": "OOB Management"}}}',
        "show lldp neighbors detail | json": '{"lldpNeighbors": {"Management1": {"lldpNeighborInfo": [{"systemName": "switch-juniper", "portId": "ge-0/0/2"}]}}}',
        "show spanning-tree | json": '{"spanningTreeInstances": {"MST0": {"isRootBridge": false}}}',
        "show ip route | json": '{"vrfs": {"default": {"routes": {"0.0.0.0/0": {"routeType": "static", "vias": [{"nexthopAddr": "192.168.1.1", "interface": "Management1"}]}}}}}',
        "show ip arp | json": '{"ipV4Neighbors": [{"address": "192.168.1.1", "hwAddress": "bc:24:11:b4:a9:82", "interface": "Management1"}]}',
        "show running-config": "! Arista vEOS configuration\nhostname arista-veos-01\nip name-server 192.168.1.1\n",
    }.get(cmd, "")
    mock_conn.find_prompt.return_value = "arista-veos-01#"

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "arista-veos-01.lan"
    assert data["model"] == "vEOS-lab"
    assert data["serial"] == "SN-ARISTA-01"
    assert data["firmware"] == "EOS 4.37.0F"
    assert data["mac_address"] == "bc:24:11:84:1a:90"
    assert data["stp"]["enabled"] is True
    assert len(data["l3_interfaces"]) == 1
    assert len(data["neighbors"]) == 1
    assert len(data["routes"]) == 1
    assert len(data["arp_table"]) == 1
    assert data["services"]["dns_servers"] == ["192.168.1.1"]


def test_mikrotik_driver_quote_stripping_and_mac_harvest():
    driver = MikroTikDriver(ip="172.16.1.251")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "/system identity print": "  name: MikroTik-Core\n",
        "/system resource print": "  version: 7.16.1 (stable)\n  platform: MikroTik\n  board-name: CHR\n",
        "/system routerboard print": "  serial-number: MT-123456\n",
        "/interface ethernet print detail": ' 0 R name="ether1" default-name="ether1" mac-address=BC:24:11:FD:10:28 \n',
        "/ip address print detail": "Flags: X - disabled, I - invalid, D - dynamic\n 0   address=172.16.1.251/24 network=172.16.1.0 interface=ether1 actual-interface=ether1 \n",
        "/ip neighbor print detail": 'Flags: X - disabled, D - dynamic\n 0 interface=ether1,bridge1 identity="edge-router-01.corp.internal" address=192.168.1.250 platform="Cisco"\n',
        "/ip route print detail": "Flags: D - DYNAMIC; A - ACTIVE; s - STATIC\n 0 As  dst-address=0.0.0.0/0 gateway=172.16.1.1 immediate-gw=172.16.1.1%ether1 \n",
        "/ip arp print detail": "Flags: D - DYNAMIC\n 0 D address=172.16.1.1 mac-address=FC:33:42:E6:B5:99 interface=ether1 \n",
        "/export compact": "# RouterOS export\n/system identity set name=MikroTik-Core\n/ip dns set servers=1.1.1.1,8.8.8.8\n",
    }.get(cmd, "")

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "MikroTik-Core"
    assert data["mac_address"] == "bc:24:11:fd:10:28"  # Extracted even across L3 gateway!
    assert data["neighbors"][0]["remote_device"] == "edge-router-01.corp.internal"  # Quotes stripped!
    assert '"' not in data["neighbors"][0]["remote_device"]
    assert data["neighbors"][0]["local_port"] == "ether1"
    assert data["services"]["dns_servers"] == ["1.1.1.1", "8.8.8.8"]


def test_frr_driver_mock():
    driver = FRRDriver(ip="192.168.1.254")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "hostname -s": "frr-router-01\n",
        "vtysh -c 'show version'": "FRRouting 10.3 (frr-router-01)\n",
        "vtysh -c 'show interface json'": '{"eth0": {"hardwareAddress": "bc:24:11:4a:78:63", "operationalStatus": "up", "ipAddresses": [{"address": "192.168.1.254/24"}]}}',
        "vtysh -c 'show ip route json'": '{"0.0.0.0/0": [{"nexthops": [{"ip": "192.168.1.1", "interfaceName": "eth0"}], "protocol": "kernel"}]}',
        "ip -j neigh show": '[{"dst": "192.168.1.3", "lladdr": "fc:33:42:e6:b5:99", "dev": "eth0"}]',
        "lldpcli show neighbors -f json": "{}",
        "vtysh -c 'show running-config'": "! FRR running config\nhostname frr-router-01\n",
    }.get(cmd, "")

    data = driver.crawl(mock_conn)
    assert data["hostname"] == "frr-router-01"
    assert data["serial"] == "Unknown"
    assert "10.3" in data["firmware"]
    assert data["mac_address"] == "bc:24:11:4a:78:63"
    assert len(data["l3_interfaces"]) == 1
    assert len(data["routes"]) == 1
    assert len(data["arp_table"]) == 1


def test_extract_services_multi_vendor():
    cfg = """
    set system name-server 192.168.1.1
    set system ntp server 129.6.15.28
    ip name-server 8.8.8.8 8.8.4.4
    ntp server 216.239.35.0
    """
    svc = extract_services_from_config(cfg)
    assert "192.168.1.1" in svc["dns_servers"]
    assert "8.8.8.8" in svc["dns_servers"]
    assert "129.6.15.28" in svc["ntp_servers"]
    assert "216.239.35.0" in svc["ntp_servers"]


def test_cisco_driver_poe_mac_optics():
    driver = CiscoDriver(ip="192.168.1.250")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show power inline": "Available: 370.0 (W)  Used: 45.2 (W)  Remaining: 324.8 (W)\n",
        "show mac address-table": " 10    0011.2233.4455    DYNAMIC     Gi1/0/1\n",
        "show interfaces transceiver": "Te1/0/1  32.5 C  3.30 V  5.5 mA  -2.1 dBm  -3.4 dBm\n",
    }.get(cmd, "")

    poe = driver.get_poe(mock_conn)
    assert poe["total_power_watts"] == 370.0
    assert poe["used_power_watts"] == 45.2
    assert poe["available_power_watts"] == 324.8

    macs = driver.get_mac_table(mock_conn)
    assert len(macs) == 1
    assert macs[0]["mac"] == "00:11:22:33:44:55"
    assert macs[0]["interface"] == "Gi1/0/1"

    optics = driver.get_optics(mock_conn)
    assert len(optics) == 1
    assert optics[0]["port"] == "Te1/0/1"
    assert optics[0]["tx_power_dbm"] == -2.1
    assert optics[0]["rx_power_dbm"] == -3.4
    assert optics[0]["temperature_c"] == 32.5


def test_juniper_driver_poe_mac_optics():
    driver = JuniperDriver(ip="192.168.1.3")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show poe controller | display json": '{"poe-controller-information": [{"poe-controller-entry": [{"maximum-power": [{"data": "740W"}], "consumed-power": [{"data": "120W"}], "available-power": [{"data": "620W"}]}]}]}',
        "show poe interface | display json": '{"poe-interface-information": [{"poe-interface-entry": [{"interface-name": [{"data": "ge-0/0/1"}], "power-consumed": [{"data": "15.4W"}], "power-status": [{"data": "ON"}], "interface-class": [{"data": "3"}]}]}]}',
        "show ethernet-switching table | display json": '{"ethernet-switching-table-information": [{"ethernet-switching-table-entry": [{"mac-address": [{"data": "00:11:22:33:44:55"}], "logical-interface": [{"data": "ge-0/0/1.0"}], "vlan-name": [{"data": "DATA"}], "mac-type": [{"data": "Learn"}]}]}]}',
        "show interfaces diagnostics optics | display json": '{"interfaces-diagnostics-optics-information": [{"physical-interface": [{"name": [{"data": "xe-0/1/0"}], "optics-diagnostics": {"laser-output-power-dbm": [{"data": "-2.10"}], "laser-rx-optical-power-dbm": [{"data": "-3.40"}], "module-temperature": [{"data": "32"}], "module-voltage": [{"data": "3.30"}]}}]}]}',
    }.get(cmd, "")

    poe = driver.get_poe(mock_conn)
    assert poe["total_power_watts"] == 740.0
    assert poe["used_power_watts"] == 120.0
    assert "ge-0/0/1" in poe["ports"]

    macs = driver.get_mac_table(mock_conn)
    assert len(macs) == 1
    assert macs[0]["mac"] == "00:11:22:33:44:55"
    assert macs[0]["interface"] == "ge-0/0/1"  # .0 stripped!

    optics = driver.get_optics(mock_conn)
    assert len(optics) == 1
    assert optics[0]["port"] == "xe-0/1/0"
    assert optics[0]["tx_power_dbm"] == -2.1
    assert optics[0]["rx_power_dbm"] == -3.4


def test_arista_driver_poe_mac_optics():
    driver = AristaDriver(ip="192.168.1.253")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show power inline | json": '{"powerSummary": {"totalPower": 740.0, "usedPower": 150.0, "availablePower": 590.0}, "interfaces": {"Ethernet1": {"operState": "delivering", "power": 15.4, "class": "3"}}}',
        "show mac address-table | json": '{"unicastTable": {"tableEntries": [{"vlanId": 20, "macAddress": "0011.2233.4455", "entryType": "dynamic", "interface": "Ethernet1"}]}}',
        "show interfaces transceiver | json": '{"interfaces": {"Ethernet1": {"vendorName": "Arista Networks", "vendorPartNumber": "SFP-10G-SR", "txPower": -2.1, "rxPower": -3.4, "temperature": 31.5, "voltage": 3.28}}}',
    }.get(cmd, "")

    poe = driver.get_poe(mock_conn)
    assert poe["total_power_watts"] == 740.0
    assert poe["used_power_watts"] == 150.0
    assert "Ethernet1" in poe["ports"]

    macs = driver.get_mac_table(mock_conn)
    assert len(macs) == 1
    assert macs[0]["mac"] == "00:11:22:33:44:55"
    assert macs[0]["interface"] == "Ethernet1"

    optics = driver.get_optics(mock_conn)
    assert len(optics) == 1
    assert optics[0]["port"] == "Ethernet1"
    assert optics[0]["part_number"] == "SFP-10G-SR"
    assert optics[0]["tx_power_dbm"] == -2.1
    assert optics[0]["rx_power_dbm"] == -3.4


def test_hpprocurve_driver_parsing():
    driver = HPProCurveDriver(ip="192.168.1.220")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = lambda cmd: {
        "show system": """
 Status and Counters - General System Information

  System Name        : SW-2920-24G
  Software revision  : WB.16.10.0025        Base MAC Addr      : 3863bb-57ca40
  ROM Version        : WB.16.03             Serial Number      : SG51FLXB59
""",
        "show modules": """
 Status and Counters - Module Information

  Chassis: 2920-24G-PoE+  J9727A         Serial Number:   SG51FLXB59
""",
        "show ip": """
Internet (IP) Service

                       |                                            Proxy ARP
  VLAN                 | IP Config  IP Address      Subnet Mask     Std  Local
  -------------------- + ---------- --------------- --------------- ----------
  DEFAULT_VLAN         | Manual     192.168.1.220   255.255.255.0    No    No
""",
        "show interfaces brief": """
 Status and Counters - Port Status

                          | Intrusion                           MDI  Flow Bcast
  Port         Type       | Alert     Enabled Status Mode       Mode Ctrl Limit
  ------------ ---------- + --------- ------- ------ ---------- ---- ---- -----
  1            100/1000T  | No        Yes     Down   1000FDx    Auto off  0
  23           100/1000T  | No        Yes     Up     1000FDx    MDI  off  0
""",
        "show lldp info remote-device": """
 LLDP Remote Devices Information

  LocalPort | ChassisId          PortId             PortDescr SysName
  --------- + ------------------ ------------------ --------- ------------------
  23        | fc 33 42 e6 b5 99  522                ge-0/0/8  desktop-switch....
  23        | MikroTik           ether1                       MikroTik
""",
        "show ip route": """
IP Route Entries

  Destination        Gateway         VLAN Type      Sub-Type   Metric     Dist.
  ------------------ --------------- ---- --------- ---------- ---------- -----
  0.0.0.0/0          192.168.1.1     1    static               1          1
  192.168.1.0/24     DEFAULT_VLAN    1    connected            1          0
""",
        "show arp": """
 IP ARP table

  IP Address       MAC Address       Type    Port
  ---------------  ----------------- ------- ----
  192.168.1.1      bc2411-b4a982     dynamic 23
""",
        "show mac-address": """
Status and Counters - Port Address Table

  MAC Address   Port  VLAN
  ------------- ----- ----
  345a60-6191c7 23    1
""",
        "show spanning-tree": """
Multiple Spanning Tree (MST) Information

  STP Enabled   : No
""",
    }.get(cmd, "")

    ver = driver.get_version(mock_conn)
    assert ver["hostname"] == "SW-2920-24G"
    assert ver["model"] == "HP 2920-24G-PoE+"
    assert ver["serial"] == "SG51FLXB59"
    assert ver["firmware"] == "WB.16.10.0025"
    assert ver["mac_address"] == "38:63:bb:57:ca:40"

    l3, details = driver.get_interfaces(mock_conn)
    assert len(l3) == 1
    assert l3[0]["ip_address"] == "192.168.1.220/24"
    assert "23" in details
    assert details["23"]["status"] == "up"
    assert details["23"]["speed"] == "1Gb/s"

    neighbors = driver.get_neighbors(mock_conn)
    assert len(neighbors) == 2
    assert neighbors[0]["local_port"] == "23"
    assert neighbors[0]["remote_port"] == "ge-0/0/8"

    routes = driver.get_routing_table(mock_conn)
    assert len(routes) == 2
    assert routes[0]["subnet"] == "0.0.0.0/0"
    assert routes[0]["next_hop"] == "192.168.1.1"

    arp = driver.get_arp_table(mock_conn)
    assert len(arp) == 1
    assert arp[0]["ip"] == "192.168.1.1"
    assert arp[0]["mac"] == "bc:24:11:b4:a9:82"

    macs = driver.get_mac_table(mock_conn)
    assert len(macs) == 1
    assert macs[0]["mac"] == "34:5a:60:61:91:c7"

    stp = driver.get_stp(mock_conn)
    assert stp["enabled"] is False


def test_safe_netmiko_connect_fallback():
    mock_connect = MagicMock()
    # First call raises IncompatiblePeer / algorithm mismatch, second succeeds
    mock_connect.side_effect = [
        Exception("Incompatible ssh peer (no acceptable kex algorithm)"),
        MagicMock(base_prompt="SW#"),
    ]

    with patch("netmiko.ConnectHandler", mock_connect):
        from net_docu_crawler.drivers.base import BaseDriver

        dev_params = {"device_type": "hp_procurve", "ip": "10.0.0.1"}
        conn = BaseDriver.safe_netmiko_connect(dev_params)
        assert conn.base_prompt == "SW#"
        assert mock_connect.call_count == 2
        # Verify fallback params were passed
        fallback_call_args = mock_connect.call_args[1]
        assert fallback_call_args["disabled_algorithms"] == {}
        assert fallback_call_args["disable_sha2_fix"] is True
        assert fallback_call_args["ssh_strict"] is False


def test_crawl_target_stops_retrying_ssh_drivers_on_transport_error():
    from net_docu_crawler.crawler import crawl_target_with_ports

    def _make_mock_driver(name):
        cls = MagicMock()
        cls.__name__ = name
        inst = MagicMock()
        inst.connect.side_effect = Exception("Incompatible ssh peer (no acceptable host key)")
        cls.return_value = inst
        return cls, inst

    cisco_cls, cisco_inst = _make_mock_driver("CiscoDriver")
    arista_cls, arista_inst = _make_mock_driver("AristaDriver")
    juniper_cls, juniper_inst = _make_mock_driver("JuniperDriver")
    fortinet_cls, fortinet_inst = _make_mock_driver("FortinetDriver")

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("unknown", "")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch("net_docu_crawler.crawler.CiscoDriver", cisco_cls),
        patch("net_docu_crawler.crawler.AristaDriver", arista_cls),
        patch("net_docu_crawler.crawler.JuniperDriver", juniper_cls),
        patch("net_docu_crawler.crawler.FortinetDriver", fortinet_cls),
    ):
        result = crawl_target_with_ports(
            ip="10.29.0.152",
            credentials=[{"username": "admin", "password": "pw"}],
            open_ports=[(22, "ssh")],
        )
        assert result["status"] == "unsupported"
        assert cisco_inst.connect.call_count == 1
        assert arista_inst.connect.call_count == 0
        assert juniper_inst.connect.call_count == 0
        assert fortinet_inst.connect.call_count == 0


def test_validate_credentials_dedups_and_flags_errors(tmp_path):
    from net_docu_crawler.crawler import load_and_validate_credentials, validate_credentials

    entries = [
        {"name": "C1", "vendor": "cisco", "username": "admin", "password": "pw1", "secret": "pw1"},
        {"name": "C1-Dup", "vendor": "cisco", "username": "admin", "password": "pw1", "secret": "pw1"},
        {"name": "BadVendor", "vendor": "unknown_os", "username": "admin", "password": "pw2"},
        {"name": "NoUser", "vendor": "cisco", "username": "", "password": "pw3"},
        {"name": "IntPass", "vendor": "cisco", "username": "admin", "password": 1234},
    ]
    valid, warnings, errors = validate_credentials(entries, source="test.json")
    assert len(valid) == 2
    assert any("duplicate of 'C1'" in w for w in warnings)
    assert any("unknown vendor tag 'unknown_os'" in w for w in warnings)
    assert len(errors) == 2

    bad_json = tmp_path / "bad.json"
    bad_json.write_text('[{"username": "admin",]', encoding="utf-8")
    v_bad, _, err_bad = load_and_validate_credentials(str(bad_json))
    assert v_bad == []
    assert any("Invalid JSON" in e for e in err_bad)

    missing_v, _, err_missing = load_and_validate_credentials(str(tmp_path / "missing.json"))
    assert missing_v == []
    assert any("not found" in e for e in err_missing)


def test_infer_vendor_from_http_and_crestron_skip():
    from net_docu_crawler.crawler import crawl_target_with_ports
    from net_docu_crawler.drivers.detector import detect_vendor_range, infer_vendor_from_http

    assert infer_vendor_from_http({"title": "FortiGate", "server": "xxxxxxxx", "cert_cn": ""}) == "fortinet"
    assert infer_vendor_from_http({"title": "", "server": "", "cert_cn": "FGT60FTK21000001"}) == "fortinet"
    assert infer_vendor_from_http({"title": "Cisco Small Business SG350", "server": "", "cert_cn": ""}) == "ciscosmb"

    with patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-CrestronSSH"):
        cand, _ = detect_vendor_range("10.29.0.131", mac="")
        assert cand == "unsupported_appliance"

    cisco_cls = MagicMock()
    with (
        patch(
            "net_docu_crawler.crawler.detect_vendor_range",
            return_value=("unsupported_appliance", "SSH-2.0-CrestronSSH"),
        ),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch("net_docu_crawler.crawler.CiscoDriver", cisco_cls),
    ):
        res = crawl_target_with_ports(
            ip="10.29.0.131",
            credentials=[{"username": "admin", "password": "pw"}],
            open_ports=[(22, "ssh")],
        )
        assert res["status"] == "unsupported"
        assert cisco_cls.call_count == 0


def test_vendor_hint_and_http_fallback_avoid_cisco_on_fortigate():
    from net_docu_crawler.crawler import crawl_target_with_ports

    cisco_cls = MagicMock()
    fg_cls = MagicMock()
    fg_cls.__name__ = "FortinetDriver"
    fg_inst = MagicMock()
    fg_inst.connect.return_value = MagicMock()
    fg_inst.crawl.return_value = {"hostname": "FG-01", "ip": "10.29.0.1", "device_type": "firewall"}
    fg_cls.return_value = fg_inst

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("unknown", "SSH-2.0-8cCW9hKGiHPMf")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch(
            "net_docu_crawler.crawler.probe_http_fingerprint",
            return_value={"title": "FortiGate", "server": "xxxxxxxx", "cert_cn": "FGT60FTK0001"},
        ),
        patch("net_docu_crawler.crawler.CiscoDriver", cisco_cls),
        patch.dict("net_docu_crawler.crawler.VENDOR_DRIVER_MAP", {"fortinet": fg_cls}),
    ):
        res = crawl_target_with_ports(
            ip="10.29.0.1",
            credentials=[{"username": "admin", "password": "pw", "vendor": "fortinet"}],
            open_ports=[(22, "ssh")],
            http_fingerprint=True,
        )
        assert res["hostname"] == "FG-01"
        assert cisco_cls.call_count == 0
        assert fg_inst.connect.call_count == 1


def test_strict_vendor_credential_scoping_skips_unrelated_vendors():
    from net_docu_crawler.crawler import crawl_target_with_ports

    tried_users = []
    fg_cls = MagicMock()
    fg_cls.__name__ = "FortinetDriver"

    def _make_inst(**kwargs):
        tried_users.append((kwargs["username"], kwargs["password"]))
        inst = MagicMock()
        inst.connect.side_effect = Exception("Authentication to device failed.")
        return inst

    fg_cls.side_effect = _make_inst

    creds = [
        {"name": "Cisco-1", "vendor": "cisco", "username": "cisco_u", "password": "pw"},
        {"name": "HP-1", "vendor": "hpprocurve", "username": "manager", "password": "pw"},
        {"name": "FG-1", "vendor": "fortinet", "username": "fg_admin", "password": "fg_pw"},
        {"name": "Generic-1", "username": "site_admin", "password": "site_pw"},
    ]

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("fortinet", "SSH-2.0-FortiSSH")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
        patch.dict("net_docu_crawler.crawler.VENDOR_DRIVER_MAP", {"fortinet": fg_cls}),
    ):
        res = crawl_target_with_ports(
            ip="10.29.0.1",
            credentials=creds,
            open_ports=[(22, "ssh")],
        )
        assert res["status"] == "unauthenticated"
        assert tried_users == [("fg_admin", "fg_pw"), ("site_admin", "site_pw")]


def test_all_10_drivers_session_log_and_interface():
    drivers = [
        CiscoDriver(ip="10.0.0.1", session_log="/tmp/test.log"),
        JuniperDriver(ip="10.0.0.2", session_log="/tmp/test.log"),
        AristaDriver(ip="10.0.0.3", session_log="/tmp/test.log"),
        ArubaDriver(ip="10.0.0.4", session_log="/tmp/test.log"),
        FortinetDriver(ip="10.0.0.5", session_log="/tmp/test.log"),
        PaloAltoDriver(ip="10.0.0.6", session_log="/tmp/test.log"),
        MikroTikDriver(ip="10.0.0.7", session_log="/tmp/test.log"),
        OpenWrtDriver(ip="10.0.0.8", session_log="/tmp/test.log"),
        OPNsenseDriver(ip="10.0.0.9", session_log="/tmp/test.log"),
        FRRDriver(ip="10.0.0.10", session_log="/tmp/test.log"),
        HPProCurveDriver(ip="10.0.0.11", session_log="/tmp/test.log"),
    ]
    assert len(drivers) == 11
    for d in drivers:
        assert d.session_log == "/tmp/test.log"
        assert callable(d.connect)
        assert callable(d.crawl)
        assert callable(d.get_optics)
        assert callable(d.get_poe)
        assert callable(d.get_mac_table)


def test_probe_tcp_port_and_scan_subnet_ports():
    from net_docu_crawler.drivers.detector import probe_tcp_port, scan_subnet_ports

    def fake_socket(*_args, **_kwargs):
        sock = MagicMock()
        sock.connect_ex.side_effect = lambda addr: 0 if addr in {("10.0.0.1", 2222), ("10.0.0.2", 23)} else 111
        return sock

    with patch("net_docu_crawler.drivers.detector.socket.socket", side_effect=fake_socket):
        assert probe_tcp_port("10.0.0.1", 2222) is True
        assert probe_tcp_port("10.0.0.1", 22) is False
        res = scan_subnet_ports(
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            ssh_ports=[22, 2222],
            telnet_ports=[23],
            max_workers=4,
        )
        assert res["10.0.0.1"] == [(2222, "ssh")]
        assert res["10.0.0.2"] == [(23, "telnet")]
        assert "10.0.0.3" not in res


def test_get_telnet_banner_strips_iac_and_detects_vendor():
    from net_docu_crawler.drivers.detector import detect_vendor_range, get_telnet_banner

    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b"\xff\xfd\x18\xff\xfd\x1f",
        b"ProCurve Switch 2920-24G\r\nUsername: ",
    ]

    with patch("net_docu_crawler.drivers.detector.socket.socket", return_value=mock_sock):
        banner = get_telnet_banner("10.0.0.50", port=23, timeout=1.0)
        assert "ProCurve" in banner
        assert "\xff" not in banner

    with (
        patch("net_docu_crawler.drivers.detector.get_telnet_banner", return_value="ProCurve Switch 2920-24G"),
        patch("net_docu_crawler.drivers.detector.get_mac_from_system_arp", return_value=""),
    ):
        vendor, b = detect_vendor_range("10.0.0.50", port=23, transport="telnet")
        assert vendor == "hpprocurve"
        assert "ProCurve" in b


def test_base_driver_connect_netmiko_custom_port_and_telnet():
    mock_connect = MagicMock(return_value=MagicMock(base_prompt="SW#"))
    with patch("netmiko.ConnectHandler", mock_connect):
        drv_ssh = HPProCurveDriver(ip="10.0.0.1", username="admin", password="pw", port=2222, transport="ssh")
        drv_ssh.connect_netmiko({"device_type": "hp_procurve", "ip": "10.0.0.1"})
        assert mock_connect.call_args[1]["port"] == 2222
        assert mock_connect.call_args[1]["device_type"] == "hp_procurve"

        drv_telnet = HPProCurveDriver(ip="10.0.0.1", username="admin", password="pw", port=2323, transport="telnet")
        drv_telnet.connect_netmiko({"device_type": "hp_procurve", "ip": "10.0.0.1"})
        assert mock_connect.call_args[1]["port"] == 2323
        assert mock_connect.call_args[1]["device_type"] == "hp_procurve_telnet"

        # Reject Telnet when *_telnet is not in Netmiko CLASS_MAPPER (never silently fall back to generic_telnet)
        import pytest

        drv_fg = FortinetDriver(ip="10.0.0.2", username="admin", password="pw", port=23, transport="telnet")
        with pytest.raises(ValueError, match="Telnet transport is not supported"):
            drv_fg.connect_netmiko({"device_type": "fortinet", "ip": "10.0.0.2"})


def test_crawler_parse_target_specs_and_partial_inventory():
    from net_docu_crawler.crawler import (
        build_partial_device_record,
        crawl_target_with_ports,
        parse_target_specs,
    )

    ips, explicit = parse_target_specs(["192.168.1.10:2222", "192.168.1.20:23", "192.168.1.30"])
    assert ips == ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
    assert explicit["192.168.1.10"] == [(2222, "ssh")]
    assert explicit["192.168.1.20"] == [(23, "telnet")]
    assert "192.168.1.30" not in explicit

    partial = build_partial_device_record(
        ip="192.168.1.99",
        mac="38:63:bb:57:ca:40",
        vendor="unknown",
        banner="Synology DSM SSH",
        port=2222,
        transport="ssh",
        status="unsupported",
    )
    assert partial["status"] == "unsupported"
    assert partial["mgmt_method"] == "SSH:2222"
    assert partial["model"] == "Synology DSM SSH"

    with (
        patch("net_docu_crawler.crawler.detect_vendor_range", return_value=("cisco", "SSH-2.0-Cisco-1.25")),
        patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value="aa:bb:cc:dd:ee:ff"),
        patch.object(CiscoDriver, "connect", side_effect=Exception("Authentication failed")),
    ):
        rec = crawl_target_with_ports(
            "192.168.1.55",
            credentials=[{"username": "admin", "password": "wrong"}],
            open_ports=[(22, "ssh")],
        )
        assert rec is not None
        assert rec["status"] == "unauthenticated"
        assert rec["vendor"] == "cisco"
        assert rec["mgmt_method"] == "SSH"


def test_multi_credential_defaults_then_actual():
    import json
    from pathlib import Path

    from net_docu_crawler.crawler import crawl_target_with_ports

    example_path = Path(__file__).resolve().parent.parent / "credentials.example.json"
    default_creds = json.loads(example_path.read_text(encoding="utf-8"))

    # Verify example file includes multiple defaults for common vendors (including empty-password defaults)
    vendors_in_example = {c["vendor"] for c in default_creds}
    assert {"cisco", "hpprocurve", "juniper", "fortinet", "mikrotik", "opnsense"}.issubset(vendors_in_example)
    assert sum(1 for c in default_creds if c["vendor"] == "hpprocurve") >= 2
    assert sum(1 for c in default_creds if c["vendor"] == "cisco") >= 2
    assert any(c["password"] == "" for c in default_creds)

    actual_creds = [
        {
            "name": "Actual-Cisco",
            "vendor": "cisco",
            "username": "netadmin",
            "password": "real-cisco-pw",
            "secret": "real",
        },
        {"name": "Actual-HP", "vendor": "hpprocurve", "username": "admin", "password": "real-hp-pw"},
        {"name": "Actual-Juniper", "vendor": "juniper", "username": "root", "password": "real-junos-pw"},
        {"name": "Actual-FortiGate", "vendor": "fortinet", "username": "admin", "password": "real-forti-pw"},
        {"name": "Actual-MikroTik", "vendor": "mikrotik", "username": "admin", "password": "real-mt-pw"},
        {"name": "Actual-OPNsense", "vendor": "opnsense", "username": "root", "password": "real-opn-pw"},
    ]
    combined_creds = default_creds + actual_creds

    cases = [
        ("cisco", CiscoDriver, "10.0.1.10", ("netadmin", "real-cisco-pw")),
        ("hpprocurve", HPProCurveDriver, "10.0.1.11", ("admin", "real-hp-pw")),
        ("juniper", JuniperDriver, "10.0.1.12", ("root", "real-junos-pw")),
        ("fortinet", FortinetDriver, "10.0.1.13", ("admin", "real-forti-pw")),
        ("mikrotik", MikroTikDriver, "10.0.1.14", ("admin", "real-mt-pw")),
        ("opnsense", OPNsenseDriver, "10.0.1.15", ("root", "real-opn-pw")),
    ]

    for vendor_key, driver_cls, ip, expected_pair in cases:
        attempts: list[tuple[str, str]] = []

        def make_connect(expected=expected_pair, log_attempts=attempts):
            def _connect(self):
                log_attempts.append((self.username, self.password))
                if (self.username, self.password) == expected:
                    return MagicMock()
                raise Exception("Authentication failed.")

            return _connect

        expected_data = {
            "ip": ip,
            "status": "success",
            "mgmt_method": "SSH",
            "vendor": vendor_key,
            "hostname": f"host-{vendor_key}",
        }

        with (
            patch("net_docu_crawler.crawler.detect_vendor_range", return_value=(vendor_key, "")),
            patch("net_docu_crawler.crawler.get_mac_from_system_arp", return_value=""),
            patch.object(driver_cls, "connect", make_connect()),
            patch.object(driver_cls, "crawl", return_value=expected_data),
        ):
            result = crawl_target_with_ports(ip, combined_creds, open_ports=[(22, "ssh")])
            assert result is not None
            assert result["status"] == "success"
            assert result["hostname"] == f"host-{vendor_key}"
            # Must have tried multiple defaults before succeeding on the actual (last) credential
            assert len(attempts) >= 2
            assert attempts[-1] == expected_pair


def test_detect_local_subnets_and_default_ssh_2222():
    from net_docu_crawler.crawler import detect_local_subnets
    from net_docu_crawler.drivers.detector import scan_host_ports

    fake_ip_out = (
        "2: enp8s0    inet 192.168.50.10/24 brd 192.168.50.255 scope global enp8s0\n"
        "4: docker0   inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
        "5: virbr0    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0\n"
    )
    mock_proc = MagicMock(returncode=0, stdout=fake_ip_out)
    with (
        patch("net_docu_crawler.crawler.sys.platform", "linux"),
        patch("net_docu_crawler.crawler.subprocess.run", return_value=mock_proc),
    ):
        assert detect_local_subnets() == ["192.168.50.0/24"]

    # Default scan_host_ports checks [22] for SSH and [23] for Telnet; explicit ssh_ports=[22, 2222] checks both
    probed = []

    def fake_probe(ip, port, timeout=0.8):
        probed.append((ip, port))
        return port == 2222

    with patch("net_docu_crawler.drivers.detector.probe_tcp_port", side_effect=fake_probe):
        default_res = scan_host_ports("10.0.0.5")
        assert ("10.0.0.5", 22) in probed
        assert ("10.0.0.5", 2222) not in probed
        assert ("10.0.0.5", 23) in probed
        assert default_res == []

        probed.clear()
        res = scan_host_ports("10.0.0.5", ssh_ports=[22, 2222])
        assert ("10.0.0.5", 22) in probed
        assert ("10.0.0.5", 2222) in probed
        assert ("10.0.0.5", 23) in probed
        assert res == [(2222, "ssh")]


def test_arp_inventory_http_fingerprint_and_snmp_probe():
    from net_docu_crawler.crawler import build_partial_device_record
    from net_docu_crawler.drivers.detector import _ber_tlv, probe_http_fingerprint, probe_snmp_sysinfo

    arp_rec = build_partial_device_record(
        ip="192.168.1.77",
        mac="38:63:bb:57:ca:40",
        port=0,
        transport="arp",
        status="discovered",
    )
    assert arp_rec["mgmt_method"] == "ARP/OUI"
    assert arp_rec["status"] == "discovered"

    # HTTP fingerprint
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n<html><title>Synology DiskStation</title></html>",
        b"",
    ]
    with (
        patch("net_docu_crawler.drivers.detector.probe_tcp_port", side_effect=lambda ip, p, timeout=0.7: p == 80),
        patch("net_docu_crawler.drivers.detector.socket.socket", return_value=mock_sock),
    ):
        fp = probe_http_fingerprint("192.168.1.77")
        assert fp is not None
        assert fp["port"] == 80
        assert fp["scheme"] == "http"
        assert fp["server"] == "nginx/1.24"
        assert fp["title"] == "Synology DiskStation"

    # SNMPv2c sysDescr / sysName
    fake_snmp_resp = _ber_tlv(
        0x30,
        _ber_tlv(0x02, b"\x01")
        + _ber_tlv(0x04, b"public")
        + _ber_tlv(
            0xA2,
            _ber_tlv(0x04, b"HP J9727A 2920-24G-PoE+ Switch") + _ber_tlv(0x04, b"SW-2920-24G"),
        ),
    )
    mock_udp = MagicMock()
    mock_udp.recvfrom.return_value = (fake_snmp_resp, ("192.168.1.220", 161))
    with patch("net_docu_crawler.drivers.detector.socket.socket", return_value=mock_udp):
        info = probe_snmp_sysinfo("192.168.1.220", community="public")
        assert info == {"sysDescr": "HP J9727A 2920-24G-PoE+ Switch", "sysName": "SW-2920-24G"}


def test_extract_followable_subnets_wan_boundary_and_overrides():
    from net_docu_crawler.crawler import extract_followable_subnets

    devices = [
        {
            "ip": "192.168.1.1",
            "l3_interfaces": [
                {"interface": "igc0", "ip_address": "100.64.224.70/19"},  # CGNAT WAN
                {"interface": "igc1", "ip_address": "192.168.1.1/24"},
                {"interface": "igc2", "ip_address": "192.168.10.1/24"},
                {"interface": "igc3", "ip_address": "8.8.8.1/24"},  # Public IP
            ],
            "routes": [
                {"subnet": "0.0.0.0/0", "next_hop": "100.64.224.1"},
                {"subnet": "172.16.1.0/24", "next_hop": "192.168.1.254"},
                {"subnet": "10.0.0.0/8", "next_hop": "192.168.1.254"},  # Too broad (/8)
            ],
        }
    ]

    # Default: strictly RFC 1918 and /22../30
    default_subnets = extract_followable_subnets(devices)
    assert set(default_subnets) == {"192.168.1.0/24", "192.168.10.0/24", "172.16.1.0/24"}

    # CGNAT override (min_prefix=19 to allow /19 CGNAT)
    cgnat_subnets = extract_followable_subnets(devices, allow_cgnat=True, min_prefix=19)
    assert "100.64.224.0/19" in cgnat_subnets
    assert "8.8.8.0/24" not in cgnat_subnets

    # Public ISP override
    public_subnets = extract_followable_subnets(devices, allow_public=True, min_prefix=19)
    assert "8.8.8.0/24" in public_subnets
    assert "100.64.224.0/19" in public_subnets


def test_migration_parsers_port_profiles_routing_fhrp_and_dhcp():
    from net_docu_crawler.migration_parsers import (
        extract_dhcp_config,
        extract_firewall_nat_vpn,
        extract_port_profiles,
        extract_routing_peers_and_fhrp_from_config,
    )

    cisco_cfg = """
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
 switchport voice vlan 20
 spanning-tree bpduguard enable
 authentication port-control auto
 channel-group 1 mode active
!
interface GigabitEthernet0/24
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,99
!
interface Vlan10
 ip address 192.168.10.2 255.255.255.0
 standby 10 ip 192.168.10.1
 standby 10 priority 110
 ip helper-address 192.168.1.5
!
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
!
router ospf 1
 network 192.168.10.0 0.0.0.255 area 0
!
ip dhcp pool CORP_DATA
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 dns-server 192.168.1.5
!
"""
    profiles = extract_port_profiles(
        cisco_cfg,
        vendor="Cisco",
        poe={"ports": {"GigabitEthernet0/1": {"power_watts": 12.4}}},
    )
    assert profiles["GigabitEthernet0/1"]["mode"] == "access"
    assert profiles["GigabitEthernet0/1"]["access_vlan"] == "10"
    assert profiles["GigabitEthernet0/1"]["voice_vlan"] == "20"
    assert profiles["GigabitEthernet0/1"]["bpdu_guard"] is True
    assert profiles["GigabitEthernet0/1"]["dot1x_mab"] is True
    assert profiles["GigabitEthernet0/1"]["lag_group"] == "Po1"
    assert profiles["GigabitEthernet0/1"]["poe_watts"] == 12.4
    assert profiles["GigabitEthernet0/24"]["mode"] == "trunk"
    assert profiles["GigabitEthernet0/24"]["trunk_allowed_vlans"] == "10,20,99"

    peers, fhrp = extract_routing_peers_and_fhrp_from_config(cisco_cfg, vendor="Cisco")
    assert any(p["protocol"] == "bgp" and p["remote_as"] == "65002" for p in peers)
    assert any(p["protocol"] == "ospf" and p["area"] == "0" for p in peers)
    assert any(f["protocol"] == "hsrp" and f["vip"] == "192.168.10.1" and f["priority"] == 110 for f in fhrp)

    dhcp = extract_dhcp_config(cisco_cfg, vendor="Cisco")
    assert any(p["name"] == "CORP_DATA" and p["gateway"] == "192.168.10.1" for p in dhcp["pools"])
    assert any(r["interface"] == "Vlan10" and r["helper_ip"] == "192.168.1.5" for r in dhcp["relays"])

    opn_xml = """<opnsense>
      <dhcpd><lan><range><from>192.168.1.100</from><to>192.168.1.200</to></range>
      <staticmap><mac>aa:bb:cc:dd:ee:ff</mac><ipaddr>192.168.1.50</ipaddr><hostname>nas</hostname></staticmap>
      </lan></dhcpd>
      <virtualip><vip><mode>carp</mode><vhid>1</vhid><interface>lan</interface><subnet>192.168.1.1</subnet><advskew>0</advskew></vip></virtualip>
      <filter><rule><type>pass</type><interface>lan</interface><protocol>tcp</protocol><source><network>lan</network></source><destination><network>any</network><port>443</port></destination><descr>Allow HTTPS</descr></rule></filter>
    </opnsense>"""
    opn_dhcp = extract_dhcp_config(opn_xml, vendor="OPNsense")
    assert opn_dhcp["pools"][0]["range"] == "192.168.1.100-192.168.1.200"
    assert opn_dhcp["reservations"][0]["hostname"] == "nas"
    _, opn_fhrp = extract_routing_peers_and_fhrp_from_config(opn_xml, vendor="OPNsense")
    assert opn_fhrp[0]["protocol"] == "carp"
    sec = extract_firewall_nat_vpn(opn_xml, vendor="OPNsense")
    assert sec["firewall_rules"][0]["dst_port"] == "443"


def test_hpprocurve_poe_and_optics():
    driver = HPProCurveDriver(ip="192.168.1.220")
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = [
        "Total Available Power : 370 W\nTotal Power Drawn : 45.2 W\n 1 | Yes High 4 15.2 W\n",
        " 23   SFP-SX   J4858C   Present\n 24   SFP+SR   J9150A   Present\n",
    ]
    poe = driver.get_poe(mock_conn)
    assert poe["total_power_watts"] == 370.0
    assert poe["used_power_watts"] == 45.2
    assert poe["ports"]["1"]["power_watts"] == 15.2

    optics = driver.get_optics(mock_conn)
    assert len(optics) == 2
    assert optics[0]["type"] == "SFP-SX"
    assert optics[1]["part_number"] == "J9150A"


def test_ciscosmb_driver_parsing_and_detection():
    from net_docu_crawler.drivers import CiscoSMBDriver, get_driver
    from net_docu_crawler.drivers.detector import detect_vendor_range

    with (
        patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-Cisco-SG300-28P"),
        patch("net_docu_crawler.drivers.detector.get_mac_from_system_arp", return_value=""),
    ):
        vendor, _ = detect_vendor_range("10.0.2.10")
        assert vendor == "ciscosmb"

    drv = get_driver("10.0.2.10", vendor_hint="ciscosmb")
    assert isinstance(drv, CiscoSMBDriver)

    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = [
        "System Description: SG300-28P 28-Port Gigabit PoE Managed Switch\nSystem Name: SW-SMB-01\nSystem MAC Address: 00:11:22:33:44:55\n",
        "Unit Model: SG300-28P\nSerial Number: DNI18120ABC\n",
        "SW version: 1.4.11.5\n",
        "192.168.1.210/24  vlan 1  Static\n",
        "gi1   1G-Copper   Full  1000  Enabled  Off  Up   Disabled On\ngi2   1G-Copper   --    --    Enabled  Off  Down Disabled Off\n",
        "gi28  aa:bb:cc:dd:ee:ff  ge-0/0/1  CORE-SW  B,R  120\n",
        "C   192.168.1.0/24 is directly connected, vlan 1\nS   0.0.0.0/0 [1/0] via 192.168.1.1, vlan 1\n",
        "vlan 1   gi1   192.168.1.1   00:90:0b:11:22:33   Dynamic\n",
        "Spanning tree enabled mode RSTP\nThis bridge is the root\n",
        "Available (W): 180.0\nConsumed (W): 15.4\ngi1  Enabled  High  15.4  Class3\n",
        "1  aa:bb:cc:dd:ee:01  gi1  dynamic\n",
        "gi27  OK  SFP\n",
        "hostname SW-SMB-01\ninterface gi1\n switchport mode access\n switchport access vlan 10\n",
    ]
    data = drv.crawl(mock_conn)
    assert data["hostname"] == "SW-SMB-01"
    assert data["model"] == "SG300-28P"
    assert data["serial"] == "DNI18120ABC"
    assert data["firmware"] == "1.4.11.5"
    assert data["mac_address"] == "00:11:22:33:44:55"
    assert data["l3_interfaces"][0]["ip_address"] == "192.168.1.210/24"
    assert data["interfaces_detail"]["gi1"]["speed"] == "1Gb/s"
    assert data["neighbors"][0]["remote_device"] == "CORE-SW"
    assert data["stp"]["enabled"] is True
    assert data["stp"]["is_root"] is True
    assert data["poe"]["used_power_watts"] == 15.4
    assert data["optics"][0]["port"] == "gi27"
    assert data["port_profiles"]["gi1"]["access_vlan"] == "10"


def test_windows_subnet_and_arp_fallbacks():
    from net_docu_crawler.crawler import detect_local_subnets
    from net_docu_crawler.drivers.detector import get_arp_table_entries

    ipconfig_out = (
        "Ethernet adapter Ethernet:\n"
        "   IPv4 Address. . . . . . . . . . . : 10.20.30.15\n"
        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
    )
    with (
        patch("net_docu_crawler.crawler.sys.platform", "win32"),
        patch("net_docu_crawler.crawler.subprocess.run", return_value=MagicMock(returncode=0, stdout=ipconfig_out)),
    ):
        assert detect_local_subnets() == ["10.20.30.0/24"]

    arp_out = (
        "Interface: 10.20.30.15 --- 0x5\n"
        "  Internet Address      Physical Address      Type\n"
        "  10.20.30.1            00-11-22-33-44-55     dynamic\n"
        "  224.0.0.22            01-00-5e-00-00-16     static\n"
    )
    with (
        patch("net_docu_crawler.drivers.detector.os.path.exists", return_value=False),
        patch("net_docu_crawler.drivers.detector.sys.platform", "win32"),
        patch("net_docu_crawler.drivers.detector.subprocess.check_output", return_value=arp_out),
    ):
        entries = get_arp_table_entries()
        assert entries == {"10.20.30.1": "00:11:22:33:44:55"}


def test_frr_driver_plain_linux_server_fallback():
    """Verify FRRDriver safely collects read-only host facts when vtysh is absent."""
    from net_docu_crawler.drivers.frr import FRRDriver

    drv = FRRDriver("10.29.55.50", "admin", "pass")
    mock_conn = MagicMock()

    def _send_cmd(cmd, **kwargs):
        if cmd == "hostname -s":
            return "debian-app-01\n"
        if cmd == "vtysh -c 'show version'":
            return "bash: vtysh: command not found\n"
        if cmd == "cat /etc/os-release":
            return 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\n'
        if cmd == "ip -j link show":
            return '[{"ifname": "lo", "operstate": "UNKNOWN", "address": "00:00:00:00:00:00"}, {"ifname": "eth0", "operstate": "UP", "address": "bc:24:11:aa:bb:cc"}]'
        if cmd == "ip -j -4 addr show":
            return '[{"ifname": "eth0", "addr_info": [{"local": "10.29.55.50", "prefixlen": 24}]}]'
        if cmd == "lldpcli show neighbors -f json":
            return "bash: lldpcli: command not found\n"
        if cmd == "ip -j route show":
            return '[{"dst": "default", "gateway": "10.29.55.1", "dev": "eth0", "protocol": "dhcp"}]'
        if cmd == "ip -j neigh show":
            return '[{"dst": "10.29.55.1", "lladdr": "b4:b2:e9:4e:7d:31", "dev": "eth0"}]'
        raise AssertionError(f"Unexpected command on plain Linux host: {cmd}")

    mock_conn.send_command.side_effect = _send_cmd
    data = drv.crawl(mock_conn)
    assert data["hostname"] == "debian-app-01"
    assert data["device_type"] == "server"
    assert data["device_persona"] == "host"
    assert "Debian GNU/Linux 13" in data["model"]
    assert data["l3_interfaces"][0]["ip_address"] == "10.29.55.50/24"
    assert data["routes"][0]["subnet"] == "0.0.0.0/0"
    assert data["raw_config"] == ""


def test_ssh_banner_strips_kexinit_and_detects_ciscosmb():
    """Verify get_ssh_banner strips binary KEXINIT bytes and detects OpenSSH_7.3p1.RL / GoAhead-Webs."""
    from net_docu_crawler.drivers.detector import (
        detect_vendor_range,
        get_ssh_banner,
        infer_vendor_from_http,
    )

    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"SSH-2.0-dropbear_2024.86\r\n\x00\x00\x01\xd4\x05\x14\xab\xcdssh-rsa"
    with patch("net_docu_crawler.drivers.detector.socket.socket", return_value=mock_sock):
        assert get_ssh_banner("10.29.55.51") == "SSH-2.0-dropbear_2024.86"

    assert (
        infer_vendor_from_http({"port": 443, "scheme": "https", "server": "GoAhead-Webs", "title": "", "cert_cn": ""})
        == "ciscosmb"
    )

    with (
        patch("net_docu_crawler.drivers.detector.oui_lookup.lookup_oui", return_value="Cisco Systems, Inc"),
        patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-OpenSSH_7.3p1.RL"),
    ):
        vendor, banner = detect_vendor_range("10.29.0.152", mac="5c:e1:76:a2:b2:1d", transport="ssh")
        assert vendor == "ciscosmb"
        assert banner == "SSH-2.0-OpenSSH_7.3p1.RL"


def test_cisco_driver_merges_cdp_mac_with_lldp_system_name():
    """Verify CiscoDriver upgrades MAC-only CDP Device IDs using LLDP System Name without duplicate edges."""
    from net_docu_crawler.drivers.cisco import CiscoDriver

    cdp_out = (
        "-------------------------\n"
        "Device ID: 5ce176a2c372\n"
        "Entry address(es):\n"
        "  IP address: 10.29.55.13\n"
        "Platform: Cisco SG250-26HP (PID:SG250-26HP-K9)-VS,  Capabilities: Router Switch IGMP\n"
        "Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): gi26\n"
        "-------------------------\n"
        "Device ID: 2c73a0368d71\n"
        "Entry address(es):\n"
        "  IP address: 10.29.55.10\n"
        "Platform: Cisco SG250X-48 (PID:SG250X-48-K9)-VSD,  Capabilities: Router Switch IGMP\n"
        "Interface: GigabitEthernet1/0/3,  Port ID (outgoing port): te3\n"
    )
    lldp_out = (
        "------------------------------------------------\n"
        "Chassis id: 5ce1.76a2.c372\n"
        "Port id: gi26\n"
        "System Name: genshaft-sw-rm13\n"
        "Management Addresses:\n"
        "    IP: 10.29.55.13\n"
        "------------------------------------------------\n"
        "Chassis id: 2c73.a036.8d71\n"
        "Port id: te3\n"
        "System Name: genshaft-sw-100\n"
        "Management Addresses:\n"
        "    IP: 10.29.55.10\n"
    )
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = [cdp_out, lldp_out]
    drv = CiscoDriver("10.29.55.15", "admin", "pass")
    neighbors = drv.get_neighbors(mock_conn)
    assert len(neighbors) == 2
    assert neighbors[0]["local_port"] == "GigabitEthernet1/0/2"
    assert neighbors[0]["remote_device"] == "genshaft-sw-rm13"
    assert neighbors[1]["local_port"] == "GigabitEthernet1/0/3"
    assert neighbors[1]["remote_device"] == "genshaft-sw-100"


def test_detector_skips_windows_openssh_and_fortinet_ignores_auth_prompts():
    """Verify Windows OpenSSH banners are skipped and FortinetDriver rejects auth-prompt words as hostnames."""
    from net_docu_crawler.drivers.detector import detect_vendor_range
    from net_docu_crawler.drivers.fortinet import FortinetDriver

    with patch("net_docu_crawler.drivers.detector.get_ssh_banner", return_value="SSH-2.0-OpenSSH_for_Windows_7.7"):
        vendor, _ = detect_vendor_range("10.29.25.35", transport="ssh")
        assert vendor == "unsupported_appliance"

    mock_conn = MagicMock()
    mock_conn.send_command.return_value = "authentication failed\n"
    mock_conn.find_prompt.return_value = "Password:"
    drv = FortinetDriver("10.29.25.34", "admin", "pass")
    ver = drv.get_version(mock_conn)
    assert ver["hostname"] == ""


def test_non_network_appliance_classification_and_retry_failed(tmp_path):
    """Verify casting-diag appliance classification and failed_hosts.json / --retry-failed filtering."""
    from net_docu_crawler.crawler import build_partial_device_record, crawl_network
    from net_docu_crawler.drivers.detector import classify_non_network_appliance

    assert classify_non_network_appliance(open_app_ports=[7236]) == ("display", "Miracast / Airtame Display")
    assert classify_non_network_appliance(open_app_ports=[7000]) == ("display", "Apple AirPlay Display")
    assert classify_non_network_appliance(open_app_ports=[8008]) == ("display", "Google Cast Display")
    assert classify_non_network_appliance(
        vendor_oui="Hangzhou Hikvision Digital Technology Co.,Ltd.",
        http_fp={"server": "App-webs/"},
        open_app_ports=[554],
    ) == ("camera", "Hikvision IP Camera")

    rec = build_partial_device_record(
        ip="10.29.0.131",
        mac="00:10:7f:c2:e2:ec",
        vendor="unsupported_appliance",
        banner="SSH-2.0-CrestronSSH",
        status="unsupported",
    )
    assert rec["device_type"] == "av_control"
    assert rec["model"] == "Crestron AV Controller"

    failed_file = tmp_path / "failed_hosts.json"
    failed_file.write_text(
        '[{"ip": "10.29.55.51", "status": "unauthenticated"}, {"ip": "10.29.0.131", "status": "unsupported"}]',
        encoding="utf-8",
    )
    creds_file = tmp_path / "creds.json"
    creds_file.write_text('[{"name": "admin", "username": "admin", "password": "pw"}]', encoding="utf-8")

    with (
        patch("net_docu_crawler.crawler.scan_subnet_ports", return_value={}) as mock_scan,
        patch("net_docu_crawler.crawler.get_arp_table_entries", return_value={}),
    ):
        crawl_network(
            targets=["10.29.0.1/23"],
            credentials_path=[str(creds_file)],
            output_dir=str(tmp_path / "out"),
            organize=False,
            retry_failed=str(failed_file),
        )
        mock_scan.assert_called_once()
        assert mock_scan.call_args[0][0] == ["10.29.55.51"]
        assert (tmp_path / "out" / "failed_hosts.json").exists()


def test_juniper_junos9_text_fallbacks():
    """Verify JuniperDriver falls back cleanly on Junos 9.x where '| display json' is unsupported."""
    from net_docu_crawler.drivers.juniper import JuniperDriver

    drv = JuniperDriver("10.10.0.10", "netops", "pass")
    mock_conn = MagicMock()

    def _send_cmd(cmd, **kwargs):
        if "| display json" in cmd:
            return "syntax error, expecting <command>.\n"
        if cmd == "show version":
            return "Hostname: ex4200-core-01\nModel: ex4200-48p\nJUNOS Base OS boot [9.6R3.8]\n"
        if cmd == "show chassis hardware":
            return "Hardware inventory:\nItem             Version  Part number  Serial number     Description\nChassis                                BM0209123456      EX4200-48P\n"
        if cmd == "show chassis mac-addresses":
            return "MAC address information:\n  Public base address     00:23:9c:aa:bb:00\n"
        if cmd == "show interfaces terse":
            return (
                "ge-0/0/0                up    up\n"
                "ge-0/0/0.0              up    up   eth-switch\n"
                "vlan.10                 up    up   inet     10.10.10.1/24\n"
                "lo0.0                   up    up   inet     127.0.0.1\n"
            )
        if cmd == "show lldp neighbors detail":
            return (
                "Local Interface: ge-0/0/1.0\n"
                "Chassis id: 00:0b:86:11:22:33\n"
                "Port id: eth0\n"
                "System capabilities: WLAN Access Point\n"
                "Management address: 10.10.10.50\n"
            )
        if cmd == "show spanning-tree bridge":
            return "STP bridge parameters\nEnabled protocol: RSTP\nRoot ID: 32768.00:23:9c:aa:bb:00\nBridge ID: 32768.00:23:9c:aa:bb:00\n"
        if cmd == "show route table inet.0":
            return (
                "0.0.0.0/0          *[Static/5] 10w0d 00:00:00\n"
                "                    > to 10.10.10.254 via vlan.10\n"
                "10.10.10.0/24      *[Direct/0] 10w0d 00:00:00\n"
                "                    > via vlan.10\n"
            )
        if cmd == "show arp no-resolve":
            return "00:0b:86:11:22:33 10.10.10.50     10.10.10.50               vlan.10              none\n"
        if cmd == "show poe controller":
            return "Controller  Maximum power  Power consumed  Available power\n0           400.0W         15.4W           384.6W\n"
        if cmd == "show poe interface":
            return "ge-0/0/1    Enabled   ON     15.4W    Class3\n"
        if cmd == "show ethernet-switching table":
            return "default           00:0b:86:11:22:33  Learn          0 ge-0/0/1.0\n"
        if cmd == "show interfaces diagnostics optics":
            return ""
        if cmd == "show configuration | display set":
            return "set system host-name ex4200-core-01\nset system name-server 10.10.10.2\n"
        return ""

    mock_conn.send_command.side_effect = _send_cmd
    data = drv.crawl(mock_conn)
    assert data["hostname"] == "ex4200-core-01"
    assert data["model"] == "ex4200-48p"
    assert data["firmware"] == "9.6R3.8"
    assert data["serial"] == "BM0209123456"
    assert data["mac_address"] == "00:23:9c:aa:bb:00"
    assert data["l3_interfaces"][0]["ip_address"] == "10.10.10.1/24"
    assert data["stp"]["enabled"] is True
    assert data["stp"]["is_root"] is True
    assert data["neighbors"][0]["local_port"] == "ge-0/0/1"
    assert data["neighbors"][0]["remote_ip"] == "10.10.10.50"
    assert len(data["routes"]) == 2
    assert data["routes"][0]["subnet"] == "0.0.0.0/0"
    assert data["routes"][0]["next_hop"] == "10.10.10.254"
    assert data["arp_table"][0]["ip"] == "10.10.10.50"
    assert data["poe"]["used_power_watts"] == 15.4
    assert data["services"]["dns_servers"] == ["10.10.10.2"]


def test_transceiver_serials_and_link_errors_across_drivers():
    """Verify transceiver type/part/serial extraction and link error counters across drivers."""
    from net_docu_crawler.drivers.aruba import ArubaDriver
    from net_docu_crawler.drivers.cisco import CiscoDriver
    from net_docu_crawler.drivers.fortinet import FortinetDriver
    from net_docu_crawler.drivers.juniper import JuniperDriver
    from net_docu_crawler.drivers.mikrotik import MikroTikDriver

    # Cisco: show inventory + show interfaces transceiver
    cisco_conn = MagicMock()
    cisco_conn.send_command.side_effect = [
        'NAME: "Gi1/0/12", DESCR: "1000BASE-SX SFP"\nPID: GLC-SX-MMD        , VID: V01  , SN: FNS18120999\n',
        "Port   Temp   Voltage   Current   Optical Tx Power   Optical Rx Power\nGi1/0/12  34.2   3.30      5.1       -4.50              -5.20\n",
    ]
    c_opt = CiscoDriver("10.0.0.1", "u", "p").get_optics(cisco_conn)
    assert len(c_opt) == 1
    assert c_opt[0]["part_number"] == "GLC-SX-MMD"
    assert c_opt[0]["serial"] == "FNS18120999"
    assert c_opt[0]["rx_power_dbm"] == -5.20

    # Juniper: show chassis hardware (Xcvr) + show interfaces diagnostics optics + show interfaces errors
    j_conn = MagicMock()
    j_conn.send_command.side_effect = [
        "syntax error\n",
        "ge-0/0/0 up up\n",
        "Physical interface: ge-0/0/0, Enabled, Physical link is Up\n  Input errors: 4, Output errors: 1\n",
        "syntax error\n",
        "FPC 0\n  PIC 0\n    Xcvr 0       REV 01   740-021308   FNS99887766       SFP+-10G-SR\n",
        "syntax error\n",
        "Physical interface: xe-0/0/0\n  Laser output power : 0.300 mW / -5.20 dBm\n  Laser rx optical power : 0.250 mW / -6.00 dBm\n",
    ]
    j_drv = JuniperDriver("10.0.0.2", "u", "p")
    _, j_detail = j_drv.get_interfaces(j_conn)
    assert j_detail["ge-0/0/0"]["input_errors"] == 4
    assert j_detail["ge-0/0/0"]["output_errors"] == 1
    j_opt = j_drv.get_optics(j_conn)
    assert len(j_opt) == 1
    assert j_opt[0]["part_number"] == "740-021308"
    assert j_opt[0]["serial"] == "FNS99887766"
    assert j_opt[0]["rx_power_dbm"] == -6.00

    # Fortinet, MikroTik, Aruba optics
    f_conn = MagicMock()
    f_conn.send_command.return_value = (
        "Interface port15 - SFP/SFP+\n  Vendor Name : FINISAR\n  Part No. : FTLX8574D3BCL\n  Serial No. : FNS112233\n"
    )
    assert FortinetDriver("10.0.0.3", "u", "p").get_optics(f_conn)[0]["serial"] == "FNS112233"

    m_conn = MagicMock()
    m_conn.send_command.return_value = "name: sfp-sfpplus1\n  sfp-vendor-name: MikroTik\n  sfp-vendor-part-number: S+85DLC03D\n  sfp-vendor-serial: MT123456\n  sfp-rx-power: -3.4\n"
    assert MikroTikDriver("10.0.0.4", "u", "p").get_optics(m_conn)[0]["serial"] == "MT123456"

    a_conn = MagicMock()
    a_conn.send_command.return_value = (
        "Transceiver in 1/1/49\n  Type : SFP+SR\n  Part Number : J9150D\n  Serial Number : AR998877\n"
    )
    assert ArubaDriver("10.0.0.5", "u", "p").get_optics(a_conn)[0]["serial"] == "AR998877"


def test_workflow_improvements(tmp_path):
    """Verify HTTP title sanitization, neighbor IP extraction, ARP MAC lookup, retry-failed merge, and infra filtering."""
    import json

    from net_docu_crawler.crawler import _sanitize_http_model_label, crawl_network, extract_neighbor_ips
    from net_docu_crawler.topology_resolver import DeviceRegistry
    from report_generator import generate_bom_hardware_sizing, generate_l2_diagram, generate_l3_diagram

    assert _sanitize_http_model_label({"title": "index.html", "server": "webserver"}) == ""
    assert _sanitize_http_model_label({"title": "113c8d7f23ad525e42fdc1ab2a14803d"}) == ""
    assert _sanitize_http_model_label({"title": "401 Authorization Required"}) == ""
    assert _sanitize_http_model_label({"title": "EX2200-24P-4G Web UI"}) == "EX2200-24P-4G Web UI"

    reg = DeviceRegistry()
    reg.register_device(
        {
            "hostname": "GEN-FW-01",
            "ip": "10.29.0.1",
            "serial": "FW123",
            "mac_address": "00:09:0f:09:00:01",
            "arp_table": [{"ip": "10.29.55.10", "mac": "00:23:9c:aa:bb:cc"}],
        }
    )
    assert reg.get_arp_mac("10.29.55.10") == "00:23:9c:aa:bb:cc"

    nbr_ips = extract_neighbor_ips(
        [
            {
                "status": "success",
                "neighbors": [
                    {
                        "remote_device": "sw-01",
                        "remote_ip": "",
                        "remote_mac": "00:23:9c:aa:bb:cc",
                        "device_type": "switch",
                    },
                    {"remote_device": "ap-01", "remote_ip": "10.29.55.90", "device_type": "ap"},
                    {"remote_device": "sw-02", "remote_ip": "10.29.55.12", "device_type": "switch"},
                ],
            }
        ],
        registry=reg,
    )
    assert nbr_ips == ["10.29.55.10", "10.29.55.12"]

    # Retry-failed merge preserves prior success devices from sibling dataset
    run_dir = tmp_path / "prior_run"
    run_dir.mkdir()
    (run_dir / "net_docu_crawler_dataset.json").write_text(
        json.dumps(
            [
                {
                    "hostname": "GEN-FW-01",
                    "ip": "10.29.0.1",
                    "vendor": "Fortinet",
                    "model": "FortiGate-100F",
                    "serial": "FG100F01",
                    "mac_address": "00:09:0f:09:00:01",
                    "device_type": "firewall",
                    "status": "success",
                    "l3_interfaces": [{"interface": "port1", "ip_address": "10.29.0.1/23", "status": "up"}],
                    "interfaces_detail": {"port1": {"status": "up"}},
                }
            ]
        ),
        encoding="utf-8",
    )
    failed_file = run_dir / "failed_hosts.json"
    failed_file.write_text(json.dumps([{"ip": "10.29.55.51", "status": "unauthenticated"}]), encoding="utf-8")
    creds_file = tmp_path / "creds.json"
    creds_file.write_text('[{"name": "admin", "username": "admin", "password": "pw"}]', encoding="utf-8")

    with (
        patch("net_docu_crawler.crawler.scan_subnet_ports", return_value={}),
        patch("net_docu_crawler.crawler.get_arp_table_entries", return_value={}),
    ):
        merged = crawl_network(
            targets=["10.29.0.1/23"],
            credentials_path=[str(creds_file)],
            output_dir=str(tmp_path / "merged_out"),
            organize=False,
            retry_failed=str(failed_file),
        )
        assert any(d.get("hostname") == "GEN-FW-01" and d.get("status") == "success" for d in merged)

    # Infra-only filtering in L2, L3, and BOM
    sample_devs = {
        "10.29.0.1": {
            "hostname": "GEN-FW-01",
            "ip": "10.29.0.1",
            "vendor": "Fortinet",
            "model": "FortiGate-100F",
            "device_type": "firewall",
            "status": "success",
            "l3_interfaces": [{"interface": "port1", "ip_address": "10.29.0.1/23", "status": "up"}],
            "interfaces_detail": {"port1": {"status": "up"}},
            "neighbors": [],
        },
        "10.29.0.33": {
            "hostname": "10.29.0.33",
            "ip": "10.29.0.33",
            "vendor": "Hikvision",
            "model": "Camera",
            "device_type": "camera",
            "status": "unsupported",
            "l3_interfaces": [],
            "interfaces_detail": {},
            "neighbors": [],
        },
    }
    l2_path = tmp_path / "L2.md"
    l3_path = tmp_path / "L3.md"
    bom_path = tmp_path / "bom.csv"
    generate_l2_diagram(sample_devs, str(l2_path))
    generate_l3_diagram(sample_devs, str(l3_path))
    generate_bom_hardware_sizing(sample_devs, str(bom_path))

    assert "10.29.0.33" not in l2_path.read_text(encoding="utf-8")
    assert "10.29.0.33" not in l3_path.read_text(encoding="utf-8")
    assert "10.29.0.33" not in bom_path.read_text(encoding="utf-8")
    assert "GEN-FW-01" in bom_path.read_text(encoding="utf-8")


def test_offline_dataset_render_and_arp_guided_subnets(tmp_path):
    """Verify connected-only subnet extraction, ARP-guided hop selection, offline --from-dataset, and session log sanitization."""
    import json

    from net_docu_crawler.crawler import (
        _select_hop_targets_for_cidrs,
        extract_followable_subnets,
        render_from_dataset_file,
    )
    from net_docu_crawler.topology_resolver import DeviceRegistry

    devs = [
        {
            "hostname": "GEN-FW-01",
            "ip": "10.29.0.1",
            "vendor": "Fortinet",
            "model": "FortiGate-100F",
            "serial": "FG100F01",
            "mac_address": "00:09:0f:09:00:01",
            "device_type": "firewall",
            "status": "success",
            "l3_interfaces": [{"interface": "port1", "ip_address": "10.29.55.1/24", "status": "up"}],
            "routes": [{"subnet": "10.99.0.0/24", "protocol": "Static", "next_hop": "10.29.0.254", "interface": "wan"}],
            "arp_table": [{"ip": "10.29.55.10", "mac": "00:23:9c:aa:bb:cc"}],
            "interfaces_detail": {"port1": {"status": "up"}},
            "neighbors": [],
            "raw_config": "enable secret 5 $1$secretHash\n",
        }
    ]
    assert extract_followable_subnets(devs, include_routes=False) == ["10.29.55.0/24"]
    assert extract_followable_subnets(devs, include_routes=True) == ["10.29.55.0/24", "10.99.0.0/24"]

    reg = DeviceRegistry()
    reg.register_device(devs[0])
    hop_targets = _select_hop_targets_for_cidrs(["10.29.55.0/24"], reg, {"10.29.0.1"})
    assert hop_targets == ["10.29.55.10"]

    ds_dir = tmp_path / "site_run"
    logs_dir = ds_dir / "logs"
    logs_dir.mkdir(parents=True)
    ds_file = ds_dir / "net_docu_crawler_dataset.json"
    ds_file.write_text(json.dumps(devs), encoding="utf-8")
    sess_log = logs_dir / "10.29.0.1_raw_session.log"
    sess_log.write_text("GEN-FW-01# show run\nenable secret 5 $1$secretHash\n", encoding="utf-8")

    render_from_dataset_file(str(ds_file), sanitize_passwords=True)
    assert (ds_dir / "Network_Analysis.md").exists()
    assert (ds_dir / "L2_network_diagrams.md").exists()
    assert "<REDACTED_SECRET>" in sess_log.read_text(encoding="utf-8")
    assert "$1$secretHash" not in sess_log.read_text(encoding="utf-8")


def test_fortinet_spaces_alias_vlan_and_lldp_fallback():
    from net_docu_crawler.drivers.fortinet import FortinetDriver

    class MockFortiConn:
        def send_command(self, cmd):
            if cmd == "show system interface":
                return (
                    "config system interface\n"
                    '    edit "GS VoIP"\n'
                    "        set ip 10.29.25.1 255.255.255.0\n"
                    '        set alias "VoIP VLAN"\n'
                    "        set vlanid 25\n"
                    "    next\n"
                    '    edit "naf.1"\n'
                    "        set ip 169.254.0.1 255.255.255.252\n"
                    "    next\n"
                    "end\n"
                )
            if cmd == "get router info routing-table all":
                return "C       10.29.25.0/24 is directly connected, GS VoIP\n"
            if cmd == "get system arp":
                return "10.29.25.10 0 aa:bb:cc:dd:ee:ff GS VoIP\n"
            if cmd == "diagnose snmp sysinfo lldp neighbor":
                return "command parse error before 'sysinfo'\nReturn code -61\n"
            if cmd == "diagnose lldp neighbor list":
                return (
                    "Port: lan1\n"
                    "  Chassis ID: 00:11:22:33:44:55\n"
                    "  System Name: genshaft-sw-mdf02\n"
                    "  Port ID: Gi1/0/48\n"
                    "  System Description: Cisco IOS\n"
                )
            return ""

    drv = FortinetDriver("10.29.0.1")
    conn = MockFortiConn()
    l3, detail = drv.get_interfaces(conn)
    assert l3 == [{"interface": "GS VoIP", "ip_address": "10.29.25.1 255.255.255.0", "status": "up", "protocol": "up"}]
    assert "GS VoIP" in detail
    assert detail["GS VoIP"]["description"] == "VoIP VLAN"
    assert detail["GS VoIP"]["vlan"] == 25
    assert "naf.1" not in detail

    routes = drv.get_routing_table(conn)
    assert routes[0]["interface"] == "GS VoIP"

    arp = drv.get_arp_table(conn)
    assert arp[0]["interface"] == "GS VoIP"

    nbrs = drv.get_neighbors(conn)
    assert len(nbrs) == 1
    assert nbrs[0]["local_port"] == "lan1"
    assert nbrs[0]["remote_device"] == "genshaft-sw-mdf02"


def test_fortios_dhcp_config_and_reservation_enrichment():
    from net_docu_crawler.crawler import enrich_devices_from_dhcp_reservations
    from net_docu_crawler.migration_parsers import extract_dhcp_config

    raw_cfg = (
        "config system dhcp server\n"
        "    edit 1\n"
        "        set dns-server1 10.29.0.1\n"
        "        set default-gateway 10.29.0.1\n"
        "        set netmask 255.255.254.0\n"
        '        set interface "internal"\n'
        "        config ip-range\n"
        "            edit 1\n"
        "                set start-ip 10.29.0.50\n"
        "                set end-ip 10.29.1.250\n"
        "            next\n"
        "        end\n"
        "        config reserved-address\n"
        "            edit 1\n"
        "                set ip 10.29.0.10\n"
        "                set mac 00:11:22:33:44:55\n"
        '                set description "wlc01"\n'
        "            next\n"
        "        end\n"
        "    next\n"
        "    edit 2\n"
        "        set status disable\n"
        '        set interface "guest"\n'
        "    next\n"
        "end\n"
    )
    dhcp = extract_dhcp_config(raw_cfg, vendor="Fortinet")
    assert len(dhcp["pools"]) == 1
    assert dhcp["pools"][0]["network"] == "10.29.0.0/23"
    assert dhcp["pools"][0]["range"] == "10.29.0.50-10.29.1.250"
    assert dhcp["reservations"] == [
        {"mac": "00:11:22:33:44:55", "ip": "10.29.0.10", "hostname": "wlc01", "pool": "internal"}
    ]

    devs = [
        {"hostname": "GEN-FW-01", "ip": "10.29.0.1", "status": "success", "dhcp": dhcp},
        {"hostname": "10.29.0.10", "ip": "10.29.0.10", "mac_address": "00:11:22:33:44:55", "status": "discovered"},
    ]
    enrich_devices_from_dhcp_reservations(devs)
    assert devs[1]["hostname"] == "wlc01"
    assert devs[1]["canonical_hostname"] == "wlc01"


def test_cisco_default_gateway_and_prefix_backfill():
    import parser as cli_parser
    from net_docu_crawler.drivers.cisco import CiscoDriver

    routes = cli_parser.parse_show_ip_route("Default gateway is 10.29.55.1\n", "cisco_ios")
    assert any(r["subnet"] == "0.0.0.0/0" and r["next_hop"] == "10.29.55.1" for r in routes)

    class MockCiscoConn:
        def send_command(self, cmd):
            if cmd == "show ip interface brief":
                return (
                    "Interface              IP-Address      OK? Method Status                Protocol\n"
                    "Vlan55                 10.29.55.15     YES NVRAM  up                    up\n"
                )
            if cmd == "show interfaces":
                return (
                    "Vlan55 is up, line protocol is up\n"
                    "  Hardware is EtherSVI, address is aabb.ccdd.eeff (bia aabb.ccdd.eeff)\n"
                    "  Internet address is 10.29.55.15/25\n"
                )
            return ""

    l3, _ = CiscoDriver("10.29.55.15").get_interfaces(MockCiscoConn())
    assert l3[0]["ip_address"] == "10.29.55.15/25"


def test_reparse_logs_dir(tmp_path):
    import json

    from net_docu_crawler.crawler import reparse_logs_dir

    run_dir = tmp_path / "prod_run"
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(parents=True)

    # Existing dataset has a discovered AP and a misclassified auth-failure stub
    (run_dir / "net_docu_crawler_dataset.json").write_text(
        json.dumps(
            [
                {"ip": "10.29.55.15", "hostname": "old", "vendor": "cisco_ios", "status": "success"},
                {"ip": "10.29.55.12", "hostname": "authentication", "vendor": "fortinet", "status": "success"},
                {"ip": "10.29.0.10", "hostname": "10.29.0.10", "status": "discovered"},
            ]
        ),
        encoding="utf-8",
    )
    (logs_dir / "10.29.55.12_raw_session.log").write_text("Password: \nLogin failed\n", encoding="utf-8")
    (logs_dir / "10.29.55.15_raw_session.log").write_text(
        "sw-mdf#show version\n"
        "Cisco IOS Software, C2960X Software, Version 15.2(7)E2\n"
        "sw-mdf uptime is 1 day\n"
        "Model number                    : WS-C2960X-48FPS-L\n"
        "System serial number            : FCW1234A5BC\n"
        "sw-mdf#show ip interface brief\n"
        "Vlan55                 10.29.55.15     YES NVRAM  up                    up\n"
        "sw-mdf#show interfaces\n"
        "Vlan55 is up, line protocol is up\n"
        "  Internet address is 10.29.55.15/25\n"
        "sw-mdf#show ip route\n"
        "Default gateway is 10.29.55.1\n"
        "sw-mdf#show running-config\n"
        "hostname sw-mdf\n",
        encoding="utf-8",
    )

    out = reparse_logs_dir(str(run_dir))
    by_ip = {d["ip"]: d for d in out}
    assert by_ip["10.29.55.15"]["l3_interfaces"][0]["ip_address"] == "10.29.55.15/25"
    assert any(r["subnet"] == "0.0.0.0/0" for r in by_ip["10.29.55.15"]["routes"])
    assert by_ip["10.29.55.12"]["status"] == "unauthenticated"
    assert by_ip["10.29.0.10"]["status"] == "discovered"


def test_hpprocurve_vt100_escape_cleaning():
    from net_docu_crawler.drivers.hpprocurve import HPProCurveDriver, _CleanProCurveConn

    class RawVT100Conn:
        def send_command(self, cmd):
            if cmd == "show system":
                return (
                    "\x1b[2J\x1b[?7h\x1b[1;23r\x1b[?6l\x1b[1;1H\x1b[?25l"
                    "  System Name        : sw-core-5412\n"
                    "  Software revision  : K.16.02.0022m\n"
                    "  Serial Number      : SG12345678\n"
                    "  Base MAC Addr      : aabbcc-ddeeff\n"
                    "[24;1H"
                )
            if cmd == "show modules":
                return "\x1b[24;1HChassis: 5412zl J8698A Serial Number: SG12345678\n"
            return ""

        def find_prompt(self):
            return "\x1b[24;1Hsw-core-5412#"

    proxy = _CleanProCurveConn(RawVT100Conn())
    info = HPProCurveDriver("10.1.0.10").get_version(proxy)
    assert info["hostname"] == "sw-core-5412"
    assert info["firmware"] == "K.16.02.0022m"
    assert info["serial"] == "SG12345678"
    assert info["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert info["model"] == "HP 5412zl"
    assert proxy.find_prompt() == "sw-core-5412#"


def test_hpprocurve_ehttp_http_fingerprint():
    from net_docu_crawler.drivers.detector import infer_vendor_from_http

    assert infer_vendor_from_http({"port": 80, "scheme": "http", "server": "eHTTP v2.0", "title": ""}) == "hpprocurve"

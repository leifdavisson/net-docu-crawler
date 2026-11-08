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
    ]
    assert len(drivers) == 10
    for d in drivers:
        assert d.session_log == "/tmp/test.log"
        assert callable(d.connect)
        assert callable(d.crawl)
        assert callable(d.get_optics)
        assert callable(d.get_poe)
        assert callable(d.get_mac_table)

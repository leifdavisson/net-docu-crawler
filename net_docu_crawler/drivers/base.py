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
Abstract Base Driver for Net-Docu-Crawler multi-vendor discovery architecture.
Defines normalized device schema and interface contract across all network hardware platforms.
"""

import re
from abc import ABC, abstractmethod

from net_docu_crawler.drivers.detector import get_mac_from_system_arp


def extract_services_from_config(raw_config: str) -> dict:
    """
    Vendor-neutral configuration parser extracting configured DNS, NTP, RADIUS, TACACS+,
    DHCP Relay / IP Helper addresses, Syslog collectors, and SNMP trap endpoints
    from Cisco IOS/NX-OS/XR, Arista EOS, Junos (`display set`), OPNsense (`config.xml`),
    FortiOS, MikroTik RouterOS (`/export`), OpenWrt (`uci export`), and ArubaOS configurations.
    """
    services: dict[str, list[str]] = {
        "dns_servers": [],
        "ntp_servers": [],
        "radius_servers": [],
        "tacacs_servers": [],
        "dhcp_relays": [],
        "syslog_servers": [],
        "snmp_servers": [],
    }
    if not raw_config:
        return services

    # XML style (OPNsense / pfSense / PAN-OS)
    for m_dns in re.findall(r"<dnsserver>([^<\s]+)</dnsserver>", raw_config):
        services["dns_servers"].append(m_dns.strip())
    for m_ntp in re.findall(r"<timeservers>([^<]+)</timeservers>", raw_config):
        services["ntp_servers"].extend(s.strip() for s in m_ntp.split() if s.strip())
    for m_dhcp in re.findall(r"<dhcrelay>\s*<server>([^<\s]+)</server>", raw_config):
        services["dhcp_relays"].append(m_dhcp.strip())
    for m_sys in re.findall(r"<syslog_server>([^<\s]+)</syslog_server>", raw_config):
        services["syslog_servers"].append(m_sys.strip())

    in_forti_dns = False
    in_forti_ntp = False
    in_forti_syslog = False
    for raw_line in raw_config.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # FortiOS block tracking
        if line == "config system dns":
            in_forti_dns, in_forti_ntp, in_forti_syslog = True, False, False
            continue
        elif line == "config system ntp":
            in_forti_ntp, in_forti_dns, in_forti_syslog = True, False, False
            continue
        elif line in ("config log syslogd setting", "config log syslogd2 setting"):
            in_forti_syslog, in_forti_dns, in_forti_ntp = True, False, False
            continue
        elif line == "end":
            in_forti_dns = in_forti_ntp = in_forti_syslog = False
            continue

        if in_forti_dns:
            m_fg_dns = re.match(r"set\s+(?:primary|secondary)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m_fg_dns and m_fg_dns.group(1) != "0.0.0.0":
                services["dns_servers"].append(m_fg_dns.group(1))
        if in_forti_ntp:
            m_fg_ntp = re.match(r'set\s+server\s+"?([^"\s]+)"?', line)
            if m_fg_ntp:
                services["ntp_servers"].append(m_fg_ntp.group(1))
            if "set ntpsync enable" in line and not services["ntp_servers"]:
                services["ntp_servers"].append("fortiguard")
        if in_forti_syslog:
            m_fg_sys = re.match(r'set\s+server\s+"?([^"\s]+)"?', line)
            if m_fg_sys and m_fg_sys.group(1) not in ("0.0.0.0", ""):
                services["syslog_servers"].append(m_fg_sys.group(1))

        # FortiOS DHCP Relay
        m_fg_relay = re.match(r'set\s+(?:dhcp-relay-ip|ip)\s+"?(\d+\.\d+\.\d+\.\d+)"?', line)
        if m_fg_relay and ("relay" in line.lower() or "dhcp" in line.lower()):
            services["dhcp_relays"].append(m_fg_relay.group(1))

        # Cisco / Arista / FRR / Aruba CLI
        m_ios_dns = re.match(r"^(?:ip\s+name-server|name-server)\s+(.+)$", line)
        if m_ios_dns:
            for tok in m_ios_dns.group(1).split():
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok):
                    services["dns_servers"].append(tok)

        m_ios_ntp = re.match(r"^(?:ntp\s+server|ntp-server)\s+(?:vrf\s+\S+\s+)?(\S+)", line)
        if m_ios_ntp:
            services["ntp_servers"].append(m_ios_ntp.group(1))

        m_ios_relay = re.match(r"^(?:ip\s+helper-address|helper-address)\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
        if m_ios_relay:
            services["dhcp_relays"].append(m_ios_relay.group(1))

        m_ios_syslog = re.match(r"^(?:logging\s+host|logging\s+server)\s+(\S+)", line, re.IGNORECASE)
        if m_ios_syslog:
            services["syslog_servers"].append(m_ios_syslog.group(1))

        m_ios_snmp = re.match(r"^snmp-server\s+host\s+(\S+)", line, re.IGNORECASE)
        if m_ios_snmp:
            services["snmp_servers"].append(m_ios_snmp.group(1))

        m_rad = re.search(r"(?:radius-server|radius\s+server)\s+host\s+(\S+)", line)
        if m_rad:
            services["radius_servers"].append(m_rad.group(1))

        m_tac = re.search(r"(?:tacacs-server|tacacs\s+server)\s+host\s+(\S+)", line)
        if m_tac:
            services["tacacs_servers"].append(m_tac.group(1))

        # Junos `display set`
        m_junos_dns = re.match(r"^set\s+system\s+name-server\s+(\S+)", line)
        if m_junos_dns:
            services["dns_servers"].append(m_junos_dns.group(1))
        m_junos_ntp = re.match(r"^set\s+system\s+ntp\s+server\s+(\S+)", line)
        if m_junos_ntp:
            services["ntp_servers"].append(m_junos_ntp.group(1))
        m_junos_rad = re.match(r"^set\s+system\s+radius-server\s+(\S+)", line)
        if m_junos_rad:
            services["radius_servers"].append(m_junos_rad.group(1))
        m_junos_tac = re.match(r"^set\s+system\s+tacplus-server\s+(\S+)", line)
        if m_junos_tac:
            services["tacacs_servers"].append(m_junos_tac.group(1))
        m_junos_relay = re.match(
            r"^set\s+forwarding-options\s+(?:dhcp-relay|helpers)\s+.*?\s+(\d+\.\d+\.\d+\.\d+)$", line
        )
        if m_junos_relay:
            services["dhcp_relays"].append(m_junos_relay.group(1))
        m_junos_syslog = re.match(r"^set\s+system\s+syslog\s+host\s+(\S+)", line)
        if m_junos_syslog:
            services["syslog_servers"].append(m_junos_syslog.group(1))
        m_junos_snmp = re.match(r"^set\s+snmp\s+trap-group\s+\S+\s+targets\s+(\S+)", line)
        if m_junos_snmp:
            services["snmp_servers"].append(m_junos_snmp.group(1))

        # MikroTik RouterOS `/export compact`
        if "servers=" in line and ("/ip dns" in line or "set servers=" in line):
            m_mt_dns = re.search(r"servers=([0-9.,]+)", line)
            if m_mt_dns:
                services["dns_servers"].extend(s for s in m_mt_dns.group(1).split(",") if s)
        if "ntp" in line and ("servers=" in line or "address=" in line):
            m_mt_ntp = re.search(r"(?:servers|address)=([^\s\"']+)", line)
            if m_mt_ntp:
                services["ntp_servers"].extend(s for s in m_mt_ntp.group(1).split(",") if s)
        if "relay=" in line or "dhcp-relay" in line:
            m_mt_relay = re.search(r"relay=([0-9.]+)", line)
            if m_mt_relay:
                services["dhcp_relays"].append(m_mt_relay.group(1))

        # OpenWrt UCI (`uci export`)
        m_uci_ntp = re.match(r"^list\s+server\s+['\"]([^'\"]+)['\"]", line)
        if m_uci_ntp and ("ntp" in m_uci_ntp.group(1) or re.match(r"^\d+\.\d+\.\d+\.\d+$", m_uci_ntp.group(1))):
            services["ntp_servers"].append(m_uci_ntp.group(1))
        m_uci_dns = re.match(r"^(?:list|option)\s+dns\s+['\"]([^'\"]+)['\"]", line)
        if m_uci_dns:
            services["dns_servers"].extend(s for s in m_uci_dns.group(1).split() if s)

    for key in services:
        # Preserve order while deduplicating
        services[key] = list(dict.fromkeys(services[key]))

    return services


def sanitize_raw_config(raw_config: str) -> str:
    """
    Sanitizes sensitive security credentials, pre-shared keys, passwords, and secrets
    from raw device configuration files before export, ticketing, or publication.
    """
    if not raw_config:
        return ""
    sanitized = raw_config

    # Cisco / Arista / FRR enable secret & passwords (Type 0, 5, 7, 8, 9)
    sanitized = re.sub(
        r"((?:enable\s+secret|enable\s+password|password|secret)\s+(?:\d+\s+)?)[^\s\r\n]+",
        r"\1<REDACTED_SECRET>",
        sanitized,
        flags=re.IGNORECASE,
    )
    # Pre-shared keys (IPsec / IKE / BGP peer / OSPF authentication)
    sanitized = re.sub(
        r"((?:pre-shared-key|key|hex-key|wpa-passphrase|authentication-key)\s+(?:\d+\s+)?)[^\s\r\n]+",
        r"\1<REDACTED_KEY>",
        sanitized,
        flags=re.IGNORECASE,
    )
    # SNMP community strings
    sanitized = re.sub(
        r"(snmp-server\s+community\s+)[^\s\r\n]+",
        r"\1<REDACTED_COMMUNITY>",
        sanitized,
        flags=re.IGNORECASE,
    )
    # Junos encrypted-password and secret
    sanitized = re.sub(
        r'(encrypted-password\s+)"[^"\r\n]+"',
        r'\1"<REDACTED_HASH>"',
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r'(authentication-key\s+)"[^"\r\n]+"',
        r'\1"<REDACTED_KEY>"',
        sanitized,
        flags=re.IGNORECASE,
    )
    # XML tags (OPNsense / pfSense / PAN-OS)
    sanitized = re.sub(
        r"(<(?:password|pre-shared-key|secret|sharedsecret)>)[^<]+(</(?:password|pre-shared-key|secret|sharedsecret)>)",
        r"\1<REDACTED>\2",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


class BaseDriver(ABC):
    """Abstract base class that all vendor-specific network drivers must implement."""

    vendor_name: str = "Generic"
    device_persona: str = "switch"
    default_device_type: str = "switch"
    paging_cmd: str = ""

    def __init__(
        self,
        ip: str,
        username: str = "",
        password: str = "",
        secret: str = "",
        timeout: int = 10,
        session_log: str = "",
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
        self.timeout = timeout
        self.session_log = session_log

    @abstractmethod
    def connect(self):
        """Establishes an authenticated read-only session using the vendor-appropriate transport."""
        pass

    @abstractmethod
    def get_version(self, conn) -> dict:
        """
        Gathers system version, hardware model, serial number, and firmware.
        Returns: {"hostname": str, "model": str, "serial": str, "firmware": str, "os_type": str}
        """
        pass

    @abstractmethod
    def get_interfaces(self, conn) -> tuple[list, dict]:
        """
        Gathers Layer 3 interfaces (with CIDR prefix where available) and physical/logical port stats.
        Returns: (l3_interfaces: list[dict], interfaces_detail: dict[str, dict])
        """
        pass

    @abstractmethod
    def get_neighbors(self, conn) -> list[dict]:
        """
        Gathers CDP, LLDP, or MNDP neighbor topologies.
        Returns: list of {"local_port": str, "remote_device": str, "remote_port": str, "remote_ip": str, "platform": str, "device_type": str}
        """
        pass

    @abstractmethod
    def get_routing_table(self, conn) -> list[dict]:
        """
        Gathers routing table entries.
        Returns: list of {"subnet": str, "protocol": str, "next_hop": str, "interface": str}
        """
        pass

    @abstractmethod
    def get_arp_table(self, conn) -> list[dict]:
        """
        Gathers Layer 3 ARP entries.
        Returns: list of {"ip": str, "mac": str, "interface": str, "age": str, "type": str, "vendor": str}
        """
        pass

    @abstractmethod
    def get_running_config(self, conn) -> str:
        """Retrieves raw configuration backup without modifying device state."""
        pass

    def get_stp(self, conn) -> dict:
        """Optional hook for L2 switching platforms to report Spanning Tree state."""
        return {"enabled": False, "vlans": {}}

    def get_poe(self, conn) -> dict:
        """Optional hook for switches to gather Power over Ethernet (PoE) inline wattage."""
        return {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}

    def get_mac_table(self, conn) -> list[dict]:
        """Optional hook for switches to gather MAC address table forwarding entries."""
        return []

    def get_optics(self, conn) -> list[dict]:
        """Optional hook for switches/routers to gather optical transceiver (SFP/SFP+/QSFP) DOM telemetry."""
        return []

    def get_services(self, conn, raw_config: str = "") -> dict:
        """Optional hook to extract DNS, NTP, RADIUS, and TACACS+ infrastructure services."""
        return extract_services_from_config(raw_config)

    def crawl(self, conn) -> dict:
        """
        Template method executing the safe read-only discovery sequence.
        Returns normalized device data dictionary ready for reporting and diagram generation.
        """
        device_data = {
            "ip": self.ip,
            "status": "success",
            "mgmt_method": "SSH",
            "vendor": self.vendor_name,
            "device_persona": self.device_persona,
            "device_type": self.default_device_type,
            "hostname": "",
            "model": "",
            "serial": "",
            "firmware": "",
            "mac_address": "",
            "neighbors": [],
            "arp_table": [],
            "mac_table": [],
            "l3_interfaces": [],
            "interfaces_detail": {},
            "stp": {"enabled": False, "vlans": {}},
            "poe": {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}},
            "optics": [],
            "routes": [],
            "services": {},
            "raw_config": "",
        }

        # 1. Version & System Info
        ver = self.get_version(conn)
        device_data.update(ver)

        # 2. Interfaces
        l3_ints, ints_detail = self.get_interfaces(conn)
        device_data["l3_interfaces"] = l3_ints
        device_data["interfaces_detail"] = ints_detail

        # Extract base MAC if not already set
        if not device_data["mac_address"]:
            for intf in ints_detail.values():
                if intf.get("mac_address"):
                    device_data["mac_address"] = intf["mac_address"]
                    break

        if not device_data["mac_address"]:
            device_data["mac_address"] = get_mac_from_system_arp(self.ip)

        # 3. Topology Neighbors
        device_data["neighbors"] = self.get_neighbors(conn)

        # 4. Routing Table
        device_data["routes"] = self.get_routing_table(conn)

        # 5. ARP Table
        device_data["arp_table"] = self.get_arp_table(conn)

        # 6. Spanning Tree (L2 switching state)
        device_data["stp"] = self.get_stp(conn)

        # 7. Power over Ethernet (PoE) & MAC Address Forwarding Table
        device_data["poe"] = self.get_poe(conn)
        device_data["mac_table"] = self.get_mac_table(conn)

        # 8. Optical Transceiver & DOM Telemetry
        device_data["optics"] = self.get_optics(conn)

        # 9. Configuration Backup & Infrastructure Services
        device_data["raw_config"] = self.get_running_config(conn)
        device_data["services"] = self.get_services(conn, device_data["raw_config"])

        return device_data

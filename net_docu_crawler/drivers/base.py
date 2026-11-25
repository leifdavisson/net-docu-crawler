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

import inspect
import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from contextlib import contextmanager

from net_docu_crawler.drivers.detector import get_mac_from_system_arp

logger = logging.getLogger(__name__)

# Schema v2.1 collection telemetry vocabulary (shared with schema.py / report_generator.py)
COLLECTION_STATES: tuple[str, ...] = (
    "ok",
    "not_applicable",
    "not_collected",
    "command_failed",
    "parse_failed",
    "partial",
)

COLLECTION_SECTIONS: tuple[str, ...] = (
    "version",
    "interfaces",
    "neighbors",
    "routes",
    "arp",
    "mac_table",
    "stp",
    "poe",
    "optics",
    "running_config",
    "vlans",
    "port_profiles",
    "vrfs",
    "routing_peers",
    "fhrp",
    "dhcp",
    "services",
    "security_policy",
    "l2_operational",
    "discovery_protocols",
)

CLI_ERROR_MARKERS: tuple[str, ...] = (
    "% invalid input",
    "invalid input",
    "unrecognized command",
    "unknown command",
    "incomplete command",
    "ambiguous command",
    "command parse error",
    "% authorization failed",
    "authorization failed",
    "command fail",
    "syntax error",
)

PAGING_PROMPT_RE = re.compile(
    r"(?im)(?:^|\r|\n)\s*(?:--\s*more\s*--|<---+\s*more\s*---+>|---+\(more(?:\s+\d+%)?\)---+|--\s*\[q\s+quit\|d\s+dump)\s*$"
)

_WRITE_OR_CONFIG_CMD_RE = re.compile(
    r"(?i)(?:^|\n)\s*(?:conf(?:ig(?:ure)?)?\b|write\b|copy\b|commit\b|save\b|reload\b|reboot\b|"
    r"clear\b|delete\b|erase\b|request\b|uci\s+(?:set|commit|delete)\b|opkg\b|/system\s+reset\b)"
)

_LARGE_OUTPUT_CMD_TOKENS: tuple[str, ...] = (
    "running-config",
    "full-configuration",
    "show configuration",
    "show config",
    "/export",
    "uci export",
    "config.xml",
    "show interfaces",
    "show interface",
    "show mac",
    "show ethernet-switching",
    "show ip route",
    "show route",
    "show arp",
    "show vlan",
    "show tech",
)


def detect_paging_artifact(output: str) -> bool:
    """Return True when CLI output contains a pagination prompt (`--More--`, `<--- More --->`, etc.)."""
    if not isinstance(output, str) or not output:
        return False
    return bool(PAGING_PROMPT_RE.search(output))


_LINE_CLI_ERROR_RE = re.compile(
    r"(?im)^\s*(?:%\s*(?:invalid|unrecognized|unknown|incomplete|ambiguous|authorization|error)|"
    r"command\s+(?:parse\s+error|fail)|syntax\s+error|cli\s+error|-?(?:ba|da|a)?sh:\s+.*command\s+not\s+found)"
)


def detect_cli_error(output: str) -> str:
    """Return the first matched CLI error marker if `output` looks like a CLI rejection, else ''."""
    if not isinstance(output, str) or not output.strip():
        return ""
    lines = [ln for ln in output.splitlines() if ln.strip()]
    if len(lines) > 25:
        head_text = "\n".join(lines[:5]).lower()
        for marker in CLI_ERROR_MARKERS:
            if marker in head_text:
                return marker
        if m := _LINE_CLI_ERROR_RE.search("\n".join(lines[:15])):
            return m.group(0).strip().lower()
        return ""
    low = output.lower()
    for marker in CLI_ERROR_MARKERS:
        if marker in low:
            return marker
    return ""


def scrub_known_secrets(text: str, secrets: Iterable[str]) -> str:
    """Replace any non-empty literal secret values in `text` with `<REDACTED>`."""
    if not text:
        return ""
    out = str(text)
    for secret in secrets:
        if isinstance(secret, str) and secret:
            out = out.replace(secret, "<REDACTED>")
    return out


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

    # XML style (OPNsense / pfSense / PAN-OS legacy & MVC)
    for m_dns in re.findall(r"<dnsserver>([^<\s]+)</dnsserver>", raw_config):
        services["dns_servers"].append(m_dns.strip())
    for m_ntp in re.findall(r"<timeservers>([^<]+)</timeservers>", raw_config):
        services["ntp_servers"].extend(s.strip() for s in m_ntp.split() if s.strip())
    for m_dhcp in re.findall(r"<dhcrelay>[\s\S]*?<server>([^<]+)</server>", raw_config, flags=re.IGNORECASE):
        services["dhcp_relays"].extend(s.strip() for s in m_dhcp.split(",") if s.strip())
    for m_mvc_dhcp in re.findall(r"<DHCRelay>[\s\S]*?<destination\b[^>]*>[\s\S]*?<server>([^<]+)</server>", raw_config):
        services["dhcp_relays"].extend(s.strip() for s in m_mvc_dhcp.split(",") if s.strip())
    for m_sys in re.findall(r"<syslog_server>([^<\s]+)</syslog_server>", raw_config):
        services["syslog_servers"].append(m_sys.strip())
    for m_mvc_sys in re.finditer(r"<Syslog>[\s\S]*?</Syslog>", raw_config):
        for m_dest in re.finditer(r"<destination\b[^>]*>([\s\S]*?)</destination>", m_mvc_sys.group(0)):
            dbody = m_dest.group(1)
            m_en = re.search(r"<enabled>([^<]+)</enabled>", dbody)
            if m_en and m_en.group(1).strip().lower() in ("0", "false"):
                continue
            m_srv = re.search(r"<(?:server|hostname)>([^<\s]+)</(?:server|hostname)>", dbody)
            if m_srv and m_srv.group(1).strip():
                services["syslog_servers"].append(m_srv.group(1).strip())

    # Modern Cisco IOS-XE / NX-OS multi-line `radius server <NAME>` & `tacacs server <NAME>` stanzas
    for m_rblk in re.finditer(
        r"(?im)^radius\s+server\s+\S+\s*\r?\n((?:[ \t]+[^\r\n]+\r?\n?)+)",
        raw_config,
    ):
        for m_addr in re.finditer(r"\baddress\s+(?:ipv4|ipv6)\s+([^\s\r\n]+)", m_rblk.group(1), re.IGNORECASE):
            services["radius_servers"].append(m_addr.group(1).strip())
    for m_tblk in re.finditer(
        r"(?im)^tacacs\s+server\s+\S+\s*\r?\n((?:[ \t]+[^\r\n]+\r?\n?)+)",
        raw_config,
    ):
        for m_addr in re.finditer(r"\baddress\s+(?:ipv4|ipv6)\s+([^\s\r\n]+)", m_tblk.group(1), re.IGNORECASE):
            services["tacacs_servers"].append(m_addr.group(1).strip())

    # Aruba Instant / AOS-CX `wlan auth-server <name>\n ip <ip>`
    for m_ablk in re.finditer(
        r"(?im)^wlan\s+auth-server\s+\S+\s*\r?\n((?:[ \t]*[^\r\n]+\r?\n?)+)",
        raw_config,
    ):
        for aln in m_ablk.group(1).splitlines():
            s_aln = aln.strip()
            if not s_aln or s_aln == "!":
                break
            m_aip = re.match(r"^ip\s+(\d+\.\d+\.\d+\.\d+)\b", s_aln, re.IGNORECASE)
            if m_aip:
                services["radius_servers"].append(m_aip.group(1))
                break

    # Juniper Junos hierarchical brace-style `system { ... }` and `snmp { ... }`
    if "system {" in raw_config or "snmp {" in raw_config:
        for m_ns_blk in re.finditer(r"\bname-server\s*\{([^}]*)\}", raw_config):
            for m_ip in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\s*;", m_ns_blk.group(1)):
                services["dns_servers"].append(m_ip.group(1))
        for m_ntp_blk in re.finditer(r"\bntp\s*\{([^}]*)\}", raw_config):
            for m_srv in re.finditer(r"\bserver\s+([^\s;{}]+)", m_ntp_blk.group(1)):
                services["ntp_servers"].append(m_srv.group(1))
        for m_sys_host in re.finditer(r"\bsyslog\s*\{[\s\S]*?\bhost\s+([^\s;{}]+)\s*\{", raw_config):
            services["syslog_servers"].append(m_sys_host.group(1))
        for m_rad_blk in re.finditer(r"\bradius-server\s*\{([\s\S]*?)\n\s*\}", raw_config):
            for m_rh in re.finditer(r"(?m)^\s*(\d+\.\d+\.\d+\.\d+)\s*\{", m_rad_blk.group(1)):
                services["radius_servers"].append(m_rh.group(1))
        for m_tac_blk in re.finditer(r"\btacplus-server\s*\{([\s\S]*?)\n\s*\}", raw_config):
            for m_th in re.finditer(r"(?m)^\s*(\d+\.\d+\.\d+\.\d+)\s*\{", m_tac_blk.group(1)):
                services["tacacs_servers"].append(m_th.group(1))
        for m_tg_blk in re.finditer(r"\btrap-group\s+\S+\s*\{[\s\S]*?\btargets\s*\{([^}]*)\}", raw_config):
            for m_tip in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\s*;", m_tg_blk.group(1)):
                services["snmp_servers"].append(m_tip.group(1))

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

        m_ios_relay = re.match(
            r"^(?:ip\s+helper-address\s+(?:vrf\s+\S+\s+|global\s+)?|helper-address\s+|ip\s+dhcp\s+relay\s+address\s+)(\d+\.\d+\.\d+\.\d+)",
            line,
            re.IGNORECASE,
        )
        if m_ios_relay:
            services["dhcp_relays"].append(m_ios_relay.group(1))

        m_ios_syslog = re.match(
            r"^(?:logging\s+host|logging\s+server|syslog-server)\s+(\S+)",
            line,
            re.IGNORECASE,
        )
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

        # HP ProCurve / ArubaOS-S (Provision)
        m_hp_dns = re.match(r"^ip\s+dns\s+server-address\s+(?:priority\s+\d+\s+)?(\S+)", line, re.IGNORECASE)
        if m_hp_dns:
            services["dns_servers"].append(m_hp_dns.group(1))
        m_hp_sntp = re.match(r"^sntp\s+server\s+(?:priority\s+\d+\s+)?(\S+)", line, re.IGNORECASE)
        if m_hp_sntp:
            services["ntp_servers"].append(m_hp_sntp.group(1))
        m_hp_syslog = re.match(r"^logging\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
        if m_hp_syslog:
            services["syslog_servers"].append(m_hp_syslog.group(1))

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
        if "relay=" in line or "dhcp-relay" in line or "dhcp-server=" in line:
            m_mt_relay = re.search(r"(?:relay|dhcp-server)=([0-9.,]+)", line)
            if m_mt_relay:
                services["dhcp_relays"].extend(s.strip() for s in m_mt_relay.group(1).split(",") if s.strip())
        if "remote=" in line and ("target=remote" in line or "logging" in line):
            m_mt_sys = re.search(r"\bremote=([^\s\"']+)", line)
            if m_mt_sys:
                services["syslog_servers"].append(m_mt_sys.group(1).strip())
        if "address=" in line and ("service=" in line or "/radius" in line):
            m_mt_rad = re.search(r"\baddress=([^\s\"']+)", line)
            if m_mt_rad:
                services["radius_servers"].append(m_mt_rad.group(1).strip())
        if "trap-target=" in line:
            m_mt_snmp = re.search(r"\btrap-target=([^\s\"']+)", line)
            if m_mt_snmp:
                services["snmp_servers"].extend(s.strip() for s in m_mt_snmp.group(1).split(",") if s.strip())

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
    Sanitizes sensitive security credentials, pre-shared keys, passwords, SNMP communities,
    and private keys from raw device configuration files before export, ticketing, or publication.
    """
    if not raw_config:
        return ""
    sanitized = raw_config

    # PEM private key blocks (OPNsense, FortiOS, IOS/XE, Junos, Linux)
    sanitized = re.sub(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        "<REDACTED_PRIVATE_KEY>",
        sanitized,
    )

    # FortiOS `set <secret_field> [ENC] <value>` (handle ENC prefix before generic password rule)
    sanitized = re.sub(
        r"(set\s+(?:password|passwd|psksecret|auth-pwd|priv-pwd|enc-password|auth-key|priv-key|private-key|api-key|secret-key|ssh-hkey|ca-password|scep-password|group-password|alicloud-access-key-secret|key|secret|community)\s+(?:ENC\s+)?)(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        r"\1<REDACTED_SECRET>",
        sanitized,
        flags=re.IGNORECASE,
    )

    # MikroTik key=value credentials (`password=...`, `secret=...`, `wpa-pre-shared-key=...`, etc.)
    sanitized = re.sub(
        r"(\b(?:password|secret|passphrase|authentication-password|privacy-password|shared-secret|wpa-pre-shared-key|wpa2-pre-shared-key|private-key|api-key|auth-key|community)=)(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        r"\1<REDACTED_SECRET>",
        sanitized,
        flags=re.IGNORECASE,
    )

    # OpenWrt UCI (`option key '...'`, `option password '...'`, `option secret '...'`)
    sanitized = re.sub(
        r"(option\s+(?:key|password|secret|psk|auth_secret|acct_secret)\s+)(?:'[^']*'|\"[^\"]*\"|[^\s\r\n]+)",
        r"\1'<REDACTED_SECRET>'",
        sanitized,
        flags=re.IGNORECASE,
    )

    # Cisco / Arista / FRR AAA, IKE, OSPF MD5, HSRP/VRRP auth, and key-string secrets (with optional encryption type digit)
    sanitized = re.sub(
        r"((?:tacacs-server\s+key|radius-server\s+key|crypto\s+isakmp\s+key|ip\s+ospf\s+message-digest-key\s+\d+\s+md5|standby\s+\d+\s+authentication(?:\s+md5\s+key-string|\s+text)?|key-string)\s+(?:\d+\s+)?)[^\s\r\n]+",
        r"\1<REDACTED_KEY>",
        sanitized,
        flags=re.IGNORECASE,
    )

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
    # SNMP community strings (Cisco, Arista, HP ProCurve quoted/unquoted, Junos)
    sanitized = re.sub(
        r"((?:snmp-server\s+community|set\s+snmp\s+community)\s+)(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
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
        r"(<(?:password|pre-shared-key|secret|sharedsecret|bcrypt-hash|md5-hash|nt-hash|phash|prv|private-key|community|rocommunity|rwcommunity|psk|auth_pass|priv_pass|bind-password|apikey|api-key|apisecret|lighttpd_user_password)>)[^<]+(</(?:password|pre-shared-key|secret|sharedsecret|bcrypt-hash|md5-hash|nt-hash|phash|prv|private-key|community|rocommunity|rwcommunity|psk|auth_pass|priv_pass|bind-password|apikey|api-key|apisecret|lighttpd_user_password)>)",
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
    supports_telnet: bool = True

    def __init__(
        self,
        ip: str,
        username: str = "",
        password: str = "",
        secret: str = "",
        timeout: int = 10,
        session_log: str = "",
        port: int | None = None,
        transport: str = "ssh",
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.secret = secret
        self.timeout = max(1, int(timeout)) if timeout else 10
        self.session_log = session_log
        self.transport = (transport or "ssh").lower()
        self.port = port if port is not None else (23 if self.transport == "telnet" else 22)
        self._collection_status: dict[str, str] = {}
        self._parse_errors: list[dict[str, str]] = []
        self._active_section: str = ""
        self._section_had_cmd_error: bool = False

    def _driver_logger(self) -> logging.Logger:
        """Return the module-scoped logger for this driver subclass."""
        return logging.getLogger(self.__class__.__module__)

    def _known_secrets(self) -> tuple[str, ...]:
        return tuple(s for s in (self.password, self.secret) if isinstance(s, str) and s)

    def _scrub_text(self, text: str) -> str:
        return scrub_known_secrets(sanitize_raw_config(str(text or "")), self._known_secrets())

    def _set_collection_status(self, section: str, status: str) -> None:
        if section:
            self._collection_status[section] = status

    def _record_parse_error(
        self,
        section: str,
        command: str,
        stage: str,
        error: str,
        raw_snippet: str = "",
    ) -> None:
        self._parse_errors.append(
            {
                "section": section or self._active_section or "unknown",
                "command": str(command or ""),
                "stage": stage if stage in ("command", "parse") else "command",
                "error": self._scrub_text(error)[:240],
                "raw_snippet": self._scrub_text(raw_snippet)[:200],
            }
        )

    def _log_cmd_failure(self, command: str, exc: Exception, *, context: str = "") -> None:
        """Emit a structured debug log entry when a read-only CLI command or parser fails."""
        prefix = f"{context} " if context else ""
        safe_exc = self._scrub_text(str(exc))
        self._driver_logger().debug("[%s] %s'%s' failed: %s", self.ip, prefix, command, safe_exc)
        self._section_had_cmd_error = True
        stage = "parse" if "parse" in context.lower() else "command"
        self._record_parse_error(self._active_section or "session", command, stage, safe_exc)

    def _compute_read_timeout(self, command: str, read_timeout: float | None = None) -> float:
        """Compute a strictly bounded per-command read timeout (never 0/infinite)."""
        if read_timeout is not None and read_timeout > 0:
            return min(float(read_timeout), 180.0)
        cmd_low = (command or "").lower()
        base = float(self.timeout)
        if any(tok in cmd_low for tok in _LARGE_OUTPUT_CMD_TOKENS):
            return max(30.0, min(base * 4.0, 120.0))
        return max(15.0, min(base * 2.0, 60.0))

    def _build_netmiko_params(
        self,
        device_type: str,
        *,
        include_auth_timeout: bool = True,
        **extra,
    ) -> dict:
        """Build Netmiko 4.x connection parameters with strict, bounded connect/auth/banner/read timeouts."""
        base_to = max(1, int(self.timeout))
        device: dict = {
            "device_type": device_type,
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "conn_timeout": base_to,
            "banner_timeout": base_to,
            "auth_timeout": base_to,
            "blocking_timeout": max(10, min(base_to * 2, 60)),
            "session_timeout": max(30, min(base_to * 4, 120)),
            "timeout": base_to,
        }
        # Retain include_auth_timeout parameter for backwards compatibility while never
        # leaving auth_timeout unset (Paramiko defaults None -> 30s).
        _ = include_auth_timeout
        device.update(extra)

        # Enforce strictly positive finite ceilings even if caller passed None/0 in extra
        for key, fallback in (
            ("conn_timeout", base_to),
            ("banner_timeout", base_to),
            ("auth_timeout", base_to),
            ("blocking_timeout", max(10, min(base_to * 2, 60))),
            ("session_timeout", max(30, min(base_to * 4, 120))),
        ):
            val = device.get(key)
            if val is None or (isinstance(val, (int, float)) and val <= 0):
                device[key] = fallback

        if "read_timeout_override" in device:
            rto = device["read_timeout_override"]
            if rto is None or (isinstance(rto, (int, float)) and rto <= 0):
                device.pop("read_timeout_override", None)

        if self.session_log:
            device["session_log"] = self.session_log
        return device

    @staticmethod
    def safe_disconnect(conn) -> None:
        """Safely terminate a Netmiko or Paramiko session, suppressing cleanup errors."""
        if conn is None:
            return
        try:
            if hasattr(conn, "disconnect"):
                conn.disconnect()
            elif hasattr(conn, "close"):
                conn.close()
        except Exception as exc:
            logger.debug("Session disconnect cleanup error ignored: %s", exc)

    @contextmanager
    def connect_session(self) -> Iterator[object]:
        """Context manager guaranteeing VTY/SSH cleanup on every exception path (including BaseException)."""
        conn = self.connect()
        try:
            yield conn
        finally:
            self.safe_disconnect(conn)

    def _finalize_connection(self, conn, *, enable: bool = False, paging_cmd: str = ""):
        """Run optional post-connect enable and read-only paging verification, closing `conn` on any BaseException."""
        try:
            if enable:
                self._safe_enable(conn)
            if paging_cmd:
                self._verify_paging_disabled(conn, paging_cmd)
            return conn
        except BaseException:
            self.safe_disconnect(conn)
            raise

    def _verify_paging_disabled(self, conn, paging_cmd: str = "") -> bool:
        """
        Issue a session-scoped read-only paging command and verify the device did not reject it
        with a CLI error or pagination prompt. Refuses any config-mode/write-capable command.
        """
        cmd = (paging_cmd or self.paging_cmd or "").strip()
        if not cmd:
            return True
        if _WRITE_OR_CONFIG_CMD_RE.search(cmd):
            self._driver_logger().warning(
                "[%s] Refused write/config-mode paging command %r under Zero-Blast-Radius policy.", self.ip, cmd
            )
            self._record_parse_error("session", cmd, "command", "Refused config/write-mode paging command")
            return False
        try:
            out = self._call_send_command(conn, cmd)
        except Exception as exc:
            self._log_cmd_failure(cmd, exc, context="paging disable")
            self._driver_logger().warning(
                "[%s] Paging-disable command %r failed: %s", self.ip, cmd, self._scrub_text(str(exc))
            )
            return False

        err_marker = detect_cli_error(out)
        if err_marker or detect_paging_artifact(out):
            reason = f"Paging-disable command {cmd!r} rejected ({err_marker or 'pagination prompt'})"
            self._driver_logger().warning("[%s] %s", self.ip, reason)
            self._record_parse_error("session", cmd, "command", reason, raw_snippet=out or "")
            return False
        return True

    def _call_send_command(self, conn, command: str, read_timeout: float | None = None):
        """Invoke `conn.send_command` forwarding bounded `read_timeout`/`timeout` when explicitly supported."""
        fn = conn.send_command
        eff_timeout = self._compute_read_timeout(command, read_timeout)
        try:
            sig = inspect.signature(fn)
            if "read_timeout" in sig.parameters:
                return fn(command, read_timeout=eff_timeout)
            if "timeout" in sig.parameters:
                return fn(command, timeout=eff_timeout)
        except (TypeError, ValueError):
            pass
        return fn(command)

    def _safe_enable(self, conn) -> bool:
        """Attempt privileged exec elevation, logging failures at debug level."""
        try:
            conn.enable()
            return True
        except Exception as exc:
            self._log_cmd_failure("enable", exc, context="privileged mode")
            return False

    def _safe_find_prompt(self, conn, default: str = "") -> str:
        """Read the device CLI prompt safely, returning default on transport error."""
        try:
            prompt = conn.find_prompt()
            return prompt if isinstance(prompt, str) else default
        except Exception as exc:
            self._log_cmd_failure("find_prompt", exc)
            return default

    def _safe_send_command(
        self,
        conn,
        command: str,
        default: str = "",
        *,
        read_timeout: float | None = None,
    ) -> str:
        """Execute a read-only CLI command with bounded timeout and `--More--` paging detection."""
        try:
            out = self._call_send_command(conn, command, read_timeout=read_timeout)
        except Exception as exc:
            self._log_cmd_failure(command, exc)
            return default
        if not isinstance(out, str):
            return default
        if detect_paging_artifact(out):
            self._driver_logger().warning(
                "[%s] Pagination prompt (--More--) detected in output of %r; output may be truncated.",
                self.ip,
                command,
            )
            self._record_parse_error(
                self._active_section or "session",
                command,
                "command",
                "Pagination prompt (--More--) detected; paging disable may have failed",
                raw_snippet=out[-200:],
            )
            self._section_had_cmd_error = True
        return out

    def _safe_send_json(self, conn, command: str, *, read_timeout: float | None = None):
        """Execute a read-only JSON CLI command and parse its payload, returning None on failure."""
        try:
            raw = self._call_send_command(conn, command, read_timeout=read_timeout)
        except Exception as exc:
            self._log_cmd_failure(command, exc)
            return None
        if not isinstance(raw, str) or not raw.strip():
            return None
        if detect_paging_artifact(raw):
            self._driver_logger().warning(
                "[%s] Pagination prompt (--More--) detected in JSON output of %r.", self.ip, command
            )
            self._record_parse_error(
                self._active_section or "session",
                command,
                "command",
                "Pagination prompt (--More--) detected in JSON command output",
                raw_snippet=raw[-200:],
            )
            self._section_had_cmd_error = True
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            self._log_cmd_failure(command, exc, context="JSON parse")
            return None

    @staticmethod
    def safe_netmiko_connect(device_params: dict):
        """
        Establishes a Netmiko connection via the 3-stage SSH compatibility ladder
        (`connect_netmiko_with_fallback`), bridging modern RFC 8731/3526 KEX peers
        and legacy SSHv2 implementations without retrying failed credentials.
        """
        from net_docu_crawler.ssh_compat import connect_netmiko_with_fallback

        return connect_netmiko_with_fallback(device_params)

    def connect_netmiko(self, device_params: dict):
        """
        Applies configured transport (SSH or Telnet) and custom port before connecting
        via safe_netmiko_connect().
        """
        from netmiko.ssh_dispatcher import CLASS_MAPPER

        params = dict(device_params)
        if self.port is not None:
            params["port"] = self.port
        if self.transport == "telnet":
            base_type = params.get("device_type", "")
            telnet_type = f"{base_type}_telnet"
            if telnet_type not in CLASS_MAPPER:
                raise ValueError(f"Telnet transport is not supported by {self.__class__.__name__} ({base_type})")
            params["device_type"] = telnet_type
        return self.safe_netmiko_connect(params)

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

    def get_routing_peers(self, conn) -> list[dict]:
        """Optional hook for routers/L3 switches to gather live BGP/OSPF neighbor state."""
        return []

    def get_fhrp(self, conn) -> list[dict]:
        """Optional hook for routers/L3 switches to gather live HSRP/VRRP/CARP redundancy state."""
        return []

    def get_services(self, conn, raw_config: str = "") -> dict:
        """Optional hook to extract DNS, NTP, RADIUS, and TACACS+ infrastructure services."""
        return extract_services_from_config(raw_config)

    def get_l2_operational(self, conn) -> dict[str, dict]:
        """Optional hook to collect live operational L2 trunk, LACP, STP port, and 802.1X state."""
        return {}

    def get_vrfs(self, conn) -> list[dict]:
        """Optional hook for routers/L3 switches to gather live VRF/routing-instance tables."""
        return []

    def get_mpls_ldp(self, conn) -> dict:
        """Optional hook for core routers to gather read-only MPLS/LDP neighbor, interface, and label state."""
        return {}

    def get_discovery_protocols(
        self, conn, raw_config: str = "", neighbors: list[dict] | None = None
    ) -> dict[str, str]:
        """
        Optional hook to report L2 neighbor discovery protocol status (LLDP, CDP, MNDP).
        Values: 'enabled' | 'disabled' | 'not_installed' | 'unsupported' | 'unknown'.
        """
        cached = getattr(self, "_discovery_protocols", None)
        if isinstance(cached, dict):
            return {
                "lldp": cached.get("lldp", "unknown"),
                "cdp": cached.get("cdp", "unsupported"),
                "mndp": cached.get("mndp", "unsupported"),
                "notes": cached.get("notes", ""),
            }
        return {
            "lldp": "enabled" if neighbors else "unknown",
            "cdp": "unsupported",
            "mndp": "unsupported",
            "notes": "",
        }

    def _run_crawl_section(
        self,
        section: str,
        fn,
        default,
        *,
        base_method_name: str | None = None,
        applicable: bool = True,
    ):
        """Execute a crawl collection hook safely while tracking Schema v2.1 `collection_status` & `parse_errors`."""
        if base_method_name and getattr(type(self), base_method_name, None) is getattr(
            BaseDriver, base_method_name, None
        ):
            self._set_collection_status(section, "not_collected" if applicable else "not_applicable")
            return default

        prev_section = self._active_section
        self._active_section = section
        self._section_had_cmd_error = False
        try:
            result = fn()
        except Exception as exc:
            safe_exc = self._scrub_text(str(exc))
            self._driver_logger().warning("[%s] Section '%s' failed: %s", self.ip, section, safe_exc)
            self._set_collection_status(section, "command_failed")
            self._record_parse_error(section, base_method_name or section, "command", safe_exc)
            return default
        finally:
            self._active_section = prev_section

        if section not in self._collection_status:
            self._set_collection_status(section, "partial" if self._section_had_cmd_error else "ok")
        return result

    def crawl(self, conn) -> dict:
        """
        Template method executing the safe read-only discovery sequence.
        Returns normalized device data dictionary ready for reporting and diagram generation,
        populated with Schema v2.1 `collection_status` and `parse_errors` telemetry.
        """
        self._collection_status = {}
        self._parse_errors = []

        if self.transport == "telnet":
            mgmt_method = "Telnet" if self.port == 23 else f"Telnet:{self.port}"
        else:
            mgmt_method = "SSH" if self.port == 22 else f"SSH:{self.port}"

        device_data = {
            "ip": self.ip,
            "status": "success",
            "mgmt_method": mgmt_method,
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
            "routing_peers": [],
            "vrfs": [],
            "mpls": {"ldp_neighbors": [], "ldp_interfaces": [], "forwarding": []},
            "fhrp": [],
            "port_profiles": {},
            "dhcp": {"pools": [], "reservations": [], "relays": []},
            "security_policy": {"firewall_rules": [], "nat_rules": [], "vpn_tunnels": []},
            "services": {},
            "discovery_protocols": {"lldp": "unknown", "cdp": "unsupported", "mndp": "unsupported", "notes": ""},
            "raw_config": "",
            "collection_status": {},
            "parse_errors": [],
        }

        # 1. Version & System Info
        ver = self._run_crawl_section("version", lambda: self.get_version(conn), {})
        if isinstance(ver, dict):
            device_data.update(ver)

        persona = str(device_data.get("device_persona") or device_data.get("device_type") or "").lower()
        is_switch = persona == "switch"
        is_router_or_fw = persona in ("router", "firewall", "switch")

        # 2. Interfaces
        l3_ints, ints_detail = self._run_crawl_section(
            "interfaces",
            lambda: self.get_interfaces(conn),
            ([], {}),
        )
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
        device_data["neighbors"] = self._run_crawl_section("neighbors", lambda: self.get_neighbors(conn), [])

        # 4. Routing Table
        device_data["routes"] = self._run_crawl_section("routes", lambda: self.get_routing_table(conn), [])

        # 5. ARP Table
        device_data["arp_table"] = self._run_crawl_section("arp", lambda: self.get_arp_table(conn), [])

        # 6. Spanning Tree (L2 switching state)
        device_data["stp"] = self._run_crawl_section(
            "stp",
            lambda: self.get_stp(conn),
            {"enabled": False, "vlans": {}},
            base_method_name="get_stp",
            applicable=is_switch,
        )

        # 7. Power over Ethernet (PoE) & MAC Address Forwarding Table
        device_data["poe"] = self._run_crawl_section(
            "poe",
            lambda: self.get_poe(conn),
            {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}},
            base_method_name="get_poe",
            applicable=is_switch,
        )
        device_data["mac_table"] = self._run_crawl_section(
            "mac_table",
            lambda: self.get_mac_table(conn),
            [],
            base_method_name="get_mac_table",
            applicable=is_switch,
        )

        # 8. Optical Transceiver & DOM Telemetry
        device_data["optics"] = self._run_crawl_section(
            "optics",
            lambda: self.get_optics(conn),
            [],
            base_method_name="get_optics",
            applicable=is_router_or_fw,
        )

        # 9. Configuration Backup & Infrastructure Services
        raw_cfg = self._run_crawl_section("running_config", lambda: self.get_running_config(conn), "")
        device_data["raw_config"] = raw_cfg if isinstance(raw_cfg, str) else ""
        cfg_err = detect_cli_error(device_data["raw_config"])
        if self._collection_status.get("running_config") == "ok":
            if cfg_err:
                self._set_collection_status("running_config", "command_failed")
                self._record_parse_error(
                    "running_config", "get_running_config", "command", cfg_err, raw_snippet=device_data["raw_config"]
                )
            elif not device_data["raw_config"].strip():
                self._set_collection_status("running_config", "not_collected")
        cfg_status = self._collection_status.get("running_config", "not_collected")
        cfg_derived_fallback = cfg_status if cfg_status != "ok" else "ok"

        device_data["services"] = self._run_crawl_section(
            "services",
            lambda: self.get_services(conn, device_data["raw_config"]),
            {},
        )
        if cfg_status != "ok" and self._collection_status.get("services") == "ok":
            self._set_collection_status("services", cfg_derived_fallback)

        device_data["discovery_protocols"] = self._run_crawl_section(
            "discovery_protocols",
            lambda: self.get_discovery_protocols(
                conn, raw_config=device_data["raw_config"], neighbors=device_data["neighbors"]
            ),
            {"lldp": "unknown", "cdp": "unsupported", "mndp": "unsupported", "notes": ""},
        )

        # 10. Vendor-Neutral Migration Intent (Port Profiles, Routing Peers/FHRP, DHCP, Firewall/NAT/VPN)
        from net_docu_crawler.migration_parsers import (
            extract_dhcp_config,
            extract_firewall_nat_vpn,
            extract_port_profiles,
            extract_routing_peers_and_fhrp_from_config,
            extract_vlans,
            extract_vrfs_and_acls,
        )

        device_data["vlans"] = extract_vlans(device_data["raw_config"], vendor=self.vendor_name)
        self._set_collection_status("vlans", cfg_derived_fallback)

        device_data["port_profiles"] = extract_port_profiles(
            device_data["raw_config"], vendor=self.vendor_name, poe=device_data["poe"]
        )
        vrfs, acls_by_port = extract_vrfs_and_acls(device_data["raw_config"], vendor=self.vendor_name)
        live_vrfs = self._run_crawl_section(
            "vrfs",
            lambda: self.get_vrfs(conn),
            [],
            base_method_name="get_vrfs",
            applicable=is_router_or_fw,
        )
        device_data["vrfs"] = live_vrfs if live_vrfs else vrfs
        if not live_vrfs and vrfs and self._collection_status.get("vrfs") == "not_collected":
            self._set_collection_status("vrfs", "ok")

        live_mpls = self._run_crawl_section(
            "mpls",
            lambda: self.get_mpls_ldp(conn),
            {},
            base_method_name="get_mpls_ldp",
            applicable=persona == "router",
        )
        if isinstance(live_mpls, dict) and live_mpls:
            device_data["mpls"] = {
                "ldp_neighbors": live_mpls.get("ldp_neighbors", []),
                "ldp_interfaces": live_mpls.get("ldp_interfaces", []),
                "forwarding": live_mpls.get("forwarding", []),
            }
        for acl_port, acl_vals in acls_by_port.items():
            prof = device_data["port_profiles"].setdefault(acl_port, {})
            if acl_vals.get("acl_in"):
                prof["acl_in"] = acl_vals["acl_in"]
            if acl_vals.get("acl_out"):
                prof["acl_out"] = acl_vals["acl_out"]
        live_l2 = self._run_crawl_section(
            "l2_operational",
            lambda: self.get_l2_operational(conn) or {},
            {},
            base_method_name="get_l2_operational",
            applicable=is_switch,
        )
        for op_port, op_vals in (live_l2 or {}).items():
            prof = device_data["port_profiles"].setdefault(op_port, {})
            for k, v in op_vals.items():
                if v not in ("", None, "unknown") or k not in prof:
                    prof[k] = v
        if cfg_status == "ok" or live_l2:
            self._set_collection_status("port_profiles", "ok")
        else:
            self._set_collection_status("port_profiles", cfg_derived_fallback)

        cfg_peers, cfg_fhrp = extract_routing_peers_and_fhrp_from_config(
            device_data["raw_config"], vendor=self.vendor_name
        )
        live_peers = self._run_crawl_section(
            "routing_peers",
            lambda: self.get_routing_peers(conn),
            [],
            base_method_name="get_routing_peers",
            applicable=is_router_or_fw,
        )
        live_fhrp = self._run_crawl_section(
            "fhrp",
            lambda: self.get_fhrp(conn),
            [],
            base_method_name="get_fhrp",
            applicable=is_router_or_fw,
        )
        device_data["routing_peers"] = live_peers if live_peers else cfg_peers
        if not live_peers and cfg_peers and self._collection_status.get("routing_peers") == "not_collected":
            self._set_collection_status("routing_peers", "ok")

        device_data["fhrp"] = live_fhrp if live_fhrp else cfg_fhrp
        if not live_fhrp and cfg_fhrp and self._collection_status.get("fhrp") == "not_collected":
            self._set_collection_status("fhrp", "ok")

        device_data["dhcp"] = extract_dhcp_config(device_data["raw_config"], vendor=self.vendor_name)
        self._set_collection_status("dhcp", cfg_derived_fallback)

        device_data["security_policy"] = extract_firewall_nat_vpn(device_data["raw_config"], vendor=self.vendor_name)
        self._set_collection_status("security_policy", cfg_derived_fallback)

        device_data["collection_status"] = dict(self._collection_status)
        device_data["parse_errors"] = list(self._parse_errors)

        from net_docu_crawler.schema import stamp_schema_v2

        return stamp_schema_v2(device_data)

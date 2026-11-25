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

import logging
import re

logger = logging.getLogger(__name__)

try:
    from netmiko.utilities import get_structured_data
except ImportError:
    get_structured_data = None

_CLI_ERROR_RE = re.compile(
    r"(?:%\s*invalid\s+input|%\s*unrecognized|%\s*ambiguous|%\s*incomplete|%\s*authorization\s+failed|syntax\s+error)",
    re.IGNORECASE,
)
_MAC_TOKEN_RE = re.compile(r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})")
_IPV4_OR_UNASSIGNED_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|unassigned)$", re.IGNORECASE)
_UPTIME_TOKEN_RE = re.compile(r"^(?:\d+[ywdhms])+$|^\d{1,2}:\d{2}:\d{2}$", re.IGNORECASE)

_ROUTE_PROTO_MAP = {
    "C": "Connected",
    "L": "Local",
    "S": "Static",
    "O": "OSPF",
    "D": "EIGRP",
    "B": "BGP",
    "R": "RIP",
    "I": "IS-IS",
    "M": "Mobile",
    "U": "Static",
    "*": "Default",
}


def _normalize_route_proto(code: str) -> str:
    c = (code or "").strip()
    if not c:
        return "Other"
    if len(c) > 3 and c.isalpha():
        return c.upper() if c.lower() in ("bgp", "ospf", "eigrp", "rip", "isis") else c.capitalize()
    first = c[0].upper()
    if c.lower().startswith("i"):
        return "IS-IS"
    return _ROUTE_PROTO_MAP.get(first, "Other")


def _expand_lldp_capabilities(raw_caps: str) -> str:
    """Expand single-letter LLDP capability codes (B, R, W, T) for device classification."""
    if not raw_caps:
        return ""
    tokens = [t.strip().upper() for t in re.split(r"[\s,/]+", raw_caps) if t.strip()]
    expanded = [raw_caps]
    code_map = {
        "W": "access point",
        "R": "router",
        "T": "telephone",
        "B": "bridge",
    }
    for tok in tokens:
        if tok in code_map:
            expanded.append(code_map[tok])
    return " ".join(expanded)


def clean_cli_output(output):
    """
    Cleans up terminal escape sequences, backspaces, paging markers (--More--),
    and paging prompt lines from the raw output.
    """
    if not output:
        return ""
    # Strip backspaces and carriage returns that overwrite text
    output = re.sub(r".\x08", "", output)  # Remove backspaced characters
    output = re.sub(r"[\b]", "", output)

    # Strip common paging prompts
    output = re.sub(r".*--\s*[Mm]ore\s*--.*", "", output, flags=re.IGNORECASE)
    output = re.sub(r".*-\s*[Mm]ore\s*-.*", "", output, flags=re.IGNORECASE)

    # Remove terminal escape codes (ANSI sequences)
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    output = ansi_escape.sub("", output)

    return output


def parse_show_version(output, os_type):
    """
    Parses 'show version' output.
    Returns a dict with: hostname, firmware, model, serial
    """
    output = clean_cli_output(output)

    data = {"hostname": "", "firmware": "", "model": "", "serial": ""}

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show version")
            if isinstance(structured, list) and len(structured) > 0:
                entry = structured[0]
                fw = (
                    entry.get("VERSION")
                    or entry.get("version")
                    or entry.get("os")
                    or entry.get("OS")
                    or entry.get("software_image")
                    or ""
                )
                hn = entry.get("HOSTNAME") or entry.get("hostname") or entry.get("device_name") or ""

                model = (
                    entry.get("HARDWARE")
                    or entry.get("hardware")
                    or entry.get("PLATFORM")
                    or entry.get("platform")
                    or entry.get("model")
                    or ""
                )
                if isinstance(model, list):
                    model = model[0] if model else ""

                serial = entry.get("SERIAL") or entry.get("serial") or entry.get("serial_number") or ""
                if isinstance(serial, list):
                    serial = serial[0] if serial else ""

                if fw:
                    data["firmware"] = str(fw).strip()
                if hn:
                    data["hostname"] = str(hn).strip()
                if model:
                    data["model"] = str(model).strip()
                if serial:
                    data["serial"] = str(serial).strip()

                if data["firmware"] or data["hostname"] or data["model"] or data["serial"]:
                    return data
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show version' (%s): %s", os_type, exc)

    # Regex Fallback
    if os_type == "cisco_ios":
        # Firmware Version
        fw_match = re.search(r"Version\s+([^,\r\n]+)", output)
        if fw_match:
            data["firmware"] = fw_match.group(1).strip()

        # Hostname (usually derived from uptime prompt like "hostname uptime is...")
        hn_match = re.search(r"(\S+)\s+uptime\s+is", output)
        if hn_match:
            data["hostname"] = hn_match.group(1).strip()

        # Model & Serial
        model_match = re.search(r"[Cc]isco\s+([A-Za-z0-9-]+)\s+\([^)]+\)\s+processor", output)
        if model_match:
            data["model"] = model_match.group(1).strip()

        serial_match = re.search(r"Processor\s+board\s+ID\s+(\S+)", output)
        if serial_match:
            data["serial"] = serial_match.group(1).strip()

    elif os_type == "cisco_nxos":
        # Hostname
        hn_match = re.search(r"Device\s+name:\s*(\S+)", output, re.IGNORECASE)
        if hn_match:
            data["hostname"] = hn_match.group(1).strip()

        # Firmware Version
        fw_match = re.search(r"NXOS:\s+version\s+(\S+)", output)
        if not fw_match:
            fw_match = re.search(r"system:\s+version\s+(\S+)", output)
        if fw_match:
            data["firmware"] = fw_match.group(1).strip()

        # Model
        model_match = re.search(r"(?:Chassis|Hardware)\s*\r?\n\s*cisco\s+([^\r\n]+)", output, re.IGNORECASE)
        if model_match:
            raw_mod = model_match.group(1).strip()
            raw_mod = re.sub(r"\s+Chassis\s*$", "", raw_mod, flags=re.IGNORECASE).strip()
            data["model"] = raw_mod

        # Serial
        serial_match = re.search(r"Processor\s+Board\s+ID\s+(\S+)", output, re.IGNORECASE)
        if serial_match:
            data["serial"] = serial_match.group(1).strip()

    elif os_type == "cisco_xr":
        # Firmware Version
        fw_match = re.search(r"Version\s+(\S+)", output)
        if fw_match:
            data["firmware"] = fw_match.group(1).strip()

        # Model
        model_match = re.search(r"cisco\s+([A-Za-z0-9-]+)\s+Series\s+\([^)]*\)\s+processor", output, re.IGNORECASE)
        if not model_match:
            model_match = re.search(r"cisco\s+([A-Za-z0-9-]+)\s+\([^)]*\)\s+processor", output, re.IGNORECASE)
        if model_match:
            data["model"] = model_match.group(1).strip()

        # Serial
        serial_match = re.search(r"Chassis\s+Serial\s+Number:\s*(\S+)", output, re.IGNORECASE)
        if serial_match:
            data["serial"] = serial_match.group(1).strip()

    return data


def parse_show_inventory(output, os_type="cisco_ios"):
    """
    Parses 'show inventory' output which is highly standard.
    Returns list of dicts: {"name": ..., "descr": ..., "pid": ..., "sn": ...}
    We can use this to enrich the Version Model/Serial if missing.
    """
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show inventory")
            if isinstance(structured, list):
                items = []
                for entry in structured:
                    items.append(
                        {
                            "name": str(entry.get("NAME") or entry.get("name") or "").strip(),
                            "descr": str(entry.get("DESCR") or entry.get("descr") or "").strip(),
                            "pid": str(entry.get("PID") or entry.get("pid") or "").strip(),
                            "sn": str(entry.get("SN") or entry.get("sn") or "").strip(),
                        }
                    )
                if items:
                    return items
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show inventory' (%s): %s", os_type, exc)

    # Regex Fallback
    items = []
    pattern = re.compile(
        r'NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"\s*\r?\nPID:\s*(\S*)\s*,\s*VID:\s*\S*\s*,\s*SN:\s*(\S*)',
        re.IGNORECASE,
    )
    for match in pattern.finditer(output):
        items.append(
            {
                "name": match.group(1).strip(),
                "descr": match.group(2).strip(),
                "pid": match.group(3).strip(),
                "sn": match.group(4).strip(),
            }
        )
    return items


def parse_ip_interface_brief(output, os_type):
    """
    Parses 'show ip interface brief' or 'show ipv4 interface brief' output.
    Returns list of dicts: {"interface": ..., "ip_address": ..., "status": ..., "protocol": ...}
    """
    output = clean_cli_output(output)
    if not output or _CLI_ERROR_RE.search(output):
        return []

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            cmd = "show ipv4 interface brief" if os_type == "cisco_xr" else "show ip interface brief"
            structured = get_structured_data(output, platform=os_type, command=cmd)
            if isinstance(structured, list):
                interfaces = []
                for entry in structured:
                    intf = entry.get("INTERFACE") or entry.get("interface") or entry.get("intf") or ""
                    ip = entry.get("IPADDR") or entry.get("ip_address") or entry.get("ipaddr") or ""
                    status = entry.get("STATUS") or entry.get("status") or entry.get("link_status") or ""
                    proto = (
                        entry.get("PROTO")
                        or entry.get("proto")
                        or entry.get("PROTOCOL")
                        or entry.get("protocol")
                        or entry.get("proto_status")
                        or ""
                    )
                    if intf and _IPV4_OR_UNASSIGNED_RE.match(str(ip).strip()):
                        interfaces.append(
                            {
                                "interface": str(intf).strip(),
                                "ip_address": str(ip).strip(),
                                "status": str(status).strip().lower(),
                                "protocol": str(proto).strip().lower(),
                            }
                        )
                if interfaces:
                    return interfaces
        except Exception as exc:
            logger.warning("TextFSM parse failed for ip interface brief (%s): %s", os_type, exc)

    # Regex Fallback
    interfaces = []
    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if (
            not line
            or line.startswith(("%", "^", "!"))
            or set(line.replace(" ", "")) <= {"-", "="}
            or "Interface" in line
            or "IP-Address" in line
            or "IP Address" in line
            or "OK?" in line
            or _CLI_ERROR_RE.search(line)
        ):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        interface = parts[0]
        ip_addr = parts[1]
        if not _IPV4_OR_UNASSIGNED_RE.match(ip_addr):
            continue

        # NX-OS 3-column layout: Interface  IP-Address  protocol-up/link-up/admin-up
        if len(parts) == 3 and "/" in parts[2]:
            st_tok = parts[2].lower()
            if "admin-down" in st_tok:
                status = "administratively down"
            elif "link-up" in st_tok:
                status = "up"
            else:
                status = "down"
            protocol = "up" if "protocol-up" in st_tok else "down"
            interfaces.append({"interface": interface, "ip_address": ip_addr, "status": status, "protocol": protocol})
            continue

        if len(parts) >= 4:
            if os_type == "cisco_xr" or (parts[2].lower() in ("up", "down") and parts[3].lower() in ("up", "down")):
                status = parts[2]
                protocol = parts[3]
            elif len(parts) >= 5 and parts[-3].lower() == "administratively" and parts[-2].lower() == "down":
                status = "administratively down"
                protocol = parts[-1]
            else:
                status = parts[-2]
                protocol = parts[-1]

            interfaces.append(
                {"interface": interface, "ip_address": ip_addr, "status": status.lower(), "protocol": protocol.lower()}
            )
    return interfaces


def parse_show_interfaces_status(output, os_type="cisco_ios"):
    """
    Parses 'show interface status' (IOS / NX-OS).
    Returns list of dicts: {"port": ..., "name": ..., "status": ..., "vlan": ..., "duplex": ..., "speed": ..., "type": ...}
    """
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show interface status")
            if isinstance(structured, list):
                ports = []
                for entry in structured:
                    port = entry.get("PORT") or entry.get("port") or ""
                    if port:
                        ports.append(
                            {
                                "port": str(port).strip(),
                                "name": str(entry.get("NAME") or entry.get("name") or "").strip(),
                                "status": str(entry.get("STATUS") or entry.get("status") or "").strip(),
                                "vlan": str(
                                    entry.get("VLAN") or entry.get("vlan") or entry.get("vlan_id") or ""
                                ).strip(),
                                "duplex": str(entry.get("DUPLEX") or entry.get("duplex") or "").strip(),
                                "speed": str(entry.get("SPEED") or entry.get("speed") or "").strip(),
                                "type": str(entry.get("TYPE") or entry.get("type") or "").strip(),
                            }
                        )
                if ports:
                    return ports
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show interface status' (%s): %s", os_type, exc)

    # Regex Fallback
    ports = []
    lines = output.splitlines()
    header_found = False
    for line in lines:
        if "Port" in line and "Status" in line:
            header_found = True
            continue
        if not header_found or not line.strip() or line.startswith("---") or line.startswith("Port"):
            continue

        match = re.match(
            r"^(\S+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled|up|down|monitoring)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
            line.strip(),
        )
        if match:
            ports.append(
                {
                    "port": match.group(1),
                    "name": match.group(2).strip(),
                    "status": match.group(3),
                    "vlan": match.group(4),
                    "duplex": match.group(5),
                    "speed": match.group(6),
                    "type": match.group(7).strip() if match.group(7) else "",
                }
            )
    return ports


def parse_show_interfaces(output, os_type):
    """
    Parses 'show interfaces' (full detail).
    Looks for packet counters, CRC/input errors, duplex/speed settings.
    Returns dict mapping interface name -> stats dict:
    {"mac_address": ..., "speed": ..., "duplex": ..., "input_errors": ..., "crc": ..., "output_errors": ..., "description": ...}
    """
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show interfaces")
            if isinstance(structured, list):
                interfaces = {}
                for entry in structured:
                    intf = entry.get("INTERFACE") or entry.get("interface") or ""
                    if not intf:
                        continue

                    mac = (
                        entry.get("ADDRESS")
                        or entry.get("address")
                        or entry.get("mac_address")
                        or entry.get("mac")
                        or ""
                    )
                    mac = str(mac).replace("-", "").replace(".", "").replace(":", "")

                    speed = str(entry.get("SPEED") or entry.get("speed") or "").strip()
                    duplex = str(entry.get("DUPLEX") or entry.get("duplex") or "").strip()
                    desc = str(entry.get("DESCRIPTION") or entry.get("description") or "").strip()

                    try:
                        input_err = int(entry.get("INPUT_ERRORS") or entry.get("input_errors") or 0)
                    except (ValueError, TypeError):
                        input_err = 0

                    try:
                        crc = int(entry.get("CRC") or entry.get("crc") or 0)
                    except (ValueError, TypeError):
                        crc = 0

                    try:
                        output_err = int(entry.get("OUTPUT_ERRORS") or entry.get("output_errors") or 0)
                    except (ValueError, TypeError):
                        output_err = 0

                    raw_status = str(
                        entry.get("LINK_STATUS") or entry.get("link_status") or entry.get("status") or "down"
                    ).strip()
                    interfaces[intf] = {
                        "status": raw_status,
                        "mac_address": mac,
                        "speed": speed,
                        "duplex": duplex,
                        "input_errors": input_err,
                        "crc": crc,
                        "output_errors": output_err,
                        "description": desc,
                    }
                if interfaces:
                    return interfaces
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show interfaces' (%s): %s", os_type, exc)

    # Regex Fallback
    interfaces = {}
    current_int = None

    lines = output.splitlines()
    for line in lines:
        int_start = re.match(r"^(\S+)\s+is\s+(up|down|administratively down)", line)
        if int_start:
            current_int = int_start.group(1)
            interfaces[current_int] = {
                "status": int_start.group(2),
                "mac_address": "",
                "speed": "",
                "duplex": "",
                "input_errors": 0,
                "crc": 0,
                "output_errors": 0,
                "description": "",
            }
            continue

        if not current_int:
            continue

        desc_match = re.search(r"[Dd]escription:\s*(.+)$", line)
        if desc_match:
            interfaces[current_int]["description"] = desc_match.group(1).strip()

        # Match hardware MAC address ONLY (never overwrite with "Internet address is x.x.x.x/y")
        if "internet address" not in line.lower():
            mac_match = re.search(
                r"address\s*(?:is|:)\s*([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})",
                line,
                re.IGNORECASE,
            )
            if mac_match and not interfaces[current_int]["mac_address"]:
                interfaces[current_int]["mac_address"] = (
                    mac_match.group(1).replace("-", "").replace(".", "").replace(":", "").lower()
                )

        # Match both IOS ("Full-duplex, 1000Mb/s") and NX-OS ("full-duplex, 10 Gb/s")
        sd_match = re.search(
            r"(\S+-duplex),\s*((?:\d+(?:\.\d+)?\s*(?:[GMK]?b/s|[GMK]?bps))|Auto-speed)",
            line,
            re.IGNORECASE,
        )
        if sd_match:
            interfaces[current_int]["duplex"] = sd_match.group(1).strip()
            interfaces[current_int]["speed"] = re.sub(r"\s+", "", sd_match.group(2).strip())

        ie_match = re.search(r"(\d+)\s+input\s+errors?,\s*(\d+)\s+CRC", line, re.IGNORECASE)
        if ie_match:
            interfaces[current_int]["input_errors"] = int(ie_match.group(1))
            interfaces[current_int]["crc"] = int(ie_match.group(2))
        else:
            ie_single = re.search(r"(\d+)\s+input\s+errors?\b", line, re.IGNORECASE)
            if ie_single:
                interfaces[current_int]["input_errors"] = int(ie_single.group(1))
            crc_single = re.search(r"(\d+)\s+CRC\b", line, re.IGNORECASE)
            if crc_single:
                interfaces[current_int]["crc"] = int(crc_single.group(1))

        oe_match = re.search(r"(\d+)\s+output\s+errors?\b", line, re.IGNORECASE)
        if oe_match:
            interfaces[current_int]["output_errors"] = int(oe_match.group(1))

    return interfaces


def classify_device_type(platform="", device_id="", capabilities="", model="", description="", **kwargs):
    """Classifies a network device type from its platform, hostname, model, or description string."""
    combined = f"{platform} {device_id} {capabilities} {model} {description}".lower()
    if any(k in combined for k in ["wlc", "wireless controller", "air-ct", "smartzone"]):
        return "wlc"
    if any(
        k in combined
        for k in [
            "air-ap",
            "c91",
            "ap-",
            "-ap",
            "aironet",
            "catalyst 91",
            "access point",
            "unifi ap",
            "instant ap",
            "air-",
        ]
    ):
        return "ap"
    if any(
        k in combined
        for k in ["asa", "firepower", "ftd", "palo", "forti", "firewall", "checkpoint", "sonicwall", "srx"]
    ):
        return "firewall"
    if any(k in combined for k in ["isr", "asr", "router", "c8000", "c8200", "c8300", "routerboard", "edgerouter"]):
        return "router"
    return "switch"


def parse_cdp_neighbors_detail(output, os_type="cisco_ios"):
    """
    Parses 'show cdp neighbors detail' output.
    Returns list of neighbor dicts:
    {"local_port": ..., "remote_device": ..., "remote_port": ..., "remote_ip": ..., "platform": ..., "device_type": ...}
    """
    output = clean_cli_output(output)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show cdp neighbors detail")
            if isinstance(structured, list):
                neighbors = []
                for entry in structured:
                    local_port = (
                        entry.get("LOCAL_PORT")
                        or entry.get("local_port")
                        or entry.get("LOCAL_INTERFACE")
                        or entry.get("local_interface")
                        or ""
                    )
                    dest_host = (
                        entry.get("DESTINATION_HOST")
                        or entry.get("destination_host")
                        or entry.get("neighbor_name")
                        or entry.get("device_id")
                        or ""
                    )
                    remote_port = (
                        entry.get("REMOTE_PORT")
                        or entry.get("remote_port")
                        or entry.get("neighbor_interface")
                        or entry.get("port_id")
                        or ""
                    )
                    remote_ip = (
                        entry.get("MANAGEMENT_IP")
                        or entry.get("management_ip")
                        or entry.get("mgmt_address")
                        or entry.get("entry_address")
                        or ""
                    )
                    platform = entry.get("PLATFORM") or entry.get("platform") or ""
                    caps = entry.get("CAPABILITIES") or entry.get("capabilities") or ""

                    if local_port:
                        neighbors.append(
                            {
                                "remote_device": str(dest_host).split(".")[0],
                                "remote_ip": str(remote_ip).strip(),
                                "local_port": str(local_port).strip(),
                                "remote_port": str(remote_port).strip(),
                                "platform": str(platform).strip(),
                                "device_type": classify_device_type(
                                    platform=str(platform),
                                    device_id=str(dest_host),
                                    capabilities=str(caps),
                                ),
                            }
                        )
                expected_cdp = len(re.findall(r"(?m)^\s*Device ID:", output))
                if neighbors and (expected_cdp == 0 or len(neighbors) >= expected_cdp):
                    return neighbors
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show cdp neighbors detail' (%s): %s", os_type, exc)

    # Regex Fallback
    neighbors = []
    current = {}

    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue

        device_match = re.match(r"^Device ID:\s*(\S+)", line)
        if device_match:
            if current and current.get("local_port"):
                current["device_type"] = classify_device_type(
                    platform=current.get("platform", ""),
                    device_id=current.get("remote_device", ""),
                    capabilities=current.pop("_capabilities", ""),
                )
                neighbors.append(current)
            current = {
                "remote_device": device_match.group(1).split(".")[0],
                "remote_ip": "",
                "local_port": "",
                "remote_port": "",
                "platform": "",
                "_capabilities": "",
            }
            continue

        if not current:
            continue

        ip_match = re.search(r"IP\s+address:\s*([0-9.]+)", line)
        if ip_match:
            current["remote_ip"] = ip_match.group(1)
            continue
        ipv4_match = re.search(r"IPv4\s+Address:\s*([0-9.]+)", line)
        if ipv4_match:
            current["remote_ip"] = ipv4_match.group(1)
            continue

        plat_match = re.search(r"Platform:\s*([^,]+)", line)
        if plat_match:
            current["platform"] = plat_match.group(1).strip()
            cap_match = re.search(r"Capabilities:\s*(.+)$", line, re.IGNORECASE)
            if cap_match:
                current["_capabilities"] = cap_match.group(1).strip()
            continue

        cap_only = re.search(r"^Capabilities:\s*(.+)$", line, re.IGNORECASE)
        if cap_only:
            current["_capabilities"] = cap_only.group(1).strip()
            continue

        ports_match = re.search(
            r"Interface:\s*([^,]+),\s*Port\s+ID\s+\(outgoing\s+port\):\s*(\S+)", line, re.IGNORECASE
        )
        if ports_match:
            current["local_port"] = ports_match.group(1).strip()
            current["remote_port"] = ports_match.group(2).strip()
            continue

    if current and current.get("local_port"):
        current["device_type"] = classify_device_type(
            platform=current.get("platform", ""),
            device_id=current.get("remote_device", ""),
            capabilities=current.pop("_capabilities", ""),
        )
        neighbors.append(current)

    return neighbors


def parse_lldp_neighbors_detail(output, os_type="cisco_ios"):
    """
    Parses 'show lldp neighbors detail' output.
    Returns list of neighbor dicts:
    {"local_port": ..., "remote_device": ..., "remote_port": ..., "remote_ip": ..., "remote_mac": ..., "platform": ..., "device_type": ...}
    """
    output = clean_cli_output(output)
    has_ip_hint = bool(
        re.search(r"(?:Management\s+Address|IPv4\s+Address|^\s*IP)\s*:\s*\d+\.\d+\.\d+\.\d+", output, re.M | re.I)
    )

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show lldp neighbors detail")
            if isinstance(structured, list):
                neighbors = []
                for entry in structured:
                    local_port = (
                        entry.get("LOCAL_INTERFACE") or entry.get("local_interface") or entry.get("local_port") or ""
                    )
                    sys_name = (
                        entry.get("SYSTEM_NAME")
                        or entry.get("system_name")
                        or entry.get("neighbor_name")
                        or entry.get("neighbor")
                        or entry.get("device_id")
                        or ""
                    )
                    remote_port = (
                        entry.get("NEIGHBOR_PORT")
                        or entry.get("neighbor_port_id")
                        or entry.get("neighbor_interface")
                        or entry.get("port_id")
                        or ""
                    )
                    remote_ip = (
                        entry.get("MANAGEMENT_ADDRESS") or entry.get("mgmt_address") or entry.get("management_ip") or ""
                    )
                    chassis_id = entry.get("CHASSIS_ID") or entry.get("chassis_id") or ""
                    desc = (
                        entry.get("SYSTEM_DESCRIPTION")
                        or entry.get("neighbor_description")
                        or entry.get("system_description")
                        or entry.get("platform")
                        or ""
                    )
                    caps = entry.get("CAPABILITIES") or entry.get("capabilities") or ""
                    if str(desc).strip().lower().startswith("management address"):
                        desc = ""
                    platform = str(desc).splitlines()[0][:60].strip() if desc else ""

                    if local_port or sys_name or chassis_id:
                        neighbors.append(
                            {
                                "local_port": str(local_port).strip(),
                                "remote_device": str(sys_name).split(".")[0].strip(),
                                "remote_port": str(remote_port).strip(),
                                "remote_ip": str(remote_ip).strip(),
                                "remote_mac": str(chassis_id).strip(),
                                "platform": platform,
                                "device_type": classify_device_type(
                                    platform=platform,
                                    device_id=str(sys_name),
                                    capabilities=_expand_lldp_capabilities(str(caps)),
                                    description=str(desc),
                                ),
                            }
                        )
                # Only accept TextFSM result if it did not drop management IPs present in raw output
                if neighbors and (not has_ip_hint or any(n.get("remote_ip") for n in neighbors)):
                    return neighbors
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show lldp neighbors detail' (%s): %s", os_type, exc)

    # Regex Fallback
    neighbors = []
    current = {}
    expect_sys_desc_next = False

    def _finalize_lldp(rec: dict) -> dict:
        caps_val = rec.pop("_capabilities", "")
        rec["device_type"] = classify_device_type(
            platform=rec.get("platform", ""),
            device_id=rec.get("remote_device", ""),
            capabilities=_expand_lldp_capabilities(caps_val),
        )
        return rec

    def _new_lldp_record(local_port: str = "", remote_device: str = "") -> dict:
        return {
            "local_port": local_port,
            "remote_device": remote_device,
            "remote_port": "",
            "remote_ip": "",
            "remote_mac": "",
            "platform": "",
            "_capabilities": "",
        }

    lines = output.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if re.match(r"^-{10,}$", line):
            expect_sys_desc_next = False
            if current and (current.get("local_port") or current.get("remote_device") or current.get("remote_mac")):
                neighbors.append(_finalize_lldp(current))
            current = {}
            continue

        if expect_sys_desc_next and current:
            expect_sys_desc_next = False
            if not re.match(
                r"^(?:Time\s+remaining|System\s+Capabilities|Enabled\s+Capabilities|Management|Auto\s+Negotiation|VLAN|Port)\b",
                line,
                re.IGNORECASE,
            ):
                current["platform"] = line[:60].strip()
                continue

        local_int_match = re.match(r"^Local\s+(?:Interface|Intf):\s*(\S+)", line, re.IGNORECASE)
        if local_int_match:
            if current and current.get("local_port"):
                neighbors.append(_finalize_lldp(current))
                current = {}
            if not current:
                current = _new_lldp_record(local_port=local_int_match.group(1))
            else:
                current["local_port"] = local_int_match.group(1)
            continue

        chassis_match = re.match(r"^Chassis\s+id:\s*(\S+)", line, re.IGNORECASE)
        if chassis_match:
            if current and (current.get("remote_device") or current.get("remote_mac")):
                neighbors.append(_finalize_lldp(current))
                current = {}
            if not current:
                current = _new_lldp_record()
            current["remote_mac"] = chassis_match.group(1)
            continue

        if not current:
            xr_dev_match = re.match(r"^System\s+Name:\s*(\S+)", line, re.IGNORECASE)
            if xr_dev_match:
                current = _new_lldp_record(remote_device=xr_dev_match.group(1).split(".")[0])
            continue

        sys_name_match = re.match(r"^System\s+Name:\s*(\S+)", line, re.IGNORECASE)
        if sys_name_match:
            current["remote_device"] = sys_name_match.group(1).split(".")[0]
            continue

        port_id_match = re.match(r"^Port\s+id:\s*(\S+)", line, re.IGNORECASE)
        if port_id_match:
            current["remote_port"] = port_id_match.group(1)
            continue

        ip_match = re.match(r"^(?:Management|IPv4)?\s*Address:\s*([0-9.]+)", line, re.IGNORECASE)
        if not ip_match:
            ip_match = re.match(r"^IP:\s*([0-9.]+)", line, re.IGNORECASE)
        if ip_match:
            current["remote_ip"] = ip_match.group(1)
            continue

        caps_match = re.match(r"^(?:Enabled|System)\s+Capabilities:\s*(.+)", line, re.IGNORECASE)
        if caps_match:
            val = caps_match.group(1).strip()
            # Prefer Enabled Capabilities when present
            if line.lower().startswith("enabled") or not current["_capabilities"]:
                current["_capabilities"] = val
            continue

        sys_desc_match = re.match(r"^System\s+Description:\s*(.*)$", line, re.IGNORECASE)
        if sys_desc_match:
            desc = sys_desc_match.group(1).strip()
            if desc:
                current["platform"] = desc[:60].strip()
            else:
                expect_sys_desc_next = True
            continue

    if current and (current.get("local_port") or current.get("remote_device") or current.get("remote_mac")):
        neighbors.append(_finalize_lldp(current))

    return neighbors


def parse_spanning_tree(output, os_type):
    """
    Parses 'show spanning-tree' or 'show spanning-tree summary'.
    Returns a dict with:
    {"enabled": True/False, "root_bridge": "Hostname/MAC of Root", "is_root": True/False,
     "protocol": ..., "bridge_priority": ..., "vlans": {...}}
    where vlans is mapping VLAN_ID -> {"role": ..., "status": ...} for interfaces
    """
    output = clean_cli_output(output)
    data = {
        "enabled": False,
        "root_bridge": "",
        "is_root": False,
        "protocol": "",
        "bridge_priority": "",
        "vlans": {},
    }

    if not output:
        return data

    output_lower = output.lower()
    if (
        _CLI_ERROR_RE.search(output)
        or "no spanning tree" in output_lower
        or "no spanning-tree" in output_lower
        or "spanning tree disabled" in output_lower
        or "spanning-tree disabled" in output_lower
        or "stp is disabled" in output_lower
    ):
        return data

    def _enrich_stp_metadata(target: dict) -> None:
        if "this bridge is the root" in output_lower or "we are the root" in output_lower:
            target["is_root"] = True

        m_proto = re.search(r"Spanning\s+tree\s+enabled\s+protocol\s+(\S+)", output, re.IGNORECASE)
        if not m_proto:
            m_proto = re.search(r"executing\s+the\s+(\S+)\s+compatible\s+Spanning\s+Tree", output, re.IGNORECASE)
        if m_proto and not target.get("protocol"):
            target["protocol"] = m_proto.group(1).strip()

        if not target.get("root_bridge"):
            root_mac_match = re.search(r"Root\s+ID.*?Address\s+([0-9a-fA-F.:-]+)", output, re.DOTALL | re.IGNORECASE)
            if not root_mac_match:
                root_mac_match = re.search(
                    r"Designated\s+root\s+has\s+priority\s+(\d+),\s*address\s+([0-9a-fA-F.:-]+)",
                    output,
                    re.IGNORECASE,
                )
                if root_mac_match:
                    target["root_bridge"] = root_mac_match.group(2).replace(".", "").replace(":", "").lower()
            else:
                target["root_bridge"] = root_mac_match.group(1).replace(".", "").replace(":", "").lower()

        if not target.get("root_bridge"):
            br_id_match = re.search(
                r"Bridge\s+Identifier\s+has\s+priority\s+(\d+),\s*address\s+([0-9a-fA-F.:-]+)",
                output,
                re.IGNORECASE,
            )
            if br_id_match:
                if not target.get("bridge_priority"):
                    target["bridge_priority"] = br_id_match.group(1)
                if target.get("is_root"):
                    target["root_bridge"] = br_id_match.group(2).replace(".", "").replace(":", "").lower()

        if not target.get("bridge_priority"):
            m_bprio = re.search(r"Bridge\s+ID\s+Priority\s+(\d+)", output, re.IGNORECASE)
            if not m_bprio:
                m_bprio = re.search(r"Bridge\s+Identifier\s+has\s+priority\s+(\d+)", output, re.IGNORECASE)
            if m_bprio:
                target["bridge_priority"] = m_bprio.group(1)

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            structured = get_structured_data(output, platform=os_type, command="show spanning-tree")
            if isinstance(structured, list) and structured:
                tf_data = {
                    "enabled": True,
                    "root_bridge": "",
                    "is_root": False,
                    "protocol": "",
                    "bridge_priority": "",
                    "vlans": {},
                }
                for entry in structured:
                    vlan_id = str(entry.get("VLAN_ID") or entry.get("vlan_id") or entry.get("vlan") or "1").strip()
                    if vlan_id not in tf_data["vlans"]:
                        tf_data["vlans"][vlan_id] = {}

                    root_mac = entry.get("ROOT_BRIDGE") or entry.get("root_mac") or ""
                    if root_mac:
                        tf_data["root_bridge"] = str(root_mac).replace(".", "").replace(":", "").lower()

                    port = str(entry.get("INTERFACE") or entry.get("interface") or "").strip()
                    role = str(entry.get("ROLE") or entry.get("role") or "").strip()
                    state = str(entry.get("STATUS") or entry.get("status") or entry.get("state") or "").strip()

                    if port:
                        tf_data["vlans"][vlan_id][port] = {"role": role, "state": state}
                _enrich_stp_metadata(tf_data)
                if tf_data["vlans"]:
                    return tf_data
        except Exception as exc:
            logger.warning("TextFSM parse failed for 'show spanning-tree' (%s): %s", os_type, exc)

    # Regex Fallback — require positive STP evidence
    if any(
        tok in output_lower
        for tok in (
            "spanning tree enabled",
            "spanning-tree enabled",
            "executing the",
            "root id",
            "bridge id",
            "bridge identifier",
        )
    ):
        data["enabled"] = True

    if not data["enabled"]:
        return data

    _enrich_stp_metadata(data)

    lines = output.splitlines()
    current_vlan = "1"

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped:
            continue

        vlan_match = re.search(r"^(?:vlan|mst)\s*(\d+)\b", line_stripped, re.IGNORECASE)
        if vlan_match:
            current_vlan = vlan_match.group(1)
            if current_vlan not in data["vlans"]:
                data["vlans"][current_vlan] = {}
            continue

        # 1. Detailed/Router format: " Port 2 (FastEthernet1) of VLAN1 is forwarding"
        det_match = re.search(
            r"Port\s+\d+\s+\(([^)]+)\)\s+of\s+VLAN\s*(\d+)\s+is\s+(\w+)", line_stripped, re.IGNORECASE
        )
        if det_match:
            port = det_match.group(1)
            vlan_id = det_match.group(2)
            state_str = det_match.group(3).lower()

            state = "FWD"
            if "forward" in state_str:
                state = "FWD"
            elif "block" in state_str:
                state = "BLK"
            elif "learn" in state_str:
                state = "LRN"
            elif "listen" in state_str:
                state = "LIS"
            elif "disable" in state_str:
                state = "DSB"

            role = "Desg"
            if vlan_id not in data["vlans"]:
                data["vlans"][vlan_id] = {}
            data["vlans"][vlan_id][port] = {"role": role, "state": state}
            continue

        # 2. Tabular format
        port_match = re.match(
            r"^([A-Za-z0-9/.-]+)\s+(Root|Desg|Altn|Back)\s+(FWD|BLK|LRN|LIS|DSB)\s+(\d+)", line_stripped
        )
        if port_match:
            port = port_match.group(1)
            role = port_match.group(2)
            state = port_match.group(3)
            if current_vlan not in data["vlans"]:
                data["vlans"][current_vlan] = {}
            data["vlans"][current_vlan][port] = {"role": role, "state": state}

    return data


def parse_show_ip_route(output, os_type):
    """
    Parses routing table (IOS, IOS-XE, NX-OS, IOS-XR).
    Returns list of dicts: {"subnet": ..., "protocol": ..., "next_hop": ..., "interface": ...}
    """
    output = clean_cli_output(output)
    if not output or _CLI_ERROR_RE.search(output):
        return []

    # Try TextFSM parsing first
    if get_structured_data:
        try:
            cmd = "show route" if os_type == "cisco_xr" else "show ip route"
            structured = get_structured_data(output, platform=os_type, command=cmd)
            if isinstance(structured, list):
                routes = []
                for entry in structured:
                    network = str(entry.get("NETWORK") or entry.get("network") or "").strip()
                    mask = str(entry.get("NETMASK") or entry.get("mask") or entry.get("prefix_length") or "").strip()
                    prefix = network
                    if mask and "/" not in prefix and prefix:
                        prefix = f"{network}/{mask}"

                    raw_proto = str(entry.get("PROTOCOL") or entry.get("protocol") or "").strip()
                    proto = _normalize_route_proto(raw_proto)
                    nexthop = str(
                        entry.get("NEXTHOP_IP") or entry.get("nexthop_ip") or entry.get("nexthop") or ""
                    ).strip()
                    interface = str(
                        entry.get("NEXTHOP_IF") or entry.get("nexthop_if") or entry.get("interface") or ""
                    ).strip()

                    if prefix:
                        routes.append(
                            {
                                "subnet": prefix,
                                "protocol": proto,
                                "next_hop": nexthop or "Directly Connected",
                                "interface": interface,
                            }
                        )
                if routes:
                    return routes
        except Exception as exc:
            logger.warning("TextFSM parse failed for routing table (%s): %s", os_type, exc)

    # Regex Fallback
    routes = []
    lines = output.splitlines()
    parent_mask = ""
    nxos_cur_subnet = ""
    gateway_last_resort = ""

    def _extract_tail_interface(tail: str) -> str:
        """Return interface token from comma-separated route tail, ignoring uptimes like 4w2d or 01:23:45."""
        if not tail:
            return ""
        for raw_part in reversed(tail.split(",")):
            tok = raw_part.strip()
            if not tok or _UPTIME_TOKEN_RE.match(tok):
                continue
            if re.match(r"^[A-Za-z][A-Za-z0-9/._:-]*$", tok):
                return tok
        return ""

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        # Track parent classful mask (e.g. "172.16.0.0/24 is subnetted, 2 subnets")
        m_sub = re.match(r"^\d+\.\d+\.\d+\.\d+/(\d+)\s+is\s+(variably\s+)?subnetted", line, re.IGNORECASE)
        if m_sub:
            parent_mask = "" if m_sub.group(2) else m_sub.group(1)
            nxos_cur_subnet = ""
            continue

        # Capture Gateway of last resort as fallback default route
        m_gw = re.match(
            r"^Gateway\s+of\s+last\s+resort\s+is\s+(\d+\.\d+\.\d+\.\d+)\s+to\s+network\s+0\.0\.0\.0", line, re.I
        )
        if m_gw:
            gateway_last_resort = m_gw.group(1)
            continue

        # NX-OS header: "10.0.0.0/24, ubest/mbest: 1/0"
        nx_hdr = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+),\s*ubest/mbest", line)
        if nx_hdr:
            nxos_cur_subnet = nx_hdr.group(1)
            continue

        # NX-OS next-hop line: "*via 10.0.0.1, Eth1/1, [1/0], 2w1d, static"
        if nxos_cur_subnet:
            nx_via = re.match(
                r"^\*?via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s*([^,\[]+))?,\s*\[\d+/\d+\],\s*[^,]+,\s*(\S+)",
                line,
                re.IGNORECASE,
            )
            if nx_via:
                nh_ip = nx_via.group(1).strip()
                intf = (nx_via.group(2) or "").strip()
                proto_raw = nx_via.group(3).strip().rstrip(",")
                routes.append(
                    {
                        "subnet": nxos_cur_subnet,
                        "protocol": _normalize_route_proto(proto_raw),
                        "next_hop": "Directly Connected" if proto_raw.lower() in ("direct", "local") else nh_ip,
                        "interface": intf,
                    }
                )
                continue

        # Directly connected (IOS / IOS-XE / IOS-XR, with optional uptime before interface)
        conn_match = re.match(
            r"^([CL])\s+(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+is\s+directly\s+connected,\s*(.+)$",
            line,
        )
        if conn_match:
            nxos_cur_subnet = ""
            subnet = conn_match.group(2)
            if "/" not in subnet and parent_mask:
                subnet = f"{subnet}/{parent_mask}"
            routes.append(
                {
                    "subnet": subnet,
                    "protocol": "Connected" if conn_match.group(1) == "C" else "Local",
                    "next_hop": "Directly Connected",
                    "interface": _extract_tail_interface(conn_match.group(3)),
                }
            )
            continue

        # Routed entry (handles S*, O*E2, O IA, O E1/E2, D EX, B*, i L1/L2, etc.)
        route_match = re.match(
            r"^([ODBRLS*i](?:\*|\s*(?:IA|E1|E2|N1|N2|EX|L1|L2|\*E1|\*E2|\*IA|\*L1|\*L2))?)\s+"
            r"(\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+\[\d+/\d+\]\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s*(.+))?$",
            line,
        )
        if route_match:
            nxos_cur_subnet = ""
            subnet = route_match.group(2)
            if "/" not in subnet and parent_mask:
                subnet = f"{subnet}/{parent_mask}"
            routes.append(
                {
                    "subnet": subnet,
                    "protocol": _normalize_route_proto(route_match.group(1)),
                    "next_hop": route_match.group(3),
                    "interface": _extract_tail_interface(route_match.group(4) or ""),
                }
            )
            continue

        dgw_match = re.match(r"^Default gateway is\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
        if dgw_match:
            routes.append(
                {
                    "subnet": "0.0.0.0/0",
                    "protocol": "Default",
                    "next_hop": dgw_match.group(1),
                    "interface": "",
                }
            )

    if gateway_last_resort and not any(r.get("subnet") == "0.0.0.0/0" for r in routes):
        routes.append(
            {
                "subnet": "0.0.0.0/0",
                "protocol": "Default",
                "next_hop": gateway_last_resort,
                "interface": "",
            }
        )

    return routes


def parse_services(running_config):
    """
    Parses running config to extract Layer 4-7 services configuration.
    Returns dict:
    {"dns_servers": [...], "ntp_servers": [...], "radius_servers": [...], "tacacs_servers": [...]}
    """
    services = {"dns_servers": [], "ntp_servers": [], "radius_servers": [], "tacacs_servers": []}

    lines = running_config.splitlines()
    for line in lines:
        line = line.strip()

        dns_match = re.match(r"^ip\s+name-server\s+(.+)$", line)
        if dns_match:
            servers = dns_match.group(1).split()
            services["dns_servers"].extend([s for s in servers if re.match(r"^[0-9.]+$", s)])

        ntp_match = re.match(r"^ntp\s+server\s+(\S+)", line)
        if ntp_match:
            services["ntp_servers"].append(ntp_match.group(1))

        rad_match = re.search(r"radius-server\s+host\s+(\S+)", line)
        if not rad_match:
            rad_match = re.search(r"radius\s+server\s+host\s+(\S+)", line)
        if rad_match:
            services["radius_servers"].append(rad_match.group(1))

        tac_match = re.search(r"tacacs-server\s+host\s+(\S+)", line)
        if not tac_match:
            tac_match = re.search(r"tacacs\s+server\s+host\s+(\S+)", line)
        if tac_match:
            services["tacacs_servers"].append(tac_match.group(1))

    for key in services:
        services[key] = list(set(services[key]))

    return services


def parse_show_ip_arp(output, os_type="cisco_ios"):
    """
    Parses 'show ip arp' or 'show arp' (IOS, NX-OS, IOS-XR).
    Extracts active L2/L3 adjacency mappings: IP address, MAC address, Age, Interface.
    Returns list of dicts:
    [{"ip": ..., "mac": ..., "age": ..., "interface": ..., "vendor": ...}, ...]
    """
    import oui_lookup

    output = clean_cli_output(output)
    entries = []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(("Protocol", "Address", "%", "^")) or _CLI_ERROR_RE.search(line):
            continue

        ip_match = re.search(r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", line)
        mac_match = _MAC_TOKEN_RE.search(line)

        if ip_match and mac_match:
            ip = ip_match.group(1)
            raw_mac = mac_match.group(1)
            norm_mac = oui_lookup.normalize_mac(raw_mac)
            vendor = oui_lookup.get_vendor(norm_mac)

            tokens = line.split()
            intf = tokens[-1] if tokens else "Unknown"

            entries.append({"ip": ip, "mac": norm_mac, "interface": intf, "vendor": vendor})

    return entries


def parse_mac_address_table(output, os_type="cisco_ios"):
    """
    Parses 'show mac address-table' or 'show mac-address-table' (IOS, IOS-XE, NX-OS).
    Returns list of dicts:
    [{"vlan": ..., "mac": ..., "type": ..., "port": ..., "interface": ..., "vendor": ...}, ...]
    """
    import oui_lookup

    output = clean_cli_output(output)
    entries = []

    for line in output.splitlines():
        line = line.strip()
        if (
            not line
            or "Vlan" in line
            or "VLAN" in line
            or "Mac Address" in line
            or "MAC Address" in line
            or line.startswith(("---", "%", "^"))
            or "Total" in line
            or _CLI_ERROR_RE.search(line)
        ):
            continue

        mac_match = _MAC_TOKEN_RE.search(line)
        if not mac_match:
            continue

        tokens = line.split()
        # Strip leading NX-OS / Cat4500/6500 entry flags (*, +, G, C, R, O, -)
        if tokens and tokens[0] in ("*", "+", "G", "C", "R", "O", "-"):
            tokens = tokens[1:]
        if len(tokens) < 4:
            continue

        raw_mac = mac_match.group(1)
        try:
            mac_idx = tokens.index(raw_mac)
        except ValueError:
            continue
        if mac_idx < 1 or mac_idx + 1 >= len(tokens):
            continue

        vlan = tokens[mac_idx - 1]
        mtype = tokens[mac_idx + 1].lower()
        port = tokens[-1]
        if port.lower() in ("cpu", "self", "drop", "router", "switch") or port.lower().startswith("sup-eth"):
            continue
        norm_mac = oui_lookup.normalize_mac(raw_mac)
        vendor = oui_lookup.get_vendor(norm_mac)
        entries.append(
            {
                "vlan": vlan,
                "mac": norm_mac,
                "type": mtype,
                "port": port,
                "interface": port,
                "vendor": vendor,
            }
        )

    return entries

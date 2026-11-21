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
Juniper Networks Driver: JunOS EX, QFX, MX, and SRX platforms.
Utilizes Junos native JSON structured outputs (`| display json`) with robust CLI fallbacks.
Official Documentation: https://www.juniper.net/documentation/product/us/en/junos-os/
"""

import json
import logging
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

logger = logging.getLogger(__name__)

# Internal Junos control-plane, PFE fabric, and tunnel pseudo-devices excluded from physical port counts
JUNOS_INTERNAL_INTERFACES = (
    "bme",
    "cbp",
    "dsc",
    "em",
    "esi",
    "fti",
    "gre",
    "ipip",
    "jsrv",
    "lo0",
    "lsi",
    "mtun",
    "pfe-",
    "pfh-",
    "pimd",
    "pime",
    "pip",
    "tap",
    "vme",
    "vtep",
)


def _is_junos_internal_interface(name: str) -> bool:
    base = name.split(".")[0].lower()
    return base.startswith(JUNOS_INTERNAL_INTERFACES)


class JuniperDriver(BaseDriver):
    vendor_name = "Juniper Networks"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "set cli screen-length 0"

    def connect(self):
        device = self._build_netmiko_params("juniper_junos", global_delay_factor=2)
        return self.connect_netmiko(device)

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Juniper Device",
            "serial": "Unknown",
            "firmware": "JunOS",
            "os_type": "juniper_junos",
            "device_persona": self.device_persona,
        }

        # Try structured JSON first
        try:
            raw = conn.send_command("show version | display json")
            data = json.loads(raw)
            if "multi-routing-engine-results" in data:
                items = data.get("multi-routing-engine-results", [{}])[0].get("multi-routing-engine-item", [])
                sw_info = items[0].get("software-information", [{}])[0] if items else {}
            else:
                sw_info = data.get("software-information", [{}])[0]

            info["hostname"] = sw_info.get("host-name", [{}])[0].get("data", "")
            info["firmware"] = sw_info.get("junos-version", [{}])[0].get("data", "")
            info["model"] = sw_info.get("product-model", [{}])[0].get("data", "")
        except Exception as exc:
            logger.debug("[%s] Junos show version | display json failed, falling back to text: %s", self.ip, exc)
            raw = conn.send_command("show version")
            m_host = re.search(r"Hostname:\s+(\S+)", raw)
            if m_host:
                info["hostname"] = m_host.group(1)
            m_model = re.search(r"Model:\s+(\S+)", raw)
            if m_model:
                info["model"] = m_model.group(1)
            m_ver = re.search(r"Junos:\s+(\S+)", raw)
            if not m_ver:
                m_ver = re.search(r"JUNOS\s+(?:Base OS boot|Software Release)\s+\[([^\]]+)\]", raw, re.IGNORECASE)
            if m_ver:
                info["firmware"] = m_ver.group(1)

        if "srx" in info["model"].lower():
            info["device_persona"] = "firewall"
            info["device_type"] = "firewall"
        elif "mx" in info["model"].lower():
            info["device_persona"] = "router"
            info["device_type"] = "router"

        # Retrieve chassis serial number
        try:
            raw_hw = conn.send_command("show chassis hardware | display json")
            hw_data = json.loads(raw_hw)
            chassis = hw_data.get("chassis-inventory", [{}])[0].get("chassis", [{}])[0]
            sn = chassis.get("serial-number", [{}])[0].get("data", "")
            desc = chassis.get("description", [{}])[0].get("data", "")
            if sn:
                info["serial"] = sn
            if desc and info["model"] == "Juniper Device":
                info["model"] = desc
        except Exception as exc:
            logger.debug(
                "[%s] Junos show chassis hardware | display json failed, falling back to text: %s", self.ip, exc
            )
            raw_hw = conn.send_command("show chassis hardware")
            m_sn = re.search(r"Chassis\s+(\S+)", raw_hw)
            if m_sn:
                info["serial"] = m_sn.group(1)

        # Retrieve base chassis MAC so remote routed crawls don't depend on local ARP
        try:
            raw_mac = conn.send_command("show chassis mac-addresses")
            m_mac = re.search(r"(?:Base|Public base)\s+address\s+([0-9a-fA-F:]{17})", raw_mac, re.IGNORECASE)
            if m_mac:
                info["mac_address"] = oui_lookup.normalize_mac(m_mac.group(1)).lower()
        except Exception as exc:
            logger.debug("[%s] Junos show chassis mac-addresses failed: %s", self.ip, exc)

        if not info["hostname"]:
            info["hostname"] = conn.find_prompt().split("@")[-1].replace(">", "").replace("#", "").strip()

        self._model = info.get("model", "")
        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}

        try:
            raw = conn.send_command("show interfaces terse | display json")
            data = json.loads(raw)
            int_list = data.get("interface-information", [{}])[0].get("physical-interface", [])
            for intf in int_list:
                name = intf.get("name", [{}])[0].get("data", "")
                if not name or _is_junos_internal_interface(name):
                    continue

                admin_status = intf.get("admin-status", [{}])[0].get("data", "down").lower()
                oper_status = intf.get("oper-status", [{}])[0].get("data", "down").lower()

                # Only include physical switch/router interfaces (ge-*, xe-*, et-*, ae*) in physical port detail
                if re.match(r"^(?:ge-|xe-|et-|fe-|ae\d|irb)", name):
                    default_speed = (
                        "10Gb/s"
                        if name.startswith("xe-")
                        else (
                            "40Gb/s" if name.startswith("et-") else ("100Mb/s" if name.startswith("fe-") else "1Gb/s")
                        )
                    )
                    interfaces_detail[name] = {
                        "status": oper_status,
                        "protocol": oper_status,
                        "admin_status": admin_status,
                        "description": "",
                        "mac_address": "",
                        "speed": default_speed,
                        "duplex": "Full",
                    }

                # Logical interfaces (SVIs / irb.0, routed units, IP addresses)
                logical_list = intf.get("logical-interface", [])
                for log_int in logical_list:
                    log_name = log_int.get("name", [{}])[0].get("data", "")
                    if _is_junos_internal_interface(log_name):
                        continue
                    log_oper = log_int.get("oper-status", [{}])[0].get("data", oper_status).lower()
                    for fam in log_int.get("address-family", []):
                        fam_name = fam.get("address-family-name", [{}])[0].get("data", "")
                        if fam_name and fam_name != "inet":
                            continue
                        for addr in fam.get("interface-address", []):
                            ip_str = addr.get("ifa-local", [{}])[0].get("data", "").strip()
                            ip_dest = addr.get("ifa-destination", [{}])[0].get("data", "").strip()
                            if not ip_str or ip_str.startswith(("127.", "128.0.")):
                                continue
                            # Attach prefix length from ifa-destination (e.g. 192.168.1.0/24 -> /24) if missing
                            if "/" not in ip_str and "/" in ip_dest:
                                prefix_len = ip_dest.split("/", 1)[1]
                                ip_str = f"{ip_str}/{prefix_len}"
                            l3_interfaces.append(
                                {
                                    "interface": log_name or name,
                                    "ip_address": ip_str,
                                    "status": log_oper,
                                    "protocol": log_oper,
                                }
                            )
        except Exception as exc:
            logger.debug(
                "[%s] Junos show interfaces terse | display json failed, falling back to text: %s", self.ip, exc
            )
            raw = conn.send_command("show interfaces terse")
            for line in raw.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[0]
                    if _is_junos_internal_interface(name):
                        continue
                    admin = parts[1].lower()
                    oper = parts[2].lower()
                    if "." not in name and re.match(r"^(?:ge-|xe-|et-|fe-|ae\d)", name):
                        interfaces_detail[name] = {
                            "status": oper,
                            "protocol": oper,
                            "admin_status": admin,
                            "description": "",
                            "mac_address": "",
                            "speed": "1Gb/s",
                            "duplex": "Full",
                        }
                    elif "." in name and len(parts) >= 5 and parts[3] == "inet":
                        ip_val = parts[-1]
                        if re.match(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$", ip_val) and not ip_val.startswith(
                            ("127.", "128.0.")
                        ):
                            l3_interfaces.append(
                                {
                                    "interface": name,
                                    "ip_address": ip_val,
                                    "status": oper,
                                    "protocol": oper,
                                }
                            )

        # Enrich up physical interfaces with input/output error counters (`show interfaces`)
        try:
            err_raw = conn.send_command("show interfaces")
            cur_if = ""
            for line in err_raw.splitlines():
                m_if = re.match(r"^\s*Physical interface:\s*([A-Za-z0-9/\._-]+)", line)
                if m_if:
                    cur_if = m_if.group(1)
                    continue
                if cur_if and cur_if in interfaces_detail:
                    m_in = re.search(r"Input errors:\s*(\d+)", line, re.IGNORECASE)
                    m_out = re.search(r"Output errors:\s*(\d+)", line, re.IGNORECASE)
                    if m_in:
                        interfaces_detail[cur_if]["input_errors"] = int(m_in.group(1))
                    if m_out:
                        interfaces_detail[cur_if]["output_errors"] = int(m_out.group(1))
        except Exception as exc:
            logger.debug("[%s] Junos show interfaces error counters failed: %s", self.ip, exc)

        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("show lldp neighbors detail | display json")
            data = json.loads(raw)
            neigh_list = data.get("lldp-neighbors-information", [{}])[0].get("lldp-neighbor-information", [])
            for n in neigh_list:
                # Prefer physical interface name (e.g. ge-0/0/3.0 -> ge-0/0/3) over numeric SNMP port index (515)
                local_intf = (
                    n.get("lldp-local-interface", [{}])[0].get("data", "")
                    or n.get("lldp-local-parent-interface-name", [{}])[0].get("data", "")
                    or n.get("lldp-local-port-id", [{}])[0].get("data", "")
                )
                local_port = re.sub(r"\.0$", "", local_intf.strip())
                remote_dev = n.get("lldp-remote-system-name", [{}])[0].get("data", "")
                if not remote_dev:
                    remote_dev = n.get("lldp-remote-chassis-id", [{}])[0].get("data", "Unknown")
                remote_port = n.get("lldp-remote-port-id", [{}])[0].get("data", "")
                remote_ip = n.get("lldp-remote-management-address", [{}])[0].get("data", "")
                remote_sys = n.get("lldp-remote-system-description", [{}])[0].get("data", "")
                remote_caps = n.get("lldp-remote-system-capabilities-enabled", [{}])[0].get("data", "") or n.get(
                    "lldp-remote-system-capabilities-supported", [{}]
                )[0].get("data", "")
                remote_mac = n.get("lldp-remote-chassis-id", [{}])[0].get("data", "")

                norm_mac = oui_lookup.normalize_mac(remote_mac or remote_port)
                mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"

                sys_low = remote_sys.lower()
                caps_low = remote_caps.lower()
                vendor_low = mac_vendor.lower() if mac_vendor != "Unknown" else ""

                dev_type = "switch"
                if (
                    any(k in sys_low for k in ["ap", "access point", "aruba", "unifi", "instant", "wlan"])
                    or any(k in caps_low for k in ["wlan", "access point"])
                    or (not sys_low and any(v in vendor_low for v in ["aruba", "ubiquiti", "ruckus", "meraki"]))
                ):
                    dev_type = "ap"
                elif any(k in sys_low for k in ["firewall", "srx", "palo", "forti", "opnsense"]):
                    dev_type = "firewall"
                elif any(k in sys_low for k in ["router", "ios software", "routeros", "frrouting"]) or (
                    "router" in caps_low and "bridge" not in caps_low
                ):
                    dev_type = "router"

                plat_short = remote_sys[:60].strip()
                if not plat_short and mac_vendor != "Unknown":
                    plat_short = f"{mac_vendor} AP" if dev_type == "ap" else mac_vendor

                neighbors.append(
                    {
                        "local_port": local_port,
                        "remote_device": remote_dev,
                        "remote_port": remote_port,
                        "remote_ip": remote_ip,
                        "remote_mac": remote_mac,
                        "platform": plat_short,
                        "remote_platform": plat_short,
                        "device_type": dev_type,
                    }
                )
        except Exception as exc:
            logger.debug(
                "[%s] Junos show lldp neighbors detail | display json failed, falling back to text: %s", self.ip, exc
            )
            raw = conn.send_command("show lldp neighbors detail")
            blocks = raw.split("Local Interface:")
            for b in blocks[1:]:
                m_port = re.match(r"\s*(\S+)", b)
                m_sys = re.search(r"System name\s*:\s*(\S+)", b)
                m_chassis = re.search(r"Chassis\s+(?:id|ID)\s*:\s*(\S+)", b)
                m_ip = re.search(r"Management address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", b)
                m_rem_port = re.search(r"Port id\s*:\s*(\S+)", b, re.IGNORECASE)
                m_desc = re.search(r"System description\s*:\s*(.+)", b)
                m_caps = re.search(r"System capabilities\s*:\s*(.+)", b)
                if m_port and (m_sys or m_chassis):
                    local_port = re.sub(r"\.0$", "", m_port.group(1).rstrip(","))
                    remote_mac = m_chassis.group(1).strip() if m_chassis else ""
                    remote_dev = m_sys.group(1) if m_sys else remote_mac
                    norm_mac = oui_lookup.normalize_mac(remote_mac) if remote_mac else ""
                    mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                    plat = m_desc.group(1).strip()[:60] if m_desc else ""
                    caps_low = m_caps.group(1).lower() if m_caps else ""
                    vendor_low = mac_vendor.lower() if mac_vendor != "Unknown" else ""

                    dev_type = "switch"
                    if (
                        any(k in plat.lower() for k in ["ap", "aruba", "unifi", "instant", "wlan", "access point"])
                        or any(k in caps_low for k in ["wlan", "access point"])
                        or (not plat and any(v in vendor_low for v in ["aruba", "ubiquiti", "ruckus", "meraki"]))
                    ):
                        dev_type = "ap"
                    if not plat and mac_vendor != "Unknown":
                        plat = f"{mac_vendor} AP" if dev_type == "ap" else mac_vendor
                    elif not plat:
                        plat = "JunOS-Discovered"

                    neighbors.append(
                        {
                            "local_port": local_port,
                            "remote_device": remote_dev,
                            "remote_port": m_rem_port.group(1) if m_rem_port else "Unknown",
                            "remote_ip": m_ip.group(1) if m_ip else "",
                            "remote_mac": remote_mac,
                            "platform": plat,
                            "remote_platform": plat,
                            "device_type": dev_type,
                        }
                    )

        # Fallback for Junos 17.x/18.x ELS platforms where `show lldp neighbors detail` is unsupported
        if not neighbors:
            try:
                raw_sum = conn.send_command("show lldp neighbors | display json")
                data_sum = json.loads(raw_sum)
                neigh_list = data_sum.get("lldp-neighbors-information", [{}])[0].get("lldp-neighbor-information", [])
                for n in neigh_list:
                    local_intf = n.get("lldp-local-interface", [{}])[0].get("data", "") or n.get(
                        "lldp-local-port-id", [{}]
                    )[0].get("data", "")
                    local_port = re.sub(r"\.0$", "", local_intf.strip())
                    remote_mac = n.get("lldp-remote-chassis-id", [{}])[0].get("data", "")
                    remote_dev = n.get("lldp-remote-system-name", [{}])[0].get("data", "") or remote_mac or "Unknown"
                    remote_port = (
                        n.get("lldp-remote-port-description", [{}])[0].get("data", "")
                        or n.get("lldp-remote-port-info", [{}])[0].get("data", "")
                        or n.get("lldp-remote-port-id", [{}])[0].get("data", "")
                    )
                    norm_mac = oui_lookup.normalize_mac(remote_mac or remote_port)
                    mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                    dev_type = (
                        "ap"
                        if any(v in mac_vendor.lower() for v in ["aruba", "ubiquiti", "ruckus", "meraki"])
                        else "switch"
                    )
                    plat = (
                        f"{mac_vendor} AP"
                        if (dev_type == "ap" and mac_vendor != "Unknown")
                        else (mac_vendor if mac_vendor != "Unknown" else "JunOS-Discovered")
                    )
                    if local_port:
                        neighbors.append(
                            {
                                "local_port": local_port,
                                "remote_device": remote_dev,
                                "remote_port": remote_port or "Unknown",
                                "remote_ip": "",
                                "remote_mac": remote_mac,
                                "platform": plat,
                                "remote_platform": plat,
                                "device_type": dev_type,
                            }
                        )
            except Exception as exc:
                logger.debug(
                    "[%s] Junos show lldp neighbors | display json failed, falling back to text: %s", self.ip, exc
                )
                try:
                    raw_sum_txt = conn.send_command("show lldp neighbors")
                    for line in raw_sum_txt.splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and re.match(r"^(?:ge-|xe-|et-|fe-|ae\d)", parts[0]):
                            local_port = re.sub(r"\.0$", "", parts[0])
                            remote_mac = parts[2]
                            remote_port = parts[3]
                            remote_dev = parts[4]
                            norm_mac = oui_lookup.normalize_mac(remote_mac)
                            mac_vendor = oui_lookup.lookup_oui(norm_mac) if norm_mac else "Unknown"
                            neighbors.append(
                                {
                                    "local_port": local_port,
                                    "remote_device": remote_dev,
                                    "remote_port": remote_port,
                                    "remote_ip": "",
                                    "remote_mac": remote_mac,
                                    "platform": mac_vendor if mac_vendor != "Unknown" else "JunOS-Discovered",
                                    "remote_platform": mac_vendor if mac_vendor != "Unknown" else "JunOS-Discovered",
                                    "device_type": "switch",
                                }
                            )
                except Exception as txt_exc:
                    logger.debug("[%s] Junos show lldp neighbors text fallback failed: %s", self.ip, txt_exc)

        return neighbors

    def get_stp(self, conn) -> dict:
        stp = {
            "enabled": False,
            "is_root": False,
            "protocol": "Unknown",
            "root_bridge": "",
            "bridge_id": "",
            "bridge_priority": "",
            "root_cost": "",
            "root_port": "",
            "vlans": {},
        }
        try:
            raw = conn.send_command("show spanning-tree bridge | display json")
            if raw.strip().startswith("{"):
                data = json.loads(raw)
                # Junos ELS schema: {"stp-bridge": [{"protocol": [...], "cist-bridge-parameters": [...]}]}
                stp_bridge = data.get("stp-bridge", [])
                if stp_bridge:
                    blk = stp_bridge[0]
                    stp["enabled"] = True
                    stp["protocol"] = blk.get("protocol", [{}])[0].get("data", "RSTP")
                    cist = blk.get("cist-bridge-parameters", [{}])[0]
                    rb = cist.get("root-bridge", [{}])[0]
                    rb_prio = rb.get("bridge-priority", [{}])[0].get("data", "")
                    rb_mac = rb.get("bridge-mac", [{}])[0].get("data", "")
                    if rb_mac:
                        stp["root_bridge"] = f"{rb_prio}.{rb_mac}".strip(".") if rb_prio else rb_mac
                    stp["root_cost"] = cist.get("root-cost", [{}])[0].get("data", "")
                    stp["root_port"] = cist.get("root-port", [{}])[0].get("data", "")
                    tb = cist.get("this-bridge", [{}])[0]
                    tb_prio = tb.get("bridge-priority", [{}])[0].get("data", "")
                    tb_mac = tb.get("bridge-mac", [{}])[0].get("data", "")
                    if tb_prio:
                        stp["bridge_priority"] = tb_prio
                    if tb_mac:
                        stp["bridge_id"] = f"{tb_prio}.{tb_mac}".strip(".") if tb_prio else tb_mac
                    if rb_mac and tb_mac and rb_mac.lower() == tb_mac.lower():
                        stp["is_root"] = True
                    return stp
                stp_info = data.get("stp-bridge-parameters-information", [])
                if stp_info:
                    stp["enabled"] = True
                    raw_str = json.dumps(stp_info).lower()
                    if "this bridge is the root" in raw_str:
                        stp["is_root"] = True
                    return stp
        except Exception as exc:
            logger.debug("[%s] Junos show spanning-tree bridge | display json failed: %s", self.ip, exc)

        try:
            raw_txt = conn.send_command("show spanning-tree bridge")
            low = raw_txt.lower()
            if "stp bridge parameters" in low or "enabled protocol" in low:
                stp["enabled"] = True
                m_proto = re.search(r"Enabled protocol\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                if m_proto:
                    stp["protocol"] = m_proto.group(1).strip()
                m_root = re.search(r"Root ID\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                m_bridge = re.search(r"Bridge ID\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                m_cost = re.search(r"Root cost\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                m_port = re.search(r"Root port\s*:\s*(\S+)", raw_txt, re.IGNORECASE)
                if m_root:
                    stp["root_bridge"] = m_root.group(1).strip()
                if m_bridge:
                    stp["bridge_id"] = m_bridge.group(1).strip()
                    if "." in stp["bridge_id"]:
                        stp["bridge_priority"] = stp["bridge_id"].split(".", 1)[0]
                if m_cost:
                    stp["root_cost"] = m_cost.group(1).strip()
                if m_port:
                    stp["root_port"] = m_port.group(1).strip()
                if "this bridge is the root" in low or (m_root and m_bridge and m_root.group(1) == m_bridge.group(1)):
                    stp["is_root"] = True
        except Exception as exc:
            logger.debug("[%s] Junos show spanning-tree bridge text fallback failed: %s", self.ip, exc)
        return stp

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show route | display json")
            data = json.loads(raw)
            tables = data.get("route-information", [{}])[0].get("route-table", [])
            for t in tables:
                t_name = t.get("table-name", [{}])[0].get("data", "inet.0")
                if not t_name.endswith("inet.0"):
                    continue
                for r in t.get("rt", []):
                    dest = r.get("rt-destination", [{}])[0].get("data", "")
                    if dest.startswith("128.0.") or dest == "224.0.0.5/32":
                        continue
                    entry = r.get("rt-entry", [{}])[0]
                    proto = entry.get("protocol-name", [{}])[0].get("data", "")
                    nh = entry.get("nh", [{}])[0]
                    via = nh.get("to", [{}])[0].get("data", "Directly Connected")
                    nh_if = nh.get("via", [{}])[0].get("data", "")
                    routes.append({"subnet": dest, "protocol": proto, "next_hop": via, "interface": nh_if})
        except Exception as exc:
            logger.debug("[%s] Junos show route | display json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_txt = conn.send_command("show route table inet.0")
                cur_dest = ""
                cur_proto = ""
                for line in raw_txt.splitlines():
                    m_dest = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+\*?\[([A-Za-z0-9_-]+)/\d+\]", line.strip())
                    if m_dest:
                        cur_dest = m_dest.group(1)
                        cur_proto = m_dest.group(2)
                        if cur_dest.startswith("128.0.") or cur_dest == "224.0.0.5/32":
                            cur_dest = ""
                        continue
                    if cur_dest:
                        m_nh = re.search(r"(?:to\s+(\d+\.\d+\.\d+\.\d+)\s+)?via\s+(\S+)", line)
                        if m_nh:
                            routes.append(
                                {
                                    "subnet": cur_dest,
                                    "protocol": cur_proto,
                                    "next_hop": m_nh.group(1) or "Directly Connected",
                                    "interface": m_nh.group(2),
                                }
                            )
                            cur_dest = ""
            except Exception as txt_exc:
                logger.debug("[%s] Junos show route table inet.0 text fallback failed: %s", self.ip, txt_exc)
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("show arp no-resolve | display json")
            data = json.loads(raw)
            entries = data.get("arp-table-information", [{}])[0].get("arp-table-entry", [])
            for e in entries:
                ip_addr = e.get("ip-address", [{}])[0].get("data", "")
                mac_addr = e.get("mac-address", [{}])[0].get("data", "")
                intf = e.get("interface-name", [{}])[0].get("data", "")
                if ip_addr and mac_addr and not ip_addr.startswith("128.0."):
                    norm_mac = oui_lookup.normalize_mac(mac_addr).lower()
                    arp_entries.append(
                        {
                            "ip": ip_addr,
                            "mac": norm_mac,
                            "interface": intf,
                            "age": "1",
                            "type": "ARPA",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception as exc:
            logger.debug("[%s] Junos show arp no-resolve | display json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_txt = conn.send_command("show arp no-resolve")
                for line in raw_txt.splitlines():
                    parts = line.split()
                    if (
                        len(parts) >= 4
                        and re.match(r"^[0-9a-fA-F:]{17}$", parts[0])
                        and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[1])
                    ):
                        ip_addr = parts[1]
                        if ip_addr.startswith("128.0."):
                            continue
                        norm_mac = oui_lookup.normalize_mac(parts[0]).lower()
                        arp_entries.append(
                            {
                                "ip": ip_addr,
                                "mac": norm_mac,
                                "interface": parts[-1],
                                "age": "1",
                                "type": "ARPA",
                                "vendor": oui_lookup.lookup_oui(norm_mac),
                            }
                        )
            except Exception as txt_exc:
                logger.debug("[%s] Junos show arp no-resolve text fallback failed: %s", self.ip, txt_exc)
        return arp_entries

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        model_l = getattr(self, "_model", "").lower()
        if model_l.startswith(("ex4600", "ex4650", "ex9200", "qfx", "ex4500", "ex4550", "mx", "srx", "ptx", "acx")):
            poe["poe_supported"] = False
            return poe
        try:
            raw = conn.send_command("show poe controller | display json")
            data = json.loads(raw)
            ctrl_entries = data.get("poe-controller-information", [{}])[0].get("poe-controller-entry", [])
            if ctrl_entries:
                for c in ctrl_entries:
                    max_p = c.get("maximum-power", [{}])[0].get("data", "0").replace("W", "").strip()
                    con_p = c.get("consumed-power", [{}])[0].get("data", "0").replace("W", "").strip()
                    rem_p = c.get("available-power", [{}])[0].get("data", "0").replace("W", "").strip()
                    poe["total_power_watts"] += float(max_p or 0)
                    poe["used_power_watts"] += float(con_p or 0)
                    poe["available_power_watts"] += float(rem_p or 0)
            else:
                # Junos 18.x+ EX schema: {"poe": [{"controller-information": [...]}]}
                ctrl_info_list = data.get("poe", [{}])[0].get("controller-information", [])
                for c in ctrl_info_list:
                    max_p = c.get("controller-maxpower", [{}])[0].get("data", "0").replace("W", "").strip()
                    con_p = c.get("controller-power", [{}])[0].get("data", "0").replace("W", "").strip()
                    rem_p = c.get("controller-available-power", [{}])[0].get("data", "").replace("W", "").strip()
                    tot_v = float(max_p or 0)
                    used_v = float(con_p or 0)
                    avail_v = float(rem_p) if rem_p else max(0.0, round(tot_v - used_v, 2))
                    poe["total_power_watts"] += tot_v
                    poe["used_power_watts"] += used_v
                    poe["available_power_watts"] += avail_v
        except Exception as exc:
            logger.debug("[%s] Junos show poe controller | display json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_txt = conn.send_command("show poe controller")
                if "syntax error" in raw_txt.lower() or "unknown command" in raw_txt.lower():
                    return poe
                m_max = re.search(r"Maximum power\s*:\s*([\d\.]+)W?", raw_txt, re.IGNORECASE)
                m_con = re.search(r"Power consumed\s*:\s*([\d\.]+)W?", raw_txt, re.IGNORECASE)
                m_avail = re.search(r"Available power\s*:\s*([\d\.]+)W?", raw_txt, re.IGNORECASE)
                if not m_max:
                    m_row = re.search(r"^\s*\d+\s+([\d\.]+)W?\s+([\d\.]+)W?\s+([\d\.]+)W?", raw_txt, re.MULTILINE)
                    if m_row:
                        poe["total_power_watts"] = float(m_row.group(1))
                        poe["used_power_watts"] = float(m_row.group(2))
                        poe["available_power_watts"] = float(m_row.group(3))
                else:
                    if m_max:
                        poe["total_power_watts"] = float(m_max.group(1))
                    if m_con:
                        poe["used_power_watts"] = float(m_con.group(1))
                    if m_avail:
                        poe["available_power_watts"] = float(m_avail.group(1))
            except Exception as txt_exc:
                logger.debug("[%s] Junos show poe controller text fallback failed: %s", self.ip, txt_exc)

        try:
            raw_if = conn.send_command("show poe interface | display json")
            data_if = json.loads(raw_if)
            entries = data_if.get("poe-interface-information", [{}])[0].get("poe-interface-entry", [])
            if entries:
                for e in entries:
                    if_name = e.get("interface-name", [{}])[0].get("data", "").strip()
                    pwr = e.get("power-consumed", [{}])[0].get("data", "0").replace("W", "").strip()
                    status = e.get("power-status", [{}])[0].get("data", "").strip()
                    p_cls = e.get("interface-class", [{}])[0].get("data", "").strip()
                    if if_name:
                        poe["ports"][if_name] = {
                            "status": status or "ON",
                            "watts": float(pwr or 0),
                            "class": p_cls,
                        }
            else:
                # Junos 18.x+ EX schema: {"poe": [{"interface-information": [...]}]}
                entries_v2 = data_if.get("poe", [{}])[0].get("interface-information", [])
                for e in entries_v2:
                    if_name = e.get("interface-name", [{}])[0].get("data", "").strip()
                    pwr = e.get("interface-power", [{}])[0].get("data", "0").replace("W", "").strip()
                    status = e.get("interface-status", [{}])[0].get("data", "").strip()
                    p_cls = e.get("interface-class", [{}])[0].get("data", "").strip()
                    if if_name:
                        poe["ports"][if_name] = {
                            "status": status or "ON",
                            "watts": float(pwr or 0),
                            "class": p_cls,
                        }
        except Exception as exc:
            logger.debug("[%s] Junos show poe interface | display json failed, falling back to text: %s", self.ip, exc)
            try:
                raw_if_txt = conn.send_command("show poe interface")
                for line in raw_if_txt.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].startswith(("ge-", "xe-", "mge-", "et-")):
                        poe["ports"][parts[0]] = {
                            "status": parts[2],
                            "watts": float(parts[3].replace("W", "")),
                            "class": parts[4] if len(parts) > 4 else "unknown",
                        }
            except Exception as txt_exc:
                logger.debug("[%s] Junos show poe interface text fallback failed: %s", self.ip, txt_exc)

        if poe["total_power_watts"] > 0 or poe["ports"]:
            poe["poe_supported"] = True
        poe["poe_capable_ports"] = len(poe["ports"])
        poe["poe_enabled_ports"] = sum(
            1 for p in poe["ports"].values() if str(p.get("status", "")).upper() != "DISABLED"
        )
        poe["poe_delivering_ports"] = sum(1 for p in poe["ports"].values() if float(p.get("watts", 0.0) or 0.0) > 0)
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show ethernet-switching table | display json")
            data = json.loads(raw)
            table_info = data.get("ethernet-switching-table-information", [{}])[0]
            mac_entries = table_info.get("ethernet-switching-table-entry", [])
            if mac_entries:
                for e in mac_entries:
                    mac_raw = e.get("mac-address", [{}])[0].get("data", "")
                    if_raw = e.get("logical-interface", [{}])[0].get("data", "")
                    vlan = e.get("vlan-name", [{}])[0].get("data", "")
                    mtype = e.get("mac-type", [{}])[0].get("data", "dynamic").lower()
                    if mac_raw and if_raw:
                        port = if_raw.split(".")[0]
                        norm_mac = oui_lookup.normalize_mac(mac_raw).lower()
                        entries.append(
                            {
                                "vlan": vlan or "default",
                                "mac": norm_mac,
                                "type": mtype,
                                "interface": port,
                                "vendor": oui_lookup.lookup_oui(norm_mac),
                            }
                        )
            else:
                # Junos ELS (l2ng) schema: {"l2ng-l2ald-rtb-macdb": [{"l2ng-l2ald-mac-entry-vlan": [...]}]}
                vlan_blocks = data.get("l2ng-l2ald-rtb-macdb", [{}])[0].get("l2ng-l2ald-mac-entry-vlan", [])
                for vb in vlan_blocks:
                    vlan_id = vb.get("l2ng-l2-vlan-id", [{}])[0].get("data", "")
                    for e in vb.get("l2ng-mac-entry", []):
                        mac_raw = e.get("l2ng-l2-mac-address", [{}])[0].get("data", "")
                        if_raw = e.get("l2ng-l2-mac-logical-interface", [{}])[0].get("data", "")
                        vlan = e.get("l2ng-l2-mac-vlan-name", [{}])[0].get("data", "") or vlan_id
                        flags = e.get("l2ng-l2-mac-flags", [{}])[0].get("data", "D").upper()
                        mtype = "static" if "S" in flags else "dynamic"
                        if mac_raw and if_raw:
                            port = if_raw.split(".")[0]
                            norm_mac = oui_lookup.normalize_mac(mac_raw).lower()
                            entries.append(
                                {
                                    "vlan": vlan or "default",
                                    "mac": norm_mac,
                                    "type": mtype,
                                    "interface": port,
                                    "vendor": oui_lookup.lookup_oui(norm_mac),
                                }
                            )
        except Exception as exc:
            logger.debug(
                "[%s] Junos show ethernet-switching table | display json failed, falling back to text: %s",
                self.ip,
                exc,
            )
            try:
                raw_txt = conn.send_command("show ethernet-switching table")
                for line in raw_txt.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and re.search(r"[0-9a-fA-F]{2}[:\.-][0-9a-fA-F]{2}", line):
                        vlan = parts[0]
                        mac = oui_lookup.normalize_mac(parts[1]).lower()
                        mtype = parts[2].lower()
                        port = parts[-1].split(".")[0]
                        entries.append(
                            {
                                "vlan": vlan,
                                "mac": mac,
                                "type": mtype,
                                "interface": port,
                                "vendor": oui_lookup.lookup_oui(mac),
                            }
                        )
            except Exception as txt_exc:
                logger.debug("[%s] Junos show ethernet-switching table text fallback failed: %s", self.ip, txt_exc)
        return entries

    def get_optics(self, conn) -> list[dict]:
        optics_by_port: dict[str, dict] = {}

        # 1. Extract inserted Xcvr part numbers & serials from `show chassis hardware` (JSON + Junos 9.x text fallback)
        def _xcvr_port(fpc_idx: str, pic_idx: str, xcvr_idx: str, descr: str) -> str:
            dl = descr.lower()
            if "qsfp" in dl or "100g" in dl or "40g" in dl:
                prefix = "et"
            elif "sfp+" in dl or "10g" in dl or "xfp" in dl:
                prefix = "xe"
            else:
                prefix = "ge"
            return f"{prefix}-{fpc_idx}/{pic_idx}/{xcvr_idx}"

        try:
            raw_hw = conn.send_command("show chassis hardware | display json")
            hw_data = json.loads(raw_hw)
            chassis = hw_data.get("chassis-inventory", [{}])[0].get("chassis", [{}])[0]
            for mod in chassis.get("chassis-module", []):
                m_name = mod.get("name", [{}])[0].get("data", "")
                m_fpc = re.match(r"FPC\s+(\d+)", m_name, re.IGNORECASE)
                if not m_fpc:
                    continue
                fpc_idx = m_fpc.group(1)
                for sub in mod.get("chassis-sub-module", []):
                    s_name = sub.get("name", [{}])[0].get("data", "")
                    m_pic = re.match(r"PIC\s+(\d+)", s_name, re.IGNORECASE)
                    if not m_pic:
                        continue
                    pic_idx = m_pic.group(1)
                    for xcvr in sub.get("chassis-sub-sub-module", []):
                        x_name = xcvr.get("name", [{}])[0].get("data", "")
                        m_x = re.match(r"Xcvr\s+(\d+)", x_name, re.IGNORECASE)
                        if not m_x:
                            continue
                        pn = xcvr.get("part-number", [{}])[0].get("data", "Unknown")
                        sn = xcvr.get("serial-number", [{}])[0].get("data", "Unknown")
                        desc = xcvr.get("description", [{}])[0].get("data", "SFP")
                        port = _xcvr_port(fpc_idx, pic_idx, m_x.group(1), desc)
                        optics_by_port[port] = {
                            "port": port,
                            "vendor": "Juniper Networks",
                            "part_number": pn or "Unknown",
                            "serial": sn or "Unknown",
                            "type": desc or "SFP",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
        except Exception as exc:
            logger.debug(
                "[%s] Junos show chassis hardware | display json optics failed, falling back to text: %s", self.ip, exc
            )
            try:
                raw_hw_txt = conn.send_command("show chassis hardware")
                fpc_idx, pic_idx = "0", "0"
                for line in raw_hw_txt.splitlines():
                    m_fpc = re.match(r"^FPC\s+(\d+)", line.strip())
                    if m_fpc:
                        fpc_idx = m_fpc.group(1)
                        continue
                    m_pic = re.match(r"^\s*PIC\s+(\d+)", line)
                    if m_pic:
                        pic_idx = m_pic.group(1)
                        continue
                    m_x = re.match(r"^\s*Xcvr\s+(\d+)\s+(?:REV\s+\S+\s+)?(\S+)\s+(\S+)\s+(.+)$", line)
                    if m_x:
                        pn, sn, desc = m_x.group(2), m_x.group(3), m_x.group(4).strip()
                        port = _xcvr_port(fpc_idx, pic_idx, m_x.group(1), desc)
                        optics_by_port[port] = {
                            "port": port,
                            "vendor": "Juniper Networks",
                            "part_number": pn or "Unknown",
                            "serial": sn or "Unknown",
                            "type": desc or "SFP",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
            except Exception as txt_exc:
                logger.debug("[%s] Junos show chassis hardware optics text fallback failed: %s", self.ip, txt_exc)

        # 2. Merge live DOM telemetry from `show interfaces diagnostics optics`
        def _merge_dom(port: str, tx, rx, temp, volt):
            # Match exact port or fallback to same FPC/PIC/slot if speed prefix differed
            target_key = port
            if target_key not in optics_by_port:
                suffix = port.split("-", 1)[-1] if "-" in port else port
                for k in optics_by_port:
                    if k.endswith("-" + suffix):
                        target_key = k
                        break
            if target_key in optics_by_port:
                optics_by_port[target_key]["port"] = port
                optics_by_port[target_key]["tx_power_dbm"] = tx
                optics_by_port[target_key]["rx_power_dbm"] = rx
                optics_by_port[target_key]["temperature_c"] = temp
                optics_by_port[target_key]["voltage_v"] = volt
            else:
                optics_by_port[port] = {
                    "port": port,
                    "vendor": "Juniper Networks",
                    "part_number": "SFP-DOM",
                    "serial": "Unknown",
                    "type": "SFP+",
                    "tx_power_dbm": tx,
                    "rx_power_dbm": rx,
                    "temperature_c": temp,
                    "voltage_v": volt,
                }

        try:
            raw = conn.send_command("show interfaces diagnostics optics | display json")
            data = json.loads(raw)
            diag_info = data.get("interfaces-diagnostics-optics-information", {})
            if isinstance(diag_info, list):
                diag_info = diag_info[0] if diag_info else {}
            phys = diag_info.get("physical-interface", [])
            if isinstance(phys, dict):
                phys = [phys]
            for p in phys:
                p_name_raw = p.get("name", "")
                p_name = (
                    p_name_raw[0].get("data", "").strip()
                    if isinstance(p_name_raw, list)
                    else (p_name_raw.get("data", "").strip() if isinstance(p_name_raw, dict) else str(p_name_raw))
                )
                diag = p.get("optics-diagnostics", {})
                if isinstance(diag, list):
                    diag = diag[0] if diag else {}

                def _extract_val(d, field):
                    v = d.get(field)
                    if isinstance(v, list) and v:
                        return v[0].get("data")
                    elif isinstance(v, dict):
                        return v.get("data")
                    return v

                tx = _extract_val(diag, "laser-output-power-dbm")
                rx = _extract_val(diag, "laser-rx-optical-power-dbm")
                temp = _extract_val(diag, "module-temperature")
                volt = _extract_val(diag, "module-voltage")
                if p_name:
                    _merge_dom(
                        p_name,
                        float(tx) if tx and tx != "N/A" else None,
                        float(rx) if rx and rx != "N/A" else None,
                        float(temp) if temp and temp != "N/A" else None,
                        float(volt) if volt and volt != "N/A" else None,
                    )
        except Exception as exc:
            logger.debug(
                "[%s] Junos show interfaces diagnostics optics | display json failed, falling back to text: %s",
                self.ip,
                exc,
            )
            try:
                raw_txt = conn.send_command("show interfaces diagnostics optics")
                current_port = ""
                cur_data: dict = {}
                for line in raw_txt.splitlines():
                    m_p = re.match(r"^Physical interface:\s*([A-Za-z0-9/\._-]+)", line)
                    if m_p:
                        if current_port and cur_data:
                            _merge_dom(
                                current_port,
                                cur_data.get("tx_power_dbm"),
                                cur_data.get("rx_power_dbm"),
                                cur_data.get("temperature_c"),
                                cur_data.get("voltage_v"),
                            )
                        current_port = m_p.group(1)
                        cur_data = {}
                    elif current_port:
                        m_tx = re.search(r"Laser output power\s*:\s*.*?/\s*([-\d\.]+)\s*dBm", line)
                        m_rx = re.search(r"Laser rx optical power\s*:\s*.*?/\s*([-\d\.]+)\s*dBm", line)
                        m_temp = re.search(r"Module temperature\s*:\s*([-\d\.]+)\s*degrees C", line)
                        m_volt = re.search(r"Module voltage\s*:\s*([-\d\.]+)\s*V", line)
                        if m_tx:
                            cur_data["tx_power_dbm"] = float(m_tx.group(1))
                        if m_rx:
                            cur_data["rx_power_dbm"] = float(m_rx.group(1))
                        if m_temp:
                            cur_data["temperature_c"] = float(m_temp.group(1))
                        if m_volt:
                            cur_data["voltage_v"] = float(m_volt.group(1))
                if current_port and cur_data:
                    _merge_dom(
                        current_port,
                        cur_data.get("tx_power_dbm"),
                        cur_data.get("rx_power_dbm"),
                        cur_data.get("temperature_c"),
                        cur_data.get("voltage_v"),
                    )
            except Exception as txt_exc:
                logger.debug("[%s] Junos show interfaces diagnostics optics text fallback failed: %s", self.ip, txt_exc)
        return list(optics_by_port.values())

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show configuration | display set")
        except Exception as exc:
            logger.debug(
                "[%s] Junos show configuration | display set failed, falling back to show configuration: %s",
                self.ip,
                exc,
            )
            return conn.send_command("show configuration")

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}
        parsed_es_json = False
        try:
            raw_es = conn.send_command("show ethernet-switching interfaces | display json")
            if isinstance(raw_es, str) and raw_es.strip().startswith("{"):
                data = json.loads(raw_es)
                entries = data.get("l2ng-l2ald-iff-interface-information", [{}])[0].get(
                    "l2ng-l2ald-iff-interface-entry", []
                )
                for entry in entries:
                    iname = (entry.get("l2ng-l2ald-iff-interface-name", [{}])[0].get("data") or "").split(".")[0]
                    if not iname:
                        continue
                    parsed_es_json = True
                    mode = (entry.get("l2ng-l2ald-iff-port-mode", [{}])[0].get("data") or "").lower()
                    state = (
                        entry.get("l2ng-l2ald-iff-interface-state", [{}])[0].get("data")
                        or entry.get("l2ng-l2ald-iff-interface-status", [{}])[0].get("data")
                        or "up"
                    ).lower()
                    flags = (entry.get("l2ng-l2ald-iff-interface-flags", [{}])[0].get("data") or "").upper()
                    is_down = state == "down" or "DN" in flags.split()

                    # Extract operational VLAN members & tagness
                    member_nodes: list[dict] = []
                    for vlist in entry.get("l2ng-l2ald-iff-interface-vlan-member-list", []):
                        if isinstance(vlist, dict):
                            member_nodes.extend(vlist.get("l2ng-l2ald-iff-interface-vlan-member", []))
                    if not member_nodes:
                        member_nodes = entry.get("l2ng-l2ald-iff-interface-vlan-member", [])

                    active_vids: list[str] = []
                    tagged_vids: list[str] = []
                    untagged_vid = ""
                    for m_node in member_nodes:
                        if not isinstance(m_node, dict):
                            continue
                        tag_id = (
                            m_node.get("l2ng-l2ald-iff-interface-vlan-member-tagid", [{}])[0].get("data")
                            or m_node.get("l2ng-l2ald-iff-interface-vlan-id", [{}])[0].get("data")
                            or ""
                        ).strip()
                        tagness = (
                            m_node.get("l2ng-l2ald-iff-interface-vlan-member-tagness", [{}])[0].get("data")
                            or m_node.get("l2ng-l2ald-iff-interface-vlan-member-tagging", [{}])[0].get("data")
                            or ""
                        ).lower()
                        if tag_id.isdigit():
                            if tag_id not in active_vids:
                                active_vids.append(tag_id)
                            if tagness == "untagged":
                                untagged_vid = tag_id
                            elif tagness == "tagged" and tag_id not in tagged_vids:
                                tagged_vids.append(tag_id)

                    if mode not in ("access", "trunk"):
                        if tagged_vids or len(active_vids) > 1:
                            mode = "trunk"
                        elif untagged_vid:
                            mode = "access"

                    if mode in ("access", "trunk"):
                        rec = ops.setdefault(iname, {})
                        rec["mode"] = mode
                        rec["oper_mode"] = "down" if is_down else mode
                        rec["encapsulation"] = "dot1q"
                        if mode == "trunk":
                            if active_vids:
                                sorted_vids = sorted(active_vids, key=int)
                                rec["trunk_active_vlans"] = ",".join(sorted_vids)
                            if untagged_vid:
                                rec["native_vlan"] = untagged_vid
                                rec["native_vlan_tagged"] = False
                            elif active_vids:
                                rec["native_vlan"] = "none"
                                rec["native_vlan_tagged"] = True
                        elif mode == "access" and untagged_vid:
                            rec["access_vlan"] = untagged_vid
        except Exception as exc:
            logger.debug("[%s] Junos show ethernet-switching interfaces | display json failed: %s", self.ip, exc)

        # Text fallback for `show ethernet-switching interfaces` (ELS & pre-ELS Junos)
        if not parsed_es_json:
            try:
                raw_es_txt = conn.send_command("show ethernet-switching interfaces")
                if (
                    isinstance(raw_es_txt, str)
                    and raw_es_txt.strip()
                    and "syntax error" not in raw_es_txt.lower()
                    and "unknown command" not in raw_es_txt.lower()
                    and "invalid" not in raw_es_txt.lower()
                ):
                    parsed_ports: dict[str, dict] = {}
                    cur_if = ""
                    for line in raw_es_txt.splitlines():
                        if not line.strip():
                            continue
                        low = line.strip().lower()
                        if low.startswith(("routing instance", "logical", "interface", "---")):
                            continue
                        m_if = re.match(r"^\s*((?:ge-|xe-|et-|fe-|mge-|ae\d)\S*)\s+(.*)$", line)
                        if m_if:
                            cur_if = m_if.group(1).split(".")[0]
                            tail = m_if.group(2)
                            p_state = parsed_ports.setdefault(cur_if, {"down": False, "tagged": [], "untagged": []})
                            if re.match(r"^down\b", tail, re.I) or re.search(r"\bDN\b", tail):
                                p_state["down"] = True
                        elif cur_if and line[0].isspace():
                            tail = line.strip()
                            p_state = parsed_ports[cur_if]
                            if re.search(r"\bDN\b", tail):
                                p_state["down"] = True
                        else:
                            continue

                        # Match ELS (`VLAN_NAME  10  65535  Forwarding  tagged`) or pre-ELS (`[up|down] VLAN_NAME  10  tagged`)
                        m_row = re.search(
                            r"^\s*(?:(?:up|down)\s+)?\S+\s+(\d{1,4})\s+(?:\d+\s+\S+.*?)?\b(tagged|untagged)\b",
                            tail,
                            re.I,
                        )
                        if m_row:
                            vid, tagness = m_row.group(1), m_row.group(2).lower()
                            if 1 <= int(vid) <= 4094:
                                bucket = p_state["tagged"] if tagness == "tagged" else p_state["untagged"]
                                if vid not in bucket:
                                    bucket.append(vid)

                    for iname, p_state in parsed_ports.items():
                        tagged = p_state["tagged"]
                        untagged = p_state["untagged"]
                        all_vids = sorted(set(tagged) | set(untagged), key=int)
                        if not all_vids:
                            continue
                        rec = ops.setdefault(iname, {})
                        rec["encapsulation"] = "dot1q"
                        if tagged or len(all_vids) > 1:
                            rec["mode"] = "trunk"
                            rec["oper_mode"] = "down" if p_state["down"] else "trunk"
                            rec["trunk_active_vlans"] = ",".join(all_vids)
                            if untagged:
                                rec["native_vlan"] = untagged[0]
                                rec["native_vlan_tagged"] = False
                            else:
                                rec["native_vlan"] = "none"
                                rec["native_vlan_tagged"] = True
                        elif untagged:
                            rec["mode"] = "access"
                            rec["oper_mode"] = "down" if p_state["down"] else "access"
                            rec["access_vlan"] = untagged[0]
            except Exception as exc:
                logger.debug("[%s] Junos show ethernet-switching interfaces text fallback failed: %s", self.ip, exc)

        try:
            raw_lacp = conn.send_command("show lacp interfaces | display json")
            if isinstance(raw_lacp, str) and raw_lacp.strip().startswith("{"):
                data = json.loads(raw_lacp)
                for grp_blk in data.get("lacp-interface-information-list", [{}])[0].get(
                    "lacp-interface-information", []
                ):
                    ae_name = grp_blk.get("lag-lacp-header", [{}])[0].get("aggregate-name", [{}])[0].get("data", "")
                    for p_ent in grp_blk.get("lag-lacp-state", []):
                        pname = p_ent.get("name", [{}])[0].get("data", "")
                        if pname and ae_name:
                            ops.setdefault(pname, {})["lag_group"] = ae_name
                            role = (p_ent.get("lacp-activity", [{}])[0].get("data") or "").lower()
                            if role in ("active", "passive"):
                                ops[pname]["lacp_mode"] = role
        except Exception as exc:
            logger.debug("[%s] Junos show lacp interfaces | display json failed: %s", self.ip, exc)

        try:
            raw_stp = conn.send_command("show spanning-tree interface | display json")
            if isinstance(raw_stp, str) and raw_stp.strip().startswith("{"):
                data = json.loads(raw_stp)
                for stp_blk in data.get("stp-interface-information", []):
                    for p_ent in stp_blk.get("stp-interface-entry", []):
                        pname = (p_ent.get("interface-name", [{}])[0].get("data") or "").split(".")[0]
                        if not pname:
                            continue
                        role = p_ent.get("port-role", [{}])[0].get("data", "")
                        state = p_ent.get("port-state", [{}])[0].get("data", "")
                        if role:
                            ops.setdefault(pname, {})["stp_role"] = role
                        if state:
                            ops.setdefault(pname, {})["stp_state"] = state
        except Exception as exc:
            logger.debug("[%s] Junos show spanning-tree interface | display json failed: %s", self.ip, exc)

        try:
            raw_dot1x = conn.send_command("show dot1x interface | display json")
            if isinstance(raw_dot1x, str) and raw_dot1x.strip().startswith("{"):
                data = json.loads(raw_dot1x)
                for d_ent in data.get("dot1x-interface-information", [{}])[0].get("interface", []):
                    pname = (d_ent.get("interface-name", [{}])[0].get("data") or "").split(".")[0]
                    if pname:
                        ops.setdefault(pname, {})["auth_policy"] = "dot1x"
        except Exception as exc:
            logger.debug("[%s] Junos show dot1x interface | display json failed: %s", self.ip, exc)

        return ops

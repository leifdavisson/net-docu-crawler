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
import re

from netmiko import ConnectHandler

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver

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
        device = {
            "device_type": "juniper_junos",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "timeout": self.timeout,
            "auth_timeout": self.timeout,
            "global_delay_factor": 2,
        }
        if self.session_log:
            device["session_log"] = self.session_log
        conn = ConnectHandler(**device)
        return conn

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
        except Exception:
            raw = conn.send_command("show version")
            m_host = re.search(r"Hostname:\s+(\S+)", raw)
            if m_host:
                info["hostname"] = m_host.group(1)
            m_model = re.search(r"Model:\s+(\S+)", raw)
            if m_model:
                info["model"] = m_model.group(1)
            m_ver = re.search(r"Junos:\s+(\S+)", raw)
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
        except Exception:
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
        except Exception:
            pass

        if not info["hostname"]:
            info["hostname"] = conn.find_prompt().split("@")[-1].replace(">", "").replace("#", "").strip()

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
                    interfaces_detail[name] = {
                        "status": oper_status,
                        "protocol": oper_status,
                        "admin_status": admin_status,
                        "description": "",
                        "mac_address": "",
                        "speed": "1Gb/s",
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
        except Exception:
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
        except Exception:
            raw = conn.send_command("show lldp neighbors detail")
            blocks = raw.split("Local Interface:")
            for b in blocks[1:]:
                m_port = re.match(r"\s*(\S+)", b)
                m_sys = re.search(r"System name\s*:\s*(\S+)", b)
                m_ip = re.search(r"Management address\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", b)
                m_rem_port = re.search(r"Port id\s*:\s*(\S+)", b)
                m_desc = re.search(r"System description\s*:\s*(.+)", b)
                if m_port and m_sys:
                    local_port = re.sub(r"\.0$", "", m_port.group(1).rstrip(","))
                    plat = m_desc.group(1).strip()[:60] if m_desc else "JunOS-Discovered"
                    dev_type = "ap" if any(k in plat.lower() for k in ["ap", "aruba", "access point"]) else "switch"
                    neighbors.append(
                        {
                            "local_port": local_port,
                            "remote_device": m_sys.group(1),
                            "remote_port": m_rem_port.group(1) if m_rem_port else "Unknown",
                            "remote_ip": m_ip.group(1) if m_ip else "",
                            "platform": plat,
                            "remote_platform": plat,
                            "device_type": dev_type,
                        }
                    )

        return neighbors

    def get_stp(self, conn) -> dict:
        stp = {"enabled": False, "is_root": False, "root_bridge": "", "vlans": {}}
        try:
            raw = conn.send_command("show spanning-tree bridge | display json")
            if raw.strip().startswith("{"):
                data = json.loads(raw)
                stp_info = data.get("stp-bridge-parameters-information", [])
                if stp_info:
                    stp["enabled"] = True
                    raw_str = json.dumps(stp_info).lower()
                    if "this bridge is the root" in raw_str:
                        stp["is_root"] = True
                    return stp
        except Exception:
            pass

        try:
            raw_txt = conn.send_command("show spanning-tree bridge")
            low = raw_txt.lower()
            if "stp bridge parameters" in low or "enabled protocol" in low:
                stp["enabled"] = True
                if "root" in low and "0:0" in low:
                    stp["is_root"] = True
        except Exception:
            pass
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
        except Exception:
            pass
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
        except Exception:
            pass
        return arp_entries

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show poe controller | display json")
            data = json.loads(raw)
            ctrl_info = data.get("poe-controller-information", [{}])[0]
            ctrl_entries = ctrl_info.get("poe-controller-entry", [])
            for c in ctrl_entries:
                max_p = c.get("maximum-power", [{}])[0].get("data", "0").replace("W", "").strip()
                con_p = c.get("consumed-power", [{}])[0].get("data", "0").replace("W", "").strip()
                rem_p = c.get("available-power", [{}])[0].get("data", "0").replace("W", "").strip()
                poe["total_power_watts"] += float(max_p or 0)
                poe["used_power_watts"] += float(con_p or 0)
                poe["available_power_watts"] += float(rem_p or 0)
        except Exception:
            try:
                raw_txt = conn.send_command("show poe controller")
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
            except Exception:
                pass

        try:
            raw_if = conn.send_command("show poe interface | display json")
            data_if = json.loads(raw_if)
            entries = data_if.get("poe-interface-information", [{}])[0].get("poe-interface-entry", [])
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
        except Exception:
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
            except Exception:
                pass

        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show ethernet-switching table | display json")
            data = json.loads(raw)
            table_info = data.get("ethernet-switching-table-information", [{}])[0]
            mac_entries = table_info.get("ethernet-switching-table-entry", [])
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
        except Exception:
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
            except Exception:
                pass
        return entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
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
                    optics.append(
                        {
                            "port": p_name,
                            "vendor": "Juniper Networks",
                            "part_number": "SFP-DOM",
                            "serial": "Unknown",
                            "type": "SFP+",
                            "tx_power_dbm": float(tx) if tx and tx != "N/A" else None,
                            "rx_power_dbm": float(rx) if rx and rx != "N/A" else None,
                            "temperature_c": float(temp) if temp and temp != "N/A" else None,
                            "voltage_v": float(volt) if volt and volt != "N/A" else None,
                        }
                    )
        except Exception:
            try:
                raw_txt = conn.send_command("show interfaces diagnostics optics")
                current_port = ""
                cur_data = {}
                for line in raw_txt.splitlines():
                    m_p = re.match(r"^Physical interface:\s*([A-Za-z0-9/\._-]+)", line)
                    if m_p:
                        if current_port and cur_data:
                            optics.append(cur_data)
                        current_port = m_p.group(1)
                        cur_data = {
                            "port": current_port,
                            "vendor": "Juniper Networks",
                            "part_number": "SFP-DOM",
                            "serial": "Unknown",
                            "type": "SFP+",
                            "tx_power_dbm": None,
                            "rx_power_dbm": None,
                            "temperature_c": None,
                            "voltage_v": None,
                        }
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
                    optics.append(cur_data)
            except Exception:
                pass
        return optics

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show configuration | display set")
        except Exception:
            return conn.send_command("show configuration")

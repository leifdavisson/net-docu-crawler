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
Arista EOS Driver: Switches and Routers running Arista EOS.
Leverages native structured JSON commands ('| json') for deterministic parsing.
Official Documentation: https://www.arista.com/en/um-eos
"""

import json
import re

import oui_lookup
from net_docu_crawler.drivers.base import BaseDriver


class AristaDriver(BaseDriver):
    """
    Driver for Arista appliances running EOS.
    Persona: switch / spine / leaf router.
    """

    vendor_name = "Arista"
    device_persona = "switch"
    default_device_type = "switch"
    paging_cmd = "terminal length 0"

    def connect(self):
        device = {
            "device_type": "arista_eos",
            "ip": self.ip,
            "username": self.username,
            "password": self.password,
            "secret": self.secret,
            "timeout": self.timeout,
            "auth_timeout": self.timeout,
        }
        if self.session_log:
            device["session_log"] = self.session_log
        conn = self.connect_netmiko(device)
        try:
            conn.enable()
        except Exception:
            pass
        return conn

    def get_version(self, conn) -> dict:
        info = {
            "hostname": "",
            "model": "Arista Switch",
            "serial": "Unknown",
            "firmware": "EOS",
            "os_type": "arista_eos",
            "device_persona": self.device_persona,
        }
        try:
            raw = conn.send_command("show version | json")
            data = json.loads(raw)
            info["model"] = data.get("modelName", "Arista")
            info["serial"] = data.get("serialNumber") or "Unknown"
            ver_str = data.get("version") or data.get("internalVersion") or ""
            info["firmware"] = f"EOS {ver_str}".strip()
            sys_mac = data.get("systemMacAddress", "")
            if sys_mac:
                info["mac_address"] = oui_lookup.normalize_mac(sys_mac).lower()
        except Exception:
            pass

        try:
            raw_host = conn.send_command("show hostname | json")
            h_data = json.loads(raw_host)
            info["hostname"] = h_data.get("fqdn") or h_data.get("hostname", "")
        except Exception:
            try:
                info["hostname"] = conn.find_prompt().rstrip(">#")
            except Exception:
                pass

        return info

    def get_interfaces(self, conn) -> tuple[list, dict]:
        l3_interfaces = []
        interfaces_detail = {}
        try:
            raw = conn.send_command("show ip interface | json")
            data = json.loads(raw)
            for intf_name, intf_data in data.get("interfaces", {}).items():
                if intf_name.lower().startswith("loopback"):
                    continue
                addr_info = intf_data.get("interfaceAddress", {}).get("primaryIp", {})
                ip_addr = addr_info.get("address", "")
                mask_len = addr_info.get("maskLen", 0)
                full_ip = f"{ip_addr}/{mask_len}" if ip_addr and ip_addr != "0.0.0.0" else ""
                status = "up" if intf_data.get("lineProtocolStatus") == "up" else "down"
                raw_mac = (
                    intf_data.get("routedAddr")
                    or intf_data.get("burnedInAddress")
                    or intf_data.get("physicalAddress")
                    or ""
                )
                norm_mac = oui_lookup.normalize_mac(raw_mac).lower() if raw_mac else ""

                if full_ip:
                    l3_interfaces.append(
                        {
                            "interface": intf_name,
                            "ip_address": full_ip,
                            "status": status,
                            "protocol": status,
                        }
                    )

                counters = intf_data.get("interfaceCounters", {})
                interfaces_detail[intf_name] = {
                    "ip_address": full_ip,
                    "status": status,
                    "mac_address": norm_mac,
                    "description": intf_data.get("description", ""),
                    "input_errors": int(counters.get("inErrors", 0) or 0),
                    "crc": int(counters.get("fcsErrors", 0) or 0),
                    "output_errors": int(counters.get("outErrors", 0) or 0),
                    "drops": int(counters.get("inDiscards", 0) or 0) + int(counters.get("outDiscards", 0) or 0),
                }
        except Exception:
            pass
        return l3_interfaces, interfaces_detail

    def get_neighbors(self, conn) -> list[dict]:
        neighbors = []
        try:
            raw = conn.send_command("show lldp neighbors detail | json")
            data = json.loads(raw)
            for local_port, nbr_list in data.get("lldpNeighbors", {}).items():
                for nbr in nbr_list.get("lldpNeighborInfo", []):
                    rem_dev = nbr.get("systemName") or nbr.get("chassisId", "Unknown")
                    rem_port = nbr.get("portId", "Unknown")
                    rem_sys = nbr.get("systemDescription", "")[:60]
                    rem_ip = ""
                    mgmt_addrs = nbr.get("managementAddresses", [])
                    if mgmt_addrs:
                        rem_ip = mgmt_addrs[0].get("address", "")
                    neighbors.append(
                        {
                            "local_port": local_port,
                            "remote_device": rem_dev,
                            "remote_port": rem_port,
                            "remote_ip": rem_ip,
                            "platform": rem_sys,
                            "remote_platform": rem_sys,
                            "device_type": "switch",
                        }
                    )
        except Exception:
            pass
        return neighbors

    def get_stp(self, conn) -> dict:
        stp = {"enabled": False, "is_root": False, "root_bridge": "", "vlans": {}}
        try:
            raw = conn.send_command("show spanning-tree | json")
            if raw.strip().startswith("{"):
                data = json.loads(raw)
                instances = data.get("spanningTreeInstances", {})
                if instances:
                    stp["enabled"] = True
                    for inst_id, inst in instances.items():
                        is_root = bool(inst.get("isRootBridge", False))
                        if is_root:
                            stp["is_root"] = True
                        stp["vlans"][inst_id] = {}
        except Exception:
            pass
        return stp

    def get_routing_table(self, conn) -> list[dict]:
        routes = []
        try:
            raw = conn.send_command("show ip route | json")
            data = json.loads(raw)
            vrf_data = data.get("vrfs", {}).get("default", {})
            for subnet, r_info in vrf_data.get("routes", {}).items():
                proto = r_info.get("routeType", "unknown")
                vias = r_info.get("vias", [])
                next_hop = vias[0].get("nexthopAddr", "directly connected") if vias else "directly connected"
                intf = vias[0].get("interface", "") if vias else ""
                routes.append(
                    {
                        "subnet": subnet,
                        "protocol": proto,
                        "next_hop": next_hop,
                        "interface": intf,
                    }
                )
        except Exception:
            pass
        return routes

    def get_arp_table(self, conn) -> list[dict]:
        arp_entries = []
        try:
            raw = conn.send_command("show ip arp | json")
            data = json.loads(raw)
            for entry in data.get("ipV4Neighbors", []):
                ip_addr = entry.get("address", "")
                mac = entry.get("hwAddress", "")
                intf = entry.get("interface", "")
                if ip_addr and mac:
                    norm_mac = oui_lookup.normalize_mac(mac).lower()
                    arp_entries.append(
                        {
                            "ip": ip_addr,
                            "mac": norm_mac,
                            "interface": intf,
                            "type": "dynamic",
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception:
            pass
        return arp_entries

    def get_poe(self, conn) -> dict:
        poe = {"total_power_watts": 0.0, "used_power_watts": 0.0, "available_power_watts": 0.0, "ports": {}}
        try:
            raw = conn.send_command("show power inline | json")
            data = json.loads(raw)
            summary = data.get("powerSummary", {})
            poe["total_power_watts"] = float(summary.get("totalPower", 0.0))
            poe["used_power_watts"] = float(summary.get("usedPower", 0.0))
            poe["available_power_watts"] = float(summary.get("availablePower", 0.0))
            for intf_name, intf_data in data.get("interfaces", {}).items():
                poe["ports"][intf_name] = {
                    "status": intf_data.get("operState", "disabled"),
                    "watts": float(intf_data.get("power", 0.0)),
                    "class": str(intf_data.get("class", "unknown")),
                }
        except Exception:
            try:
                raw_txt = conn.send_command("show power inline")
                m_tot = re.search(r"Total:\s*([\d\.]+)W?", raw_txt, re.IGNORECASE)
                m_used = re.search(r"Used:\s*([\d\.]+)W?", raw_txt, re.IGNORECASE)
                m_avail = re.search(r"Available:\s*([\d\.]+)W?", raw_txt, re.IGNORECASE)
                if m_tot:
                    poe["total_power_watts"] = float(m_tot.group(1))
                if m_used:
                    poe["used_power_watts"] = float(m_used.group(1))
                if m_avail:
                    poe["available_power_watts"] = float(m_avail.group(1))
                for line in raw_txt.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].startswith(("Et", "Ethernet")):
                        poe["ports"][parts[0]] = {
                            "status": parts[2],
                            "watts": float(parts[3]),
                            "class": parts[4] if len(parts) > 4 else "unknown",
                        }
            except Exception:
                pass
        return poe

    def get_mac_table(self, conn) -> list[dict]:
        entries = []
        try:
            raw = conn.send_command("show mac address-table | json")
            data = json.loads(raw)
            table_entries = data.get("unicastTable", {}).get("tableEntries", [])
            for e in table_entries:
                vlan = str(e.get("vlanId", "1"))
                mac_raw = e.get("macAddress", "")
                mtype = e.get("entryType", "dynamic").lower()
                intf = e.get("interface", "")
                if mac_raw and intf:
                    norm_mac = oui_lookup.normalize_mac(mac_raw).lower()
                    entries.append(
                        {
                            "vlan": vlan,
                            "mac": norm_mac,
                            "type": mtype,
                            "interface": intf,
                            "vendor": oui_lookup.lookup_oui(norm_mac),
                        }
                    )
        except Exception:
            try:
                raw_txt = conn.send_command("show mac address-table")
                for line in raw_txt.splitlines():
                    parts = line.split()
                    if len(parts) >= 4 and ("DYNAMIC" in line.upper() or "STATIC" in line.upper()):
                        mac = oui_lookup.normalize_mac(parts[1]).lower()
                        entries.append(
                            {
                                "vlan": parts[0],
                                "mac": mac,
                                "type": parts[2].lower(),
                                "interface": parts[3],
                                "vendor": oui_lookup.lookup_oui(mac),
                            }
                        )
            except Exception:
                pass
        return entries

    def get_optics(self, conn) -> list[dict]:
        optics = []
        try:
            raw = conn.send_command("show interfaces transceiver | json")
            data = json.loads(raw)
            for intf_name, intf_info in data.get("interfaces", {}).items():
                optics.append(
                    {
                        "port": intf_name,
                        "vendor": intf_info.get("vendorName") or "Arista Networks",
                        "part_number": intf_info.get("vendorPartNumber") or "SFP-DOM",
                        "serial": intf_info.get("vendorSerial") or "Unknown",
                        "type": intf_info.get("mediaType") or "SFP+",
                        "tx_power_dbm": float(intf_info["txPower"])
                        if "txPower" in intf_info and intf_info["txPower"] is not None
                        else None,
                        "rx_power_dbm": float(intf_info["rxPower"])
                        if "rxPower" in intf_info and intf_info["rxPower"] is not None
                        else None,
                        "temperature_c": float(intf_info["temperature"])
                        if "temperature" in intf_info and intf_info["temperature"] is not None
                        else None,
                        "voltage_v": float(intf_info["voltage"])
                        if "voltage" in intf_info and intf_info["voltage"] is not None
                        else None,
                    }
                )
        except Exception:
            try:
                raw_txt = conn.send_command("show interfaces transceiver")
                for line in raw_txt.splitlines():
                    line = line.strip()
                    if not line or line.startswith("Port") or "---" in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 6 and parts[0].startswith(("Et", "Ethernet")):
                        port = parts[0]
                        temp = float(parts[1]) if parts[1] != "N/A" else None
                        volt = float(parts[2]) if parts[2] != "N/A" else None
                        tx = float(parts[4]) if parts[4] != "N/A" else None
                        rx = float(parts[5]) if parts[5] != "N/A" else None
                        optics.append(
                            {
                                "port": port,
                                "vendor": "Arista Networks",
                                "part_number": "SFP-DOM",
                                "serial": "Unknown",
                                "type": "SFP+",
                                "tx_power_dbm": tx,
                                "rx_power_dbm": rx,
                                "temperature_c": temp,
                                "voltage_v": volt,
                            }
                        )
            except Exception:
                pass
        return optics

    def get_running_config(self, conn) -> str:
        try:
            return conn.send_command("show running-config")
        except Exception:
            return ""

    @staticmethod
    def _eos_vlans_to_str(val) -> str:
        """Normalize Arista EOS JSON VLAN container (dict, list, or str) into a comma-separated string."""
        if not val:
            return ""
        if isinstance(val, str):
            return val.strip().lower()
        if isinstance(val, dict):
            inner = val.get("vlanIds")
            if inner is None:
                inner = val.get("vlans")
            if inner is None:
                return ""
            val = inner
        if isinstance(val, list):
            parts = [str(v).strip() for v in val if str(v).strip()]
            return ",".join(parts)
        return str(val).strip()

    def get_l2_operational(self, conn) -> dict[str, dict]:
        ops: dict[str, dict] = {}

        # 1. Operational trunk state (`show interfaces trunk | json` with text fallback)
        parsed_trunk_json = False
        try:
            raw_trunk = conn.send_command("show interfaces trunk | json")
            if isinstance(raw_trunk, str) and raw_trunk.strip().startswith("{"):
                data = json.loads(raw_trunk)
                trunks = data.get("trunks") or data.get("interfaces") or {}
                if isinstance(trunks, dict):
                    for port, pdata in trunks.items():
                        if not isinstance(pdata, dict):
                            continue
                        parsed_trunk_json = True
                        status = str(pdata.get("status") or "trunking").lower()
                        oper_m = (
                            "trunk"
                            if ("trunk" in status or status == "up")
                            else ("down" if status == "down" else "access")
                        )
                        encap_raw = str(pdata.get("encapsulation") or "dot1q").lower()
                        encap = "isl" if "isl" in encap_raw else "dot1q"
                        rec = ops.setdefault(port, {})
                        rec["mode"] = "trunk" if oper_m == "trunk" else rec.get("mode", "trunk")
                        rec["oper_mode"] = oper_m
                        rec["encapsulation"] = encap
                        nat = pdata.get("nativeVlan", pdata.get("nativeVlanId"))
                        if nat is not None and str(nat).strip():
                            rec["native_vlan"] = str(nat).strip()
                        allowed = self._eos_vlans_to_str(pdata.get("allowedVlans") or pdata.get("allowed"))
                        if allowed:
                            rec["trunk_allowed_vlans"] = allowed
                        active = self._eos_vlans_to_str(
                            pdata.get("activeVlans") or pdata.get("forwardingVlans") or pdata.get("active")
                        )
                        if active:
                            rec["trunk_active_vlans"] = active
                        if "nativeVlanTagged" in pdata:
                            rec["native_vlan_tagged"] = bool(pdata["nativeVlanTagged"])
        except Exception:
            pass

        if not parsed_trunk_json:
            try:
                raw_txt = conn.send_command("show interfaces trunk")
                if (
                    isinstance(raw_txt, str)
                    and raw_txt.strip()
                    and "Invalid input" not in raw_txt
                    and "Unrecognized" not in raw_txt
                ):
                    section = ""
                    for line in raw_txt.splitlines():
                        stripped = line.strip()
                        if not stripped or set(stripped) <= {"-", "="}:
                            continue
                        low = stripped.lower()
                        if "mode" in low and "native vlan" in low:
                            section = "mode"
                            continue
                        if "vlans allowed on trunk" in low:
                            section = "allowed"
                            continue
                        if "vlans allowed and active" in low:
                            section = "active"
                            continue
                        if "vlans in spanning tree forwarding" in low:
                            section = "forwarding"
                            continue
                        if low.startswith("port "):
                            continue
                        if section == "mode":
                            m_eos = re.match(
                                r"^\s*(\S+)\s+(on|trunk|auto|desirable)\s+(?:(\S+)\s+)?(trunking|not-trunking)\s+(\d+)",
                                line,
                                re.I,
                            )
                            if m_eos:
                                p, _mode_t, _enc, status_t, nat = m_eos.groups()
                                rec = ops.setdefault(p, {})
                                is_trk = status_t.lower() == "trunking"
                                rec["mode"] = "trunk" if is_trk else "access"
                                rec["oper_mode"] = "trunk" if is_trk else "access"
                                rec["encapsulation"] = "dot1q"
                                rec["native_vlan"] = nat
                        elif section == "allowed":
                            m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                            if m:
                                p, vlans = m.group(1), m.group(2).lower()
                                rec = ops.setdefault(p, {})
                                rec["mode"] = "trunk"
                                rec.setdefault("oper_mode", "trunk")
                                rec["trunk_allowed_vlans"] = vlans
                        elif section == "active":
                            m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                            if m:
                                p, vlans = m.group(1), m.group(2).lower()
                                rec = ops.setdefault(p, {})
                                rec.setdefault("mode", "trunk")
                                rec.setdefault("oper_mode", "trunk")
                                rec["trunk_active_vlans"] = vlans
                        elif section == "forwarding":
                            m = re.match(r"^\s*(\S+)\s+([\d,-]+|none|all)\s*$", line, re.I)
                            if m:
                                p, vlans = m.group(1), m.group(2).lower()
                                rec = ops.setdefault(p, {})
                                if not rec.get("trunk_active_vlans"):
                                    rec["trunk_active_vlans"] = vlans
            except Exception:
                pass

        # 2. Operational Port-Channel / LAG state (`show port-channel summary | json` with text fallback)
        parsed_pc_json = False
        try:
            raw_pc = conn.send_command("show port-channel summary | json")
            if isinstance(raw_pc, str) and raw_pc.strip().startswith("{"):
                data = json.loads(raw_pc)
                pcs = data.get("portChannels", {})
                if isinstance(pcs, dict):
                    for pc_name, pc_info in pcs.items():
                        if not isinstance(pc_info, dict):
                            continue
                        parsed_pc_json = True
                        proto = str(pc_info.get("protocol") or "lacp").lower()
                        ports_obj = pc_info.get("ports", {})
                        if isinstance(ports_obj, dict):
                            for m_port, m_info in ports_obj.items():
                                lacp_m = str(m_info.get("lacpMode") or "").lower() if isinstance(m_info, dict) else ""
                                if lacp_m not in ("active", "passive", "on"):
                                    lacp_m = "active" if "lacp" in proto else "on"
                                rec = ops.setdefault(m_port, {})
                                rec["lag_group"] = pc_name
                                rec["lacp_mode"] = lacp_m
                        elif isinstance(ports_obj, list):
                            for m_port in ports_obj:
                                if isinstance(m_port, str) and m_port:
                                    rec = ops.setdefault(m_port, {})
                                    rec["lag_group"] = pc_name
                                    rec["lacp_mode"] = "active" if "lacp" in proto else "on"
        except Exception:
            pass

        if not parsed_pc_json:
            try:
                raw_pc_txt = conn.send_command("show port-channel summary")
                if isinstance(raw_pc_txt, str) and raw_pc_txt.strip() and "Invalid input" not in raw_pc_txt:
                    for line in raw_pc_txt.splitlines():
                        m_pc = re.match(
                            r"^\s*\d+\s+(Po\d+|Port-Channel\d+)\([^)]*\)\s+(LACP|STATIC|-)\s+(.+)$",
                            line,
                            re.I,
                        )
                        if m_pc:
                            pc_name, proto, members_str = m_pc.group(1), m_pc.group(2).lower(), m_pc.group(3)
                            for tok in members_str.split():
                                pname = re.sub(r"\([^)]*\)$", "", tok).strip()
                                if pname:
                                    rec = ops.setdefault(pname, {})
                                    rec["lag_group"] = pc_name
                                    rec["lacp_mode"] = "active" if proto == "lacp" else "on"
            except Exception:
                pass

        return ops

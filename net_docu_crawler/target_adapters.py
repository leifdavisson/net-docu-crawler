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

"""
Target-Platform Configuration Adapters (Phase 6 / ADAPT-10).
Renders vendor-specific port/VLAN/SVI configurations strictly from correlated
`dev["ports"]` records, blocking rendering when mandatory fields are 'unknown'.
"""

_TARGET_VENDOR_ALIASES: dict[str, str] = {
    "juniper": "juniper",
    "junos": "juniper",
    "juniper_junos": "juniper",
    "meraki": "meraki",
    "cisco": "cisco",
    "ios": "cisco",
    "ios-xe": "cisco",
    "nxos": "cisco",
    "nx-os": "cisco",
    "cisco_ios": "cisco",
    "cisco_xe": "cisco",
    "cisco_nxos": "cisco",
    "arista": "arista",
    "eos": "arista",
    "arista_eos": "arista",
    "aruba": "aruba",
    "aruba_os": "aruba",
    "aruba_cx": "aruba",
    "arubaos": "aruba",
    "aos-cx": "aruba",
    "aoscx": "aruba",
    "hpprocurve": "hpprocurve",
    "hp_procurve": "hpprocurve",
    "procurve": "hpprocurve",
    "hp": "hpprocurve",
    "arubaos-s": "hpprocurve",
    "aos-s": "hpprocurve",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "fortios": "fortinet",
}


def normalize_target_vendor(target_vendor: str) -> str:
    """Normalize a target-vendor identifier or alias to its canonical adapter key."""
    raw = (target_vendor or "").strip().lower()
    return _TARGET_VENDOR_ALIASES.get(raw, raw)


def render_device_target_config(dev: dict, target_vendor: str) -> list[str]:
    """
    Render staged target-platform configuration lines for `dev`.
    Blocks any port with `mode == 'unknown'` or trunk `native_vlan == 'unknown'`.
    Supports: `meraki`, `juniper`, `cisco`, `arista`, `aruba` (AOS-CX), `hpprocurve`, `fortinet`.
    """
    tv = normalize_target_vendor(target_vendor)
    hostname = dev.get("hostname") or dev.get("ip", "")
    ports = dev.get("ports") or {}
    lines: list[str] = []

    if tv == "meraki":
        lines.append(f"# Meraki Switch Profile: {hostname}")
        for pname, p in ports.items():
            mode = p.get("mode", "unknown")
            if mode == "unknown" or (mode == "trunk" and p.get("native_vlan") in ("", "unknown")):
                lines.append(f"# BLOCKED: {pname} has unresolved mode/native_vlan; manual verification required")
                continue
            if mode == "access":
                lines.append(
                    f'{{"portId": "{pname}", "type": "access", "vlan": "{p.get("access_vlan", "")}", "voiceVlan": "{p.get("voice_vlan", "")}"}}'
                )
            elif mode == "trunk":
                allowed = ",".join(str(v) for v in (p.get("allowed_vlans") or []))
                lines.append(
                    f'{{"portId": "{pname}", "type": "trunk", "vlan": "{p.get("native_vlan", "none")}", "allowedVlans": "{allowed}"}}'
                )
        return lines

    for pname, p in ports.items():
        mode = p.get("mode", "unknown")
        native_vlan = str(p.get("native_vlan") or "").strip()
        access_vlan = str(p.get("access_vlan") or "").strip()
        voice_vlan = str(p.get("voice_vlan") or "").strip()
        allowed_vlans = [str(v).strip() for v in (p.get("allowed_vlans") or []) if str(v).strip()]

        if mode == "unknown" or (mode == "trunk" and native_vlan in ("", "unknown")):
            lines.append(f"# BLOCKED: {pname} has unresolved mode/native_vlan; manual verification required")
            continue

        if tv == "juniper":
            if mode == "access" and access_vlan:
                lines.append(f"set interfaces {pname} unit 0 family ethernet-switching interface-mode access")
                lines.append(f"set interfaces {pname} unit 0 family ethernet-switching vlan members {access_vlan}")
                if voice_vlan:
                    lines.append(f"set switch-options voip interface {pname}.0 vlan {voice_vlan}")
            elif mode == "trunk":
                lines.append(f"set interfaces {pname} unit 0 family ethernet-switching interface-mode trunk")
                if native_vlan and native_vlan != "none":
                    lines.append(
                        f"set interfaces {pname} unit 0 family ethernet-switching native-vlan-id {native_vlan}"
                    )
                if allowed_vlans:
                    lines.append(
                        f"set interfaces {pname} unit 0 family ethernet-switching vlan members [{' '.join(allowed_vlans)}]"
                    )
        elif tv in ("cisco", "arista"):
            lines.append(f"interface {pname}")
            if mode == "access" and access_vlan:
                lines.append(" switchport mode access")
                lines.append(f" switchport access vlan {access_vlan}")
                if voice_vlan:
                    lines.append(f" switchport voice vlan {voice_vlan}")
            elif mode == "trunk":
                lines.append(" switchport mode trunk")
                if native_vlan and native_vlan != "none":
                    lines.append(f" switchport trunk native vlan {native_vlan}")
                if allowed_vlans:
                    lines.append(f" switchport trunk allowed vlan {','.join(allowed_vlans)}")
        elif tv == "aruba":
            lines.append(f"interface {pname}")
            lines.append(" no routing")
            if mode == "access" and access_vlan:
                lines.append(f" vlan access {access_vlan}")
                if voice_vlan:
                    lines.append(f" # voice vlan {voice_vlan}")
            elif mode == "trunk":
                if native_vlan and native_vlan != "none":
                    lines.append(f" vlan trunk native {native_vlan}")
                if allowed_vlans:
                    lines.append(f" vlan trunk allowed {','.join(allowed_vlans)}")
        elif tv == "hpprocurve":
            lines.append(f"interface {pname}")
            if mode == "access" and access_vlan:
                lines.append(f" untagged vlan {access_vlan}")
                if voice_vlan:
                    lines.append(f" tagged vlan {voice_vlan}")
            elif mode == "trunk":
                if native_vlan and native_vlan != "none":
                    lines.append(f" untagged vlan {native_vlan}")
                if allowed_vlans:
                    lines.append(f" tagged vlan {','.join(allowed_vlans)}")
        elif tv == "fortinet":
            lines.append(f'edit "{pname}"')
            if mode == "access" and access_vlan:
                lines.append(f' set vlan "vlan{access_vlan}"')
                if voice_vlan:
                    lines.append(f' set allowed-vlans "vlan{voice_vlan}"')
            elif mode == "trunk":
                if native_vlan and native_vlan != "none":
                    lines.append(f" set native-vlan {native_vlan}")
                if allowed_vlans:
                    lines.append(f" set allowed-vlans {','.join(allowed_vlans)}")
            lines.append("next")
    return lines

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
Target-Platform Configuration Adapters (Phase 6 / ADAPT-10).
Renders vendor-specific port/VLAN/SVI configurations strictly from correlated
`dev["ports"]` records, blocking rendering when mandatory fields are 'unknown'.
"""


def render_device_target_config(dev: dict, target_vendor: str) -> list[str]:
    """
    Render staged target-platform configuration lines for `dev`.
    Blocks any port with `mode == 'unknown'` or trunk `native_vlan == 'unknown'`.
    """
    tv = (target_vendor or "").strip().lower()
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
                lines.append(f'{{"portId": "{pname}", "type": "access", "vlan": "{p.get("access_vlan", "")}", "voiceVlan": "{p.get("voice_vlan", "")}"}}')
            elif mode == "trunk":
                allowed = ",".join(p.get("allowed_vlans") or [])
                lines.append(f'{{"portId": "{pname}", "type": "trunk", "vlan": "{p.get("native_vlan", "none")}", "allowedVlans": "{allowed}"}}')
        return lines

    for pname, p in ports.items():
        mode = p.get("mode", "unknown")
        if mode == "unknown" or (mode == "trunk" and p.get("native_vlan") in ("", "unknown")):
            lines.append(f"# BLOCKED: {pname} has unresolved mode/native_vlan; manual verification required")
            continue
        if tv == "juniper":
            if mode == "access" and p.get("access_vlan"):
                lines.append(f"set interfaces {pname} unit 0 family ethernet-switching interface-mode access")
                lines.append(f"set interfaces {pname} unit 0 family ethernet-switching vlan members {p['access_vlan']}")
            elif mode == "trunk":
                lines.append(f"set interfaces {pname} unit 0 family ethernet-switching interface-mode trunk")
                if p.get("allowed_vlans"):
                    lines.append(f"set interfaces {pname} unit 0 family ethernet-switching vlan members [{' '.join(p['allowed_vlans'])}]")
        elif tv in ("cisco", "arista", "aruba"):
            lines.append(f"interface {pname}")
            if mode == "access" and p.get("access_vlan"):
                lines.append(" switchport mode access")
                lines.append(f" switchport access vlan {p['access_vlan']}")
            elif mode == "trunk":
                lines.append(" switchport mode trunk")
                if p.get("allowed_vlans"):
                    lines.append(f" switchport trunk allowed vlan {','.join(p['allowed_vlans'])}")
    return lines

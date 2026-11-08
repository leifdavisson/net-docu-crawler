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
Net-Docu-Crawler: Unified Multi-Vendor Network Infrastructure Documentation Engine.
Consolidates zero-blast-radius discovery across Cisco, Juniper, Aruba, Palo Alto,
Arista, MikroTik, Fortinet, FRRouting, OPNsense, and OpenWrt platforms.
"""

from net_docu_crawler.drivers import (
    DRIVER_REGISTRY,
    AristaDriver,
    ArubaDriver,
    BaseDriver,
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
from net_docu_crawler.topology_resolver import DeviceRegistry

__version__ = "2.0.0"

__all__ = [
    "BaseDriver",
    "CiscoDriver",
    "JuniperDriver",
    "ArubaDriver",
    "PaloAltoDriver",
    "FortinetDriver",
    "AristaDriver",
    "MikroTikDriver",
    "FRRDriver",
    "OPNsenseDriver",
    "OpenWrtDriver",
    "DRIVER_REGISTRY",
    "DeviceRegistry",
    "get_driver",
]

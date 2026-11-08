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
Driver Registry and Factory Dispatch for Net-Docu-Crawler.
Instantiates verified, zero-blast-radius multi-vendor drivers.
"""

from net_docu_crawler.drivers.arista import AristaDriver
from net_docu_crawler.drivers.aruba import ArubaDriver
from net_docu_crawler.drivers.base import BaseDriver
from net_docu_crawler.drivers.cisco import CiscoDriver
from net_docu_crawler.drivers.detector import detect_vendor_range
from net_docu_crawler.drivers.fortinet import FortinetDriver
from net_docu_crawler.drivers.frr import FRRDriver
from net_docu_crawler.drivers.juniper import JuniperDriver
from net_docu_crawler.drivers.mikrotik import MikroTikDriver
from net_docu_crawler.drivers.openwrt import OpenWrtDriver
from net_docu_crawler.drivers.opnsense import OPNsenseDriver
from net_docu_crawler.drivers.paloalto import PaloAltoDriver

# Registry mapping vendor string to driver class
DRIVER_REGISTRY: dict[str, type[BaseDriver]] = {
    "cisco": CiscoDriver,
    "juniper": JuniperDriver,
    "aruba": ArubaDriver,
    "paloalto": PaloAltoDriver,
    "fortinet": FortinetDriver,
    "arista": AristaDriver,
    "mikrotik": MikroTikDriver,
    "frrouting": FRRDriver,
    "frr": FRRDriver,
    "opnsense": OPNsenseDriver,
    "openwrt": OpenWrtDriver,
}


def get_driver(
    ip: str,
    mac: str = "",
    username: str = "",
    password: str = "",
    secret: str = "",
    vendor_hint: str | None = None,
    timeout: int = 10,
) -> BaseDriver:
    """
    Factory function returning the appropriate vendor driver instance.
    If vendor_hint is provided, uses it directly; otherwise executes the Zero-Blast Detection cascade.
    """
    vendor = vendor_hint.lower() if vendor_hint else ""

    if not vendor or vendor not in DRIVER_REGISTRY:
        detected_vendor, _banner = detect_vendor_range(ip, mac=mac, timeout=float(timeout))
        vendor = detected_vendor

    # Default fallback to CiscoDriver if unknown (preserves legacy behavior safely)
    driver_cls = DRIVER_REGISTRY.get(vendor, CiscoDriver)
    return driver_cls(ip=ip, username=username, password=password, secret=secret, timeout=timeout)


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
    "get_driver",
]

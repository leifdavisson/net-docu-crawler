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
from net_docu_crawler.drivers.ciscosmb import CiscoSMBDriver
from net_docu_crawler.drivers.detector import detect_vendor_range
from net_docu_crawler.drivers.fortinet import FortinetDriver
from net_docu_crawler.drivers.frr import FRRDriver
from net_docu_crawler.drivers.hpprocurve import HPProCurveDriver
from net_docu_crawler.drivers.juniper import JuniperDriver
from net_docu_crawler.drivers.mikrotik import MikroTikDriver
from net_docu_crawler.drivers.openwrt import OpenWrtDriver
from net_docu_crawler.drivers.opnsense import OPNsenseDriver
from net_docu_crawler.drivers.paloalto import PaloAltoDriver

# Registry mapping vendor string to driver class (single source of truth)
DRIVER_REGISTRY: dict[str, type[BaseDriver]] = {
    "cisco": CiscoDriver,
    "ciscosmb": CiscoSMBDriver,
    "cisco_s300": CiscoSMBDriver,
    "cbs": CiscoSMBDriver,
    "sg300": CiscoSMBDriver,
    "sg350": CiscoSMBDriver,
    "juniper": JuniperDriver,
    "aruba": ArubaDriver,
    "hpprocurve": HPProCurveDriver,
    "procurve": HPProCurveDriver,
    "hp": HPProCurveDriver,
    "paloalto": PaloAltoDriver,
    "fortinet": FortinetDriver,
    "arista": AristaDriver,
    "mikrotik": MikroTikDriver,
    "frrouting": FRRDriver,
    "frr": FRRDriver,
    "opnsense": OPNsenseDriver,
    "openwrt": OpenWrtDriver,
}

# Canonical alias used by crawler and external callers/tests
VENDOR_DRIVER_MAP: dict[str, type[BaseDriver]] = DRIVER_REGISTRY

# Reverse mapping from driver class to canonical vendor key
DRIVER_VENDOR_MAP: dict[type[BaseDriver], str] = {
    CiscoDriver: "cisco",
    CiscoSMBDriver: "ciscosmb",
    AristaDriver: "arista",
    JuniperDriver: "juniper",
    FortinetDriver: "fortinet",
    ArubaDriver: "aruba",
    HPProCurveDriver: "hpprocurve",
    PaloAltoDriver: "paloalto",
    MikroTikDriver: "mikrotik",
    OPNsenseDriver: "opnsense",
    OpenWrtDriver: "openwrt",
    FRRDriver: "frrouting",
}


def resolve_driver_for_vendor(
    vendor: str | None,
    default: type[BaseDriver] | None = None,
) -> type[BaseDriver] | None:
    """Resolve a vendor identifier or alias to its registered `BaseDriver` subclass."""
    norm = (vendor or "").strip().lower()
    if not norm:
        return default
    return DRIVER_REGISTRY.get(norm, default)


def resolve_vendor_for_driver(driver_cls: type[BaseDriver]) -> str:
    """Return the canonical vendor identifier for a `BaseDriver` subclass."""
    return DRIVER_VENDOR_MAP.get(driver_cls, "")


def get_driver(
    ip: str,
    mac: str = "",
    username: str = "",
    password: str = "",
    secret: str = "",
    vendor_hint: str | None = None,
    timeout: int = 10,
    port: int | None = None,
    transport: str = "ssh",
) -> BaseDriver:
    """
    Factory function returning the appropriate vendor driver instance.
    If vendor_hint is provided, uses it directly; otherwise executes the Zero-Blast Detection cascade.
    """
    vendor = vendor_hint.lower() if vendor_hint else ""

    if not vendor or vendor not in DRIVER_REGISTRY:
        probe_port = port if port is not None else (23 if transport == "telnet" else 22)
        detected_vendor, _banner = detect_vendor_range(
            ip, mac=mac, port=probe_port, timeout=float(timeout), transport=transport
        )
        vendor = detected_vendor

    # Default fallback to CiscoDriver if unknown (preserves legacy behavior safely)
    driver_cls = resolve_driver_for_vendor(vendor, default=CiscoDriver) or CiscoDriver
    return driver_cls(
        ip=ip,
        username=username,
        password=password,
        secret=secret,
        timeout=timeout,
        port=port,
        transport=transport,
    )


__all__ = [
    "BaseDriver",
    "CiscoDriver",
    "CiscoSMBDriver",
    "JuniperDriver",
    "ArubaDriver",
    "PaloAltoDriver",
    "FortinetDriver",
    "HPProCurveDriver",
    "AristaDriver",
    "MikroTikDriver",
    "FRRDriver",
    "OPNsenseDriver",
    "OpenWrtDriver",
    "DRIVER_REGISTRY",
    "VENDOR_DRIVER_MAP",
    "DRIVER_VENDOR_MAP",
    "resolve_driver_for_vendor",
    "resolve_vendor_for_driver",
    "get_driver",
]

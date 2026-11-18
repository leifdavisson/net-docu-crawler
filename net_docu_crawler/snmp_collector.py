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
Read-Only SNMPv2c GetBulk MIB Table Walker (Phase 2).
Zero external dependencies; strictly bounded by `max_rows` and `timeout`.
Supports IF-MIB and LLDP-MIB fallback enrichment when CLI access is unavailable.
"""

import socket

from net_docu_crawler.drivers.detector import _ber_tlv, _encode_oid

OID_IF_NAME = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
OID_IF_ALIAS = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18)
OID_IF_ADMIN = (1, 3, 6, 1, 2, 1, 2, 2, 1, 7)
OID_IF_OPER = (1, 3, 6, 1, 2, 1, 2, 2, 1, 8)
OID_LLDP_REM_SYSNAME = (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9)


def build_getbulk_packet(
    community: str,
    oid: tuple[int, ...],
    max_repetitions: int = 25,
    request_id: int = 1,
) -> bytes:
    """Build an SNMPv2c GetBulkRequest (PDU tag 0xA5) packet."""
    vb = _ber_tlv(0x30, _encode_oid(oid) + b"\x05\x00")
    varbinds = _ber_tlv(0x30, vb)
    pdu = _ber_tlv(
        0xA5,
        _ber_tlv(0x02, request_id.to_bytes(2, "big"))
        + _ber_tlv(0x02, b"\x00")  # non-repeaters = 0
        + _ber_tlv(0x02, max_repetitions.to_bytes(1, "big"))
        + varbinds,
    )
    return _ber_tlv(
        0x30,
        _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, community.encode("utf-8")) + pdu,
    )


def snmp_getbulk_raw(
    ip: str,
    oid: tuple[int, ...],
    community: str = "public",
    port: int = 161,
    timeout: float = 1.5,
    max_repetitions: int = 25,
) -> bytes:
    """Send a single read-only SNMPv2c GetBulkRequest and return raw response bytes."""
    pkt = build_getbulk_packet(community=community, oid=oid, max_repetitions=max_repetitions)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (ip, port))
        resp, _ = sock.recvfrom(8192)
        return resp
    except Exception:
        return b""
    finally:
        sock.close()


def _read_ber_len(buf: bytes, idx: int) -> tuple[int, int]:
    """Decode ASN.1 BER length field starting at `idx`, returning (length, next_idx)."""
    first = buf[idx]
    if first < 0x80:
        return first, idx + 1
    num_bytes = first & 0x7F
    length = int.from_bytes(buf[idx + 1 : idx + 1 + num_bytes], "big")
    return length, idx + 1 + num_bytes


def _decode_oid(raw: bytes) -> str:
    """Decode BER OBJECT IDENTIFIER payload into dotted string."""
    if not raw:
        return ""
    arcs = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(val)
            val = 0
    return ".".join(str(a) for a in arcs)


def _decode_ber_value(tag: int, payload: bytes) -> object:
    """Decode basic SNMPv2c BER value tags."""
    if tag == 0x04:  # OCTET STRING
        return payload.decode("utf-8", errors="replace")
    if tag in (0x02, 0x41, 0x42, 0x43):  # INTEGER, Counter32, Gauge32, TimeTicks
        return int.from_bytes(payload, "big", signed=(tag == 0x02))
    if tag == 0x40 and len(payload) == 4:  # IpAddress
        return ".".join(str(b) for b in payload)
    if tag == 0x06:  # OBJECT IDENTIFIER
        return _decode_oid(payload)
    if tag in (0x05, 0x80, 0x81, 0x82):  # NULL, noSuchObject, noSuchInstance, endOfMibView
        return None
    return payload.hex()


def parse_getbulk_response(data: bytes) -> list[tuple[str, object]]:
    """Decode an SNMPv2c GetResponse-PDU (0xA2) into a list of `(oid_str, value)` tuples."""
    if not data or len(data) < 10 or data[0] != 0x30:
        return []
    try:
        _, idx = _read_ber_len(data, 1)
        # Skip version (INTEGER) and community (OCTET STRING)
        for _ in range(2):
            v_len, idx = _read_ber_len(data, idx + 1)
            idx += v_len
        if idx >= len(data) or data[idx] != 0xA2:
            return []
        _, idx = _read_ber_len(data, idx + 1)
        # Skip request-id, error-status, error-index
        for _ in range(3):
            f_len, idx = _read_ber_len(data, idx + 1)
            idx += f_len
        if idx >= len(data) or data[idx] != 0x30:
            return []
        vb_list_len, idx = _read_ber_len(data, idx + 1)
        end = min(len(data), idx + vb_list_len)
        results: list[tuple[str, object]] = []
        while idx < end:
            if data[idx] != 0x30:
                break
            seq_len, v_idx = _read_ber_len(data, idx + 1)
            next_seq = v_idx + seq_len
            if data[v_idx] != 0x06:
                idx = next_seq
                continue
            oid_len, o_idx = _read_ber_len(data, v_idx + 1)
            oid_str = _decode_oid(data[o_idx : o_idx + oid_len])
            val_idx = o_idx + oid_len
            val_tag = data[val_idx]
            val_len, p_idx = _read_ber_len(data, val_idx + 1)
            val = _decode_ber_value(val_tag, data[p_idx : p_idx + val_len])
            results.append((oid_str, val))
            idx = next_seq
        return results
    except Exception:
        return []


def collect_snmp_fallback(ip: str, community: str = "public", timeout: float = 2.0) -> dict:
    """
    Bounded read-only SNMPv2c GetBulk collector for IF-MIB and LLDP-MIB
    when SSH/CLI access is unavailable.
    """
    if_names: dict[str, str] = {}
    if_aliases: dict[str, str] = {}
    if_admin: dict[str, str] = {}
    if_oper: dict[str, str] = {}
    lldp_names: list[dict] = []

    def _walk(base_oid: tuple[int, ...]) -> list[tuple[str, object]]:
        raw = snmp_getbulk_raw(ip, base_oid, community=community, timeout=timeout, max_repetitions=30)
        prefix = ".".join(str(x) for x in base_oid) + "."
        return [(o[len(prefix) :], v) for o, v in parse_getbulk_response(raw) if o.startswith(prefix)]

    for idx, val in _walk(OID_IF_NAME):
        if_names[idx] = str(val)
    for idx, val in _walk(OID_IF_ALIAS):
        if_aliases[idx] = str(val)
    for idx, val in _walk(OID_IF_ADMIN):
        if_admin[idx] = "up" if val == 1 else "down"
    for idx, val in _walk(OID_IF_OPER):
        if_oper[idx] = "up" if val == 1 else "down"
    for idx, val in _walk(OID_LLDP_REM_SYSNAME):
        if val:
            lldp_names.append({"index": idx, "remote_device": str(val)})

    interfaces_detail = {}
    for idx, name in if_names.items():
        interfaces_detail[name] = {
            "status": if_oper.get(idx, "unknown"),
            "admin_status": if_admin.get(idx, "unknown"),
            "description": if_aliases.get(idx, ""),
        }
    return {"interfaces_detail": interfaces_detail, "lldp_remote_names": lldp_names}

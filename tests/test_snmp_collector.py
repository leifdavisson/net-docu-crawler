# Copyright (C) 2026 Leif Davisson <leifdavisson@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net_docu_crawler.snmp_collector import OID_IF_NAME, build_getbulk_packet


def test_build_getbulk_packet():
    pkt = build_getbulk_packet("public", OID_IF_NAME, max_repetitions=10, request_id=42)
    assert pkt.startswith(b"\x30")
    assert b"public" in pkt
    assert b"\xa5" in pkt  # GetBulkRequest-PDU tag


def test_parse_getbulk_response_ber():
    from net_docu_crawler.drivers.detector import _ber_tlv, _encode_oid
    from net_docu_crawler.snmp_collector import parse_getbulk_response

    vb1 = _ber_tlv(0x30, _encode_oid(OID_IF_NAME + (1,)) + _ber_tlv(0x04, b"ge-0/0/0"))
    vb2 = _ber_tlv(0x30, _encode_oid((1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)) + _ber_tlv(0x02, b"\x01"))
    pdu = _ber_tlv(
        0xA2,
        _ber_tlv(0x02, b"\x01") + _ber_tlv(0x02, b"\x00") + _ber_tlv(0x02, b"\x00") + _ber_tlv(0x30, vb1 + vb2),
    )
    resp = _ber_tlv(0x30, _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, b"public") + pdu)
    parsed = parse_getbulk_response(resp)
    assert parsed == [("1.3.6.1.2.1.31.1.1.1.1.1", "ge-0/0/0"), ("1.3.6.1.2.1.2.2.1.8.1", 1)]

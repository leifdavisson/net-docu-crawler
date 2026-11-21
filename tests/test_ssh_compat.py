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
Unit and wire-protocol tests for `net_docu_crawler.ssh_compat` (GitHub Issue #1).
"""

from __future__ import annotations

import hashlib
import logging
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import paramiko
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.ed25519key import Ed25519Key
from paramiko.kex_curve25519 import KexCurve25519
from paramiko.kex_group1 import KexGroup1
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import (
    AuthenticationException,
    BadHostKeyException,
    IncompatiblePeer,
    SSHException,
)
from paramiko.transport import Transport

from net_docu_crawler.drivers.base import BaseDriver
from net_docu_crawler.drivers.opnsense import OPNsenseDriver, OPNsenseSSHConnection
from net_docu_crawler.ssh_compat import (
    LEGACY_CIPHERS,
    LEGACY_KEX_ALGORITHMS,
    LEGACY_MACS,
    KexGroup18SHA512,
    LegacyDSSKey,
    configure_paramiko_compat,
    connect_netmiko_with_fallback,
    connect_paramiko_with_fallback,
    is_ssh_negotiation_error,
)


@pytest.fixture(autouse=True)
def _restore_paramiko_transport_tables():
    """Snapshots and restores global Paramiko algorithm registries around each test."""
    orig_kex_info = dict(Transport._kex_info)
    orig_pref_kex = tuple(Transport._preferred_kex)
    orig_key_info = dict(Transport._key_info)
    orig_pref_keys = tuple(Transport._preferred_keys)
    orig_pref_ciphers = tuple(Transport._preferred_ciphers)
    orig_pref_macs = tuple(Transport._preferred_macs)
    orig_key_classes = list(getattr(paramiko, "key_classes", []))

    # Strip custom registrations before each test to verify clean registration
    Transport._kex_info.pop("curve25519-sha256", None)
    Transport._kex_info.pop("diffie-hellman-group18-sha512", None)
    Transport._preferred_kex = tuple(
        k for k in Transport._preferred_kex if k not in ("curve25519-sha256", "diffie-hellman-group18-sha512")
    )
    Transport._key_info.pop("ssh-dss", None)
    Transport._key_info.pop("ssh-dss-cert-v01@openssh.com", None)
    Transport._preferred_keys = tuple(k for k in Transport._preferred_keys if k != "ssh-dss")
    if hasattr(paramiko, "key_classes") and LegacyDSSKey in paramiko.key_classes:
        paramiko.key_classes.remove(LegacyDSSKey)

    yield

    Transport._kex_info = orig_kex_info
    Transport._preferred_kex = orig_pref_kex
    Transport._key_info = orig_key_info
    Transport._preferred_keys = orig_pref_keys
    Transport._preferred_ciphers = orig_pref_ciphers
    Transport._preferred_macs = orig_pref_macs
    if hasattr(paramiko, "key_classes"):
        paramiko.key_classes[:] = orig_key_classes


def _build_1024bit_dsa_keypair() -> tuple[dsa.DSAPrivateKey, bytes]:
    priv = dsa.generate_private_key(key_size=1024)
    pub_nums = priv.public_key().public_numbers()
    param_nums = pub_nums.parameter_numbers
    msg = Message()
    msg.add_string("ssh-dss")
    msg.add_mpint(param_nums.p)
    msg.add_mpint(param_nums.q)
    msg.add_mpint(param_nums.g)
    msg.add_mpint(pub_nums.y)
    return priv, msg.asbytes()


def test_configure_paramiko_compat_registers_curve25519_and_group18_idempotently():
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(configure_paramiko_compat, False) for _ in range(16)]
        for fut in futures:
            fut.result()

    assert logging.getLogger("paramiko").level == logging.CRITICAL
    assert logging.getLogger("paramiko.transport").level == logging.CRITICAL

    if KexCurve25519.is_available():
        assert Transport._kex_info["curve25519-sha256"] is KexCurve25519
        assert Transport._preferred_kex.count("curve25519-sha256") == 1

    assert Transport._kex_info["diffie-hellman-group18-sha512"] is KexGroup18SHA512
    assert issubclass(KexGroup18SHA512, KexGroup1)
    assert KexGroup18SHA512.P.bit_length() == 8192
    assert KexGroup18SHA512.G == 2
    assert KexGroup18SHA512.hash_algo is hashlib.sha512
    assert Transport._preferred_kex.count("diffie-hellman-group18-sha512") == 1

    # Stage 1 keeps legacy ssh-dss disabled
    assert "ssh-dss" not in Transport._key_info
    assert "ssh-dss" not in Transport._preferred_keys


def test_configure_paramiko_compat_enables_legacy_dss_and_legacy_algorithms():
    # Simulate an environment where legacy SHA-1/CBC/MD5 entries were stripped from _preferred_*
    Transport._preferred_kex = ("ecdh-sha2-nistp256",)
    Transport._preferred_ciphers = ("aes256-ctr",)
    Transport._preferred_macs = ("hmac-sha2-256",)

    configure_paramiko_compat(enable_legacy_dss=True)
    configure_paramiko_compat(enable_legacy_dss=True)

    assert Transport._key_info["ssh-dss"] is LegacyDSSKey
    assert Transport._preferred_keys.count("ssh-dss") == 1
    for kex in LEGACY_KEX_ALGORITHMS:
        assert Transport._preferred_kex.count(kex) == 1
    for cipher in LEGACY_CIPHERS:
        assert Transport._preferred_ciphers.count(cipher) == 1
    for mac in LEGACY_MACS:
        assert Transport._preferred_macs.count(mac) == 1


def test_legacy_dss_key_1024bit_signature_verification_and_serialization():
    priv, pub_wire = _build_1024bit_dsa_keypair()

    dss_key = LegacyDSSKey(msg=Message(pub_wire))
    assert dss_key.get_name() == "ssh-dss"
    assert LegacyDSSKey.identifiers() == ["ssh-dss"]
    assert dss_key.get_bits() == 1024
    assert dss_key.can_sign() is False
    assert dss_key.asbytes() == pub_wire

    # Roundtrip via data= and PKey.from_type_string when legacy DSS is enabled
    configure_paramiko_compat(enable_legacy_dss=True)
    dss_from_type = PKey.from_type_string("ssh-dss", pub_wire)
    assert isinstance(dss_from_type, LegacyDSSKey)
    assert dss_from_type == dss_key

    with pytest.raises(SSHException):
        dss_key.sign_ssh_data(b"read-only")

    exchange_hash = hashlib.sha256(b"ssh-v2-kex-exchange-hash").digest()
    der_sig = priv.sign(exchange_hash, hashes.SHA1())
    r, s = decode_dss_signature(der_sig)
    raw_rs = r.to_bytes(20, byteorder="big") + s.to_bytes(20, byteorder="big")
    assert len(raw_rs) == 40

    sig_msg = Message()
    sig_msg.add_string("ssh-dss")
    sig_msg.add_string(raw_rs)
    assert dss_key.verify_ssh_sig(exchange_hash, Message(sig_msg.asbytes())) is True

    # Also support bare 40-byte r || s signature blobs from non-compliant legacy daemons
    assert dss_key.verify_ssh_sig(exchange_hash, Message(raw_rs)) is True

    # Reject tampered data, corrupted signature bytes, wrong algorithm tag, and bad length
    assert dss_key.verify_ssh_sig(b"tampered-hash", Message(sig_msg.asbytes())) is False

    corrupted_rs = bytes([raw_rs[0] ^ 0xFF]) + raw_rs[1:]
    bad_sig_msg = Message()
    bad_sig_msg.add_string("ssh-dss")
    bad_sig_msg.add_string(corrupted_rs)
    assert dss_key.verify_ssh_sig(exchange_hash, Message(bad_sig_msg.asbytes())) is False

    wrong_algo_msg = Message()
    wrong_algo_msg.add_string("ssh-rsa")
    wrong_algo_msg.add_string(raw_rs)
    assert dss_key.verify_ssh_sig(exchange_hash, Message(wrong_algo_msg.asbytes())) is False

    short_sig_msg = Message()
    short_sig_msg.add_string("ssh-dss")
    short_sig_msg.add_string(raw_rs[:39])
    assert dss_key.verify_ssh_sig(exchange_hash, Message(short_sig_msg.asbytes())) is False


@pytest.mark.parametrize("kex_name", ["curve25519-sha256", "diffie-hellman-group18-sha512"])
def test_live_socketpair_kex_handshake_for_registered_algorithms(kex_name: str, tmp_path):
    if kex_name == "curve25519-sha256" and not KexCurve25519.is_available():
        pytest.skip("X25519 not supported by local OpenSSL backend")

    configure_paramiko_compat(enable_legacy_dss=False)

    raw_ed = ed25519.Ed25519PrivateKey.generate()
    key_path = tmp_path / "host_ed25519"
    key_path.write_bytes(
        raw_ed.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.OpenSSH,
            encryption_algorithm=NoEncryption(),
        )
    )
    host_key = Ed25519Key(filename=str(key_path))

    disable_other_kex = [k for k in Transport._preferred_kex if k != kex_name]
    s_sock, c_sock = socket.socketpair()
    server_t = Transport(s_sock, disabled_algorithms={"kex": disable_other_kex})
    client_t = Transport(c_sock, disabled_algorithms={"kex": disable_other_kex})
    try:
        server_t.add_server_key(host_key)
        server_err: list[BaseException] = []

        def _run_server():
            try:
                event = threading.Event()
                server_t.start_server(event=event, server=paramiko.ServerInterface())
                event.wait(timeout=10)
            except BaseException as exc:
                server_err.append(exc)

        t = threading.Thread(target=_run_server, daemon=True)
        t.start()
        client_t.start_client(timeout=10)
        t.join(timeout=10)
        assert not server_err
        assert client_t.is_active()
        assert client_t.get_remote_server_key() == host_key
    finally:
        client_t.close()
        server_t.close()
        c_sock.close()
        s_sock.close()


def test_is_ssh_negotiation_error_matches_negotiation_only():
    positive_samples = [
        IncompatiblePeer("Incompatible ssh peer (no acceptable kex algorithm)"),
        BadHostKeyException("10.0.0.1", MagicMock(), MagicMock()),
        Exception("Incompatible ssh server (no acceptable cipher)"),
        Exception("no acceptable host key"),
        Exception("no matching host key type found"),
        Exception("no acceptable mac"),
        Exception("key exchange failed"),
        Exception("unable to agree on key exchange"),
        Exception("bad host key"),
        Exception("Invalid key (class: LegacyDSSKey)"),
        NetmikoTimeoutException(
            "A paramiko SSHException occurred during connection creation:\n\n"
            "Incompatible ssh peer (no acceptable kex algorithm)\n"
        ),
    ]
    for exc in positive_samples:
        assert is_ssh_negotiation_error(exc) is True

    negative_samples = [
        AuthenticationException("Authentication failed."),
        NetmikoAuthenticationException("Authentication to device failed.\nInvalid key or password"),
        Exception("Authentication failed: invalid key"),
        Exception("Permission denied (publickey,password)."),
        NetmikoTimeoutException("TCP connection to device failed."),
        TimeoutError("timed out"),
        ConnectionRefusedError("Connection refused"),
    ]
    for exc in negative_samples:
        assert is_ssh_negotiation_error(exc) is False


def test_connect_netmiko_with_fallback_stage1_stage2_stage3_and_fast_abort():
    base_params = {"device_type": "cisco_ios", "ip": "10.0.0.10", "username": "admin", "password": "pw"}

    # 1) Stage 2 succeeds: disable_sha2_fix MUST be False, ssh-dss enabled
    mock_stage2 = MagicMock(
        side_effect=[
            IncompatiblePeer("Incompatible ssh peer (no acceptable host key)"),
            MagicMock(base_prompt="R1#"),
        ]
    )
    with patch("netmiko.ConnectHandler", mock_stage2):
        conn = connect_netmiko_with_fallback(base_params)
        assert conn.base_prompt == "R1#"
        assert mock_stage2.call_count == 2
        assert "disabled_algorithms" not in base_params
        stage2_call = mock_stage2.call_args_list[1][1]
        assert stage2_call["disabled_algorithms"] == {}
        assert stage2_call["disable_sha2_fix"] is False
        assert stage2_call["ssh_strict"] is False
        assert "ssh-dss" in Transport._key_info

    # 2) Stage 3 succeeds when Stage 2 fails with SSHException / broken rsa-sha2
    mock_stage3 = MagicMock(
        side_effect=[
            IncompatiblePeer("Incompatible ssh peer (no acceptable kex algorithm)"),
            NetmikoTimeoutException(
                "A paramiko SSHException occurred during connection creation:\n\n"
                "Signature verification (rsa-sha2-512) failed."
            ),
            MagicMock(base_prompt="OldIOS#"),
        ]
    )
    with patch("netmiko.ConnectHandler", mock_stage3):
        conn = BaseDriver.safe_netmiko_connect(base_params)
        assert conn.base_prompt == "OldIOS#"
        assert mock_stage3.call_count == 3
        assert mock_stage3.call_args_list[1][1]["disable_sha2_fix"] is False
        stage3_call = mock_stage3.call_args_list[2][1]
        assert stage3_call["disabled_algorithms"] == {}
        assert stage3_call["disable_sha2_fix"] is True
        assert stage3_call["ssh_strict"] is False

    # 3) Immediate re-raise on Stage 1 authentication failure (anti-lockout)
    mock_auth_fail = MagicMock(side_effect=NetmikoAuthenticationException("Authentication to device failed."))
    with patch("netmiko.ConnectHandler", mock_auth_fail):
        with pytest.raises(NetmikoAuthenticationException):
            connect_netmiko_with_fallback(base_params)
        assert mock_auth_fail.call_count == 1

    # 4) Immediate re-raise on Stage 1 TCP timeout
    mock_tcp_fail = MagicMock(side_effect=NetmikoTimeoutException("TCP connection to device failed."))
    with patch("netmiko.ConnectHandler", mock_tcp_fail):
        with pytest.raises(NetmikoTimeoutException):
            connect_netmiko_with_fallback(base_params)
        assert mock_tcp_fail.call_count == 1

    # 5) Stage 2 reaches userauth and fails password -> must NOT burn a Stage 3 attempt
    mock_stage2_auth_fail = MagicMock(
        side_effect=[
            IncompatiblePeer("Incompatible ssh peer (no acceptable host key)"),
            NetmikoAuthenticationException("Authentication to device failed."),
        ]
    )
    with patch("netmiko.ConnectHandler", mock_stage2_auth_fail):
        with pytest.raises(NetmikoAuthenticationException):
            connect_netmiko_with_fallback(base_params)
        assert mock_stage2_auth_fail.call_count == 2


def test_opnsense_driver_connect_uses_three_stage_paramiko_fallback():
    driver = OPNsenseDriver(ip="192.168.1.1", username="root", password="secret", timeout=7)

    # Stage 1 -> Stage 2 -> Stage 3 fallback via OPNsenseDriver.connect()
    mock_client = MagicMock(spec=paramiko.SSHClient)
    mock_client.connect.side_effect = [
        IncompatiblePeer("Incompatible ssh peer (no acceptable kex algorithm)"),
        SSHException("Signature verification (rsa-sha2-512) failed."),
        None,
    ]

    with patch("net_docu_crawler.drivers.opnsense.paramiko.SSHClient", return_value=mock_client):
        conn = driver.connect()
        assert isinstance(conn, OPNsenseSSHConnection)
        assert conn.client is mock_client
        assert mock_client.connect.call_count == 3

        stage1_kwargs = mock_client.connect.call_args_list[0][1]
        assert "disabled_algorithms" not in stage1_kwargs
        assert stage1_kwargs["hostname"] == "192.168.1.1"

        stage2_kwargs = mock_client.connect.call_args_list[1][1]
        assert stage2_kwargs["disabled_algorithms"] == {}
        assert "ssh-dss" in Transport._key_info

        stage3_kwargs = mock_client.connect.call_args_list[2][1]
        assert stage3_kwargs["disabled_algorithms"] == {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}

    # Authentication error aborts immediately on Stage 1
    mock_auth_client = MagicMock(spec=paramiko.SSHClient)
    mock_auth_client.connect.side_effect = AuthenticationException("Authentication failed.")
    with pytest.raises(AuthenticationException):
        connect_paramiko_with_fallback(mock_auth_client, hostname="192.168.1.1", username="root", password="bad")
    assert mock_auth_client.connect.call_count == 1

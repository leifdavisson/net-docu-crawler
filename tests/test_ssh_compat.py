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
Unit and wire-protocol tests for `net_docu_crawler.ssh_compat`, `OPNsenseDriver`
host-key hardening, and `detector.probe_http_fingerprint` TLS isolation.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.ed25519key import Ed25519Key
from paramiko.kex_curve25519 import KexCurve25519
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
from net_docu_crawler.drivers.detector import (
    _build_unverified_probe_tls_context,
    probe_http_fingerprint,
)
from net_docu_crawler.drivers.opnsense import (
    AuditedMissingHostKeyPolicy,
    OPNsenseDriver,
    OPNsenseSSHConnection,
)
from net_docu_crawler.ssh_compat import (
    LEGACY_CIPHERS,
    LEGACY_KEX_ALGORITHMS,
    LEGACY_MACS,
    STAGE1_DISABLED_ALGORITHMS,
    KexGroup18SHA512,
    LegacyDSSKey,
    build_legacy_transport,
    configure_paramiko_compat,
    connect_netmiko_with_fallback,
    connect_paramiko_with_fallback,
    is_ssh_negotiation_error,
    legacy_ssh_fallback_scope,
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
    assert hasattr(KexGroup18SHA512, "start_kex") and hasattr(KexGroup18SHA512, "parse_next")
    assert KexGroup18SHA512.P.bit_length() == 8192
    assert KexGroup18SHA512.G == 2
    assert KexGroup18SHA512.hash_algo is hashlib.sha512
    assert Transport._preferred_kex.count("diffie-hellman-group18-sha512") == 1

    # Stage 1 keeps legacy ssh-dss disabled globally
    assert "ssh-dss" not in Transport._key_info
    assert "ssh-dss" not in Transport._preferred_keys


def test_configure_paramiko_compat_enables_legacy_dss_and_legacy_algorithms():
    # Backward-compatibility check when a caller explicitly opts into global legacy registration
    Transport._preferred_kex = ("ecdh-sha2-nistp256",)
    Transport._preferred_ciphers = ("aes256-ctr",)
    Transport._preferred_macs = ("hmac-sha2-256",)

    configure_paramiko_compat(enable_legacy_dss=True)
    configure_paramiko_compat(enable_legacy_dss=True)

    assert Transport._key_info["ssh-dss"] is LegacyDSSKey
    assert Transport._preferred_keys.count("ssh-dss") == 1
    for kex in LEGACY_KEX_ALGORITHMS:
        if kex in Transport._kex_info:
            assert Transport._preferred_kex.count(kex) == 1
    for cipher in LEGACY_CIPHERS:
        if cipher in Transport._cipher_info:
            assert Transport._preferred_ciphers.count(cipher) == 1
    for mac in LEGACY_MACS:
        if mac in Transport._mac_info:
            assert Transport._preferred_macs.count(mac) == 1


def test_legacy_dss_key_1024bit_signature_verification_and_serialization(caplog):
    priv, pub_wire = _build_1024bit_dsa_keypair()

    dss_key = LegacyDSSKey(msg=Message(pub_wire))
    assert dss_key.get_name() == "ssh-dss"
    assert LegacyDSSKey.identifiers() == ["ssh-dss"]
    assert dss_key.get_bits() == 1024
    assert dss_key.can_sign() is False
    assert dss_key.asbytes() == pub_wire

    # Roundtrip via data= and PKey.from_type_string when legacy DSS is explicitly enabled
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
    with caplog.at_level(logging.DEBUG, logger="net_docu_crawler.ssh_compat"):
        assert dss_key.verify_ssh_sig(b"tampered-hash", Message(sig_msg.asbytes())) is False
    assert "ssh-dss signature verification rejected" in caplog.text

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


def test_per_connection_legacy_transport_does_not_pollute_global_transport_tables():
    """
    Verifies a legacy ssh-dss + aes128-cbc + hmac-md5 + diffie-hellman-group1-sha1
    handshake succeeds via `build_legacy_transport` while global `Transport._key_info`
    and `Transport._preferred_keys` remain completely untouched for other sessions.
    """
    configure_paramiko_compat(enable_legacy_dss=False)
    assert "ssh-dss" not in Transport._key_info
    assert "ssh-dss" not in Transport._preferred_keys

    priv, _ = _build_1024bit_dsa_keypair()

    class _ServerDSSKey(LegacyDSSKey):
        def can_sign(self) -> bool:
            return True

        def sign_ssh_data(self, data: bytes, algorithm: str | None = None) -> Message:
            der = priv.sign(data, hashes.SHA1())
            r, s = decode_dss_signature(der)
            m = Message()
            m.add_string("ssh-dss")
            m.add_string(r.to_bytes(20, "big") + s.to_bytes(20, "big"))
            return m

    srv_key = _ServerDSSKey(key=priv)
    s_sock, c_sock = socket.socketpair()
    server_t = Transport(s_sock)
    legacy_kex = next(
        (
            k
            for k in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1")
            if k in Transport._kex_info
        ),
        Transport._preferred_kex[0],
    )
    legacy_cipher = next(
        (c for c in ("aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc") if c in Transport._cipher_info),
        Transport._preferred_ciphers[0],
    )
    legacy_mac = next(
        (m for m in ("hmac-md5", "hmac-sha1", "hmac-md5-96", "hmac-sha1-96") if m in Transport._mac_info),
        Transport._preferred_macs[0],
    )
    server_t._key_info = {**Transport._key_info, "ssh-dss": _ServerDSSKey}
    server_t._preferred_keys = ("ssh-dss",)
    server_t._preferred_ciphers = (legacy_cipher,)
    server_t._preferred_macs = (legacy_mac,)
    server_t._preferred_kex = (legacy_kex,)
    server_t.add_server_key(srv_key)

    client_t = build_legacy_transport(c_sock)
    try:
        server_err: list[BaseException] = []

        def _run_server():
            try:
                ev = threading.Event()
                server_t.start_server(event=ev, server=paramiko.ServerInterface())
                ev.wait(timeout=10)
            except BaseException as exc:
                server_err.append(exc)

        t = threading.Thread(target=_run_server, daemon=True)
        t.start()
        client_t.start_client(timeout=10)
        t.join(timeout=10)
        assert not server_err
        assert client_t.is_active()
        remote_key = client_t.get_remote_server_key()
        assert isinstance(remote_key, LegacyDSSKey)
        assert remote_key.get_name() == "ssh-dss"

        # Global Transport tables MUST remain untouched
        assert "ssh-dss" not in Transport._key_info
        assert "ssh-dss" not in Transport._preferred_keys
    finally:
        client_t.close()
        server_t.close()
        c_sock.close()
        s_sock.close()


def test_legacy_ssh_fallback_scope_is_thread_local():
    configure_paramiko_compat(enable_legacy_dss=False)
    captured_factories: dict[str, object] = {}
    barrier = threading.Barrier(2)

    def _fake_orig_connect(self_client, *args, **kwargs):
        captured_factories[threading.current_thread().name] = kwargs.get("transport_factory")

    # Patch the underlying wrapped SSHClient.connect target via Transport check
    orig_connect = paramiko.SSHClient.connect.__wrapped__  # type: ignore[attr-defined]
    with patch.object(paramiko.SSHClient, "connect", wraps=paramiko.SSHClient.connect):
        # Verify thread-local isolation by inspecting kwargs injected by _scoped_ssh_client_connect
        pass

    # Directly verify via two concurrent threads calling SSHClient.connect with a dummy sock/factory check
    def _worker_legacy():
        client = paramiko.SSHClient()
        with legacy_ssh_fallback_scope():
            barrier.wait(timeout=5)
            with patch.object(orig_connect, "__call__", _fake_orig_connect):
                pass
            # Check via sock mock that fails immediately after transport_factory is invoked
            mock_sock = MagicMock()
            with patch(
                "net_docu_crawler.ssh_compat.build_legacy_transport", side_effect=SSHException("scoped-hit")
            ) as m_tf:
                with pytest.raises(SSHException, match="scoped-hit"):
                    client.connect(hostname="10.0.0.1", sock=mock_sock)
                captured_factories["legacy"] = m_tf.call_count

    def _worker_modern():
        client = paramiko.SSHClient()
        barrier.wait(timeout=5)
        mock_sock = MagicMock()
        with (
            patch("net_docu_crawler.ssh_compat.build_legacy_transport") as m_tf,
            patch("paramiko.client.Transport", side_effect=SSHException("modern-hit")),
        ):
            with pytest.raises(SSHException, match="modern-hit"):
                client.connect(hostname="10.0.0.2", sock=mock_sock)
            captured_factories["modern"] = m_tf.call_count

    t1 = threading.Thread(target=_worker_legacy)
    t2 = threading.Thread(target=_worker_modern)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert captured_factories["legacy"] == 1
    assert captured_factories["modern"] == 0


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

    # 1) Stage 2 succeeds: Stage 1 disabled weak algorithms per-connection; Stage 2 scopes legacy without global mutation
    scope_states: list[bool] = []

    def _stage2_side_effect(**kwargs):
        from net_docu_crawler.ssh_compat import _is_legacy_scope_active

        scope_states.append(_is_legacy_scope_active())
        if len(scope_states) == 1:
            raise IncompatiblePeer("Incompatible ssh peer (no acceptable host key)")
        return MagicMock(base_prompt="R1#")

    mock_stage2 = MagicMock(side_effect=_stage2_side_effect)
    with patch("netmiko.ConnectHandler", mock_stage2):
        conn = connect_netmiko_with_fallback(base_params)
        assert conn.base_prompt == "R1#"
        assert mock_stage2.call_count == 2
        assert "disabled_algorithms" not in base_params
        stage1_call = mock_stage2.call_args_list[0][1]
        assert stage1_call["disabled_algorithms"] == {k: list(v) for k, v in STAGE1_DISABLED_ALGORITHMS.items()}
        stage2_call = mock_stage2.call_args_list[1][1]
        assert stage2_call["disabled_algorithms"] == {}
        assert stage2_call["disable_sha2_fix"] is False
        assert stage2_call["ssh_strict"] is False
        assert scope_states == [False, True]
        # Global Transport registries MUST NOT be polluted by Stage 2 fallback
        assert "ssh-dss" not in Transport._key_info
        assert "ssh-dss" not in Transport._preferred_keys

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
        assert "ssh-dss" not in Transport._key_info

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


def test_opnsense_driver_connect_uses_three_stage_paramiko_fallback_and_host_key_policy(caplog, monkeypatch):
    monkeypatch.delenv("NDC_STRICT_HOST_KEYS", raising=False)
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
        assert mock_client.load_system_host_keys.call_count == 1
        policy_arg = mock_client.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(policy_arg, AuditedMissingHostKeyPolicy)
        assert not isinstance(policy_arg, paramiko.AutoAddPolicy)
        assert mock_client.connect.call_count == 3

        stage1_kwargs = mock_client.connect.call_args_list[0][1]
        assert stage1_kwargs["disabled_algorithms"] == {k: list(v) for k, v in STAGE1_DISABLED_ALGORITHMS.items()}
        assert stage1_kwargs["hostname"] == "192.168.1.1"
        assert "transport_factory" not in stage1_kwargs

        stage2_kwargs = mock_client.connect.call_args_list[1][1]
        assert stage2_kwargs["disabled_algorithms"] == {}
        assert stage2_kwargs["transport_factory"] is build_legacy_transport
        assert "ssh-dss" not in Transport._key_info

        stage3_kwargs = mock_client.connect.call_args_list[2][1]
        assert stage3_kwargs["disabled_algorithms"] == {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}
        assert stage3_kwargs["transport_factory"] is build_legacy_transport

    # Verify AuditedMissingHostKeyPolicy logs warning with SHA256 fingerprint and does NOT persist host keys
    real_client = paramiko.SSHClient()
    _, pub_wire = _build_1024bit_dsa_keypair()
    sample_key = LegacyDSSKey(msg=Message(pub_wire))
    policy = AuditedMissingHostKeyPolicy()
    with caplog.at_level(logging.WARNING, logger="net_docu_crawler.drivers.opnsense"):
        policy.missing_host_key(real_client, "192.168.1.1", sample_key)
    assert "Unverified SSH host key for 192.168.1.1" in caplog.text
    assert "SHA256:" in caplog.text
    assert len(real_client.get_host_keys()) == 0

    # Strict host-key checking via constructor or NDC_STRICT_HOST_KEYS=1 enforces RejectPolicy
    strict_driver = OPNsenseDriver(ip="192.168.1.1", username="root", password="secret", strict_host_key_checking=True)
    strict_client = MagicMock(spec=paramiko.SSHClient)
    with patch("net_docu_crawler.drivers.opnsense.paramiko.SSHClient", return_value=strict_client):
        strict_driver.connect()
        strict_policy = strict_client.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(strict_policy, paramiko.RejectPolicy)

    monkeypatch.setenv("NDC_STRICT_HOST_KEYS", "1")
    env_strict_driver = OPNsenseDriver(ip="192.168.1.1", username="root", password="secret")
    assert env_strict_driver.strict_host_key_checking is True

    # Authentication error aborts immediately on Stage 1
    mock_auth_client = MagicMock(spec=paramiko.SSHClient)
    mock_auth_client.connect.side_effect = AuthenticationException("Authentication failed.")
    with pytest.raises(AuthenticationException):
        connect_paramiko_with_fallback(mock_auth_client, hostname="192.168.1.1", username="root", password="bad")
    assert mock_auth_client.connect.call_count == 1


def test_detector_probe_http_fingerprint_isolates_tls_context_and_logs_debug(caplog):
    ctx = _build_unverified_probe_tls_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE

    # Generate an ephemeral self-signed DER certificate to verify CN extraction over HTTPS
    priv_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FG100F-LAB")])
    now = datetime.datetime.now(datetime.timezone.utc)
    der_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv_rsa.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(priv_rsa, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )

    mock_raw_sock = MagicMock()
    mock_tls_sock = MagicMock()
    mock_tls_sock.getpeercert.return_value = der_cert
    mock_tls_sock.recv.side_effect = [
        b"HTTP/1.1 200 OK\r\nServer: xxxxxxxx-xxxxx\r\n\r\n<html><title>FortiGate</title></html>",
        b"",
    ]
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = mock_tls_sock

    with (
        patch("net_docu_crawler.drivers.detector.probe_tcp_port", side_effect=lambda ip, p, timeout=0.7: p == 443),
        patch("net_docu_crawler.drivers.detector.socket.socket", return_value=mock_raw_sock),
        patch("net_docu_crawler.drivers.detector._build_unverified_probe_tls_context", return_value=mock_ctx),
        caplog.at_level(logging.DEBUG, logger="net_docu_crawler.drivers.detector"),
    ):
        fp = probe_http_fingerprint("10.0.0.254")
        assert fp == {
            "port": 443,
            "scheme": "https",
            "server": "xxxxxxxx-xxxxx",
            "title": "FortiGate",
            "cert_cn": "FG100F-LAB",
        }
        assert "FG100F-LAB" in caplog.text

    # Verify SSL handshake failure logs at DEBUG level rather than failing silently without telemetry
    caplog.clear()
    failing_sock = MagicMock()
    failing_sock.connect.side_effect = ssl.SSLError("TLSV1_ALERT_INTERNAL_ERROR")
    with (
        patch("net_docu_crawler.drivers.detector.probe_tcp_port", side_effect=lambda ip, p, timeout=0.7: p == 443),
        patch("net_docu_crawler.drivers.detector.socket.socket", return_value=failing_sock),
        caplog.at_level(logging.DEBUG, logger="net_docu_crawler.drivers.detector"),
    ):
        assert probe_http_fingerprint("10.0.0.254") is None
        assert "HTTP/HTTPS fingerprint probe failed" in caplog.text

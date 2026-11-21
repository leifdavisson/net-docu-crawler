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
Multi-stage SSH cryptographic compatibility and legacy fallback layer for Net-Docu-Crawler.

Bridges modern hardened SSHv2 peers (RFC 8731 ``curve25519-sha256`` and RFC 3526
``diffie-hellman-group18-sha512``) and legacy network management planes requiring
deprecated KEX, ciphers, MACs, read-only ``ssh-dss`` host-key verification, or
RFC 8332 ``rsa-sha2-256``/``512`` downgrade workarounds without weakening default
sessions or re-trying failed authentication credentials.

Official Upstream Documentation & References:
- Paramiko: https://www.paramiko.org/
- Netmiko: https://github.com/ktbyers/netmiko
- pyca/cryptography: https://cryptography.io/
"""

from __future__ import annotations

import hashlib
import logging
import socket
import threading
from typing import Any

import netmiko
import paramiko
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.kex_curve25519 import KexCurve25519
from paramiko.message import Message

try:
    from paramiko.kex_group1 import KexGroup1 as _BaseModpKex
except ImportError:  # Paramiko 5.x removed kex_group1
    from paramiko.kex_group16 import KexGroup16SHA512 as _BaseModpKex
from paramiko.pkey import PKey
from paramiko.ssh_exception import (
    AuthenticationException,
    BadHostKeyException,
    IncompatiblePeer,
    SSHException,
)
from paramiko.transport import Transport

_COMPAT_LOCK = threading.RLock()

LEGACY_KEX_ALGORITHMS: tuple[str, ...] = (
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1",
)

LEGACY_CIPHERS: tuple[str, ...] = (
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
)

LEGACY_MACS: tuple[str, ...] = (
    "hmac-sha1",
    "hmac-md5",
    "hmac-sha1-96",
    "hmac-md5-96",
)

RSA_SHA2_PUBKEYS: list[str] = ["rsa-sha2-256", "rsa-sha2-512"]

_NEGOTIATION_ERROR_SUBSTRINGS: tuple[str, ...] = (
    "incompatible",
    "no acceptable kex",
    "no acceptable host key",
    "no matching host key",
    "no acceptable cipher",
    "no acceptable mac",
    "key exchange failed",
    "unable to agree",
    "bad host key",
    "invalid key",
    "signature verification",
    "unknown host key type",
)

_AUTH_ERROR_SUBSTRINGS: tuple[str, ...] = (
    "authentication failed",
    "authentication to device failed",
    "permission denied",
)


class KexGroup18SHA512(_BaseModpKex):
    """
    RFC 3526 Section 7 (8192-bit MODP Group 18) Diffie-Hellman key exchange with SHA-512
    (RFC 8268 ``diffie-hellman-group18-sha512``).
    """

    name = "diffie-hellman-group18-sha512"
    P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
        "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
        "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
        "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
        "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
        "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
        "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
        "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
        "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
        "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
        "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
        "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
        "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
        "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
        "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
        "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
        "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
        "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
        "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
        "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
        "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
        16,
    )
    G = 2
    hash_algo = hashlib.sha512


class LegacyDSSKey(PKey):
    """
    Read-only RFC 4253 Section 6.6 ``ssh-dss`` host-key verifier for Paramiko 4.0+,
    which removed ``DSSKey`` upstream.

    Strictly supports public host-key parsing and 40-byte ``r || s`` SHA-1 signature
    verification via ``pyca/cryptography`` during fallback KEX; signing and user
    authentication key generation are intentionally disabled (``can_sign() -> False``).
    """

    name = "ssh-dss"

    @classmethod
    def identifiers(cls) -> list[str]:
        return ["ssh-dss"]

    def __init__(
        self,
        msg: Message | None = None,
        data: bytes | None = None,
        vals: tuple[int, int, int, int] | None = None,
        key: dsa.DSAPublicKey | dsa.DSAPrivateKey | None = None,
        password: str | bytes | None = None,
        **_unused: Any,
    ) -> None:
        self.public_blob = None
        if msg is None and data is not None:
            msg = Message(data)

        if key is not None:
            pub_key = key.public_key() if isinstance(key, dsa.DSAPrivateKey) else key
            pub_nums = pub_key.public_numbers()
            param_nums = pub_nums.parameter_numbers
            self.p = param_nums.p
            self.q = param_nums.q
            self.g = param_nums.g
            self.y = pub_nums.y
            self.key = pub_key
            return

        if vals is not None:
            self.p, self.q, self.g, self.y = vals
        else:
            self._check_type_and_load_cert(
                msg=msg,
                key_type=self.name,
                cert_type="ssh-dss-cert-v01@openssh.com",
            )
            assert msg is not None
            try:
                self.p = msg.get_mpint()
                self.q = msg.get_mpint()
                self.g = msg.get_mpint()
                self.y = msg.get_mpint()
            except EOFError as exc:
                raise SSHException(f"Truncated ssh-dss host key payload: {exc}")

        try:
            param_nums = dsa.DSAParameterNumbers(p=self.p, q=self.q, g=self.g)
            self.key = dsa.DSAPublicNumbers(y=self.y, parameter_numbers=param_nums).public_key()
        except ValueError as exc:
            raise SSHException(f"Invalid ssh-dss public key parameters: {exc}")

    @property
    def _fields(self) -> tuple[str, int, int, int, int]:
        return (self.get_name(), self.p, self.q, self.g, self.y)

    def asbytes(self) -> bytes:
        m = Message()
        m.add_string(self.name)
        m.add_mpint(self.p)
        m.add_mpint(self.q)
        m.add_mpint(self.g)
        m.add_mpint(self.y)
        return m.asbytes()

    def get_name(self) -> str:
        return "ssh-dss"

    def get_bits(self) -> int:
        return self.key.key_size

    def can_sign(self) -> bool:
        return False

    def sign_ssh_data(self, data: bytes, algorithm: str | None = None) -> Message:
        raise SSHException("LegacyDSSKey is read-only and does not support signing")

    def verify_ssh_sig(self, data: bytes, msg: Message) -> bool:
        raw = msg.asbytes()
        if len(raw) == 40:
            sig_bytes = raw
        else:
            msg.rewind()
            try:
                sig_type = msg.get_text()
                sig_bytes = msg.get_binary()
            except (EOFError, UnicodeDecodeError):
                return False
            if sig_type != self.name:
                return False

        if len(sig_bytes) != 40:
            return False

        r = int.from_bytes(sig_bytes[:20], byteorder="big", signed=False)
        s = int.from_bytes(sig_bytes[20:], byteorder="big", signed=False)
        der_sig = encode_dss_signature(r, s)
        try:
            self.key.verify(der_sig, data, hashes.SHA1())
        except (InvalidSignature, ValueError):
            return False
        return True


def _append_missing_tuple_items(current: tuple[str, ...], items: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    updated = list(current)
    changed = False
    for item in items:
        if item not in updated:
            updated.append(item)
            changed = True
    return tuple(updated) if changed else current


def configure_paramiko_compat(enable_legacy_dss: bool = False) -> None:
    """
    Idempotently registers missing modern and (optionally) legacy SSH algorithms on
    ``paramiko.Transport`` while silencing noisy Paramiko background-thread tracebacks.
    """
    with _COMPAT_LOCK:
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

        modern_kex: list[str] = []
        if KexCurve25519.is_available():
            Transport._kex_info["curve25519-sha256"] = KexCurve25519
            modern_kex.append("curve25519-sha256")

        Transport._kex_info["diffie-hellman-group18-sha512"] = KexGroup18SHA512
        modern_kex.append("diffie-hellman-group18-sha512")

        Transport._preferred_kex = _append_missing_tuple_items(Transport._preferred_kex, modern_kex)

        if enable_legacy_dss:
            if "ssh-dss" not in Transport._key_info:
                Transport._key_info["ssh-dss"] = LegacyDSSKey
            if "ssh-dss-cert-v01@openssh.com" not in Transport._key_info:
                Transport._key_info["ssh-dss-cert-v01@openssh.com"] = LegacyDSSKey

            key_classes = getattr(paramiko, "key_classes", None)
            if isinstance(key_classes, list) and LegacyDSSKey not in key_classes:
                key_classes.append(LegacyDSSKey)

            Transport._preferred_keys = _append_missing_tuple_items(Transport._preferred_keys, ("ssh-dss",))

            supported_legacy_kex = [k for k in LEGACY_KEX_ALGORITHMS if k in Transport._kex_info]
            Transport._preferred_kex = _append_missing_tuple_items(Transport._preferred_kex, supported_legacy_kex)

            supported_legacy_ciphers = [c for c in LEGACY_CIPHERS if c in Transport._cipher_info]
            Transport._preferred_ciphers = _append_missing_tuple_items(
                Transport._preferred_ciphers, supported_legacy_ciphers
            )

            supported_legacy_macs = [m for m in LEGACY_MACS if m in Transport._mac_info]
            Transport._preferred_macs = _append_missing_tuple_items(Transport._preferred_macs, supported_legacy_macs)


def _iter_exception_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        cur = cur.__cause__ if cur.__cause__ is not None else cur.__context__
    return chain


def _is_auth_error(exc: BaseException) -> bool:
    for cur in _iter_exception_chain(exc):
        if isinstance(cur, (AuthenticationException, NetmikoAuthenticationException)):
            return True
        msg = str(cur).lower()
        if any(tok in msg for tok in _AUTH_ERROR_SUBSTRINGS):
            return True
    return False


def is_ssh_negotiation_error(exc: BaseException) -> bool:
    """
    Returns ``True`` when ``exc`` indicates an SSH cryptographic negotiation or host-key
    incompatibility, and ``False`` for authentication failures, TCP timeouts, or socket errors.
    """
    if _is_auth_error(exc):
        return False

    for cur in _iter_exception_chain(exc):
        if isinstance(cur, (IncompatiblePeer, BadHostKeyException)):
            return True
        msg = str(cur).lower()
        if any(sub in msg for sub in _NEGOTIATION_ERROR_SUBSTRINGS):
            return True
    return False


def _should_retry_stage3(exc: BaseException) -> bool:
    """
    Determines whether a Stage 2 failure warrants Stage 3 (``rsa-sha2-256``/``512`` disablement).
    Never retries authentication failures or TCP/socket reachability timeouts.
    """
    if _is_auth_error(exc):
        return False
    if is_ssh_negotiation_error(exc):
        return True
    if isinstance(exc, (OSError, socket.error, EOFError)):
        return False
    if isinstance(exc, NetmikoTimeoutException):
        return "a paramiko sshexception occurred" in str(exc).lower()
    if isinstance(exc, SSHException):
        return True
    return False


def connect_netmiko_with_fallback(device_params: dict[str, Any]):
    """
    Establishes a Netmiko SSH/Telnet connection using a 3-stage compatibility ladder:

    - Stage 1: Modern hardened KEX registered (``curve25519-sha256``, ``diffie-hellman-group18-sha512``),
      legacy ``ssh-dss`` disabled, default Netmiko settings.
    - Stage 2: Triggered only on ``is_ssh_negotiation_error``; enables ``LegacyDSSKey`` / legacy
      KEX/ciphers/MACs with ``disabled_algorithms={}``, ``disable_sha2_fix=False`` (keeping
      ``rsa-sha2-256``/``512`` active), and ``ssh_strict=False``.
    - Stage 3: Triggered if Stage 2 still fails SSH negotiation / ``SSHException`` (never auth
      failure); sets ``disable_sha2_fix=True`` for legacy peers with broken RFC 8332 SHA-2 RSA.
    """
    configure_paramiko_compat(enable_legacy_dss=False)
    try:
        return netmiko.ConnectHandler(**device_params)
    except Exception as exc1:
        if not is_ssh_negotiation_error(exc1):
            raise

    configure_paramiko_compat(enable_legacy_dss=True)
    stage2_params = dict(device_params)
    stage2_params["disabled_algorithms"] = {}
    stage2_params["disable_sha2_fix"] = False
    stage2_params["ssh_strict"] = False
    try:
        return netmiko.ConnectHandler(**stage2_params)
    except Exception as exc2:
        if not _should_retry_stage3(exc2):
            raise

    stage3_params = dict(device_params)
    stage3_params["disabled_algorithms"] = {}
    stage3_params["disable_sha2_fix"] = True
    stage3_params["ssh_strict"] = False
    return netmiko.ConnectHandler(**stage3_params)


def connect_paramiko_with_fallback(client: paramiko.SSHClient, **connect_kwargs: Any) -> None:
    """
    Establishes a direct ``paramiko.SSHClient`` connection (used by ``OPNsenseDriver``)
    mirroring the 3-stage SSH negotiation fallback ladder.
    """
    configure_paramiko_compat(enable_legacy_dss=False)
    try:
        client.connect(**connect_kwargs)
        return
    except Exception as exc1:
        if not is_ssh_negotiation_error(exc1):
            raise
        try:
            client.close()
        except Exception:
            pass

    configure_paramiko_compat(enable_legacy_dss=True)
    stage2_kwargs = dict(connect_kwargs)
    stage2_kwargs["disabled_algorithms"] = {}
    try:
        client.connect(**stage2_kwargs)
        return
    except Exception as exc2:
        if not _should_retry_stage3(exc2):
            raise
        try:
            client.close()
        except Exception:
            pass

    stage3_kwargs = dict(connect_kwargs)
    stage3_kwargs["disabled_algorithms"] = {"pubkeys": list(RSA_SHA2_PUBKEYS)}
    client.connect(**stage3_kwargs)

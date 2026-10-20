"""QoreChain post-quantum cryptography.

Standardized NIST primitives, wrapping liboqs (via the ``oqs`` package) and the
Python standard library:
  - ML-DSA   (FIPS-204) signatures — levels 44 / 65 / 87 (default 87)
  - ML-KEM   (FIPS-203) key encapsulation — levels 512 / 768 / 1024 (default 1024)
  - SHAKE-256 (FIPS-202) extendable-output hash

The API mirrors the other language bindings in this repo and is validated
against the shared vectors in /vectors.
"""
from __future__ import annotations

import ctypes
import hashlib
import struct
from typing import Tuple

import threading

import oqs  # liboqs-python
import oqs.rand as _oqs_rand

__version__ = "0.2.3"

# liboqs's ML-DSA signs hedged: it draws the 32-byte FIPS-204 `rnd` from
# OQS_randombytes. This binding signs DETERMINISTICALLY by default (rnd = 32
# zero bytes) so signatures match the shared /vectors and every other language
# binding — so MlDsa.sign routes liboqs's RNG to a zero
# filler for the duration of the sign call, then restores the system RNG.
# The RNG switch is process-global in liboqs, so every operation of this module
# that draws randomness (keygen, encapsulation, hedged signing) takes the same
# lock as the deterministic sign path. Without it a keygen on another thread
# during a sign call drew zeros and produced a key anyone can reproduce. The
# lock covers this module only: other liboqs users in the same process are not
# protected and should not run concurrently with it.
_rng_lock = threading.Lock()
_RNG_CB_TYPE = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)


def _zero_fill(buf, n):  # pragma: no cover - trivial
    ctypes.memset(buf, 0, n)


_ZERO_RNG = _RNG_CB_TYPE(_zero_fill)  # module-level ref: must outlive installation

MLDSA_LEVELS = {"ml-dsa-44": "ML-DSA-44", "ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87"}
MLKEM_LEVELS = {"ml-kem-512": "ML-KEM-512", "ml-kem-768": "ML-KEM-768", "ml-kem-1024": "ML-KEM-1024"}
# Exact FIPS-204 / FIPS-203 sizes. Every key, signature and ciphertext is checked
# against these BEFORE it reaches liboqs through ctypes: liboqs reads a fixed
# number of bytes from each pointer, so a short buffer would be read past its end
# and a long one silently truncated.
MLDSA_LENGTHS = {  # (public key, secret key, signature)
    "ml-dsa-44": (1312, 2560, 2420),
    "ml-dsa-65": (1952, 4032, 3309),
    "ml-dsa-87": (2592, 4896, 4627),
}
MLKEM_LENGTHS = {  # (public key, secret key, ciphertext)
    "ml-kem-512": (800, 1632, 768),
    "ml-kem-768": (1184, 2400, 1088),
    "ml-kem-1024": (1568, 3168, 1568),
}

_BYTES_LIKE = (bytes, bytearray, memoryview)


def _is_bytes(v) -> bool:
    return isinstance(v, _BYTES_LIKE)


def _require_bytes(fn: str, arg: str, value, length=None) -> bytes:
    """Return ``value`` as bytes, or raise ValueError naming ``arg`` and, when
    fixed, the expected ``length``."""
    if not _is_bytes(value):
        want = f" of {length} bytes" if length is not None else ""
        raise ValueError(f"{fn}: {arg} must be bytes{want}, got {type(value).__name__}")
    value = bytes(value)
    if length is not None and len(value) != length:
        raise ValueError(f"{fn}: {arg} must be exactly {length} bytes, got {len(value)}")
    return value


MLDSA_DEFAULT = "ml-dsa-87"
MLKEM_DEFAULT = "ml-kem-1024"


class MlDsa:
    """ML-DSA (FIPS-204) signatures at a chosen level."""

    def __init__(self, level: str = MLDSA_DEFAULT):
        self.alg = MLDSA_LEVELS[level]
        self.level = level
        self.public_key_len, self.secret_key_len, self.signature_len = MLDSA_LENGTHS[level]

    def keygen(self) -> Tuple[bytes, bytes]:
        with _rng_lock, oqs.Signature(self.alg) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
            return pk, sk

    def sign(self, secret_key: bytes, message: bytes, *, hedged: bool = False) -> bytes:
        """Sign ``message`` with ``secret_key`` (empty context, FIPS-204 pure).

        DETERMINISTIC (FIPS-204 §3.4) by default: the same (secret_key, message)
        always yields the same signature, matching every other language binding
        and the shared /vectors. QoreChain's on-chain PQC verifier accepts any
        valid FIPS-204 signature, hedged or deterministic. Pass ``hedged=True``
        for randomized signing (equally accepted by the chain; not
        reproducible).

        Raises ValueError if ``secret_key`` is not exactly the expanded secret-key
        size for this level or ``message`` is not bytes.
        """
        fn = f"{self.level}.sign"
        secret_key = _require_bytes(fn, "secret_key", secret_key, self.secret_key_len)
        message = _require_bytes(fn, "message", message)
        if hedged:
            with _rng_lock, oqs.Signature(self.alg, secret_key) as s:
                return s.sign(message)
        with _rng_lock:
            oqs.native().OQS_randombytes_custom_algorithm(_ZERO_RNG)
            try:
                with oqs.Signature(self.alg, secret_key) as s:
                    return s.sign(message)
            finally:
                _oqs_rand.randombytes_switch_algorithm("system")

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return True iff ``signature`` is valid over ``message`` under
        ``public_key``. Never raises: a wrong-length key or signature, a
        non-bytes argument or any other malformed input returns False."""
        if not (_is_bytes(public_key) and _is_bytes(message) and _is_bytes(signature)):
            return False
        public_key, message, signature = bytes(public_key), bytes(message), bytes(signature)
        if len(public_key) != self.public_key_len or len(signature) != self.signature_len:
            return False
        try:
            with oqs.Signature(self.alg) as s:
                return bool(s.verify(message, signature, public_key))
        except Exception:  # noqa: BLE001 - malformed input is "not valid", never an error
            return False


class MlKem:
    """ML-KEM (FIPS-203) key encapsulation at a chosen level."""

    def __init__(self, level: str = MLKEM_DEFAULT):
        self.alg = MLKEM_LEVELS[level]
        self.level = level
        self.public_key_len, self.secret_key_len, self.ciphertext_len = MLKEM_LENGTHS[level]

    def keygen(self) -> Tuple[bytes, bytes]:
        with _rng_lock, oqs.KeyEncapsulation(self.alg) as k:
            pk = k.generate_keypair()
            sk = k.export_secret_key()
            return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to ``public_key`` -> ``(ciphertext, shared_secret)``.
        Raises ValueError if ``public_key`` is not exactly the level's size."""
        public_key = _require_bytes(f"{self.level}.encapsulate", "public_key", public_key, self.public_key_len)
        with _rng_lock, oqs.KeyEncapsulation(self.alg) as k:
            ct, ss = k.encap_secret(public_key)
            return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate ``ciphertext`` with ``secret_key`` -> shared secret. Raises
        ValueError if either is not exactly the level's size."""
        fn = f"{self.level}.decapsulate"
        secret_key = _require_bytes(fn, "secret_key", secret_key, self.secret_key_len)
        ciphertext = _require_bytes(fn, "ciphertext", ciphertext, self.ciphertext_len)
        with oqs.KeyEncapsulation(self.alg, secret_key) as k:
            return k.decap_secret(ciphertext)


# Default handles (security level 5).
mldsa = MlDsa(MLDSA_DEFAULT)
mlkem = MlKem(MLKEM_DEFAULT)


def shake256(data: bytes, out_len: int = 32) -> bytes:
    """SHAKE-256 (FIPS-202) digest of ``data`` with ``out_len`` bytes."""
    return hashlib.shake_256(data).digest(out_len)


def pubkey_hash(public_key: bytes, length: int = 20) -> bytes:
    """SHAKE-256(public_key) truncated to ``length`` bytes (pay-to-pubkey-hash)."""
    return shake256(public_key, length)


# Hybrid sign-bytes: the message a PQC signature covers in QoreChain's
# hybrid-extension scheme (b0 = tx body WITHOUT the PQC extension, auth = AuthInfo
# bytes). Two forms exist and a network accepts exactly ONE at any height:
#   v1 (legacy): BE32(len b0) || b0 || BE32(len auth) || auth
#   v2:          b"qorechain-pqc-hybrid-v2" || BE64(len chain_id) || chain_id || <v1 layout>
# The two networks that existed before v2 (qorechain-vladi, qorechain-diana)
# verify v1 until a switching upgrade is applied on them, v2 afterwards; every
# other chain verifies v2 from genesis. The switch has shipped under TWO plan
# names: testnet took it as "v3.1.98" and mainnet as "v3.2.0", and each network
# keeps its record forever. Ask the network for every name in
# SIGN_BYTES_V2_UPGRADES and pass the answers to sign_bytes_version_for_applied.
# This module is pure: asking a network for its applied heights is left to the
# caller.
HYBRID_SIGN_BYTES_DOMAIN = b"qorechain-pqc-hybrid-v2"
# Every upgrade-plan name that switched a network to v2, newest first. Mirror of
# the chain's x/pqc/types.SignBytesV2Upgrades.
SIGN_BYTES_V2_UPGRADES = ("v3.2.0", "v3.1.98")
# DEPRECATED: the primary (newest) name only. A network may have taken the switch
# under any name in SIGN_BYTES_V2_UPGRADES (testnet applied "v3.1.98", mainnet
# "v3.2.0"); querying only this one misreads testnet as not switched. Use
# SIGN_BYTES_V2_UPGRADES with sign_bytes_version_for_applied.
SIGN_BYTES_V2_UPGRADE = "v3.2.0"
LEGACY_SIGN_BYTES_CHAINS = ("qorechain-vladi", "qorechain-diana")


def _height(v) -> int:
    return 0 if v in (None, "") else int(v)


def sign_bytes_version_for(chain_id: str, v2_applied_height) -> str:
    """Return ``"v2"`` if the switch to v2 was applied (height > 0) or ``chain_id``
    is not a legacy network, else ``"v1"``. Mirror of the chain's
    SignBytesVersionFor. The height is compared numerically (``"0"`` is not
    applied) and must already be the greatest across SIGN_BYTES_V2_UPGRADES;
    prefer :func:`sign_bytes_version_for_applied`, which computes it."""
    if _height(v2_applied_height) > 0 or chain_id not in LEGACY_SIGN_BYTES_CHAINS:
        return "v2"
    return "v1"


def sign_bytes_version_for_applied(chain_id: str, applied_heights) -> str:
    """:func:`sign_bytes_version_for` over every known upgrade name.

    ``applied_heights`` maps a plan name to the height at which the network
    applied it (absent, ``0`` or ``"0"`` = not applied); the greatest height
    across SIGN_BYTES_V2_UPGRADES decides and other names are ignored. Mirror of
    the chain's SignBytesVersionForApplied."""
    applied_heights = applied_heights or {}
    best = 0
    for name in SIGN_BYTES_V2_UPGRADES:
        h = _height(applied_heights.get(name))
        if h > best:
            best = h
    return sign_bytes_version_for(chain_id, best)


def hybrid_sign_bytes_v1(body_without_pqc_ext: bytes, auth_info_bytes: bytes) -> bytes:
    """Legacy v1 form: ``BE32(len b0) || b0 || BE32(len auth) || auth``."""
    return (
        struct.pack(">I", len(body_without_pqc_ext))
        + body_without_pqc_ext
        + struct.pack(">I", len(auth_info_bytes))
        + auth_info_bytes
    )


def hybrid_sign_bytes_v2(chain_id: str, body_without_pqc_ext: bytes, auth_info_bytes: bytes) -> bytes:
    """v2 form, byte-identical to the chain's x/pqc/types.HybridSignBytes:

    ``domain || BE64(len chain_id) || chain_id || BE32(len b0) || b0 || BE32(len auth) || auth``

    The domain tag keeps a signature made in another context from being valid
    transaction sign-bytes; the chain-id keeps it from verifying on another network.
    """
    if not chain_id:
        raise ValueError("hybrid_sign_bytes_v2: chain_id is required")
    cid = chain_id.encode("utf-8")
    return (
        HYBRID_SIGN_BYTES_DOMAIN
        + struct.pack(">Q", len(cid))
        + cid
        + hybrid_sign_bytes_v1(body_without_pqc_ext, auth_info_bytes)
    )


def hybrid_sign_bytes(version: str, chain_id: str, body_without_pqc_ext: bytes, auth_info_bytes: bytes) -> bytes:
    """Hybrid sign-bytes in the given form (``"v1"`` or ``"v2"``). The version is
    required: there is no implicit form, because each network accepts exactly one."""
    if version == "v2":
        return hybrid_sign_bytes_v2(chain_id, body_without_pqc_ext, auth_info_bytes)
    if version == "v1":
        return hybrid_sign_bytes_v1(body_without_pqc_ext, auth_info_bytes)
    raise ValueError(f"hybrid_sign_bytes: version must be 'v1' or 'v2', got {version!r}")

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

__version__ = "0.1.1"

# liboqs's ML-DSA signs hedged: it draws the 32-byte FIPS-204 `rnd` from
# OQS_randombytes. QoreChain's on-chain PQC verifier accepts ONLY the
# DETERMINISTIC variant (rnd = 32 zero bytes), matching the shared /vectors and
# every other language binding — so MlDsa.sign routes liboqs's RNG to a zero
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
MLDSA_DEFAULT = "ml-dsa-87"
MLKEM_DEFAULT = "ml-kem-1024"


class MlDsa:
    """ML-DSA (FIPS-204) signatures at a chosen level."""

    def __init__(self, level: str = MLDSA_DEFAULT):
        self.alg = MLDSA_LEVELS[level]
        self.level = level

    def keygen(self) -> Tuple[bytes, bytes]:
        with _rng_lock, oqs.Signature(self.alg) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
            return pk, sk

    def sign(self, secret_key: bytes, message: bytes, *, hedged: bool = False) -> bytes:
        """Sign ``message`` with ``secret_key`` (empty context, FIPS-204 pure).

        DETERMINISTIC (FIPS-204 §3.4) by default: the same (secret_key, message)
        always yields the same signature, matching every other language binding
        and the shared /vectors. QoreChain's on-chain PQC verifier accepts ONLY
        deterministic signatures, so this default is consensus-critical: do not
        change it. Pass ``hedged=True`` for randomized signing in non-chain
        contexts (NOT accepted by the chain).
        """
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
        with oqs.Signature(self.alg) as s:
            return bool(s.verify(message, signature, public_key))


class MlKem:
    """ML-KEM (FIPS-203) key encapsulation at a chosen level."""

    def __init__(self, level: str = MLKEM_DEFAULT):
        self.alg = MLKEM_LEVELS[level]
        self.level = level

    def keygen(self) -> Tuple[bytes, bytes]:
        with _rng_lock, oqs.KeyEncapsulation(self.alg) as k:
            pk = k.generate_keypair()
            sk = k.export_secret_key()
            return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        with _rng_lock, oqs.KeyEncapsulation(self.alg) as k:
            ct, ss = k.encap_secret(public_key)
            return ct, ss

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
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


HYBRID_SIGN_BYTES_DOMAIN = b"qorechain-pqc-hybrid-v2"


def hybrid_sign_bytes(chain_id: str, body_without_pqc_ext: bytes, auth_info_bytes: bytes) -> bytes:
    """Canonical PQC sign-bytes, v2:

    ``domain || BE64(len chain_id) || chain_id || BE32(len b0) || b0 || BE32(len auth) || auth``

    The domain tag keeps a signature made in another context from being valid
    transaction sign-bytes; the chain-id keeps it from verifying on another
    network. Byte-identical to the chain's x/pqc/types.HybridSignBytes. The v1
    form (no domain, no chain-id) is rejected by a v2 chain.
    """
    if not chain_id:
        raise ValueError("hybrid_sign_bytes: chain_id is required")
    cid = chain_id.encode("utf-8")
    return (
        HYBRID_SIGN_BYTES_DOMAIN
        + struct.pack(">Q", len(cid))
        + cid
        + struct.pack(">I", len(body_without_pqc_ext))
        + body_without_pqc_ext
        + struct.pack(">I", len(auth_info_bytes))
        + auth_info_bytes
    )

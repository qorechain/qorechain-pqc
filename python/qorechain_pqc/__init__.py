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

import hashlib
import struct
from typing import Tuple

import oqs  # liboqs-python

__version__ = "0.1.0"

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
        with oqs.Signature(self.alg) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
            return pk, sk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(self.alg, secret_key) as s:
            return s.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.alg) as s:
            return bool(s.verify(message, signature, public_key))


class MlKem:
    """ML-KEM (FIPS-203) key encapsulation at a chosen level."""

    def __init__(self, level: str = MLKEM_DEFAULT):
        self.alg = MLKEM_LEVELS[level]
        self.level = level

    def keygen(self) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.alg) as k:
            pk = k.generate_keypair()
            sk = k.export_secret_key()
            return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.alg) as k:
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


def hybrid_sign_bytes(body_without_pqc_ext: bytes, auth_info_bytes: bytes) -> bytes:
    """Canonical PQC sign-bytes: BE32(len(b0))||b0||BE32(len(auth))||auth."""
    return (
        struct.pack(">I", len(body_without_pqc_ext))
        + body_without_pqc_ext
        + struct.pack(">I", len(auth_info_bytes))
        + auth_info_bytes
    )

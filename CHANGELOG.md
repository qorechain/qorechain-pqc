# Changelog

## [0.2.1]

### Fixed

- **Hybrid sign-bytes version: both upgrade plan names.** Every binding knew only
  `v3.1.98`. The chain switches to the v2 form under either `v3.2.0` (mainnet) or
  `v3.1.98` (testnet), so on mainnet a caller querying only the old name read
  height 0, chose v1, and had every hybrid transaction refused. Each binding now
  exports the list (`v3.2.0`, then `v3.1.98`) and a `signBytesVersionForApplied`
  that takes the applied height per name. The singular constant is now `v3.2.0`.
  (QSR-2026-0389, 0416, 0427, 0431, 0495, 0507.)
- **Java: an expanded secret key was silently reduced to its first 32 bytes.** Java
  takes a 32-byte ML-DSA seed, while the other bindings take the 4,896-byte
  expanded key. Given an expanded key, Java used its first 32 bytes — which are ρ,
  the same 32 bytes that begin the public key — producing a key anyone can derive.
  Any seed that is not exactly 32 bytes is now refused. (QSR-2026-0388.)
- **Input validation.** JS `verify` returns false instead of throwing on malformed
  input (which also fixes `batchVerify`); Python checks exact lengths instead of
  zero-padding truncated keys and ciphertexts; Java checks lengths and nulls instead
  of throwing raw library exceptions. (QSR-2026-0570, 0572, 0573.)
- **An empty chain id in v2 sign-bytes** is refused on the checked entry points in
  every binding (Go `HybridSignBytes`, Rust `try_hybrid_sign_bytes*`); the plain
  variants never panic.
- **Go:** CIRCL ≥ v1.6.5, and the trailing-byte signature check from 0.2.0 now
  ships as a Go release. Go ≥ 1.25 is required. (QSR-2026-0202, 0329.)
- CI builds liboqs 0.16.0 with liboqs-python 0.16.0.1.

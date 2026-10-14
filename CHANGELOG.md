# Changelog

## [0.2.1]

### Fixed

- **Hybrid sign-bytes version: both upgrade plan names.** The chain switches to
  the v2 form under either `v3.2.0` (mainnet) or `v3.1.98` (testnet). Every
  binding now exports the list and a `signBytesVersionForApplied` that takes the
  applied height per name, so the correct form is chosen on both networks. The
  singular constant is now `v3.2.0`.
- **Java: stricter secret-key handling.** The Java binding takes a 32-byte ML-DSA
  seed, while the other bindings take the 4,896-byte expanded key. Any input that
  is not exactly a 32-byte seed is now refused.
- **Input validation across bindings.** JS `verify` returns false instead of
  throwing on malformed input; Python checks exact lengths; Java checks lengths
  and nulls and throws `IllegalArgumentException`.
- **Empty chain id** in v2 sign-bytes is refused on the checked entry points in
  every binding (Go `HybridSignBytes`, Rust `try_hybrid_sign_bytes*`).
- **Go:** CIRCL ≥ v1.6.5; Go ≥ 1.25 is required.
- CI builds liboqs 0.16.0 with liboqs-python 0.16.0.1.

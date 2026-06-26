# qorechain-pqc (Rust)

Post-quantum cryptography for [QoreChain](https://github.com/qorechain/qorechain-pqc) — standardized NIST primitives with one consistent API, proven byte-compatible against a shared cross-language test-vector suite.

| Primitive | Standard | Role |
|---|---|---|
| ML-DSA | FIPS-204 | digital signatures (44 · 65 · **87**) |
| ML-KEM | FIPS-203 | key encapsulation (512 · 768 · **1024**) |
| SHAKE-256 | FIPS-202 | extendable-output hash |

Backed by the [`fips204`](https://crates.io/crates/fips204), [`fips203`](https://crates.io/crates/fips203) and [`sha3`](https://crates.io/crates/sha3) crates.

## Add

```sh
cargo add qorechain-pqc
```

## Use

```rust
use qorechain_pqc::{mldsa, mlkem, shake256, pubkey_hash};

// ML-DSA-87 signatures
let (pk, sk) = mldsa::default::keygen()?;
let sig = mldsa::default::sign(&sk, message)?;
assert!(mldsa::default::verify(&pk, message, &sig));

// ML-KEM-1024 key encapsulation
let (ek, dk) = mlkem::default::keygen()?;
let (ct, ss) = mlkem::default::encapsulate(&ek)?;
assert_eq!(ss, mlkem::default::decapsulate(&dk, &ct)?);

// SHAKE-256 + pay-to-pubkey-hash
let digest = shake256(data, 32);
let h = pubkey_hash(&pk, 20);
```

Level modules: `mldsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87}`, `mlkem::{ml_kem_512, ml_kem_768, ml_kem_1024}` (`default` is L5).

## Interop

Every binding (JS, Rust, Go, C, Python, Java) verifies the same vectors in [`/vectors`](https://github.com/qorechain/qorechain-pqc/tree/main/vectors). See the [root README](https://github.com/qorechain/qorechain-pqc#readme).

## License

Apache-2.0

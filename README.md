# qorechain-pqc

Post-quantum cryptography for [QoreChain](https://github.com/qorechain) — **standardized NIST primitives**, one consistent API, in six languages, **proven byte-compatible** against a shared test-vector suite.

> **Standards only.** This library wraps audited implementations of the final NIST standards. It does **not** invent a custom scheme — a non-standard variant is exactly what breaks interoperability (and what motivated this repo). Every binding is validated against the same vectors so a signature produced in one language verifies in every other.

| Primitive | Standard | Role | Levels (default **bold**) |
|---|---|---|---|
| **ML-DSA** | FIPS-204 | digital signatures | 44 · 65 · **87** |
| **ML-KEM** | FIPS-203 | key encapsulation | 512 · 768 · **1024** |
| **SHAKE-256** | FIPS-202 | extendable-output hash | — |

## Sizes (bytes) — pick the level by your size/security budget

| Scheme | Security | Public key | Signature / Ciphertext |
|---|---|---|---|
| ML-DSA-44 | L2 | 1312 | 2420 |
| ML-DSA-65 | L3 | 1952 | 3309 |
| **ML-DSA-87** | L5 | 2592 | 4627 |
| ML-KEM-512 | L1 | 800 | 768 |
| ML-KEM-768 | L3 | 1184 | 1088 |
| **ML-KEM-1024** | L5 | 1568 | 1568 |

> You cannot make a NIST standard smaller and still be standard. To shrink the on-chain footprint, drop a security level (e.g. ML-DSA-65 is ~28% smaller than 87 and still L3), store only `pubkeyHash` in account state and put the full key in the tx, and never persist signatures in state (verify-and-discard). See [DESIGN.md](DESIGN.md).

## Languages

| Language | Package | Backed by | Status |
|---|---|---|---|
| JavaScript / TypeScript | `@qorechain/pqc` (npm) | [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) | ✅ tested |
| Rust | `qorechain-pqc` (crates.io) | `fips204` · `fips203` · `sha3` | ✅ tested |
| Go | `github.com/qorechain/qorechain-pqc/go` | [Cloudflare CIRCL](https://github.com/cloudflare/circl) | ✅ tested |
| C | `c/` (static lib + header) | [liboqs](https://github.com/open-quantum-safe/liboqs) + OpenSSL | ✅ tested |
| Python | `qorechain-pqc` (PyPI) | [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) | ✅ tested |
| Java | `network.qorechain:qorechain-pqc` (Maven) | [Bouncy Castle](https://www.bouncycastle.org/) | ✅ builds in CI |

## Consistent API (every language)

```
keygen()                              -> (publicKey, secretKey)
sign(secretKey, message)              -> signature
verify(publicKey, message, signature) -> bool

kem.keygen()                          -> (publicKey, secretKey)
kem.encapsulate(publicKey)            -> (cipherText, sharedSecret)
kem.decapsulate(secretKey, cipherText)-> sharedSecret

shake256(data, outLen=32)             -> digest
```

Blockchain helpers: `pubkeyHash(pk, len=20)` (pay-to-pubkey-hash registration) and
`hybridSignBytes(bodyWithoutPqcExt, authInfo)` (QoreChain's wallet-compatible
hybrid-extension sign-bytes framing).

### Quick start

```js
// JavaScript
import { mldsa, mlkem, shake256, pubkeyHash } from '@qorechain/pqc';
const { publicKey, secretKey } = mldsa.keygen();
const sig = mldsa.sign(secretKey, msg);
mldsa.verify(publicKey, msg, sig); // true
```

```rust
// Rust
use qorechain_pqc::mldsa::default as mldsa;
let (pk, sk) = mldsa::keygen()?;
let sig = mldsa::sign(&sk, msg)?;
assert!(mldsa::verify(&pk, msg, &sig));
```

```go
// Go
pk, sk, _ := pqc.MLDSA.Keygen()
sig, _ := pqc.MLDSA.Sign(sk, msg)
pqc.MLDSA.Verify(pk, msg, sig) // true
```

## The interop guarantee

`vectors/` holds canonical test vectors generated from `@noble/post-quantum` (the
FIPS reference). **Every binding's test suite verifies the same vectors**, so a
JS-signed ML-DSA signature verifies in Rust/Go/C/Python/Java, ML-KEM shared
secrets match across all six, and SHAKE-256 digests are identical. CI runs all of
them on every change. Regenerate with `node scripts/gen-vectors.mjs`.

## License

Apache-2.0.

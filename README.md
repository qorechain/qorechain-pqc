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
| Java | `io.github.qorechain:qorechain-pqc` (Maven Central) | [Bouncy Castle](https://www.bouncycastle.org/) | ✅ published |

## Consistent API (every language)

```
keygen()                              -> (publicKey, secretKey)
keygenFromSeed(seed)                  -> (publicKey, secretKey)   # 32-byte FIPS-204 xi
sign(secretKey, message)              -> signature                # DETERMINISTIC
verify(publicKey, message, signature) -> bool

kem.keygen()                          -> (publicKey, secretKey)
kem.encapsulate(publicKey)            -> (cipherText, sharedSecret)
kem.decapsulate(secretKey, cipherText)-> sharedSecret

shake256(data, outLen=32)             -> digest
```

Blockchain helpers: `pubkeyHash(pk, len=20)` (pay-to-pubkey-hash registration) and
QoreChain's wallet-compatible hybrid-extension sign-bytes, in both forms:

```
v1 (legacy): BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
v2:          "qorechain-pqc-hybrid-v2" ‖ BE64(len chainId) ‖ chainId ‖ BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
```

A network accepts exactly one form at any height. `qorechain-vladi` (mainnet) and
`qorechain-diana` (testnet) verify v1 until the `v3.1.98` upgrade is applied on
them and v2 afterwards; testnet is on v2, **mainnet stays on v1 until its own
upgrade**. Other chains verify v2 from genesis. Every binding exposes the v1
builder, the v2 builder, a dispatcher that requires the version, and
`signBytesVersionFor(chainId, v2AppliedHeight)` (v2 iff height > 0 or the chain is
not one of the two above):

| Binding | v1 / v2 / dispatcher / version rule |
|---|---|
| JS | `hybridSignBytesV1`, `hybridSignBytesV2`, `hybridSignBytes('v1'\|'v2', chainId, b0, auth)`, `signBytesVersionFor` |
| Go | `HybridSignBytesV1`, `HybridSignBytesV2`, `HybridSignBytes(SignBytesV1\|SignBytesV2, …) ([]byte, error)`, `SignBytesVersionFor` |
| Rust | `hybrid_sign_bytes_v1`, `hybrid_sign_bytes_v2`, `hybrid_sign_bytes(SignBytesVersion::V1\|V2, …)`, `sign_bytes_version_for` |
| Python | `hybrid_sign_bytes_v1`, `hybrid_sign_bytes_v2`, `hybrid_sign_bytes("v1"\|"v2", …)`, `sign_bytes_version_for` |
| Java | `hybridSignBytesV1`, `hybridSignBytesV2`, `hybridSignBytes(SIGN_BYTES_V1\|SIGN_BYTES_V2, …)`, `signBytesVersionFor` |
| C | `qpqc_hybrid_sign_bytes_v1`, `qpqc_hybrid_sign_bytes_v2`, `qpqc_hybrid_sign_bytes(QPQC_SIGN_BYTES_V1\|_V2, …)`, `qpqc_sign_bytes_version_for` |

These are pure functions: learning a network's applied height
(`GET {lcd}/cosmos/upgrade/v1beta1/applied_plan/v3.1.98`, `{"height":"<n>"}`,
compare numerically — `"0"` means not applied) is the caller's job; the
`@qorechain/wallet-adapter` resolver does it for JS wallets. All bindings are
tested against the chain's KAT, `vectors/signbytes-kat-v3.1.98.json` (flat copy for
C/Java: `vectors/signbytes-kat-v3.1.98.flat.txt`, from
`scripts/gen-signbytes-kat-flat.mjs`). **0.2.0 is breaking**: the old two-argument
`hybridSignBytes(b0, auth)` (v1) is now `hybridSignBytesV1` in every binding.

> **`sign` is DETERMINISTIC (FIPS-204 §3.4) in every binding** — the same
> `(secretKey, message)` always yields the same signature, byte-identical across
> languages and to the shared `/vectors`. QoreChain's on-chain PQC verifier
> accepts only deterministic signatures, so this default is consensus-critical.
> Randomized (hedged) signing is available as an explicit opt-in per binding
> (`{hedged: true}` / `sign_hedged` / `mldsaSignHedged` / `qpqc_mldsa_sign_hedged`)
> for non-chain uses. (The liboqs-backed C and Python bindings have no seeded
> keygen; their vector tests use the expanded `secretKey` field instead.)

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

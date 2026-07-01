# @qorechain/pqc

Post-quantum cryptography for [QoreChain](https://github.com/qorechain/qorechain-pqc) — standardized NIST primitives with one consistent API, proven byte-compatible against a shared cross-language test-vector suite.

| Primitive | Standard | Role |
|---|---|---|
| ML-DSA | FIPS-204 | digital signatures (44 · 65 · **87**) |
| ML-KEM | FIPS-203 | key encapsulation (512 · 768 · **1024**) |
| SHAKE-256 | FIPS-202 | extendable-output hash |

Backed by [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum).

## Install

```sh
npm install @qorechain/pqc
```

## Use

```js
import { mldsa, mlkem, shake256, pubkeyHash } from '@qorechain/pqc';

// ML-DSA-87 signatures — DETERMINISTIC by default (FIPS-204 §3.4), as required
// by QoreChain's on-chain PQC verifier. Pass { hedged: true } for randomized
// signing in non-chain contexts.
const { publicKey, secretKey } = mldsa.keygen();
const sig = mldsa.sign(secretKey, message);
mldsa.verify(publicKey, message, sig); // true

// ML-KEM-1024 key encapsulation
const { publicKey: ek, secretKey: dk } = mlkem.keygen();
const { cipherText, sharedSecret } = mlkem.encapsulate(ek);
mlkem.decapsulate(dk, cipherText); // === sharedSecret

// SHAKE-256 + blockchain helpers
shake256(data, 32);        // 32-byte digest
pubkeyHash(publicKey, 20); // pay-to-pubkey-hash
```

Level-specific exports: `mldsa44/65/87`, `mlkem512/768/1024` (`mldsa`/`mlkem` are the L5 defaults). Also `hybridSignBytes(bodyWithoutPqcExt, authInfo)` and `batchVerify`.

## Interop

Every binding (JS, Rust, Go, C, Python, Java) verifies the same vectors in [`/vectors`](https://github.com/qorechain/qorechain-pqc/tree/main/vectors), so a signature produced here verifies in every other language. See the [root README](https://github.com/qorechain/qorechain-pqc#readme).

## License

Apache-2.0

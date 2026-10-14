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

Level-specific exports: `mldsa44/65/87`, `mlkem512/768/1024` (`mldsa`/`mlkem` are the L5 defaults). Also `batchVerify` and the hybrid sign-bytes helpers: `hybridSignBytesV1(b0, auth)` (legacy), `hybridSignBytesV2(chainId, b0, auth)` (non-empty `chainId` required), `hybridSignBytes(version, chainId, b0, auth)` (version `'v1' | 'v2'` required), `SIGN_BYTES_V2_UPGRADES` and `signBytesVersionForApplied(chainId, appliedHeights)`.

A network accepts exactly one form. Mainnet (`qorechain-vladi`) and testnet (`qorechain-diana`) both verify **v2** today: the switch shipped under two plan names, `v3.1.98` (testnet) and `v3.2.0` (mainnet, applied at height 2,981,742), so ask the node for **every** name in `SIGN_BYTES_V2_UPGRADES` and let the greatest applied height decide:

```js
import { SIGN_BYTES_V2_UPGRADES, signBytesVersionForApplied, hybridSignBytes } from '@qorechain/pqc';

const applied = {};
for (const name of SIGN_BYTES_V2_UPGRADES) {
  const r = await fetch(`${lcd}/cosmos/upgrade/v1beta1/applied_plan/${name}`).then((x) => x.json());
  applied[name] = r.height; // "0" = not applied
}
const version = signBytesVersionForApplied(chainId, applied); // 'v1' | 'v2'
const signBytes = hybridSignBytes(version, chainId, b0, authInfo);
```

`signBytesVersionFor(chainId, height)` and the single-name `SIGN_BYTES_V2_UPGRADE` (now `'v3.2.0'`) remain for compatibility but are deprecated: querying only one name misreads a network that switched under the other.

Input checking: `verify` (and therefore `batchVerify`) never throws — a wrong-length key or signature, a non-byte message or any other malformed input returns `false`. `keygen(seed)`, `sign`, `encapsulate` and `decapsulate` throw an `Error` naming the bad argument and its expected length.

## Interop

Every binding (JS, Rust, Go, C, Python, Java) verifies the same vectors in [`/vectors`](https://github.com/qorechain/qorechain-pqc/tree/main/vectors), so a signature produced here verifies in every other language. See the [root README](https://github.com/qorechain/qorechain-pqc#readme).

## License

Apache-2.0

# qorechain-pqc (C)

Post-quantum cryptography for [QoreChain](https://github.com/qorechain/qorechain-pqc) — standardized NIST primitives with one consistent API, proven byte-compatible against a shared cross-language test-vector suite.

| Primitive | Standard | Role |
|---|---|---|
| ML-DSA | FIPS-204 | digital signatures (44 · 65 · **87**) |
| ML-KEM | FIPS-203 | key encapsulation (512 · 768 · **1024**) |
| SHAKE-256 | FIPS-202 | extendable-output hash |

Backed by [liboqs](https://github.com/open-quantum-safe/liboqs) (ML-DSA / ML-KEM) and OpenSSL (SHAKE-256).

## Build

Requires `liboqs` and OpenSSL development headers.

```sh
make            # builds libqorechain_pqc.a
make test       # builds + runs the shared-vector tests
```

## Use

```c
#include "qorechain_pqc.h"

// ML-DSA-87 signatures (heap-allocated outputs; free with qpqc_free)
uint8_t *pk, *sk; size_t pk_len, sk_len;
qpqc_mldsa_keygen("ml-dsa-87", &pk, &pk_len, &sk, &sk_len);

uint8_t *sig; size_t sig_len;
qpqc_mldsa_sign("ml-dsa-87", sk, sk_len, msg, msg_len, &sig, &sig_len);
int ok = qpqc_mldsa_verify("ml-dsa-87", pk, pk_len, msg, msg_len, sig, sig_len);

// SHAKE-256 + pay-to-pubkey-hash
uint8_t digest[32]; qpqc_shake256(data, data_len, digest, 32);

qpqc_free(pk); qpqc_free(sk); qpqc_free(sig);
```

See [`qorechain_pqc.h`](qorechain_pqc.h) for the full ABI (ML-KEM encapsulate/decapsulate, `qpqc_pubkey_hash`, `qpqc_hybrid_sign_bytes`).

## Interop

Every binding (JS, Rust, Go, C, Python, Java) verifies the same vectors in [`/vectors`](https://github.com/qorechain/qorechain-pqc/tree/main/vectors). See the [root README](https://github.com/qorechain/qorechain-pqc#readme).

## License

Apache-2.0

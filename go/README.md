# qorechain-pqc (Go)

Post-quantum cryptography for [QoreChain](https://github.com/qorechain/qorechain-pqc) — standardized NIST primitives with one consistent API, proven byte-compatible against a shared cross-language test-vector suite.

| Primitive | Standard | Role |
|---|---|---|
| ML-DSA | FIPS-204 | digital signatures (44 · 65 · **87**) |
| ML-KEM | FIPS-203 | key encapsulation (512 · 768 · **1024**) |
| SHAKE-256 | FIPS-202 | extendable-output hash |

Backed by [Cloudflare CIRCL](https://github.com/cloudflare/circl).

## Get

```sh
go get github.com/qorechain/qorechain-pqc/go
```

## Use

```go
import pqc "github.com/qorechain/qorechain-pqc/go"

// ML-DSA-87 signatures
pk, sk, _ := pqc.MLDSA.Keygen()
sig, _ := pqc.MLDSA.Sign(sk, message)
pqc.MLDSA.Verify(pk, message, sig) // true

// ML-KEM-1024 key encapsulation
ek, dk, _ := pqc.MLKEM.Keygen()
ct, ss, _ := pqc.MLKEM.Encapsulate(ek)
ss2, _ := pqc.MLKEM.Decapsulate(dk, ct) // bytes.Equal(ss, ss2)

// SHAKE-256 + pay-to-pubkey-hash
digest := pqc.Shake256(data, 32)
h := pqc.PubkeyHash(pk, 20)
```

Level values: `MLDSA44/65/87`, `MLKEM512/768/1024` (`MLDSA`/`MLKEM` are the L5 defaults).

## Interop

Every binding (JS, Rust, Go, C, Python, Java) verifies the same vectors in [`/vectors`](https://github.com/qorechain/qorechain-pqc/tree/main/vectors). See the [root README](https://github.com/qorechain/qorechain-pqc#readme).

## License

Apache-2.0

# qorechain-pqc (Java)

Post-quantum cryptography for [QoreChain](https://github.com/qorechain/qorechain-pqc) — standardized NIST primitives with one consistent API, proven byte-compatible against a shared cross-language test-vector suite.

| Primitive | Standard | Role |
|---|---|---|
| ML-DSA | FIPS-204 | digital signatures (44 · 65 · **87**) |
| ML-KEM | FIPS-203 | key encapsulation (512 · 768 · **1024**) |
| SHAKE-256 | FIPS-202 | extendable-output hash |

Backed by [Bouncy Castle](https://www.bouncycastle.org/).

## Add (Maven)

```xml
<dependency>
  <groupId>io.github.qorechain</groupId>
  <artifactId>qorechain-pqc</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Use

```java
import network.qorechain.pqc.Pqc;

// ML-DSA-87 signatures — byte[][] {publicKey, secretKey}
byte[][] kp = Pqc.mldsaKeygen("ml-dsa-87");
byte[] sig = Pqc.mldsaSign("ml-dsa-87", kp[1], message);
boolean ok = Pqc.mldsaVerify("ml-dsa-87", kp[0], message, sig);

// ML-KEM-1024 — encapsulate returns {ciphertext, sharedSecret}
byte[][] kem = Pqc.mlkemKeygen("ml-kem-1024");
byte[][] enc = Pqc.mlkemEncapsulate("ml-kem-1024", kem[0]);
byte[] ss = Pqc.mlkemDecapsulate("ml-kem-1024", kem[1], enc[0]);

// SHAKE-256 + pay-to-pubkey-hash
byte[] digest = Pqc.shake256(data, 32);
byte[] h = Pqc.pubkeyHash(kp[0], 20);
```

## Interop

Every binding (JS, Rust, Go, C, Python, Java) verifies the same vectors in [`/vectors`](https://github.com/qorechain/qorechain-pqc/tree/main/vectors). See the [root README](https://github.com/qorechain/qorechain-pqc#readme).

## License

Apache-2.0

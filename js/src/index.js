// @qorechain/pqc — post-quantum cryptography for QoreChain.
//
// Standards (final NIST FIPS), wrapping the audited @noble/post-quantum:
//   - ML-DSA   (FIPS-204) signatures — levels 44 / 65 / 87 (default 87)
//   - ML-KEM   (FIPS-203) key encapsulation — levels 512 / 768 / 1024 (default 1024)
//   - SHAKE-256 (FIPS-202) extendable-output hash
//
// The API is intentionally identical across every language binding in this repo
// (keygen / sign(secretKey, message) / verify(publicKey, message, signature)),
// and all bindings are validated against the shared vectors in /vectors.
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { shake256 as nobleShake } from '@noble/hashes/sha3.js';

function wrapSig(scheme, name) {
  return {
    name,
    // keygen(seed?) -> { publicKey, secretKey }. seed is a 32-byte ML-DSA xi.
    keygen: (seed) => scheme.keygen(seed),
    // sign(secretKey, message, opts?) -> signature  (conventional arg order)
    //
    // DETERMINISTIC (FIPS-204 §3.4) by default — same (secretKey, message)
    // always yields the same signature, matching every other language binding
    // and the shared /vectors. QoreChain's on-chain PQC verifier accepts ONLY
    // deterministic signatures, so this default is consensus-critical: do not
    // change it. Pass { hedged: true } to opt in to randomized signing for
    // non-chain uses that want side-channel hedging.
    sign: (secretKey, message, opts = {}) => opts.hedged === true
      ? scheme.sign(message, secretKey) // noble's default: hedged (random rnd)
      : scheme.sign(message, secretKey, { extraEntropy: false }),
    // verify(publicKey, message, signature) -> boolean
    verify: (publicKey, message, signature) => scheme.verify(signature, message, publicKey),
  };
}
function wrapKem(scheme, name) {
  return {
    name,
    keygen: (seed) => scheme.keygen(seed),
    encapsulate: (publicKey) => scheme.encapsulate(publicKey),
    decapsulate: (secretKey, cipherText) => scheme.decapsulate(cipherText, secretKey),
  };
}

export const mldsa44 = wrapSig(ml_dsa44, 'ml-dsa-44');
export const mldsa65 = wrapSig(ml_dsa65, 'ml-dsa-65');
export const mldsa87 = wrapSig(ml_dsa87, 'ml-dsa-87');
export const mlkem512 = wrapKem(ml_kem512, 'ml-kem-512');
export const mlkem768 = wrapKem(ml_kem768, 'ml-kem-768');
export const mlkem1024 = wrapKem(ml_kem1024, 'ml-kem-1024');

// QoreChain defaults (security level 5).
export const mldsa = mldsa87;
export const mlkem = mlkem1024;

// SHAKE-256 (FIPS-202). Default 32-byte digest; XOF for arbitrary length.
export function shake256(data, outLen = 32) { return nobleShake(data, { dkLen: outLen }); }

// ── Blockchain helpers ──────────────────────────────────────────────────────

// pubkeyHash: SHAKE-256(publicKey) truncated to `len` bytes (default 20). Lets a
// chain register only the 20/32-byte hash in account state and require the full
// public key in the transaction (pay-to-pubkey-hash style), keeping state small.
export function pubkeyHash(publicKey, len = 20) { return shake256(publicKey, len); }

// hybridSignBytes: the canonical message a PQC signature covers in QoreChain's
// hybrid-extension scheme. B0 is the tx body WITHOUT the PQC extension; the
// framing BE32(len(B0))||B0||BE32(len(authInfo))||authInfo is independent of the
// extension, so a wallet's classical signature and this PQC signature can be
// layered without invalidating each other.
export function hybridSignBytes(bodyWithoutPqcExt, authInfoBytes) {
  const be32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };
  const parts = [be32(bodyWithoutPqcExt.length), bodyWithoutPqcExt, be32(authInfoBytes.length), authInfoBytes];
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// batchVerify: verify many (publicKey, message, signature) triples; returns the
// index of the first failure, or -1 if all valid.
export function batchVerify(scheme, items) {
  for (let i = 0; i < items.length; i++) {
    const { publicKey, message, signature } = items[i];
    if (scheme.verify(publicKey, message, signature) !== true) return i;
  }
  return -1;
}

export const VERSION = '0.1.1';

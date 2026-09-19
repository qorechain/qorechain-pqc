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

// ── Hybrid sign-bytes: the message a PQC signature covers in QoreChain's
// hybrid-extension scheme. B0 is the tx body WITHOUT the PQC extension and A the
// AuthInfo bytes, so the wallet's classical signature and this PQC signature can
// be layered without invalidating each other. Two forms exist, and a network
// accepts exactly ONE of them at any height:
//
//   v1 (legacy): BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
//   v2:          "qorechain-pqc-hybrid-v2" ‖ BE64(len chainId) ‖ chainId ‖
//                  BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
//
// v2's domain tag keeps a signature the key made in another context from being
// valid transaction sign-bytes; the chain-id keeps it from verifying on another
// network. Networks that existed before chain release v3.1.98 verify v1 until
// that upgrade is applied on them (signBytesVersionFor). This library is pure:
// asking a network for its applied height is left to the caller.
export const HYBRID_SIGN_BYTES_V2_DOMAIN = 'qorechain-pqc-hybrid-v2';
export const HYBRID_SIGN_BYTES_DOMAIN = HYBRID_SIGN_BYTES_V2_DOMAIN;
export const SIGN_BYTES_V2_UPGRADE = 'v3.1.98';
export const LEGACY_SIGN_BYTES_CHAINS = Object.freeze(['qorechain-vladi', 'qorechain-diana']);

const be32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };
const be64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; };
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// Legacy v1 form, kept for networks that have not applied v3.1.98.
export function hybridSignBytesV1(bodyWithoutPqcExt, authInfoBytes) {
  return concat([be32(bodyWithoutPqcExt.length), bodyWithoutPqcExt, be32(authInfoBytes.length), authInfoBytes]);
}

// v2 form (x/pqc/types.HybridSignBytes).
export function hybridSignBytesV2(chainId, bodyWithoutPqcExt, authInfoBytes) {
  if (typeof chainId !== 'string' || chainId.length === 0) throw new Error('hybridSignBytesV2: chainId is required');
  const te = new TextEncoder();
  const cid = te.encode(chainId);
  return concat([te.encode(HYBRID_SIGN_BYTES_V2_DOMAIN), be64(cid.length), cid,
    be32(bodyWithoutPqcExt.length), bodyWithoutPqcExt, be32(authInfoBytes.length), authInfoBytes]);
}

// Version-dispatching builder. `version` ('v1' | 'v2') is REQUIRED: there is no
// implicit form, because each network accepts exactly one.
export function hybridSignBytes(version, chainId, bodyWithoutPqcExt, authInfoBytes) {
  if (version === 'v2') return hybridSignBytesV2(chainId, bodyWithoutPqcExt, authInfoBytes);
  if (version === 'v1') return hybridSignBytesV1(bodyWithoutPqcExt, authInfoBytes);
  throw new Error(`hybridSignBytes: version must be 'v1' or 'v2', got ${JSON.stringify(version)} (signature is hybridSignBytes(version, chainId, b0, authInfo))`);
}

// The form a client must sign for chainId, given the height at which the v3.1.98
// plan was applied on it (0 / "0" / null = not applied). Mirrors the chain's
// SignBytesVersionFor. Compared numerically: nodes return the height as a
// string, and "0" is truthy.
export function signBytesVersionFor(chainId, v2AppliedHeight) {
  const h = v2AppliedHeight === undefined || v2AppliedHeight === null || v2AppliedHeight === ''
    ? 0n : BigInt(typeof v2AppliedHeight === 'number' ? Math.trunc(v2AppliedHeight) : v2AppliedHeight);
  if (h > 0n) return 'v2';
  return LEGACY_SIGN_BYTES_CHAINS.includes(chainId) ? 'v1' : 'v2';
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

export const VERSION = '0.2.0';

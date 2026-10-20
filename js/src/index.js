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

// Exact FIPS-204 / FIPS-203 sizes, checked before any input reaches the backend
// so a malformed argument is reported by name instead of surfacing as a raw
// RangeError/TypeError from inside @noble.
const SIG_LENGTHS = {
  'ml-dsa-44': { seed: 32, publicKey: 1312, secretKey: 2560, signature: 2420 },
  'ml-dsa-65': { seed: 32, publicKey: 1952, secretKey: 4032, signature: 3309 },
  'ml-dsa-87': { seed: 32, publicKey: 2592, secretKey: 4896, signature: 4627 },
};
const KEM_LENGTHS = {
  'ml-kem-512': { seed: 64, publicKey: 800, secretKey: 1632, cipherText: 768 },
  'ml-kem-768': { seed: 64, publicKey: 1184, secretKey: 2400, cipherText: 1088 },
  'ml-kem-1024': { seed: 64, publicKey: 1568, secretKey: 3168, cipherText: 1568 },
};

const isBytes = (v) => v instanceof Uint8Array;
const describe = (v) => (isBytes(v) ? `${v.length} bytes`
  : v === null ? 'null' : Array.isArray(v) ? 'an Array' : typeof v);
// Throws a plain Error naming the argument and, when fixed, the expected length.
function requireBytes(fn, arg, v, len) {
  if (!isBytes(v)) {
    throw new Error(`${fn}: ${arg} must be a Uint8Array${len === undefined ? '' : ` of ${len} bytes`}, got ${describe(v)}`);
  }
  if (len !== undefined && v.length !== len) {
    throw new Error(`${fn}: ${arg} must be exactly ${len} bytes, got ${v.length}`);
  }
}

function wrapSig(scheme, name) {
  const L = SIG_LENGTHS[name];
  return {
    name,
    // keygen(seed?) -> { publicKey, secretKey }. seed is a 32-byte ML-DSA xi.
    keygen: (seed) => {
      if (seed !== undefined) requireBytes(`${name}.keygen`, 'seed', seed, L.seed);
      return scheme.keygen(seed);
    },
    // sign(secretKey, message, opts?) -> signature  (conventional arg order)
    //
    // DETERMINISTIC (FIPS-204 §3.4) by default — same (secretKey, message)
    // always yields the same signature, matching every other language binding
    // and the shared /vectors. QoreChain's on-chain PQC verifier accepts any
    // valid FIPS-204 signature, hedged or deterministic; the default keeps
    // signatures reproducible. Pass { hedged: true } to opt in to randomized
    // (hedged) signing, which the chain accepts equally.
    sign: (secretKey, message, opts = {}) => {
      requireBytes(`${name}.sign`, 'secretKey', secretKey, L.secretKey);
      requireBytes(`${name}.sign`, 'message', message);
      return opts && opts.hedged === true
        ? scheme.sign(message, secretKey) // noble's default: hedged (random rnd)
        : scheme.sign(message, secretKey, { extraEntropy: false });
    },
    // verify(publicKey, message, signature) -> boolean. Never throws: any
    // malformed input (wrong-length key or signature, non-byte message, …) is
    // simply not a valid signature, so it returns false.
    verify: (publicKey, message, signature) => {
      if (!isBytes(publicKey) || publicKey.length !== L.publicKey) return false;
      if (!isBytes(signature) || signature.length !== L.signature) return false;
      if (!isBytes(message)) return false;
      try {
        return scheme.verify(signature, message, publicKey) === true;
      } catch {
        return false;
      }
    },
  };
}
function wrapKem(scheme, name) {
  const L = KEM_LENGTHS[name];
  return {
    name,
    // keygen(seed?) -> { publicKey, secretKey }. seed is the 64-byte d ‖ z.
    keygen: (seed) => {
      if (seed !== undefined) requireBytes(`${name}.keygen`, 'seed', seed, L.seed);
      return scheme.keygen(seed);
    },
    encapsulate: (publicKey) => {
      requireBytes(`${name}.encapsulate`, 'publicKey', publicKey, L.publicKey);
      return scheme.encapsulate(publicKey);
    },
    decapsulate: (secretKey, cipherText) => {
      requireBytes(`${name}.decapsulate`, 'secretKey', secretKey, L.secretKey);
      requireBytes(`${name}.decapsulate`, 'cipherText', cipherText, L.cipherText);
      return scheme.decapsulate(cipherText, secretKey);
    },
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
// network.
//
// The two networks that existed before v2 (qorechain-vladi, qorechain-diana)
// verify v1 until a switching upgrade is applied on them, v2 afterwards; every
// other chain verifies v2 from genesis. The switch has shipped under TWO plan
// names: testnet took it as "v3.1.98" and mainnet as "v3.2.0", and each network
// keeps its record forever. Ask the network for every name in
// SIGN_BYTES_V2_UPGRADES and pass the answers to signBytesVersionForApplied.
// This library is pure: asking a network for its applied heights is left to the
// caller.
export const HYBRID_SIGN_BYTES_V2_DOMAIN = 'qorechain-pqc-hybrid-v2';
export const HYBRID_SIGN_BYTES_DOMAIN = HYBRID_SIGN_BYTES_V2_DOMAIN;
// Every upgrade-plan name that switched a network to v2, newest first. Mirror of
// the chain's x/pqc/types.SignBytesV2Upgrades.
export const SIGN_BYTES_V2_UPGRADES = Object.freeze(['v3.2.0', 'v3.1.98']);
// DEPRECATED: the primary (newest) name only. A network may have taken the
// switch under any name in SIGN_BYTES_V2_UPGRADES (testnet applied "v3.1.98",
// mainnet "v3.2.0"); querying only this one misreads testnet as not switched.
// Use SIGN_BYTES_V2_UPGRADES with signBytesVersionForApplied.
export const SIGN_BYTES_V2_UPGRADE = 'v3.2.0';
export const LEGACY_SIGN_BYTES_CHAINS = Object.freeze(['qorechain-vladi', 'qorechain-diana']);

const be32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, false); return b; };
const be64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; };
const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

// Legacy v1 form, kept for networks that have not applied any of SIGN_BYTES_V2_UPGRADES.
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

// Parses an applied height as returned by a node (number, numeric string,
// bigint; 0 / "0" / "" / null / undefined = not applied).
function toHeight(v) {
  if (v === undefined || v === null || v === '') return 0n;
  return BigInt(typeof v === 'number' ? Math.trunc(v) : v);
}

// The form a client must sign for chainId, given the height at which the switch
// to v2 was applied on it (0 / "0" / null = not applied) — already the greatest
// height across SIGN_BYTES_V2_UPGRADES; prefer signBytesVersionForApplied, which
// computes it. Mirrors the chain's SignBytesVersionFor. Compared numerically:
// nodes return the height as a string, and "0" is truthy.
export function signBytesVersionFor(chainId, v2AppliedHeight) {
  if (toHeight(v2AppliedHeight) > 0n) return 'v2';
  return LEGACY_SIGN_BYTES_CHAINS.includes(chainId) ? 'v1' : 'v2';
}

// signBytesVersionFor over every known upgrade name. appliedHeights maps a plan
// name to the height at which the network applied it (absent / 0 / "0" = not
// applied), as an object or a Map; the greatest height across
// SIGN_BYTES_V2_UPGRADES decides and other names are ignored. Mirrors the
// chain's SignBytesVersionForApplied.
export function signBytesVersionForApplied(chainId, appliedHeights) {
  const get = (n) => (appliedHeights instanceof Map ? appliedHeights.get(n)
    : appliedHeights && Object.prototype.hasOwnProperty.call(appliedHeights, n) ? appliedHeights[n] : undefined);
  let best = 0n;
  for (const name of SIGN_BYTES_V2_UPGRADES) {
    const h = toHeight(get(name));
    if (h > best) best = h;
  }
  return signBytesVersionFor(chainId, best);
}

// batchVerify: verify many (publicKey, message, signature) triples; returns the
// index of the first failure, or -1 if all valid.
export function batchVerify(scheme, items) {
  for (let i = 0; i < items.length; i++) {
    const { publicKey, message, signature } = items[i] ?? {};
    if (scheme.verify(publicKey, message, signature) !== true) return i;
  }
  return -1;
}

export const VERSION = '0.2.2';

// Generates canonical cross-language test vectors for qorechain-pqc.
//
// Source of truth: @noble/post-quantum (audited FIPS-204 / FIPS-203 / FIPS-202).
// Every language binding in this repo MUST reproduce these byte-for-byte:
//   - ML-DSA: keygen(seed) deterministic -> pk; sign is made deterministic with
//     {extraEntropy:false} (FIPS-204 non-hedged) so vectors are reproducible;
//     verify(pk,msg,sig)==true in every binding.
//   - ML-KEM: keygen(seed) deterministic -> (pk,sk); encapsulate(pk, m) with a
//     fixed 32-byte coin m is deterministic -> (ct,ss); decapsulate(ct,sk)==ss.
//   - SHAKE-256: shake256(msg, dkLen) must match.
//
// Outputs (a single run keeps JSON + flat.txt in lockstep):
//   vectors/<alg>.json   — structured, read by the JS/Rust/Go/Python tests
//   vectors/flat.txt     — line-based, read by the C/Java tests
//
// Run: node scripts/gen-vectors.mjs
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'vectors');
const hex = (b) => Buffer.from(b).toString('hex');
const seedN = (n, len) => { const s = new Uint8Array(len); for (let i = 0; i < len; i++) s[i] = (n * 131 + i * 17 + 7) & 0xff; return s; };
const msgN = (n) => new TextEncoder().encode(`qorechain-pqc/vector/${n}`);
const flat = [];

function mldsa(name, scheme) {
  const cases = [];
  for (let i = 0; i < 5; i++) {
    const seed = seedN(i + 1, 32);
    const { publicKey, secretKey } = scheme.keygen(seed); // deterministic from 32-byte seed
    const msg = msgN(i);
    const sig = scheme.sign(msg, secretKey, { extraEntropy: false }); // deterministic (non-hedged)
    if (scheme.verify(sig, msg, publicKey) !== true) throw new Error(`${name} self-verify failed`);
    cases.push({ seed: hex(seed), publicKey: hex(publicKey), message: hex(msg), signature: hex(sig) });
    flat.push(`mldsa ${name} ${hex(publicKey)} ${hex(msg)} ${hex(sig)}`);
  }
  return { algorithm: name, fips: 'FIPS-204', sizes: { publicKey: cases[0].publicKey.length / 2, signature: cases[0].signature.length / 2 }, deterministicKeygen: true, cases };
}

function mlkem(name, scheme) {
  const cases = [];
  for (let i = 0; i < 5; i++) {
    const seed = seedN(i + 1, 64); // ML-KEM keygen seed is 64 bytes (d||z)
    const { publicKey, secretKey } = scheme.keygen(seed);
    const coin = seedN(100 + i, 32); // fixed encapsulation coin -> deterministic (ct,ss)
    const { cipherText, sharedSecret } = scheme.encapsulate(publicKey, coin);
    const ss2 = scheme.decapsulate(cipherText, secretKey);
    if (hex(ss2) !== hex(sharedSecret)) throw new Error(`${name} encaps/decaps mismatch`);
    cases.push({ seed: hex(seed), publicKey: hex(publicKey), secretKey: hex(secretKey), cipherText: hex(cipherText), sharedSecret: hex(sharedSecret) });
    flat.push(`mlkem ${name} ${hex(secretKey)} ${hex(cipherText)} ${hex(sharedSecret)}`);
  }
  return { algorithm: name, fips: 'FIPS-203', sizes: { publicKey: cases[0].publicKey.length / 2, cipherText: cases[0].cipherText.length / 2, sharedSecret: cases[0].sharedSecret.length / 2 }, deterministicKeygen: true, cases };
}

function shake() {
  const cases = [];
  for (let i = 0; i < 6; i++) {
    const msg = i === 0 ? new Uint8Array(0) : msgN(i);
    const out32 = hex(shake256(msg, { dkLen: 32 }));
    const out64 = hex(shake256(msg, { dkLen: 64 }));
    cases.push({ message: hex(msg), out32, out64 });
    flat.push(`shake ${msg.length === 0 ? '-' : hex(msg)} ${out32} ${out64}`);
  }
  return { algorithm: 'shake256', fips: 'FIPS-202', cases };
}

const vectors = {
  'ml-dsa-44': mldsa('ml-dsa-44', ml_dsa44),
  'ml-dsa-65': mldsa('ml-dsa-65', ml_dsa65),
  'ml-dsa-87': mldsa('ml-dsa-87', ml_dsa87),
  'ml-kem-512': mlkem('ml-kem-512', ml_kem512),
  'ml-kem-768': mlkem('ml-kem-768', ml_kem768),
  'ml-kem-1024': mlkem('ml-kem-1024', ml_kem1024),
  'shake-256': shake(),
};
for (const [k, v] of Object.entries(vectors)) {
  writeFileSync(join(out, `${k}.json`), JSON.stringify(v, null, 2) + '\n');
  console.log(`wrote vectors/${k}.json (${v.cases.length} cases)`);
}
writeFileSync(join(out, 'flat.txt'), flat.join('\n') + '\n');
console.log(`wrote vectors/flat.txt (${flat.length} records)`);

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as pqc from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vdir = join(here, '..', '..', 'vectors');
const load = (n) => JSON.parse(readFileSync(join(vdir, n), 'utf8'));
const hb = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const hx = (b) => Buffer.from(b).toString('hex');

for (const [name, scheme] of [['ml-dsa-44', pqc.mldsa44], ['ml-dsa-65', pqc.mldsa65], ['ml-dsa-87', pqc.mldsa87]]) {
  test(`${name}: deterministic keygen + verify shared vectors`, () => {
    for (const c of load(`${name}.json`).cases) {
      const { publicKey } = scheme.keygen(hb(c.seed));
      assert.equal(hx(publicKey), c.publicKey, 'keygen(seed) must reproduce publicKey');
      assert.equal(scheme.verify(hb(c.publicKey), hb(c.message), hb(c.signature)), true);
    }
  });

  // Regression: QoreChain's PQC ante verifier accepts only DETERMINISTIC
  // (FIPS-204 §3.4) signatures — sign() must reproduce the shared vectors
  // byte-for-byte, not emit hedged/randomized signatures.
  test(`${name}: sign() is deterministic and reproduces shared vectors`, () => {
    for (const c of load(`${name}.json`).cases) {
      const { secretKey } = scheme.keygen(hb(c.seed));
      assert.equal(hx(scheme.sign(secretKey, hb(c.message))), c.signature,
        'sign(secretKey, message) must reproduce the chain-verified deterministic signature');
    }
  });
}

for (const [name, scheme] of [['ml-kem-512', pqc.mlkem512], ['ml-kem-768', pqc.mlkem768], ['ml-kem-1024', pqc.mlkem1024]]) {
  test(`${name}: deterministic keygen + decapsulate shared vectors`, () => {
    for (const c of load(`${name}.json`).cases) {
      const { publicKey } = scheme.keygen(hb(c.seed));
      assert.equal(hx(publicKey), c.publicKey, 'keygen(seed) must reproduce publicKey');
      assert.equal(hx(scheme.decapsulate(hb(c.secretKey), hb(c.cipherText))), c.sharedSecret);
    }
  });
}

test('shake-256: shared vectors', () => {
  for (const c of load('shake-256.json').cases) {
    assert.equal(hx(pqc.shake256(hb(c.message), 32)), c.out32);
    assert.equal(hx(pqc.shake256(hb(c.message), 64)), c.out64);
  }
});

test('mldsa.sign({ hedged: true }): randomized opt-in still verifies', () => {
  const { publicKey, secretKey } = pqc.mldsa.keygen();
  const msg = new TextEncoder().encode('hedged-opt-in');
  const a = pqc.mldsa.sign(secretKey, msg, { hedged: true });
  const b = pqc.mldsa.sign(secretKey, msg, { hedged: true });
  assert.notEqual(hx(a), hx(b), 'hedged signatures must be randomized');
  assert.equal(pqc.mldsa.verify(publicKey, msg, a), true);
  assert.equal(pqc.mldsa.verify(publicKey, msg, b), true);
});

test('blockchain helpers: pubkeyHash + hybridSignBytes framing', () => {
  const { publicKey, secretKey } = pqc.mldsa.keygen();
  assert.equal(pqc.pubkeyHash(publicKey).length, 20);
  const body = new Uint8Array([1, 2, 3]), auth = new Uint8Array([9, 9]);
  const sb = pqc.hybridSignBytes(body, auth);
  // BE32(3)||body||BE32(2)||auth
  assert.deepEqual([...sb], [0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9]);
  const sig = pqc.mldsa.sign(secretKey, sb);
  assert.equal(pqc.mldsa.verify(publicKey, sb, sig), true);
});

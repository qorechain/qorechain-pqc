// Hybrid sign-bytes v1 (legacy) / v2 against the chain's v3.1.98 KAT vectors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as pqc from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KAT = JSON.parse(readFileSync(join(here, '..', '..', 'vectors', 'signbytes-kat-v3.1.98.json'), 'utf8'));
const hb = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const hx = (b) => Buffer.from(b).toString('hex');

test('constants', () => {
  assert.equal(pqc.HYBRID_SIGN_BYTES_V2_DOMAIN, KAT.hybrid_domain);
  assert.equal(pqc.HYBRID_SIGN_BYTES_DOMAIN, KAT.hybrid_domain);
  assert.equal(pqc.SIGN_BYTES_V2_UPGRADE, 'v3.1.98');
  assert.deepEqual([...pqc.LEGACY_SIGN_BYTES_CHAINS], ['qorechain-vladi', 'qorechain-diana']);
});

test('KAT hybrid_v2: all vectors byte-exact (direct and via the dispatcher)', () => {
  assert.equal(KAT.hybrid_v2.length, 5);
  for (const v of KAT.hybrid_v2) {
    const b0 = hb(v.body_without_pqc_ext_hex), a = hb(v.auth_info_hex);
    assert.equal(hx(pqc.hybridSignBytesV2(v.chain_id, b0, a)), v.sign_bytes_hex, v.name);
    assert.equal(hx(pqc.hybridSignBytes('v2', v.chain_id, b0, a)), v.sign_bytes_hex, v.name);
  }
});

test('v1 legacy layout; dispatcher requires an explicit version', () => {
  const b0 = Uint8Array.from([1, 2, 3]), a = Uint8Array.from([9, 9]);
  assert.deepEqual([...pqc.hybridSignBytesV1(b0, a)], [0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9]);
  assert.throws(() => pqc.hybridSignBytes(b0, a), /version must be/);
  assert.throws(() => pqc.hybridSignBytes('qorechain-vladi', b0, a), /version must be/);
  assert.throws(() => pqc.hybridSignBytesV2('', b0, a));
});

test('signBytesVersionFor truth table', () => {
  for (const cid of ['qorechain-vladi', 'qorechain-diana']) {
    for (const h of [0, '0', 0n, null, undefined]) assert.equal(pqc.signBytesVersionFor(cid, h), 'v1', `${cid} ${h}`);
    for (const h of [5746000, '5746000', 5746000n]) assert.equal(pqc.signBytesVersionFor(cid, h), 'v2');
  }
  assert.equal(pqc.signBytesVersionFor('qorechain-other', 0), 'v2');
  assert.equal(pqc.signBytesVersionFor('qorechain-other', '5746000'), 'v2');
});

test('a signature over v2 verifies over v2 bytes and not over v1', () => {
  const { publicKey, secretKey } = pqc.mldsa.keygen(new Uint8Array(32).fill(4));
  const b0 = Uint8Array.from([1, 2, 3]), a = Uint8Array.from([9]);
  const v2 = pqc.hybridSignBytes('v2', 'qorechain-vladi', b0, a);
  const v1 = pqc.hybridSignBytes('v1', 'qorechain-vladi', b0, a);
  const sig = pqc.mldsa.sign(secretKey, v2);
  assert.equal(pqc.mldsa.verify(publicKey, v2, sig), true);
  assert.equal(pqc.mldsa.verify(publicKey, v1, sig), false);
});

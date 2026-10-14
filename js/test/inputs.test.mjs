// Malformed inputs: verify (and so batchVerify) returns false and never throws;
// keygen/sign/encapsulate/decapsulate throw an Error naming the argument.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as pqc from '../src/index.js';

const msg = new TextEncoder().encode('qorechain');

for (const [name, s, pkLen, skLen, sigLen] of [
  ['ml-dsa-44', pqc.mldsa44, 1312, 2560, 2420],
  ['ml-dsa-65', pqc.mldsa65, 1952, 4032, 3309],
  ['ml-dsa-87', pqc.mldsa87, 2592, 4896, 4627],
]) {
  test(`${name}: verify returns false on malformed input, never throws`, () => {
    const { publicKey, secretKey } = s.keygen(new Uint8Array(32).fill(7));
    const sig = s.sign(secretKey, msg);
    assert.equal(s.verify(publicKey, msg, sig), true);
    const bad = [
      [publicKey.subarray(0, pkLen - 1), msg, sig],          // short public key
      [new Uint8Array(pkLen + 1), msg, sig],                  // long public key
      [new Uint8Array(0), msg, sig],                          // empty public key
      [publicKey, msg, sig.subarray(0, sigLen - 1)],          // short signature
      [publicKey, msg, Uint8Array.from([...sig, 0])],         // trailing byte
      [publicKey, 'qorechain', sig],                          // string message
      [publicKey, [1, 2, 3], sig],                            // array message
      [publicKey, null, sig],
      [publicKey, undefined, sig],
      [null, msg, sig],
      [undefined, msg, sig],
      ['00'.repeat(pkLen), msg, sig],                         // hex string key
      [publicKey, msg, null],
      [publicKey, msg, {}],
      [123, 456, 789],
    ];
    for (const [pk, m, sg] of bad) {
      let r;
      assert.doesNotThrow(() => { r = s.verify(pk, m, sg); });
      assert.equal(r, false);
    }
  });

  test(`${name}: batchVerify reports malformed items instead of throwing`, () => {
    const { publicKey, secretKey } = s.keygen(new Uint8Array(32).fill(8));
    const sig = s.sign(secretKey, msg);
    const good = { publicKey, message: msg, signature: sig };
    assert.equal(pqc.batchVerify(s, [good, good]), -1);
    assert.equal(pqc.batchVerify(s, [good, { publicKey: publicKey.subarray(1), message: msg, signature: sig }]), 1);
    assert.equal(pqc.batchVerify(s, [{ publicKey, message: 'x', signature: sig }]), 0);
    assert.equal(pqc.batchVerify(s, [good, null]), 1);
    assert.equal(pqc.batchVerify(s, [good, {}]), 1);
  });

  test(`${name}: keygen/sign name the bad argument and expected length`, () => {
    assert.throws(() => s.keygen(new Uint8Array(31)), (e) => e.constructor === Error && /seed must be exactly 32 bytes, got 31/.test(e.message));
    assert.throws(() => s.keygen('seed'), /seed must be a Uint8Array of 32 bytes, got string/);
    const { secretKey } = s.keygen();
    assert.throws(() => s.sign(secretKey.subarray(1), msg), (e) => e.constructor === Error && new RegExp(`secretKey must be exactly ${skLen} bytes, got ${skLen - 1}`).test(e.message));
    assert.throws(() => s.sign(new Uint8Array(32), msg), new RegExp(`${name}\\.sign: secretKey must be exactly ${skLen} bytes, got 32`));
    assert.throws(() => s.sign(null, msg), /secretKey must be a Uint8Array/);
    assert.throws(() => s.sign(secretKey, 'qorechain'), /message must be a Uint8Array, got string/);
    assert.throws(() => s.sign(secretKey, undefined), /message must be a Uint8Array, got undefined/);
    // Still signs fine with a null opts.
    assert.equal(s.sign(secretKey, msg, null).length, sigLen);
  });
}

for (const [name, k, pkLen, skLen, ctLen] of [
  ['ml-kem-512', pqc.mlkem512, 800, 1632, 768],
  ['ml-kem-768', pqc.mlkem768, 1184, 2400, 1088],
  ['ml-kem-1024', pqc.mlkem1024, 1568, 3168, 1568],
]) {
  test(`${name}: keygen/encapsulate/decapsulate name the bad argument and expected length`, () => {
    assert.throws(() => k.keygen(new Uint8Array(32)), /seed must be exactly 64 bytes, got 32/);
    const { publicKey, secretKey } = k.keygen();
    assert.throws(() => k.encapsulate(publicKey.subarray(1)), (e) => e.constructor === Error && new RegExp(`${name}\\.encapsulate: publicKey must be exactly ${pkLen} bytes, got ${pkLen - 1}`).test(e.message));
    assert.throws(() => k.encapsulate(null), /publicKey must be a Uint8Array/);
    const { cipherText, sharedSecret } = k.encapsulate(publicKey);
    assert.deepEqual(k.decapsulate(secretKey, cipherText), sharedSecret);
    assert.throws(() => k.decapsulate(secretKey.subarray(1), cipherText), new RegExp(`secretKey must be exactly ${skLen} bytes, got ${skLen - 1}`));
    assert.throws(() => k.decapsulate(secretKey, cipherText.subarray(1)), new RegExp(`cipherText must be exactly ${ctLen} bytes, got ${ctLen - 1}`));
    assert.throws(() => k.decapsulate(secretKey, 'ct'), /cipherText must be a Uint8Array of \d+ bytes, got string/);
  });
}

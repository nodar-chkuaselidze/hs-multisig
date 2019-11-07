/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const MultisigMTX = require('../lib/primitives/mtx');
const {KeyRing, Script, Coin, consensus} = require('hsd');

const utils = require('./util/wallet');

// 1 BTC
const HNS = consensus.COIN;

describe('MultisigMTX', function () {
  it('should get input signature', async () => {
    const ring = createRing();
    const ring2 = createRing();
    const {mtx, coins} = await createSpendingTX(ring, HNS);
    const coin = coins[0];

    // sign duplicate tx
    const signedMTX = mtx.clone();
    signedMTX.view = mtx.view;

    const signed = signedMTX.sign(ring);
    assert(signed, 'Could not sign transaction.');

    let sig;
    {
      // get signature from input
      const input = signedMTX.inputs[0];
      const signScript = input.witness;
      const vector = signScript.toStack();

      sig = vector.get(0);
    }

    const sig2 = mtx.getInputSignature(0, coin, ring);
    const check1 = mtx.checkSignature(0, coin, ring, sig);

    assert.bufferEqual(sig2, sig);
    assert.strictEqual(check1, true);

    let err;
    try {
      mtx.checkSignature(0, coin, ring2, sig);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.message, 'Coin does not belong to the ring.');

    // apply signature
    sig = null;
    err = null;

    mtx.scriptInput(0, coin, ring);
    let applied = mtx.applySignature(0, coin, ring, sig2);

    assert.strictEqual(applied, true);

    {
      const input = mtx.inputs[0];
      const signScript = input.witness;
      const vector = signScript.toStack();

      sig = vector.get(0);
    }

    assert.bufferEqual(sig, sig2);

    // reset mtx input
    applied = mtx.applySignature(0, coin, ring2, sig2);
    assert.strictEqual(applied, false);
  });

  it('should get input signature multisig', async () => {
    // generate keys
    const [ring1, ring2] = createMultisigRings();
    const {mtx, coins} = await createSpendingTX(ring1, HNS);
    const coin = coins[0];

    const signedMTX = mtx.clone();
    signedMTX.view = mtx.view;

    // sign with first key.
    const signed = signedMTX.sign(ring1);
    assert(signed, 'Could not sign transaction.');

    let sig;

    {
      const input = signedMTX.inputs[0];
      const signScript = input.witness;
      const vector = signScript.toStack();

      // get signatures from stack
      const [sig1, sig2] = [vector.get(1), vector.get(2)];
      sig = sig1.length > 0 ? sig1 : sig2;
    }

    // choose correct signature
    const sig2 = mtx.getInputSignature(0, coin, ring1);

    assert.bufferEqual(sig2, sig, 'Signature is not correct.');
    assert.strictEqual(mtx.checkSignature(0, coin, ring1, sig), true);
    assert.strictEqual(mtx.checkSignature(0, coin, ring2, sig), false);

    mtx.scriptInput(0, coin, ring1);

    const applied = mtx.applySignature(0, coin, ring1, sig);
    assert.strictEqual(applied, true);

    sig = null;

    {
      const input = mtx.inputs[0];
      const signScript = input.witness;
      const vector = signScript.toStack();

      // get signatures from stack
      const [sig1, sig2] = [vector.get(1), vector.get(2)];
      sig = sig1.length > 0 ? sig1 : sig2;
    }

    assert.bufferEqual(sig, sig2);
  });

  it('should get signatures for rings', async () => {
    // NOTE: should we accept multiple rings
    // and arrays of signatures ?
    // It will results signatures to be inside array
    const [ring1, ring2] = createMultisigRings();
    const {mtx} = await createSpendingTX(ring1, HNS, 2);

    const sigs1 = mtx.getSignatures([ring1, ring1]);
    const sigs2 = mtx.getSignatures([ring2, ring2]);
    const rings1 = [ring1, ring1];
    const rings2 = [ring2, ring2];

    mtx.applySignatures(rings1, sigs1, true);
    mtx.applySignatures(rings2, sigs2, true);

    assert.strictEqual(mtx.checkSignatures(rings1, sigs1), 2);
    assert.strictEqual(mtx.checkSignatures(rings2, sigs2), 2);

    assert.strictEqual(mtx.checkSignatures([ring1, ring2], sigs1), 1);
    assert.strictEqual(mtx.checkSignatures([ring1, ring2], sigs2), 1);

    assert.strictEqual(mtx.checkSignatures(rings2, sigs1), 0);
    assert.strictEqual(mtx.checkSignatures(rings1, sigs2), 0);

    assert.strictEqual(mtx.isSigned(), true, 'MTX is not signed.');
    assert.strictEqual(mtx.verify(), true, 'MTX verification failed.');
  });

  it('should empty inputs for transaction', async () => {
    const [ring1, ring2] = createMultisigRings();
    const {mtx} = await createSpendingTX(ring1, HNS, 2);

    mtx.sign([ring1, ring2]);

    mtx.emptyInputs();

    for (const input of mtx.inputs) {
      const {witness} = input;

      assert.strictEqual(witness.length, 0, 'Witness is not empty.');
    }
  });
});

/**
 * Create multisig 2-of-2 keyrings
 * @ignore
 * @returns {[KeyRing, KeyRing]}
 */

function createMultisigRings() {
  const key1 = KeyRing.generate();
  const key2 = KeyRing.generate();

  const [pub1, pub2] = [key1.publicKey, key2.publicKey];

  const script = Script.fromMultisig(2, 2, [pub1, pub2]);
  key1.script = script;
  key2.script = script;

  return [key1, key2];
}

/**
 * Create p2pkh keyring
 * @ignore
 * @returns {KeyRing}
 */

function createRing() {
  const key = KeyRing.generate();
  return key;
}

/*
 * Create spending transaction
 * send from ourselves to ourselves.
 * total value will be value * coins
 * @ignore
 * @param {KeyRing} ring
 * @param {Number} value
 * @param {Number} n - number of inputs to use
 * @return {MultisigMTX}
 */

async function createSpendingTX(ring, value, n = 1) {
  const address = ring.getAddress();
  const coins = [];
  const mtx = new MultisigMTX();

  for (let i = 0; i < n; i++) {
    const fundTX = utils.createFundTX(address, value);
    const coin = Coin.fromTX(fundTX, 0, -1);

    coins.push(coin);
  }

  // send money to ourselves.
  mtx.addOutput({
    address: address,
    value: value * n
  });

  // fund tx
  await mtx.fund(coins, {
    changeAddress: address,
    rate: 0
  });

  return { mtx, coins };
}

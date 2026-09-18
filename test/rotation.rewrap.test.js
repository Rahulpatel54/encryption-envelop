'use strict';

/**
 * Unit-level test of the KEK_REWRAP field logic in isolation from BullMQ/DB,
 * covering: rewrap changes only wrapping metadata, and idempotent re-run
 * (already-migrated envelope is skipped) leaves data byte-identical.
 */

const envelopeMod = require('../app/service/encryption/crypto/envelope');
const aesGcm = require('../app/service/encryption/crypto/aes-gcm');

function makeKeyService(kekByVersion) {
  return {
    async unwrapKey(wrapped, version) {
      const kek = kekByVersion.get(version);
      return aesGcm.decrypt(kek, { iv: wrapped.wrapIv, ciphertext: wrapped.wrappedDek, tag: wrapped.wrapTag });
    },
    async wrapKey(dek, version) {
      const kek = kekByVersion.get(version);
      const { iv, ciphertext, tag } = aesGcm.encrypt(kek, dek);
      return { wrappedDek: ciphertext, wrapIv: iv, wrapTag: tag, providerKeyId: null };
    },
  };
}

// Re-implemented here at the field level (mirrors worker's rewrapRecordFields)
// so we can test it without a live Sequelize record/transaction.
async function rewrapField(serialized, keyService, toVersion) {
  const env = envelopeMod.deserializeEnvelope(serialized);
  if (env.kekVersion === toVersion) return serialized; // idempotent skip
  const dek = await keyService.unwrapKey(
    { wrappedDek: env.wrappedDek, wrapIv: env.wrapIv, wrapTag: env.wrapTag },
    env.kekVersion
  );
  const { wrappedDek, wrapIv, wrapTag, providerKeyId } = await keyService.wrapKey(dek, toVersion);
  const newEnv = envelopeMod.buildEnvelope({
    kekProvider: env.kekProvider,
    kekVersion: toVersion,
    providerKeyId,
    wrappedDek,
    wrapIv,
    wrapTag,
    iv: env.iv,
    tag: env.tag,
    ciphertext: env.ciphertext,
  });
  return envelopeMod.serializeEnvelope(newEnv);
}

describe('KEK_REWRAP field logic', () => {
  test('rewrap changes kekVersion/wrapping but not ciphertext/iv/tag', async () => {
    const kekByVersion = new Map([
      [1, aesGcm.generateKey()],
      [2, aesGcm.generateKey()],
    ]);
    const keyService = makeKeyService(kekByVersion);

    const dek = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(dek, Buffer.from('unchanged payload'));
    const wrappedV1 = await keyService.wrapKey(dek, 1);
    const originalSerialized = envelopeMod.serializeEnvelope(
      envelopeMod.buildEnvelope({ kekProvider: 'env', kekVersion: 1, ...wrappedV1, iv, tag, ciphertext })
    );

    const rewrapped = await rewrapField(originalSerialized, keyService, 2);
    const rewrappedEnv = envelopeMod.deserializeEnvelope(rewrapped);
    const originalEnv = envelopeMod.deserializeEnvelope(originalSerialized);

    expect(rewrappedEnv.kekVersion).toBe(2);
    expect(rewrappedEnv.ciphertext.equals(originalEnv.ciphertext)).toBe(true);
    expect(rewrappedEnv.iv.equals(originalEnv.iv)).toBe(true);
    expect(rewrappedEnv.tag.equals(originalEnv.tag)).toBe(true);
    expect(rewrappedEnv.wrappedDek.equals(originalEnv.wrappedDek)).toBe(false);
  });

  test('idempotent retry: rewrapping an already-migrated envelope is a no-op', async () => {
    const kekByVersion = new Map([
      [1, aesGcm.generateKey()],
      [2, aesGcm.generateKey()],
    ]);
    const keyService = makeKeyService(kekByVersion);
    const dek = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(dek, Buffer.from('payload'));
    const wrappedV1 = await keyService.wrapKey(dek, 1);
    const serialized = envelopeMod.serializeEnvelope(
      envelopeMod.buildEnvelope({ kekProvider: 'env', kekVersion: 1, ...wrappedV1, iv, tag, ciphertext })
    );

    const once = await rewrapField(serialized, keyService, 2);
    const twice = await rewrapField(once, keyService, 2); // simulates a retried job re-processing this record
    expect(twice).toBe(once); // exact same string — proven no-op, not just equivalent
  });
});
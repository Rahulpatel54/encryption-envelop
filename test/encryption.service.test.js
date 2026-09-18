'use strict';

const { EncryptionService } = require('../app/service/encryption/encryption.service');

/** Minimal fake KeyService/provider for isolated unit testing. */
function makeFakeKeyService({ activeVersion = 1 } = {}) {
  const crypto = require('crypto');
  const aesGcm = require('../app/service/encryption/crypto/aes-gcm');
  const kekStore = new Map([[activeVersion, aesGcm.generateKey()]]);

  return {
    kekStore,
    async getActiveKey() {
      return { version: activeVersion, provider: 'env', providerKeyId: null };
    },
    async wrapKey(dek, version) {
      const kek = kekStore.get(version);
      if (!kek) throw new Error('unknown kek version');
      const { iv, ciphertext, tag } = aesGcm.encrypt(kek, dek);
      return { wrappedDek: ciphertext, wrapIv: iv, wrapTag: tag, providerKeyId: null };
    },
    async unwrapKey(wrapped, version) {
      const kek = kekStore.get(version);
      if (!kek) throw new Error('unknown kek version');
      return aesGcm.decrypt(kek, { iv: wrapped.wrapIv, ciphertext: wrapped.wrappedDek, tag: wrapped.wrapTag });
    },
  };
}

describe('EncryptionService', () => {
  test('encrypt/decrypt round-trip', async () => {
    const svc = new EncryptionService({ keyService: makeFakeKeyService() });
    const env = await svc.encrypt('super secret value');
    const plaintext = await svc.decryptToString(env);
    expect(plaintext).toBe('super secret value');
  });

  test('serialized envelope is versioned and does not contain raw plaintext', async () => {
    const svc = new EncryptionService({ keyService: makeFakeKeyService() });
    const env = await svc.encrypt('do-not-leak-me');
    expect(env.startsWith('v1:')).toBe(true);
    expect(env).not.toContain('do-not-leak-me');
  });

  test('tampered envelope ciphertext fails decryption', async () => {
    const svc = new EncryptionService({ keyService: makeFakeKeyService() });
    const env = await svc.encrypt('hello world');
    const { deserializeEnvelope, buildEnvelope, serializeEnvelope } = require('../app/service/encryption/crypto/envelope');
    const parsed = deserializeEnvelope(env);
    parsed.ciphertext[0] ^= 0xff;
    const tampered = serializeEnvelope(buildEnvelope(parsed));
    await expect(svc.decrypt(tampered)).rejects.toThrow();
  });

  test('decrypting with a KeyService that lacks the wrapping KEK version fails', async () => {
    const keyService = makeFakeKeyService();
    const svc = new EncryptionService({ keyService });
    const env = await svc.encrypt('hello');
    keyService.kekStore.clear(); // simulate KEK no longer available
    await expect(svc.decrypt(env)).rejects.toThrow();
  });

  test('AAD binding: decrypting with a different AAD than was used to encrypt fails', async () => {
    const svc = new EncryptionService({ keyService: makeFakeKeyService() });
    const env = await svc.encrypt('bound value', { aad: 'record-1' });
    await expect(svc.decrypt(env, { aad: 'record-2' })).rejects.toThrow();
    const ok = await svc.decrypt(env, { aad: 'record-1' });
    expect(ok.toString('utf8')).toBe('bound value');
  });
});
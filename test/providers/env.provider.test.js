'use strict';

const crypto = require('crypto');

describe('EnvKeyProvider', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    process.env.ENCRYPTION_KEY_PROVIDER = 'env';
    process.env.ENCRYPTION_KEK_VERSION = '2';
    process.env.ENCRYPTION_KEK = crypto.randomBytes(32).toString('base64');
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  test('wraps and unwraps a DEK under the active version', async () => {
    const { EnvKeyProvider } = require('../../app/service/encryption/providers/env.provider');
    const provider = new EnvKeyProvider();
    const dek = crypto.randomBytes(32);

    const { version } = await provider.getActiveKey();
    expect(version).toBe(2);

    const wrapped = await provider.wrapKey(dek, version);
    const unwrapped = await provider.unwrapKey(wrapped, version);
    expect(unwrapped.equals(dek)).toBe(true);
  });

  test('supports legacy KEK versions for decrypting old data (KEK versioning)', async () => {
    const legacyKey = crypto.randomBytes(32).toString('base64');
    const { EnvKeyProvider } = require('../../app/service/encryption/providers/env.provider');
    const provider = new EnvKeyProvider({ legacyKeys: { 1: legacyKey } });

    const dek = crypto.randomBytes(32);
    const wrappedUnderV1 = await provider.wrapKey(dek, 1);
    const unwrapped = await provider.unwrapKey(wrappedUnderV1, 1);
    expect(unwrapped.equals(dek)).toBe(true);
  });

  test('throws when unwrapping under an unknown version', async () => {
    const { EnvKeyProvider } = require('../../app/service/encryption/providers/env.provider');
    const provider = new EnvKeyProvider();
    const dek = crypto.randomBytes(32);
    const wrapped = await provider.wrapKey(dek, 2);
    await expect(provider.unwrapKey(wrapped, 99)).rejects.toThrow();
  });
});
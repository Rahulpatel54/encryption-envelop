'use strict';

/**
 * Centralized, validated configuration for the encryption/key-management module.
 * Fails fast at load time (or first access) if required env vars are missing/malformed.
 */

const REQUIRED_BASE64_32_BYTE = (name, value) => {
  if (!value) {
    throw new Error(`[encryption.config] Missing required env var: ${name}`);
  }
  let buf;
  try {
    buf = Buffer.from(value, 'base64');
  } catch (err) {
    throw new Error(`[encryption.config] ${name} is not valid base64`);
  }
  if (buf.length !== 32) {
    throw new Error(
      `[encryption.config] ${name} must decode to exactly 32 bytes (256 bits), got ${buf.length}`
    );
  }
  return buf;
};

const toInt = (value, fallback) => {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`[encryption.config] Invalid positive integer value: "${value}"`);
  }
  return n;
};

let cachedConfig = null;

/**
 * Builds and validates config from process.env. Throws on invalid/missing config.
 * Cached after first successful call; call resetEncryptionConfigCache() in tests.
 */
function getEncryptionConfig() {
  if (cachedConfig) return cachedConfig;

  const provider = (process.env.ENCRYPTION_KEY_PROVIDER || 'env').trim();
  if (!['env', 'kms'].includes(provider)) {
    throw new Error(
      `[encryption.config] ENCRYPTION_KEY_PROVIDER must be "env" or "kms", got "${provider}"`
    );
  }

  const kekVersion = toInt(process.env.ENCRYPTION_KEK_VERSION, undefined);
  if (!kekVersion) {
    throw new Error('[encryption.config] Missing required env var: ENCRYPTION_KEK_VERSION');
  }

  const config = {
    provider,
    kekVersion,
    rotation: {
      batchSize: toInt(process.env.ENCRYPTION_ROTATION_BATCH_SIZE, 500),
      attempts: toInt(process.env.ENCRYPTION_ROTATION_ATTEMPTS, 3),
      queueName: process.env.ENCRYPTION_ROTATION_QUEUE_NAME || 'encryption-rotation',
    },
    redis: {
      url: process.env.REDIS_URL || 'redis://127.0.0.1:6379',
    },
  };

  if (provider === 'env') {
    // Validate the KEK is present and well-formed. We deliberately do NOT cache
    // the decoded key material itself here — that decoding happens inside
    // EnvKeyProvider, which owns the key's lifecycle in memory.
    REQUIRED_BASE64_32_BYTE('ENCRYPTION_KEK', process.env.ENCRYPTION_KEK);
  }

  if (provider === 'kms') {
    // KMS provider requires a key/provider identifier; the actual vendor SDK
    // wiring is left to the caller (see providers/kms.provider.js).
    if (!process.env.ENCRYPTION_KMS_KEY_ID) {
      throw new Error(
        '[encryption.config] ENCRYPTION_KMS_KEY_ID is required when ENCRYPTION_KEY_PROVIDER=kms'
      );
    }
    config.kms = {
      keyId: process.env.ENCRYPTION_KMS_KEY_ID,
    };
  }

  cachedConfig = config;
  return config;
}

function resetEncryptionConfigCache() {
  cachedConfig = null;
}

module.exports = { getEncryptionConfig, resetEncryptionConfigCache };
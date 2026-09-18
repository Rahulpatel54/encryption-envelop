'use strict';

const { KeyProvider } = require('./key.provider');
const aesGcm = require('../crypto/aes-gcm');
const { getEncryptionConfig } = require('../../../config/encryption.config');

/**
 * EnvKeyProvider: KEK material sourced from environment variables.
 *
 * Only the *current* KEK version's key material is required to be present
 * in the environment. Older versions needed for decrypting historical data
 * are supplied via `legacyKeys` (version -> base64 key), typically loaded
 * from a secrets manager or a previous .env at deploy time. This keeps the
 * provider fully functional for KEK versioning without ever persisting
 * plaintext key material to PostgreSQL.
 *
 * wrapKey/unwrapKey wrap the DEK using AES-256-GCM with the KEK as the
 * encryption key — i.e. a nested envelope, matching the module's aes-gcm
 * primitives rather than a separate key-wrap algorithm.
 */
class EnvKeyProvider extends KeyProvider {
  /**
   * @param {object} [opts]
   * @param {Record<number, string>} [opts.legacyKeys] version -> base64-encoded 32-byte key
   */
  constructor(opts = {}) {
    super();
    const config = getEncryptionConfig();
    this._activeVersion = config.kekVersion;

    this._keysByVersion = new Map();
    this._keysByVersion.set(
      config.kekVersion,
      Buffer.from(process.env.ENCRYPTION_KEK, 'base64')
    );

    for (const [versionStr, base64Key] of Object.entries(opts.legacyKeys || {})) {
      const version = Number.parseInt(versionStr, 10);
      const buf = Buffer.from(base64Key, 'base64');
      if (buf.length !== 32) {
        throw new Error(`EnvKeyProvider: legacy key for version ${version} is not 32 bytes`);
      }
      this._keysByVersion.set(version, buf);
    }
  }

  get name() {
    return 'env';
  }

  async getActiveKey() {
    return { version: this._activeVersion, providerKeyId: null };
  }

  async getKey(version) {
    if (!this._keysByVersion.has(version)) {
      throw new Error(
        `EnvKeyProvider: no key material available for KEK version ${version}. ` +
          'Supply it via legacyKeys to decrypt data wrapped under that version.'
      );
    }
    return { version, providerKeyId: null };
  }

  async wrapKey(dek, version) {
    const kek = this._requireKekMaterial(version);
    const { iv, ciphertext, tag } = aesGcm.encrypt(kek, dek);
    return { wrappedDek: ciphertext, wrapIv: iv, wrapTag: tag, providerKeyId: null };
  }

  async unwrapKey(wrapped, version) {
    const kek = this._requireKekMaterial(version);
    return aesGcm.decrypt(kek, {
      iv: wrapped.wrapIv,
      ciphertext: wrapped.wrappedDek,
      tag: wrapped.wrapTag,
    });
  }

  _requireKekMaterial(version) {
    const kek = this._keysByVersion.get(version);
    if (!kek) {
      throw new Error(`EnvKeyProvider: missing KEK material for version ${version}`);
    }
    return kek;
  }
}

module.exports = { EnvKeyProvider };
'use strict';

const { getEncryptionConfig } = require('../../config/encryption.config');
const { EnvKeyProvider } = require('./providers/env.provider');
const { KmsKeyProvider } = require('./providers/kms.provider');

/**
 * KeyService owns:
 *  - selecting/instantiating the active KeyProvider based on config
 *  - the encryption_keys metadata table (version lifecycle: PENDING -> ACTIVE -> RETIRED)
 *
 * It never touches plaintext KEK/DEK material beyond delegating to the
 * provider — only metadata is persisted to PostgreSQL.
 */

const KEY_STATUS = Object.freeze({
  PENDING: 'PENDING',
  ACTIVE: 'ACTIVE',
  RETIRED: 'RETIRED',
});

class KeyService {
  /**
   * @param {object} deps
   * @param {import('../../models/security/encryption.key.model')} deps.EncryptionKeyModel
   * @param {import('./providers/key.provider').KeyProvider} [deps.provider] override for tests
   */
  constructor({ EncryptionKeyModel, provider } = {}) {
    this.EncryptionKeyModel = EncryptionKeyModel;
    this.provider = provider || KeyService._buildProviderFromConfig();
  }

  static _buildProviderFromConfig() {
    const config = getEncryptionConfig();
    if (config.provider === 'kms') return new KmsKeyProvider();
    return new EnvKeyProvider();
  }

  /** @returns {Promise<{ version: number, providerKeyId: string|null, provider: string }>} */
  async getActiveKey() {
    const { version, providerKeyId } = await this.provider.getActiveKey();
    return { version, providerKeyId, provider: this.provider.name };
  }

  /** @param {number} version */
  async getKey(version) {
    const { providerKeyId } = await this.provider.getKey(version);
    return { version, providerKeyId, provider: this.provider.name };
  }

  async wrapKey(dek, version) {
    return this.provider.wrapKey(dek, version);
  }

  async unwrapKey(wrapped, version) {
    return this.provider.unwrapKey(wrapped, version);
  }

  /**
   * Records a new key version in metadata (does not create key material —
   * that's provisioned in the provider/vendor KMS out of band, and for the
   * env provider comes from a new ENCRYPTION_KEK[_version] deploy).
   */
  async createKeyVersion({ version, providerKeyId = null, metadata = {} }) {
    return this.EncryptionKeyModel.create({
      provider: this.provider.name,
      key_type: 'KEK',
      version,
      provider_key_id: providerKeyId,
      status: KEY_STATUS.PENDING,
      metadata,
    });
  }

  /** Marks a key version ACTIVE. Does not deactivate other versions automatically. */
  async activateKey(version) {
    const [, [row]] = await this.EncryptionKeyModel.update(
      { status: KEY_STATUS.ACTIVE, activated_at: new Date() },
      { where: { version, key_type: 'KEK' }, returning: true }
    );
    if (!row) throw new Error(`KeyService: no KEK metadata row for version ${version}`);
    return row;
  }

  /**
   * Marks a key version RETIRED. Callers MUST confirm (e.g. via rotation
   * completion + audit) that no stored data still depends on this version
   * before retiring it — this method performs no such check itself, by
   * design, since that determination is application-specific.
   */
  async retireKey(version) {
    const [, [row]] = await this.EncryptionKeyModel.update(
      { status: KEY_STATUS.RETIRED, retired_at: new Date() },
      { where: { version, key_type: 'KEK' }, returning: true }
    );
    if (!row) throw new Error(`KeyService: no KEK metadata row for version ${version}`);
    return row;
  }
}

module.exports = { KeyService, KEY_STATUS };
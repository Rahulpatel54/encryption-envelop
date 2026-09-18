'use strict';

const aesGcm = require('./crypto/aes-gcm');
const { getEncryptionConfig } = require('../../config/encryption.config');
const { EnvKeyProvider } = require('./providers/env.provider');
const { KmsKeyProvider } = require('./providers/kms.provider');

/**
 * KeyService owns:
 *  - selecting/instantiating the active KEK provider (env/kms) based on config
 *  - the full lifecycle of Data Encryption Keys (DEKs), stored wrapped in the
 *    `encryption_keys` table (key_type = 'DEK'): generate -> PENDING,
 *    activate -> ACTIVE (retiring whatever was ACTIVE before), RETIRED forever
 *    kept for disaster recovery / late migrations / compliance retention.
 *
 * KEK (Master Key) itself is NEVER stored — only in env/KMS, accessed via
 * `this.provider`. Only the *wrapped* DEK bytes ever touch PostgreSQL.
 *
 * The active DEK is cached in memory after first use (mirroring how
 * EnvKeyProvider caches the KEK itself) so encrypt() doesn't hit the DB and
 * re-unwrap on every single call. The cached Buffer is considered owned by
 * this service — callers must never scrub/mutate it; see encryption.service.js.
 */

const KEY_STATUS = Object.freeze({
  PENDING: 'PENDING',
  ACTIVE: 'ACTIVE',
  RETIRED: 'RETIRED',
});

function b64(buf) {
  return buf.toString('base64');
}
function unb64(str) {
  return Buffer.from(str, 'base64');
}

class KeyService {
  /**
   * @param {object} deps
   * @param {import('../../models/security/encryption.key.model')} deps.EncryptionKeyModel
   * @param {import('./providers/key.provider').KeyProvider} [deps.provider] override for tests
   */
  constructor({ EncryptionKeyModel, provider } = {}) {
    this.EncryptionKeyModel = EncryptionKeyModel;
    this.provider = provider || KeyService._buildProviderFromConfig();
    this._activeDekCache = null; // { version, dek } — see class doc above
  }

  static _buildProviderFromConfig() {
    const config = getEncryptionConfig();
    if (config.provider === 'kms') return new KmsKeyProvider();
    return new EnvKeyProvider();
  }

  // ---- KEK-facing info (unchanged shape; used by /test/active-key etc) ----

  /** @returns {Promise<{ version: number, providerKeyId: string|null, provider: string }>} */
  async getActiveKey() {
    const { version, providerKeyId } = await this.provider.getActiveKey();
    return { version, providerKeyId, provider: this.provider.name };
  }

  // ---- DEK lifecycle ----

  /**
   * Returns the currently ACTIVE DEK, unwrapped and cached in memory.
   * Bootstraps DEK v1 automatically on a fresh install (no ACTIVE row yet).
   * @returns {Promise<{ version: number, dek: Buffer }>}
   */
  async getActiveDek() {
    if (this._activeDekCache) return this._activeDekCache;

    let row = await this.EncryptionKeyModel.findOne({
      where: { key_type: 'DEK', status: KEY_STATUS.ACTIVE },
    });

    if (!row) {
      row = await this._bootstrapFirstDek();
    }

    const result = await this.getDek(row.version);
    this._activeDekCache = result;
    return result;
  }

  /**
   * Fetches and unwraps a specific DEK version, regardless of its status
   * (ACTIVE, PENDING mid-rotation, or RETIRED — needed to decrypt old data).
   * @param {number} version
   * @returns {Promise<{ version: number, dek: Buffer }>}
   */
  async getDek(version) {
    if (this._activeDekCache && this._activeDekCache.version === version) {
      return this._activeDekCache;
    }
    const row = await this.EncryptionKeyModel.findOne({ where: { key_type: 'DEK', version } });
    if (!row) {
      throw new Error(`KeyService: no DEK metadata row for version ${version}`);
    }
    const config = getEncryptionConfig();
    const dek = await this.provider.unwrapKey(
      { wrappedDek: unb64(row.wrapped_dek), wrapIv: unb64(row.wrap_iv), wrapTag: unb64(row.wrap_tag) },
      config.kekVersion
    );
    return { version, dek };
  }

  /**
   * Phase 1: generates a brand-new random DEK, wraps it under the active
   * KEK, and persists it as PENDING. Does not activate it — new writes keep
   * using the current ACTIVE DEK until the rotation worker has migrated
   * existing records and Phase 3 explicitly activates this version.
   * @returns {Promise<{ version: number }>}
   */
  async generateDek() {
    const config = getEncryptionConfig();
    const dek = aesGcm.generateKey();
    try {
      const { wrappedDek, wrapIv, wrapTag, providerKeyId } = await this.provider.wrapKey(dek, config.kekVersion);
      const maxVersion = await this.EncryptionKeyModel.max('version', { where: { key_type: 'DEK' } });
      const nextVersion = (Number(maxVersion) || 0) + 1;

      await this.EncryptionKeyModel.create({
        provider: this.provider.name,
        key_type: 'DEK',
        version: nextVersion,
        provider_key_id: providerKeyId || null,
        wrapped_dek: b64(wrappedDek),
        wrap_iv: b64(wrapIv),
        wrap_tag: b64(wrapTag),
        status: KEY_STATUS.PENDING,
      });

      return { version: nextVersion };
    } finally {
      // safe to scrub: this is a local, one-off buffer created purely to be
      // wrapped and persisted above — never the shared/cached active DEK.
      dek.fill(0);
    }
  }

  /**
   * Phase 3: activates a DEK version (marks it ACTIVE) and retires whatever
   * was ACTIVE before it. The retired version's row is kept — never
   * deleted — for disaster recovery, late migrations, and compliance
   * retention, exactly as required.
   * @param {number} version
   */
  async activateDek(version) {
    const sequelize = this.EncryptionKeyModel.sequelize;
    const updated = await sequelize.transaction(async (t) => {
      await this.EncryptionKeyModel.update(
        { status: KEY_STATUS.RETIRED, retired_at: new Date() },
        { where: { key_type: 'DEK', status: KEY_STATUS.ACTIVE }, transaction: t }
      );
      const [, rows] = await this.EncryptionKeyModel.update(
        { status: KEY_STATUS.ACTIVE, activated_at: new Date() },
        { where: { key_type: 'DEK', version }, returning: true, transaction: t }
      );
      if (!rows || !rows[0]) {
        throw new Error(`KeyService: no DEK metadata row for version ${version}`);
      }
      return rows[0];
    });

    this._activeDekCache = null; // force re-fetch/unwrap of the new active DEK next time
    return updated;
  }

  async _bootstrapFirstDek() {
    const { version } = await this.generateDek();
    return this.activateDek(version);
  }
}

module.exports = { KeyService, KEY_STATUS };
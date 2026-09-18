'use strict';

/**
 * KeyProvider interface. EncryptionService/KeyService depend only on this
 * shape — never on EnvKeyProvider or KmsKeyProvider directly.
 *
 * All methods are async to accommodate providers that call out to a network
 * KMS/HSM.
 */
class KeyProvider {
  /** @returns {Promise<{ version: number, providerKeyId: string|null }>} */
  async getActiveKey() {
    throw new Error('KeyProvider.getActiveKey() not implemented');
  }

  /**
   * @param {number} version
   * @returns {Promise<{ version: number, providerKeyId: string|null }>}
   */
  // eslint-disable-next-line no-unused-vars
  async getKey(version) {
    throw new Error('KeyProvider.getKey() not implemented');
  }

  /**
   * Wraps (encrypts) a raw DEK using the KEK identified by `version`.
   * @param {Buffer} dek
   * @param {number} version
   * @returns {Promise<{ wrappedDek: Buffer, wrapIv: Buffer, wrapTag: Buffer, providerKeyId: string|null }>}
   */
  // eslint-disable-next-line no-unused-vars
  async wrapKey(dek, version) {
    throw new Error('KeyProvider.wrapKey() not implemented');
  }

  /**
   * Unwraps (decrypts) a wrapped DEK using the KEK identified by `version`.
   * @param {{ wrappedDek: Buffer, wrapIv: Buffer, wrapTag: Buffer }} wrapped
   * @param {number} version
   * @returns {Promise<Buffer>} raw DEK
   */
  // eslint-disable-next-line no-unused-vars
  async unwrapKey(wrapped, version) {
    throw new Error('KeyProvider.unwrapKey() not implemented');
  }

  /** Provider identifier used in envelopes/metadata, e.g. 'env' | 'kms'. */
  get name() {
    throw new Error('KeyProvider.name not implemented');
  }
}

module.exports = { KeyProvider };
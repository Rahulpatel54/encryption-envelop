'use strict';

const { KeyProvider } = require('./key.provider');
const { getEncryptionConfig } = require('../../../config/encryption.config');

/**
 * KmsKeyProvider: adapter for a cloud KMS/HSM (AWS KMS, GCP Cloud KMS, etc).
 *
 * This module deliberately does NOT depend on any vendor SDK. Instead, it
 * accepts an injected `kmsClient` conforming to a tiny interface:
 *
 *   kmsClient.encrypt({ keyId, plaintext }) -> Promise<{ ciphertext: Buffer, providerKeyId?: string }>
 *   kmsClient.decrypt({ keyId, ciphertext }) -> Promise<{ plaintext: Buffer }>
 *
 * Most cloud KMS "Encrypt"/"Decrypt" APIs return an opaque ciphertext blob
 * and manage IV/tag internally, so wrapKey/unwrapKey here just pass the DEK
 * through to that API rather than re-implementing AES-GCM locally. This
 * keeps EncryptionService/KeyService completely unaware of which vendor is
 * behind the KEK.
 *
 * To activate: implement a small `kmsClient` using @aws-sdk/client-kms or
 * @google-cloud/kms in your application code, and construct this provider
 * with it. This file intentionally throws NotImplemented until that client
 * is wired in, per "do not add AWS/GCP SDKs unless genuinely required."
 */
class KmsKeyProvider extends KeyProvider {
  /**
   * @param {object} opts
   * @param {{ encrypt: Function, decrypt: Function }} [opts.kmsClient]
   * @param {Record<number, string>} [opts.keyIdsByVersion] version -> vendor key ID
   */
  constructor(opts = {}) {
    super();
    const config = getEncryptionConfig();
    this._activeVersion = config.kekVersion;
    this._kmsClient = opts.kmsClient || null;
    this._keyIdsByVersion = new Map(
      Object.entries(opts.keyIdsByVersion || { [config.kekVersion]: config.kms?.keyId })
        .filter(([, v]) => Boolean(v))
        .map(([version, keyId]) => [Number.parseInt(version, 10), keyId])
    );
  }

  get name() {
    return 'kms';
  }

  async getActiveKey() {
    return {
      version: this._activeVersion,
      providerKeyId: this._keyIdsByVersion.get(this._activeVersion) || null,
    };
  }

  async getKey(version) {
    const providerKeyId = this._keyIdsByVersion.get(version);
    if (!providerKeyId) {
      throw new Error(`KmsKeyProvider: no vendor key ID registered for version ${version}`);
    }
    return { version, providerKeyId };
  }

  async wrapKey(dek, version) {
    this._requireClient();
    const { providerKeyId } = await this.getKey(version);
    const { ciphertext } = await this._kmsClient.encrypt({ keyId: providerKeyId, plaintext: dek });
    // No local IV/tag: the vendor KMS owns authenticated encryption of the DEK.
    return {
      wrappedDek: ciphertext,
      wrapIv: Buffer.alloc(0),
      wrapTag: Buffer.alloc(0),
      providerKeyId,
    };
  }

  async unwrapKey(wrapped, version) {
    this._requireClient();
    const { providerKeyId } = await this.getKey(version);
    const { plaintext } = await this._kmsClient.decrypt({
      keyId: providerKeyId,
      ciphertext: wrapped.wrappedDek,
    });
    return plaintext;
  }

  _requireClient() {
    if (!this._kmsClient) {
      throw new Error(
        'KmsKeyProvider: no kmsClient configured. Inject an AWS KMS / GCP Cloud KMS ' +
          'client adapter (encrypt/decrypt) before use.'
      );
    }
  }
}

module.exports = { KmsKeyProvider };
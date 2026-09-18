'use strict';

const aesGcm = require('./crypto/aes-gcm');
const envelope = require('./crypto/envelope');

/**
 * EncryptionService: the only entry point application code should use for
 * turning plaintext into storable ciphertext and back. It has no knowledge
 * of PostgreSQL, HTTP, or BullMQ, and never leaks key material outward.
 *
 * Each encrypt() call generates a fresh random DEK, so every field/record
 * has its own independently-compromisable key — the KEK only ever wraps DEKs.
 */
class EncryptionService {
  /** @param {object} deps @param {import('./key.service').KeyService} deps.keyService */
  constructor({ keyService }) {
    this.keyService = keyService;
  }

  /**
   * @param {string|Buffer} plaintext
   * @param {object} [opts]
   * @param {Buffer|string} [opts.aad] additional authenticated data (e.g. record id) —
   *   must be supplied identically on decrypt.
   * @returns {Promise<string>} serialized, storable envelope string
   */
  async encrypt(plaintext, opts = {}) {
    const plaintextBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    const aad = opts.aad ? (Buffer.isBuffer(opts.aad) ? opts.aad : Buffer.from(String(opts.aad))) : undefined;

    const dek = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(dek, plaintextBuf, aad);

    const { version: kekVersion, provider: kekProvider, providerKeyId } =
      await this.keyService.getActiveKey();
    const { wrappedDek, wrapIv, wrapTag, providerKeyId: wrapProviderKeyId } =
      await this.keyService.wrapKey(dek, kekVersion);

    dek.fill(0); // best-effort scrub of the raw DEK from memory once wrapped

    const env = envelope.buildEnvelope({
      kekProvider,
      kekVersion,
      providerKeyId: wrapProviderKeyId || providerKeyId,
      wrappedDek,
      wrapIv,
      wrapTag,
      iv,
      tag,
      ciphertext,
    });
    return envelope.serializeEnvelope(env);
  }

  /**
   * @param {string} serializedEnvelope
   * @param {object} [opts]
   * @param {Buffer|string} [opts.aad] must match the aad used on encrypt()
   * @returns {Promise<Buffer>} plaintext buffer (caller decides utf8 vs binary)
   */
  async decrypt(serializedEnvelope, opts = {}) {
    const aad = opts.aad ? (Buffer.isBuffer(opts.aad) ? opts.aad : Buffer.from(String(opts.aad))) : undefined;
    const env = envelope.deserializeEnvelope(serializedEnvelope);

    const dek = await this.keyService.unwrapKey(
      { wrappedDek: env.wrappedDek, wrapIv: env.wrapIv, wrapTag: env.wrapTag },
      env.kekVersion
    );

    try {
      return aesGcm.decrypt(dek, { iv: env.iv, ciphertext: env.ciphertext, tag: env.tag }, aad);
    } finally {
      dek.fill(0);
    }
  }

  /** Convenience: decrypt and coerce to utf8 string. */
  async decryptToString(serializedEnvelope, opts = {}) {
    const buf = await this.decrypt(serializedEnvelope, opts);
    return buf.toString('utf8');
  }

  /** Inspects an envelope's metadata (kekVersion/provider) without decrypting. */
  inspect(serializedEnvelope) {
    const env = envelope.deserializeEnvelope(serializedEnvelope);
    return { v: env.v, alg: env.alg, kekProvider: env.kekProvider, kekVersion: env.kekVersion };
  }
}

module.exports = { EncryptionService };
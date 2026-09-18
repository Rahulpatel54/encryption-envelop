'use strict';

const aesGcm = require('./crypto/aes-gcm');
const envelope = require('./crypto/envelope');

/**
 * EncryptionService: the only entry point application code should use for
 * turning plaintext credentials into storable ciphertext and back. It has
 * no knowledge of PostgreSQL, HTTP, or BullMQ, and never leaks key material
 * outward.
 *
 * Every encrypt() call uses the current ACTIVE DEK (fetched/cached via
 * KeyService.getActiveDek()) — the DEK is shared across records, not
 * generated per record. The envelope only tags which DEK version was used
 * (`keyVersion`); the wrapped key material itself lives once in
 * `encryption_keys`, not copied into every row.
 *
 * IMPORTANT: DEK Buffers returned by keyService are cache-owned. Do not
 * fill()/mutate them here — doing so would corrupt the shared cache and
 * break every subsequent encrypt()/decrypt() call in the process.
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

    const { version: keyVersion, dek } = await this.keyService.getActiveDek();
    const { iv, ciphertext, tag } = aesGcm.encrypt(dek, plaintextBuf, aad);

    const env = envelope.buildEnvelope({ keyVersion, iv, tag, ciphertext });
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

    const { dek } = await this.keyService.getDek(env.keyVersion);
    return aesGcm.decrypt(dek, { iv: env.iv, ciphertext: env.ciphertext, tag: env.tag }, aad);
  }

  /** Convenience: decrypt and coerce to utf8 string. */
  async decryptToString(serializedEnvelope, opts = {}) {
    const buf = await this.decrypt(serializedEnvelope, opts);
    return buf.toString('utf8');
  }

  /** Inspects an envelope's metadata (which DEK version encrypted it) without decrypting. */
  inspect(serializedEnvelope) {
    const env = envelope.deserializeEnvelope(serializedEnvelope);
    return { v: env.v, alg: env.alg, keyVersion: env.keyVersion };
  }
}

module.exports = { EncryptionService };
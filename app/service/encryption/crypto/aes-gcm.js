'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96-bit IV, NIST-recommended for GCM
const AUTH_TAG_LENGTH_BYTES = 16;
const KEY_LENGTH_BYTES = 32; // 256-bit key

/**
 * Low-level AES-256-GCM primitives. No knowledge of envelopes, keys, providers,
 * or persistence lives here — just authenticated encryption on raw buffers.
 */

function assertKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH_BYTES) {
    throw new Error(`aes-gcm: key must be a ${KEY_LENGTH_BYTES}-byte Buffer`);
  }
}

function generateKey() {
  return crypto.randomBytes(KEY_LENGTH_BYTES);
}

function generateIv() {
  return crypto.randomBytes(IV_LENGTH_BYTES);
}

/**
 * @param {Buffer} key 32-byte key
 * @param {Buffer} plaintext
 * @param {Buffer} [aad] optional additional authenticated data
 * @returns {{ iv: Buffer, ciphertext: Buffer, tag: Buffer }}
 */
function encrypt(key, plaintext, aad) {
  assertKey(key);
  if (!Buffer.isBuffer(plaintext)) {
    throw new Error('aes-gcm: plaintext must be a Buffer');
  }
  const iv = generateIv();
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

/**
 * @param {Buffer} key 32-byte key
 * @param {{ iv: Buffer, ciphertext: Buffer, tag: Buffer }} parts
 * @param {Buffer} [aad]
 * @returns {Buffer} plaintext
 * @throws if the auth tag does not verify (tampered ciphertext or wrong key)
 */
function decrypt(key, { iv, ciphertext, tag }, aad) {
  assertKey(key);
  if (!Buffer.isBuffer(iv) || iv.length !== IV_LENGTH_BYTES) {
    throw new Error('aes-gcm: invalid iv');
  }
  if (!Buffer.isBuffer(tag) || tag.length !== AUTH_TAG_LENGTH_BYTES) {
    throw new Error('aes-gcm: invalid auth tag');
  }
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH_BYTES,
  });
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  // Throws (e.g. "Unsupported state or unable to authenticate data") on
  // tampering or wrong key — this is the authenticity guarantee.
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = {
  ALGORITHM,
  IV_LENGTH_BYTES,
  AUTH_TAG_LENGTH_BYTES,
  KEY_LENGTH_BYTES,
  generateKey,
  generateIv,
  encrypt,
  decrypt,
};
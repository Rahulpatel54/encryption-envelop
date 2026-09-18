'use strict';

/**
 * Versioned, self-describing envelope format for encrypted values.
 *
 * An envelope carries everything needed to decrypt itself except the KEK:
 *   - which provider/version wrapped the DEK
 *   - the wrapped DEK + its own auth data
 *   - the data ciphertext + IV + auth tag
 *
 * Serialized form: "v1:" + base64(JSON.stringify(envelope))
 * The version prefix lets future formats change shape without breaking
 * ability to detect and (with a migration) read old envelopes.
 */

const ENVELOPE_VERSION = 1;
const PREFIX = `v${ENVELOPE_VERSION}:`;

function b64(buf) {
  return buf.toString('base64');
}
function unb64(str) {
  return Buffer.from(str, 'base64');
}

/**
 * @param {object} parts
 * @param {string} parts.kekProvider   'env' | 'kms'
 * @param {number} parts.kekVersion    version of the KEK that wrapped the DEK
 * @param {Buffer} parts.wrappedDek
 * @param {Buffer} parts.wrapIv
 * @param {Buffer} parts.wrapTag
 * @param {Buffer} parts.iv
 * @param {Buffer} parts.tag
 * @param {Buffer} parts.ciphertext
 * @param {string} [parts.providerKeyId] opaque KMS key identifier, if applicable
 */
function buildEnvelope(parts) {
  return {
    v: ENVELOPE_VERSION,
    alg: 'AES-256-GCM',
    kekProvider: parts.kekProvider,
    kekVersion: parts.kekVersion,
    providerKeyId: parts.providerKeyId || null,
    wrappedDek: b64(parts.wrappedDek),
    wrapIv: b64(parts.wrapIv),
    wrapTag: b64(parts.wrapTag),
    iv: b64(parts.iv),
    tag: b64(parts.tag),
    ciphertext: b64(parts.ciphertext),
  };
}

/** Serializes an envelope object into the storable string form. */
function serializeEnvelope(envelope) {
  return PREFIX + Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64');
}

/** Parses a storable string back into an envelope object (with Buffers restored). */
function deserializeEnvelope(serialized) {
  if (typeof serialized !== 'string' || !serialized.startsWith(PREFIX)) {
    throw new Error('envelope: unrecognized or missing version prefix');
  }
  const json = Buffer.from(serialized.slice(PREFIX.length), 'base64').toString('utf8');
  let raw;
  try {
    raw = JSON.parse(json);
  } catch (err) {
    throw new Error('envelope: malformed payload');
  }
  if (raw.v !== ENVELOPE_VERSION) {
    // Future-proofing hook: dispatch to a version-specific reader here
    // once additional envelope versions exist.
    throw new Error(`envelope: unsupported envelope version ${raw.v}`);
  }
  return {
    v: raw.v,
    alg: raw.alg,
    kekProvider: raw.kekProvider,
    kekVersion: raw.kekVersion,
    providerKeyId: raw.providerKeyId || null,
    wrappedDek: unb64(raw.wrappedDek),
    wrapIv: unb64(raw.wrapIv),
    wrapTag: unb64(raw.wrapTag),
    iv: unb64(raw.iv),
    tag: unb64(raw.tag),
    ciphertext: unb64(raw.ciphertext),
  };
}

module.exports = { ENVELOPE_VERSION, buildEnvelope, serializeEnvelope, deserializeEnvelope };
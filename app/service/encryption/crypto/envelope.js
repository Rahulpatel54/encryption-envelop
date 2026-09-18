'use strict';

/**
 * Versioned, self-describing envelope format for encrypted values.
 *
 * ARCHITECTURE NOTE (shared versioned DEK model):
 * Earlier revisions of this module embedded a freshly-generated, wrapped DEK
 * inside every single envelope (one DEK per record). This version instead
 * assumes a *shared* DEK per version, stored once (wrapped) in the
 * `encryption_keys` table (see key.service.js). An envelope therefore only
 * needs to record which DEK *version* encrypted it — the wrapped key
 * material itself lives in exactly one place, not copied into every row.
 * This is what lets rotation ("Phase 2: Background Migration") work by
 * simply re-encrypting under a new version and updating that tag.
 *
 * Serialized form: "v2:" + base64(JSON.stringify(envelope))
 * The version prefix lets future formats change shape without breaking the
 * ability to detect (and, with a migration, read) old envelopes. v2 is
 * intentionally incompatible with the old per-record-DEK v1 format — mixing
 * them silently would be a correctness/security bug, so v1 payloads throw.
 */

const ENVELOPE_VERSION = 2;
const PREFIX = `v${ENVELOPE_VERSION}:`;

function b64(buf) {
  return buf.toString('base64');
}
function unb64(str) {
  return Buffer.from(str, 'base64');
}

/**
 * @param {object} parts
 * @param {number} parts.keyVersion  version of the shared DEK that encrypted this value
 * @param {Buffer} parts.iv
 * @param {Buffer} parts.tag
 * @param {Buffer} parts.ciphertext
 */
function buildEnvelope(parts) {
  return {
    v: ENVELOPE_VERSION,
    alg: 'AES-256-GCM',
    keyVersion: parts.keyVersion,
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
    throw new Error(`envelope: unsupported envelope version ${raw.v}`);
  }
  return {
    v: raw.v,
    alg: raw.alg,
    keyVersion: raw.keyVersion,
    iv: unb64(raw.iv),
    tag: unb64(raw.tag),
    ciphertext: unb64(raw.ciphertext),
  };
}

module.exports = { ENVELOPE_VERSION, buildEnvelope, serializeEnvelope, deserializeEnvelope };
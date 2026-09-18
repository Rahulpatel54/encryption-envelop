'use strict';

/**
 * Test-only controller for exercising EncryptionService/KeyService
 * directly over HTTP — encrypt arbitrary plaintext, decrypt an envelope,
 * roundtrip both in one call, inspect an envelope's metadata, or check
 * which KEK version/provider is currently active.
 *
 * No crypto lives here — this is a thin pass-through to the existing
 * service layer, same shape as encryption.rotation.controller.js.
 */

function buildEncryptionTestController({ encryptionService, keyService }) {
  return {
    /** POST /test/encrypt { plaintext, aad? } -> { envelope } */
    async encrypt(req, res) {
      try {
        const { plaintext, aad } = req.body || {};
        if (typeof plaintext !== 'string' || plaintext.length === 0) {
          return res.status(400).json({ error: 'plaintext (non-empty string) is required' });
        }
        const envelope = await encryptionService.encrypt(plaintext, aad ? { aad } : {});
        return res.status(200).json({ envelope });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },

    /** POST /test/decrypt { envelope, aad? } -> { plaintext } */
    async decrypt(req, res) {
      try {
        const { envelope, aad } = req.body || {};
        if (typeof envelope !== 'string' || envelope.length === 0) {
          return res.status(400).json({ error: 'envelope (non-empty string) is required' });
        }
        const plaintext = await encryptionService.decryptToString(envelope, aad ? { aad } : {});
        return res.status(200).json({ plaintext });
      } catch (err) {
        // Wrong key, tampered ciphertext, mismatched aad, or malformed
        // envelope all land here — deliberately vague, matching the "never
        // leak crypto internals" posture of the rest of this module.
        return res.status(400).json({ error: 'decryption failed', detail: err.message });
      }
    },

    /** POST /test/roundtrip { plaintext, aad? } -> { envelope, roundtripped, matched } */
    async roundtrip(req, res) {
      try {
        const { plaintext, aad } = req.body || {};
        if (typeof plaintext !== 'string' || plaintext.length === 0) {
          return res.status(400).json({ error: 'plaintext (non-empty string) is required' });
        }
        const opts = aad ? { aad } : {};
        const envelope = await encryptionService.encrypt(plaintext, opts);
        const roundtripped = await encryptionService.decryptToString(envelope, opts);
        return res.status(200).json({
          envelope,
          roundtripped,
          matched: roundtripped === plaintext,
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },

    /** POST /test/inspect { envelope } -> envelope metadata, no decryption */
    async inspect(req, res) {
      try {
        const { envelope } = req.body || {};
        if (typeof envelope !== 'string' || envelope.length === 0) {
          return res.status(400).json({ error: 'envelope (non-empty string) is required' });
        }
        return res.status(200).json(encryptionService.inspect(envelope));
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },

    /** GET /test/active-key -> which KEK version/provider is currently active */
    async activeKey(req, res) {
      try {
        return res.status(200).json(await keyService.getActiveKey());
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },
  };
}

module.exports = { buildEncryptionTestController };
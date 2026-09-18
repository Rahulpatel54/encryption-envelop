'use strict';

/**
 * Thin controller — validates request shape, delegates to RotationService,
 * and shapes responses. No crypto, no BullMQ, no Sequelize model logic here.
 *
 * Authorization integration point: this module deliberately does NOT
 * implement any authorization/permission check, since the real application
 * has its own Casbin-based layer. Wire it in as Express middleware on the
 * routes (see encryption.routes.js) — e.g. `casbinMiddleware('encryption:rotate')`
 * — before these handlers run. `req.user` (or equivalent) is expected to be
 * populated by that point; `created_by` below reads from it defensively.
 */

const ALLOWED_TYPES = ['KEK_REWRAP', 'DEK_ROTATION'];

function buildRotationController({ rotationService }) {
  return {
    async createRotation(req, res) {
      try {
        const { type, provider, target, fromVersion, toVersion } = req.body || {};

        if (!ALLOWED_TYPES.includes(type)) {
          return res.status(400).json({ error: `type must be one of ${ALLOWED_TYPES.join(', ')}` });
        }
        if (!provider || typeof provider !== 'string') {
          return res.status(400).json({ error: 'provider is required' });
        }
        if (!target || typeof target !== 'string') {
          return res.status(400).json({ error: 'target is required' });
        }

        const rotation = await rotationService.createRotation({
          type,
          provider,
          target,
          fromVersion,
          toVersion,
          createdBy: req.user?.id ?? null, // integration point for real auth/user context
        });

        return res.status(202).json(toPublicRotation(rotation));
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },

    async getRotation(req, res) {
      try {
        const rotation = await rotationService.getRotation(req.params.id);
        if (!rotation) return res.status(404).json({ error: 'rotation not found' });
        return res.status(200).json(toPublicRotation(rotation));
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },

    async cancelRotation(req, res) {
      try {
        const rotation = await rotationService.cancelRotation(req.params.id);
        return res.status(200).json(toPublicRotation(rotation));
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },
  };
}

/** Strips anything that isn't safe to return over the API (no key material exists here anyway, but stay explicit). */
function toPublicRotation(rotation) {
  const r = rotation.toJSON ? rotation.toJSON() : rotation;
  return {
    id: r.id,
    type: r.type,
    status: r.status,
    provider: r.provider,
    target: r.target,
    fromVersion: r.from_version,
    toVersion: r.to_version,
    totalRecords: r.total_records,
    processedRecords: r.processed_records,
    failedRecords: r.failed_records,
    startedAt: r.started_at,
    completedAt: r.completed_at,
    cancelledAt: r.cancelled_at,
    createdAt: r.created_at,
  };
}

module.exports = { buildRotationController };
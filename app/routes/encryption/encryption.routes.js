'use strict';

const express = require('express');
const { buildRotationController } = require('../../controllers/encryption/encryption.rotation.controller');

/**
 * @param {object} deps
 * @param {import('../../service/encryption/rotation.service').RotationService} deps.rotationService
 * @param {import('express').RequestHandler} [deps.authorize] plug in the real app's
 *   Casbin/authz middleware here per-route; left as a no-op pass-through by default.
 */
function buildEncryptionRoutes({ rotationService, authorize }) {
  const router = express.Router();
  const controller = buildRotationController({ rotationService });
  const authz = authorize || ((req, res, next) => next());

  router.post('/rotations', authz, controller.createRotation);
  router.get('/rotations/:id', authz, controller.getRotation);
  router.post('/rotations/:id/cancel', authz, controller.cancelRotation);

  return router;
}

module.exports = { buildEncryptionRoutes };
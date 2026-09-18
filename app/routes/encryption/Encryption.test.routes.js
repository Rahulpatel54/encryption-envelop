'use strict';

const express = require('express');
const router = express.Router();
const db = require('../../models');
const { buildEncryptionTestController } = require('../../controllers/encryption/encryption.test.controller');
const { buildWorkerTestController } = require('../../controllers/encryption/encryption.worker.test.controller');
const { KeyService } = require('../../service/encryption/key.service');
const { EncryptionService } = require('../../service/encryption/encryption.service');
const { RotationService } = require('../../service/encryption/rotation.service');
const rotationRegistry = require('../../service/encryption/rotation.registry');
const { registerInMemoryTestTarget } = require('../../service/encryption/testing/in-memory.target');
const rotationWorker = require('../../workers/encryption.rotation.worker');

/**
 * Test-only routes — no new dependencies, just express + the existing
 * service/worker layer. Split into two groups:
 *
 *   Crypto layer (encryption.test.controller.js):
 *     POST /encryption/test/encrypt      { plaintext, aad? } -> { envelope }
 *     POST /encryption/test/decrypt      { envelope, aad? }  -> { plaintext }
 *     POST /encryption/test/roundtrip    { plaintext, aad? } -> { envelope, roundtripped, matched }
 *     POST /encryption/test/inspect      { envelope }        -> envelope metadata (no decrypt)
 *     GET  /encryption/test/active-key   -> current KEK version/provider
 *
 *   Redis / BullMQ / worker pipeline (encryption.worker.test.controller.js):
 *     GET  /encryption/test/redis-ping        -> raw Redis connectivity check
 *     POST /encryption/test/bullmq-echo       -> isolated queue+worker round trip
 *     GET  /encryption/test/queue-health      -> real rotation queue job counts + worker.isRunning()
 *     POST /encryption/test/records/seed      { count?, text? } -> seed disposable encrypted rows
 *     GET  /encryption/test/records           -> list in-memory test rows (envelope metadata only)
 *     POST /encryption/test/records/reset     -> clear in-memory test rows
 *     POST /encryption/test/rotation          {} -> run a REAL DEK rotation through
 *                                                 RotationService -> BullMQ -> EncryptionRotationWorker
 *                                                 against the in-memory test rows
 *
 * SECURITY: these endpoints let a caller encrypt/decrypt arbitrary data and
 * kick off real rotation jobs on demand — great for testing, not something
 * to expose in production. Mounted only when NODE_ENV !== 'production'; if
 * you enable it anywhere shared, put casbinMiddleware in front of it the
 * same way encryption.routes.js does for the real rotation endpoints.
 *
 * NOTE: /test/rotation only completes if the EncryptionRotationWorker
 * process is actually running (see app/workers/encryption.rotation.worker.js
 * wiring notes) — use /test/queue-health to check workerRunning first.
 */
if (process.env.NODE_ENV !== 'production') {
  const keyService = new KeyService({ EncryptionKeyModel: db.EncryptionKey });
  const encryptionService = new EncryptionService({ keyService });
  const cryptoController = buildEncryptionTestController({ encryptionService, keyService });

  // Reuses the same queue name as the production RotationService, so jobs
  // created here are picked up by the same running worker.
  const rotationService = new RotationService({ RotationModel: db.EncryptionRotation, keyService });
  const testTargetName = registerInMemoryTestTarget(rotationRegistry);
  const workerController = buildWorkerTestController({
    encryptionService,
    rotationService,
    rotationWorker,
    testTargetName,
  });

  router.post('/test/encrypt', cryptoController.encrypt);
  router.post('/test/decrypt', cryptoController.decrypt);
  router.post('/test/roundtrip', cryptoController.roundtrip);
  router.post('/test/inspect', cryptoController.inspect);
  router.get('/test/active-key', cryptoController.activeKey);

  router.get('/test/redis-ping', workerController.redisPing);
  router.post('/test/bullmq-echo', workerController.bullmqEcho);
  router.get('/test/queue-health', workerController.queueHealth);
  router.post('/test/records/seed', workerController.seedRecords);
  router.get('/test/records', workerController.listRecords);
  router.post('/test/records/reset', workerController.resetRecords);
  router.post('/test/rotation', workerController.startTestRotation);
} else {
  router.use('/test', (req, res) => res.status(404).json({ error: 'not found' }));
}

module.exports = router;
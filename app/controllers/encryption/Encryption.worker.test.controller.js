'use strict';

const IORedis = require('ioredis');
const { getEncryptionConfig } = require('../../config/encryption.config');
const { testModel } = require('../../service/encryption/testing/in-memory.target');

/**
 * Test-only controller for exercising the Redis connection, the BullMQ
 * queue/worker plumbing, and the real EncryptionRotationWorker pipeline
 * end-to-end — separate from encryption.test.controller.js, which only
 * covers the crypto layer (encrypt/decrypt/inspect).
 *
 * @param {object} deps
 * @param {import('../../service/encryption/encryption.service').EncryptionService} deps.encryptionService
 * @param {import('../../service/encryption/rotation.service').RotationService} deps.rotationService
 * @param {{ isRunning: Function }} [deps.rotationWorker] the singleton worker, for status only
 * @param {string} deps.testTargetName registered name of the in-memory test target
 */
function buildWorkerTestController({ encryptionService, rotationService, rotationWorker, testTargetName }) {
  return {
    /** GET /test/redis-ping -> raw round trip to the configured Redis, independent of BullMQ */
    async redisPing(req, res) {
      const config = getEncryptionConfig();
      const client = new IORedis({
        host: config.redis.host,
        port: config.redis.port,
        db: config.redis.db,
        maxRetriesPerRequest: 1,
        lazyConnect: true,
      });
      const start = Date.now();
      try {
        await client.connect();
        const reply = await client.ping();
        return res.status(200).json({ reply, latencyMs: Date.now() - start, redis: config.redis });
      } catch (err) {
        return res.status(502).json({ error: 'redis ping failed', detail: err.message });
      } finally {
        client.disconnect();
      }
    },

    /**
     * POST /test/bullmq-echo { payload? }
     * Spins up an isolated queue+worker+queueEvents on a "-echo-test" queue
     * name (never touches the real rotation queue), pushes one job, waits
     * for it to be processed, and tears everything down. Proves BullMQ +
     * Redis + worker dispatch all work without needing any rotation state.
     */
    async bullmqEcho(req, res) {
      const { Queue, Worker, QueueEvents } = require('bullmq');
      const config = getEncryptionConfig();
      const connection = { host: config.redis.host, port: config.redis.port, db: config.redis.db };
      const queueName = `${config.rotation.queueName}-echo-test`;
      const payload = (req.body && req.body.payload) ?? { hello: 'world' };

      const queue = new Queue(queueName, { connection });
      const worker = new Worker(
        queueName,
        async (job) => ({ echoed: job.data, processedAt: new Date().toISOString() }),
        { connection }
      );
      const queueEvents = new QueueEvents(queueName, { connection });

      try {
        await worker.waitUntilReady();
        await queueEvents.waitUntilReady();
        const job = await queue.add('echo', payload, { removeOnComplete: true, removeOnFail: true });
        const result = await job.waitUntilFinished(queueEvents, 10_000);
        return res.status(200).json({ ok: true, sent: payload, result });
      } catch (err) {
        return res.status(502).json({ error: 'bullmq echo failed', detail: err.message });
      } finally {
        await queueEvents.close();
        await worker.close();
        await queue.close();
      }
    },

    /** GET /test/queue-health -> job counts on the REAL rotation queue + whether the worker process is running */
    async queueHealth(req, res) {
      try {
        const counts = await rotationService.queue.getJobCounts();
        return res.status(200).json({
          queue: getEncryptionConfig().rotation.queueName,
          counts,
          workerRunning: rotationWorker ? rotationWorker.isRunning() : null,
        });
      } catch (err) {
        return res.status(502).json({ error: err.message });
      }
    },

    /** POST /test/records/seed { count?, text? } -> inserts disposable encrypted rows into the in-memory test target */
    async seedRecords(req, res) {
      try {
        const count = Math.min(Number(req.body?.count) || 5, 500);
        const text = req.body?.text || 'test-value';
        const ids = [];
        for (let i = 0; i < count; i += 1) {
          const envelope = await encryptionService.encrypt(`${text}-${i}`);
          ids.push(testModel.insert({ value_encrypted: envelope }));
        }
        return res.status(200).json({ target: testTargetName, inserted: ids.length, ids });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },

    /** GET /test/records -> current in-memory test rows, envelope metadata only (kekVersion/provider) — never decrypts */
    async listRecords(req, res) {
      const rows = await testModel.findAllPlain();
      const summarized = rows.map((r) => ({ id: r.id, ...encryptionService.inspect(r.value_encrypted) }));
      return res.status(200).json({ target: testTargetName, count: summarized.length, records: summarized });
    },

    /** POST /test/records/reset -> clears the in-memory test rows */
    async resetRecords(req, res) {
      testModel.reset();
      return res.status(200).json({ target: testTargetName, reset: true });
    },

    /**
     * POST /test/rotation { type, fromVersion?, toVersion? }
     * Runs a REAL rotation — RotationService.createRotation() enqueues onto
     * the actual production BullMQ queue, and (if the worker process is
     * running) EncryptionRotationWorker picks it up, takes the advisory
     * lock, rewraps/re-encrypts each in-memory test row in a transaction,
     * and checkpoints/reports progress exactly as it would for real data.
     * Poll GET /encryption/rotations/:id or subscribe to the
     * "rotation:<id>" socket room to watch it happen.
     */
    async startTestRotation(req, res) {
      try {
        const { type, fromVersion, toVersion } = req.body || {};
        if (!['KEK_REWRAP', 'DEK_ROTATION'].includes(type)) {
          return res.status(400).json({ error: 'type must be KEK_REWRAP or DEK_ROTATION' });
        }
        const config = getEncryptionConfig();
        const rotation = await rotationService.createRotation({
          type,
          provider: config.provider,
          target: testTargetName,
          fromVersion,
          toVersion: type === 'KEK_REWRAP' ? toVersion ?? config.kekVersion : toVersion,
          createdBy: 'test-endpoint',
        });
        return res.status(202).json({
          rotationId: rotation.id,
          status: rotation.status,
          pollUrl: `/encryption/rotations/${rotation.id}`,
          socketRoom: `rotation:${rotation.id}`,
        });
      } catch (err) {
        return res.status(400).json({ error: err.message });
      }
    },
  };
}

module.exports = { buildWorkerTestController };
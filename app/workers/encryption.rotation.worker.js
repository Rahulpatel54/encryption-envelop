// app/workers/encryption.rotation.worker.js
'use strict';

const { Worker } = require('bullmq');
const IORedis = require('ioredis');
const { Op } = require('sequelize');
const { getEncryptionConfig } = require('../config/encryption.config');
const { getTarget } = require('../service/encryption/rotation.registry');
const { reportProgress, persistCheckpoint } = require('../service/encryption/rotation.progress');
const envelopeMod = require('../service/encryption/crypto/envelope');
const { logger } = require('../utils/logger');

async function acquireRotationLock(sequelize, lockKeyString) {
  const connection = await sequelize.connectionManager.getConnection({ type: 'write' });
  try {
    const result = await connection.query('SELECT pg_try_advisory_lock(hashtext($1)) AS locked', [lockKeyString]);
    if (!result.rows[0].locked) {
      sequelize.connectionManager.releaseConnection(connection);
      return null;
    }
    return connection;
  } catch (err) {
    sequelize.connectionManager.releaseConnection(connection);
    throw err;
  }
}

async function releaseRotationLock(sequelize, connection, lockKeyString) {
  if (!connection) return;
  try {
    await connection.query('SELECT pg_advisory_unlock(hashtext($1))', [lockKeyString]);
  } finally {
    sequelize.connectionManager.releaseConnection(connection);
  }
}

/**
 * Singleton worker matching the EmailWorker shape expected by
 * app/workers/index.js: start() / stop() / isRunning() / getWorker().
 * Construct with db + services once at process startup via configure().
 */
class EncryptionRotationWorker {
  constructor() {
    this._worker = null;
    this._bullmqConnection = null;
    this._isRunning = false;
    this._deps = null; // { sequelize, RotationModel, encryptionService, keyService }
  }

  /** Call once at process startup before start(), since deps aren't available at require-time. */
  configure({ sequelize, RotationModel, encryptionService, keyService }) {
    this._deps = { sequelize, RotationModel, encryptionService, keyService };
  }

  async start() {
    if (this._isRunning) {
      logger.warn('Encryption rotation worker is already running');
      return;
    }
    if (!this._deps) {
      throw new Error('EncryptionRotationWorker.configure() must be called before start()');
    }

    const config = getEncryptionConfig();

    this._bullmqConnection = new IORedis({
      host: config.redis.host,
      port: config.redis.port,
      db: config.redis.db,
      maxRetriesPerRequest: null,
    });

    this._worker = new Worker(
      config.rotation.queueName,
      (job) => this._processJob(job),
      {
        connection: this._bullmqConnection,
        concurrency: 1,
      }
    );

    this._attachEventHandlers();
    await this._worker.waitUntilReady();
    this._isRunning = true;
    logger.info('Encryption rotation worker ready', { queue: config.rotation.queueName });
  }

  async _processJob(job) {
    const { sequelize, RotationModel, encryptionService, keyService } = this._deps;
    const config = getEncryptionConfig();
    const { rotationId } = job.data;

    const rotation = await RotationModel.findByPk(rotationId);
    if (!rotation) throw new Error(`Rotation ${rotationId} not found`);
    if (rotation.status === 'CANCELLED') return { rotationId, status: 'CANCELLED' };

    const lockKey = `${rotation.type}:${rotation.target}`;
    const lockConnection = await acquireRotationLock(sequelize, lockKey);
    if (!lockConnection) {
      throw new Error(`Rotation target "${rotation.target}" is locked by another rotation`);
    }

    try {
      if (rotation.status === 'QUEUED') {
        await RotationModel.update(
          { status: 'RUNNING', started_at: new Date() },
          { where: { id: rotationId, status: 'QUEUED' } }
        );
      }

      const targetConfig = getTarget(rotation.target);
      if (!targetConfig) {
        throw new Error(`Unknown rotation target "${rotation.target}" — is it registered?`);
      }

      let processed = Number(rotation.processed_records) || 0;
      let failed = Number(rotation.failed_records) || 0;
      let lastId = rotation.last_processed_id != null ? rotation.last_processed_id : 0;
      const total = rotation.total_records != null ? Number(rotation.total_records) : null;
      const batchSize = config.rotation.batchSize;
      const pkAttr = targetConfig.primaryKey;

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const fresh = await RotationModel.findByPk(rotationId);
        if (!fresh || fresh.status === 'CANCELLED') {
          await reportProgress(job, { rotationId, status: 'CANCELLED', processed, total, failed });
          return { rotationId, status: 'CANCELLED' };
        }

        const batch = await targetConfig.model.findAll({
          where: { [pkAttr]: { [Op.gt]: lastId } },
          order: [[pkAttr, 'ASC']],
          limit: batchSize,
        });

        if (batch.length === 0) break;

        await sequelize.transaction(async (t) => {
          for (const record of batch) {
            try {
              if (rotation.type === 'KEK_REWRAP') {
                await this._rewrapRecordFields({ record, fields: targetConfig.encryptedFields, keyService, toVersion: rotation.to_version, transaction: t });
              } else {
                await this._rotateDekForRecordFields({ record, fields: targetConfig.encryptedFields, encryptionService, primaryKeyValue: record.get(pkAttr), transaction: t });
              }
              processed += 1;
            } catch (err) {
              failed += 1;
              logger.error('Encryption rotation record failed', { rotationId, recordId: record.get(pkAttr), message: err.message });
            }
            lastId = record.get(pkAttr);
          }
          await persistCheckpoint(RotationModel, rotationId, { processedRecords: processed, failedRecords: failed, lastProcessedId: lastId }, t);
        });

        await reportProgress(job, { rotationId, status: 'RUNNING', processed, total, failed });
      }

      await RotationModel.update({ status: 'COMPLETED', completed_at: new Date() }, { where: { id: rotationId } });
      await reportProgress(job, { rotationId, status: 'COMPLETED', processed, total, failed });
      return { rotationId, status: 'COMPLETED', processed, failed };
    } catch (err) {
      await RotationModel.update({ status: 'FAILED', error: String(err.message || err).slice(0, 2000) }, { where: { id: rotationId } });
      throw err;
    } finally {
      await releaseRotationLock(sequelize, lockConnection, lockKey);
    }
  }

  async _rewrapRecordFields({ record, fields, keyService, toVersion, transaction }) {
    const updates = {};
    for (const field of fields) {
      const serialized = record.get(field);
      if (!serialized) continue;
      const env = envelopeMod.deserializeEnvelope(serialized);
      if (env.kekVersion === toVersion) continue;
      const dek = await keyService.unwrapKey({ wrappedDek: env.wrappedDek, wrapIv: env.wrapIv, wrapTag: env.wrapTag }, env.kekVersion);
      try {
        const { wrappedDek, wrapIv, wrapTag, providerKeyId } = await keyService.wrapKey(dek, toVersion);
        const newEnv = envelopeMod.buildEnvelope({ kekProvider: env.kekProvider, kekVersion: toVersion, providerKeyId, wrappedDek, wrapIv, wrapTag, iv: env.iv, tag: env.tag, ciphertext: env.ciphertext });
        updates[field] = envelopeMod.serializeEnvelope(newEnv);
      } finally {
        dek.fill(0);
      }
    }
    if (Object.keys(updates).length > 0) await record.update(updates, { transaction });
  }

  async _rotateDekForRecordFields({ record, fields, encryptionService, primaryKeyValue, transaction }) {
    const updates = {};
    for (const field of fields) {
      const serialized = record.get(field);
      if (!serialized) continue;
      const aad = Buffer.from(`${record.constructor.name}:${field}:${primaryKeyValue}`);
      const plaintext = await encryptionService.decrypt(serialized, { aad });
      updates[field] = await encryptionService.encrypt(plaintext, { aad });
      plaintext.fill(0);
    }
    if (Object.keys(updates).length > 0) await record.update(updates, { transaction });
  }

  _attachEventHandlers() {
    this._worker.on('active', (job) => logger.info('Encryption rotation job active', { jobId: job.id }));
    this._worker.on('completed', (job) => logger.info('Encryption rotation job completed', { jobId: job.id }));
    this._worker.on('failed', (job, error) => logger.error('Encryption rotation job failed', { jobId: job?.id, message: error.message }));
    this._worker.on('error', (error) => logger.error('Encryption rotation worker error', { message: error.message }));
  }

  async stop() {
    if (!this._isRunning) return;
    this._isRunning = false;
    if (this._worker) {
      await this._worker.close();
      this._worker = null;
    }
    if (this._bullmqConnection) {
      await this._bullmqConnection.quit();
      this._bullmqConnection = null;
    }
    logger.info('Encryption rotation worker stopped gracefully');
  }

  isRunning() {
    return this._isRunning;
  }

  getWorker() {
    return this._worker;
  }
}

const encryptionRotationWorker = new EncryptionRotationWorker();
module.exports = encryptionRotationWorker;


// register in workers/index.js
// const emailWorker = require('./email.worker');
// const encryptionRotationWorker = require('./encryption.rotation.worker');

// // NEW — deps must be wired before start() is called
// const db = require('../models');
// const { KeyService } = require('../service/encryption/key.service');
// const { EncryptionService } = require('../service/encryption/encryption.service');
// require('../service/encryption/rotation.targets'); // registers targets

// const keyService = new KeyService({ EncryptionKeyModel: db.EncryptionKey });
// const encryptionService = new EncryptionService({ keyService });
// encryptionRotationWorker.configure({
//   sequelize: db.sequelize,
//   RotationModel: db.EncryptionRotation,
//   encryptionService,
//   keyService,
// });

// const workers = [
//   { name: 'email-worker', instance: emailWorker },
//   { name: 'encryption-rotation-worker', instance: encryptionRotationWorker }, // NEW
// ];

// add in model/index.js
// db.EncryptionKey = require("./security/encryption.key.model.js")(sequelize, Sequelize)
// db.EncryptionRotation = require("./security/encryption.rotation.model.js")(sequelize, Sequelize)





// app.js — edit
// javascript
// // existing:
// const io = socketServer(app, server, corsOptions)
// app.set("io", io)

// // ADD right after:
// const { initRotationSocket } = require("./app/service/encryption/rotation.socket")
// initRotationSocket(io)

// rotation.socket.js needs its Redis config fixed the same way as the worker — QueueEvents needs host/port/db, not url:

// javascript
// // OLD in rotation.socket.js
// const queueEvents = new QueueEvents(config.rotation.queueName, {
//   connection: { url: config.redis.url },
// });

// // NEW
// const queueEvents = new QueueEvents(config.rotation.queueName, {
//   connection: {
//     host: config.redis.host,
//     port: config.redis.port,
//     db: config.redis.db,
//   },
// });

// Same fix applies to rotation.service.js's Queue construction:

// javascript
// // OLD
// this.queue = queue || new Queue(config.rotation.queueName, { connection: { url: config.redis.url } });

// // NEW
// this.queue = queue || new Queue(config.rotation.queueName, {
//   connection: { host: config.redis.host, port: config.redis.port, db: config.redis.db },
// });
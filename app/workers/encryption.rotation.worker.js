'use strict';

const { Worker } = require('bullmq');
const { Op } = require('sequelize');
const { getEncryptionConfig } = require('../config/encryption.config');
const { getTarget } = require('../service/encryption/rotation.registry');
const { reportProgress, persistCheckpoint } = require('../service/encryption/rotation.progress');

/**
 * Acquires a session-level Postgres advisory lock on a dedicated connection,
 * held for the duration of the rotation job so no two conflicting rotations
 * for the same target can run concurrently. Uses hashtext() so any string
 * target key can be used as the lock key. Assumes the `pg` dialect
 * (node-postgres) under Sequelize.
 */
async function acquireRotationLock(sequelize, lockKeyString) {
  const connection = await sequelize.connectionManager.getConnection({ type: 'write' });
  try {
    const result = await connection.query('SELECT pg_try_advisory_lock(hashtext($1)) AS locked', [
      lockKeyString,
    ]);
    const locked = result.rows[0].locked;
    if (!locked) {
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
 * @param {object} deps
 * @param {import('sequelize').Sequelize} deps.sequelize
 * @param {import('sequelize').ModelStatic} deps.RotationModel
 * @param {import('../service/encryption/encryption.service').EncryptionService} deps.encryptionService
 * @param {import('../service/encryption/key.service').KeyService} deps.keyService
 * @returns {import('bullmq').Worker}
 */
function createRotationWorker({ sequelize, RotationModel, encryptionService, keyService }) {
  const config = getEncryptionConfig();

  const processor = async (job) => {
    const { rotationId } = job.data;
    const rotation = await RotationModel.findByPk(rotationId);
    if (!rotation) throw new Error(`Rotation ${rotationId} not found`);
    if (rotation.status === 'CANCELLED') return { rotationId, status: 'CANCELLED' };

    const lockKey = `${rotation.type}:${rotation.target}`;
    const lockConnection = await acquireRotationLock(sequelize, lockKey);
    if (!lockConnection) {
      // Another rotation is actively running for this target. Let BullMQ's
      // retry/backoff handle re-attempting later rather than racing it.
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
                // eslint-disable-next-line no-await-in-loop
                await rewrapRecordFields({
                  record,
                  fields: targetConfig.encryptedFields,
                  keyService,
                  toVersion: rotation.to_version,
                  transaction: t,
                });
              } else {
                // eslint-disable-next-line no-await-in-loop
                await rotateDekForRecordFields({
                  record,
                  fields: targetConfig.encryptedFields,
                  encryptionService,
                  primaryKeyValue: record.get(pkAttr),
                  transaction: t,
                });
              }
              processed += 1;
            } catch (err) {
              failed += 1;
              // eslint-disable-next-line no-console
              console.error('[encryption.rotation.worker] record failed', {
                rotationId,
                recordId: record.get(pkAttr),
                message: err.message,
              });
            }
            lastId = record.get(pkAttr);
          }

          await persistCheckpoint(
            RotationModel,
            rotationId,
            { processedRecords: processed, failedRecords: failed, lastProcessedId: lastId },
            t
          );
        });

        await reportProgress(job, { rotationId, status: 'RUNNING', processed, total, failed });
      }

      await RotationModel.update(
        { status: 'COMPLETED', completed_at: new Date() },
        { where: { id: rotationId } }
      );
      await reportProgress(job, { rotationId, status: 'COMPLETED', processed, total, failed });
      return { rotationId, status: 'COMPLETED', processed, failed };
    } catch (err) {
      await RotationModel.update(
        { status: 'FAILED', error: String(err.message || err).slice(0, 2000) },
        { where: { id: rotationId } }
      );
      throw err; // let BullMQ apply its retry/backoff policy
    } finally {
      await releaseRotationLock(sequelize, lockConnection, lockKey);
    }
  };

  const worker = new Worker(config.rotation.queueName, processor, {
    connection: { url: config.redis.url },
    concurrency: 1, // one rotation job in flight per worker process; scale via multiple targets/workers
  });

  worker.on('error', (err) => {
    // eslint-disable-next-line no-console
    console.error('[encryption.rotation.worker] worker error', err.message);
  });

  return worker;
}

/**
 * KEK_REWRAP: unwrap each field's DEK under the record's current KEK
 * version, re-wrap under `toVersion`, and update ONLY the wrapping portion
 * of the envelope. Ciphertext/IV/tag/DEK are untouched. Idempotent: if a
 * field's envelope is already at `toVersion`, it's skipped.
 */
async function rewrapRecordFields({ record, fields, keyService, toVersion, transaction }) {
  const envelopeMod = require('../service/encryption/crypto/envelope');
  const updates = {};

  for (const field of fields) {
    const serialized = record.get(field);
    if (!serialized) continue;

    const env = envelopeMod.deserializeEnvelope(serialized);
    if (env.kekVersion === toVersion) continue; // already migrated — idempotent skip

    const dek = await keyService.unwrapKey(
      { wrappedDek: env.wrappedDek, wrapIv: env.wrapIv, wrapTag: env.wrapTag },
      env.kekVersion
    );
    try {
      const { wrappedDek, wrapIv, wrapTag, providerKeyId } = await keyService.wrapKey(dek, toVersion);
      const newEnv = envelopeMod.buildEnvelope({
        kekProvider: env.kekProvider,
        kekVersion: toVersion,
        providerKeyId,
        wrappedDek,
        wrapIv,
        wrapTag,
        iv: env.iv,
        tag: env.tag,
        ciphertext: env.ciphertext,
      });
      updates[field] = envelopeMod.serializeEnvelope(newEnv);
    } finally {
      dek.fill(0);
    }
  }

  if (Object.keys(updates).length > 0) {
    await record.update(updates, { transaction });
  }
}

/**
 * Note: I've added AAD binding (ModelName:field:primaryKey) inside the worker's DEK rotation path. If you also bind AAD at initial-encryption time elsewhere in your app, use the exact same AAD convention there, or decryption will fail.
 * DEK_ROTATION: fully decrypt each field with its current DEK and
 * re-encrypt with a freshly generated DEK (wrapped under the currently
 * active KEK). Idempotent in the sense that re-running it simply generates
 * another fresh DEK — safe, if slightly wasteful, on at-least-once retry of
 * a batch that had already partially committed (it cannot partially commit,
 * since each batch is one bounded transaction).
 */
async function rotateDekForRecordFields({ record, fields, encryptionService, primaryKeyValue, transaction }) {
  const updates = {};

  for (const field of fields) {
    const serialized = record.get(field);
    if (!serialized) continue;

    const aad = Buffer.from(`${record.constructor.name}:${field}:${primaryKeyValue}`);
    const plaintext = await encryptionService.decrypt(serialized, { aad });
    updates[field] = await encryptionService.encrypt(plaintext, { aad });
    plaintext.fill(0);
  }

  if (Object.keys(updates).length > 0) {
    await record.update(updates, { transaction });
  }
}

module.exports = { createRotationWorker, acquireRotationLock, releaseRotationLock };
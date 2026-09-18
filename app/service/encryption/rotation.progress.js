'use strict';

/**
 * Helpers for turning worker progress into (a) a persisted checkpoint in
 * PostgreSQL and (b) a BullMQ job.updateProgress() call, which is what
 * rotation.socket.js's QueueEvents listener consumes to push to clients.
 */

/**
 * @param {import('bullmq').Job} job
 * @param {object} payload
 * @param {string} payload.rotationId
 * @param {'RUNNING'|'COMPLETED'|'FAILED'|'CANCELLED'} payload.status
 * @param {number} payload.processed
 * @param {number|null} payload.total
 * @param {number} payload.failed
 */
async function reportProgress(job, payload) {
  const percentage =
    payload.total && payload.total > 0
      ? Math.min(100, Math.floor((payload.processed / payload.total) * 100))
      : null;

  // job.updateProgress emits a BullMQ "progress" event, picked up by
  // QueueEvents in rotation.socket.js. Payload is intentionally minimal —
  // no key material, no record data, ever.
  await job.updateProgress({ ...payload, percentage });
}

/**
 * Persists a checkpoint so a crashed/restarted worker can resume exactly
 * where it left off, without redoing already-migrated records.
 *
 * @param {import('sequelize').ModelStatic} RotationModel
 * @param {string} rotationId
 * @param {{ processedRecords: number, failedRecords: number, lastProcessedId: number|string }} checkpoint
 * @param {import('sequelize').Transaction} [transaction]
 */
async function persistCheckpoint(RotationModel, rotationId, checkpoint, transaction) {
  await RotationModel.update(
    {
      processed_records: checkpoint.processedRecords,
      failed_records: checkpoint.failedRecords,
      last_processed_id: checkpoint.lastProcessedId,
    },
    { where: { id: rotationId }, transaction }
  );
}

module.exports = { reportProgress, persistCheckpoint };
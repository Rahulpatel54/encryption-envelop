'use strict';

const { Queue } = require('bullmq');
const { Op } = require('sequelize');
const { getEncryptionConfig } = require('../../config/encryption.config');
const { getTarget } = require('./rotation.registry');
const { emitCancelled } = require('./rotation.socket');

/**
 * RotationService: business-logic facade over the encryption_rotations
 * table + BullMQ queue. Controllers talk to this, never to BullMQ or the
 * worker directly.
 */
class RotationService {
  /**
   * @param {object} deps
   * @param {import('sequelize').ModelStatic} deps.RotationModel
   * @param {import('socket.io').Server} deps.io
   * @param {import('bullmq').Queue} [deps.queue] override for tests
   */
  constructor({ RotationModel, queue }) {
        this.RotationModel = RotationModel
        const config = getEncryptionConfig()
        this.queue = queue || new Queue(config.rotation.queueName, {
            connection: { host: config.redis.host, port: config.redis.port, db: config.redis.db },
        })
        this._config = config
    }

  /**
   * @param {object} params
   * @param {'KEK_REWRAP'|'DEK_ROTATION'} params.type
   * @param {string} params.provider
   * @param {string} params.target registered target name
   * @param {number} [params.fromVersion]
   * @param {number} [params.toVersion]
   * @param {string} [params.createdBy] integration point for the app's own authz layer
   *   (e.g. pass the authenticated principal's id here; this service does not
   *   itself authorize the request — see controller for the integration point)
   */
  async createRotation({ type, provider, target, fromVersion, toVersion, createdBy }) {
    if (!['KEK_REWRAP', 'DEK_ROTATION'].includes(type)) {
      throw new Error(`RotationService: invalid rotation type "${type}"`);
    }
    const targetConfig = getTarget(target);
    if (!targetConfig) {
      throw new Error(`RotationService: unknown rotation target "${target}"`);
    }

    const total = await targetConfig.model.count();

    const rotation = await this.RotationModel.create({
      type,
      status: 'QUEUED',
      provider,
      target,
      from_version: fromVersion ?? null,
      to_version: toVersion ?? null,
      total_records: total,
      processed_records: 0,
      failed_records: 0,
      last_processed_id: null,
      created_by: createdBy ?? null,
    });

    await this.enqueueRotation(rotation);
    return rotation;
  }

  /** Adds (or re-adds, idempotently by jobId) the BullMQ job for a rotation. */
  async enqueueRotation(rotation) {
    await this.queue.add(
      rotation.type,
      { rotationId: rotation.id },
      {
        jobId: rotation.id, // dedupes: re-adding the same rotationId is a no-op
        attempts: this._config.rotation.attempts,
        backoff: { type: 'exponential', delay: 5000 },
        removeOnComplete: { age: 86400 },
        removeOnFail: false,
      }
    );
  }

  async getRotation(id) {
    return this.RotationModel.findByPk(id);
  }

  /**
   * Requests cancellation. Sets status=CANCELLED (checked by the worker
   * between batches so it can stop gracefully rather than being killed
   * mid-transaction) and attempts to remove the job if it hasn't started.
   */
  async cancelRotation(id) {
    const rotation = await this.RotationModel.findByPk(id);
    if (!rotation) throw new Error(`RotationService: rotation ${id} not found`);
    if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(rotation.status)) {
      return rotation; // already terminal; nothing to do
    }

    await this.RotationModel.update(
      { status: 'CANCELLED', cancelled_at: new Date() },
      { where: { id, status: { [Op.in]: ['QUEUED', 'RUNNING'] } } }
    );

    try {
      const job = await this.queue.getJob(id);
      if (job) {
        const state = await job.getState();
        if (state === 'waiting' || state === 'delayed') {
          await job.remove();
        }
        // If already 'active', the worker itself observes status=CANCELLED
        // on its next per-batch check and stops.
      }
    } catch (err) {
      // Non-fatal: DB status is the source of truth; queue cleanup is best-effort.
    }

    if (this.io) emitCancelled(this.io, id);
    return this.RotationModel.findByPk(id);
  }
}

module.exports = { RotationService };
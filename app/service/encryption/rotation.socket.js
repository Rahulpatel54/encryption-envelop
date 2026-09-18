'use strict';

const { QueueEvents } = require('bullmq');
const { getEncryptionConfig } = require('../../config/encryption.config');

const ROOM_PREFIX = 'rotation:';
const roomName = (rotationId) => `${ROOM_PREFIX}${rotationId}`;

/**
 * Bridges BullMQ job lifecycle events -> Socket.IO rooms, one room per
 * rotation ("rotation:<rotationId>"). Frontend never polls PostgreSQL for
 * progress; it subscribes to its rotation's room and receives batch-level
 * updates only.
 *
 * Never emits key material, plaintext, ciphertext, or raw error stacks.
 */
function initRotationSocket(io) {
  const config = getEncryptionConfig();
  const namespace = io.of('/encryption-rotations');

  namespace.on('connection', (socket) => {
    socket.on('rotation:subscribe', (rotationId) => {
      if (typeof rotationId === 'string' && rotationId.length > 0) {
        socket.join(roomName(rotationId));
      }
    });

    socket.on('rotation:unsubscribe', (rotationId) => {
      if (typeof rotationId === 'string') {
        socket.leave(roomName(rotationId));
      }
    });
  });

  const queueEvents = new QueueEvents(config.rotation.queueName, {
    connection: { url: config.redis.url },
  });

  queueEvents.on('progress', ({ jobId, data }) => {
    const payload = sanitizePayload(data);
    if (!payload?.rotationId) return;
    namespace.to(roomName(payload.rotationId)).emit('rotation:progress', payload);
  });

  queueEvents.on('completed', ({ jobId, returnvalue }) => {
    const payload = sanitizePayload(returnvalue) || { rotationId: jobId };
    namespace.to(roomName(payload.rotationId)).emit('rotation:completed', {
      ...payload,
      status: 'COMPLETED',
    });
  });

  queueEvents.on('failed', ({ jobId, failedReason }) => {
    // Deliberately generic — never forward raw error/stack text, which could
    // leak internal detail (paths, query fragments, etc).
    namespace.to(roomName(jobId)).emit('rotation:failed', {
      rotationId: jobId,
      status: 'FAILED',
      message: 'Rotation failed. See server logs / GET /encryption/rotations/:id for status.',
    });
  });

  return { namespace, queueEvents };
}

function sanitizePayload(data) {
  if (!data || typeof data !== 'object') return null;
  const { rotationId, status, processed, total, failed, percentage } = data;
  return { rotationId, status, processed, total, failed, percentage };
}

/** Emits a cancellation notice; called directly by RotationService.cancelRotation. */
function emitCancelled(io, rotationId) {
  io.of('/encryption-rotations')
    .to(roomName(rotationId))
    .emit('rotation:cancelled', { rotationId, status: 'CANCELLED' });
}

module.exports = { initRotationSocket, emitCancelled, roomName };
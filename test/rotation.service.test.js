'use strict';

/**
 * Unit tests for RotationService against a fully mocked model/queue,
 * covering: rotation state transitions and cancellation behavior.
 */

const { RotationService } = require('../app/service/encryption/rotation.service');
const registry = require('../app/service/encryption/rotation.registry');

describe('RotationService', () => {
  beforeEach(() => {
    registry._clearRegistry();
    registry.registerTarget('fake.target', {
      model: { count: jest.fn().mockResolvedValue(42) },
      primaryKey: 'id',
      encryptedFields: ['secret_encrypted'],
    });
    process.env.ENCRYPTION_KEY_PROVIDER = 'env';
    process.env.ENCRYPTION_KEK_VERSION = '1';
    process.env.ENCRYPTION_KEK = require('crypto').randomBytes(32).toString('base64');
    require('../app/config/encryption.config').resetEncryptionConfigCache();
  });

  function makeMockModel() {
    const rows = new Map();
    return {
      create: jest.fn(async (data) => {
        const row = { id: 'rot-1', status: 'QUEUED', ...data, toJSON() { return this; } };
        rows.set(row.id, row);
        return row;
      }),
      findByPk: jest.fn(async (id) => rows.get(id) || null),
      update: jest.fn(async (data, opts) => {
        const row = rows.get(opts.where.id);
        if (row && (!opts.where.status || row.status === opts.where.status || Array.isArray(opts.where.status?.[Symbol.for?.('in')]))) {
          Object.assign(row, data);
        } else if (row) {
          Object.assign(row, data);
        }
        return [1];
      }),
      _rows: rows,
    };
  }

  test('createRotation starts a rotation in QUEUED status and enqueues a job', async () => {
    const RotationModel = makeMockModel();
    const queue = { add: jest.fn().mockResolvedValue(undefined) };
    const svc = new RotationService({ RotationModel, io: null, queue });

    const rotation = await svc.createRotation({
      type: 'KEK_REWRAP',
      provider: 'env',
      target: 'fake.target',
      toVersion: 2,
    });

    expect(rotation.status).toBe('QUEUED');
    expect(rotation.total_records).toBe(42);
    expect(queue.add).toHaveBeenCalledWith(
      'KEK_REWRAP',
      { rotationId: 'rot-1' },
      expect.objectContaining({ jobId: 'rot-1' })
    );
  });

  test('rejects an unregistered target', async () => {
    const RotationModel = makeMockModel();
    const queue = { add: jest.fn() };
    const svc = new RotationService({ RotationModel, io: null, queue });

    await expect(
      svc.createRotation({ type: 'DEK_ROTATION', provider: 'env', target: 'nope' })
    ).rejects.toThrow(/unknown rotation target/i);
  });

  test('cancelRotation moves QUEUED -> CANCELLED and removes a waiting job', async () => {
    const RotationModel = makeMockModel();
    const job = { getState: jest.fn().mockResolvedValue('waiting'), remove: jest.fn() };
    const queue = { add: jest.fn(), getJob: jest.fn().mockResolvedValue(job) };
    const svc = new RotationService({ RotationModel, io: null, queue });

    const rotation = await svc.createRotation({ type: 'DEK_ROTATION', provider: 'env', target: 'fake.target' });
    const cancelled = await svc.cancelRotation(rotation.id);

    expect(cancelled.status).toBe('CANCELLED');
    expect(job.remove).toHaveBeenCalled();
  });

  test('cancelRotation is a no-op on an already-terminal rotation', async () => {
    const RotationModel = makeMockModel();
    const queue = { add: jest.fn() };
    const svc = new RotationService({ RotationModel, io: null, queue });
    const rotation = await svc.createRotation({ type: 'DEK_ROTATION', provider: 'env', target: 'fake.target' });
    RotationModel._rows.get(rotation.id).status = 'COMPLETED';

    const result = await svc.cancelRotation(rotation.id);
    expect(result.status).toBe('COMPLETED');
  });
});
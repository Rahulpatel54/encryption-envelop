'use strict';

const { reportProgress, persistCheckpoint } = require('../app/service/encryption/rotation.progress');

describe('rotation.progress', () => {
  test('reportProgress computes percentage and forwards to job.updateProgress (no sensitive fields)', async () => {
    const job = { updateProgress: jest.fn() };
    await reportProgress(job, { rotationId: 'r1', status: 'RUNNING', processed: 250, total: 1000, failed: 3 });

    expect(job.updateProgress).toHaveBeenCalledWith({
      rotationId: 'r1',
      status: 'RUNNING',
      processed: 250,
      total: 1000,
      failed: 3,
      percentage: 25,
    });
  });

  test('reportProgress handles unknown total gracefully', async () => {
    const job = { updateProgress: jest.fn() };
    await reportProgress(job, { rotationId: 'r1', status: 'RUNNING', processed: 10, total: null, failed: 0 });
    expect(job.updateProgress).toHaveBeenCalledWith(
      expect.objectContaining({ percentage: null })
    );
  });

  test('persistCheckpoint writes processed/failed/lastProcessedId to the model', async () => {
    const RotationModel = { update: jest.fn().mockResolvedValue([1]) };
    await persistCheckpoint(RotationModel, 'r1', { processedRecords: 5, failedRecords: 1, lastProcessedId: 500 }, 'txn');
    expect(RotationModel.update).toHaveBeenCalledWith(
      { processed_records: 5, failed_records: 1, last_processed_id: 500 },
      { where: { id: 'r1' }, transaction: 'txn' }
    );
  });
});
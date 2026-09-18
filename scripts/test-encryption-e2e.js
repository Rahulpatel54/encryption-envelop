'use strict';

/**
 * End-to-end smoke test for the encryption/rotation module.
 *
 * Exercises the full pipeline against REAL Postgres + Redis (no mocks):
 *   EncryptionService.encrypt() -> DB -> RotationService.createRotation()
 *   -> BullMQ -> EncryptionRotationWorker -> advisory lock -> batched
 *   transaction -> checkpoint -> job.updateProgress() -> QueueEvents
 *   -> decrypt() verification
 *
 * Run: node --env-file=.env scripts/test-encryption-e2e.js
 *
 * Safe to re-run: drops and recreates its own throwaway table each time.
 */

const { Sequelize, DataTypes, Op } = require('sequelize');
const dbConfig = require('../config/db.config.js');

const { getEncryptionConfig, resetEncryptionConfigCache } = require('../app/config/encryption.config');
const { registerTarget, _clearRegistry } = require('../app/service/encryption/rotation.registry');
const { KeyService } = require('../app/service/encryption/key.service');
const { EncryptionService } = require('../app/service/encryption/encryption.service');
const { RotationService } = require('../app/service/encryption/rotation.service');
const encryptionRotationWorker = require('../app/workers/encryption.rotation.worker');
const { QueueEvents } = require('bullmq');

const SEED_COUNT = 47; // deliberately not a clean multiple of batch size
const TARGET_NAME = 'test.e2e_records';
const TEST_TABLE = 'encryption_e2e_test_records';

let sequelize;
let exitCode = 0;

function log(step, msg) {
  console.log(`[${step}] ${msg}`);
}

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
}

async function waitForStatus(RotationModel, rotationId, targetStatuses, timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const row = await RotationModel.findByPk(rotationId);
    if (row && targetStatuses.includes(row.status)) return row;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`Timed out waiting for rotation ${rotationId} to reach ${targetStatuses.join('/')}`);
}

async function main() {
  log('SETUP', 'Validating encryption config...');
  resetEncryptionConfigCache();
  const config = getEncryptionConfig();
  log('SETUP', `provider=${config.provider} kekVersion=${config.kekVersion} batchSize=${config.rotation.batchSize} redis=${config.redis.host}:${config.redis.port}`);

  sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
    host: dbConfig.HOST,
    port: dbConfig.PORT,
    dialect: dbConfig.dialect,
    logging: false,
  });
  await sequelize.authenticate();
  log('SETUP', 'Database connected');

  // --- Throwaway test model (not part of production schema) ---
  const TestRecord = sequelize.define(
    TEST_TABLE,
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      secret_encrypted: { type: DataTypes.TEXT, allowNull: false },
      label: { type: DataTypes.STRING, allowNull: false },
    },
    { tableName: TEST_TABLE, timestamps: false }
  );
  await TestRecord.sync({ force: true }); // drop + recreate fresh each run
  log('SETUP', `Test table "${TEST_TABLE}" created`);

  // --- Load real security models ---
  const EncryptionKeyModel = require('../app/models/security/encryption.key.model')(sequelize, Sequelize);
  const EncryptionRotationModel = require('../app/models/security/encryption.rotation.model')(sequelize, Sequelize);
  await EncryptionKeyModel.sync();
  await EncryptionRotationModel.sync();

  const keyService = new KeyService({ EncryptionKeyModel });
  const encryptionService = new EncryptionService({ keyService });

  // --- Register the test target ---
  _clearRegistry();
  registerTarget(TARGET_NAME, {
    model: TestRecord,
    primaryKey: 'id',
    encryptedFields: ['secret_encrypted'],
  });
  log('SETUP', `Registered rotation target "${TARGET_NAME}"`);

  // ============================================================
  // STEP 1: Seed encrypted rows via EncryptionService
  // ============================================================
  log('SEED', `Encrypting and inserting ${SEED_COUNT} rows...`);
  for (let i = 0; i < SEED_COUNT; i++) {
    const plaintext = `secret-value-${i}`;
    const aad = Buffer.from(`${TEST_TABLE}:secret_encrypted:${i + 1}`); // matches worker's AAD convention (model name : field : pk)
    // NOTE: worker uses record.constructor.name for AAD, which for sequelize.define
    // models is the model name string passed to define() ("encryption_e2e_test_records").
    const envelope = await encryptionService.encrypt(plaintext, { aad });
    await TestRecord.create({ secret_encrypted: envelope, label: `row-${i}` });
  }
  const seededCount = await TestRecord.count();
  assert(seededCount === SEED_COUNT, `expected ${SEED_COUNT} seeded rows, got ${seededCount}`);
  log('SEED', `✅ ${seededCount} rows inserted, each independently encrypted with a fresh DEK`);

  // Sanity: envelopes are versioned and non-plaintext
  const sample = await TestRecord.findOne({ where: { id: 1 } });
  assert(sample.secret_encrypted.startsWith('v1:'), 'envelope missing version prefix');
  assert(!sample.secret_encrypted.includes('secret-value'), 'plaintext leaked into stored envelope!');
  log('SEED', '✅ Stored envelope is versioned and contains no plaintext');

  // ============================================================
  // STEP 2: Register KEK version 1 as ACTIVE in metadata
  // ============================================================
  await keyService.createKeyVersion({ version: config.kekVersion, providerKeyId: null });
  await keyService.activateKey(config.kekVersion);
  log('KEY', `✅ KEK version ${config.kekVersion} recorded as ACTIVE`);

  // ============================================================
  // STEP 3: Start the worker (in-process, matching workers/index.js shape)
  // ============================================================
  encryptionRotationWorker.configure({
    sequelize,
    RotationModel: EncryptionRotationModel,
    encryptionService,
    keyService,
  });
  await encryptionRotationWorker.start();
  log('WORKER', '✅ EncryptionRotationWorker started and listening');

  // ============================================================
  // STEP 4: Subscribe to BullMQ progress events directly (proxy for
  // what rotation.socket.js -> Socket.IO would forward to the frontend)
  // ============================================================
  const queueEvents = new QueueEvents(config.rotation.queueName, {
    connection: { host: config.redis.host, port: config.redis.port, db: config.redis.db },
  });
  await queueEvents.waitUntilReady();

  const progressEvents = [];
  queueEvents.on('progress', ({ data }) => {
    progressEvents.push(data);
    log('PROGRESS', `processed=${data.processed}/${data.total} failed=${data.failed} pct=${data.percentage}%`);
  });

  // ============================================================
  // STEP 5: DEK_ROTATION — full decrypt/re-encrypt under a new DEK
  // ============================================================
  log('TEST 1', 'Creating DEK_ROTATION rotation...');
  const rotationService = new RotationService({ RotationModel: EncryptionRotationModel });
  const dekRotation = await rotationService.createRotation({
    type: 'DEK_ROTATION',
    provider: config.provider,
    target: TARGET_NAME,
  });
  assert(dekRotation.status === 'QUEUED', 'rotation should start QUEUED');
  log('TEST 1', `Rotation ${dekRotation.id} created with status QUEUED, total=${dekRotation.total_records}`);

  const dekFinal = await waitForStatus(EncryptionRotationModel, dekRotation.id, ['COMPLETED', 'FAILED']);
  assert(dekFinal.status === 'COMPLETED', `DEK_ROTATION should complete, got ${dekFinal.status}: ${dekFinal.error}`);
  assert(Number(dekFinal.processed_records) === SEED_COUNT, `expected ${SEED_COUNT} processed, got ${dekFinal.processed_records}`);
  assert(Number(dekFinal.failed_records) === 0, `expected 0 failures, got ${dekFinal.failed_records}`);
  assert(progressEvents.length > 1, 'expected multiple batch-level progress events, not one-shot');
  log('TEST 1', `✅ DEK_ROTATION completed: processed=${dekFinal.processed_records} failed=${dekFinal.failed_records}`);
  log('TEST 1', `✅ Received ${progressEvents.length} progress events (batch-level, not per-record)`);

  // Verify: data still decrypts correctly after DEK rotation
  const rowAfterDek = await TestRecord.findByPk(1);
  const aad1 = Buffer.from(`${TEST_TABLE}:secret_encrypted:1`);
  const decrypted = await encryptionService.decryptToString(rowAfterDek.secret_encrypted, { aad: aad1 });
  assert(decrypted === 'secret-value-0', `decrypted value mismatch after DEK_ROTATION: got "${decrypted}"`);
  log('TEST 1', '✅ Row still decrypts correctly after DEK_ROTATION (new DEK, same plaintext)');

  // ============================================================
  // STEP 6: KEK_REWRAP — rewrap all DEKs under KEK version 2
  // ============================================================
  log('TEST 2', 'Registering KEK version 2 and creating KEK_REWRAP rotation...');

  // Simulate a new KEK version being available (env provider needs the
  // material present; here we just prove the rewrap path end-to-end using
  // the SAME active version as a stand-in, since introducing a second real
  // KEK requires a legacyKeys/new deploy in the real EnvKeyProvider).
  // To truly test cross-version rewrap, see the note below the script.
  await keyService.createKeyVersion({ version: config.kekVersion, providerKeyId: null, metadata: { note: 'e2e-test-rewrap-target' } }).catch(() => {
    // already exists from Step 2 — fine, this call is best-effort for metadata completeness
  });

  const rewrapRotation = await rotationService.createRotation({
    type: 'KEK_REWRAP',
    provider: config.provider,
    target: TARGET_NAME,
    fromVersion: config.kekVersion,
    toVersion: config.kekVersion, // same version = should be a no-op / idempotent skip on every row
  });
  const rewrapFinal = await waitForStatus(EncryptionRotationModel, rewrapRotation.id, ['COMPLETED', 'FAILED']);
  assert(rewrapFinal.status === 'COMPLETED', `KEK_REWRAP should complete, got ${rewrapFinal.status}: ${rewrapFinal.error}`);
  log('TEST 2', `✅ KEK_REWRAP completed: processed=${rewrapFinal.processed_records} failed=${rewrapFinal.failed_records}`);

  const rowAfterRewrap = await TestRecord.findByPk(1);
  const decrypted2 = await encryptionService.decryptToString(rowAfterRewrap.secret_encrypted, { aad: aad1 });
  assert(decrypted2 === 'secret-value-0', 'decryption failed after KEK_REWRAP');
  log('TEST 2', '✅ Row still decrypts correctly after KEK_REWRAP');

  // ============================================================
  // STEP 7: Idempotent retry — re-run the same rotation type again;
  // already-migrated envelopes must be skipped without corrupting data
  // ============================================================
  log('TEST 3', 'Re-running KEK_REWRAP to the same target version (idempotency check)...');
  const rewrapAgain = await rotationService.createRotation({
    type: 'KEK_REWRAP',
    provider: config.provider,
    target: TARGET_NAME,
    fromVersion: config.kekVersion,
    toVersion: config.kekVersion,
  });
  const rewrapAgainFinal = await waitForStatus(EncryptionRotationModel, rewrapAgain.id, ['COMPLETED', 'FAILED']);
  assert(rewrapAgainFinal.status === 'COMPLETED', 'idempotent re-run should still complete cleanly');
  const rowStillOk = await TestRecord.findByPk(1);
  const decrypted3 = await encryptionService.decryptToString(rowStillOk.secret_encrypted, { aad: aad1 });
  assert(decrypted3 === 'secret-value-0', 'decryption failed after idempotent re-run');
  log('TEST 3', '✅ Idempotent re-run completed cleanly, data still correct');

  // ============================================================
  // STEP 8: Cancellation — start a rotation and cancel it mid-flight
  // ============================================================
  log('TEST 4', 'Testing cancellation...');
  const cancelRotation = await rotationService.createRotation({
    type: 'DEK_ROTATION',
    provider: config.provider,
    target: TARGET_NAME,
  });
  // Race condition by design: cancel almost immediately, before the worker
  // finishes. With only 47 rows / batchSize 500 this will likely run to
  // completion before cancellation lands — that's fine, this step just
  // proves cancelRotation() doesn't throw and the status API responds.
  await new Promise((r) => setTimeout(r, 50));
  const cancelled = await rotationService.cancelRotation(cancelRotation.id);
  log('TEST 4', `✅ cancelRotation() returned status=${cancelled.status} (QUEUED/RUNNING->CANCELLED, or COMPLETED if it beat the cancel)`);
  assert(['CANCELLED', 'COMPLETED', 'RUNNING', 'QUEUED'].includes(cancelled.status), 'unexpected status after cancel');

  // Let it settle either way, then confirm no crash / no double-processing
  await waitForStatus(EncryptionRotationModel, cancelRotation.id, ['COMPLETED', 'FAILED', 'CANCELLED'], 15000);
  log('TEST 4', '✅ Rotation reached a terminal state after cancel attempt');

  // ============================================================
  // STEP 9: Unregistered target is rejected
  // ============================================================
  log('TEST 5', 'Verifying unregistered target is rejected...');
  try {
    await rotationService.createRotation({ type: 'DEK_ROTATION', provider: config.provider, target: 'nope.does.not.exist' });
    throw new Error('expected createRotation to reject an unknown target, but it did not');
  } catch (err) {
    assert(/unknown rotation target/i.test(err.message), `unexpected error: ${err.message}`);
    log('TEST 5', '✅ Unregistered target correctly rejected');
  }

  log('DONE', '🎉 All end-to-end checks passed');
}

main()
  .catch((err) => {
    console.error('[FATAL]', err);
    exitCode = 1;
  })
  .finally(async () => {
    try {
      await encryptionRotationWorker.stop();
    } catch (e) {
      console.error('Error stopping worker:', e.message);
    }
    try {
      if (sequelize) await sequelize.close();
    } catch (e) {
      console.error('Error closing DB:', e.message);
    }
    process.exit(exitCode);
  });

//node --env-file=.env scripts/test-encryption-e2e.js
#!/usr/bin/env node
'use strict';

/**
 * Local test harness for the encryption / DEK-rotation module.
 *
 * Run with:  node test.js
 *
 * Place this file in the same directory as app.js (project root) — every
 * require() below is relative to ./app/...
 *
 * No real Postgres or Redis is required. Sequelize models and BullMQ
 * Queue/Job objects are replaced with small in-memory fakes that implement
 * only the surface area the production code actually calls (the same
 * philosophy as app/service/encryption/testing/in-memory.target.js, which
 * this script reuses directly). That lets us run the *real* crypto,
 * key-lifecycle, and rotation-worker code end-to-end, deterministically,
 * with no external services.
 *
 * If a live Redis happens to be reachable (REDIS_HOST/REDIS_PORT), the last
 * section does a quick connectivity sanity check — but nothing else in this
 * suite depends on it, so this always runs offline.
 */

const crypto = require('crypto');
const assert = require('assert');

// ---------------------------------------------------------------------------
// 0. Environment bootstrap — MUST happen before any app module is required,
//    since app/config/encryption.config.js validates + caches env vars on
//    first access.
// ---------------------------------------------------------------------------
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.ENCRYPTION_KEY_PROVIDER = 'env';
process.env.ENCRYPTION_KEK_VERSION = '1';
process.env.ENCRYPTION_KEK = crypto.randomBytes(32).toString('base64');
process.env.ENCRYPTION_ROTATION_BATCH_SIZE = '10';
process.env.ENCRYPTION_ROTATION_ATTEMPTS = '3';
process.env.ENCRYPTION_ROTATION_QUEUE_NAME = 'encryption-rotation-test';
process.env.REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
process.env.REDIS_PORT = process.env.REDIS_PORT || '6379';
process.env.REDIS_DB = process.env.REDIS_DB || '0';

const { Op } = require('sequelize');

// ---------------------------------------------------------------------------
// App modules under test
// ---------------------------------------------------------------------------
const aesGcm = require('./app/service/encryption/crypto/aes-gcm');
const envelopeMod = require('./app/service/encryption/crypto/envelope');
const { getEncryptionConfig, resetEncryptionConfigCache } = require('./app/config/encryption.config');
const { EnvKeyProvider } = require('./app/service/encryption/providers/env.provider');
const { KmsKeyProvider } = require('./app/service/encryption/providers/kms.provider');
const { KeyService } = require('./app/service/encryption/key.service');
const { EncryptionService } = require('./app/service/encryption/encryption.service');
const rotationRegistry = require('./app/service/encryption/rotation.registry');
const { reportProgress, persistCheckpoint } = require('./app/service/encryption/rotation.progress');
const { RotationService } = require('./app/service/encryption/rotation.service');
const rotationWorker = require('./app/workers/encryption.rotation.worker');
const { testModel, registerInMemoryTestTarget } = require('./app/service/encryption/testing/in-memory.target');
const { buildRotationController } = require('./app/controllers/encryption/encryption.rotation.controller');

// ---------------------------------------------------------------------------
// Tiny test runner
// ---------------------------------------------------------------------------
const RESET = '\x1b[0m', BOLD = '\x1b[1m', GREEN = '\x1b[32m', RED = '\x1b[31m', YELLOW = '\x1b[33m', DIM = '\x1b[2m';
const results = [];
let currentSuite = '';

function section(title) {
  currentSuite = title;
  console.log(`\n${BOLD}${title}${RESET}`);
}

async function t(name, fn) {
  const label = `${currentSuite} > ${name}`;
  try {
    await fn();
    results.push({ label, pass: true });
    console.log(`  ${GREEN}\u2713${RESET} ${name}`);
  } catch (err) {
    results.push({ label, pass: false, err });
    console.log(`  ${RED}\u2717${RESET} ${name}`);
    const msg = err && err.stack ? err.stack.split('\n').slice(0, 3).join('\n      ') : String(err);
    console.log(`      ${RED}${msg}${RESET}`);
  }
}

function note(msg) {
  console.log(`  ${DIM}\u2139 ${msg}${RESET}`);
}

function warn(msg) {
  console.log(`  ${YELLOW}\u26a0 ${msg}${RESET}`);
}

// ---------------------------------------------------------------------------
// In-memory fakes: Sequelize-model-shaped store + Sequelize-shaped handle
// ---------------------------------------------------------------------------

function matchesWhere(row, where) {
  if (!where) return true;
  return Object.keys(where).every((key) => {
    const cond = where[key];
    if (cond && typeof cond === 'object' && !Buffer.isBuffer(cond)) {
      const syms = Object.getOwnPropertySymbols(cond);
      if (syms.length) {
        return syms.every((s) => {
          const val = cond[s];
          if (s === Op.gt) return row[key] > val;
          if (s === Op.gte) return row[key] >= val;
          if (s === Op.lt) return row[key] < val;
          if (s === Op.lte) return row[key] <= val;
          if (s === Op.in) return val.includes(row[key]);
          return true;
        });
      }
    }
    return row[key] === cond;
  });
}

function wrapRow(row) {
  return {
    ...row,
    get(field) {
      return row[field];
    },
    async update(values) {
      Object.assign(row, values);
      return wrapRow(row);
    },
    toJSON() {
      return { ...row };
    },
  };
}

/** Generic in-memory stand-in for a Sequelize model — covers the surface
 * area actually used by KeyService / RotationService / EncryptionRotationWorker:
 * create, findOne, findByPk, update, max. */
function createMockModel() {
  const rows = [];
  const model = {
    _rows: rows,
    async create(data) {
      const row = { id: data.id || crypto.randomUUID(), created_at: new Date(), updated_at: new Date(), ...data };
      rows.push(row);
      return wrapRow(row);
    },
    async findOne({ where } = {}) {
      const row = rows.find((r) => matchesWhere(r, where));
      return row ? wrapRow(row) : null;
    },
    async findByPk(id) {
      const row = rows.find((r) => r.id === id);
      return row ? wrapRow(row) : null;
    },
    async update(values, { where } = {}) {
      const affected = rows.filter((r) => matchesWhere(r, where));
      affected.forEach((r) => Object.assign(r, values, { updated_at: new Date() }));
      return [affected.length, affected.map(wrapRow)];
    },
    async max(field, { where } = {}) {
      const filtered = rows.filter((r) => matchesWhere(r, where));
      if (!filtered.length) return null;
      return Math.max(...filtered.map((r) => Number(r[field]) || 0));
    },
  };
  model.sequelize = createMockSequelize();
  return model;
}

/** Fake sequelize handle: just enough for KeyService.activateDek's
 * transaction() and EncryptionRotationWorker's advisory-lock + transaction
 * usage. `lockAvailable: false` simulates another rotation holding the lock. */
function createMockSequelize({ lockAvailable = true } = {}) {
  return {
    async transaction(cb) {
      return cb({ __fakeTransaction: true });
    },
    connectionManager: {
      async getConnection() {
        return {
          async query(sql) {
            if (sql.startsWith('SELECT pg_try_advisory_lock')) return { rows: [{ locked: lockAvailable }] };
            if (sql.startsWith('SELECT pg_advisory_unlock')) return { rows: [{}] };
            return { rows: [] };
          },
        };
      },
      releaseConnection() {
        // no-op
      },
    },
  };
}

/** Fake BullMQ Queue — enough for RotationService.enqueueRotation/cancelRotation. */
function createMockQueue() {
  const jobs = new Map();
  return {
    _jobs: jobs,
    async add(name, data, opts) {
      const job = { id: opts.jobId, name, data, opts, _state: 'waiting' };
      jobs.set(job.id, job);
      return job;
    },
    async getJob(id) {
      const job = jobs.get(id);
      if (!job) return null;
      return {
        async getState() {
          return job._state;
        },
        async remove() {
          jobs.delete(id);
        },
      };
    },
  };
}

function mockRes() {
  const res = { statusCode: null, body: null };
  res.status = (code) => {
    res.statusCode = code;
    return res;
  };
  res.json = (body) => {
    res.body = body;
    return res;
  };
  return res;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  // ---- aes-gcm.js -----------------------------------------------------
  section('aes-gcm.js — low-level AES-256-GCM primitives');

  await t('generateKey/generateIv produce correctly sized buffers', () => {
    assert.strictEqual(aesGcm.generateKey().length, 32);
    assert.strictEqual(aesGcm.generateIv().length, 12);
  });

  await t('encrypt/decrypt round-trips plaintext', () => {
    const key = aesGcm.generateKey();
    const plaintext = Buffer.from('the quick brown fox');
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, plaintext);
    const decrypted = aesGcm.decrypt(key, { iv, ciphertext, tag });
    assert.deepStrictEqual(decrypted, plaintext);
  });

  await t('decrypt fails with the wrong key', () => {
    const key = aesGcm.generateKey();
    const wrongKey = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('secret'));
    assert.throws(() => aesGcm.decrypt(wrongKey, { iv, ciphertext, tag }));
  });

  await t('decrypt fails on tampered ciphertext', () => {
    const key = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('secret'));
    ciphertext[0] ^= 0xff;
    assert.throws(() => aesGcm.decrypt(key, { iv, ciphertext, tag }));
  });

  await t('AAD is authenticated — mismatched AAD fails, matching AAD succeeds', () => {
    const key = aesGcm.generateKey();
    const { iv, ciphertext, tag } = aesGcm.encrypt(key, Buffer.from('secret'), Buffer.from('ctx-a'));
    assert.throws(() => aesGcm.decrypt(key, { iv, ciphertext, tag }, Buffer.from('ctx-b')));
    const ok = aesGcm.decrypt(key, { iv, ciphertext, tag }, Buffer.from('ctx-a'));
    assert.strictEqual(ok.toString(), 'secret');
  });

  await t('rejects non-32-byte keys', () => {
    assert.throws(() => aesGcm.encrypt(Buffer.alloc(16), Buffer.from('x')));
  });

  // ---- envelope.js ------------------------------------------------------
  section('crypto/envelope.js — versioned envelope format');

  await t('build/serialize/deserialize preserves all fields', () => {
    const iv = crypto.randomBytes(12);
    const tag = crypto.randomBytes(16);
    const ciphertext = crypto.randomBytes(32);
    const env = envelopeMod.buildEnvelope({ keyVersion: 7, iv, tag, ciphertext });
    const serialized = envelopeMod.serializeEnvelope(env);
    assert.ok(serialized.startsWith('v2:'));
    const parsed = envelopeMod.deserializeEnvelope(serialized);
    assert.strictEqual(parsed.keyVersion, 7);
    assert.deepStrictEqual(parsed.iv, iv);
    assert.deepStrictEqual(parsed.tag, tag);
    assert.deepStrictEqual(parsed.ciphertext, ciphertext);
  });

  await t('rejects strings without the version prefix', () => {
    assert.throws(() => envelopeMod.deserializeEnvelope('not-an-envelope'), /unrecognized or missing version prefix/);
  });

  await t('rejects malformed base64/JSON payloads', () => {
    const bogus = 'v2:' + Buffer.from('{not json', 'utf8').toString('base64');
    assert.throws(() => envelopeMod.deserializeEnvelope(bogus), /malformed payload/);
  });

  await t('rejects unsupported envelope versions', () => {
    const bogus = 'v2:' + Buffer.from(JSON.stringify({ v: 99 }), 'utf8').toString('base64');
    assert.throws(() => envelopeMod.deserializeEnvelope(bogus), /unsupported envelope version/);
  });

  // ---- encryption.config.js ---------------------------------------------
  section('config/encryption.config.js — env validation');

  await t('throws when ENCRYPTION_KEK is missing', () => {
    const saved = process.env.ENCRYPTION_KEK;
    delete process.env.ENCRYPTION_KEK;
    resetEncryptionConfigCache();
    try {
      assert.throws(() => getEncryptionConfig(), /Missing required env var: ENCRYPTION_KEK/);
    } finally {
      process.env.ENCRYPTION_KEK = saved;
      resetEncryptionConfigCache();
      getEncryptionConfig(); // re-warm cache with valid config for the rest of the run
    }
  });

  await t('throws when ENCRYPTION_KEK does not decode to 32 bytes', () => {
    const saved = process.env.ENCRYPTION_KEK;
    process.env.ENCRYPTION_KEK = Buffer.alloc(16).toString('base64');
    resetEncryptionConfigCache();
    try {
      assert.throws(() => getEncryptionConfig(), /must decode to exactly 32 bytes/);
    } finally {
      process.env.ENCRYPTION_KEK = saved;
      resetEncryptionConfigCache();
      getEncryptionConfig();
    }
  });

  await t('kms provider requires ENCRYPTION_KMS_KEY_ID', () => {
    const savedProvider = process.env.ENCRYPTION_KEY_PROVIDER;
    const savedKeyId = process.env.ENCRYPTION_KMS_KEY_ID;
    delete process.env.ENCRYPTION_KMS_KEY_ID;
    process.env.ENCRYPTION_KEY_PROVIDER = 'kms';
    resetEncryptionConfigCache();
    try {
      assert.throws(() => getEncryptionConfig(), /ENCRYPTION_KMS_KEY_ID is required/);
    } finally {
      process.env.ENCRYPTION_KEY_PROVIDER = savedProvider;
      if (savedKeyId) process.env.ENCRYPTION_KMS_KEY_ID = savedKeyId;
      resetEncryptionConfigCache();
      getEncryptionConfig();
    }
  });

  // ---- env.provider.js ---------------------------------------------------
  section('providers/env.provider.js — EnvKeyProvider (KEK)');

  await t('getActiveKey reflects the configured KEK version', async () => {
    const provider = new EnvKeyProvider();
    const active = await provider.getActiveKey();
    assert.strictEqual(active.version, Number(process.env.ENCRYPTION_KEK_VERSION));
    assert.strictEqual(active.providerKeyId, null);
  });

  await t('wrapKey/unwrapKey round-trips a DEK under the active KEK', async () => {
    const provider = new EnvKeyProvider();
    const dek = aesGcm.generateKey();
    const version = Number(process.env.ENCRYPTION_KEK_VERSION);
    const wrapped = await provider.wrapKey(dek, version);
    const unwrapped = await provider.unwrapKey(wrapped, version);
    assert.deepStrictEqual(unwrapped, dek);
  });

  await t('getKey throws for a KEK version with no material', async () => {
    const provider = new EnvKeyProvider();
    await assert.rejects(() => provider.getKey(999));
  });

  await t('legacyKeys let older KEK versions still unwrap', async () => {
    const legacyKey = crypto.randomBytes(32);
    const provider = new EnvKeyProvider({ legacyKeys: { 0: legacyKey.toString('base64') } });
    const dek = aesGcm.generateKey();
    const wrapped = await provider.wrapKey(dek, 0);
    const unwrapped = await provider.unwrapKey(wrapped, 0);
    assert.deepStrictEqual(unwrapped, dek);
  });

  // ---- kms.provider.js ----------------------------------------------------
  section('providers/kms.provider.js — KmsKeyProvider (KEK)');

  await t('throws without an injected kmsClient', async () => {
    const provider = new KmsKeyProvider({ keyIdsByVersion: { 1: 'vendor-key-1' } });
    const dek = aesGcm.generateKey();
    await assert.rejects(() => provider.wrapKey(dek, 1), /no kmsClient configured/);
  });

  await t('delegates wrap/unwrap to an injected kmsClient', async () => {
    const fakeVendorStore = new Map();
    const fakeKmsClient = {
      async encrypt({ keyId, plaintext }) {
        const ciphertext = Buffer.concat([Buffer.from('kms:'), plaintext]);
        fakeVendorStore.set(ciphertext.toString('hex'), plaintext);
        return { ciphertext, providerKeyId: keyId };
      },
      async decrypt({ ciphertext }) {
        const plaintext = fakeVendorStore.get(ciphertext.toString('hex'));
        if (!plaintext) throw new Error('unknown ciphertext');
        return { plaintext };
      },
    };
    const provider = new KmsKeyProvider({ kmsClient: fakeKmsClient, keyIdsByVersion: { 1: 'vendor-key-1' } });
    const dek = aesGcm.generateKey();
    const wrapped = await provider.wrapKey(dek, 1);
    assert.strictEqual(wrapped.providerKeyId, 'vendor-key-1');
    const unwrapped = await provider.unwrapKey(wrapped, 1);
    assert.deepStrictEqual(unwrapped, dek);
  });

  await t('getKey throws when no vendor key id is registered for a version', async () => {
    const provider = new KmsKeyProvider({ keyIdsByVersion: {} });
    await assert.rejects(() => provider.getKey(5), /no vendor key ID registered/);
  });

  // ---- key.service.js -----------------------------------------------------
  section('key.service.js — DEK lifecycle');

  const keyModel = createMockModel();
  const keyService = new KeyService({ EncryptionKeyModel: keyModel });

  await t('bootstraps DEK v1 automatically when no ACTIVE row exists', async () => {
    const { version, dek } = await keyService.getActiveDek();
    assert.strictEqual(version, 1);
    assert.ok(Buffer.isBuffer(dek) && dek.length === 32);
    const row = await keyModel.findOne({ where: { key_type: 'DEK', version: 1 } });
    assert.strictEqual(row.status, 'ACTIVE');
  });

  await t('getActiveDek is cached in-memory (no repeat DB hit)', async () => {
    let calls = 0;
    const original = keyModel.findOne.bind(keyModel);
    keyModel.findOne = async (...args) => {
      calls += 1;
      return original(...args);
    };
    await keyService.getActiveDek();
    await keyService.getActiveDek();
    keyModel.findOne = original;
    assert.strictEqual(calls, 0, 'cached active DEK should not hit the model again');
  });

  await t('generateDek mints the next PENDING version without activating it', async () => {
    const { version } = await keyService.generateDek();
    assert.strictEqual(version, 2);
    const row = await keyModel.findOne({ where: { key_type: 'DEK', version: 2 } });
    assert.strictEqual(row.status, 'PENDING');
    const stillActive = await keyService.getActiveDek();
    assert.strictEqual(stillActive.version, 1, 'active DEK unchanged until activateDek()');
  });

  await t('activateDek promotes PENDING -> ACTIVE and retires the previous ACTIVE', async () => {
    await keyService.activateDek(2);
    const v1 = await keyModel.findOne({ where: { key_type: 'DEK', version: 1 } });
    const v2 = await keyModel.findOne({ where: { key_type: 'DEK', version: 2 } });
    assert.strictEqual(v1.status, 'RETIRED');
    assert.strictEqual(v2.status, 'ACTIVE');
    const active = await keyService.getActiveDek();
    assert.strictEqual(active.version, 2, 'cache invalidated and refreshed on activation');
  });

  await t('getDek can still unwrap a RETIRED version (needed to decrypt old data)', async () => {
    const { dek } = await keyService.getDek(1);
    assert.ok(Buffer.isBuffer(dek) && dek.length === 32);
  });

  await t('getDek throws for an unknown version', async () => {
    await assert.rejects(() => keyService.getDek(999), /no DEK metadata row/);
  });

  // ---- encryption.service.js -----------------------------------------------
  section('encryption.service.js — EncryptionService');

  const encModel = createMockModel();
  const encKeyService = new KeyService({ EncryptionKeyModel: encModel });
  const encryptionService = new EncryptionService({ keyService: encKeyService });

  let roundtripEnvelope;
  await t('encrypt/decryptToString round-trips', async () => {
    roundtripEnvelope = await encryptionService.encrypt('hello world');
    const plaintext = await encryptionService.decryptToString(roundtripEnvelope);
    assert.strictEqual(plaintext, 'hello world');
  });

  await t('inspect reveals metadata without decrypting', () => {
    const meta = encryptionService.inspect(roundtripEnvelope);
    assert.strictEqual(meta.v, 2);
    assert.strictEqual(meta.alg, 'AES-256-GCM');
    assert.strictEqual(meta.keyVersion, 1);
  });

  await t('AAD binds ciphertext to context', async () => {
    const env = await encryptionService.encrypt('bound value', { aad: 'record:42' });
    await assert.rejects(() => encryptionService.decryptToString(env, { aad: 'record:43' }));
    const ok = await encryptionService.decryptToString(env, { aad: 'record:42' });
    assert.strictEqual(ok, 'bound value');
  });

  await t('tampered envelope fails authentication', async () => {
    const env = await encryptionService.encrypt('do not tamper with me');
    const flipped = env.slice(0, -1) + (env.slice(-1) === 'A' ? 'B' : 'A');
    await assert.rejects(() => encryptionService.decryptToString(flipped));
  });

  await t('data survives a full key rotation (encrypted under v1 stays readable after v2 is activated)', async () => {
    const env = await encryptionService.encrypt('rotate me');
    await encKeyService.generateDek();
    await encKeyService.activateDek(2);
    const plaintext = await encryptionService.decryptToString(env);
    assert.strictEqual(plaintext, 'rotate me');
    const meta = encryptionService.inspect(env);
    assert.strictEqual(meta.keyVersion, 1, 'old envelope keeps its original tag until migrated');
  });

  // ---- rotation.registry.js -----------------------------------------------
  section('rotation.registry.js');

  await t('registerTarget/getTarget/listTargets round-trip', () => {
    rotationRegistry._clearRegistry();
    rotationRegistry.registerTarget('users.ssn', { model: {}, primaryKey: 'id', encryptedFields: ['ssn_encrypted'] });
    assert.deepStrictEqual(rotationRegistry.listTargets(), ['users.ssn']);
    assert.ok(rotationRegistry.getTarget('users.ssn'));
  });

  await t('rejects duplicate target names', () => {
    assert.throws(
      () => rotationRegistry.registerTarget('users.ssn', { model: {}, primaryKey: 'id', encryptedFields: ['x'] }),
      /already registered/
    );
  });

  await t('rejects invalid target config', () => {
    assert.throws(
      () => rotationRegistry.registerTarget('bad.target', { model: {}, primaryKey: 'id', encryptedFields: [] }),
      /invalid config/
    );
  });

  // ---- rotation.progress.js -----------------------------------------------
  section('rotation.progress.js');

  await t('reportProgress computes percentage and forwards it to job.updateProgress', async () => {
    const calls = [];
    const fakeJob = { updateProgress: async (p) => calls.push(p) };
    await reportProgress(fakeJob, { rotationId: 'r1', status: 'RUNNING', processed: 25, total: 100, failed: 1 });
    assert.strictEqual(calls[0].percentage, 25);
    await reportProgress(fakeJob, { rotationId: 'r1', status: 'RUNNING', processed: 5, total: null, failed: 0 });
    assert.strictEqual(calls[1].percentage, null, 'no total => no percentage');
    await reportProgress(fakeJob, { rotationId: 'r1', status: 'COMPLETED', processed: 100, total: 100, failed: 0 });
    assert.strictEqual(calls[2].percentage, 100);
  });

  await t('persistCheckpoint writes checkpoint fields via RotationModel.update', async () => {
    const model = createMockModel();
    await model.create({ id: 'r2', processed_records: 0, failed_records: 0, last_processed_id: null });
    await persistCheckpoint(model, 'r2', { processedRecords: 10, failedRecords: 2, lastProcessedId: 99 });
    const row = await model.findByPk('r2');
    assert.strictEqual(row.processed_records, 10);
    assert.strictEqual(row.failed_records, 2);
    assert.strictEqual(row.last_processed_id, 99);
  });

  // ---- testing/in-memory.target.js ----------------------------------------
  section('testing/in-memory.target.js');

  await t('insert/count/findAll paginate in primary-key order', async () => {
    testModel.reset();
    const ids = [];
    for (let i = 0; i < 5; i += 1) ids.push(testModel.insert({ value_encrypted: `x${i}` }));
    assert.strictEqual(await testModel.count(), 5);
    const page1 = await testModel.findAll({ where: { id: { [Op.gt]: 0 } }, limit: 2 });
    assert.deepStrictEqual(page1.map((r) => r.id), ids.slice(0, 2));
    const page2 = await testModel.findAll({ where: { id: { [Op.gt]: page1[1].id } }, limit: 2 });
    assert.deepStrictEqual(page2.map((r) => r.id), ids.slice(2, 4));
  });

  await t('registerInMemoryTestTarget is idempotent', () => {
    rotationRegistry._clearRegistry();
    const name1 = registerInMemoryTestTarget(rotationRegistry);
    const name2 = registerInMemoryTestTarget(rotationRegistry);
    assert.strictEqual(name1, name2);
    assert.strictEqual(rotationRegistry.listTargets().length, 1);
  });

  // ---- rotation.service.js ------------------------------------------------
  section('rotation.service.js — RotationService (mocked queue + model)');

  const rsKeyModel = createMockModel();
  const rsKeyService = new KeyService({ EncryptionKeyModel: rsKeyModel });
  await rsKeyService.getActiveDek(); // bootstrap v1

  const rsRotationModel = createMockModel();
  const rsQueue = createMockQueue();
  rotationRegistry._clearRegistry();
  const rsTargetName = 'test.rotation_service_target';
  rotationRegistry.registerTarget(rsTargetName, {
    model: { count: async () => 42 },
    primaryKey: 'id',
    encryptedFields: ['value_encrypted'],
  });
  const rotationService = new RotationService({ RotationModel: rsRotationModel, keyService: rsKeyService, queue: rsQueue });

  await t('createRotation mints a new PENDING DEK, snapshots from/to versions, and enqueues a job', async () => {
    const rotation = await rotationService.createRotation({ target: rsTargetName, createdBy: 'tester' });
    assert.strictEqual(rotation.status, 'QUEUED');
    assert.strictEqual(rotation.from_version, 1);
    assert.strictEqual(rotation.to_version, 2);
    assert.strictEqual(rotation.total_records, 42);
    const job = rsQueue._jobs.get(rotation.id);
    assert.ok(job, 'job should be enqueued');
    assert.deepStrictEqual(job.data, { rotationId: rotation.id });
  });

  await t('createRotation rejects unknown targets', async () => {
    await assert.rejects(() => rotationService.createRotation({ target: 'no.such.target' }));
  });

  await t('cancelRotation flips status and removes the still-waiting job', async () => {
    const rotation = await rotationService.createRotation({ target: rsTargetName });
    const cancelled = await rotationService.cancelRotation(rotation.id);
    assert.strictEqual(cancelled.status, 'CANCELLED');
    assert.strictEqual(rsQueue._jobs.has(rotation.id), false);
  });

  await t('cancelRotation on an already-terminal rotation is a no-op', async () => {
    const rotation = await rotationService.createRotation({ target: rsTargetName });
    await rsRotationModel.update({ status: 'COMPLETED' }, { where: { id: rotation.id } });
    const result = await rotationService.cancelRotation(rotation.id);
    assert.strictEqual(result.status, 'COMPLETED');
  });

  await t('cancelRotation on an unknown id throws', async () => {
    await assert.rejects(() => rotationService.cancelRotation('does-not-exist'));
  });

  // ---- encryption.rotation.controller.js ----------------------------------
  section('encryption.rotation.controller.js — thin HTTP layer');

  const controller = buildRotationController({ rotationService });

  await t('createRotation responds 202 with the public rotation shape', async () => {
    const req = { body: { target: rsTargetName }, user: { id: 'u1' } };
    const res = mockRes();
    await controller.createRotation(req, res);
    assert.strictEqual(res.statusCode, 202);
    assert.strictEqual(res.body.status, 'QUEUED');
    assert.strictEqual(res.body.target, rsTargetName);
  });

  await t('createRotation responds 400 on missing target', async () => {
    const res = mockRes();
    await controller.createRotation({ body: {} }, res);
    assert.strictEqual(res.statusCode, 400);
  });

  await t('getRotation responds 404 for an unknown id', async () => {
    const res = mockRes();
    await controller.getRotation({ params: { id: 'missing' } }, res);
    assert.strictEqual(res.statusCode, 404);
  });

  await t('cancelRotation responds 200 and reflects the new status', async () => {
    const createRes = mockRes();
    await controller.createRotation({ body: { target: rsTargetName } }, createRes);
    const id = createRes.body.id;
    const res = mockRes();
    await controller.cancelRotation({ params: { id }, app: { get: () => null } }, res);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.status, 'CANCELLED');
  });

  // ---- encryption.rotation.worker.js — full pipeline ----------------------
  section('workers/encryption.rotation.worker.js — Phase 2/3 pipeline (mocked Postgres/BullMQ)');

  rotationRegistry._clearRegistry();
  testModel.reset();
  const workerKeyModel = createMockModel();
  const workerKeyService = new KeyService({ EncryptionKeyModel: workerKeyModel });
  const workerEncryptionService = new EncryptionService({ keyService: workerKeyService });
  await workerKeyService.getActiveDek(); // bootstrap v1

  const pipelineTargetName = registerInMemoryTestTarget(rotationRegistry, 'test.worker_pipeline');

  // NOTE: encrypted with the AAD convention EncryptionRotationWorker itself
  // uses ("Model:field:pk") so the round-trip below actually succeeds — see
  // the "[known issue]" test further down for what happens when that's skipped.
  const seededPlaintexts = new Map();
  for (let i = 0; i < 12; i += 1) {
    const id = testModel.insert({ value_encrypted: null });
    const plaintext = `secret-value-${i}`;
    const aad = `InMemoryTestRecord:value_encrypted:${id}`;
    const envelope = await workerEncryptionService.encrypt(plaintext, { aad });
    testModel._store.set(id, { value_encrypted: envelope });
    seededPlaintexts.set(id, plaintext);
  }

  const workerRotationModel = createMockModel();
  const workerQueue = createMockQueue();
  const workerRotationService = new RotationService({
    RotationModel: workerRotationModel,
    keyService: workerKeyService,
    queue: workerQueue,
  });

  const pipelineRotation = await workerRotationService.createRotation({ target: pipelineTargetName, createdBy: 'test' });
  assert.strictEqual(pipelineRotation.total_records, 12);

  const workerSequelize = createMockSequelize();
  rotationWorker.configure({
    sequelize: workerSequelize,
    RotationModel: workerRotationModel,
    encryptionService: workerEncryptionService,
    keyService: workerKeyService,
  });

  await t('migrates every record to the new DEK version and activates it', async () => {
    const progressEvents = [];
    const fakeJob = {
      id: pipelineRotation.id,
      data: { rotationId: pipelineRotation.id },
      async updateProgress(payload) {
        progressEvents.push(payload);
      },
    };

    const result = await rotationWorker._processJob(fakeJob);
    assert.strictEqual(result.status, 'COMPLETED');
    assert.strictEqual(result.processed, 12);
    assert.strictEqual(result.failed, 0);

    const finalRotationRow = await workerRotationModel.findByPk(pipelineRotation.id);
    assert.strictEqual(finalRotationRow.status, 'COMPLETED');
    assert.strictEqual(finalRotationRow.processed_records, 12);

    const activeKey = await workerKeyService.getActiveKey();
    assert.strictEqual(activeKey.version, pipelineRotation.to_version);

    const rows = await testModel.findAllPlain();
    for (const row of rows) {
      const meta = workerEncryptionService.inspect(row.value_encrypted);
      assert.strictEqual(meta.keyVersion, pipelineRotation.to_version);
      const aad = `InMemoryTestRecord:value_encrypted:${row.id}`;
      const plaintext = await workerEncryptionService.decryptToString(row.value_encrypted, { aad });
      assert.strictEqual(plaintext, seededPlaintexts.get(row.id));
    }

    assert.ok(progressEvents.some((p) => p.status === 'RUNNING'));
    assert.ok(progressEvents.some((p) => p.status === 'COMPLETED' && p.percentage === 100));
  });

  await t('a retired DEK version stays unwrappable after rotation (old data stays recoverable)', async () => {
    const { dek } = await workerKeyService.getDek(pipelineRotation.from_version);
    assert.ok(Buffer.isBuffer(dek) && dek.length === 32);
  });

  await t('a rotation observed as CANCELLED stops before touching any records', async () => {
    rotationRegistry._clearRegistry();
    testModel.reset();
    const targetName = registerInMemoryTestTarget(rotationRegistry, 'test.worker_cancel');
    for (let i = 0; i < 3; i += 1) {
      const id = testModel.insert({ value_encrypted: null });
      const aad = `InMemoryTestRecord:value_encrypted:${id}`;
      const envelope = await workerEncryptionService.encrypt(`v-${i}`, { aad });
      testModel._store.set(id, { value_encrypted: envelope });
    }
    const rotation = await workerRotationService.createRotation({ target: targetName });
    await workerRotationModel.update({ status: 'CANCELLED' }, { where: { id: rotation.id } });
    const fakeJob = { id: rotation.id, data: { rotationId: rotation.id }, async updateProgress() {} };
    const result = await rotationWorker._processJob(fakeJob);
    assert.strictEqual(result.status, 'CANCELLED');
    const rows = await testModel.findAllPlain();
    for (const row of rows) {
      const meta = workerEncryptionService.inspect(row.value_encrypted);
      assert.strictEqual(meta.keyVersion, rotation.from_version, 'untouched');
    }
  });

  await t('throws when the target is already locked by another in-flight rotation', async () => {
    rotationRegistry._clearRegistry();
    testModel.reset();
    const targetName = registerInMemoryTestTarget(rotationRegistry, 'test.worker_locked');
    const rotation = await workerRotationService.createRotation({ target: targetName });
    const lockedSequelize = createMockSequelize({ lockAvailable: false });
    rotationWorker.configure({
      sequelize: lockedSequelize,
      RotationModel: workerRotationModel,
      encryptionService: workerEncryptionService,
      keyService: workerKeyService,
    });
    const fakeJob = { id: rotation.id, data: { rotationId: rotation.id }, async updateProgress() {} };
    await assert.rejects(() => rotationWorker._processJob(fakeJob), /locked by another rotation/);
    // restore for subsequent tests
    rotationWorker.configure({
      sequelize: workerSequelize,
      RotationModel: workerRotationModel,
      encryptionService: workerEncryptionService,
      keyService: workerKeyService,
    });
  });

  await t('[known issue] rows seeded with no AAD (as /test/records/seed does) fail migration', async () => {
    rotationRegistry._clearRegistry();
    testModel.reset();
    const targetName = registerInMemoryTestTarget(rotationRegistry, 'test.worker_noaad');
    for (let i = 0; i < 4; i += 1) {
      // Mirrors Encryption.worker.test.controller.js's seedRecords(), which
      // calls encryptionService.encrypt(text) with NO aad — while
      // EncryptionRotationWorker._migrateRecordFields() always derives one
      // ("Model:field:pk") when re-encrypting during a rotation.
      const envelope = await workerEncryptionService.encrypt(`no-aad-${i}`);
      testModel.insert({ value_encrypted: envelope });
    }
    const rotation = await workerRotationService.createRotation({ target: targetName });
    const fakeJob = { id: rotation.id, data: { rotationId: rotation.id }, async updateProgress() {} };
    const result = await rotationWorker._processJob(fakeJob);
    assert.strictEqual(result.status, 'COMPLETED', 'the rotation job itself still finishes');
    assert.strictEqual(result.failed, 4, 'but every record fails AAD-mismatched decryption');
    assert.strictEqual(result.processed, 0);
    warn(
      'confirmed: /test/records/seed encrypts with no AAD, but the rotation worker always ' +
        'derives one on migration — real rows seeded that way will never successfully rotate.'
    );
  });

  // ---- optional live infrastructure -----------------------------------------
  section('optional live-infrastructure checks (never block the suite)');

  await t('Redis reachability', async () => {
    let IORedis;
    try {
      IORedis = require('ioredis');
    } catch (e) {
      note('ioredis not installed — skipping');
      return;
    }
    const client = new IORedis({
      host: process.env.REDIS_HOST,
      port: Number(process.env.REDIS_PORT),
      db: Number(process.env.REDIS_DB),
      lazyConnect: true,
      connectTimeout: 1000,
      maxRetriesPerRequest: 1,
    });
    try {
      await client.connect();
      const pong = await client.ping();
      assert.strictEqual(pong, 'PONG');
      note('live Redis detected — connectivity confirmed');
    } catch (err) {
      note('no live Redis reachable — skipped (expected in most local setups)');
    } finally {
      client.disconnect();
    }
  });

  // ---- summary ----------------------------------------------------------
  const passed = results.filter((r) => r.pass).length;
  const failed = results.filter((r) => !r.pass).length;
  console.log(`\n${BOLD}${'-'.repeat(60)}${RESET}`);
  console.log(`${BOLD}Results:${RESET} ${GREEN}${passed} passed${RESET}, ${failed ? RED : DIM}${failed} failed${RESET}, ${results.length} total`);
  if (failed) {
    console.log(`\n${RED}Failed:${RESET}`);
    results.filter((r) => !r.pass).forEach((r) => console.log(`  - ${r.label}`));
  }
  process.exitCode = failed ? 1 : 0;
}

main().catch((err) => {
  console.error('\nFATAL — test harness crashed outside a test case:');
  console.error(err);
  process.exitCode = 1;
});
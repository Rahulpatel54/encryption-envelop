#!/usr/bin/env node
'use strict';

/**
 * test-encryption-pipeline.js
 * ---------------------------------------------------------------------------
 * One master script that exercises the ENTIRE envelope-encryption + DEK
 * rotation pipeline, end to end:
 *
 *   HTTP route -> Express controller -> RotationService/EncryptionService
 *   -> KeyService (KEK/DEK) -> Postgres (encryption_keys, encryption_rotations)
 *   -> BullMQ (Redis) -> EncryptionRotationWorker -> Postgres (data rows)
 *   -> QueueEvents -> Socket.IO ("rotation:<id>" room) -> client
 *
 * WHAT IT NEEDS RUNNING FIRST (this script does not start any of these):
 *   1. The Express app, with NODE_ENV != 'production' (so /encryption/test/*
 *      routes are mounted) — see Encryption.test.routes.js.
 *   2. Redis, reachable at the app's configured REDIS_HOST/PORT/DB.
 *   3. Postgres, migrated (encryption_keys + encryption_rotations tables).
 *   4. The EncryptionRotationWorker process running and configure()'d
 *      (see the wiring comment block at the bottom of
 *      app/workers/encryption.rotation.worker.js) — without it, rotations
 *      will sit QUEUED forever and this script will report that clearly.
 *
 * USAGE
 *   node scripts/test-encryption-pipeline.js
 *
 * CONFIG (env vars, all optional)
 *   BASE_URL            default http://localhost:3000
 *   ENCRYPTION_PATH     default /encryption            (mount point of both route files)
 *   AUTH_HEADER         e.g. "Bearer <jwt>" — sent as Authorization on the
 *                        casbin-protected production /encryption/rotations*
 *                        endpoints. Without it those steps are SKIPPED
 *                        (not failed) and the script falls back to verifying
 *                        the same pipeline through the unauthenticated
 *                        /encryption/test/* routes instead.
 *   AUTH_COOKIE         alternative to AUTH_HEADER, sent as Cookie
 *   SEED_COUNT          default 15   — disposable rows migrated per rotation
 *   POLL_INTERVAL_MS    default 500
 *   POLL_TIMEOUT_MS     default 30000
 *   VERBOSE             set to "1" to dump full JSON bodies on each step
 *
 * EXIT CODE: 0 if every non-skipped step passed, 1 otherwise (CI-friendly).
 * ---------------------------------------------------------------------------
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const ENCRYPTION_PATH = process.env.ENCRYPTION_PATH || '/encryption';
const API = `${BASE_URL}${ENCRYPTION_PATH}`;
const AUTH_HEADER = process.env.AUTH_HEADER || null;
const AUTH_COOKIE = process.env.AUTH_COOKIE || null;
const SEED_COUNT = Number(process.env.SEED_COUNT || 15);
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 500);
const POLL_TIMEOUT_MS = Number(process.env.POLL_TIMEOUT_MS || 30000);
const VERBOSE = process.env.VERBOSE === '1';
const SOCKET_NAMESPACE = '/encryption-rotations';

if (typeof fetch !== 'function') {
  console.error('This script needs Node 18+ (global fetch). Please upgrade Node and retry.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// tiny test harness
// ---------------------------------------------------------------------------

const results = [];
function record(status, name, detail) {
  results.push({ status, name, detail });
  const badge = { PASS: '✅', FAIL: '❌', SKIP: '⏭ ' }[status];
  console.log(`${badge} ${name}${detail ? ' — ' + detail : ''}`);
}
const pass = (name, detail) => record('PASS', name, detail);
const fail = (name, detail) => record('FAIL', name, detail);
const skip = (name, detail) => record('SKIP', name, detail);

function assertTrue(cond, msg) {
  if (!cond) throw new Error(msg);
}

/** Runs one named step; any thrown error becomes a FAIL for that step, and execution continues. */
async function step(name, fn) {
  try {
    const detail = await fn();
    pass(name, detail);
    return { ok: true, value: detail };
  } catch (err) {
    fail(name, err.message);
    return { ok: false, error: err };
  }
}

async function httpJson(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (AUTH_HEADER) headers.Authorization = AUTH_HEADER;
  if (AUTH_COOKIE) headers.Cookie = AUTH_COOKIE;
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let json = null;
  const text = await res.text();
  try {
    json = text ? JSON.parse(text) : null;
  } catch (_) {
    /* non-JSON response, leave json null */
  }
  if (VERBOSE) {
    console.log(`  ${method} ${path} -> ${res.status}`, json ?? text);
  }
  return { status: res.status, json, text };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollUntil(fn, predicate, { intervalMs = POLL_INTERVAL_MS, timeoutMs = POLL_TIMEOUT_MS } = {}) {
  const start = Date.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const value = await fn();
    if (predicate(value)) return value;
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for condition`);
    }
    await sleep(intervalMs);
  }
}

// ---------------------------------------------------------------------------
// optional realtime layer: subscribe to the rotation's Socket.IO room so we
// can prove QueueEvents -> namespace -> client actually fires, not just poll
// ---------------------------------------------------------------------------

async function connectRotationSocket() {
  let ioClient;
  try {
    // eslint-disable-next-line global-require
    ({ io: ioClient } = require('socket.io-client'));
  } catch (_) {
    return null; // optional dependency not installed — caller treats as SKIP
  }
  const socket = ioClient(`${BASE_URL}${SOCKET_NAMESPACE}`, {
    transports: ['websocket'],
    reconnection: false,
    timeout: 5000,
  });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('socket connect timeout')), 5000);
    socket.on('connect', () => {
      clearTimeout(t);
      resolve();
    });
    socket.on('connect_error', (err) => {
      clearTimeout(t);
      reject(err);
    });
  });
  return socket;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`\nEncryption pipeline test — target: ${BASE_URL}\n`);

  // 1. Redis reachability (independent of BullMQ) -------------------------
  await step('redis-ping', async () => {
    const { status, json } = await httpJson('GET', `${ENCRYPTION_PATH}/test/redis-ping`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(json && (json.reply === 'PONG' || json.reply === 'pong'), `unexpected reply: ${JSON.stringify(json)}`);
    return `latency ${json.latencyMs}ms`;
  });

  // 2. Active KEK info ------------------------------------------------------
  await step('active-kek-info', async () => {
    const { status, json } = await httpJson('GET', `${ENCRYPTION_PATH}/test/active-key`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(typeof json.version === 'number', 'missing KEK version');
    assertTrue(typeof json.provider === 'string', 'missing KEK provider');
    return `provider=${json.provider} version=${json.version}`;
  });

  // 3. BullMQ + Redis round trip (isolated queue, doesn't touch rotation state)
  await step('bullmq-echo', async () => {
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/bullmq-echo`, { payload: { ping: true } });
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(json.ok === true, 'echo did not report ok:true');
    assertTrue(json.result && json.result.echoed && json.result.echoed.ping === true, 'echoed payload mismatch');
    return 'queue + worker + redis round trip confirmed';
  });

  // 4. Rotation queue health + worker process presence ----------------------
  let workerRunning = false;
  await step('queue-health (initial)', async () => {
    const { status, json } = await httpJson('GET', `${ENCRYPTION_PATH}/test/queue-health`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    workerRunning = json.workerRunning === true;
    return `queue=${json.queue} counts=${JSON.stringify(json.counts)} workerRunning=${json.workerRunning}`;
  });
  if (!workerRunning) {
    console.warn(
      '\n⚠️  workerRunning=false — EncryptionRotationWorker does not appear to be started.\n' +
        '    Rotation steps below will be exercised but will likely stay QUEUED.\n' +
        '    Start it via your worker process entrypoint before re-running for full coverage.\n'
    );
  }

  // 5. Crypto layer: roundtrip, inspect, tamper/AAD checks ------------------
  let sampleEnvelope = null;
  await step('crypto-roundtrip', async () => {
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/roundtrip`, {
      plaintext: 'pipeline-check-secret',
      aad: 'pipeline-aad',
    });
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(json.matched === true, 'decrypted value did not match plaintext');
    sampleEnvelope = json.envelope;
    return 'encrypt -> decrypt round trip matched';
  });

  await step('crypto-inspect', async () => {
    assertTrue(sampleEnvelope, 'no envelope from previous step');
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/inspect`, { envelope: sampleEnvelope });
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(json.alg === 'AES-256-GCM', `unexpected alg: ${json.alg}`);
    assertTrue(typeof json.keyVersion === 'number', 'missing keyVersion on envelope');
    return `alg=${json.alg} keyVersion=${json.keyVersion}`;
  });

  await step('crypto-rejects-missing-aad', async () => {
    assertTrue(sampleEnvelope, 'no envelope from previous step');
    // encrypted with aad "pipeline-aad" — decrypting with none must fail auth
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/decrypt`, { envelope: sampleEnvelope });
    assertTrue(status === 400, `expected 400 (auth failure), got ${status}`);
    assertTrue(json && json.error === 'decryption failed', `unexpected error body: ${JSON.stringify(json)}`);
    return 'GCM auth-tag check correctly rejected mismatched AAD';
  });

  await step('crypto-rejects-corrupted-envelope', async () => {
    const corrupted = sampleEnvelope.slice(0, -4) + 'abcd';
    const { status } = await httpJson('POST', `${ENCRYPTION_PATH}/test/inspect`, { envelope: corrupted });
    assertTrue(status === 400, `expected 400 for corrupted envelope, got ${status}`);
    return 'malformed envelope correctly rejected';
  });

  // 6. Seed disposable rows, confirm baseline state -------------------------
  await step('records-reset', async () => {
    const { status } = await httpJson('POST', `${ENCRYPTION_PATH}/test/records/reset`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    return 'in-memory test rows cleared';
  });

  await step('records-seed', async () => {
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/records/seed`, {
      count: SEED_COUNT,
      text: 'pipeline-value',
    });
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(json.inserted === SEED_COUNT, `expected ${SEED_COUNT} inserted, got ${json.inserted}`);
    return `${json.inserted} disposable rows seeded`;
  });

  let fromVersion = null;
  const listResult = await step('records-list (pre-rotation baseline)', async () => {
    const { status, json } = await httpJson('GET', `${ENCRYPTION_PATH}/test/records`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    assertTrue(json.count === SEED_COUNT, `expected ${SEED_COUNT} records, got ${json.count}`);
    const versions = new Set(json.records.map((r) => r.keyVersion));
    assertTrue(versions.size === 1, `expected all rows on one key version, saw ${[...versions]}`);
    fromVersion = [...versions][0];
    return `all ${json.count} rows on keyVersion=${fromVersion}`;
  });
  if (!listResult.ok) {
    console.error('\nCannot continue rotation tests without a seeded baseline. Aborting.\n');
    return finish();
  }

  // 7. Optional realtime socket subscription, set up BEFORE starting the job
  let socket = null;
  const socketEvents = [];
  const socketStep = await step('socket-connect (optional)', async () => {
    socket = await connectRotationSocket();
    if (!socket) {
      throw Object.assign(new Error('socket.io-client not installed — run `npm i -D socket.io-client` to enable this check'), {
        __skip: true,
      });
    }
    return 'connected to /encryption-rotations namespace';
  });
  if (!socketStep.ok && socketStep.error.__skip) {
    results.pop(); // undo the FAIL just recorded
    skip('socket-connect (optional)', socketStep.error.message);
  }

  // 8. Drive a REAL rotation through the full pipeline ----------------------
  let rotationId = null;
  let toVersion = null;
  const startResult = await step('start-rotation (POST /test/rotation)', async () => {
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/rotation`, {});
    assertTrue(status === 202, `expected 202, got ${status}`);
    rotationId = json.rotationId;
    toVersion = json.toVersion;
    assertTrue(rotationId, 'no rotationId returned');
    assertTrue(typeof toVersion === 'number' && toVersion > fromVersion, `expected toVersion > ${fromVersion}, got ${toVersion}`);
    if (socket) socket.emit('rotation:subscribe', rotationId);
    return `rotationId=${rotationId} from=${fromVersion} to=${toVersion}`;
  });

  if (socket) {
    ['rotation:progress', 'rotation:completed', 'rotation:failed', 'rotation:cancelled'].forEach((evt) => {
      socket.on(evt, (payload) => socketEvents.push({ evt, payload }));
    });
  }

  if (!startResult.ok) {
    console.error('\nCannot continue: rotation failed to start. Aborting remaining rotation checks.\n');
    if (socket) socket.close();
    return finish();
  }

  // 9. Verify migration converges (Phase 2) — this is the core proof that
  //    route -> service -> BullMQ -> Redis -> worker -> Postgres all wired up
  await step('rotation-migrates-all-records (Phase 2)', async () => {
    const final = await pollUntil(
      async () => {
        const { json } = await httpJson('GET', `${ENCRYPTION_PATH}/test/records`);
        return json;
      },
      (json) => json.count === SEED_COUNT && json.records.every((r) => r.keyVersion === toVersion)
    );
    assertTrue(final.records.every((r) => r.keyVersion === toVersion), 'not all records migrated to toVersion');
    return `all ${final.count} rows migrated to keyVersion=${toVersion}`;
  });

  // 10. Verify Phase 3 activation: brand-new writes now use the new DEK ----
  await step('new-writes-use-activated-dek (Phase 3)', async () => {
    const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/test/encrypt`, { plaintext: 'post-rotation-write' });
    assertTrue(status === 200, `expected 200, got ${status}`);
    const inspectRes = await httpJson('POST', `${ENCRYPTION_PATH}/test/inspect`, { envelope: json.envelope });
    assertTrue(inspectRes.json.keyVersion === toVersion, `expected new writes on keyVersion=${toVersion}, got ${inspectRes.json.keyVersion}`);
    return `new encrypt() calls now use keyVersion=${toVersion}`;
  });

  // 11. Give the socket a moment to catch up, then check we actually heard
  //     real-time progress from the BullMQ QueueEvents -> Socket.IO bridge
  if (socket) {
    await sleep(1000);
    await step('socket-received-rotation-events', async () => {
      const forThisRotation = socketEvents.filter((e) => e.payload && e.payload.rotationId === rotationId);
      assertTrue(forThisRotation.length > 0, 'no socket events observed for this rotation');
      const sawCompleted = forThisRotation.some((e) => e.evt === 'rotation:completed');
      return `${forThisRotation.length} event(s) received${sawCompleted ? ', including completion' : ''}`;
    });
    socket.close();
  }

  // 12. Queue health after the dust settles ---------------------------------
  await step('queue-health (final)', async () => {
    const { status, json } = await httpJson('GET', `${ENCRYPTION_PATH}/test/queue-health`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    return `counts=${JSON.stringify(json.counts)}`;
  });

  // 13. Authenticated production management API (create/get/cancel) -------
  //     These sit behind casbinMiddleware; without AUTH_HEADER/AUTH_COOKIE
  //     configured they're expected to be rejected — that's a SKIP, not a
  //     FAIL, since it just means "run this with real credentials to cover it".
  if (!AUTH_HEADER && !AUTH_COOKIE) {
    skip('production-rotations-api (create/get/cancel)', 'set AUTH_HEADER or AUTH_COOKIE env var to exercise the casbin-protected /encryption/rotations* endpoints');
  } else {
    let prodRotationId = null;
    await step('production-create-rotation (POST /rotations)', async () => {
      const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/rotations`, { target: 'test.in_memory_echo' });
      assertTrue(status === 202, `expected 202, got ${status}: ${JSON.stringify(json)}`);
      prodRotationId = json.id;
      assertTrue(prodRotationId, 'no rotation id returned');
      return `id=${prodRotationId} from=${json.fromVersion} to=${json.toVersion}`;
    });

    if (prodRotationId) {
      await step('production-get-rotation (GET /rotations/:id)', async () => {
        const { status, json } = await httpJson('GET', `${ENCRYPTION_PATH}/rotations/${prodRotationId}`);
        assertTrue(status === 200, `expected 200, got ${status}`);
        assertTrue(json.id === prodRotationId, 'id mismatch');
        return `status=${json.status}`;
      });

      await step('production-cancel-rotation (POST /rotations/:id/cancel)', async () => {
        const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/rotations/${prodRotationId}/cancel`);
        assertTrue(status === 200, `expected 200, got ${status}`);
        assertTrue(['CANCELLED', 'COMPLETED'].includes(json.status), `unexpected terminal status: ${json.status}`);
        return `status=${json.status}`;
      });
    }

    await step('production-create-rotation-rejects-missing-target', async () => {
      const { status, json } = await httpJson('POST', `${ENCRYPTION_PATH}/rotations`, {});
      assertTrue(status === 400, `expected 400, got ${status}`);
      assertTrue(json && /target/i.test(json.error || ''), `unexpected error: ${JSON.stringify(json)}`);
      return 'validation correctly rejected missing target';
    });
  }

  // 14. Cleanup --------------------------------------------------------------
  await step('records-cleanup', async () => {
    const { status } = await httpJson('POST', `${ENCRYPTION_PATH}/test/records/reset`);
    assertTrue(status === 200, `expected 200, got ${status}`);
    return 'in-memory test rows cleared';
  });

  return finish();
}

function finish() {
  const failed = results.filter((r) => r.status === 'FAIL');
  const skipped = results.filter((r) => r.status === 'SKIP');
  const passed = results.filter((r) => r.status === 'PASS');
  console.log(`\n${passed.length} passed, ${failed.length} failed, ${skipped.length} skipped\n`);
  if (failed.length > 0) {
    console.log('Failures:');
    failed.forEach((r) => console.log(`  - ${r.name}: ${r.detail}`));
    console.log('');
  }
  process.exit(failed.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('\nFatal error running pipeline test:', err);
  process.exit(1);
});
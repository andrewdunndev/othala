// Tests for the in-process OIDC client reconciler in src/server/registrar.ts.
//
// All tests use injectable stubs — no live Hydra is contacted and no real
// manifests are read from disk. Delays are passed as baseDelayMs=1 so the
// retry tests run in milliseconds.
//
// Run with: npx vitest run scripts/registrar.test.mjs

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';

// Imports the reconciler's TypeScript source directly (not the built .mjs).
import {
  reconcileClients,
  reconcileOnBoot,
  reloadOnSighup,
} from '../src/server/registrar.ts';

// Import invalidateManifestCache to spy on its effect.
import { invalidateManifestCache } from '../src/lib/manifests.ts';

// ── helpers ────────────────────────────────────────────────────────────────

/** A stub register that returns a fixed result list. */
function stubRegister(results = [{ action: 'created', clientId: 'x' }]) {
  let callCount = 0;
  async function register() {
    callCount++;
    return results;
  }
  register.callCount = () => callCount;
  return register;
}

/** A stub register that fails N times then succeeds. */
function stubRegisterFailN(failTimes, successResult = [{ action: 'created', clientId: 'y' }]) {
  let calls = 0;
  async function register() {
    calls++;
    if (calls <= failTimes) {
      throw new Error(`stub failure #${calls}`);
    }
    return successResult;
  }
  register.callCount = () => calls;
  return register;
}

/** A stub register that always rejects. */
function stubRegisterAlwaysFails() {
  let calls = 0;
  async function register() {
    calls++;
    throw new Error(`always-failing stub call #${calls}`);
  }
  register.callCount = () => calls;
  return register;
}

// ── reconcileClients ───────────────────────────────────────────────────────

test('reconcileClients calls the injected register and logs each result', async () => {
  const reg = stubRegister([{ action: 'created', clientId: 'x' }]);
  const logs = [];
  const origLog = console.log;
  console.log = (...args) => logs.push(args.join(' '));
  try {
    await reconcileClients(reg);
  } finally {
    console.log = origLog;
  }
  assert.equal(reg.callCount(), 1, 'register should be called once');
  assert.ok(
    logs.some((l) => l.includes('created') && l.includes('x')),
    'should log "created x"',
  );
  assert.ok(
    logs.some((l) => l.includes('1 client(s) processed')),
    'should log total count',
  );
});

test('reconcileClients single-flight: second concurrent call returns without calling register twice', async () => {
  // A register that blocks until we release it.
  let releaseFirst;
  const blocked = new Promise((resolve) => { releaseFirst = resolve; });

  let callCount = 0;
  const blockingRegister = async () => {
    callCount++;
    await blocked;
    return [{ action: 'created', clientId: 'z' }];
  };

  // Suppress console output for this test.
  const origWarn = console.warn;
  const origLog = console.log;
  const origError = console.error;
  console.warn = () => {};
  console.log = () => {};
  console.error = () => {};

  try {
    // Start first call (will block inside register).
    const first = reconcileClients(blockingRegister);

    // Give the first call a tick to enter the reconciling=true state.
    await new Promise((resolve) => setImmediate(resolve));

    // Second concurrent call — should be a no-op.
    await reconcileClients(blockingRegister);

    // Assert second call did NOT invoke register.
    assert.equal(callCount, 1, 'register should only be called once — second call is a no-op');

    // Unblock first call and await it.
    releaseFirst();
    await first;
  } finally {
    console.warn = origWarn;
    console.log = origLog;
    console.error = origError;
  }
});

// ── reloadOnSighup ─────────────────────────────────────────────────────────

test('reloadOnSighup invalidates the manifest cache then calls the injected register', async () => {
  // We can't easily observe the cache pointer directly from outside the module,
  // but we can confirm: (1) reloadOnSighup calls register (= reconcileClients ran),
  // and (2) it does not throw even when register rejects.
  const reg = stubRegister([{ action: 'updated', clientId: 'filedrop' }]);

  const origLog = console.log;
  console.log = () => {};
  try {
    await reloadOnSighup(reg);
  } finally {
    console.log = origLog;
  }

  assert.equal(reg.callCount(), 1, 'register should be called after cache invalidation');
});

test('reloadOnSighup does NOT throw when register rejects (swallows, serves on)', async () => {
  const failing = stubRegisterAlwaysFails();

  const origLog = console.log;
  const origError = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    // Must not throw.
    await assert.doesNotReject(() => reloadOnSighup(failing));
  } finally {
    console.log = origLog;
    console.error = origError;
  }

  assert.equal(failing.callCount(), 1, 'failing register should still have been called once');
});

// ── reconcileOnBoot ────────────────────────────────────────────────────────

test('reconcileOnBoot retries on failure then succeeds without throwing', async () => {
  // Fails 2 times, succeeds on 3rd attempt.
  const reg = stubRegisterFailN(2);

  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};

  try {
    await assert.doesNotReject(() => reconcileOnBoot(reg, 5, 1));
  } finally {
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;
  }

  // Called 3 times: fail, fail, succeed.
  assert.equal(reg.callCount(), 3, 'register should be called until success');
});

test('reconcileOnBoot gives up after `attempts` exhausted without throwing', async () => {
  const failing = stubRegisterAlwaysFails();

  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  const errors = [];
  console.log = () => {};
  console.warn = () => {};
  console.error = (...args) => errors.push(args.join(' '));

  try {
    // Must NOT throw even after all attempts exhausted.
    await assert.doesNotReject(() => reconcileOnBoot(failing, 3, 1));
  } finally {
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;
  }

  // Called exactly `attempts` times.
  assert.equal(failing.callCount(), 3, 'register should be called exactly `attempts` times');

  // Logs the "gave up" message.
  assert.ok(
    errors.some((e) => e.includes('gave up') || e.includes('SIGHUP to retry')),
    'should log the give-up message with SIGHUP hint',
  );
});

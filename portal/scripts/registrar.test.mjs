// Invariant: reconciliation is single-flight, boot retries with capped backoff until Hydra answers, and a failing register never stops the server.

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';

import {
  lastReconcileOk,
  reconcileClients,
  reconcileOnBoot,
  reloadOnSighup,
} from '../src/server/registrar.ts';

import { invalidateManifestCache } from '../src/lib/manifests.ts';

function stubRegister(results = [{ action: 'created', clientId: 'x' }]) {
  let callCount = 0;
  async function register() {
    callCount++;
    return results;
  }
  register.callCount = () => callCount;
  return register;
}

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

function stubRegisterAlwaysFails() {
  let calls = 0;
  async function register() {
    calls++;
    throw new Error(`always-failing stub call #${calls}`);
  }
  register.callCount = () => calls;
  return register;
}

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
    logs.some((l) => /reconcile complete.*1 client\(s\) processed/.test(l)),
    'should log the reconcile complete line',
  );
});

test('reconcileClients single-flight: concurrent calls return at once and queue exactly one rerun', async () => {
  let releaseFirst;
  const blocked = new Promise((resolve) => { releaseFirst = resolve; });

  let callCount = 0;
  const blockingRegister = async () => {
    callCount++;
    await blocked;
    return [{ action: 'created', clientId: 'z' }];
  };

  const origWarn = console.warn;
  const origLog = console.log;
  const origError = console.error;
  console.warn = () => {};
  console.log = () => {};
  console.error = () => {};

  try {
    const first = reconcileClients(blockingRegister);

    await new Promise((resolve) => setImmediate(resolve));

    await reconcileClients(blockingRegister);
    await reconcileClients(blockingRegister);

    assert.equal(callCount, 1, 'concurrent calls do not run register in parallel');

    releaseFirst();
    await first;
    assert.equal(callCount, 2, 'the calls made mid-pass collapse into one rerun');
  } finally {
    console.warn = origWarn;
    console.log = origLog;
    console.error = origError;
  }
});

test('reloadOnSighup invalidates the manifest cache then calls the injected register', async () => {
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
    await assert.doesNotReject(() => reloadOnSighup(failing));
  } finally {
    console.log = origLog;
    console.error = origError;
  }

  assert.equal(failing.callCount(), 1, 'failing register should still have been called once');
});

test('reconcileOnBoot retries on failure then succeeds without throwing', async () => {
  const reg = stubRegisterFailN(2);

  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};

  try {
    await assert.doesNotReject(() => reconcileOnBoot(reg, 1, 4));
  } finally {
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;
  }

  assert.equal(reg.callCount(), 3, 'register should be called until success');
});

test('reconcileOnBoot keeps retrying past the old give-up point and logs each backoff step once', async () => {
  const reg = stubRegisterFailN(12);

  const origLog = console.log;
  const origWarn = console.warn;
  const origError = console.error;
  const lines = [];
  console.log = () => {};
  console.warn = (...args) => lines.push(args.join(' '));
  console.error = (...args) => lines.push(args.join(' '));

  try {
    await assert.doesNotReject(() => reconcileOnBoot(reg, 1, 4));
  } finally {
    console.log = origLog;
    console.warn = origWarn;
    console.error = origError;
  }

  assert.equal(reg.callCount(), 13, 'register is retried until it succeeds');
  assert.equal(lastReconcileOk(), true);
  for (const step of [1, 2, 4]) {
    assert.equal(lines.filter((l) => l.includes(`retrying in ${step}ms`)).length, 1, `delay ${step}ms is logged once`);
  }
  assert.ok(lines.length <= 5, `failures are not logged per attempt (${lines.length} lines)`);
  assert.ok(!lines.some((l) => l.includes('gave up')));
});

test('lastReconcileOk is false after a failed pass and true again after a good one', async () => {
  const origLog = console.log;
  const origError = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    await assert.rejects(reconcileClients(stubRegisterAlwaysFails()));
    assert.equal(lastReconcileOk(), false);
    await reconcileClients(stubRegister());
    assert.equal(lastReconcileOk(), true);
  } finally {
    console.log = origLog;
    console.error = origError;
  }
});

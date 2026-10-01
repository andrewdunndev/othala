// Invariant: sendInviteRecoveryEmail targets only the confirmed identity address.

import { test, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { sendInviteRecoveryEmail } from '../src/lib/kratos.ts';

const realFetch = globalThis.fetch;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function installFetch({ initStatus = 200, flowId = 'flow-abc', submitStatus = 200 } = {}) {
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = String(typeof input === 'string' ? input : input?.url ?? input);
    calls.push({
      url,
      method: init.method ?? 'GET',
      headers: init.headers ?? {},
      body: init.body ? JSON.parse(init.body) : undefined,
    });
    if (url.includes('/self-service/recovery/api')) {
      if (initStatus < 200 || initStatus >= 300) {
        return new Response('', { status: initStatus });
      }
      return jsonResponse(flowId === null ? {} : { id: flowId }, initStatus);
    }
    if (url.includes('/self-service/recovery')) {
      return jsonResponse({ state: 'sent_email' }, submitStatus);
    }
    throw new Error(`unexpected fetch to ${url}`);
  };
  return calls;
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

test('sendInviteRecoveryEmail: GETs the API-flow init endpoint with Accept: application/json', async () => {
  const calls = installFetch();
  await sendInviteRecoveryEmail('invitee@othala.test');
  const init = calls.find((c) => c.url.includes('/self-service/recovery/api'));
  assert.ok(init, 'init call must be made');
  assert.equal(init.method, 'GET');
  assert.equal(init.headers.Accept, 'application/json');
});

test('sendInviteRecoveryEmail: POSTs method=code + email to the flow returned by init', async () => {
  const calls = installFetch({ flowId: 'flow-xyz' });
  await sendInviteRecoveryEmail('invitee@othala.test');
  const submit = calls.find((c) => c.url.includes('/self-service/recovery?flow='));
  assert.ok(submit, 'submit call must be made');
  assert.equal(submit.method, 'POST');
  assert.ok(submit.url.includes('flow=flow-xyz'), `submit URL must carry the flow id: ${submit.url}`);
  assert.deepEqual(submit.body, { method: 'code', email: 'invitee@othala.test' });
});

test('sendInviteRecoveryEmail: submit call never carries a csrf_token (API flow, not browser)', async () => {
  const calls = installFetch();
  await sendInviteRecoveryEmail('invitee@othala.test');
  const submit = calls.find((c) => c.url.includes('/self-service/recovery?flow='));
  assert.equal(submit.body.csrf_token, undefined);
});

test('sendInviteRecoveryEmail: resolves on submit status 200 (standard success)', async () => {
  installFetch({ submitStatus: 200 });
  await assert.doesNotReject(() => sendInviteRecoveryEmail('a@othala.test'));
});

test('sendInviteRecoveryEmail: resolves on submit status 422 (re-render with messages)', async () => {
  installFetch({ submitStatus: 422 });
  await assert.doesNotReject(() => sendInviteRecoveryEmail('a@othala.test'));
});

test('sendInviteRecoveryEmail: resolves on submit status 400 (Kratos v26 flow-state-mismatch, NOT a failure)', async () => {
  installFetch({ submitStatus: 400 });
  await assert.doesNotReject(() => sendInviteRecoveryEmail('a@othala.test'));
});

test('sendInviteRecoveryEmail: rejects on a genuine submit failure (500)', async () => {
  installFetch({ submitStatus: 500 });
  await assert.rejects(
    () => sendInviteRecoveryEmail('a@othala.test'),
    /HTTP 500/,
  );
});

test('sendInviteRecoveryEmail: rejects when the init call itself fails', async () => {
  installFetch({ initStatus: 503 });
  await assert.rejects(
    () => sendInviteRecoveryEmail('a@othala.test'),
    /recovery flow init failed/,
  );
});

test('sendInviteRecoveryEmail: rejects when init succeeds but returns no flow id', async () => {
  installFetch({ flowId: null });
  await assert.rejects(
    () => sendInviteRecoveryEmail('a@othala.test'),
    /no flow id/,
  );
});

test('sendInviteRecoveryEmail: error messages never include the email address', async () => {
  installFetch({ submitStatus: 500 });
  try {
    await sendInviteRecoveryEmail('should-not-leak@othala.test');
    assert.fail('expected sendInviteRecoveryEmail to throw');
  } catch (err) {
    assert.ok(
      !String(err.message).includes('should-not-leak@othala.test'),
      `error message must not leak the recipient address: ${err.message}`,
    );
  }
});

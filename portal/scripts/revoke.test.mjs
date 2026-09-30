// Invariant: revocation runs its steps in order and a failed session-delete step aborts the fan-out.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { revokeSubject, RevokeError } from '../src/lib/revoke.ts';
import { ResponseError } from '@ory/client-fetch';

function makeDeps() {
  const calls = [];
  return {
    calls,
    deps: {
      identityApi: {
        async patchIdentity(args) {
          calls.push(['patchIdentity', args]);
        },
        async deleteIdentitySessions(args) {
          calls.push(['deleteIdentitySessions', args]);
        },
      },
      oauth2Api: {
        async revokeOAuth2LoginSessions(args) {
          calls.push(['revokeOAuth2LoginSessions', args]);
        },
        async revokeOAuth2ConsentSessions(args) {
          calls.push(['revokeOAuth2ConsentSessions', args]);
        },
      },
    },
  };
}

test('admin/sign-out trigger runs steps 2-4 in order (no step 1)', async () => {
  const { calls, deps } = makeDeps();
  const result = await revokeSubject('sub-1', {}, deps);

  const order = calls.map((c) => c[0]);
  assert.deepEqual(order, [
    'deleteIdentitySessions',
    'revokeOAuth2LoginSessions',
    'revokeOAuth2ConsentSessions',
  ]);
  assert.equal(result.deactivated, false);
  assert.equal(result.kratosSessionsRevoked, true);
  assert.equal(result.hydraLoginRevoked, true);
  assert.equal(result.hydraConsentRevoked, true);
});

test('deactivate trigger runs step 1 (state->inactive) BEFORE step 2', async () => {
  const { calls, deps } = makeDeps();
  const result = await revokeSubject('sub-1', { deactivate: true }, deps);

  const order = calls.map((c) => c[0]);
  assert.deepEqual(order, [
    'patchIdentity',
    'deleteIdentitySessions',
    'revokeOAuth2LoginSessions',
    'revokeOAuth2ConsentSessions',
  ]);
  assert.deepEqual(calls[0][1].jsonPatch, [
    { op: 'replace', path: '/state', value: 'inactive' },
  ]);
  assert.equal(result.deactivated, true);
});

test('Hydra revoke targets the subject (typed args, no string interpolation)', async () => {
  const { calls, deps } = makeDeps();
  await revokeSubject('sub-xyz', {}, deps);
  const login = calls.find((c) => c[0] === 'revokeOAuth2LoginSessions');
  const consent = calls.find((c) => c[0] === 'revokeOAuth2ConsentSessions');
  assert.deepEqual(login[1], { subject: 'sub-xyz' });
  assert.deepEqual(consent[1], { subject: 'sub-xyz', all: true });
});

test('step-2 (delete-sessions) failure ABORTS the fan-out', async () => {
  const { calls, deps } = makeDeps();
  deps.identityApi.deleteIdentitySessions = async () => {
    throw new Error('kratos 500');
  };

  await assert.rejects(
    () => revokeSubject('sub-1', {}, deps),
    (err) => {
      assert.ok(err instanceof RevokeError);
      assert.equal(err.dependency, 'kratos-admin');
      assert.equal(err.step, 'delete-sessions');
      assert.match(err.message, /kratos-admin/);
      assert.doesNotMatch(err.message, /kratos 500/);
      return true;
    },
  );
  const order = calls.map((c) => c[0]);
  assert.ok(!order.includes('revokeOAuth2LoginSessions'));
});

test('step-2 (delete-sessions) 404 = no active sessions: TOLERATED, fan-out continues to Hydra', async () => {
  const { calls, deps } = makeDeps();
  deps.identityApi.deleteIdentitySessions = async () => {
    throw new ResponseError(new Response(null, { status: 404 }), 'Not Found');
  };

  const result = await revokeSubject('sub-1', {}, deps);
  const order = calls.map((c) => c[0]);
  assert.ok(order.includes('revokeOAuth2LoginSessions'), 'Hydra login revoke must run after a 404');
  assert.ok(order.includes('revokeOAuth2ConsentSessions'), 'Hydra consent revoke must run after a 404');
  assert.equal(result.kratosSessionsRevoked, true); // nothing to revoke == revoked
  assert.equal(result.hydraLoginRevoked, true);
  assert.equal(result.hydraConsentRevoked, true);
});

test('step-2 failure under deactivate still runs step 1 first then aborts', async () => {
  const { calls, deps } = makeDeps();
  deps.identityApi.deleteIdentitySessions = async (args) => {
    calls.push(['deleteIdentitySessions', args]); // record the attempt
    throw new Error('boom');
  };
  await assert.rejects(() => revokeSubject('sub-1', { deactivate: true }, deps), RevokeError);
  const order = calls.map((c) => c[0]);
  assert.deepEqual(order, ['patchIdentity', 'deleteIdentitySessions']);
});

test('step-1 (state->inactive) failure throws prescriptive kratos-admin error', async () => {
  const { calls, deps } = makeDeps();
  deps.identityApi.patchIdentity = async () => {
    throw new Error('patch failed');
  };
  await assert.rejects(
    () => revokeSubject('sub-1', { deactivate: true }, deps),
    (err) => {
      assert.equal(err.dependency, 'kratos-admin');
      assert.equal(err.step, 'state->inactive');
      return true;
    },
  );
  assert.equal(calls.length, 0);
});

test('Hydra login-revoke failure throws prescriptive hydra-admin error', async () => {
  const { deps } = makeDeps();
  deps.oauth2Api.revokeOAuth2LoginSessions = async () => {
    throw new Error('hydra down');
  };
  await assert.rejects(
    () => revokeSubject('sub-1', {}, deps),
    (err) => {
      assert.ok(err instanceof RevokeError);
      assert.equal(err.dependency, 'hydra-admin');
      assert.equal(err.step, 'revoke-login-sessions');
      assert.match(err.message, /loginRememberFor|remember/i);
      return true;
    },
  );
});

// Tests for src/lib/revoke.ts — the in-process revocation fan-out (CU3 B1).
//
// Run with: tsx --test scripts/revoke.test.mjs
//
// Proves the fan-out contract with injected SDK stubs (no live Kratos/Hydra):
//   - ORDER: step 1 (state->inactive, deactivate only) precedes step 2
//     (delete-sessions); steps 3-4 are the Hydra login+consent revoke.
//   - deactivate trigger runs step 1; admin/sign-out triggers do NOT.
//   - step-2 failure ABORTS the fan-out (Hydra steps never fire) and throws
//     a prescriptive RevokeError naming kratos-admin.
//   - steps 5-6 failures DO NOT abort (collected into bestEffortFailures).
//   - LDAP step is skipped silently when LDAP_BRIDGE_ADMIN_URL is unset (via
//     the injected flush stub here; the env-skip path is the default helper).
//   - prescriptive errors name the dependency for hydra-admin failures too.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { revokeSubject, RevokeError } from '../src/lib/revoke.ts';

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
      flushLdapBindCache: async (subject) => {
        calls.push(['flushLdapBindCache', subject]);
      },
      invalidateIdentityCache: (subject) => {
        calls.push(['invalidateIdentityCache', subject]);
      },
    },
  };
}

test('admin/sign-out trigger runs steps 2-6 in order (no step 1)', async () => {
  const { calls, deps } = makeDeps();
  const result = await revokeSubject('sub-1', {}, deps);

  const order = calls.map((c) => c[0]);
  assert.deepEqual(order, [
    'deleteIdentitySessions',
    'revokeOAuth2LoginSessions',
    'revokeOAuth2ConsentSessions',
    'invalidateIdentityCache',
    'flushLdapBindCache',
  ]);
  assert.equal(result.deactivated, false);
  assert.equal(result.kratosSessionsRevoked, true);
  assert.equal(result.hydraLoginRevoked, true);
  assert.equal(result.hydraConsentRevoked, true);
  assert.equal(result.identityCacheInvalidated, true);
  assert.equal(result.bestEffortFailures.length, 0);
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
    'invalidateIdentityCache',
    'flushLdapBindCache',
  ]);
  // The state flip is the documented [{op:replace,path:/state,value:inactive}].
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
      // Prescriptive: names the dependency + next action, not the raw error.
      assert.match(err.message, /kratos-admin/);
      assert.doesNotMatch(err.message, /kratos 500/);
      return true;
    },
  );
  // Hydra steps + best-effort steps must NOT have fired after the abort.
  const order = calls.map((c) => c[0]);
  assert.ok(!order.includes('revokeOAuth2LoginSessions'));
  assert.ok(!order.includes('invalidateIdentityCache'));
});

test('step-2 failure under deactivate still runs step 1 first then aborts', async () => {
  const { calls, deps } = makeDeps();
  deps.identityApi.deleteIdentitySessions = async (args) => {
    calls.push(['deleteIdentitySessions', args]); // record the attempt
    throw new Error('boom');
  };
  await assert.rejects(() => revokeSubject('sub-1', { deactivate: true }, deps), RevokeError);
  // state flip happened (step 1), session delete attempted (step 2), no Hydra.
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
  // Nothing after step 1 ran.
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

test('best-effort step 5 (cache) failure does NOT abort; collected', async () => {
  const { calls, deps } = makeDeps();
  deps.invalidateIdentityCache = () => {
    throw new Error('cache blew up');
  };
  const result = await revokeSubject('sub-1', {}, deps);
  // The hard cut still completed.
  assert.equal(result.kratosSessionsRevoked, true);
  assert.equal(result.hydraLoginRevoked, true);
  assert.equal(result.hydraConsentRevoked, true);
  assert.equal(result.identityCacheInvalidated, false);
  // LDAP (step 6) still ran after the cache failure.
  assert.ok(calls.some((c) => c[0] === 'flushLdapBindCache'));
  assert.equal(result.bestEffortFailures.length, 1);
  assert.equal(result.bestEffortFailures[0].step, 'identity-cache-invalidate');
});

test('best-effort step 6 (LDAP) failure does NOT abort; collected', async () => {
  const { deps } = makeDeps();
  deps.flushLdapBindCache = async () => {
    throw new Error('ldap unreachable');
  };
  const result = await revokeSubject('sub-1', {}, deps);
  assert.equal(result.kratosSessionsRevoked, true);
  assert.equal(result.identityCacheInvalidated, true);
  assert.equal(result.bestEffortFailures.length, 1);
  assert.equal(result.bestEffortFailures[0].dependency, 'ldap-bridge');
  assert.equal(result.bestEffortFailures[0].step, 'flush-bind-cache');
});

test('default LDAP flush is a silent no-op when LDAP_BRIDGE_ADMIN_URL is unset', async () => {
  // Exercise the real default helper (no flush injected) so the env-skip path
  // is covered. Stub fetch to detect an unexpected request.
  const prevUrl = process.env.LDAP_BRIDGE_ADMIN_URL;
  delete process.env.LDAP_BRIDGE_ADMIN_URL;
  const origFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => {
    fetched = true;
    return { ok: true };
  };
  try {
    const { deps } = makeDeps();
    // remove the injected flush so the default helper is used
    delete deps.flushLdapBindCache;
    const result = await revokeSubject('sub-1', {}, deps);
    assert.equal(fetched, false, 'no LDAP request when URL unset');
    assert.equal(result.bestEffortFailures.length, 0);
  } finally {
    globalThis.fetch = origFetch;
    if (prevUrl === undefined) delete process.env.LDAP_BRIDGE_ADMIN_URL;
    else process.env.LDAP_BRIDGE_ADMIN_URL = prevUrl;
  }
});

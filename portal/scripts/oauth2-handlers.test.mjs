// Contract tests for src/lib/oauth2-handlers.ts — the OAuth2 challenge
// providers (CU1 item 1) and the gate applied on BOTH login and consent
// (CU1 item 6).
//
// Run with: tsx --test scripts/oauth2-handlers.test.mjs
//
// Drives the framework-agnostic handlers with a stub OAuth2Api + stub identity
// lookup, asserting accept/reject behaviour and the relative return_to bounce.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleLogin, handleConsent, handleLogout, buildLoginReturnTo } from '../src/lib/oauth2-handlers.ts';

function activeMember(overrides = {}) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'ada', email: 'a@dunn.dev', displayName: 'Ada' },
    metadata_admin: { groups: ['access-grafana'] },
    verifiable_addresses: [{ value: 'a@dunn.dev', verified: true, via: 'email', status: 'completed' }],
    ...overrides,
  };
}

// Build a stub OAuth2Api capturing calls; per-test overrides supply challenge data.
function stubOAuth2(over = {}) {
  const calls = { acceptLogin: 0, rejectLogin: 0, acceptConsent: 0, rejectConsent: 0, acceptLogout: 0 };
  const api = {
    getOAuth2LoginRequest: over.getOAuth2LoginRequest
      ?? (async () => ({ challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' } })),
    getOAuth2ConsentRequest: over.getOAuth2ConsentRequest
      ?? (async () => ({ challenge: 'cc', subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email', 'profile'], requested_access_token_audience: [] })),
    getOAuth2LogoutRequest: over.getOAuth2LogoutRequest
      ?? (async () => ({ challenge: 'gc', subject: 'id-1', client: { client_id: 'grafana' } })),
    acceptOAuth2LoginRequest: async (p) => { calls.acceptLogin++; calls.acceptLoginBody = p.acceptOAuth2LoginRequest; return { redirect_to: 'https://dag.dunn.dev/after-login' }; },
    rejectOAuth2LoginRequest: async (p) => { calls.rejectLogin++; calls.rejectLoginReason = p.rejectOAuth2Request?.error_description; return { redirect_to: 'https://dag.dunn.dev/login-rejected' }; },
    acceptOAuth2ConsentRequest: async (p) => { calls.acceptConsent++; calls.acceptConsentBody = p.acceptOAuth2ConsentRequest; return { redirect_to: 'https://dag.dunn.dev/after-consent' }; },
    rejectOAuth2ConsentRequest: async (p) => { calls.rejectConsent++; calls.rejectConsentReason = p.rejectOAuth2Request?.error_description; return { redirect_to: 'https://dag.dunn.dev/consent-rejected' }; },
    acceptOAuth2LogoutRequest: async () => { calls.acceptLogout++; return { redirect_to: 'https://dag.dunn.dev/after-logout' }; },
  };
  return { api, calls };
}

// ── return_to hardening (CU1 item 5) ──────────────────────────────────────

test('buildLoginReturnTo is a RELATIVE path (no scheme/host)', () => {
  const r = buildLoginReturnTo('lc');
  assert.equal(r, '/oauth2/login?login_challenge=lc');
  assert.ok(r.startsWith('/') && !r.includes('://'));
});

// ── LOGIN ─────────────────────────────────────────────────────────────────

test('login accepts an active member (skip path)', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => activeMember(),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-login');
  assert.equal(calls.acceptLogin, 1);
  assert.equal(calls.rejectLogin, 0);
});

test('login REJECTS when missing the access group', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => activeMember({ metadata_admin: { groups: [] } }),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/login-rejected');
  assert.equal(calls.acceptLogin, 0);
  assert.match(calls.rejectLoginReason, /access-grafana group/);
});

test('login REJECTS when identity state is inactive', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => activeMember({ state: 'inactive' }),
  });
  assert.equal(res.status, 302);
  assert.equal(calls.rejectLoginReason, 'identity not active');
});

test('login REJECTS when identity lookup fails (fail-closed)', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => { throw new Error('kratos down'); },
  });
  assert.equal(res.status, 302);
  assert.equal(calls.rejectLoginReason, 'identity lookup failed');
});

test('login bounces to RELATIVE return_to when not authenticated (skip=false, no session)', async () => {
  const { api } = stubOAuth2({
    getOAuth2LoginRequest: async () => ({ challenge: 'lc', skip: false, subject: '', client: { client_id: 'grafana' } }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => null,
  });
  assert.equal(res.status, 302);
  const loc = res.headers.get('location');
  // The return_to query param must be a relative path.
  const u = new URL(loc, 'https://dag.dunn.dev');
  assert.equal(u.pathname, '/auth/login');
  assert.equal(u.searchParams.get('return_to'), '/oauth2/login?login_challenge=lc');
});

test('login 400 on missing challenge', async () => {
  const res = await handleLogin(new Request('https://x/oauth2/login'), {});
  assert.equal(res.status, 400);
});

// ── CONSENT ─────────────────────────────────────────────────────────────────

test('consent accepts an active member and grants scope + injects id_token', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
    oauth2: api,
    getIdentity: async () => activeMember(),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-consent');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile']);
  assert.equal(calls.acceptConsentBody.session.id_token.email, 'a@dunn.dev');
  assert.deepEqual(calls.acceptConsentBody.session.id_token.groups, ['access-grafana']);
});

test('consent REJECTS when missing the access group', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
    oauth2: api,
    getIdentity: async () => activeMember({ metadata_admin: { groups: [] } }),
  });
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 0);
  assert.match(calls.rejectConsentReason, /access-grafana group/);
});

test('consent REJECTS when identity state is inactive', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
    oauth2: api,
    getIdentity: async () => activeMember({ state: 'inactive' }),
  });
  assert.equal(res.status, 302);
  assert.equal(calls.rejectConsentReason, 'identity not active');
});

test('consent REJECTS when identity lookup fails (fail-closed)', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
    oauth2: api,
    getIdentity: async () => { throw new Error('kratos down'); },
  });
  assert.equal(res.status, 302);
  assert.equal(calls.rejectConsentReason, 'identity lookup failed');
});

test('consent 400 on missing challenge', async () => {
  const res = await handleConsent(new Request('https://x/oauth2/consent'), {});
  assert.equal(res.status, 400);
});

// ── LOGOUT ──────────────────────────────────────────────────────────────────

test('logout accepts and redirects', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogout(new Request('https://x/oauth2/logout?logout_challenge=gc'), { oauth2: api });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-logout');
  assert.equal(calls.acceptLogout, 1);
});

test('logout 400 on missing challenge', async () => {
  const res = await handleLogout(new Request('https://x/oauth2/logout'), {});
  assert.equal(res.status, 400);
});

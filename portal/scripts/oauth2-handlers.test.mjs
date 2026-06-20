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
import { handleLogin, handleConsent, handleConsentPost, handleLogout, buildLoginReturnTo } from '../src/lib/oauth2-handlers.ts';
import { describeScopeList, SCOPE_DESCRIPTIONS } from '../src/lib/scope-descriptions.ts';
import { parseManifest } from '../src/lib/manifests.ts';
import { signToken, _resetForTests } from '../src/lib/csrf.ts';
import { deepMergeClaims } from '../src/lib/claims.ts';

// Ensure CSRF_SECRET is set for tests that exercise CSRF verification.
if (!process.env.CSRF_SECRET) {
  process.env.CSRF_SECRET = 'test-secret-must-be-at-least-32-chars-long!!';
}

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
// defaultSession: the session returned by the default getSession stub. Provided so
// tests that use the skip=true login path (FIX-A: now re-verifies a live Kratos
// session) don't need to provide getSession for the common happy path.
function stubOAuth2(over = {}) {
  const calls = { acceptLogin: 0, rejectLogin: 0, acceptConsent: 0, rejectConsent: 0, acceptLogout: 0 };
  const api = {
    getOAuth2LoginRequest: over.getOAuth2LoginRequest
      ?? (async () => ({ challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' } })),
    getOAuth2ConsentRequest: over.getOAuth2ConsentRequest
      // Default: skip_consent:true client — auto-accept path. Tests that exercise
      // the prompt path supply their own getOAuth2ConsentRequest with skip:false.
      ?? (async () => ({ challenge: 'cc', skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email', 'profile'], requested_access_token_audience: [] })),
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

// Default getSession stub for skip=true login tests: returns an active session
// matching the default subject 'id-1'. Tests that need a different session
// (including the FIX-A specific tests) supply their own getSession override.
function defaultSession(overrides = {}) {
  return async () => ({
    active: true,
    identity: {
      id: 'id-1',
      state: 'active',
      schema_id: 'family',
      schema_url: '',
      traits: { username: 'ada', email: 'a@dunn.dev', displayName: 'Ada' },
      metadata_admin: { groups: ['access-grafana'] },
    },
    authenticator_assurance_level: 'aal1',
    ...overrides,
  });
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
    getSession: defaultSession(),
    // access-model Phase 2: the gate keys off the manifest's accessGroups
    // binding (grafana.yaml → access-grafana), not a derived name.
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-login');
  assert.equal(calls.acceptLogin, 1);
  assert.equal(calls.rejectLogin, 0);
});

test('login REJECTS when missing the access group — opaque error_description, real reason logged', async () => {
  const { api, calls } = stubOAuth2();
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ metadata_admin: { groups: [] } }),
      getSession: defaultSession(),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/login-rejected');
    assert.equal(calls.acceptLogin, 0);
    // Client-facing error_description must be opaque — NOT the raw group name.
    assert.equal(calls.rejectLoginReason, 'access_denied', 'error_description must be opaque');
    // Real reason must appear in the server-side log for operator observability.
    const logged = warnArgs.find((a) => a[0].includes('oauth2/login'));
    assert.ok(logged, 'console.warn must be called for denied login');
    assert.match(logged[1].reason, /access group\(s\): access-grafana/, 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
});

test('login REJECTS when identity state is inactive — opaque error_description, real reason logged', async () => {
  const { api, calls } = stubOAuth2();
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ state: 'inactive' }),
      getSession: defaultSession(),
    });
    assert.equal(res.status, 302);
    assert.equal(calls.rejectLoginReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/login'));
    assert.ok(logged, 'console.warn must be called for denied login');
    assert.equal(logged[1].reason, 'identity not active', 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
});

test('login REJECTS when identity lookup fails (fail-closed) — opaque error_description', async () => {
  const { api, calls } = stubOAuth2();
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => { throw new Error('kratos down'); },
      getSession: defaultSession(),
    });
    assert.equal(res.status, 302);
    assert.equal(calls.rejectLoginReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/login'));
    assert.ok(logged, 'console.warn must be called for denied login');
    assert.equal(logged[1].reason, 'identity lookup failed', 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
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
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-consent');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile']);
  assert.equal(calls.acceptConsentBody.session.id_token.email, 'a@dunn.dev');
  assert.deepEqual(calls.acceptConsentBody.session.id_token.groups, ['access-grafana']);
});

test('consent REJECTS when missing the access group — opaque error_description, real reason logged', async () => {
  const { api, calls } = stubOAuth2();
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ metadata_admin: { groups: [] } }),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(res.status, 302);
    assert.equal(calls.acceptConsent, 0);
    assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/consent'));
    assert.ok(logged, 'console.warn must be called for denied consent');
    assert.match(logged[1].reason, /access group\(s\): access-grafana/, 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
});

test('consent REJECTS when identity state is inactive — opaque error_description, real reason logged', async () => {
  const { api, calls } = stubOAuth2();
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ state: 'inactive' }),
    });
    assert.equal(res.status, 302);
    assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/consent'));
    assert.ok(logged, 'console.warn must be called for denied consent');
    assert.equal(logged[1].reason, 'identity not active', 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
});

test('consent REJECTS when identity lookup fails (fail-closed) — opaque error_description', async () => {
  const { api, calls } = stubOAuth2();
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleConsent(new Request('https://x/oauth2/consent?consent_challenge=cc'), {
      oauth2: api,
      getIdentity: async () => { throw new Error('kratos down'); },
    });
    assert.equal(res.status, 302);
    assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/consent'));
    assert.ok(logged, 'console.warn must be called for denied consent');
    assert.equal(logged[1].reason, 'identity lookup failed', 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
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

// ── CONSENT PROMPT — NEW CONTRACT SUITE ─────────────────────────────────────
//
// T1–T6 cover coordinator decisions 1–5 and the scope-description module.

// T1: REGRESSION GUARD — skip=true must auto-accept (no bounce to /auth/consent).
// This is the path all 11 current estate clients take. Must be behaviorally
// unchanged after the prompt-path addition.
// D3: assert FULL payload — remember_for===3600 (skip path matches Go), grant_scope,
// id_token.email set. This guard fails if the payload regresses.
test('T1: consent skip=true auto-accepts (REGRESSION GUARD)', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc',
      skip: true,
      subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email', 'profile'],
      requested_access_token_audience: [],
    }),
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => activeMember(),
      manifest: () => loadManifest('grafana'),
    },
  );
  // Must accept (redirect_to = after-consent URL), NOT bounce to /auth/consent.
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-consent');
  assert.equal(calls.acceptConsent, 1, 'acceptConsent must be called once');
  assert.equal(calls.rejectConsent, 0, 'rejectConsent must NOT be called');
  // Regression: must NOT redirect to /auth/consent.
  assert.ok(
    !res.headers.get('location')?.includes('/auth/consent'),
    'skip=true must NOT bounce to the grant screen',
  );
  // D3: assert FULL payload shape — regression guard.
  assert.equal(
    calls.acceptConsentBody.remember_for,
    3600,
    'skip path must use remember_for=3600 (Go consentRememberFor), not 30d',
  );
  assert.deepEqual(
    calls.acceptConsentBody.grant_scope,
    ['email', 'profile'],
    'grant_scope must match requested_scope',
  );
  assert.equal(
    calls.acceptConsentBody.session.id_token.email,
    'a@dunn.dev',
    'id_token.email must be set on skip path',
  );
  assert.equal(
    calls.acceptConsentBody.remember,
    true,
    'remember must be true',
  );
});

// T2: skip=false -> 302 bounce to /auth/consent?consent_challenge=cc.
test('T2: consent skip=false bounces to /auth/consent with challenge', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc',
      skip: false,
      subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['openid', 'email'],
      requested_access_token_audience: [],
    }),
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => activeMember(),
      // Bind access-grafana (so the gate passes) but DON'T skip consent — this
      // test asserts the bounce to the grant screen, which the real grafana
      // manifest (skip_consent:true, see T2b) would suppress.
      manifest: () => ({
        clientId: 'grafana',
        clientName: 'grafana',
        accessGroup: 'access-grafana',
        accessGroups: ['access-grafana'],
        skipConsent: false,
        skipAccessCheck: false,
        roles: [],
        groupRoleMap: {},
        emitGroupsClaim: null,
      }),
    },
  );
  assert.equal(res.status, 302);
  const loc = res.headers.get('location');
  assert.ok(loc?.startsWith('/auth/consent'), `location should start with /auth/consent, got: ${loc}`);
  assert.ok(loc?.includes('consent_challenge=cc'), `location should include consent_challenge, got: ${loc}`);
  // Must NOT have auto-accepted.
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called on skip=false');
});

// T2b: REGRESSION GUARD (Go parity) — Hydra reports consent.skip=false (OSS Hydra
// v26.2.0 does NOT auto-skip on the client's skip_consent field), but the MANIFEST
// is skip_consent:true (grafana), so the operator pre-consented at authoring time:
// AUTO-ACCEPT, do NOT bounce to the grant UI. The Go original keyed on the client's
// skip_consent; the first TS port regressed to consent.skip only, sending every
// "never prompts" client to the grant screen on first login (caught by e2e
// deep-coverage 2026-06-02). loadManifest is hoisted, so it is callable here.
test('T2b: consent skip=false but manifest skip_consent:true AUTO-ACCEPTS', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc',
      skip: false,
      subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['openid', 'email'],
      requested_access_token_audience: [],
    }),
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => activeMember(),
      manifest: () => loadManifest('grafana'),
    },
  );
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-consent');
  assert.equal(calls.acceptConsent, 1, 'manifest skip_consent:true must auto-accept');
  assert.equal(calls.rejectConsent, 0, 'must not reject');
  assert.ok(
    !res.headers.get('location')?.includes('/auth/consent'),
    'manifest skip_consent:true must NOT bounce to the grant screen',
  );
});

// T3: POST Allow -> accept with remember:true, remember_for=2592000, grant_scope, id_token claims.
test('T3: POST Allow accepts with remember=true, 30-day remember_for, claims', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc',
      skip: false,
      subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email', 'profile'],
      requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: csrfToken });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', cookie: 'session=s1' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getIdentity: async () => activeMember(),
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-consent');
  assert.equal(calls.acceptConsent, 1, 'acceptConsent must be called once');
  assert.equal(calls.acceptConsentBody.remember, true, 'remember must be true');
  assert.equal(calls.acceptConsentBody.remember_for, 2_592_000, 'remember_for must be 30 days (2592000s)');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile'], 'grant_scope must match requested_scope');
  // id_token claims must be populated (email from activeMember traits).
  assert.equal(calls.acceptConsentBody.session.id_token.email, 'a@dunn.dev', 'id_token.email must be set');
});

// T4: POST Deny -> rejectOAuth2ConsentRequest called, redirects.
test('T4: POST Deny rejects and redirects', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc',
      skip: false,
      subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email'],
      requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'deny', csrf_token: csrfToken });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', cookie: 'session=s1' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/consent-rejected');
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called once');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called on deny');
});

// T5: Session-subject mismatch -> reject with access_denied.
test('T5: POST Allow rejects with access_denied on session-subject mismatch', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc',
      skip: false,
      subject: 'other-id',   // challenge belongs to a different user
      client: { client_id: 'grafana' },
      requested_scope: ['email'],
      requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: csrfToken });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', cookie: 'session=s1' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
  });
  assert.equal(res.status, 302);
  // Must reject (redirect to consent-rejected), not accept.
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called on subject mismatch');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called on subject mismatch');
  assert.match(calls.rejectConsentReason, /mismatch/, 'rejection reason must mention mismatch');
});

// T6: Scope-description mapping — describeScopeList and unknown-scope fallback.
test('T6: describeScopeList maps known scopes and falls back for unknown', () => {
  const result = describeScopeList(['openid', 'email', 'groups', 'profile', 'offline_access', 'unknown_scope']);

  assert.equal(result.length, 6, 'must return one entry per scope');

  // Known scopes get human descriptions.
  assert.equal(result[0].scope, 'openid');
  assert.equal(result[0].description, SCOPE_DESCRIPTIONS['openid']);

  assert.equal(result[1].scope, 'email');
  assert.equal(result[1].description, SCOPE_DESCRIPTIONS['email']);

  assert.equal(result[2].scope, 'groups');
  assert.equal(result[2].description, SCOPE_DESCRIPTIONS['groups']);

  assert.equal(result[3].scope, 'profile');
  assert.equal(result[3].description, SCOPE_DESCRIPTIONS['profile'], 'profile must map to display name description');

  assert.equal(result[4].scope, 'offline_access');
  assert.equal(result[4].description, SCOPE_DESCRIPTIONS['offline_access'], 'offline_access must map to stay signed in description');

  // Unknown scope falls back to the scope name itself.
  assert.equal(result[5].scope, 'unknown_scope');
  assert.equal(result[5].description, 'unknown_scope', 'unknown scope must fall back to scope name');
});

// ── D1: CSRF guard ────────────────────────────────────────────────────────────

test('D1: POST Allow with missing csrf_token returns 400', async () => {
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: false, subject: 'id-1',
      client: { client_id: 'grafana' }, requested_scope: ['email'], requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow' });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
  });
  assert.equal(res.status, 400, 'missing CSRF token must return 400');
});

test('D1: POST Allow with invalid csrf_token returns 400', async () => {
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: false, subject: 'id-1',
      client: { client_id: 'grafana' }, requested_scope: ['email'], requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: 'bad.token.value.here' });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
  });
  assert.equal(res.status, 400, 'invalid CSRF token must return 400');
});

// ── A4: Claims injection tests — real manifest data ──────────────────────────

// Load real manifests from e2e/manifests/ (the unified fixture set) for
// test scenarios. hydra/clients/ moved to the iac catalog at M3; the e2e
// fixtures carry the same oidc:/consent: blocks (on othala.test), and
// parseManifest reads those, ignoring the presentation: block.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const clientsDir = join(__dirname, '..', '..', 'e2e', 'manifests');

function loadManifest(name) {
  const yaml = readFileSync(join(clientsDir, `${name}.yaml`), 'utf8');
  return parseManifest(yaml, `${name}.yaml`);
}

const grafanaManifest = loadManifest('grafana');
const audiobookshelfManifest = loadManifest('audiobookshelf');

// A4a: audiobookshelf — identity in 'family' group -> user role ->
// claim_emit.groups = ['user'] replaces the identity groups.
test('A4a: audiobookshelf family member gets user role, groups replaced', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'audiobookshelf' },
      requested_scope: ['openid', 'email', 'groups'],
      requested_access_token_audience: [],
    }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['family', 'access-audiobookshelf'] },
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => identity,
      manifest: (id) => id === 'audiobookshelf' ? audiobookshelfManifest : undefined,
    },
  );
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 1);
  const idToken = calls.acceptConsentBody.session.id_token;
  // audiobookshelf user role: claim_emit.groups = ['user'] — replaces identity groups
  assert.deepEqual(idToken.groups, ['user'], 'groups must be replaced by role claim_emit');
  assert.equal(idToken.email, 'a@dunn.dev', 'email must still be present');
});

// A4b: grafana — identity in 'admin' group -> admin role ->
// grafana_role=['GrafanaAdmin'], groups=['admin'].
test('A4b: grafana admin member gets GrafanaAdmin role, grafana_role claim injected', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['openid', 'email', 'groups'],
      requested_access_token_audience: [],
    }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['admin', 'access-grafana'] },
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => identity,
      manifest: (id) => id === 'grafana' ? grafanaManifest : undefined,
    },
  );
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 1);
  const idToken = calls.acceptConsentBody.session.id_token;
  assert.deepEqual(idToken.grafana_role, ['GrafanaAdmin'], 'grafana_role claim must be injected');
  assert.deepEqual(idToken.groups, ['admin'], 'groups must be replaced by role claim_emit');
  assert.equal(idToken.email, 'a@dunn.dev', 'email must still be present');
});

// A4c: override beats group_role_map — identity in 'family' + metadata_admin.roles.grafana='admin'
test('A4c: grafana override (roles.grafana=admin) beats group_role_map for family member', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['openid', 'email', 'groups'],
      requested_access_token_audience: [],
    }),
  });
  // Identity is in 'family' (would normally get 'viewer') but has a 'grafana'='admin' override.
  const identity = activeMember({
    metadata_admin: {
      groups: ['family', 'access-grafana'],
      roles: { grafana: 'admin' },
    },
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => identity,
      manifest: (id) => id === 'grafana' ? grafanaManifest : undefined,
    },
  );
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 1);
  const idToken = calls.acceptConsentBody.session.id_token;
  // Override wins: admin role -> grafana_role=['GrafanaAdmin'], not Viewer
  assert.deepEqual(idToken.grafana_role, ['GrafanaAdmin'], 'override must beat group_role_map');
});

// A4e: a manifest that binds access but declares NO roles -> base claims only
// (no deepMerge, groups emitted by default).
//
// access-model Phase 2: a TRULY missing manifest is now fail-closed (no binding
// = no access — there is no implicit prefix-derived group anymore), so this
// test supplies a minimal manifest that binds the user's access group but maps
// no roles. The claim-composition behaviour under test (base claims, groups
// emitted, zero role injection) is unchanged.
test('A4e: roleless manifest -> base claims only, groups emitted', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'unknown-client' },
      requested_scope: ['email', 'profile'],
      requested_access_token_audience: [],
    }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['family', 'access-unknown-client'] },
  });
  // Minimal binding manifest: grants entry via access-unknown-client, no roles.
  const rolelessManifest = {
    clientId: 'unknown-client',
    clientName: 'unknown-client',
    accessGroup: 'access-unknown-client',
    accessGroups: ['access-unknown-client'],
    skipAccessCheck: false,
    roles: [],
    groupRoleMap: {},
    emitGroupsClaim: null,
  };
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => identity,
      manifest: () => rolelessManifest,
    },
  );
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 1);
  const idToken = calls.acceptConsentBody.session.id_token;
  // Base claims only — groups are present (no suppression), no role injection
  assert.deepEqual(idToken.groups, ['family', 'access-unknown-client'], 'groups must be emitted from identity');
  assert.equal(idToken.email, 'a@dunn.dev', 'email must be present');
  assert.ok(!('grafana_role' in idToken), 'no role claims injected when manifest declares no roles');
  assert.ok(!('roles' in idToken), 'no roles claim injected when manifest declares no roles');
});

// D3 regression guard: grafana skip path injects grafana_role from manifest
test('D3: grafana skip path injects grafana_role from manifest (regression guard)', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email', 'profile'],
      requested_access_token_audience: [],
    }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['family', 'access-grafana'] },
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => identity,
      manifest: (id) => id === 'grafana' ? grafanaManifest : undefined,
    },
  );
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 1);
  const idToken = calls.acceptConsentBody.session.id_token;
  // family -> viewer role -> grafana_role: ['Viewer']
  assert.deepEqual(idToken.grafana_role, ['Viewer'], 'grafana_role must be injected for grafana viewer');
  assert.equal(calls.acceptConsentBody.remember_for, 3600, 'skip path must use remember_for=3600');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile'], 'grant_scope must match');
  assert.equal(idToken.email, 'a@dunn.dev', 'id_token.email must be set');
});

// C: skip_access_check bypasses access-group gate but NOT state gate
test('C: skip_access_check bypasses access-group check', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email'],
      requested_access_token_audience: [],
    }),
  });
  // Identity has NO access-grafana group — normally denied.
  const identity = activeMember({ metadata_admin: { groups: [] } });
  const skipManifest = { ...grafanaManifest, skipAccessCheck: true };
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => identity,
      manifest: () => skipManifest,
    },
  );
  assert.equal(res.status, 302);
  assert.equal(calls.acceptConsent, 1, 'skip_access_check must allow even without access group');
  assert.equal(calls.rejectConsent, 0);
});

test('C: skip_access_check still enforces state===active', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email'],
      requested_access_token_audience: [],
    }),
  });
  // Inactive identity — must still be denied even with skip_access_check.
  const identity = activeMember({ state: 'inactive', metadata_admin: { groups: [] } });
  const skipManifest = { ...grafanaManifest, skipAccessCheck: true };
  const warnArgs = [];
  const origWarn = console.warn;
  console.warn = (...a) => warnArgs.push(a);
  try {
    const res = await handleConsent(
      new Request('https://x/oauth2/consent?consent_challenge=cc'),
      {
        oauth2: api,
        getIdentity: async () => identity,
        manifest: () => skipManifest,
      },
    );
    assert.equal(res.status, 302);
    assert.equal(calls.rejectConsent, 1, 'inactive identity must still be denied with skip_access_check');
    assert.equal(calls.acceptConsent, 0);
    // Client sees opaque error_description; real reason is server-side only.
    assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/consent'));
    assert.ok(logged, 'console.warn must be called');
    assert.equal(logged[1].reason, 'identity not active', 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
});

// ── Session-presence guard on the POST path ───────────────────────────────────

// T7a: POST rejects when there is no active session (getSession returns null).
// Covers the no-active-session branch in handleConsentPost (~lines 390-405).
test('T7a: POST rejects when there is no active session (getSession returns null)', async () => {
  _resetForTests();
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: false, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email'],
      requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: 'irrelevant' });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => null,   // no session at all
  });
  // Must reject via rejectOAuth2ConsentRequest with access_denied, not accept.
  assert.equal(res.status, 302, 'should redirect (reject path)');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called when session is absent');
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called when session is absent');
  assert.match(calls.rejectConsentReason, /no active session/, 'rejection reason must mention no active session');
});

// T7b: POST Allow re-gates and rejects when the identity is inactive (access-denied
// on the allow path re-gate). Covers the allow-path gate at ~lines 454-472.
test('T7b: POST Allow re-gates and rejects an inactive identity', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: false, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['email'],
      requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: csrfToken });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', cookie: 'session=s1' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    // Session is present + subject matches, but the identity itself is inactive.
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
    // getIdentity returns an inactive identity — re-gate must catch this.
    getIdentity: async () => activeMember({ state: 'inactive', metadata_admin: { groups: ['access-grafana'] } }),
    manifest: (id) => id === 'grafana' ? grafanaManifest : undefined,
  });
  // Must reject (gate fires on the allow path), not accept.
  assert.equal(res.status, 302, 'should redirect (reject path)');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called for inactive identity on allow path');
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called when re-gate fails for inactive identity');
  // Client-facing error_description must be opaque; real reason stays server-side.
  assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque on allow-path re-gate');
});

// ── deepMergeClaims — recursive nested-object merge ──────────────────────────
//
// Current real manifests have flat claim_emit maps, so the recursive object
// branch of deepMergeClaims is not exercised by the A4 tests. These unit
// tests drive it directly.

test('deepMergeClaims: recursive nested-object merge (src-wins on scalar conflict, dst-only keys preserved)', () => {
  // Simulate resource_access.<app>.roles shape as used by some OIDC clients.
  const dst = {
    resource_access: {
      myapp: { roles: ['user'] },
      otherapp: { roles: ['viewer'] },   // dst-only key — must survive
    },
    flat_key: 'base',
  };
  const src = {
    resource_access: {
      myapp: { roles: ['admin'] },       // scalar/array conflict: src wins
    },
    flat_key: 'override',               // scalar conflict: src wins
  };

  deepMergeClaims(dst, src);

  // src wins on array conflict inside nested object.
  assert.deepEqual(
    dst.resource_access.myapp.roles,
    ['admin'],
    'src wins on array conflict inside nested object',
  );
  // dst-only nested key must be preserved.
  assert.deepEqual(
    dst.resource_access.otherapp.roles,
    ['viewer'],
    'dst-only nested key must be preserved after merge',
  );
  // scalar conflict at top level: src wins.
  assert.equal(dst.flat_key, 'override', 'scalar conflict: src wins');
});

test('deepMergeClaims: missing key in dst is copied from src', () => {
  const dst = { a: 1 };
  const src = { b: { nested: true } };
  deepMergeClaims(dst, src);
  assert.deepEqual(dst.b, { nested: true }, 'missing key in dst must be copied from src');
  assert.equal(dst.a, 1, 'existing dst key must not be disturbed');
});

test('deepMergeClaims: null/undefined dst or src is a no-op', () => {
  // Should not throw.
  deepMergeClaims(null, { a: 1 });
  deepMergeClaims({ a: 1 }, null);
  deepMergeClaims(undefined, { a: 1 });
});

// ── FIX-A: login skip=true must re-verify live Kratos session ─────────────────

test('FIX-A: login skip=true with NO live Kratos session redirects to login UI', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LoginRequest: async () => ({
      challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' },
    }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => null,   // no live session
    getIdentity: async () => activeMember(),
  });
  // Must bounce to login UI, NOT accept.
  assert.equal(res.status, 302, 'must redirect');
  assert.equal(calls.acceptLogin, 0, 'acceptLogin must NOT be called when no session');
  const loc = res.headers.get('location');
  const u = new URL(loc, 'https://dag.dunn.dev');
  assert.equal(u.pathname, '/auth/login', 'must redirect to login UI');
  assert.equal(u.searchParams.get('return_to'), '/oauth2/login?login_challenge=lc',
    'return_to must be the relative login challenge path');
});

test('FIX-A: login skip=true with session whose identity.id !== login.subject redirects to login UI', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LoginRequest: async () => ({
      challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' },
    }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    // Session is active but for a DIFFERENT user (id-2 vs login.subject id-1).
    getSession: async () => ({
      active: true,
      identity: { id: 'id-2', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
    getIdentity: async () => activeMember(),
  });
  assert.equal(res.status, 302, 'must redirect');
  assert.equal(calls.acceptLogin, 0, 'acceptLogin must NOT be called on subject mismatch');
  const loc = res.headers.get('location');
  const u = new URL(loc, 'https://dag.dunn.dev');
  assert.equal(u.pathname, '/auth/login', 'must redirect to login UI on subject mismatch');
});

test('FIX-A: login skip=true with matching live active session accepts', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LoginRequest: async () => ({
      challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' },
    }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
      authenticator_assurance_level: 'aal1',
    }),
    getIdentity: async () => activeMember(),
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(res.status, 302, 'must redirect');
  assert.equal(calls.acceptLogin, 1, 'acceptLogin must be called when session matches');
  assert.equal(res.headers.get('location'), 'https://dag.dunn.dev/after-login');
});

test('FIX-A: login skip=true with Kratos upstream error returns 502', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LoginRequest: async () => ({
      challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' },
    }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => { throw new Error('kratos network error'); },
    getIdentity: async () => activeMember(),
  });
  assert.equal(res.status, 502, 'Kratos error on skip path must return 502');
  assert.equal(calls.acceptLogin, 0, 'acceptLogin must NOT be called on getSession error');
});

// ── FIX-E: consent CSRF token must be action-scoped to 'consent' ──────────────

test('FIX-E: POST Allow with identity-only (non-action-scoped) csrf_token returns 400', async () => {
  _resetForTests();
  // signToken without action → identity-only 4-part token.
  // verifyToken now requires action='consent' → 5-part token → malformed error → 400.
  const csrfToken = signToken('id-1');   // no action — identity-only
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: false, subject: 'id-1',
      client: { client_id: 'grafana' }, requested_scope: ['email'], requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: csrfToken });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
  });
  assert.equal(res.status, 400, 'identity-only token must be rejected when action scope is required');
});

test('FIX-E: POST Allow with wrong action-scoped csrf_token returns 400', async () => {
  _resetForTests();
  // Token minted for 'deactivate' — must be rejected for 'consent'.
  const csrfToken = signToken('id-1', 'deactivate');
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: false, subject: 'id-1',
      client: { client_id: 'grafana' }, requested_scope: ['email'], requested_access_token_audience: [],
    }),
  });
  const body = new URLSearchParams({ consent_challenge: 'cc', action: 'allow', csrf_token: csrfToken });
  const req = new Request('https://x/oauth2/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const res = await handleConsentPost(req, {
    oauth2: api,
    getSession: async () => ({
      active: true,
      identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
    }),
  });
  assert.equal(res.status, 400, 'wrong-action token must be rejected');
});

// ── FIX-F: logout subject-binding ─────────────────────────────────────────────

test('FIX-F: logout subject mismatch (live session belongs to different user) redirects to home', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => ({ challenge: 'gc', subject: 'id-1' }),
  });
  process.env.OTHALA_PUBLIC_URL = 'https://dag.dunn.dev';
  try {
    const res = await handleLogout(
      new Request('https://x/oauth2/logout?logout_challenge=gc', {
        headers: { cookie: 'session=s2' },
      }),
      {
        oauth2: api,
        // Session is for id-2, but logout challenge is for id-1.
        getSession: async () => ({
          active: true,
          identity: { id: 'id-2', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
        }),
      },
    );
    assert.equal(res.status, 302, 'subject mismatch must redirect');
    assert.equal(calls.acceptLogout, 0, 'acceptLogout must NOT be called on subject mismatch');
    const loc = res.headers.get('location');
    assert.ok(loc?.endsWith('/'), 'must redirect to portal home');
  } finally {
    delete process.env.OTHALA_PUBLIC_URL;
  }
});

test('FIX-F: logout with matching session subject accepts normally', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => ({ challenge: 'gc', subject: 'id-1' }),
  });
  const res = await handleLogout(
    new Request('https://x/oauth2/logout?logout_challenge=gc', {
      headers: { cookie: 'session=s1' },
    }),
    {
      oauth2: api,
      getSession: async () => ({
        active: true,
        identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
      }),
    },
  );
  assert.equal(res.status, 302, 'matching session must accept');
  assert.equal(calls.acceptLogout, 1, 'acceptLogout must be called when subjects match');
});

test('FIX-F: logout with no live session accepts normally (expected on post-Kratos-logout flow)', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => ({ challenge: 'gc', subject: 'id-1' }),
  });
  const res = await handleLogout(
    new Request('https://x/oauth2/logout?logout_challenge=gc'),
    {
      oauth2: api,
      getSession: async () => null,   // no session — already logged out of Kratos
    },
  );
  assert.equal(res.status, 302, 'no-session logout must accept');
  assert.equal(calls.acceptLogout, 1, 'acceptLogout must be called when no session present');
});

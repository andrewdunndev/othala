// Contract tests for src/lib/oauth2-handlers.ts — the OAuth2 challenge
// providers (CU1 item 1) and the gate applied on BOTH login and consent
// (CU1 item 6).
//
// Run with: npx vitest run scripts/oauth2-handlers.test.mjs
//
// Drives the framework-agnostic handlers with a stub OAuth2Api + stub identity
// lookup, asserting accept/reject behaviour and the relative return_to bounce.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { handleLogin, loginRememberFor, handleConsent, handleConsentPost, handleLogout, buildLoginReturnTo } from '../src/lib/oauth2-handlers.ts';
import { describeScopeList, SCOPE_DESCRIPTIONS } from '../src/lib/scope-descriptions.ts';
import { parseManifest } from '../src/lib/manifests.ts';
import { signToken, _resetForTests } from '../src/lib/csrf.ts';
import { deepMergeClaims } from '../src/lib/claims.ts';
import {
  identity, session, whoamiIdentity, withTotp, withWebauthnKey, withPasskey, withLookupSecret,
  oauth2LoginRequest, oauth2ConsentRequest, oauth2LogoutRequest,
} from '../src/lib/test-builders.ts';

// Ensure CSRF_SECRET is set for tests that exercise CSRF verification.
if (!process.env.CSRF_SECRET) {
  process.env.CSRF_SECRET = 'test-secret-must-be-at-least-32-chars-long!!';
}

// The default subject: an ordinary grafana member. Under the converged access
// model that means holding `grafana-access` and NOTHING else — entry comes from
// the `<svc>-access` group for everyone, admins included, and `grafana-admin`
// is a ROLE-only group that grants no entry.
// grafana.yaml maps `grafana-access` → viewer, so this identity is a viewer.
function activeMember(overrides = {}) {
  return {
    ...identity({ id: 'id-1', username: 'ada', email: 'a@othala.test', displayName: 'Ada', metadataAdmin: { groups: ['grafana-access'] } }),
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
      ?? (async () => oauth2LoginRequest({ skip: true, subject: 'id-1' })),
    getOAuth2ConsentRequest: over.getOAuth2ConsentRequest
      // Default: skip_consent:true client — auto-accept path. Tests that exercise
      // the prompt path supply their own getOAuth2ConsentRequest with skip:false.
      ?? (async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', requested_scope: ['email', 'profile'] })),
    getOAuth2LogoutRequest: over.getOAuth2LogoutRequest
      ?? (async () => oauth2LogoutRequest({ subject: 'id-1' })),
    acceptOAuth2LoginRequest: async (p) => { calls.acceptLogin++; calls.acceptLoginBody = p.acceptOAuth2LoginRequest; return { redirect_to: 'https://sso.othala.test/after-login' }; },
    rejectOAuth2LoginRequest: async (p) => { calls.rejectLogin++; calls.rejectLoginReason = p.rejectOAuth2Request?.error_description; return { redirect_to: 'https://sso.othala.test/login-rejected' }; },
    acceptOAuth2ConsentRequest: async (p) => { calls.acceptConsent++; calls.acceptConsentBody = p.acceptOAuth2ConsentRequest; return { redirect_to: 'https://sso.othala.test/after-consent' }; },
    rejectOAuth2ConsentRequest: async (p) => { calls.rejectConsent++; calls.rejectConsentReason = p.rejectOAuth2Request?.error_description; return { redirect_to: 'https://sso.othala.test/consent-rejected' }; },
    acceptOAuth2LogoutRequest: async () => { calls.acceptLogout++; return { redirect_to: 'https://sso.othala.test/after-logout' }; },
    revokeOAuth2LoginSessions: over.revokeOAuth2LoginSessions
      ?? (async (p) => { calls.revokeLoginSessions = (calls.revokeLoginSessions ?? []).concat([p]); }),
  };
  return { api, calls };
}

// Default getSession stub for skip=true login tests: returns an active session
// matching the default subject 'id-1'. Tests that need a different session
// (including the FIX-A specific tests) supply their own getSession override.
function defaultSession(overrides = {}) {
  return async () => session('aal1', ['password'], { identity: whoamiIdentity(activeMember()), ...overrides });
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
    // The gate keys off the manifest's accessGroups binding
    // (grafana.yaml → grafana-access), not a derived name.
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-login');
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
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/login-rejected');
    assert.equal(calls.acceptLogin, 0);
    // Client-facing error_description must be opaque — NOT the raw group name.
    assert.equal(calls.rejectLoginReason, 'access_denied', 'error_description must be opaque');
    // Real reason must appear in the server-side log for operator observability.
    const logged = warnArgs.find((a) => a[0].includes('oauth2/login'));
    assert.ok(logged, 'console.warn must be called for denied login');
    assert.match(logged[1].reason, /access group\(s\): grafana-access/, 'real reason must be in the server-side log');
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
    getOAuth2LoginRequest: async () => oauth2LoginRequest(),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => null,
  });
  assert.equal(res.status, 302);
  const loc = res.headers.get('location');
  // The return_to query param must be a relative path.
  const u = new URL(loc, 'https://sso.othala.test');
  assert.equal(u.pathname, '/auth/login');
  assert.equal(u.searchParams.get('return_to'), '/oauth2/login?login_challenge=lc');
});

test('login 400 on missing challenge', async () => {
  const res = await handleLogin(new Request('https://x/oauth2/login'), {});
  assert.equal(res.status, 400);
});

// ── second-factor step-up at app sign-in ───────────────────────────────────

const ADD = { password: (i) => i, totp: withTotp, webauthn: (i) => withWebauthnKey(i), passkey: withPasskey, lookup_secret: withLookupSecret };

function withCreds(...types) {
  return types.reduce((i, t) => ADD[t](i), activeMember()).credentials;
}

const FRESH = async () => oauth2LoginRequest();

for (const [branch, getReq] of [['skip', undefined], ['fresh', FRESH]]) {
  test(`login (${branch}) steps an aal1 totp holder up to aal2 and never accepts`, async () => {
    const { api, calls } = stubOAuth2(getReq ? { getOAuth2LoginRequest: getReq } : {});
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ credentials: withCreds('password', 'totp') }),
      getSession: defaultSession(),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(res.status, 302);
    const u = new URL(res.headers.get('location'), 'https://sso.othala.test');
    assert.equal(u.pathname, '/auth/login');
    assert.equal(u.searchParams.get('aal'), 'aal2');
    assert.equal(u.searchParams.get('return_to'), '/oauth2/login?login_challenge=lc');
    assert.equal(calls.acceptLogin, 0);
    assert.equal(calls.rejectLogin, 0);
  });

  test(`login (${branch}) steps an aal1 admin-marked identity up even without a second factor`, async () => {
    const { api, calls } = stubOAuth2(getReq ? { getOAuth2LoginRequest: getReq } : {});
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ metadata_admin: { groups: ['grafana-access'], admin: true } }),
      getSession: defaultSession(),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(new URL(res.headers.get('location'), 'https://x').searchParams.get('aal'), 'aal2');
    assert.equal(calls.acceptLogin, 0);
  });

  test(`login (${branch}) accepts an aal2 session with acr aal2`, async () => {
    const { api, calls } = stubOAuth2(getReq ? { getOAuth2LoginRequest: getReq } : {});
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ credentials: withCreds('password', 'totp') }),
      getSession: defaultSession({ authenticator_assurance_level: 'aal2' }),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-login');
    assert.equal(calls.acceptLogin, 1);
    assert.equal(calls.acceptLoginBody.acr, 'aal2');
  });

  test(`login (${branch}) accepts a passkey-only aal1 session without step-up`, async () => {
    const { api, calls } = stubOAuth2(getReq ? { getOAuth2LoginRequest: getReq } : {});
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({ credentials: withCreds('passkey', 'lookup_secret') }),
      getSession: defaultSession(),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-login');
    assert.equal(calls.acceptLogin, 1);
    assert.equal(calls.acceptLoginBody.acr, 'aal1');
  });

  test(`login (${branch}) accepts a password member whose webauthn entry holds no keys`, async () => {
    // The identity schema gives every identity a webauthn entry (identifiers,
    // empty config); that entry is not an enrolled second factor.
    const { api, calls } = stubOAuth2(getReq ? { getOAuth2LoginRequest: getReq } : {});
    const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
      oauth2: api,
      getIdentity: async () => activeMember({
        credentials: {
          password: { type: 'password', identifiers: ['a'], config: {} },
          webauthn: { type: 'webauthn', identifiers: ['a'], config: {} },
        },
      }),
      getSession: defaultSession(),
      manifest: () => loadManifest('grafana'),
    });
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-login');
    assert.equal(calls.acceptLogin, 1);
    assert.equal(calls.acceptLoginBody.acr, 'aal1');
  });
}

// ── login memory follows the Kratos session ──────────────────────────────

const IN_20_DAYS = () => new Date(Date.now() + 20 * 86_400_000);

test('login (fresh) remembers the login until the Kratos session expires, without renewing', async () => {
  const { api, calls } = stubOAuth2({ getOAuth2LoginRequest: FRESH });
  await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => activeMember(),
    getSession: defaultSession({ expires_at: IN_20_DAYS() }),
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(calls.acceptLogin, 1);
  assert.equal(calls.acceptLoginBody.remember, true);
  assert.ok(Math.abs(calls.acceptLoginBody.remember_for - 20 * 86_400) <= 2, `remember_for ${calls.acceptLoginBody.remember_for}`);
  assert.equal(calls.acceptLoginBody.extend_session_lifespan, undefined);
});

test('login (skip) re-accepts with remember and renews the remembered login', async () => {
  const { api, calls } = stubOAuth2();
  await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => activeMember(),
    getSession: defaultSession({ expires_at: IN_20_DAYS() }),
    manifest: () => loadManifest('grafana'),
  });
  assert.equal(calls.acceptLogin, 1);
  assert.equal(calls.acceptLoginBody.remember, true);
  assert.ok(Math.abs(calls.acceptLoginBody.remember_for - 20 * 86_400) <= 2, `remember_for ${calls.acceptLoginBody.remember_for}`);
  assert.equal(calls.acceptLoginBody.extend_session_lifespan, true);
});

test('loginRememberFor falls back to the Kratos lifespan without expires_at', () => {
  const s = session('aal1', ['password'], { expires_at: undefined });
  assert.equal(loginRememberFor(s), 2_592_000);
});

test('loginRememberFor rounds up and reads a string expires_at', () => {
  const now = Date.UTC(2026, 0, 1);
  assert.equal(loginRememberFor(session('aal1', ['password'], { expires_at: new Date(now + 1500) }), now), 2);
  assert.equal(loginRememberFor({ ...session(), expires_at: new Date(now + 3_600_000).toISOString() }, now), 3600);
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-consent');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile']);
  assert.equal(calls.acceptConsentBody.session.id_token.email, 'a@othala.test');
  // Default stub requested_scope is ['email','profile'] — no 'groups' scope, so groups
  // claim is gate-removed by H2 (OIDC Core §5.4). grafana's viewer role claim_emit also
  // has grafana_role/groups but neither survives the scope-gate without 'groups'.
  assert.equal('groups' in calls.acceptConsentBody.session.id_token, false, 'groups absent when groups scope not requested');
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
    assert.match(logged[1].reason, /access group\(s\): grafana-access/, 'real reason must be in the server-side log');
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-logout');
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-consent');
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
    'a@othala.test',
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
      // Bind grafana-access (so the gate passes) but DON'T skip consent — this
      // test asserts the bounce to the grant screen, which the real grafana
      // manifest (skip_consent:true, see T2b) would suppress.
      manifest: () => ({
        clientId: 'grafana',
        clientName: 'grafana',
        accessGroup: 'grafana-access',
        accessGroups: ['grafana-access'],
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-consent');
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-consent');
  assert.equal(calls.acceptConsent, 1, 'acceptConsent must be called once');
  assert.equal(calls.acceptConsentBody.remember, true, 'remember must be true');
  assert.equal(calls.acceptConsentBody.remember_for, 2_592_000, 'remember_for must be 30 days (2592000s)');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile'], 'grant_scope must match requested_scope');
  // id_token claims must be populated (email from activeMember traits).
  assert.equal(calls.acceptConsentBody.session.id_token.email, 'a@othala.test', 'id_token.email must be set');
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/consent-rejected');
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
// test scenarios. hydra/clients/ moved to the deployment catalog at M3; the e2e
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

// A4a: audiobookshelf — the baseline (non-admin) case under the converged
// access model. The role now comes from the SERVICE ACCESS group the member
// already holds for entry (`audiobookshelf-access` → user in group_role_map),
// NOT from a cohort. The old form of this test asserted that the `family`
// cohort granted the role; cohort groups are gone entirely, and a cohort
// granting a role is exactly what the converged model retired.
//
// The invariant still under test is unchanged and is the reason the case
// exists: claim_emit.groups = ['user'] is UNIONed with the identity's REAL
// memberships (H1: additive, never replace). The identity holds two service
// access groups so the union is asserted over more than one real membership —
// `grafana-access` is a second service's entry group and maps to no role here,
// so it can only survive by being preserved.
test('A4a: audiobookshelf access-group holder gets user role, groups unioned', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'audiobookshelf' },
      requested_scope: ['openid', 'email', 'groups'],
      requested_access_token_audience: [],
    }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['audiobookshelf-access', 'grafana-access'] },
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
  // audiobookshelf user role: claim_emit.groups = ['user'] — UNIONed with identity groups
  // (H1: real memberships preserved; role claim contributes additively)
  assert.ok(Array.isArray(idToken.groups), 'groups must be an array');
  assert.ok(idToken.groups.includes('audiobookshelf-access'), 'identity group audiobookshelf-access must be preserved');
  assert.ok(idToken.groups.includes('grafana-access'), 'unrelated identity group grafana-access must be preserved');
  assert.ok(idToken.groups.includes('user'), 'role claim_emit group user must be present');
  assert.equal(idToken.email, 'a@othala.test', 'email must still be present');
});

// A4b: grafana — the ADMIN case under the converged access model. An admin
// holds BOTH `grafana-access` (entry, for everyone) and `grafana-admin` (role
// only). The old form of this test gave the identity a bare `admin` cohort
// group and asserted that it granted the admin role estate-wide; that group and
// that derivation are both gone.
//
// The NEW invariant this pins is highest-rank-wins in lookupRole
// (portal/src/lib/claims.ts step 2): the identity's group SET maps to TWO
// declared roles — `grafana-admin`→admin (rank 0) and `grafana-access`→viewer
// (rank 2) — and admin must win. The stored order below is the alphabetical
// order normalizeGroupOrder actually produces, which puts `grafana-access`
// FIRST: a first-match-wins walk would hand this admin the viewer role. That is
// the regression this case catches, and the reason the resolver was changed.
test('A4b: grafana admin holds both groups, highest-ranked role (admin) wins, groups unioned', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['openid', 'email', 'groups'],
      requested_access_token_audience: [],
    }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['grafana-access', 'grafana-admin'] },
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
  // admin (rank 0) must beat viewer (rank 2) even though `grafana-access` is
  // stored first. Viewer here would mean first-match-wins came back.
  assert.deepEqual(idToken.grafana_role, ['GrafanaAdmin'], 'grafana_role claim must be injected');
  // admin role claim_emit.groups = ['admin']; both real memberships survive the
  // union. Union = ['grafana-access','grafana-admin','admin'].
  assert.ok(Array.isArray(idToken.groups), 'groups must be an array');
  assert.ok(idToken.groups.includes('admin'), 'admin role claim_emit group must be present');
  assert.ok(idToken.groups.includes('grafana-access'), 'identity group grafana-access must be preserved');
  assert.ok(idToken.groups.includes('grafana-admin'), 'identity group grafana-admin must be preserved');
  assert.equal(idToken.email, 'a@othala.test', 'email must still be present');
});

// A4c: override beats group_role_map. Identity holds `grafana-access` (which
// group_role_map sends to viewer) plus metadata_admin.roles.grafana='admin'.
// Only the SPELLING of the group supplying the losing role changed here —
// grafana.yaml renamed the viewer mapping from the `family` cohort to
// `grafana-access`. The assertion is unchanged and the contest is unchanged:
// a group-derived viewer competes with an override naming admin, and the
// override must win (lookupRole step 1 beats step 2, portal/src/lib/claims.ts).
// Note the identity deliberately does NOT hold `grafana-admin` — if it did, the
// group walk could reach admin on its own and the override would prove nothing.
test('A4c: grafana override (roles.grafana=admin) beats group_role_map viewer', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => ({
      challenge: 'cc', skip: true, subject: 'id-1',
      client: { client_id: 'grafana' },
      requested_scope: ['openid', 'email', 'groups'],
      requested_access_token_audience: [],
    }),
  });
  // Identity holds only `grafana-access` (would normally resolve to 'viewer')
  // but carries a 'grafana'='admin' override.
  const identity = activeMember({
    metadata_admin: {
      groups: ['grafana-access'],
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
// A TRULY missing manifest is fail-closed (no binding = no access — there is no
// implicit prefix-derived group), so this
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
  // requested_scope=['email','profile'] — 'groups' not in scope; H2 gates groups out.
  // Base claims only: email present, groups absent (no scope), no role injection.
  assert.equal(idToken.email, 'a@othala.test', 'email must be present');
  assert.equal('groups' in idToken, false, 'groups absent when groups scope not requested');
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
    metadata_admin: { groups: ['grafana-access'] },
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
  // grafana-access -> viewer role -> grafana_role: ['Viewer']
  assert.deepEqual(idToken.grafana_role, ['Viewer'], 'grafana_role must be injected for grafana viewer');
  assert.equal(calls.acceptConsentBody.remember_for, 3600, 'skip path must use remember_for=3600');
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile'], 'grant_scope must match');
  assert.equal(idToken.email, 'a@othala.test', 'id_token.email must be set');
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
  // Identity has NO grafana-access group — normally denied.
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
// Covers handleConsentPost's 'no active session' rejection branch.
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
// on the allow path re-gate). Covers handleConsentPost's allow-path gate call.
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
    // getIdentity returns an inactive identity that DOES hold the bound access
    // group (`grafana-access`), so the only thing that can deny is the
    // state===active check — the group gate is satisfied. That isolation is the
    // point: with a stale group name this test would pass on the wrong denial.
    getIdentity: async () => activeMember({ state: 'inactive', metadata_admin: { groups: ['grafana-access'] } }),
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

test('deepMergeClaims: recursive nested-object merge (array union, scalar src-wins, dst-only keys preserved)', () => {
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
      myapp: { roles: ['admin'] },       // array conflict: unioned (H1: union, not src-wins)
    },
    flat_key: 'override',               // scalar conflict: src wins
  };

  deepMergeClaims(dst, src);

  // arrays are unioned: dst-first, then new src elements appended.
  assert.deepEqual(
    dst.resource_access.myapp.roles,
    ['user', 'admin'],
    'array conflict inside nested object becomes union',
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
  const u = new URL(loc, 'https://sso.othala.test');
  assert.equal(u.pathname, '/auth/login', 'must redirect to login UI');
  assert.equal(u.searchParams.get('return_to'), '/oauth2/login?login_challenge=lc',
    'return_to must be the relative login challenge path');
});

const otherUserSession = async () => ({
  active: true,
  identity: { id: 'id-2', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
});
const mismatchLogin = (over = {}) => async () => ({
  challenge: 'lc', skip: true, subject: 'id-1', client: { client_id: 'grafana' },
  session_id: 'sid-1', request_url: 'https://hydra.othala.test/oauth2/auth?client_id=grafana', ...over,
});
const loginReq = () => new Request('https://x/oauth2/login?login_challenge=lc');

test('login skip=true with another user\'s live session revokes that login session by sid and re-enters the request', async () => {
  const { api, calls } = stubOAuth2({ getOAuth2LoginRequest: mismatchLogin() });
  const res = await handleLogin(loginReq(), { oauth2: api, getSession: otherUserSession, getIdentity: async () => activeMember() });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://hydra.othala.test/oauth2/auth?client_id=grafana');
  assert.deepEqual(calls.revokeLoginSessions, [{ sid: 'sid-1' }], 'revoke by sid only, never subject-wide');
  assert.equal(calls.acceptLogin, 0, 'acceptLogin must NOT be called on subject mismatch');
});

test('login skip=true subject mismatch without a session_id is 502 and revokes nothing', async () => {
  const { api, calls } = stubOAuth2({ getOAuth2LoginRequest: mismatchLogin({ session_id: undefined }) });
  const res = await handleLogin(loginReq(), { oauth2: api, getSession: otherUserSession, getIdentity: async () => activeMember() });
  assert.equal(res.status, 502);
  assert.equal(calls.revokeLoginSessions, undefined);
});

test('login skip=true subject mismatch is 502 when the sid revoke throws', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LoginRequest: mismatchLogin(),
    revokeOAuth2LoginSessions: async () => { throw new Error('hydra down'); },
  });
  const res = await handleLogin(loginReq(), { oauth2: api, getSession: otherUserSession, getIdentity: async () => activeMember() });
  assert.equal(res.status, 502);
  assert.equal(calls.acceptLogin, 0);
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
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-login');
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

test('FIX-E: POST Allow with an action-less 4-part csrf_token returns 400', async () => {
  _resetForTests();
  // Strip the action segment (ts.id.nonce.action.sig -> ts.id.nonce.sig).
  const [ts, id, nonce, , sig] = signToken('id-1', 'consent').split('.');
  const csrfToken = [ts, id, nonce, sig].join('.');
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
  assert.equal(res.status, 400, '4-part token must be rejected');
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
  process.env.OTHALA_PUBLIC_URL = 'https://sso.othala.test';
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
        id: 's1',
        active: true,
        identity: { id: 'id-1', state: 'active', schema_id: 'family', schema_url: '', traits: {} },
      }),
      revokeSession: async () => {},
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

// ── logout ends the SSO session ───────────────────────────────────────────────

function logoutRequest() {
  return new Request('https://x/oauth2/logout?logout_challenge=gc', { headers: { cookie: 'ory_kratos_session=s' } });
}

test('logout revokes the subject\'s Kratos session before accepting', async () => {
  const live = session();
  const order = [];
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: live.identity.id }),
  });
  const accept = api.acceptOAuth2LogoutRequest;
  api.acceptOAuth2LogoutRequest = async (p) => { order.push('accept'); return accept(p); };
  const revoked = [];
  const res = await handleLogout(logoutRequest(), {
    oauth2: api,
    getSession: async () => live,
    revokeSession: async (id) => { order.push('revoke'); revoked.push(id); },
  });
  assert.deepEqual(revoked, [live.id], 'the live session is revoked by id');
  assert.deepEqual(order, ['revoke', 'accept'], 'revoke happens before accept');
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-logout');
  assert.equal(calls.acceptLogout, 1);
});

test('logout does not accept when the session revoke fails', async () => {
  const live = session();
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: live.identity.id }),
  });
  process.env.OTHALA_PUBLIC_URL = 'https://sso.othala.test';
  try {
    const res = await handleLogout(logoutRequest(), {
      oauth2: api,
      getSession: async () => live,
      revokeSession: async () => { throw new Error('kratos admin 500'); },
    });
    assert.equal(calls.acceptLogout, 0, 'acceptLogout must NOT be called when revoke fails');
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/auth/error?reason=auth-unreachable');
  } finally {
    delete process.env.OTHALA_PUBLIC_URL;
  }
});

test('logout does not accept when the live session carries no id', async () => {
  const live = session('aal1', ['password'], { id: undefined });
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: live.identity.id }),
  });
  let revokes = 0;
  const res = await handleLogout(logoutRequest(), {
    oauth2: api,
    getSession: async () => live,
    revokeSession: async () => { revokes++; },
  });
  assert.equal(revokes, 0);
  assert.equal(calls.acceptLogout, 0);
  assert.match(res.headers.get('location') ?? '', /\/auth\/error\?reason=auth-unreachable$/);
});

test('logout subject mismatch neither revokes nor accepts', async () => {
  const live = session('aal1', ['password'], { identity: whoamiIdentity(identity({ id: 'id-2' })) });
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: 'id-1' }),
  });
  let revokes = 0;
  const res = await handleLogout(logoutRequest(), {
    oauth2: api,
    getSession: async () => live,
    revokeSession: async () => { revokes++; },
  });
  assert.equal(revokes, 0, 'another user\'s session is never revoked');
  assert.equal(calls.acceptLogout, 0);
  assert.equal(res.status, 302);
  assert.ok(res.headers.get('location')?.endsWith('/'));
});

test('logout with no live session accepts without a revoke', async () => {
  const { api, calls } = stubOAuth2();
  let revokes = 0;
  const res = await handleLogout(logoutRequest(), {
    oauth2: api,
    getSession: async () => null,
    revokeSession: async () => { revokes++; },
  });
  assert.equal(revokes, 0);
  assert.equal(calls.acceptLogout, 1);
  assert.equal(res.status, 302);
});

test('logout with an empty subject revokes the live session, then accepts', async () => {
  const live = session();
  const order = [];
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: '' }),
  });
  const accept = api.acceptOAuth2LogoutRequest;
  api.acceptOAuth2LogoutRequest = async (p) => { order.push('accept'); return accept(p); };
  const revoked = [];
  const res = await handleLogout(logoutRequest(), {
    oauth2: api,
    getSession: async () => live,
    revokeSession: async (id) => { order.push('revoke'); revoked.push(id); },
  });
  assert.deepEqual(revoked, [live.id]);
  assert.deepEqual(order, ['revoke', 'accept']);
  assert.equal(res.status, 302);
  assert.equal(calls.acceptLogout, 1);
});

test('logout with an empty subject and no session accepts without a revoke', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: '' }),
  });
  let revokes = 0;
  const res = await handleLogout(logoutRequest(), {
    oauth2: api,
    getSession: async () => null,
    revokeSession: async () => { revokes++; },
  });
  assert.equal(revokes, 0);
  assert.equal(calls.acceptLogout, 1);
  assert.equal(res.status, 302);
});

test('logout with an empty subject does not accept when the revoke fails', async () => {
  const live = session();
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: '' }),
  });
  process.env.OTHALA_PUBLIC_URL = 'https://sso.othala.test';
  try {
    const res = await handleLogout(logoutRequest(), {
      oauth2: api,
      getSession: async () => live,
      revokeSession: async () => { throw new Error('kratos admin 500'); },
    });
    assert.equal(calls.acceptLogout, 0);
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/auth/error?reason=auth-unreachable');
  } finally {
    delete process.env.OTHALA_PUBLIC_URL;
  }
});

test('logout with rp_initiated:false bounces to the portal logout and neither revokes nor accepts', async () => {
  const live = session();
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: live.identity.id, rp_initiated: false }),
  });
  const revoked = [];
  process.env.OTHALA_PUBLIC_URL = 'https://sso.othala.test';
  try {
    const res = await handleLogout(logoutRequest(), {
      oauth2: api,
      getSession: async () => live,
      revokeSession: async (id) => { revoked.push(id); },
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/auth/logout');
    assert.deepEqual(revoked, []);
    assert.equal(calls.acceptLogout, 0);
  } finally {
    delete process.env.OTHALA_PUBLIC_URL;
  }
});

test('logout redirects to auth-unreachable, accepting nothing, when the session lookup throws', async () => {
  const { api, calls } = stubOAuth2();
  process.env.OTHALA_PUBLIC_URL = 'https://sso.othala.test';
  try {
    const res = await handleLogout(logoutRequest(), {
      oauth2: api,
      getSession: async () => { throw new Error('kratos down'); },
    });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), 'https://sso.othala.test/auth/error?reason=auth-unreachable');
    assert.equal(calls.acceptLogout, 0);
  } finally {
    delete process.env.OTHALA_PUBLIC_URL;
  }
});

// Invariant: login and consent admit only gated members; denials are opaque to clients and logged server-side.

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

if (!process.env.CSRF_SECRET) {
  process.env.CSRF_SECRET = 'test-secret-must-be-at-least-32-chars-long!!';
}

function activeMember(overrides = {}) {
  return {
    ...identity({ id: 'id-1', username: 'ada', email: 'a@othala.test', displayName: 'Ada', metadataAdmin: { groups: ['grafana-access'] } }),
    ...overrides,
  };
}

function stubOAuth2(over = {}) {
  const calls = { acceptLogin: 0, rejectLogin: 0, acceptConsent: 0, rejectConsent: 0, acceptLogout: 0 };
  const api = {
    getOAuth2LoginRequest: over.getOAuth2LoginRequest
      ?? (async () => oauth2LoginRequest({ skip: true, subject: 'id-1' })),
    getOAuth2ConsentRequest: over.getOAuth2ConsentRequest
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

function defaultSession(overrides = {}) {
  return async () => session('aal1', ['password'], { identity: whoamiIdentity(activeMember()), ...overrides });
}

test('buildLoginReturnTo is a RELATIVE path (no scheme/host)', () => {
  const r = buildLoginReturnTo('lc');
  assert.equal(r, '/oauth2/login?login_challenge=lc');
  assert.ok(r.startsWith('/') && !r.includes('://'));
});

test('login accepts an active member (skip path)', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getIdentity: async () => activeMember(),
    getSession: defaultSession(),
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
    assert.equal(calls.rejectLoginReason, 'access_denied', 'error_description must be opaque');
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
  const u = new URL(loc, 'https://sso.othala.test');
  assert.equal(u.pathname, '/auth/login');
  assert.equal(u.searchParams.get('return_to'), '/oauth2/login?login_challenge=lc');
});

test('login 400 on missing challenge', async () => {
  const res = await handleLogin(new Request('https://x/oauth2/login'), {});
  assert.equal(res.status, 400);
});

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

test('logout accepts and redirects', async () => {
  const { api, calls } = stubOAuth2();
  const res = await handleLogout(new Request('https://x/oauth2/logout?logout_challenge=gc'), { oauth2: api, getSession: async () => null });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), 'https://sso.othala.test/after-logout');
  assert.equal(calls.acceptLogout, 1);
});

test('logout 400 on missing challenge', async () => {
  const res = await handleLogout(new Request('https://x/oauth2/logout'), {});
  assert.equal(res.status, 400);
});

test('T1: consent skip=true auto-accepts (REGRESSION GUARD)', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email', 'profile'] }),
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
  assert.equal(calls.acceptConsent, 1, 'acceptConsent must be called once');
  assert.equal(calls.rejectConsent, 0, 'rejectConsent must NOT be called');
  assert.ok(
    !res.headers.get('location')?.includes('/auth/consent'),
    'skip=true must NOT bounce to the grant screen',
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
  assert.equal(calls.acceptConsentBody.remember, false, 'consent must not be remembered');
});

test('T2: consent skip=false bounces to /auth/consent with challenge', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['openid', 'email'] }),
  });
  const res = await handleConsent(
    new Request('https://x/oauth2/consent?consent_challenge=cc'),
    {
      oauth2: api,
      getIdentity: async () => activeMember(),
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
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called on skip=false');
});

test('T2b: consent skip=false but manifest skip_consent:true AUTO-ACCEPTS', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['openid', 'email'] }),
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

test('T3: POST Allow accepts without remembering consent, with claims', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email', 'profile'] }),
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
  assert.equal(calls.acceptConsentBody.remember, false, 'consent must not be remembered');
  assert.equal(calls.acceptConsentBody.remember_for, undefined);
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile'], 'grant_scope must match requested_scope');
  assert.equal(calls.acceptConsentBody.session.id_token.email, 'a@othala.test', 'id_token.email must be set');
});

test('T4: POST Deny rejects and redirects', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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

test('T5: POST Allow rejects with access_denied on session-subject mismatch', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'other-id', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called on subject mismatch');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called on subject mismatch');
  assert.match(calls.rejectConsentReason, /mismatch/, 'rejection reason must mention mismatch');
});

test('T6: describeScopeList maps known scopes and falls back for unknown', () => {
  const result = describeScopeList(['openid', 'email', 'groups', 'profile', 'offline_access', 'unknown_scope']);

  assert.equal(result.length, 6, 'must return one entry per scope');

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

  assert.equal(result[5].scope, 'unknown_scope');
  assert.equal(result[5].description, 'unknown_scope', 'unknown scope must fall back to scope name');
});

test('D1: POST Allow with missing csrf_token returns 400', async () => {
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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

test('A4a: audiobookshelf access-group holder gets user role, groups unioned', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'audiobookshelf' }, requested_scope: ['openid', 'email', 'groups'] }),
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
  assert.ok(Array.isArray(idToken.groups), 'groups must be an array');
  assert.ok(idToken.groups.includes('audiobookshelf-access'), 'identity group audiobookshelf-access must be preserved');
  assert.ok(!idToken.groups.includes('grafana-access'), 'another app\'s group must not be sent');
  assert.ok(idToken.groups.includes('user'), 'role claim_emit group user must be present');
  assert.equal(idToken.email, 'a@othala.test', 'email must still be present');
});

test('A4b: grafana admin holds both groups, highest-ranked role (admin) wins, groups unioned', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['openid', 'email', 'groups'] }),
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
  assert.deepEqual(idToken.grafana_role, ['GrafanaAdmin'], 'grafana_role claim must be injected');
  assert.ok(Array.isArray(idToken.groups), 'groups must be an array');
  assert.ok(idToken.groups.includes('admin'), 'admin role claim_emit group must be present');
  assert.ok(idToken.groups.includes('grafana-access'), 'identity group grafana-access must be preserved');
  assert.ok(idToken.groups.includes('grafana-admin'), 'identity group grafana-admin must be preserved');
  assert.equal(idToken.email, 'a@othala.test', 'email must still be present');
});

test('A4c: grafana override (roles.grafana=admin) beats group_role_map viewer', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['openid', 'email', 'groups'] }),
  });
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
  assert.deepEqual(idToken.grafana_role, ['GrafanaAdmin'], 'override must beat group_role_map');
});

test('A4e: roleless manifest -> base claims only, groups emitted', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'unknown-client' }, requested_scope: ['email', 'profile'] }),
  });
  const identity = activeMember({
    metadata_admin: { groups: ['family', 'access-unknown-client'] },
  });
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
  assert.equal(idToken.email, 'a@othala.test', 'email must be present');
  assert.equal('groups' in idToken, false, 'groups absent when groups scope not requested');
  assert.ok(!('grafana_role' in idToken), 'no role claims injected when manifest declares no roles');
  assert.ok(!('roles' in idToken), 'no roles claim injected when manifest declares no roles');
});

test('D3: grafana skip path injects grafana_role from manifest (regression guard)', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email', 'profile'] }),
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
  assert.deepEqual(idToken.grafana_role, ['Viewer'], 'grafana_role must be injected for grafana viewer');
  assert.equal(calls.acceptConsentBody.remember, false);
  assert.deepEqual(calls.acceptConsentBody.grant_scope, ['email', 'profile'], 'grant_scope must match');
  assert.equal(idToken.email, 'a@othala.test', 'id_token.email must be set');
});

test('C: skip_access_check bypasses access-group check', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
  });
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
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
  });
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
    assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque');
    const logged = warnArgs.find((a) => a[0].includes('oauth2/consent'));
    assert.ok(logged, 'console.warn must be called');
    assert.equal(logged[1].reason, 'identity not active', 'real reason must be in the server-side log');
  } finally {
    console.warn = origWarn;
  }
});

test('T7a: POST rejects when there is no active session (getSession returns null)', async () => {
  _resetForTests();
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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
  assert.equal(res.status, 302, 'should redirect (reject path)');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called when session is absent');
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called when session is absent');
  assert.match(calls.rejectConsentReason, /no active session/, 'rejection reason must mention no active session');
});

test('T7b: POST Allow re-gates and rejects an inactive identity', async () => {
  _resetForTests();
  const csrfToken = signToken('id-1', 'consent');
  const { api, calls } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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
    getIdentity: async () => activeMember({ state: 'inactive', metadata_admin: { groups: ['grafana-access'] } }),
    manifest: (id) => id === 'grafana' ? grafanaManifest : undefined,
  });
  assert.equal(res.status, 302, 'should redirect (reject path)');
  assert.equal(calls.acceptConsent, 0, 'acceptConsent must NOT be called for inactive identity on allow path');
  assert.equal(calls.rejectConsent, 1, 'rejectConsent must be called when re-gate fails for inactive identity');
  assert.equal(calls.rejectConsentReason, 'access_denied', 'error_description must be opaque on allow-path re-gate');
});

test('deepMergeClaims: recursive nested-object merge (array union, scalar src-wins, dst-only keys preserved)', () => {
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

  assert.deepEqual(
    dst.resource_access.myapp.roles,
    ['user', 'admin'],
    'array conflict inside nested object becomes union',
  );
  assert.deepEqual(
    dst.resource_access.otherapp.roles,
    ['viewer'],
    'dst-only nested key must be preserved after merge',
  );
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
  deepMergeClaims(null, { a: 1 });
  deepMergeClaims({ a: 1 }, null);
  deepMergeClaims(undefined, { a: 1 });
});

test('FIX-A: login skip=true with NO live Kratos session redirects to login UI', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LoginRequest: async () => oauth2LoginRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' } }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => null,   // no live session
    getIdentity: async () => activeMember(),
  });
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
const mismatchLogin = (over = {}) => async () => oauth2LoginRequest({
  skip: true, subject: 'id-1', client: { client_id: 'grafana' },
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
    getOAuth2LoginRequest: async () => oauth2LoginRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' } }),
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
    getOAuth2LoginRequest: async () => oauth2LoginRequest({ skip: true, subject: 'id-1', client: { client_id: 'grafana' } }),
  });
  const res = await handleLogin(new Request('https://x/oauth2/login?login_challenge=lc'), {
    oauth2: api,
    getSession: async () => { throw new Error('kratos network error'); },
    getIdentity: async () => activeMember(),
  });
  assert.equal(res.status, 502, 'Kratos error on skip path must return 502');
  assert.equal(calls.acceptLogin, 0, 'acceptLogin must NOT be called on getSession error');
});

test('FIX-E: POST Allow with an action-less 4-part csrf_token returns 400', async () => {
  _resetForTests();
  const [ts, id, nonce, , sig] = signToken('id-1', 'consent').split('.');
  const csrfToken = [ts, id, nonce, sig].join('.');
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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
  const csrfToken = signToken('id-1', 'deactivate');
  const { api } = stubOAuth2({
    getOAuth2ConsentRequest: async () => oauth2ConsentRequest({ skip: false, subject: 'id-1', client: { client_id: 'grafana' }, requested_scope: ['email'] }),
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

test('FIX-F: logout subject mismatch (live session belongs to different user) redirects to home', async () => {
  const { api, calls } = stubOAuth2({
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: 'id-1' }),
  });
  process.env.OTHALA_PUBLIC_URL = 'https://sso.othala.test';
  try {
    const res = await handleLogout(
      new Request('https://x/oauth2/logout?logout_challenge=gc', {
        headers: { cookie: 'session=s2' },
      }),
      {
        oauth2: api,
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
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: 'id-1' }),
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
    getOAuth2LogoutRequest: async () => oauth2LogoutRequest({ subject: 'id-1' }),
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

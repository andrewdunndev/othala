// Invariant: the admin listener serves only admin routes and refuses to boot on weak secrets.

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Readable } from 'node:stream';
import {
  isAdminRoute,
  isAdminEndpoint,
  bearerMatches,
  parseBearer,
  handleAdminRequest,
  LOGIN_CODE_ADMIN_REFUSAL,
  LOGIN_CODE_UNAVAILABLE,
  USERNAME_CHANGE_REFUSAL,
  PROFILE_UPDATE_UNAVAILABLE,
  usernameChangeVerdict,
  startupEnvErrors,
  ADMIN_GET_ROUTES,
  ADMIN_POST_ROUTES,
} from '../src/server/listen.mjs';
import { asAdmin, identity, session, withCredential, withPasskey, withTotp, withWebauthnKey } from '../src/lib/test-builders.ts';
import * as secondFactorRuntime from '../src/lib/second-factor-gate.ts';
import { emailChangeLocked, emailChangeVerdict, EMAIL_CHANGE_REFUSAL } from '../src/lib/profile-gate.ts';
import { getIdentity, listSessions, revokeSession } from '../src/lib/admin-api.ts';
import { decideAccess } from '../src/lib/gate.ts';

const runtime = { KRATOS_ADMIN_URL: 'http://kratos.test', HYDRA_ADMIN_URL: 'http://hydra.test', ...secondFactorRuntime, emailChangeVerdict, getIdentity, listSessions, revokeSession, decideAccess };
const handle = (req, res, rt = runtime) => handleAdminRequest(req, res, rt);

const ADMIN_UUID = '11111111-1111-1111-1111-111111111111';
const OTHER_UUID = '22222222-2222-2222-2222-222222222222';

function fakeRes() {
  return {
    statusCode: 0,
    body: '',
    headers: null,
    headersSent: false,
    writeHead(code, headers) { this.statusCode = code; this.headers = headers; this.headersSent = true; return this; },
    end(chunk) { if (chunk) this.body += chunk; },
  };
}

function fakeReq({ method = 'GET', url = '/', headers = {}, body = '' } = {}) {
  const req = Readable.from(body ? [Buffer.from(body)] : []);
  req.method = method;
  req.url = url;
  req.headers = headers;
  return req;
}

const realFetch = globalThis.fetch;

/** Send the fixed Kratos admin URL (http://kratos:4434) to a mock server on `port`; returns the restore. */
function redirectKratosAdmin(port) {
  globalThis.fetch = (url, init) =>
    realFetch(String(url).replace('http://kratos:4434', `http://127.0.0.1:${port}`), init);
  return () => { globalThis.fetch = realFetch; };
}

let restoreKratos = () => {};

beforeEach(() => {
  delete process.env.RECOVERY_GATE_SECRET;
  restoreKratos();
});

test('admin GET mux serves exactly /healthz and /readyz', () => {
  assert.deepEqual([...ADMIN_GET_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.equal(isAdminRoute('GET', '/healthz'), true);
  assert.equal(isAdminRoute('GET', '/readyz'), true);
});

test('admin POST mux serves exactly the admin endpoints', () => {
  assert.deepEqual([...ADMIN_POST_ROUTES].sort(), [
    '/admin/login-code-gate',
    '/admin/passkey-prune',
    '/admin/profile-gate',
    '/admin/profile-sessions',
    '/admin/recovery-gate',
    '/admin/second-factor-gate',
  ]);
});

test('admin POST paths are NOT public GET routes (disjoint from public mux)', () => {
  for (const p of ADMIN_POST_ROUTES) {
    assert.equal(isAdminRoute('GET', p), false, `${p} must not be a public GET admin route`);
  }
});

test('admin mux does NOT serve any public/challenge path', () => {
  for (const p of ['/', '/auth/login', '/admin', '/oauth2/login', '/oauth2/consent', '/oauth2/logout']) {
    assert.equal(isAdminEndpoint('GET', p), false, `${p} must not be an admin endpoint`);
    assert.equal(isAdminEndpoint('POST', p), false, `${p} must not be an admin endpoint`);
  }
});

test('challenge + public paths 404 on the admin port', async () => {
  const paths = [
    '/oauth2/login?login_challenge=x',
    '/oauth2/consent?consent_challenge=x',
    '/',
    '/admin',
    '/auth/login',
  ];
  for (const p of paths) {
    const res = fakeRes();
    await handle(fakeReq({ method: 'GET', url: p }), res);
    assert.equal(res.statusCode, 404, `${p} should 404 on admin port`);
  }
});

test('healthz is liveness only: 200 with no dependency call', async () => {
  const res = fakeRes();
  await handle(fakeReq({ method: 'GET', url: '/healthz' }), res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { status: 'ok' });
});

test('readyz is 200 when Kratos and Hydra are ready, 503 naming the one that is not', async () => {
  const realFetch = globalThis.fetch;
  try {
    for (const [down, status, failed] of [[null, 200, undefined], ['hydra', 503, ['hydra']], ['kratos', 503, ['kratos']]]) {
      globalThis.fetch = async (url) => {
        if (down && String(url).includes(down)) throw new Error('refused');
        return { ok: true };
      };
      const res = fakeRes();
      await handle(fakeReq({ method: 'GET', url: '/readyz' }), res);
      assert.equal(res.statusCode, status);
      assert.deepEqual(JSON.parse(res.body).failed, failed);
    }
    globalThis.fetch = async () => ({ ok: false });
    const res = fakeRes();
    await handle(fakeReq({ method: 'GET', url: '/readyz' }), res);
    assert.deepEqual(JSON.parse(res.body).failed, ['hydra', 'kratos']);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('a served admin POST path on the wrong method (GET) 404s', async () => {
  for (const p of ADMIN_POST_ROUTES) {
    const res = fakeRes();
    await handle(fakeReq({ method: 'GET', url: p }), res);
    assert.equal(res.statusCode, 404, `GET ${p} should 404`);
  }
});

test('parseBearer extracts the token', () => {
  assert.equal(parseBearer('Bearer abc123'), 'abc123');
  assert.equal(parseBearer('bearer abc'), '');
  assert.equal(parseBearer(undefined), '');
});

test('bearerMatches is fail-closed when the expected secret is unset', () => {
  assert.equal(bearerMatches('anything', ''), false);
  assert.equal(bearerMatches('', ''), false);
  assert.equal(bearerMatches(undefined, ''), false);
});

test('bearerMatches accepts only the exact secret (constant-time path)', () => {
  assert.equal(bearerMatches('s3cret', 's3cret'), true);
  assert.equal(bearerMatches('s3creT', 's3cret'), false);
  assert.equal(bearerMatches('s3cre', 's3cret'), false); // length mismatch
  assert.equal(bearerMatches('s3cretX', 's3cret'), false);
});

test('startup fails when RECOVERY_GATE_SECRET is set but shorter than 32 bytes', () => {
  process.env.RECOVERY_GATE_SECRET = 'short-secret';
  const errors = startupEnvErrors();
  assert.ok(errors.some((e) => /RECOVERY_GATE_SECRET/.test(e) && /32 bytes/.test(e)));
});

test('startup fails when CSRF_SECRET is unset or shorter than 32 bytes', () => {
  process.env.RECOVERY_GATE_SECRET = 'x'.repeat(32);
  const saved = process.env.CSRF_SECRET;
  try {
    process.env.CSRF_SECRET = 'x'.repeat(10);
    assert.ok(startupEnvErrors().some((e) => /CSRF_SECRET/.test(e) && /32 bytes/.test(e)));
    delete process.env.CSRF_SECRET;
    assert.ok(startupEnvErrors().some((e) => /CSRF_SECRET/.test(e)));
    process.env.CSRF_SECRET = 'x'.repeat(32);
    assert.ok(!startupEnvErrors().some((e) => /CSRF_SECRET/.test(e)));
  } finally {
    if (saved === undefined) delete process.env.CSRF_SECRET;
    else process.env.CSRF_SECRET = saved;
  }
});

test('POST /admin/recovery-gate is fail-closed when RECOVERY_GATE_SECRET unset (403)', async () => {
  const res = fakeRes();
  await handle(
    fakeReq({ method: 'POST', url: '/admin/recovery-gate', headers: { authorization: 'Bearer x' }, body: '{}' }),
    res,
  );
  assert.equal(res.statusCode, 403);
  assert.deepEqual(JSON.parse(res.body), { error: 'forbidden' });
});

test('POST /admin/recovery-gate REFUSES recovery when the admin-API marker is true (403)', async () => {
  const mockKratos = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: ADMIN_UUID, metadata_admin: { admin: true, groups: ['admin', 'family'] } }));
  });
  await new Promise((r) => mockKratos.listen(0, '127.0.0.1', r));
  const { port } = mockKratos.address();
  restoreKratos = redirectKratosAdmin(port);
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  try {
    const res = fakeRes();
    await handle(
      fakeReq({
        method: 'POST',
        url: '/admin/recovery-gate',
        headers: { authorization: 'Bearer gate-secret' },
        body: JSON.stringify({ identity_id: ADMIN_UUID, is_admin: false, traits: { email: 'admin@othala.test' } }),
      }),
      res,
    );
    assert.equal(res.statusCode, 403, 'admin marker true (from admin API) must refuse recovery');
    assert.match(res.body, /console-only/, 'refusal must be the admin-marker reason, not a fail-closed fallback');
  } finally {
    await new Promise((r) => mockKratos.close(r));
    restoreKratos();
  }
});

test('POST /admin/recovery-gate ALLOWS recovery for a non-admin identity (200)', async () => {
  const mockKratos = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: OTHER_UUID, metadata_admin: {} }));
  });
  await new Promise((r) => mockKratos.listen(0, '127.0.0.1', r));
  const { port } = mockKratos.address();
  restoreKratos = redirectKratosAdmin(port);
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  try {
    const res = fakeRes();
    await handle(
      fakeReq({
        method: 'POST',
        url: '/admin/recovery-gate',
        headers: { authorization: 'Bearer gate-secret' },
        body: JSON.stringify({ identity_id: OTHER_UUID, is_admin: false, traits: { email: 'kid@othala.test' } }),
      }),
      res,
    );
    assert.equal(res.statusCode, 200);
  } finally {
    await new Promise((r) => mockKratos.close(r));
    restoreKratos();
  }
});

test('POST /admin/recovery-gate refuses an unknown identity (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(
    fakeReq({
      method: 'POST',
      url: '/admin/recovery-gate',
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: OTHER_UUID, traits: { email: 'kid@othala.test' } }),
    }),
    res,
  );
  assert.equal(res.statusCode, 403, 'unknown identity must refuse (fail-closed)');
});

test('POST /admin/recovery-gate refuses an unknown identity whatever the payload says (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(
    fakeReq({
      method: 'POST',
      url: '/admin/recovery-gate',
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: OTHER_UUID, is_admin: 'true' }),
    }),
    res,
  );
  assert.equal(res.statusCode, 403, 'unknown identity must refuse (fail-closed)');
});

test('bearer rejection on recovery-gate is 403 (not 401) — Kratos can_interrupt safety', async () => {
  process.env.RECOVERY_GATE_SECRET = 'correct';
  const res = fakeRes();
  await handle(
    fakeReq({ method: 'POST', url: '/admin/recovery-gate', headers: { authorization: 'Bearer wrong' }, body: '{}' }),
    res,
  );
  assert.equal(res.statusCode, 403, 'must be 403, not 401');
  assert.notEqual(res.statusCode, 401, 'must NOT be 401 (would be fail-open under can_interrupt)');
  assert.deepEqual(JSON.parse(res.body), { error: 'forbidden' });
});

async function withMockKratos(respond, fn) {
  const mockKratos = http.createServer(respond);
  await new Promise((r) => mockKratos.listen(0, '127.0.0.1', r));
  restoreKratos = redirectKratosAdmin(mockKratos.address().port);
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  try {
    await fn();
  } finally {
    await new Promise((r) => mockKratos.close(r));
    restoreKratos();
  }
}

function postLoginCodeGate(body, bearer = 'gate-secret') {
  return fakeReq({
    method: 'POST',
    url: '/admin/login-code-gate',
    headers: { authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
}

function identityServer(metadataAdmin) {
  return (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: ADMIN_UUID, metadata_admin: metadataAdmin }));
  };
}

test('login-code-gate REFUSES an admin-marked identity with the neutral message (403)', async () => {
  await withMockKratos(identityServer({ admin: true }), async () => {
    const res = fakeRes();
    await handle(postLoginCodeGate({ identity_id: ADMIN_UUID, is_admin: false }), res);
    assert.equal(res.statusCode, 403);
    assert.equal(JSON.parse(res.body).messages[0].messages[0].text, LOGIN_CODE_ADMIN_REFUSAL);
  });
});

test('login-code-gate ALLOWS a member (200)', async () => {
  await withMockKratos(identityServer({ groups: ['family'], admin: false }), async () => {
    const res = fakeRes();
    await handle(postLoginCodeGate({ identity_id: OTHER_UUID, is_admin: false }), res);
    assert.equal(res.statusCode, 200);
  });
});

test('login-code-gate REFUSES when the admin API fails (fail-closed, 403)', async () => {
  await withMockKratos((req, res) => { res.writeHead(500); res.end(); }, async () => {
    const res = fakeRes();
    await handle(postLoginCodeGate({ identity_id: OTHER_UUID, is_admin: false }), res);
    assert.equal(res.statusCode, 403);
    assert.equal(JSON.parse(res.body).messages[0].messages[0].text, LOGIN_CODE_UNAVAILABLE);
  });
});

test('login-code-gate REFUSES when the id is missing (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  for (const body of [{ is_admin: false }]) {
    const res = fakeRes();
    await handle(postLoginCodeGate(body), res);
    assert.equal(res.statusCode, 403);
  }
});

test('login-code-gate rejects a wrong bearer with 403 before reading the body', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(postLoginCodeGate({ identity_id: OTHER_UUID }, 'wrong'), res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(JSON.parse(res.body), { error: 'forbidden' });
});

const STORED = identity({ id: OTHER_UUID, username: 'ada.lovelace' });

function postProfileGate(body, bearer = 'gate-secret') {
  return fakeReq({
    method: 'POST',
    url: '/admin/profile-gate',
    headers: { authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
}

function profilePayload(traits) {
  return { identity_id: STORED.id, is_admin: false, groups: [], traits };
}

function storedIdentityServer(stored) {
  return (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stored));
  };
}

function refusalText(res) {
  const [msg] = JSON.parse(res.body).messages;
  assert.equal(msg.instance_ptr, '#/traits/username');
  return msg.messages[0].text;
}

test('usernameChangeVerdict refuses a rename and allows the stored username', () => {
  assert.deepEqual(usernameChangeVerdict(STORED, 'ada.lovelace'), { refuse: false });
  assert.deepEqual(usernameChangeVerdict(STORED, 'ada.byron'), { refuse: true, text: USERNAME_CHANGE_REFUSAL });
  assert.deepEqual(usernameChangeVerdict(STORED, 'Ada.Lovelace'), { refuse: true, text: USERNAME_CHANGE_REFUSAL });
});

test('usernameChangeVerdict refuses when either side is not a username', () => {
  assert.equal(usernameChangeVerdict(STORED, undefined).text, PROFILE_UPDATE_UNAVAILABLE);
  assert.equal(usernameChangeVerdict({ ...STORED, traits: {} }, 'ada.lovelace').text, PROFILE_UPDATE_UNAVAILABLE);
  assert.equal(usernameChangeVerdict(null, 'ada.lovelace').refuse, true);
});

test('profile-gate REFUSES a username change with the neutral message (403)', async () => {
  await withMockKratos(storedIdentityServer(STORED), async () => {
    const res = fakeRes();
    await handle(postProfileGate(profilePayload({ ...STORED.traits, username: 'ada.byron' })), res);
    assert.equal(res.statusCode, 403);
    assert.equal(refusalText(res), USERNAME_CHANGE_REFUSAL);
  });
});

test('profile-gate ALLOWS a profile update that keeps the username (200)', async () => {
  await withMockKratos(storedIdentityServer(STORED), async () => {
    const res = fakeRes();
    await handle(postProfileGate({ ...profilePayload({ ...STORED.traits, displayName: 'Ada' }), authentication_methods: [] }), res);
    assert.equal(res.statusCode, 200);
  });
});

const KEYLESS = { ...STORED, credentials: { code: STORED.credentials.code } };
const KEYED = STORED;
const at = (n) => new Date(Date.UTC(2026, 0, 1, 0, n)).toISOString();
const entry = (method, n, aal = 'aal1') => ({ method, aal, completed_at: at(n) });
const NEW_EMAIL = { ...STORED.traits, email: 'new@example.test' };

test('emailChangeVerdict table', () => {
  const refuse = (stored, traits, methods) => emailChangeVerdict(stored, traits, methods).refuse;
  assert.equal(refuse(KEYLESS, NEW_EMAIL, [entry('code', 0)]), false, 'keyless with code');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('password', 0), entry('code', 1)]), true, 'password then code');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('code', 0), entry('password', 1)]), false, 'code then password');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('password', 1), entry('code', 0)]), false, 'order of the array is not the order of time');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('code', 0), entry('totp', 1, 'aal2')]), true, 'aal2 never counts');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('password', 0), entry('code', 1), entry('totp', 2, 'aal2')]), true, 'aal2 newer than code');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('code', 0), entry('webauthn', 1)]), false, 'webauthn newest');
  assert.equal(refuse(withPasskey(KEYLESS), NEW_EMAIL, [entry('code', 0), entry('passkey', 1)]), false, 'passkey newest');
  assert.equal(refuse(withPasskey(KEYLESS), NEW_EMAIL, [entry('passkey', 0), entry('code', 1)]), true, 'passkey account, code newest');
  assert.equal(refuse(KEYED, NEW_EMAIL, [{ method: 'password', aal: 'aal1', completed_at: 'not a date' }]), true, 'unparseable');
  assert.equal(refuse(KEYED, NEW_EMAIL, [{ method: 'password', aal: 'aal1' }]), true, 'missing completed_at');
  assert.equal(refuse(KEYED, NEW_EMAIL, undefined), true, 'missing session data');
  assert.equal(refuse(KEYED, NEW_EMAIL, []), true, 'empty session data');
  assert.equal(refuse(KEYED, STORED.traits, [entry('code', 0)]), false, 'unchanged email');
  assert.equal(refuse(KEYED, NEW_EMAIL, [entry('password', 0), entry('code_recovery', 1)]), true, 'a recovery session is not a first factor');
  assert.equal(refuse(KEYED, { ...STORED.traits, email: STORED.traits.email.toUpperCase() }, [entry('code', 0)]), true, 'a case variant is a change');
  assert.equal(refuse(KEYED, { ...STORED.traits, email: ` ${STORED.traits.email}` }, [entry('code', 0)]), true, 'a whitespace variant is a change');
  assert.equal(refuse(KEYED, { ...STORED.traits, recoveryEmail: 'r@example.test' }, [entry('code', 0)]), true, 'recoveryEmail alone');
  const withRecovery = { ...KEYED, traits: { ...STORED.traits, recoveryEmail: 'r@example.test' } };
  assert.equal(refuse(withRecovery, STORED.traits, [entry('code', 0)]), true, 'dropping recoveryEmail is a change');
  assert.equal(refuse(KEYED, { ...STORED.traits, recoveryEmail: '' }, [entry('code', 0)]), false, 'absent equals empty');
  const changed = emailChangeVerdict(KEYED, { ...NEW_EMAIL, recoveryEmail: 'r@example.test' }, [entry('code', 0)]);
  assert.deepEqual(changed.pointers, ['#/traits/email', '#/traits/recoveryEmail']);
  assert.equal(changed.text, EMAIL_CHANGE_REFUSAL);
});

test('emailChangeVerdict counts a key only when the credential holds a secret', () => {
  const afterCode = (stored) => emailChangeVerdict(stored, NEW_EMAIL, [entry('code', 0)]).refuse;
  const schemaOnly = identity({ id: OTHER_UUID, username: 'ada.lovelace', password: false });
  assert.equal(afterCode(schemaOnly), false, 'password entry with empty config');
  assert.equal(afterCode(withCredential(schemaOnly, 'password', { hashed_password: '' })), false, 'empty hash');
  assert.equal(afterCode(KEYED), true, 'password with a hashed_password');
  assert.equal(afterCode(withCredential(schemaOnly, 'passkey', { credentials: [] })), false, 'passkey entry with empty credentials');
  assert.equal(afterCode(withCredential(schemaOnly, 'passkey', {})), false, 'passkey entry with empty config');
  assert.equal(afterCode(withPasskey(schemaOnly)), true, 'passkey with one credential');
  assert.equal(afterCode(withWebauthnKey(schemaOnly)), false, 'second-factor webauthn key');
  assert.equal(afterCode(withWebauthnKey(schemaOnly, { passwordless: true })), true, 'passwordless webauthn key');
  const { credentials: _c, ...bare } = schemaOnly;
  assert.equal(afterCode(bare), true, 'credentials missing');
  assert.equal(afterCode(null), true, 'no stored identity');
});

test('profile-gate refuses an email change from a code session on the changed trait (403)', async () => {
  await withMockKratos(storedIdentityServer(KEYED), async () => {
    const res = fakeRes();
    await handle(postProfileGate({ ...profilePayload({ ...STORED.traits, recoveryEmail: 'r@example.test' }), authentication_methods: [entry('password', 0), entry('code', 1)] }), res);
    assert.equal(res.statusCode, 403);
    const [msg] = JSON.parse(res.body).messages;
    assert.equal(msg.instance_ptr, '#/traits/recoveryEmail');
    assert.equal(msg.messages[0].text, EMAIL_CHANGE_REFUSAL);
  });
});

test('profile-gate allows an email change from a password session (200) and refuses without session data (403)', async () => {
  await withMockKratos(storedIdentityServer(KEYED), async () => {
    const ok = fakeRes();
    await handle(postProfileGate({ ...profilePayload(NEW_EMAIL), authentication_methods: [entry('code', 0), entry('password', 1)] }), ok);
    assert.equal(ok.statusCode, 200);
    const bare = fakeRes();
    await handle(postProfileGate(profilePayload(NEW_EMAIL)), bare);
    assert.equal(bare.statusCode, 403);
  });
});

test('profile-gate REFUSES when the stored identity cannot be read (fail-closed, 403)', async () => {
  await withMockKratos((req, res) => { res.writeHead(500); res.end(); }, async () => {
    const res = fakeRes();
    await handle(postProfileGate(profilePayload(STORED.traits)), res);
    assert.equal(res.statusCode, 403);
    assert.equal(refusalText(res), PROFILE_UPDATE_UNAVAILABLE);
  });
});

test('profile-gate REFUSES when the id is missing (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  for (const body of [{ traits: STORED.traits }]) {
    const res = fakeRes();
    await handle(postProfileGate(body), res);
    assert.equal(res.statusCode, 403);
    assert.equal(refusalText(res), PROFILE_UPDATE_UNAVAILABLE);
  }
});

test('profile-gate rejects a wrong bearer with 403 before reading the body', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(postProfileGate(profilePayload(STORED.traits), 'wrong'), res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(JSON.parse(res.body), { error: 'forbidden' });
});

function postSecondFactorGate(method, body, bearer = 'gate-secret') {
  return fakeReq({
    method: 'POST',
    url: `/admin/second-factor-gate?method=${method}`,
    headers: { authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
}

function secondFactorText(res) {
  const [msg] = JSON.parse(res.body).messages;
  assert.equal(msg.instance_ptr, '#/');
  return msg.messages[0].text;
}

const ADMIN_TOTP_ONLY = withTotp(asAdmin(identity({ id: OTHER_UUID })));

test('second-factor-gate REFUSES an admin unlinking the only totp (403)', async () => {
  let requested = '';
  const server = (req, res) => {
    requested = req.url;
    storedIdentityServer(ADMIN_TOTP_ONLY)(req, res);
  };
  await withMockKratos(server, async () => {
    const res = fakeRes();
    await handle(postSecondFactorGate('totp', { identity_id: OTHER_UUID }), res);
    assert.equal(res.statusCode, 403);
    assert.equal(secondFactorText(res), secondFactorRuntime.SECOND_FACTOR_KEEP);
  });
  assert.match(requested, /include_credential=totp/);
  assert.match(requested, /include_credential=webauthn/);
});

test('second-factor-gate ALLOWS an admin with totp and a key to change keys (200)', async () => {
  await withMockKratos(storedIdentityServer(withWebauthnKey(ADMIN_TOTP_ONLY)), async () => {
    const res = fakeRes();
    await handle(postSecondFactorGate('webauthn', { identity_id: OTHER_UUID }), res);
    assert.equal(res.statusCode, 200);
  });
});

test('second-factor-gate REFUSES without a method, id, readable identity or runtime (403)', async () => {
  const unavailable = secondFactorRuntime.SECOND_FACTOR_UNAVAILABLE;
  await withMockKratos(storedIdentityServer(ADMIN_TOTP_ONLY), async () => {
    for (const [method, body, rt] of [
      ['', { identity_id: OTHER_UUID }, runtime],
      ['totp', {}, runtime],
      ['totp', { identity_id: OTHER_UUID }, {}],
    ]) {
      const res = fakeRes();
      await handle(postSecondFactorGate(method, body), res, rt);
      assert.equal(res.statusCode, 403);
      assert.equal(secondFactorText(res), unavailable);
    }
  });
  await withMockKratos((req, res) => { res.writeHead(500); res.end(); }, async () => {
    const res = fakeRes();
    await handle(postSecondFactorGate('webauthn', { identity_id: OTHER_UUID }), res);
    assert.equal(res.statusCode, 403);
    assert.equal(secondFactorText(res), unavailable);
  });
});

test('second-factor-gate rejects a wrong bearer with 403 before reading the body', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(postSecondFactorGate('totp', { identity_id: OTHER_UUID }, 'wrong'), res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(JSON.parse(res.body), { error: 'forbidden' });
});

const SAVING = session('aal1', ['password'], { id: 'aaaaaaaa-0000-0000-0000-000000000001' });
const OTHER_A = session('aal1', ['password'], { id: 'aaaaaaaa-0000-0000-0000-000000000002' });
const OTHER_B = session('aal1', ['code'], { id: 'aaaaaaaa-0000-0000-0000-000000000003' });

function postProfileSessions(body, bearer = 'gate-secret') {
  return fakeReq({
    method: 'POST',
    url: '/admin/profile-sessions',
    headers: { authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
}

function sessionsServer(calls, listed, listStatus = 200) {
  return (req, res) => {
    calls.push(`${req.method} ${req.url}`);
    if (req.method === 'GET') {
      res.writeHead(listStatus, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(listed));
      return;
    }
    res.writeHead(204);
    res.end();
  };
}

test('profile-sessions ends every other active session and keeps the saving one (200)', async () => {
  const calls = [];
  await withMockKratos(sessionsServer(calls, [SAVING, OTHER_A, OTHER_B]), async () => {
    const res = fakeRes();
    await handle(postProfileSessions({ ...profilePayload(STORED.traits), session_id: SAVING.id }), res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(JSON.parse(res.body), { ended: 2 });
  });
  const canon = (c) => {
    const [verb, target] = c.split(' ');
    const u = new URL(target, 'http://x');
    u.searchParams.sort();
    return `${verb} ${u.pathname}${u.search}`;
  };
  assert.deepEqual(calls.map(canon), [
    `GET /admin/identities/${STORED.id}/sessions?active=true&per_page=1000`,
    `DELETE /admin/sessions/${OTHER_A.id}`,
    `DELETE /admin/sessions/${OTHER_B.id}`,
  ]);
});

test('profile-sessions ends nothing without a session_id, so the saving session survives (200)', async () => {
  const calls = [];
  await withMockKratos(sessionsServer(calls, [SAVING, OTHER_A]), async () => {
    for (const session_id of [undefined, '', '  ']) {
      const res = fakeRes();
      await handle(postProfileSessions({ ...profilePayload(STORED.traits), session_id }), res);
      assert.equal(res.statusCode, 200);
      assert.deepEqual(JSON.parse(res.body), { ended: 0 });
    }
  });
  assert.deepEqual(calls, []);
});

test('profile-sessions answers 200 when the session list fails, since the profile already saved', async () => {
  const calls = [];
  await withMockKratos(sessionsServer(calls, { error: 'down' }, 500), async () => {
    const res = fakeRes();
    await handle(postProfileSessions({ ...profilePayload(STORED.traits), session_id: SAVING.id }), res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(JSON.parse(res.body), { ended: 0 });
  });
  assert.equal(calls.length, 1);
});

test('profile-sessions rejects a wrong bearer with 403 before reading the body', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(postProfileSessions({ identity_id: STORED.id, session_id: SAVING.id }, 'wrong'), res);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(JSON.parse(res.body), { error: 'forbidden' });
});

function postPasskeyPrune(body, bearer = 'gate-secret') {
  return fakeReq({
    method: 'POST',
    url: '/admin/passkey-prune',
    headers: { authorization: `Bearer ${bearer}` },
    body: JSON.stringify(body),
  });
}

test('passkey-prune prunes the named identity and reports the count (200)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const pruned = [];
  const rt = { prunePasskeyNames: async (id) => { pruned.push(id); return 2; } };
  const res = fakeRes();
  await handle(postPasskeyPrune({ identity_id: 'person-1' }), res, rt);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { pruned: 2 });
  assert.deepEqual(pruned, ['person-1']);
});

test('passkey-prune answers 200 and prunes nothing without an identity_id or when the prune fails', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const calls = [];
  const rt = { prunePasskeyNames: async (id) => { calls.push(id); throw new Error('down'); } };
  for (const body of [{}, { identity_id: '  ' }]) {
    const res = fakeRes();
    await handle(postPasskeyPrune(body), res, rt);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(JSON.parse(res.body), { pruned: 0 });
  }
  assert.deepEqual(calls, []);
  const res = fakeRes();
  await handle(postPasskeyPrune({ identity_id: 'person-1' }), res, rt);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { pruned: 0 });
});

test('passkey-prune rejects a wrong bearer with 403 before touching the runtime', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const rt = { prunePasskeyNames: async () => { throw new Error('must not run'); } };
  const res = fakeRes();
  await handle(postPasskeyPrune({ identity_id: 'person-1' }, 'wrong'), res, rt);
  assert.equal(res.statusCode, 403);
});

test('recovery, username and second-factor gates and profile-sessions read the identity via the runtime', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const read = [];
  const recorder = {
    ...runtime,
    async getIdentity(id) { read.push(id); return identity({ id }); },
    async listSessions(id) { read.push(id); return []; },
  };
  const post = (url, body) => fakeReq({
    method: 'POST', url, headers: { authorization: 'Bearer gate-secret' }, body: JSON.stringify(body),
  });
  for (const [url, body] of [
    ['/admin/recovery-gate', { identity_id: 'r' }],
    ['/admin/profile-gate', { identity_id: 'u', traits: {} }],
    ['/admin/second-factor-gate?method=totp', { identity_id: 's' }],
    ['/admin/profile-sessions', { identity_id: 'p', session_id: 'keep' }],
  ]) {
    await handle(post(url, body), fakeRes(), recorder);
  }
  assert.deepEqual(read, ['r', 'u', 's', 'p']);
});

test('emailChangeLocked follows the verdict for the stored identity and session', () => {
  assert.equal(emailChangeLocked(KEYED, [entry('password', 0), entry('code', 1)]), true);
  assert.equal(emailChangeLocked(KEYED, [entry('code', 0), entry('password', 1)]), false);
  assert.equal(emailChangeLocked(KEYLESS, [entry('code', 0)]), false);
});

test('startup fails in production when a required var is unset', () => {
  process.env.RECOVERY_GATE_SECRET = 'x'.repeat(32);
  const names = ['OTHALA_PUBLIC_URL', 'OTHALA_APEX', 'OTHALA_INSTANCE_NAME', 'OTHALA_CONTACT_RECIPIENT', 'OTHALA_SMTP_CONNECTION_URI'];
  const saved = { NODE_ENV: process.env.NODE_ENV, ...Object.fromEntries(names.map((n) => [n, process.env[n]])) };
  const restore = (k, v) => (v === undefined ? delete process.env[k] : (process.env[k] = v));
  try {
    process.env.NODE_ENV = 'production';
    for (const n of names) delete process.env[n];
    const errors = startupEnvErrors();
    for (const n of names) assert.ok(errors.some((e) => e.includes(n)), n);
    process.env.OTHALA_PUBLIC_URL = 'https://auth.example.com';
    process.env.OTHALA_APEX = 'example.com';
    process.env.OTHALA_INSTANCE_NAME = 'Acme';
    process.env.OTHALA_CONTACT_RECIPIENT = 'admin@example.com';
    process.env.OTHALA_SMTP_CONNECTION_URI = 'smtps://u:p@smtp.example.com:465';
    assert.ok(!startupEnvErrors().some((e) => /OTHALA_/.test(e)));
    process.env.NODE_ENV = 'test';
    delete process.env.OTHALA_APEX;
    assert.ok(!startupEnvErrors().some((e) => /OTHALA_APEX/.test(e)), 'dev and test keep their defaults');
  } finally {
    for (const [k, v] of Object.entries(saved)) restore(k, v);
  }
});

test('startup refuses in production without PORTAL_ADMIN_BIND_HOST, and on a wildcard; dev defaults to loopback', () => {
  const names = ['RECOVERY_GATE_SECRET', 'CSRF_SECRET', 'NODE_ENV', 'PORTAL_ADMIN_BIND_HOST', 'OTHALA_PUBLIC_URL', 'OTHALA_APEX', 'OTHALA_INSTANCE_NAME', 'OTHALA_CONTACT_RECIPIENT', 'OTHALA_SMTP_CONNECTION_URI'];
  const saved = Object.fromEntries(names.map((n) => [n, process.env[n]]));
  const restore = (k, v) => (v === undefined ? delete process.env[k] : (process.env[k] = v));
  const bindErrors = () => startupEnvErrors().filter((e) => e.includes('PORTAL_ADMIN_BIND_HOST'));
  try {
    process.env.RECOVERY_GATE_SECRET = 'x'.repeat(32);
    process.env.CSRF_SECRET = 'x'.repeat(32);
    process.env.OTHALA_PUBLIC_URL = 'https://auth.example.com';
    process.env.OTHALA_APEX = 'example.com';
    process.env.OTHALA_INSTANCE_NAME = 'Acme';
    process.env.OTHALA_CONTACT_RECIPIENT = 'admin@example.com';
    process.env.OTHALA_SMTP_CONNECTION_URI = 'smtps://u:p@smtp.example.com:465';
    process.env.NODE_ENV = 'production';
    delete process.env.PORTAL_ADMIN_BIND_HOST;
    assert.equal(bindErrors().length, 1, 'unset in production fails');
    assert.match(bindErrors()[0], /not set/);
    process.env.PORTAL_ADMIN_BIND_HOST = '0.0.0.0';
    assert.equal(bindErrors().length, 1, 'wildcard fails');
    process.env.PORTAL_ADMIN_BIND_HOST = '10.0.0.5';
    assert.equal(bindErrors().length, 0, 'an internal address passes');
    assert.deepEqual(startupEnvErrors(), []);
    // Mutation: unsetting the address must turn a clean boot into a refusal.
    delete process.env.PORTAL_ADMIN_BIND_HOST;
    assert.ok(startupEnvErrors().length > 0);
    process.env.NODE_ENV = 'test';
    assert.equal(bindErrors().length, 0, 'dev keeps the loopback default');
  } finally {
    for (const [k, v] of Object.entries(saved)) restore(k, v);
  }
});

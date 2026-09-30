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
import { asAdmin, identity, session, withTotp, withWebauthnKey } from '../src/lib/test-builders.ts';
import * as secondFactorRuntime from '../src/lib/second-factor-gate.ts';
import { getIdentity, listSessions, revokeSession } from '../src/lib/admin-api.ts';
import { isAdminMarker } from '../src/lib/admin-auth.ts';

const runtime = { ...secondFactorRuntime, getIdentity, listSessions, revokeSession, isAdminMarker };
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

beforeEach(() => {
  delete process.env.RECOVERY_GATE_SECRET;
  delete process.env.KRATOS_ADMIN_URL;
});

test('admin GET mux serves exactly /healthz and /readyz', () => {
  assert.deepEqual([...ADMIN_GET_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.equal(isAdminRoute('GET', '/healthz'), true);
  assert.equal(isAdminRoute('GET', '/readyz'), true);
});

test('admin POST mux serves exactly the admin endpoints', () => {
  assert.deepEqual([...ADMIN_POST_ROUTES].sort(), [
    '/admin/login-code-gate',
    '/admin/profile-sessions',
    '/admin/recovery-gate',
    '/admin/second-factor-gate',
    '/admin/username-gate',
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

test('healthz/readyz return 200 ok on the admin port', async () => {
  for (const p of ['/healthz', '/readyz']) {
    const res = fakeRes();
    await handle(fakeReq({ method: 'GET', url: p }), res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(JSON.parse(res.body), { status: 'ok' });
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
});

test('POST /admin/recovery-gate REFUSES recovery when the admin-API marker is true (403)', async () => {
  const mockKratos = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: ADMIN_UUID, metadata_admin: { admin: true, groups: ['admin', 'family'] } }));
  });
  await new Promise((r) => mockKratos.listen(0, '127.0.0.1', r));
  const { port } = mockKratos.address();
  process.env.KRATOS_ADMIN_URL = `http://127.0.0.1:${port}`;
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
    delete process.env.KRATOS_ADMIN_URL;
  }
});

test('POST /admin/recovery-gate is fail-closed when KRATOS_ADMIN_URL is unset (403, admin-api-unavailable)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
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
  assert.equal(res.statusCode, 403, 'unset KRATOS_ADMIN_URL must fail closed');
  assert.match(res.body, /unavailable/, 'must refuse via the admin-api-unavailable fail-closed path');
});

test('POST /admin/recovery-gate ALLOWS recovery for a non-admin identity (200)', async () => {
  const mockKratos = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: OTHER_UUID, metadata_admin: {} }));
  });
  await new Promise((r) => mockKratos.listen(0, '127.0.0.1', r));
  const { port } = mockKratos.address();
  process.env.KRATOS_ADMIN_URL = `http://127.0.0.1:${port}`;
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
    delete process.env.KRATOS_ADMIN_URL;
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
});

async function withMockKratos(respond, fn) {
  const mockKratos = http.createServer(respond);
  await new Promise((r) => mockKratos.listen(0, '127.0.0.1', r));
  process.env.KRATOS_ADMIN_URL = `http://127.0.0.1:${mockKratos.address().port}`;
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  try {
    await fn();
  } finally {
    await new Promise((r) => mockKratos.close(r));
    delete process.env.KRATOS_ADMIN_URL;
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

test('login-code-gate REFUSES when KRATOS_ADMIN_URL is unset or the id is missing (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  for (const body of [{ identity_id: OTHER_UUID }, { is_admin: false }]) {
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

function postUsernameGate(body, bearer = 'gate-secret') {
  return fakeReq({
    method: 'POST',
    url: '/admin/username-gate',
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

test('username-gate REFUSES a username change with the neutral message (403)', async () => {
  await withMockKratos(storedIdentityServer(STORED), async () => {
    const res = fakeRes();
    await handle(postUsernameGate(profilePayload({ ...STORED.traits, username: 'ada.byron' })), res);
    assert.equal(res.statusCode, 403);
    assert.equal(refusalText(res), USERNAME_CHANGE_REFUSAL);
  });
});

test('username-gate ALLOWS a profile update that keeps the username (200)', async () => {
  await withMockKratos(storedIdentityServer(STORED), async () => {
    const res = fakeRes();
    await handle(postUsernameGate(profilePayload({ ...STORED.traits, email: 'ada@example.test' })), res);
    assert.equal(res.statusCode, 200);
  });
});

test('username-gate REFUSES when the stored identity cannot be read (fail-closed, 403)', async () => {
  await withMockKratos((req, res) => { res.writeHead(500); res.end(); }, async () => {
    const res = fakeRes();
    await handle(postUsernameGate(profilePayload(STORED.traits)), res);
    assert.equal(res.statusCode, 403);
    assert.equal(refusalText(res), PROFILE_UPDATE_UNAVAILABLE);
  });
});

test('username-gate REFUSES when KRATOS_ADMIN_URL is unset or the id is missing (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  for (const body of [profilePayload(STORED.traits), { traits: STORED.traits }]) {
    const res = fakeRes();
    await handle(postUsernameGate(body), res);
    assert.equal(res.statusCode, 403);
    assert.equal(refusalText(res), PROFILE_UPDATE_UNAVAILABLE);
  }
});

test('username-gate rejects a wrong bearer with 403 before reading the body', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handle(postUsernameGate(profilePayload(STORED.traits), 'wrong'), res);
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

test('recovery, username and second-factor gates and profile-sessions read the identity via the runtime', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  process.env.KRATOS_ADMIN_URL = 'http://kratos.invalid:4434';
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
    ['/admin/username-gate', { identity_id: 'u', traits: {} }],
    ['/admin/second-factor-gate?method=totp', { identity_id: 's' }],
    ['/admin/profile-sessions', { identity_id: 'p', session_id: 'keep' }],
  ]) {
    await handle(post(url, body), fakeRes(), recorder);
  }
  assert.deepEqual(read, ['r', 'u', 's', 'p']);
});

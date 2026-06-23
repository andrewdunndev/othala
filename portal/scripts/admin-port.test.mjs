// Contract tests for the D-listener admin mux (CU1 item 4/6, extended CU3 + CVP-P3).
//
// Run with: tsx --test scripts/admin-port.test.mjs
//
// Asserts:
//   - the admin port serves /healthz + /readyz (GET) and the CU3/CVP-P3 admin
//     endpoints /admin/revoke-user + /admin/recovery-gate + /admin/login-gate
//     (POST), and that every public/challenge path 404s there (the two muxes
//     are disjoint);
//   - the revoke-user + recovery-gate + login-gate paths are NOT public GET
//     routes (the public mux never sees them via the admin helpers);
//   - the admin-endpoint + recovery-gate bearer checks are CONSTANT-TIME and
//     FAIL-CLOSED (unset secret rejects everything).
//
// Imports the pure helpers from listen.mjs without binding any socket or
// loading the SSR handler / runtime bundle.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import {
  isAdminRoute,
  isAdminEndpoint,
  bearerMatches,
  parseBearer,
  handleAdminRequest,
  recoveryGateVerdict,
  ADMIN_ROUTES,
  ADMIN_GET_ROUTES,
  ADMIN_POST_ROUTES,
} from '../src/server/listen.mjs';

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

// A minimal request: a readable stream carrying the body + method/url/headers.
function fakeReq({ method = 'GET', url = '/', headers = {}, body = '' } = {}) {
  const req = Readable.from(body ? [Buffer.from(body)] : []);
  req.method = method;
  req.url = url;
  req.headers = headers;
  return req;
}

beforeEach(() => {
  delete process.env.OTHALA_ADMIN_ENDPOINT_BEARER;
  delete process.env.RECOVERY_GATE_SECRET;
  delete process.env.OTHALA_ADMIN_IDS;
});

// ── CU1 disjointness (unchanged) ───────────────────────────────────────────

test('admin GET mux serves exactly /healthz and /readyz', () => {
  assert.deepEqual([...ADMIN_GET_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.deepEqual([...ADMIN_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.equal(isAdminRoute('GET', '/healthz'), true);
  assert.equal(isAdminRoute('GET', '/readyz'), true);
});

test('admin POST mux serves exactly the CU3 + CVP-P3 endpoints', () => {
  assert.deepEqual([...ADMIN_POST_ROUTES].sort(), ['/admin/login-gate', '/admin/recovery-gate', '/admin/revoke-user']);
});

test('revoke-user + recovery-gate + login-gate are NOT public GET routes (disjoint from public mux)', () => {
  for (const p of ['/admin/revoke-user', '/admin/recovery-gate', '/admin/login-gate']) {
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
    await handleAdminRequest(fakeReq({ method: 'GET', url: p }), res);
    assert.equal(res.statusCode, 404, `${p} should 404 on admin port`);
  }
});

test('healthz/readyz return 200 ok on the admin port', async () => {
  for (const p of ['/healthz', '/readyz']) {
    const res = fakeRes();
    await handleAdminRequest(fakeReq({ method: 'GET', url: p }), res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(JSON.parse(res.body), { status: 'ok' });
  }
});

test('a served admin POST path on the wrong method (GET) 404s', async () => {
  for (const p of ['/admin/revoke-user', '/admin/recovery-gate', '/admin/login-gate']) {
    const res = fakeRes();
    await handleAdminRequest(fakeReq({ method: 'GET', url: p }), res);
    assert.equal(res.statusCode, 404, `GET ${p} should 404`);
  }
});

// ── constant-time, fail-closed bearer ──────────────────────────────────────

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

// ── revoke-user endpoint auth ──────────────────────────────────────────────

test('POST /admin/revoke-user 401s with no/wrong bearer (fail-closed unset)', async () => {
  // unset secret -> every request rejected
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer x' }, body: '{"subject":"s"}' }),
    res,
  );
  assert.equal(res.statusCode, 401);
});

test('POST /admin/revoke-user 401s with a wrong bearer when secret IS set', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'right-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer wrong' }, body: '{"subject":"s"}' }),
    res,
  );
  assert.equal(res.statusCode, 401);
});

test('POST /admin/revoke-user with a valid bearer routes through revokeSubject', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'right-secret';
  let revokedSubject = null;
  const runtime = {
    async revokeSubject(subject) {
      revokedSubject = subject;
      return { subject, kratosSessionsRevoked: true, bestEffortFailures: [] };
    },
    isAdminId: () => false,
  };
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer right-secret' }, body: '{"subject":"sub-9"}' }),
    res,
    runtime,
  );
  assert.equal(res.statusCode, 200);
  assert.equal(revokedSubject, 'sub-9');
  assert.equal(JSON.parse(res.body).kratosSessionsRevoked, true);
});

test('POST /admin/revoke-user returns prescriptive error (dependency + action), no raw upstream leak', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'right-secret';
  class FakeRevokeError extends Error {
    constructor() {
      super('revoke step "delete-sessions" failed against kratos-admin: re-run the revoke.');
      this.dependency = 'kratos-admin';
      this.step = 'delete-sessions';
    }
  }
  const runtime = {
    async revokeSubject() { throw new FakeRevokeError(); },
    isAdminId: () => false,
  };
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer right-secret' }, body: '{"subject":"s"}' }),
    res,
    runtime,
  );
  assert.equal(res.statusCode, 502); // kratos-admin -> upstream dependency
  const out = JSON.parse(res.body);
  assert.equal(out.dependency, 'kratos-admin');
  assert.equal(out.step, 'delete-sessions');
  assert.match(out.action, /re-run the revoke/);
});

test('POST /admin/revoke-user 400s on a missing subject', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'right-secret';
  const runtime = { async revokeSubject() { throw new Error('should not run'); }, isAdminId: () => false };
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer right-secret' }, body: '{}' }),
    res,
    runtime,
  );
  assert.equal(res.statusCode, 400);
});

// ── recovery-gate endpoint auth + verdict ──────────────────────────────────

test('POST /admin/recovery-gate is fail-closed when RECOVERY_GATE_SECRET unset', async () => {
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/recovery-gate', headers: { authorization: 'Bearer x' }, body: '{}' }),
    res,
    { revokeSubject: async () => ({}), isAdminId: () => false },
  );
  assert.equal(res.statusCode, 401);
});

test('POST /admin/recovery-gate REFUSES recovery for an allowlisted admin UUID (403)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const runtime = { revokeSubject: async () => ({}), isAdminId: (id) => id === ADMIN_UUID };
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      method: 'POST',
      url: '/admin/recovery-gate',
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: ADMIN_UUID, traits: { email: 'admin@othala.test' } }),
    }),
    res,
    runtime,
  );
  assert.equal(res.statusCode, 403);
});

test('POST /admin/recovery-gate ALLOWS recovery for a non-admin UUID (200)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const runtime = { revokeSubject: async () => ({}), isAdminId: () => false };
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      method: 'POST',
      url: '/admin/recovery-gate',
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: OTHER_UUID, traits: { email: 'kid@othala.test' } }),
    }),
    res,
    runtime,
  );
  assert.equal(res.statusCode, 200);
});

test('recoveryGateVerdict is FAIL-CLOSED on a malformed payload (no identity_id)', () => {
  assert.equal(recoveryGateVerdict({}, () => false).refuse, true);
  assert.equal(recoveryGateVerdict({ traits: {} }, () => false).refuse, true);
  assert.equal(recoveryGateVerdict({ identity: {} }, () => false).refuse, true);
});

test('recoveryGateVerdict reads identity_id at top level OR identity.id under .identity', () => {
  const isAdmin = (id) => id === ADMIN_UUID;
  // top-level identity_id (canonical jsonnet shape)
  assert.equal(recoveryGateVerdict({ identity_id: ADMIN_UUID, traits: {} }, isAdmin).refuse, true);
  // fallback: identity.id
  assert.equal(recoveryGateVerdict({ identity: { id: ADMIN_UUID } }, isAdmin).refuse, true);
  // non-admin
  assert.equal(recoveryGateVerdict({ identity_id: OTHER_UUID, traits: {} }, isAdmin).refuse, false);
});

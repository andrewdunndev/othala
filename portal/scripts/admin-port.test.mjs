// Contract tests for the D-listener admin mux (CU1 item 4/6, extended CU3).
//
// Run with: tsx --test scripts/admin-port.test.mjs
//
// Asserts:
//   - the admin port serves /healthz + /readyz (GET) and the CU3 admin
//     endpoints /admin/revoke-user + /admin/recovery-gate (POST), and that
//     every public/challenge path 404s there (the two muxes are disjoint);
//   - the revoke-user + recovery-gate paths are NOT public GET routes (the
//     public mux never sees them via the admin helpers);
//   - the admin-endpoint + recovery-gate bearer checks are CONSTANT-TIME and
//     FAIL-CLOSED (unset secret rejects everything).
//
// The login-gate (POST /admin/login-gate) was retired in ADR 08: the
// after.code hook was dropped from kratos.yml; AAL2-on-/admin makes an admin
// email-code AAL1 session harmless. ADMIN_POST_ROUTES no longer includes it.
//
// Imports the pure helpers from listen.mjs without binding any socket or
// loading the SSR handler / runtime bundle.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
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
  delete process.env.KRATOS_ADMIN_URL;
});

// ── CU1 disjointness ──────────────────────────────────────────────────────────

test('admin GET mux serves exactly /healthz and /readyz', () => {
  assert.deepEqual([...ADMIN_GET_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.deepEqual([...ADMIN_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.equal(isAdminRoute('GET', '/healthz'), true);
  assert.equal(isAdminRoute('GET', '/readyz'), true);
});

test('admin POST mux serves exactly the CU3 endpoints (login-gate retired)', () => {
  // Login-gate was retired in ADR 08; it must NOT be in ADMIN_POST_ROUTES.
  assert.deepEqual([...ADMIN_POST_ROUTES].sort(), ['/admin/recovery-gate', '/admin/revoke-user']);
  assert.equal(ADMIN_POST_ROUTES.has('/admin/login-gate'), false, 'login-gate must be retired from POST routes');
});

test('revoke-user + recovery-gate are NOT public GET routes (disjoint from public mux)', () => {
  for (const p of ['/admin/revoke-user', '/admin/recovery-gate']) {
    assert.equal(isAdminRoute('GET', p), false, `${p} must not be a public GET admin route`);
  }
});

test('login-gate is not an admin GET or POST route (fully retired)', () => {
  assert.equal(isAdminRoute('GET', '/admin/login-gate'), false);
  assert.equal(isAdminEndpoint('GET', '/admin/login-gate'), false);
  assert.equal(isAdminEndpoint('POST', '/admin/login-gate'), false);
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

test('login-gate POST 404s on the admin port (retired route)', async () => {
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/login-gate', body: '{}' }),
    res,
  );
  assert.equal(res.statusCode, 404, '/admin/login-gate must 404 (retired)');
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
  for (const p of ['/admin/revoke-user', '/admin/recovery-gate']) {
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

test('POST /admin/revoke-user 403s with no/wrong bearer (fail-closed unset)', async () => {
  // unset secret -> every request rejected
  // 403 not 401: Kratos can_interrupt webhooks must see 403 to abort the flow;
  // a 401 risks skip-and-continue (fail-open).
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer x' }, body: '{"subject":"s"}' }),
    res,
  );
  assert.equal(res.statusCode, 403);
});

test('POST /admin/revoke-user 403s with a wrong bearer when secret IS set', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'right-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer wrong' }, body: '{"subject":"s"}' }),
    res,
  );
  assert.equal(res.statusCode, 403);
});

test('POST /admin/revoke-user with a valid bearer routes through revokeSubject', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'right-secret';
  let revokedSubject = null;
  const runtime = {
    async revokeSubject(subject) {
      revokedSubject = subject;
      return { subject, kratosSessionsRevoked: true, bestEffortFailures: [] };
    },
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
  const runtime = { async revokeSubject() { throw new Error('should not run'); } };
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer right-secret' }, body: '{}' }),
    res,
    runtime,
  );
  assert.equal(res.statusCode, 400);
});

// ── recovery-gate endpoint auth + verdict ──────────────────────────────────

test('POST /admin/recovery-gate is fail-closed when RECOVERY_GATE_SECRET unset (403)', async () => {
  // 403 not 401: Kratos can_interrupt webhooks must see 403 to abort the flow;
  // a 401 risks skip-and-continue (fail-open).
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/recovery-gate', headers: { authorization: 'Bearer x' }, body: '{}' }),
    res,
  );
  assert.equal(res.statusCode, 403);
});

test('POST /admin/recovery-gate REFUSES recovery when the admin-API marker is true (403)', async () => {
  // Genuinely exercise the admin-refusal MECHANISM. handleRecoveryGate IGNORES
  // the payload's is_admin field (Kratos v26 omits metadata_admin from ctx) and
  // resolves authority via fetchAdminMarker → the Kratos admin API. So we mock
  // that API to return metadata_admin.admin===true and assert the 403 comes from
  // the marker, NOT a fail-closed fallback. Sending is_admin:false in the body
  // proves the verdict ignores the payload. (The prior version of this test left
  // KRATOS_ADMIN_URL unset, so its 403 came from the admin-api-unavailable
  // fail-closed path — it passed even if the isAdmin check were inverted.)
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
    await handleAdminRequest(
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
  // Explicit coverage of the fail-closed path the old admin-true test relied on
  // by accident: with no admin API to consult, the marker cannot be verified, so
  // recovery is refused regardless of the identity. KRATOS_ADMIN_URL is cleared
  // in beforeEach.
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
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

test('POST /admin/recovery-gate ALLOWS recovery when is_admin===false (200)', async () => {
  // fetchAdminMarker calls the Kratos admin API directly (ADR 08 workaround:
  // Kratos v26.2.0 omits metadata_admin from webhook ctx). Provide a mock
  // Kratos admin API that returns a non-admin identity for OTHER_UUID so the
  // gate can resolve the marker without a live Kratos instance.
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
    await handleAdminRequest(
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

test('POST /admin/recovery-gate refuses when is_admin is missing (malformed, fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      method: 'POST',
      url: '/admin/recovery-gate',
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: OTHER_UUID, traits: { email: 'kid@othala.test' } }),
    }),
    res,
  );
  assert.equal(res.statusCode, 403, 'missing is_admin must refuse (fail-closed)');
});

test('POST /admin/recovery-gate refuses when is_admin is string "true" (non-boolean, fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      method: 'POST',
      url: '/admin/recovery-gate',
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: OTHER_UUID, is_admin: 'true' }),
    }),
    res,
  );
  assert.equal(res.statusCode, 403, 'non-boolean is_admin must refuse (fail-closed)');
});

test('recoveryGateVerdict is FAIL-CLOSED on a malformed payload (no identity_id)', () => {
  assert.equal(recoveryGateVerdict({}).refuse, true);
  assert.equal(recoveryGateVerdict({ traits: {}, is_admin: false }).refuse, true);
  assert.equal(recoveryGateVerdict({ identity: {}, is_admin: false }).refuse, true);
});

test('recoveryGateVerdict reads identity_id at top level OR identity.id under .identity', () => {
  // top-level identity_id (canonical jsonnet shape)
  assert.equal(recoveryGateVerdict({ identity_id: ADMIN_UUID, is_admin: true, traits: {} }).refuse, true);
  // fallback: identity.id
  assert.equal(recoveryGateVerdict({ identity: { id: ADMIN_UUID }, is_admin: true }).refuse, true);
  // non-admin
  assert.equal(recoveryGateVerdict({ identity_id: OTHER_UUID, is_admin: false, traits: {} }).refuse, false);
});

// ── Security: bearer rejection MUST be 403, never 401 (Kratos can_interrupt) ─

test('bearer rejection on recovery-gate is 403 (not 401) — Kratos can_interrupt safety', async () => {
  // Kratos webhooks use can_interrupt: true; a non-403 response (e.g. 401)
  // risks being treated as a non-interrupting webhook error (skip-and-continue
  // = fail-open), whereas 403 reliably aborts the flow.
  process.env.RECOVERY_GATE_SECRET = 'correct';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/recovery-gate', headers: { authorization: 'Bearer wrong' }, body: '{}' }),
    res,
  );
  assert.equal(res.statusCode, 403, 'must be 403, not 401');
  assert.notEqual(res.statusCode, 401, 'must NOT be 401 (would be fail-open under can_interrupt)');
});

test('bearer rejection on revoke-user is 403 (not 401)', async () => {
  process.env.OTHALA_ADMIN_ENDPOINT_BEARER = 'correct';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ method: 'POST', url: '/admin/revoke-user', headers: { authorization: 'Bearer wrong' }, body: '{"subject":"s"}' }),
    res,
  );
  assert.equal(res.statusCode, 403, 'must be 403, not 401');
  assert.notEqual(res.statusCode, 401, 'must NOT be 401');
});

// Tests for the admin login-gate endpoint (CVP-P3).
//
// Run with: tsx --test scripts/admin-login-gate.test.mjs
//
// POST /admin/login-gate — Kratos fires this webhook on the `after.code`
// login hook before issuing the session. The gate refuses email-code login
// for admin identities (id on OTHALA_ADMIN_IDS), forcing them to use a
// passkey or console instead. Other login methods are unaffected.
//
// Mirrors admin-recovery-gate.test.mjs: same bearer (RECOVERY_GATE_SECRET),
// same payload shape ({ identity_id, groups, traits }), same fail-closed
// semantics on missing/empty id.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import {
  handleAdminRequest,
  handleLoginGate,
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

function fakeReq({ method = 'POST', url = '/admin/login-gate', headers = {}, body = '' } = {}) {
  const req = Readable.from(body ? [Buffer.from(body)] : []);
  req.method = method;
  req.url = url;
  req.headers = headers;
  return req;
}

function makeRuntime(adminIds) {
  const normalized = new Set(adminIds.map((id) => id.trim().toLowerCase()));
  return {
    revokeSubject: async () => ({}),
    isAdminId: (id) => typeof id === 'string' && normalized.has(id.trim().toLowerCase()),
  };
}

beforeEach(() => {
  delete process.env.RECOVERY_GATE_SECRET;
  delete process.env.OTHALA_ADMIN_IDS;
});

// ── Route registration ──────────────────────────────────────────────────────

test('/admin/login-gate is in ADMIN_POST_ROUTES', () => {
  assert.ok(ADMIN_POST_ROUTES.has('/admin/login-gate'), '/admin/login-gate must be in ADMIN_POST_ROUTES');
});

// ── Bearer auth ─────────────────────────────────────────────────────────────

test('POST /admin/login-gate 401s when RECOVERY_GATE_SECRET is unset (fail-closed)', async () => {
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ headers: { authorization: 'Bearer x' }, body: JSON.stringify({ identity_id: OTHER_UUID }) }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 401);
});

test('POST /admin/login-gate 401s with wrong bearer', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ headers: { authorization: 'Bearer wrong' }, body: JSON.stringify({ identity_id: OTHER_UUID }) }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 401);
});

test('POST /admin/login-gate 401s with missing bearer', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({ headers: {}, body: JSON.stringify({ identity_id: OTHER_UUID }) }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 401);
});

// ── Admin identity → refuse (403) ───────────────────────────────────────────

test('admin id → 403 with descriptive message', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: ADMIN_UUID, groups: ['admin'], traits: { email: 'admin@example.com' } }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
  const body = JSON.parse(res.body);
  // Kratos-webhook error shape: { messages: [{ messages: [{ type, text }] }] }
  assert.ok(body.messages, 'response must have messages key');
  const text = body.messages[0].messages[0].text;
  assert.match(text, /email-code login is disabled for admins/);
});

test('admin id in UPPERCASE → 403 (case-insensitive)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: ADMIN_UUID.toUpperCase() }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
});

// ── Non-admin identity → allow (200) ────────────────────────────────────────

test('non-admin id → 200 { ok: true }', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: OTHER_UUID, groups: ['family'], traits: { email: 'user@example.com' } }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true });
});

// ── Fail-closed: missing/empty id ───────────────────────────────────────────

test('missing identity_id → 403 (fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ groups: [], traits: { email: 'user@example.com' } }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
});

test('empty string identity_id → 403 (fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: '' }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
});

test('whitespace-only identity_id → 403 (fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: '   ' }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
});

test('null identity_id → 403 (fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: JSON.stringify({ identity_id: null }),
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
});

// ── Malformed body → 403 ────────────────────────────────────────────────────

test('malformed JSON body → 403 (fail-closed)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'gate-secret';
  const res = fakeRes();
  await handleAdminRequest(
    fakeReq({
      headers: { authorization: 'Bearer gate-secret' },
      body: 'not-json{{{',
    }),
    res,
    makeRuntime([ADMIN_UUID]),
  );
  assert.equal(res.statusCode, 403);
});

// ── Direct handleLoginGate export ───────────────────────────────────────────

test('handleLoginGate export is callable directly (test isolation)', async () => {
  process.env.RECOVERY_GATE_SECRET = 'direct-secret';
  const res = fakeRes();
  const req = fakeReq({
    headers: { authorization: 'Bearer direct-secret' },
    body: JSON.stringify({ identity_id: OTHER_UUID }),
  });
  await handleLoginGate(req, res, makeRuntime([ADMIN_UUID]));
  assert.equal(res.statusCode, 200);
});

// Tests for src/lib/admin-api.ts — Kratos admin API wrappers.
//
// Run with: npx vitest run scripts/admin-api.test.mjs
//
// The TS source is canonical; this test re-ports the API surface in JS
// form and asserts observable network behaviour (URL shape, method,
// request body, response parsing) by stubbing globalThis.fetch.
//
// Coverage:
//   - adminBase: env-driven URL construction (default + override)
//   - authHeaders: bearer token optional
//   - createIdentity: method, URL, body shape, schema_id default + override
//   - updateIdentity: GET then PUT, body carries schema_id + state from
//     current, traits + metadata_admin from input
//   - deleteIdentity: DELETE method + URL
//   - deactivateIdentity: PATCH (JSON-Patch state→inactive) + DELETE sessions
//   - deleteIdentitySessions: (via deactivateIdentity path)
//   - listIdentities: GET with per_page=250 cap
//   - getIdentity: GET with credential includes in query string
//   - getRecoveryLink: POST body shape + response parsing
//   - ok helper: throws on non-2xx with status in message

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import { identity } from '../src/lib/test-builders.ts';

// An admin-API identity body with the listed fields as given. A field set to
// undefined is absent on the wire (JSON.stringify drops it).
function kratosIdentity(fields) {
  return { ...identity({ id: fields.id }), ...fields };
}

// ─── env setup ────────────────────────────────────────────────────────────────
// Set env BEFORE porting so the helpers read the right value in each test.
// We manipulate process.env per test to cover both default and override paths.

const DEFAULT_BASE = 'http://kratos:4434';

// Mirror config.ts optionalVar for OTHALA_DEFAULT_SCHEMA_ID.
function defaultSchemaId() {
  const v = process.env.OTHALA_DEFAULT_SCHEMA_ID;
  return v !== undefined && v.trim() !== '' ? v.trim() : 'default';
}

// ─── JS port of admin-api.ts ──────────────────────────────────────────────────
// Re-ports the functions verbatim rather than importing admin-api.ts directly.
// The runner is now vitest (which reads .ts natively, no loader needed), but
// switching this file to a direct import is a separate change from the
// runner migration — left as-is here to keep the conversion mechanical.

function adminBase() {
  return process.env.KRATOS_ADMIN_URL ?? DEFAULT_BASE;
}

function adminToken() {
  return process.env.KRATOS_ADMIN_TOKEN ?? '';
}

function authHeaders(extra = {}) {
  const headers = { Accept: 'application/json', ...extra };
  const token = adminToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function ok(res, label) {
  if (res.ok) return;
  let body = '';
  try { body = await res.text(); } catch { /* ignore */ }
  throw new Error(`${label}: ${res.status} ${body.slice(0, 240)}`);
}

// Minimal metadata_admin passthrough (mirrors validateMetadataAdmin at
// the portal level — the test focuses on network shape, not validation).
function validateMetadataAdmin(input) {
  if (input === null || input === undefined) return {};
  return input;
}

async function listIdentities() {
  const res = await fetch(`${adminBase()}/admin/identities?per_page=250`, {
    headers: authHeaders(),
  });
  await ok(res, 'listIdentities');
  return await res.json();
}

async function getIdentity(id) {
  const url =
    `${adminBase()}/admin/identities/${encodeURIComponent(id)}` +
    `?include_credential=password,webauthn,passkey,totp`;
  const res = await fetch(url, { headers: authHeaders() });
  await ok(res, 'getIdentity');
  return await res.json();
}

async function createIdentity(input) {
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const res = await fetch(`${adminBase()}/admin/identities`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      schema_id: input.schemaId ?? defaultSchemaId(),
      traits: input.traits,
      metadata_admin: validated,
    }),
  });
  await ok(res, 'createIdentity');
  return await res.json();
}

async function updateIdentity(id, input) {
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const current = await getIdentity(id);
  const res = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      schema_id: current.schema_id,
      state: current.state ?? 'active',
      traits: input.traits,
      metadata_admin: validated,
    }),
  });
  await ok(res, 'updateIdentity');
  return await res.json();
}

async function deleteIdentity(id) {
  const res = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  await ok(res, 'deleteIdentity');
}

async function deactivateIdentity(id) {
  const res = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: authHeaders({ 'Content-Type': 'application/json-patch+json' }),
    body: JSON.stringify([{ op: 'replace', path: '/state', value: 'inactive' }]),
  });
  await ok(res, 'deactivateIdentity');
  const sessRes = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}/sessions`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  await ok(sessRes, 'deleteIdentitySessions');
}

async function getRecoveryLink(id, expiresIn = '1h') {
  const res = await fetch(`${adminBase()}/admin/recovery/code`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ identity_id: id, expires_in: expiresIn }),
  });
  await ok(res, 'getRecoveryLink');
  return await res.json();
}

// JS port of patchAdminMarker from admin-api.ts.
// Uses raw fetch (not the SDK) to keep this test self-contained.
async function patchAdminMarker(id, grant) {
  // Fetch current identity.
  const getUrl =
    `${adminBase()}/admin/identities/${encodeURIComponent(id)}` +
    `?include_credential=password,webauthn,passkey,totp,lookup_secret`;
  const getRes = await fetch(getUrl, { headers: authHeaders() });
  await ok(getRes, 'patchAdminMarker/getIdentity');
  const current = await getRes.json();

  if (grant) {
    const hasMeta = current.metadata_admin != null && typeof current.metadata_admin === 'object';
    let patch;
    if (!hasMeta) {
      patch = [{ op: 'add', path: '/metadata_admin', value: { admin: true } }];
    } else {
      const meta = current.metadata_admin;
      if ('admin' in meta) {
        patch = [{ op: 'replace', path: '/metadata_admin/admin', value: true }];
      } else {
        patch = [{ op: 'add', path: '/metadata_admin/admin', value: true }];
      }
    }
    const patchRes = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json-patch+json' }),
      body: JSON.stringify(patch),
    });
    await ok(patchRes, 'patchAdminMarker/patch');
  } else {
    const meta = current.metadata_admin;
    if (!meta || !('admin' in meta)) {
      // Already absent — no-op.
      return;
    }
    const patchRes = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json-patch+json' }),
      body: JSON.stringify([{ op: 'remove', path: '/metadata_admin/admin' }]),
    });
    await ok(patchRes, 'patchAdminMarker/patch');
  }
}

// ─── Fetch stub infrastructure ────────────────────────────────────────────────

let capturedCalls = [];

function mockFetch(responseBody = kratosIdentity({ id: 'mock-id', traits: {}, metadata_admin: {} }), status = 200) {
  capturedCalls = [];
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    return new Response(JSON.stringify(responseBody), { status });
  };
}

// For updateIdentity: first call (getIdentity) returns currentIdentity,
// second call (PUT) returns updated identity.
function mockFetchSequence(responses) {
  capturedCalls = [];
  let i = 0;
  globalThis.fetch = async (url, opts) => {
    const r = responses[i] ?? responses[responses.length - 1];
    i++;
    capturedCalls.push({ url: String(url), opts });
    return new Response(JSON.stringify(r.body), { status: r.status ?? 200 });
  };
}

beforeEach(() => {
  delete process.env.KRATOS_ADMIN_URL;
  delete process.env.KRATOS_ADMIN_TOKEN;
  delete process.env.OTHALA_DEFAULT_SCHEMA_ID;
  mockFetch();
});

// ─── adminBase ────────────────────────────────────────────────────────────────

test('adminBase: defaults to http://kratos:4434', () => {
  assert.equal(adminBase(), DEFAULT_BASE);
});

test('adminBase: KRATOS_ADMIN_URL overrides default', () => {
  process.env.KRATOS_ADMIN_URL = 'http://custom-host:4434';
  assert.equal(adminBase(), 'http://custom-host:4434');
  delete process.env.KRATOS_ADMIN_URL;
});

// ─── authHeaders ─────────────────────────────────────────────────────────────

test('authHeaders: no token → no Authorization header', () => {
  const h = authHeaders();
  assert.equal(h.Authorization, undefined);
  assert.equal(h.Accept, 'application/json');
});

test('authHeaders: token set → Authorization: Bearer <token>', () => {
  process.env.KRATOS_ADMIN_TOKEN = 'secret-token';
  const h = authHeaders();
  assert.equal(h.Authorization, 'Bearer secret-token');
  delete process.env.KRATOS_ADMIN_TOKEN;
});

test('authHeaders: extra headers are merged', () => {
  const h = authHeaders({ 'Content-Type': 'application/json' });
  assert.equal(h['Content-Type'], 'application/json');
  assert.equal(h.Accept, 'application/json');
});

// ─── ok helper ───────────────────────────────────────────────────────────────

test('ok: does not throw on 2xx response', async () => {
  const res = new Response('{}', { status: 200 });
  await assert.doesNotReject(() => ok(res, 'test'));
});

test('ok: throws on 4xx with status in message', async () => {
  const res = new Response('not found body', { status: 404 });
  await assert.rejects(
    () => ok(res, 'getIdentity'),
    (err) => {
      assert.match(err.message, /404/);
      assert.match(err.message, /getIdentity/);
      return true;
    },
  );
});

test('ok: throws on 5xx', async () => {
  const res = new Response('internal error', { status: 500 });
  await assert.rejects(
    () => ok(res, 'createIdentity'),
    /500/,
  );
});

// ─── listIdentities ───────────────────────────────────────────────────────────

test('listIdentities: GETs /admin/identities', async () => {
  mockFetch([]);
  await listIdentities();
  assert.equal(capturedCalls.length, 1);
  assert.match(capturedCalls[0].url, /\/admin\/identities/);
  assert.equal(capturedCalls[0].opts?.method, undefined); // no explicit method = GET
});

test('listIdentities: caps per_page at 250', async () => {
  mockFetch([]);
  await listIdentities();
  assert.match(capturedCalls[0].url, /per_page=250/);
});

test('listIdentities: uses correct base URL', async () => {
  process.env.KRATOS_ADMIN_URL = 'http://admin.internal:9000';
  mockFetch([]);
  await listIdentities();
  assert.match(capturedCalls[0].url, /^http:\/\/admin\.internal:9000\//);
  delete process.env.KRATOS_ADMIN_URL;
});

// ─── getIdentity ─────────────────────────────────────────────────────────────

test('getIdentity: GETs /admin/identities/<id>', async () => {
  mockFetch(kratosIdentity({ id: 'abc123', traits: {}, schema_id: 'family', state: 'active' }));
  await getIdentity('abc123');
  assert.match(capturedCalls[0].url, /\/admin\/identities\/abc123/);
});

test('getIdentity: includes credential include query params', async () => {
  mockFetch(kratosIdentity({ id: 'abc123', traits: {} }));
  await getIdentity('abc123');
  assert.match(capturedCalls[0].url, /include_credential=password/);
  assert.match(capturedCalls[0].url, /webauthn/);
  assert.match(capturedCalls[0].url, /passkey/);
  assert.match(capturedCalls[0].url, /totp/);
});

test('getIdentity: URL-encodes special characters in id', async () => {
  mockFetch(kratosIdentity({ id: 'id/with/slash', traits: {} }));
  await getIdentity('id/with/slash');
  assert.match(capturedCalls[0].url, /id%2Fwith%2Fslash/);
});

// ─── createIdentity ───────────────────────────────────────────────────────────

test('createIdentity: POSTs to /admin/identities', async () => {
  await createIdentity({ traits: { username: 'alice', email: 'alice@example.com' }, metadataAdmin: {} });
  assert.equal(capturedCalls[0].opts.method, 'POST');
  assert.match(capturedCalls[0].url, /\/admin\/identities$/);
});

test('createIdentity: sets Content-Type application/json', async () => {
  await createIdentity({ traits: { username: 'alice', email: 'alice@example.com' }, metadataAdmin: {} });
  const headers = capturedCalls[0].opts.headers;
  assert.equal(headers['Content-Type'], 'application/json');
});

test('createIdentity: defaults schema_id to OTHALA_DEFAULT_SCHEMA_ID (neutral default "default")', async () => {
  delete process.env.OTHALA_DEFAULT_SCHEMA_ID;
  await createIdentity({ traits: { username: 'alice', email: 'alice@example.com' }, metadataAdmin: {} });
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.equal(body.schema_id, 'default');
});

test('createIdentity: OTHALA_DEFAULT_SCHEMA_ID env var overrides neutral default', async () => {
  process.env.OTHALA_DEFAULT_SCHEMA_ID = 'family';
  await createIdentity({ traits: { username: 'alice', email: 'alice@example.com' }, metadataAdmin: {} });
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.equal(body.schema_id, 'family');
  delete process.env.OTHALA_DEFAULT_SCHEMA_ID;
});

test('createIdentity: passes through explicit schemaId', async () => {
  await createIdentity({
    traits: { username: 'alice', email: 'alice@example.com' },
    metadataAdmin: {},
    schemaId: 'guest',
  });
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.equal(body.schema_id, 'guest');
});

test('createIdentity: includes traits in request body', async () => {
  const traits = { username: 'alice', email: 'alice@example.com', displayName: 'Alice' };
  await createIdentity({ traits, metadataAdmin: {} });
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.deepEqual(body.traits, traits);
});

test('createIdentity: includes metadata_admin in request body', async () => {
  const meta = { groups: ['family', 'admin'] };
  await createIdentity({ traits: { username: 'alice', email: 'alice@example.com' }, metadataAdmin: meta });
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.deepEqual(body.metadata_admin, meta);
});

test('createIdentity: returns parsed response body', async () => {
  mockFetch(kratosIdentity({ id: 'new-id', traits: { username: 'alice' }, metadata_admin: {} }));
  const result = await createIdentity({
    traits: { username: 'alice', email: 'alice@example.com' },
    metadataAdmin: {},
  });
  assert.equal(result.id, 'new-id');
});

// ─── updateIdentity ───────────────────────────────────────────────────────────

test('updateIdentity: fetches current identity first (GET before PUT)', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-1', traits: {}, schema_id: 'family', state: 'active' }) },
    { body: kratosIdentity({ id: 'id-1', traits: {}, metadata_admin: {} }) },
  ]);
  await updateIdentity('id-1', { traits: { username: 'alice', email: 'alice@example.com' }, metadataAdmin: {} });
  assert.equal(capturedCalls.length, 2);
  // First call is the GET
  assert.match(capturedCalls[0].url, /\/admin\/identities\/id-1/);
  assert.equal(capturedCalls[0].opts?.method, undefined); // GET
  // Second call is the PUT
  assert.equal(capturedCalls[1].opts.method, 'PUT');
});

test('updateIdentity: PUTs to /admin/identities/<id>', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-1', traits: {}, schema_id: 'family', state: 'active' }) },
    { body: kratosIdentity({ id: 'id-1', traits: {}, metadata_admin: {} }) },
  ]);
  await updateIdentity('id-1', { traits: { username: 'bob', email: 'bob@example.com' }, metadataAdmin: {} });
  assert.match(capturedCalls[1].url, /\/admin\/identities\/id-1$/);
});

test('updateIdentity: carries schema_id + state from current identity', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-1', traits: {}, schema_id: 'employee', state: 'inactive' }) },
    { body: kratosIdentity({ id: 'id-1', traits: {}, metadata_admin: {} }) },
  ]);
  await updateIdentity('id-1', { traits: { username: 'bob', email: 'bob@example.com' }, metadataAdmin: {} });
  const putBody = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(putBody.schema_id, 'employee');
  assert.equal(putBody.state, 'inactive');
});

test('updateIdentity: defaults state to "active" when current has none', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-1', traits: {}, schema_id: 'family', state: undefined }) },
    { body: kratosIdentity({ id: 'id-1', traits: {}, metadata_admin: {} }) },
  ]);
  await updateIdentity('id-1', { traits: { username: 'bob', email: 'bob@example.com' }, metadataAdmin: {} });
  const putBody = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(putBody.state, 'active');
});

test('updateIdentity: new traits + metadata_admin replace old in PUT body', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-1', traits: { username: 'old' }, schema_id: 'family', state: 'active' }) },
    { body: kratosIdentity({ id: 'id-1', traits: {}, metadata_admin: {} }) },
  ]);
  const newTraits = { username: 'new-alice', email: 'new@example.com' };
  const newMeta = { groups: ['admin'] };
  await updateIdentity('id-1', { traits: newTraits, metadataAdmin: newMeta });
  const putBody = JSON.parse(capturedCalls[1].opts.body);
  assert.deepEqual(putBody.traits, newTraits);
  assert.deepEqual(putBody.metadata_admin, newMeta);
});

test('updateIdentity: URL-encodes id with special characters', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id/slash', traits: {}, schema_id: 'family', state: 'active' }) },
    { body: kratosIdentity({ id: 'id/slash', traits: {}, metadata_admin: {} }) },
  ]);
  await updateIdentity('id/slash', { traits: { username: 'a', email: 'a@a.com' }, metadataAdmin: {} });
  assert.match(capturedCalls[1].url, /id%2Fslash/);
});

// ─── deleteIdentity ───────────────────────────────────────────────────────────

test('deleteIdentity: DELETEs /admin/identities/<id>', async () => {
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    // Use 200 — Node's undici rejects 204 in new Response(); ok() only checks res.ok
    return new Response('{}', { status: 200 });
  };
  await deleteIdentity('del-id');
  assert.equal(capturedCalls[0].opts.method, 'DELETE');
  assert.match(capturedCalls[0].url, /\/admin\/identities\/del-id$/);
});

test('deleteIdentity: URL-encodes id', async () => {
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    return new Response('{}', { status: 200 });
  };
  await deleteIdentity('id with spaces');
  assert.match(capturedCalls[0].url, /id%20with%20spaces/);
});

// ─── deactivate: Kratos-side primitives (steps 1-2 of the CU3 fan-out) ────────
//
// CU3: the real deactivateIdentity now delegates to revokeSubject({deactivate:
// true}), which adds Hydra login+consent revoke + best-effort cache/LDAP steps
// (proven end-to-end in revoke.test.mjs). This re-port still pins the Kratos
// wire contract those first two steps depend on: PATCH state->inactive THEN
// DELETE sessions, with the session-delete failure aborting (prescriptive).

test('deactivate (Kratos primitive): first request is PATCH with JSON-Patch content type', async () => {
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    return new Response('', { status: 200 });
  };
  await deactivateIdentity('deact-id');
  assert.equal(capturedCalls[0].opts.method, 'PATCH');
  assert.equal(capturedCalls[0].opts.headers['Content-Type'], 'application/json-patch+json');
});

test('deactivateIdentity: PATCH body sets state to inactive via JSON-Patch replace op', async () => {
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    return new Response('', { status: 200 });
  };
  await deactivateIdentity('deact-id');
  const patchBody = JSON.parse(capturedCalls[0].opts.body);
  assert.deepEqual(patchBody, [{ op: 'replace', path: '/state', value: 'inactive' }]);
});

test('deactivateIdentity: second request DELETEs sessions', async () => {
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    return new Response('', { status: 200 });
  };
  await deactivateIdentity('deact-id');
  assert.equal(capturedCalls.length, 2);
  assert.equal(capturedCalls[1].opts.method, 'DELETE');
  assert.match(capturedCalls[1].url, /\/admin\/identities\/deact-id\/sessions$/);
});

test('deactivateIdentity: throws when sessions DELETE fails (half-deactivated guard)', async () => {
  // PATCH succeeds, sessions DELETE fails (500). Without the ok() check on
  // sessRes the caller saw silent success and the identity stayed in a
  // half-deactivated state (marked inactive, sessions still live).
  let call = 0;
  globalThis.fetch = async (url, opts) => {
    capturedCalls.push({ url: String(url), opts });
    call++;
    if (call === 1) return new Response('', { status: 200 });
    return new Response('upstream broken', { status: 500 });
  };
  await assert.rejects(
    () => deactivateIdentity('deact-id'),
    (err) => {
      assert.match(err.message, /deleteIdentitySessions/);
      assert.match(err.message, /500/);
      return true;
    },
  );
});

// ─── getRecoveryLink ─────────────────────────────────────────────────────────

test('getRecoveryLink: POSTs to /admin/recovery/code', async () => {
  mockFetch({ recovery_link: 'https://example.com/link', recovery_code: '123456', expires_at: '2026-01-01T00:00:00Z' });
  await getRecoveryLink('user-id');
  assert.equal(capturedCalls[0].opts.method, 'POST');
  assert.match(capturedCalls[0].url, /\/admin\/recovery\/code$/);
});

test('getRecoveryLink: request body includes identity_id', async () => {
  mockFetch({ recovery_link: 'https://example.com/link', recovery_code: '123456', expires_at: '2026-01-01T00:00:00Z' });
  await getRecoveryLink('user-123');
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.equal(body.identity_id, 'user-123');
});

test('getRecoveryLink: defaults expires_in to "1h"', async () => {
  mockFetch({ recovery_link: 'https://example.com/link', recovery_code: '123456', expires_at: '2026-01-01T00:00:00Z' });
  await getRecoveryLink('user-123');
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.equal(body.expires_in, '1h');
});

test('getRecoveryLink: passes explicit expires_in', async () => {
  mockFetch({ recovery_link: 'https://example.com/link', recovery_code: '123456', expires_at: '2026-01-01T00:00:00Z' });
  await getRecoveryLink('user-123', '24h');
  const body = JSON.parse(capturedCalls[0].opts.body);
  assert.equal(body.expires_in, '24h');
});

test('getRecoveryLink: returns parsed recovery_link + recovery_code + expires_at', async () => {
  mockFetch({ recovery_link: 'https://example.com/recovery/abc', recovery_code: '654321', expires_at: '2026-06-01T00:00:00Z' });
  const result = await getRecoveryLink('user-123');
  assert.equal(result.recovery_link, 'https://example.com/recovery/abc');
  assert.equal(result.recovery_code, '654321');
  assert.equal(result.expires_at, '2026-06-01T00:00:00Z');
});

// ─── error propagation ────────────────────────────────────────────────────────

test('listIdentities: throws on non-2xx response', async () => {
  globalThis.fetch = async () => new Response('forbidden', { status: 403 });
  await assert.rejects(() => listIdentities(), /403/);
});

test('createIdentity: throws on non-2xx response', async () => {
  globalThis.fetch = async () => new Response('conflict', { status: 409 });
  await assert.rejects(
    () => createIdentity({ traits: { username: 'a', email: 'a@a.com' }, metadataAdmin: {} }),
    /409/,
  );
});

test('getRecoveryLink: throws on non-2xx and includes label in message', async () => {
  globalThis.fetch = async () => new Response('bad request', { status: 400 });
  await assert.rejects(
    () => getRecoveryLink('user-id'),
    (err) => {
      assert.match(err.message, /getRecoveryLink/);
      assert.match(err.message, /400/);
      return true;
    },
  );
});

// ─── patchAdminMarker ─────────────────────────────────────────────────────────

test('patchAdminMarker/grant: GET then PATCH add when metadata_admin absent', async () => {
  // First call = GET identity (no metadata_admin). Second = PATCH.
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u1', traits: {}, schema_id: 'family', state: 'active' /* no metadata_admin */ }) },
    { body: kratosIdentity({ id: 'u1', traits: {}, metadata_admin: { admin: true } }) },
  ]);
  await patchAdminMarker('u1', true);
  assert.equal(capturedCalls.length, 2);
  // First call: GET
  assert.match(capturedCalls[0].url, /\/admin\/identities\/u1/);
  assert.equal(capturedCalls[0].opts?.method, undefined);
  // Second call: PATCH
  assert.equal(capturedCalls[1].opts.method, 'PATCH');
  const patch = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(patch[0].op, 'add');
  assert.equal(patch[0].path, '/metadata_admin');
  assert.deepEqual(patch[0].value, { admin: true });
});

test('patchAdminMarker/grant: add /metadata_admin/admin when metadata_admin exists without admin key', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u2', traits: {}, metadata_admin: { groups: ['family'] } }) },
    { body: kratosIdentity({ id: 'u2', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
  ]);
  await patchAdminMarker('u2', true);
  const patch = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(patch[0].op, 'add');
  assert.equal(patch[0].path, '/metadata_admin/admin');
  assert.equal(patch[0].value, true);
});

test('patchAdminMarker/grant: replace /metadata_admin/admin when admin key already exists', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u3', traits: {}, metadata_admin: { groups: ['family'], admin: false } }) },
    { body: kratosIdentity({ id: 'u3', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
  ]);
  await patchAdminMarker('u3', true);
  const patch = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(patch[0].op, 'replace');
  assert.equal(patch[0].path, '/metadata_admin/admin');
  assert.equal(patch[0].value, true);
});

test('patchAdminMarker/revoke: GET then PATCH remove when admin key present', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u4', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
    { body: kratosIdentity({ id: 'u4', traits: {}, metadata_admin: { groups: ['family'] } }) },
  ]);
  await patchAdminMarker('u4', false);
  assert.equal(capturedCalls.length, 2);
  assert.equal(capturedCalls[1].opts.method, 'PATCH');
  const patch = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(patch[0].op, 'remove');
  assert.equal(patch[0].path, '/metadata_admin/admin');
});

test('patchAdminMarker/revoke: no-op (no PATCH) when admin key already absent', async () => {
  // metadata_admin exists but no admin key.
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u5', traits: {}, metadata_admin: { groups: ['family'] } }) },
  ]);
  await patchAdminMarker('u5', false);
  // Only the GET call; no PATCH issued.
  assert.equal(capturedCalls.length, 1);
});

test('patchAdminMarker/revoke: no-op when metadata_admin absent entirely', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'u6', traits: {} }) },
  ]);
  await patchAdminMarker('u6', false);
  assert.equal(capturedCalls.length, 1);
});

// ─── updateIdentity: admin marker preservation ────────────────────────────────

test('updateIdentity: includes admin:true when provided in metadataAdmin', async () => {
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-admin', traits: {}, schema_id: 'family', state: 'active', metadata_admin: { groups: ['family'], admin: true } }) },
    { body: kratosIdentity({ id: 'id-admin', traits: {}, metadata_admin: { groups: ['family'], admin: true } }) },
  ]);
  const newTraits = { username: 'alice', email: 'alice@example.com' };
  // Caller preserves admin marker by including it in metadataAdmin input.
  await updateIdentity('id-admin', { traits: newTraits, metadataAdmin: { groups: ['family'], admin: true } });
  const putBody = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(putBody.metadata_admin.admin, true);
});

test('updateIdentity: omitting admin from metadataAdmin does NOT include it in PUT (caller must explicitly preserve)', async () => {
  // This test documents the contract: the validator only passes through what is
  // given. The [id].astro save handler is responsible for reading + forwarding
  // the existing admin value. This test confirms the low-level API is not
  // silently preserving it (the contract is explicit, not magic).
  mockFetchSequence([
    { body: kratosIdentity({ id: 'id-noadmin', traits: {}, schema_id: 'family', state: 'active', metadata_admin: { groups: ['family'] } }) },
    { body: kratosIdentity({ id: 'id-noadmin', traits: {}, metadata_admin: { groups: ['family'] } }) },
  ]);
  await updateIdentity('id-noadmin', { traits: { username: 'bob', email: 'bob@example.com' }, metadataAdmin: { groups: ['family'] } });
  const putBody = JSON.parse(capturedCalls[1].opts.body);
  assert.equal(putBody.metadata_admin.admin, undefined);
});

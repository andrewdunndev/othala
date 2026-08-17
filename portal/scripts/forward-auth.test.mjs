// Tests for src/pages/api/forward-auth.ts — the Caddy forward_auth group-gate.
//
// Run with: tsx --test scripts/forward-auth.test.mjs
//
// This is SECURITY-SENSITIVE AUTHZ. The endpoint must FAIL CLOSED. We import
// the real GET/HEAD handlers and drive them through the real Kratos/Admin SDK
// code paths, stubbing only globalThis.fetch — routing by URL to the whoami
// (public, :4433) vs. admin identities (:4434) endpoints. This mirrors the
// fetch-stub style in admin-api.test.mjs / revoke.test.mjs and keeps the gate,
// session, and admin-resolution logic exactly as it runs in production.
//
// Status contract under test:
//   no group param        → 403 (fail-closed)
//   bad group format      → 403 (fail-closed)
//   no/invalid session    → 401 (Caddy → login redirect)
//   active + in group     → 200 (+ X-Kratos-Authenticated-Identity-Id)
//   active + NOT in group → 403
//   inactive + in group   → 403 (state check, fail-closed)
//   non-canonical stored group → 403 (read-boundary refusal, fail-closed)
//   admin lookup fails    → 503 (we never learned state/groups)
//   kratos unreachable    → 503 (an outage is not an authz answer)
//
// 503 is still a DENY: Caddy's forward_auth matches `@good status 2xx` and
// copies any other response back to the client instead of proxying to the
// protected upstream. The tests below assert the status is non-2xx for every
// failure path, which is the property the edge actually keys on.

import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { GET, HEAD } from '../src/pages/api/forward-auth.ts';

// ─── fetch stub ────────────────────────────────────────────────────────────
//
// Two upstreams to distinguish:
//   - whoami:  GET /sessions/whoami        (Kratos public, default :4433)
//   - admin:   GET /admin/identities/<id>  (Kratos admin,  default :4434)

const realFetch = globalThis.fetch;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Install a fetch stub.
 *   opts.whoami   — { status, body } for /sessions/whoami (body = Session)
 *   opts.identity — { status, body } for /admin/identities/<id> (body = Identity)
 *   opts.whoamiThrow — if true, the whoami fetch rejects (network error)
 */
function installFetch(opts) {
  globalThis.fetch = async (input) => {
    const url = String(typeof input === 'string' ? input : input?.url ?? input);
    if (url.includes('/sessions/whoami')) {
      if (opts.whoamiThrow) throw new TypeError('network down');
      const w = opts.whoami ?? { status: 401, body: { error: { code: 401 } } };
      return jsonResponse(w.body, w.status);
    }
    if (url.includes('/admin/identities/')) {
      const i = opts.identity ?? { status: 200, body: {} };
      return jsonResponse(i.body, i.status);
    }
    throw new Error(`unexpected fetch to ${url}`);
  };
}

beforeEach(() => {
  delete process.env.KRATOS_PUBLIC_URL;
  delete process.env.KRATOS_ADMIN_URL;
  delete process.env.KRATOS_ADMIN_TOKEN;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

// Build an APIContext-like arg for the handler (request + url, the only fields read).
function ctx(group, cookie = 'ory_kratos_session=abc') {
  const base = 'https://sso.othala.test/api/forward-auth';
  const url = new URL(group === undefined ? base : `${base}?group=${encodeURIComponent(group)}`);
  const headers = new Headers();
  if (cookie !== null) headers.set('cookie', cookie);
  const request = new Request(url, { method: 'GET', headers });
  return { request, url };
}

const ACTIVE_IN_GROUP = {
  status: 200,
  body: { id: 'id-1', state: 'active', metadata_admin: { groups: ['access-observe', 'family'] } },
};
const SESSION_OK = {
  status: 200,
  body: { active: true, identity: { id: 'id-1', traits: {} } },
};

// ─── group-param validation (fail closed before any network) ────────────────

test('no group param → 403', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx(undefined));
  assert.equal(res.status, 403);
  assert.equal(await res.text(), 'forbidden');
});

test('empty group param → 403', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx(''));
  assert.equal(res.status, 403);
});

test('non-prefixed group, member → 200 (Phase 3: no access- prefix required)', async () => {
  // ACTIVE_IN_GROUP is in `family` (a bare, non-prefixed adopter group). Under
  // the relaxed charset regex this now passes the input guard and the gate
  // ALLOWS on membership. (Pre-Phase-3 this 403'd on the prefix check.)
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('family'));
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
});

test('non-prefixed group, NOT a member → 403 (gate, not format)', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('photos'));
  assert.equal(res.status, 403);
});

test('bad group format (uppercase) → 403', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-Observe'));
  assert.equal(res.status, 403);
});

test('bad group format (injection chars) → 403', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-observe; rm -rf'));
  assert.equal(res.status, 403);
});

// ─── session verification ───────────────────────────────────────────────────

test('no session (401 from whoami) → 401 unauthenticated', async () => {
  installFetch({ whoami: { status: 401, body: { error: { code: 401 } } } });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 401);
  assert.equal(await res.text(), 'unauthenticated');
});

test('invalid session (403 from whoami) → 401 unauthenticated', async () => {
  installFetch({ whoami: { status: 403, body: { error: { code: 403 } } } });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 401);
});

test('no cookie at all → 401 unauthenticated', async () => {
  installFetch({ whoami: { status: 401, body: { error: { code: 401 } } } });
  const res = await GET(ctx('access-observe', null));
  assert.equal(res.status, 401);
});

test('inactive session (active:false) → 401', async () => {
  installFetch({ whoami: { status: 200, body: { active: false, identity: { id: 'id-1' } } } });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 401);
});

test('active session with NO identity id → 401, and the admin API is never called', async () => {
  // TWO independent assertions here, and only the STATUS one detects a dropped
  // `!session.identity?.id` guard. Without the guard the undefined id reaches
  // getIdentity, where the Ory SDK's own required-parameter check rejects it
  // BEFORE issuing any fetch; that throw lands in the 503 branch, so 401
  // becomes 503 and the status line below fails. `adminCalls` CANNOT fail
  // here — the same pre-fetch reject means no admin hop happens with the guard
  // or without it. Keep it regardless: "no admin API call for a session with no
  // identity" is a real invariant worth pinning, it is simply not the detector.
  // The genuinely unguarded ALLOW lives in the sibling empty-string test below,
  // where '' survives the SDK's null check, the lookup really is issued, and
  // the gate really does 200.
  let adminCalls = 0;
  installFetch({
    whoami: { status: 200, body: { active: true, identity: { traits: {} } } },
    identity: ACTIVE_IN_GROUP,
  });
  const inner = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(typeof input === 'string' ? input : input?.url ?? input);
    if (url.includes('/admin/identities/')) adminCalls += 1;
    return inner(input);
  };
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 401);
  assert.equal(await res.text(), 'unauthenticated');
  assert.equal(adminCalls, 0);
});

test('active session with an empty-string identity id → 401 (falsy, not merely absent)', async () => {
  installFetch({
    whoami: { status: 200, body: { active: true, identity: { id: '', traits: {} } } },
    identity: ACTIVE_IN_GROUP,
  });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 401);
});

test('kratos unreachable → 503 (NOT 401 — avoids login-redirect loop)', async () => {
  installFetch({ whoamiThrow: true });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 503);
  assert.equal(await res.text(), 'unavailable');
});

test('kratos unreachable → NOT 403 (an outage must not read as a denial)', async () => {
  installFetch({ whoamiThrow: true });
  const res = await GET(ctx('access-observe'));
  assert.notEqual(res.status, 403);
});

// ─── admin resolution + gate ────────────────────────────────────────────────

test('active identity IN group → 200 + identity-id header', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), 'id-1');
});

test('active identity NOT in group → 403', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', state: 'active', metadata_admin: { groups: ['family'] } } },
  });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), null);
});

test('inactive identity IN group → 403 (fail-closed state check)', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', state: 'inactive', metadata_admin: { groups: ['access-observe'] } } },
  });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 403);
});

test('identity missing state field IN group → 403 (fail-closed)', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', metadata_admin: { groups: ['access-observe'] } } },
  });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 403);
});

test('admin lookup failure (404) → 503 (state/groups never learned)', async () => {
  installFetch({ whoami: SESSION_OK, identity: { status: 404, body: { error: 'not found' } } });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 503);
});

test('admin lookup failure (500) → 503 (fail-closed)', async () => {
  installFetch({ whoami: SESSION_OK, identity: { status: 500, body: { error: 'boom' } } });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 503);
  assert.equal(await res.text(), 'unavailable');
});

// ─── the read boundary we do NOT own ────────────────────────────────────────

test('non-canonical stored group → 403, even when the required group matches its case fold', async () => {
  // Only a raw Kratos admin-API write can store "Access-Observe"; every portal
  // write path rejects it (metadata-admin.ts validateGroups). The gate must
  // refuse rather than case-fold it into a match.
  installFetch({
    whoami: SESSION_OK,
    identity: {
      status: 200,
      body: { id: 'id-1', state: 'active', metadata_admin: { groups: ['Access-Observe'] } },
    },
  });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), null);
});

test('one non-canonical group denies a group the identity legitimately holds', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: {
      status: 200,
      body: {
        id: 'id-1',
        state: 'active',
        metadata_admin: { groups: ['access-observe', 'Access-Grafana'] },
      },
    },
  });
  const res = await GET(ctx('access-observe'));
  assert.equal(res.status, 403);
});

// ─── every failure path denies at the edge (non-2xx) ────────────────────────

test('no failure path returns 2xx (Caddy forward_auth @good status 2xx)', async () => {
  const cases = [
    [{ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP }, 'photos'],
    [{ whoami: { status: 401, body: {} } }, 'access-observe'],
    [{ whoamiThrow: true }, 'access-observe'],
    [{ whoami: SESSION_OK, identity: { status: 500, body: {} } }, 'access-observe'],
    [{ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP }, 'BAD-CASE'],
  ];
  for (const [fetchOpts, group] of cases) {
    installFetch(fetchOpts);
    const res = await GET(ctx(group));
    assert.ok(res.status < 200 || res.status > 299, `${group} → ${res.status} must not be 2xx`);
  }
});

// ─── the body never names the group or the identity ─────────────────────────

test('no denial body echoes the required group or the identity id', async () => {
  const noGroups = {
    status: 200,
    body: { id: 'id-1', state: 'active', metadata_admin: { groups: [] } },
  };
  for (const group of ['access-observe', 'BAD-CASE']) {
    installFetch({ whoami: SESSION_OK, identity: noGroups });
    const res = await GET(ctx(group));
    const body = await res.text();
    assert.equal(body.includes(group), false);
    assert.equal(body.includes('id-1'), false);
  }
});

// ─── HEAD parity (a HEAD that 200s where GET 403s is an auth bypass) ─────────

test('HEAD applies the same decision: allowed → 200', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await HEAD(ctx('access-observe'));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), 'id-1');
});

test('HEAD applies the same decision: not in group → 403', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', state: 'active', metadata_admin: { groups: [] } } },
  });
  const res = await HEAD(ctx('access-observe'));
  assert.equal(res.status, 403);
});

test('HEAD with no session → 401', async () => {
  installFetch({ whoami: { status: 401, body: { error: { code: 401 } } } });
  const res = await HEAD(ctx('access-observe'));
  assert.equal(res.status, 401);
});

// ─── responses are never cached ──────────────────────────────────────────────

test('responses carry Cache-Control: no-store', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-observe'));
  assert.match(res.headers.get('Cache-Control') ?? '', /no-store/);
});

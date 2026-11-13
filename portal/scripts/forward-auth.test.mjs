// Invariant: forward_auth admits only requests whose groups match an explicit binding.

import { test, afterEach, vi } from 'vitest';
import assert from 'node:assert/strict';
import { GET, HEAD } from '../src/pages/api/forward-auth.ts';
import { setContentDir, invalidateManifestCache } from '../src/lib/manifests.ts';
import { _resetForTests as resetManifestStore } from '../src/lib/manifest-store.ts';

const realFetch = globalThis.fetch;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

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

afterEach(() => {
  globalThis.fetch = realFetch;
});

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
  body: { id: 'id-1', state: 'active', metadata_admin: { groups: ['access-proxywatch', 'family'] } },
};
const SESSION_OK = {
  status: 200,
  body: { active: true, identity: { id: 'id-1', traits: {} } },
};

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
  const res = await GET(ctx('access-Proxywatch'));
  assert.equal(res.status, 403);
});

test('bad group format (injection chars) → 403', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-proxywatch; rm -rf'));
  assert.equal(res.status, 403);
});

test('no session (401 from whoami) → 401 unauthenticated', async () => {
  installFetch({ whoami: { status: 401, body: { error: { code: 401 } } } });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
  assert.equal(await res.text(), 'unauthenticated');
});

test('invalid session (403 from whoami) → 401 unauthenticated', async () => {
  installFetch({ whoami: { status: 403, body: { error: { code: 403 } } } });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
});

test('no cookie at all → 401 unauthenticated', async () => {
  installFetch({ whoami: { status: 401, body: { error: { code: 401 } } } });
  const res = await GET(ctx('access-proxywatch', null));
  assert.equal(res.status, 401);
});

test('inactive session (active:false) → 401', async () => {
  installFetch({ whoami: { status: 200, body: { active: false, identity: { id: 'id-1' } } } });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
});

test('active session with NO identity id → 401, and the admin API is never called', async () => {
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
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
  assert.equal(await res.text(), 'unauthenticated');
  assert.equal(adminCalls, 0);
});

test('active session with an empty-string identity id → 401 (falsy, not merely absent)', async () => {
  installFetch({
    whoami: { status: 200, body: { active: true, identity: { id: '', traits: {} } } },
    identity: ACTIVE_IN_GROUP,
  });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
});

test('kratos unreachable → 503 (NOT 401 — avoids login-redirect loop)', async () => {
  installFetch({ whoamiThrow: true });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 503);
  assert.equal(await res.text(), 'unavailable');
});

test('kratos unreachable → the log names the failing step and the error', async () => {
  const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
  try {
    installFetch({ whoamiThrow: true });
    assert.equal((await GET(ctx('access-proxywatch'))).status, 503);
    assert.ok(
      spy.mock.calls.some((c) => c[0] === '[portal] upstream failure' && c[1]?.step === 'getSession' && typeof c[1]?.error === 'string'),
    );
  } finally {
    spy.mockRestore();
  }
});

test('kratos unreachable → NOT 403 (an outage must not read as a denial)', async () => {
  installFetch({ whoamiThrow: true });
  const res = await GET(ctx('access-proxywatch'));
  assert.notEqual(res.status, 403);
});

test('active identity IN group → 200 + identity-id header', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'ok');
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), 'id-1');
});

test('active identity NOT in group → 403', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', state: 'active', metadata_admin: { groups: ['family'] } } },
  });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), null);
});

test('inactive identity IN group → 403 (fail-closed state check)', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', state: 'inactive', metadata_admin: { groups: ['access-proxywatch'] } } },
  });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 403);
});

test('identity missing state field IN group → 403 (fail-closed)', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', metadata_admin: { groups: ['access-proxywatch'] } } },
  });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 403);
});

test('admin lookup failure (404) → 503 (state/groups never learned)', async () => {
  installFetch({ whoami: SESSION_OK, identity: { status: 404, body: { error: 'not found' } } });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 503);
});

test('admin lookup failure (500) → 503 (fail-closed)', async () => {
  installFetch({ whoami: SESSION_OK, identity: { status: 500, body: { error: 'boom' } } });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 503);
  assert.equal(await res.text(), 'unavailable');
});

test('non-canonical stored group → 403, even when the required group matches its case fold', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: {
      status: 200,
      body: { id: 'id-1', state: 'active', metadata_admin: { groups: ['Access-Proxywatch'] } },
    },
  });
  const res = await GET(ctx('access-proxywatch'));
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
        metadata_admin: { groups: ['access-proxywatch', 'Access-Grafana'] },
      },
    },
  });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 403);
});

test('no failure path returns 2xx (Caddy forward_auth @good status 2xx)', async () => {
  const cases = [
    [{ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP }, 'photos'],
    [{ whoami: { status: 401, body: {} } }, 'access-proxywatch'],
    [{ whoamiThrow: true }, 'access-proxywatch'],
    [{ whoami: SESSION_OK, identity: { status: 500, body: {} } }, 'access-proxywatch'],
    [{ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP }, 'BAD-CASE'],
  ];
  for (const [fetchOpts, group] of cases) {
    installFetch(fetchOpts);
    const res = await GET(ctx(group));
    assert.ok(res.status < 200 || res.status > 299, `${group} → ${res.status} must not be 2xx`);
  }
});

test('no denial body echoes the required group or the identity id', async () => {
  const noGroups = {
    status: 200,
    body: { id: 'id-1', state: 'active', metadata_admin: { groups: [] } },
  };
  for (const group of ['access-proxywatch', 'BAD-CASE']) {
    installFetch({ whoami: SESSION_OK, identity: noGroups });
    const res = await GET(ctx(group));
    const body = await res.text();
    assert.equal(body.includes(group), false);
    assert.equal(body.includes('id-1'), false);
  }
});

test('HEAD applies the same decision: allowed → 200', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await HEAD(ctx('access-proxywatch'));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), 'id-1');
});

test('HEAD applies the same decision: not in group → 403', async () => {
  installFetch({
    whoami: SESSION_OK,
    identity: { status: 200, body: { id: 'id-1', state: 'active', metadata_admin: { groups: [] } } },
  });
  const res = await HEAD(ctx('access-proxywatch'));
  assert.equal(res.status, 403);
});

test('HEAD with no session → 401', async () => {
  installFetch({ whoami: { status: 401, body: { error: { code: 401 } } } });
  const res = await HEAD(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
});

test('responses carry Cache-Control: no-store', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  const res = await GET(ctx('access-proxywatch'));
  assert.match(res.headers.get('Cache-Control') ?? '', /no-store/);
});

function sessionAt(aal) {
  return { status: 200, body: { active: true, authenticator_assurance_level: aal, identity: { id: 'id-1', traits: {} } } };
}

const ENROLLED_CONFIG = {
  totp: { totp_url: 'otpauth://totp/othala:a?secret=JBSWY3DPEHPK3PXP' },
  webauthn: { credentials: [{ id: 'w', is_passwordless: false }] },
};

function inGroupWith(...types) {
  return {
    status: 200,
    body: {
      ...ACTIVE_IN_GROUP.body,
      credentials: Object.fromEntries(types.map((t) => [t, { type: t, identifiers: ['a'], config: ENROLLED_CONFIG[t] ?? {} }])),
    },
  };
}

test('aal1 session, identity holds totp → 401 (step up)', async () => {
  installFetch({ whoami: sessionAt('aal1'), identity: inGroupWith('password', 'totp') });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), null);
  assert.equal((await HEAD(ctx('access-proxywatch'))).status, 401);
});

test('aal1 session, admin-marked identity with no second factor → 401 (step up)', async () => {
  const base = inGroupWith('password');
  installFetch({
    whoami: sessionAt('aal1'),
    identity: { status: 200, body: { ...base.body, metadata_admin: { ...base.body.metadata_admin, admin: true } } },
  });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 401);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), null);
});

test('aal2 session, identity holds totp → 200', async () => {
  installFetch({ whoami: sessionAt('aal2'), identity: inGroupWith('password', 'totp') });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 200);
});

test('aal1 session in the group with no manifest set → 503 (the step-up rule cannot be evaluated)', async () => {
  setContentDir(import.meta.filename); // a file, not a directory: reading apps/ under it fails with ENOTDIR, not ENOENT
  invalidateManifestCache();
  resetManifestStore();
  try {
    installFetch({ whoami: sessionAt('aal1'), identity: inGroupWith('passkey') });
    assert.equal((await GET(ctx('access-proxywatch'))).status, 503);
    installFetch({ whoami: sessionAt('aal2'), identity: inGroupWith('password', 'totp') });
    assert.equal((await GET(ctx('access-proxywatch'))).status, 200);
  } finally {
    setContentDir(undefined);
    invalidateManifestCache();
    resetManifestStore();
  }
});

test('aal1 session, passkey-only identity → 200 (no second factor to ask for)', async () => {
  installFetch({ whoami: sessionAt('aal1'), identity: inGroupWith('passkey', 'lookup_secret') });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 200);
});

test('aal1 session, password identity with the schema webauthn entry and no keys → 200', async () => {
  const base = inGroupWith('password');
  const credentials = { ...base.body.credentials, webauthn: { type: 'webauthn', identifiers: ['a'], config: {} } };
  installFetch({ whoami: sessionAt('aal1'), identity: { status: 200, body: { ...base.body, credentials } } });
  const res = await GET(ctx('access-proxywatch'));
  assert.equal(res.status, 200);
});

test('aal1 session, identity NOT in group but holds totp → 403 (the gate answers first)', async () => {
  installFetch({ whoami: sessionAt('aal1'), identity: inGroupWith('totp') });
  const res = await GET(ctx('photos'));
  assert.equal(res.status, 403);
});

const SPOOFED_HEADERS = {
  'X-Kratos-Authenticated-Identity-Id': 'id-member',
  'Remote-User': 'id-member',
  'X-Forwarded-User': 'id-member',
};

function ctxWithHeaders(group, extra) {
  const c = ctx(group);
  const headers = new Headers(c.request.headers);
  for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  return { url: c.url, request: new Request(c.url, { method: 'GET', headers }) };
}

function installByIdentity(session) {
  const members = { 'id-member': ['family'], 'id-other': ['photos'] };
  globalThis.fetch = async (input) => {
    const url = String(typeof input === 'string' ? input : input?.url ?? input);
    if (url.includes('/sessions/whoami')) {
      return session
        ? jsonResponse({ active: true, identity: { id: 'id-other', traits: {} } })
        : jsonResponse({ error: { code: 401 } }, 401);
    }
    const id = url.split('/admin/identities/')[1]?.split(/[?/]/)[0];
    return jsonResponse({ id, state: 'active', metadata_admin: { groups: members[id] ?? [] } });
  };
}

test('inbound identity headers naming a member never lift a non-member session → 403', async () => {
  installByIdentity(true);
  const res = await GET(ctxWithHeaders('family', SPOOFED_HEADERS));
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('X-Kratos-Authenticated-Identity-Id'), null);
});

test('inbound identity headers without a session → 401', async () => {
  installByIdentity(false);
  const res = await GET(ctxWithHeaders('family', SPOOFED_HEADERS));
  assert.equal(res.status, 401);
});

test('a deactivated identity is refused on the very next call, with no cached decision', async () => {
  installFetch({ whoami: SESSION_OK, identity: ACTIVE_IN_GROUP });
  assert.equal((await GET(ctx('family'))).status, 200);
  installFetch({ whoami: SESSION_OK, identity: { status: 200, body: { ...ACTIVE_IN_GROUP.body, state: 'inactive' } } });
  assert.equal((await GET(ctx('family'))).status, 403);
});

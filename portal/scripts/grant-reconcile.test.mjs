// Invariant: a credential change flips the fingerprint and no sign-in write does; an identity with no marker is stamped
// without a revoke; a mismatch revokes and then stamps; a failed revoke never stamps; the marker is one JSON Patch add.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  credentialFingerprint,
  readGrantsMarker,
  reconcileIdentity,
  revokeThenStamp,
  sweepGrants,
  startGrantSweep,
} from '../src/lib/grant-reconcile.ts';
import { patchGrantsRevoked } from '../src/lib/admin-api.ts';
import { sweepIntervalMs } from '../src/server/listen.ts';

// Shapes follow Kratos v26.2.0 identity credential configs (identity/credentials_*.go).
const T = '2026-11-13T00:00:00.000Z';
const password = (hashed_password) => ({ type: 'password', identifiers: ['a@x'], version: 0, created_at: T, updated_at: T, config: { hashed_password } });
const key = (id, extra = {}) => ({
  id,
  public_key: 'cHVi',
  attestation_type: 'none',
  authenticator: { aaguid: 'AAAA', sign_count: 0, clone_warning: false },
  display_name: 'key',
  added_at: T,
  is_passwordless: true,
  ...extra,
});
const passkey = (...keys) => ({ type: 'passkey', identifiers: ['u'], version: 1, created_at: T, updated_at: T, config: { credentials: keys, user_handle: 'aGFuZGxl' } });
const webauthn = (...keys) => ({ ...passkey(...keys), type: 'webauthn' });
const totp = (secret) => ({ type: 'totp', identifiers: ['i'], version: 0, created_at: T, updated_at: T, config: { totp_url: `otpauth://totp/o:u?secret=${secret}&issuer=o` } });
const lookup = (...codes) => ({ type: 'lookup_secret', identifiers: ['i'], version: 0, created_at: T, updated_at: T, config: { recovery_codes: codes } });
const code = () => ({ type: 'code', identifiers: ['a@x'], version: 1, created_at: T, updated_at: T, config: { addresses: [{ channel: 'email', address: 'a@x' }] } });

const ARGON = '$argon2id$v=19$m=131072,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2g';
const base = () => ({ password: password(ARGON), passkey: passkey(key('k1')), webauthn: webauthn(key('w1')), totp: totp('JBSWY3DP'), lookup_secret: lookup({ code: 'c1' }, { code: 'c2' }), code: code() });
const fp = (credentials) => credentialFingerprint({ credentials });

test('every credential change flips the fingerprint', () => {
  const b = fp(base());
  const changes = {
    'password replaced': { ...base(), password: password('$argon2id$v=19$m=131072,t=3,p=1$b3RoZXI$b3RoZXJoYXNo') },
    'password removed': { ...base(), password: undefined },
    'passkey added': { ...base(), passkey: passkey(key('k1'), key('k2')) },
    'passkey removed': { ...base(), passkey: passkey() },
    'passkey type deleted': { ...base(), passkey: undefined },
    'passkey swapped': { ...base(), passkey: passkey(key('k9')) },
    'security key added': { ...base(), webauthn: webauthn(key('w1'), key('w2')) },
    'security key type deleted': { ...base(), webauthn: undefined },
    'totp replaced': { ...base(), totp: totp('KRSXG5CT') },
    'totp removed': { ...base(), totp: undefined },
    'backup codes regenerated': { ...base(), lookup_secret: lookup({ code: 'n1' }, { code: 'n2' }) },
    'backup codes removed': { ...base(), lookup_secret: undefined },
  };
  for (const [name, credentials] of Object.entries(changes)) assert.notEqual(fp(credentials), b, name);
});

test('no sign-in write changes the fingerprint', () => {
  const b = fp(base());
  const writes = {
    // webauthn and passkey login write no identity (strategy/webauthn/login.go, passkey/passkey_login.go); counters would not count anyway
    'authenticator counters move': { ...base(), passkey: passkey(key('k1', { authenticator: { aaguid: 'AAAA', sign_count: 7, clone_warning: true } })) },
    'key renamed': { ...base(), webauthn: webauthn(key('w1', { display_name: 'renamed' })) },
    // lookup/login.go sets used_at on the code it consumes
    'backup code used': { ...base(), lookup_secret: lookup({ code: 'c1', used_at: T }, { code: 'c2' }) },
    // totp/login.go and code/strategy_login.go write nothing to the identity
    'credential timestamps and versions move': { ...base(), password: { ...password(ARGON), updated_at: '2026-11-14T00:00:00Z', version: 3 } },
    'code credential addresses or identifiers change': { ...base(), code: { ...code(), identifiers: ['b@x'], config: { addresses: [] } } },
    'code credential removed': { ...base(), code: undefined },
    'identifiers change': { ...base(), password: { ...password(ARGON), identifiers: ['new@x'] } },
  };
  for (const [name, credentials] of Object.entries(writes)) assert.equal(fp(credentials), b, name);
});

test('the fingerprint is order-independent, hex, and carries no secret in the clear', () => {
  const a = fp({ lookup_secret: lookup({ code: 'c1' }, { code: 'c2' }), passkey: passkey(key('a'), key('b')) });
  const b = fp({ passkey: passkey(key('b'), key('a')), lookup_secret: lookup({ code: 'c2', used_at: T }, { code: 'c1' }) });
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.ok(!fp(base()).includes('JBSWY3DP'));
  assert.equal(fp(undefined), fp({}));
});

const MARK = { fp: 'a'.repeat(64), at: T };
const ident = (credentials, grants_revoked) => ({ id: 'id-1', credentials, metadata_admin: grants_revoked ? { grants_revoked } : {} });

function harness({ failRevoke = false } = {}) {
  const calls = [];
  return {
    calls,
    deps: {
      revokeGrants: async (id) => {
        calls.push(['revoke', id]);
        if (failRevoke) throw new Error('hydra down');
      },
      stampMarker: async (id, marker) => calls.push(['stamp', id, marker]),
      now: () => new Date(T),
    },
  };
}

test('no marker: stamped without a revoke', async () => {
  const h = harness();
  const out = await reconcileIdentity(ident(base()), h.deps);
  assert.equal(out, 'stamped');
  assert.deepEqual(h.calls, [['stamp', 'id-1', { fp: fp(base()), at: T }]]);
});

test('matching marker: nothing happens', async () => {
  const h = harness();
  assert.equal(await reconcileIdentity(ident(base(), { fp: fp(base()), at: T }), h.deps), 'current');
  assert.deepEqual(h.calls, []);
});

test('mismatching marker: revoke, then stamp the current fingerprint', async () => {
  const h = harness();
  assert.equal(await reconcileIdentity(ident(base(), MARK), h.deps), 'revoked');
  assert.deepEqual(h.calls, [['revoke', 'id-1'], ['stamp', 'id-1', { fp: fp(base()), at: T }]]);
});

test('a revoke failure stamps nothing and propagates', async () => {
  const h = harness({ failRevoke: true });
  await assert.rejects(reconcileIdentity(ident(base(), MARK), h.deps), /hydra down/);
  assert.deepEqual(h.calls, [['revoke', 'id-1']]);
});

test('a malformed marker reads as absent', () => {
  for (const bad of [null, 'x', { fp: 'short', at: T }, { fp: 'a'.repeat(64) }, { fp: 'A'.repeat(64), at: T }]) {
    assert.equal(readGrantsMarker({ grants_revoked: bad }), undefined);
  }
  assert.deepEqual(readGrantsMarker({ grants_revoked: MARK }), MARK);
});

test('the sweep reconciles every identity, and one failure does not stop the rest', async () => {
  const logs = [];
  const a = { ...ident(base(), MARK), id: 'a' };
  const b = { ...ident(base()), id: 'b' };
  const c = { ...ident(base(), MARK), id: 'c' };
  const calls = [];
  const deps = {
    listIdentities: async () => [a, b, c],
    revokeGrants: async (id) => {
      calls.push(['revoke', id]);
      if (id === 'a') throw new Error('boom');
    },
    stampMarker: async (id) => calls.push(['stamp', id]),
  };
  const r = await sweepGrants(deps, (m) => logs.push(m));
  assert.deepEqual(r, { stamped: 1, revoked: 1, failed: 1 });
  assert.deepEqual(calls, [['revoke', 'a'], ['stamp', 'b'], ['revoke', 'c'], ['stamp', 'c']]);
  assert.equal(logs.length, 1);
  assert.ok(!logs[0].includes('JBSWY3DP'));
});

test('the hook path revokes, then stamps the fingerprint read before the revoke; a failed revoke stamps nothing', async () => {
  const order = [];
  const deps = {
    getIdentity: async () => (order.push('read'), ident(base())),
    revokeGrants: async () => order.push('revoke'),
    stampMarker: async (id, m) => order.push(['stamp', m.fp]),
    now: () => new Date(T),
  };
  await revokeThenStamp('id-1', deps, () => {});
  assert.deepEqual(order, ['read', 'revoke', ['stamp', fp(base())]]);

  const failing = [];
  await assert.rejects(
    revokeThenStamp('id-1', { ...deps, revokeGrants: async () => { throw new Error('hydra down'); }, stampMarker: async () => failing.push('stamp') }, () => {}),
    /hydra down/,
  );
  assert.deepEqual(failing, []);
});

test('the hook path still revokes when the credentials cannot be read, and writes no marker', async () => {
  const calls = [];
  await revokeThenStamp(
    'id-1',
    { getIdentity: async () => { throw new Error('kratos down'); }, revokeGrants: async () => calls.push('revoke'), stampMarker: async () => calls.push('stamp') },
    () => {},
  );
  assert.deepEqual(calls, ['revoke']);
});

test('the marker is written by one JSON Patch add on /metadata_admin/grants_revoked', async () => {
  const patches = [];
  const { IdentityApi } = await import('@ory/client-fetch');
  const orig = { get: IdentityApi.prototype.getIdentity, patch: IdentityApi.prototype.patchIdentity };
  IdentityApi.prototype.getIdentity = async () => ({ id: 'id-1', metadata_admin: { groups: ['everyone'] } });
  IdentityApi.prototype.patchIdentity = async function (args) {
    patches.push(args);
  };
  try {
    await patchGrantsRevoked('id-1', MARK);
    assert.deepEqual(patches, [{ id: 'id-1', jsonPatch: [{ op: 'add', path: '/metadata_admin/grants_revoked', value: MARK }] }]);
    patches.length = 0;
    IdentityApi.prototype.getIdentity = async () => ({ id: 'id-1', metadata_admin: null });
    await patchGrantsRevoked('id-1', MARK);
    assert.deepEqual(patches[0].jsonPatch, [{ op: 'add', path: '/metadata_admin', value: { grants_revoked: MARK } }]);
  } finally {
    IdentityApi.prototype.getIdentity = orig.get;
    IdentityApi.prototype.patchIdentity = orig.patch;
  }
});

test('sweep period: 5 minutes unless OTHALA_REVOKE_SWEEP_SECONDS is a number of seconds of at least 1', () => {
  assert.equal(sweepIntervalMs({}), 300_000);
  assert.equal(sweepIntervalMs({ OTHALA_REVOKE_SWEEP_SECONDS: '10' }), 10_000);
  for (const bad of ['', 'x', '0', '-5', '0.2']) assert.equal(sweepIntervalMs({ OTHALA_REVOKE_SWEEP_SECONDS: bad }), 300_000, bad);
});

test('the timer sweeps now and again each period, and stops when told', async () => {
  let passes = 0;
  const stop = startGrantSweep({ listIdentities: async () => (passes++, []), revokeGrants: async () => {}, stampMarker: async () => {} }, 20, () => {});
  await new Promise((r) => setTimeout(r, 90));
  stop();
  const seen = passes;
  assert.ok(seen >= 3, `passes ${seen}`);
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(passes, seen);
});

// Invariants: the access gate admits only active identities holding the bound group; a denial outranks a step-up,
// and step-up follows enrolled second factors, the admin marker and elevated roles only.

import { test, describe, it, expect } from 'vitest';
import assert from 'node:assert/strict';
import {
  decideAccess,
  needsStepUp,
  holdsElevatedRole,
  enforceAccessGate,
  enforceGroupGate,
  hasGroup,
  nonCanonicalGroups,
} from '../src/lib/gate.ts';
import { parseIdentity } from '../src/lib/identity-facts.ts';
import { asAdmin, identity as buildIdentity, withCredential, withLookupSecret, withPasskey, withTotp, withWebauthnKey, manifest as manifestOf } from '../src/lib/test-builders.ts';

const identity = (overrides = {}) => ({ ...buildIdentity({ metadataAdmin: { groups: ['memories'] } }), ...overrides });
const identityGroups = (i) => parseIdentity(i).groups;

function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: clientId,
    accessGroups: opts.accessGroups ?? [`access-${clientId}`],
    skipAccessCheck: opts.skipAccessCheck ?? false,
    roles: [],
    groupRoleMap: {},
  };
}

test('identityGroups / hasGroup read metadata_admin.groups defensively', () => {
  assert.deepEqual(identityGroups(identity()), ['memories']);
  assert.equal(hasGroup(identity(), 'memories'), true);
  assert.equal(hasGroup(identity(), 'other'), false);
  assert.deepEqual(identityGroups(identity({ metadata_admin: {} })), []);
  assert.deepEqual(identityGroups(identity({ metadata_admin: undefined })), []);
  assert.deepEqual(identityGroups(null), []);
});

test('gate ALLOWS an active member of a bound access group', () => {
  const r = enforceAccessGate(identity(), manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, true);
  assert.equal(r.reason, undefined);
});

test('gate ALLOWS via OR-semantics when the user is in any one bound group', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['memories'] } }),
    manifest('photos', { accessGroups: ['admin-memories', 'memories'] }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when the user is in NONE of the bound groups', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['other'] } }),
    manifest('photos', { accessGroups: ['memories'] }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /not in any of the access group/);
});

test('gate DENIES when the manifest binds no access groups (no implicit access)', () => {
  const r = enforceAccessGate(identity(), manifest('photos', { accessGroups: [] }));
  assert.equal(r.allowed, false);
  assert.match(r.reason, /no access group bound/);
});

test('gate DENIES when no manifest is supplied (fail-closed)', () => {
  const r = enforceAccessGate(identity(), undefined);
  assert.equal(r.allowed, false);
});

test('skip_access_check bypasses the group check for an active identity', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: [] } }),
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when state is inactive (deactivated identity)', () => {
  const r = enforceAccessGate(identity({ state: 'inactive' }), manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES when state is missing (fail-closed)', () => {
  const r = enforceAccessGate(identity({ state: undefined }), manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('skip_access_check NEVER bypasses the state check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive' }),
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES on null identity (lookup failure, fail-closed)', () => {
  const r = enforceAccessGate(null, manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity lookup failed');
});

test('state check precedes group check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive', metadata_admin: { groups: [] } }),
    manifest('photos', { accessGroups: ['memories'] }),
  );
  assert.equal(r.reason, 'identity not active');
});

test('regression: access-proxywatch flat binding still admits a member', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['access-proxywatch'] } }),
    manifest('proxywatch', { accessGroups: ['access-proxywatch'] }),
  );
  assert.equal(r.allowed, true);
});

test('enforceGroupGate: active member of the named group → allow', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['access-proxywatch'] } }), 'access-proxywatch');
  assert.equal(r.allowed, true);
});

test('enforceGroupGate: not a member → deny', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['other'] } }), 'access-proxywatch');
  assert.equal(r.allowed, false);
});

test('hasGroup does NOT match a mixed-case stored group against a lowercase query', () => {
  const id = identity({ metadata_admin: { groups: ['Access-Grafana'] } });
  assert.equal(hasGroup(id, 'access-grafana'), false);
});

test('hasGroup does NOT match a lowercase stored group against a mixed-case query', () => {
  const id = identity({ metadata_admin: { groups: ['access-grafana'] } });
  assert.equal(hasGroup(id, 'Access-Grafana'), false);
});

test('hasGroup does NOT match an UPPERCASE stored group against a lowercase query', () => {
  const id = identity({ metadata_admin: { groups: ['ACCESS-GRAFANA'] } });
  assert.equal(hasGroup(id, 'access-grafana'), false);
});

test('hasGroup rejects a different group name', () => {
  const id = identity({ metadata_admin: { groups: ['access-grafana'] } });
  assert.equal(hasGroup(id, 'access-photos'), false);
});

test('nonCanonicalGroups reports exactly the stored names that miss GROUP_RE', () => {
  const id = identity({ metadata_admin: { groups: ['access-proxywatch', 'Access-Grafana', 'has space'] } });
  assert.deepEqual(nonCanonicalGroups(id), ['Access-Grafana', 'has space']);
  assert.deepEqual(nonCanonicalGroups(identity()), []);
  assert.deepEqual(nonCanonicalGroups(null), []);
});

test('enforceGroupGate DENIES when a stored group is non-canonical, naming it', () => {
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['Access-Proxywatch'] } }),
    'access-proxywatch',
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /non-canonical/);
  assert.match(r.reason, /Access-Proxywatch/);
});

test('enforceGroupGate DENIES a group the identity legitimately holds when ANOTHER is non-canonical', () => {
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['access-proxywatch', 'Access-Grafana'] } }),
    'access-proxywatch',
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /Access-Grafana/);
});

test('enforceAccessGate DENIES on a non-canonical stored group, even with skip_access_check', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['Access-Proxywatch'] } }),
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /non-canonical/);
});

test('the state check still precedes the non-canonical refusal', () => {
  const r = enforceGroupGate(
    identity({ state: 'inactive', metadata_admin: { groups: ['Access-Proxywatch'] } }),
    'access-proxywatch',
  );
  assert.equal(r.reason, 'identity not active');
});

describe('step-up and elevation', () => {
  const APPLY = {
    password: (i) => i,
    passkey: withPasskey,
    totp: withTotp,
    webauthn: (i) => withWebauthnKey(i),
    lookup_secret: withLookupSecret,
    'webauthn-schema-only': (i) => i,
    'webauthn-no-keys': (i) => withCredential(i, 'webauthn', { credentials: [] }),
    'webauthn-passwordless-only': (i) => withWebauthnKey(i, { passwordless: true }),
    'totp-no-url': (i) => withCredential(i, 'totp', {}),
  };

  function identity(types, admin) {
    const base = buildIdentity({
      id: 'id-1',
      password: types.includes('password'),
      ...(admin === undefined ? {} : { metadataAdmin: { admin } }),
    });
    return types.reduce((i, t) => APPLY[t](i), base);
  }

  describe('needsStepUp', () => {
    const cases = [
      ['aal1 + totp', 'aal1', ['password', 'totp'], undefined, true],
      ['aal1 + webauthn', 'aal1', ['passkey', 'webauthn'], undefined, true],
      ['missing aal + totp', undefined, ['totp'], undefined, true],
      ['aal1 admin-marked, no second factor', 'aal1', ['password'], true, true],
      ['aal1 passkey only', 'aal1', ['passkey'], undefined, false],
      ['aal1 password only', 'aal1', ['password'], undefined, false],
      ['aal1 lookup_secret only', 'aal1', ['lookup_secret'], undefined, false],
      ['aal1 password + schema webauthn entry, no keys', 'aal1', ['password', 'webauthn-schema-only'], undefined, false],
      ['aal1 password + emptied webauthn entry', 'aal1', ['password', 'webauthn-no-keys'], undefined, false],
      ['aal1 passwordless webauthn key only', 'aal1', ['password', 'webauthn-passwordless-only'], undefined, false],
      ['aal1 totp entry without a totp_url', 'aal1', ['password', 'totp-no-url'], undefined, false],
      ['aal1 admin marker false', 'aal1', ['password'], false, false],
      ['aal2 + totp', 'aal2', ['totp'], undefined, false],
      ['aal2 admin-marked', 'aal2', ['totp'], true, false],
    ];

    it.each(cases)('%s', (_name, aal, types, admin, expected) => {
      const session = aal === undefined ? {} : { authenticator_assurance_level: aal };
      expect(needsStepUp(session, identity(types, admin))).toBe(expected);
    });

    it('null session with a second factor steps up', () => {
      expect(needsStepUp(null, identity(['totp']))).toBe(true);
    });

    it('null identity never steps up (the gate denies it elsewhere)', () => {
      expect(needsStepUp({ authenticator_assurance_level: 'aal1' }, null)).toBe(false);
    });
  });

  const x = manifestOf('x', ['admin', 'user'], { 'x-admin': 'admin', 'x-access': 'user' }, ['x-access']);

  describe('holdsElevatedRole', () => {
    const listen = manifestOf('listen', ['admin', 'user', 'guest'], { 'listen-admin': 'admin', 'listen-access': 'user' }, ['listen-access']);
    const grafana = manifestOf('grafana', ['admin', 'editor', 'viewer'], { 'grafana-admin': 'admin', 'grafana-access': 'viewer' }, ['grafana-access']);
    const held = (manifests, groups, roles) =>
      holdsElevatedRole(buildIdentity({ metadataAdmin: { groups, ...(roles ? { roles } : {}) } }), manifests);

    it('a role above the entry role holds elevation', () => {
      expect(held([x], ['x-admin'])).toBe(true);
      expect(held([listen], ['listen-admin'])).toBe(true);
    });
    it('the entry role and below do not', () => {
      expect(held([x], ['x-access'])).toBe(false);
      expect(held([listen], ['listen-access'])).toBe(false);
      expect(held([x, listen], [])).toBe(false);
      expect(holdsElevatedRole(null, [x])).toBe(false);
    });
    it('an override resolves through the same ranking', () => {
      expect(held([grafana], ['grafana-access'], { grafana: 'editor' })).toBe(true);
      expect(held([grafana], ['grafana-admin'], { grafana: 'viewer' })).toBe(false);
    });
    it('an override naming an undeclared role is not elevated, whatever the groups map', () => {
      expect(held([grafana], ['grafana-access', 'grafana-admin'], { grafana: 'reader' })).toBe(false);
    });
    it('the entry role is the lowest-ranked mapped access group', () => {
      const m = manifestOf('m', ['admin', 'editor', 'viewer'], { 'm-edit': 'editor', 'm-view': 'viewer' }, ['m-edit', 'm-view']);
      expect(held([m], ['m-edit'])).toBe(true);
      expect(held([m], ['m-view'])).toBe(false);
    });
    it('without a mapped access group the entry role is the last declared', () => {
      const m = manifestOf('m', ['admin', 'editor', 'viewer'], {}, ['m-access']);
      expect(held([m], ['m-access'], { m: 'editor' })).toBe(true);
      expect(held([m], ['m-access'], { m: 'viewer' })).toBe(false);
    });
    it('a manifest without roles is never elevated', () => {
      expect(held([manifestOf('y', [], {}, ['y-access'])], ['y-access'])).toBe(false);
    });
  });

  describe('decideAccess', () => {
    const member = (groups = ['x-access']) => buildIdentity({ metadataAdmin: { groups } });
    const aal1 = { authenticator_assurance_level: 'aal1' };
    const aal2 = { authenticator_assurance_level: 'aal2' };
    const cases = [
      ['app: member at aal1', member(), { app: x }, aal1, 'allow'],
      ['app: not in an access group', member([]), { app: x }, aal1, 'deny'],
      ['app: inactive identity', { ...member(), state: 'inactive' }, { app: x }, aal1, 'deny'],
      ['app: identity lookup failed', null, { app: x }, aal1, 'deny'],
      ['app: no manifest', member(), { app: undefined }, aal1, 'deny'],
      ['app: second factor at aal1', withTotp(member()), { app: x }, aal1, 'stepUp'],
      ['app: second factor at aal2', withTotp(member()), { app: x }, aal2, 'allow'],
      ['app: admin marker at aal1', asAdmin(member()), { app: x }, aal1, 'stepUp'],
      ['app: elevated role at aal1', member(['x-access', 'x-admin']), { app: x }, aal1, 'stepUp'],
      ['app: denial outranks step-up', withTotp(member([])), { app: x }, aal1, 'deny'],
      ['group: member at aal1', member(), { group: 'x-access' }, aal1, 'allow'],
      ['group: not a member', member(), { group: 'y-access' }, aal1, 'deny'],
      ['group: non-canonical stored group', member(['x-access', 'Bad Name']), { group: 'x-access' }, aal1, 'deny'],
      ['group: second factor at aal1', withTotp(member()), { group: 'x-access' }, aal1, 'stepUp'],
      ['admin: marker, aal2, fresh', asAdmin(member()), 'admin', { ...aal2, fresh: true }, 'allow'],
      ['admin: no marker', member(), 'admin', { ...aal2, fresh: true }, 'deny'],
      ['admin: stale aal2', asAdmin(member()), 'admin', { ...aal2, fresh: false }, 'stepUp'],
      ['admin: freshness unknown', asAdmin(member()), 'admin', aal2, 'stepUp'],
      ['admin: aal1', asAdmin(member()), 'admin', { ...aal1, fresh: true }, 'stepUp'],
      ['admin: session rules settle without an identity', null, 'admin', aal1, 'stepUp'],
      ['emailed code: admin account', asAdmin(member()), 'emailed-code', null, 'deny'],
      ['emailed code: member', withTotp(member()), 'emailed-code', null, 'allow'],
      ['emailed code: no identity to refuse', null, 'emailed-code', null, 'allow'],
    ];

    it.each(cases)('%s', (_name, i, target, session, expected) => {
      expect(Object.keys(decideAccess(i, target, session, [x]))).toEqual([expected]);
    });
  });
});

// Tests for portal/src/lib/gate.ts — the COMPLETE access gate (CU1 item 2).
//
// Run with: npx vitest run scripts/gate.test.mjs
//
// Imports the canonical implementation directly. The gate keys off the
// manifest's bound access groups (manifest.accessGroups, OR-semantics) AND
// state==active, both fail-closed — NOT a derived `access-<clientId>` name. The
// exhaustive fail-closed property lives in portal/scripts/gate-property.test.mjs.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  enforceAccessGate,
  enforceGroupGate,
  hasGroup,
  identityGroups,
  nonCanonicalGroups,
} from '../src/lib/gate.ts';

function identity(overrides = {}) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'tester', email: 'a@othala.test' },
    metadata_admin: { groups: ['memories'] },
    ...overrides,
  };
}

// A manifest fixture: accessGroups is the load-bearing binding.
function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: clientId,
    accessGroup: `access-${clientId}`,
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
  const r = enforceAccessGate(identity(), 'photos', manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, true);
  assert.equal(r.reason, undefined);
});

test('gate ALLOWS via OR-semantics when the user is in any one bound group', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['memories'] } }),
    'photos',
    manifest('photos', { accessGroups: ['admin-memories', 'memories'] }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when the user is in NONE of the bound groups', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['other'] } }),
    'photos',
    manifest('photos', { accessGroups: ['memories'] }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /not in any of the access group/);
});

test('gate DENIES when the manifest binds no access groups (no implicit access)', () => {
  const r = enforceAccessGate(identity(), 'photos', manifest('photos', { accessGroups: [] }));
  assert.equal(r.allowed, false);
  assert.match(r.reason, /no access group bound/);
});

test('gate DENIES when no manifest is supplied (fail-closed)', () => {
  const r = enforceAccessGate(identity(), 'photos', undefined);
  assert.equal(r.allowed, false);
});

test('skip_access_check bypasses the group check for an active identity', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: [] } }),
    'photos',
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when state is inactive (deactivated identity)', () => {
  const r = enforceAccessGate(identity({ state: 'inactive' }), 'photos', manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES when state is missing (fail-closed)', () => {
  const r = enforceAccessGate(identity({ state: undefined }), 'photos', manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('skip_access_check NEVER bypasses the state check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive' }),
    'photos',
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES on null identity (lookup failure, fail-closed)', () => {
  const r = enforceAccessGate(null, 'photos', manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity lookup failed');
});

test('state check precedes group check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive', metadata_admin: { groups: [] } }),
    'photos',
    manifest('photos', { accessGroups: ['memories'] }),
  );
  assert.equal(r.reason, 'identity not active');
});

// A flat `access-`-prefixed name is an ordinary binding. This asserts the gate
// ALLOWS when the manifest binds `access-observe` AND the identity holds
// `access-observe` — both sides carry the same name, so what is pinned is that
// the prefix gets no special handling, not that a stale group name is remapped
// onto a renamed binding. The gate compares bound names against identity groups
// verbatim (portal/src/lib/gate.ts:
// `accessGroups.some((g) => userGroups.includes(g))`) and derives nothing from
// clientId. Retained across the `<svc>-access` rename: that rename was cosmetic
// and forced no data migration, so a flat legacy binding must still admit.
test('regression: access-observe flat binding still admits a member', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['access-observe'] } }),
    'observe',
    manifest('observe', { accessGroups: ['access-observe'] }),
  );
  assert.equal(r.allowed, true);
});

// enforceGroupGate is forward-auth's arbitrary-group path: a single required
// group, no manifest, no skip_access_check hatch.
test('enforceGroupGate: active member of the named group → allow', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['access-observe'] } }), 'access-observe');
  assert.equal(r.allowed, true);
});

test('enforceGroupGate: not a member → deny', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['other'] } }), 'access-observe');
  assert.equal(r.allowed, false);
});

// ── group names are compared VERBATIM ────────────────────────────────────────
// hasGroup used to lowercase both sides — the only one of the group
// comparisons in portal/src that did, and the most permissive of them. There is
// one canonical form (GROUP_RE, src/lib/access-groups.ts) validated at every
// boundary this codebase owns, so a case fold could only ever match a name no
// owned boundary could have written.

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

// ── the READ boundary we do not own ──────────────────────────────────────────

test('nonCanonicalGroups reports exactly the stored names that miss GROUP_RE', () => {
  const id = identity({ metadata_admin: { groups: ['access-observe', 'Access-Grafana', 'has space'] } });
  assert.deepEqual(nonCanonicalGroups(id), ['Access-Grafana', 'has space']);
  assert.deepEqual(nonCanonicalGroups(identity()), []);
  assert.deepEqual(nonCanonicalGroups(null), []);
});

test('enforceGroupGate DENIES when a stored group is non-canonical, naming it', () => {
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['Access-Observe'] } }),
    'access-observe',
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /non-canonical/);
  assert.match(r.reason, /Access-Observe/);
});

test('enforceGroupGate DENIES a group the identity legitimately holds when ANOTHER is non-canonical', () => {
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['access-observe', 'Access-Grafana'] } }),
    'access-observe',
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /Access-Grafana/);
});

test('enforceAccessGate DENIES on a non-canonical stored group, even with skip_access_check', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['Access-Observe'] } }),
    'photos',
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /non-canonical/);
});

test('the state check still precedes the non-canonical refusal', () => {
  const r = enforceGroupGate(
    identity({ state: 'inactive', metadata_admin: { groups: ['Access-Observe'] } }),
    'access-observe',
  );
  assert.equal(r.reason, 'identity not active');
});

// Tests for src/lib/gate.ts — the COMPLETE access gate (CU1 item 2).
//
// Run with: tsx --test scripts/gate.test.mjs
//
// Imports the canonical implementation directly. access-model Phase 2: the gate
// keys off the manifest's bound access groups (manifest.accessGroups,
// OR-semantics) AND state==active, both fail-closed — NOT a derived
// `access-<clientId>` name (docs/access-model.md §10). The exhaustive
// fail-closed property lives in scripts/gate-property.test.mjs (§16).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  enforceAccessGate,
  enforceGroupGate,
  hasGroup,
  identityGroups,
} from '../src/lib/gate.ts';

function identity(overrides = {}) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'tester', email: 'a@dunn.dev' },
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
  const r = enforceAccessGate(identity(), 'immich', manifest('immich', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, true);
  assert.equal(r.reason, undefined);
});

test('gate ALLOWS via OR-semantics when the user is in any one bound group', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['memories'] } }),
    'immich',
    manifest('immich', { accessGroups: ['admin-memories', 'memories'] }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when the user is in NONE of the bound groups', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['other'] } }),
    'immich',
    manifest('immich', { accessGroups: ['memories'] }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /not in any of the access group/);
});

test('gate DENIES when the manifest binds no access groups (no implicit access)', () => {
  const r = enforceAccessGate(identity(), 'immich', manifest('immich', { accessGroups: [] }));
  assert.equal(r.allowed, false);
  assert.match(r.reason, /no access group bound/);
});

test('gate DENIES when no manifest is supplied (fail-closed)', () => {
  const r = enforceAccessGate(identity(), 'immich', undefined);
  assert.equal(r.allowed, false);
});

test('skip_access_check bypasses the group check for an active identity', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: [] } }),
    'immich',
    manifest('immich', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when state is inactive (deactivated identity)', () => {
  const r = enforceAccessGate(identity({ state: 'inactive' }), 'immich', manifest('immich', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES when state is missing (fail-closed)', () => {
  const r = enforceAccessGate(identity({ state: undefined }), 'immich', manifest('immich', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('skip_access_check NEVER bypasses the state check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive' }),
    'immich',
    manifest('immich', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES on null identity (lookup failure, fail-closed)', () => {
  const r = enforceAccessGate(null, 'immich', manifest('immich', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity lookup failed');
});

test('state check precedes group check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive', metadata_admin: { groups: [] } }),
    'immich',
    manifest('immich', { accessGroups: ['memories'] }),
  );
  assert.equal(r.reason, 'identity not active');
});

// access-observe regression: a flat (prefixed) name is a valid binding. The
// live dag binds `access-observe`; a member must still get in through the
// rerouted gate (DoD: live dag must not regress).
test('regression: access-observe flat binding still admits a member', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['access-observe'] } }),
    'observe',
    manifest('observe', { accessGroups: ['access-observe'] }),
  );
  assert.equal(r.allowed, true);
});

// enforceGroupGate (forward-auth's arbitrary-group path) is UNCHANGED in
// Phase 2: it still takes a single required group. Phase 3 relaxes the
// forward-auth GROUP_RE; this gate function itself does not.
test('enforceGroupGate: active member of the named group → allow', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['access-observe'] } }), 'access-observe');
  assert.equal(r.allowed, true);
});

test('enforceGroupGate: not a member → deny', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['other'] } }), 'access-observe');
  assert.equal(r.allowed, false);
});

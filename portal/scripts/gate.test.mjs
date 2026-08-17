// Tests for portal/src/lib/gate.ts — the COMPLETE access gate (CU1 item 2).
//
// Run with: tsx --test scripts/gate.test.mjs
//
// Imports the canonical implementation directly. access-model Phase 2: the gate
// keys off the manifest's bound access groups (manifest.accessGroups,
// OR-semantics) AND state==active, both fail-closed — NOT a derived
// `access-<clientId>` name (docs/access-model.md §10). The exhaustive
// fail-closed property lives in portal/scripts/gate-property.test.mjs (§16).

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

// A flat `access-`-prefixed name is an ordinary binding. This asserts the gate
// ALLOWS when the manifest binds `access-observe` AND the identity holds
// `access-observe` — both sides carry the same name, so what is pinned is that
// the prefix gets no special handling, not that a stale group name is remapped
// onto a renamed binding. The gate compares bound names against identity groups
// verbatim (portal/src/lib/gate.ts:
// `accessGroups.some((g) => userGroups.includes(g))`) and derives nothing from
// clientId. Retained across the `<svc>-access` rename, which docs/access-model.md
// §17 step 4 records as cosmetic, forcing no data migration.
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

// ── hasGroup case-normalization ───────────────────────────────────────────────
// An out-of-band admin-API write with mixed-case group names would silently
// fail to match a lowercase query without normalization (deny→correct-match fix).

test('hasGroup matches when stored group is mixed-case and query is lowercase', () => {
  const id = identity({ metadata_admin: { groups: ['Access-Grafana'] } });
  assert.equal(hasGroup(id, 'access-grafana'), true, 'mixed-case stored must match lowercase query');
});

test('hasGroup matches when stored group is lowercase and query is mixed-case', () => {
  const id = identity({ metadata_admin: { groups: ['access-grafana'] } });
  assert.equal(hasGroup(id, 'Access-Grafana'), true, 'lowercase stored must match mixed-case query');
});

test('hasGroup matches when both stored and query are UPPERCASE', () => {
  const id = identity({ metadata_admin: { groups: ['ACCESS-GRAFANA'] } });
  assert.equal(hasGroup(id, 'access-grafana'), true, 'UPPER stored must match lowercase query');
});

test('hasGroup still rejects non-members after normalization', () => {
  const id = identity({ metadata_admin: { groups: ['Access-Grafana'] } });
  assert.equal(hasGroup(id, 'access-immich'), false, 'different group must still deny');
});

test('enforceGroupGate allows when stored group case differs from query (via hasGroup normalization)', () => {
  // Integration check: the gate uses hasGroup internally; verify normalization
  // flows through the full enforce path.
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['Access-Observe'] } }),
    'access-observe',
  );
  assert.equal(r.allowed, true);
});

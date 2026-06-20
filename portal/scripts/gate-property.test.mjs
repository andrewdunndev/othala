// The fail-closed PROPERTY TEST — the load-bearing gate of the access-model
// refactor (docs/access-model.md §16).
//
// Run with: tsx --test scripts/gate-property.test.mjs
//
// The invariant under test, for ALL (identity, manifest):
//
//   enforceAccessGate(identity, clientId, manifest).allowed === true
//     IFF
//   identity != null
//     AND identity.state === 'active'
//     AND ( manifest.skipAccessCheck === true
//           OR manifest.accessGroups ∩ identity.groups ≠ ∅ )
//
// Anything else DENIES (fail-closed). The whole point of the refactor is that
// access-bearing groups come from the manifest's `accessGroups` binding (a
// list, OR-semantics) — NOT from a derived `access-<clientId>` prefix. Running
// this against the prefix-based implementation FAILS (that failure proves the
// test bites); making it pass is the Phase-2 cutover gate.
//
// The matrix from §16 is covered both as explicit enumerated cases and as a
// fast-check property over randomized inputs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { enforceAccessGate } from '../src/lib/gate.ts';

// ─── fixtures ────────────────────────────────────────────────────────────────

/** Build a manifest fixture. accessGroups defaults to the prefix-free binding. */
function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: opts.clientName ?? clientId,
    redirectUris: [],
    postLogoutRedirectUris: [],
    scopes: [],
    scope: '',
    audience: [],
    grantTypes: [],
    responseTypes: [],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroup: `access-${clientId}`,
    accessGroups: opts.accessGroups ?? [],
    roles: opts.roles ?? [],
    groupRoleMap: opts.groupRoleMap ?? {},
    emitGroupsClaim: null,
    skipAccessCheck: opts.skipAccessCheck ?? false,
    sourcePath: `${clientId}.yaml`,
  };
}

/** Build an identity fixture. `groups`==null models a failed lookup (null id). */
function identity(groups, state = 'active') {
  if (groups === null) return null;
  return {
    id: 'id-1',
    state,
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'tester', email: 'a@dunn.dev' },
    metadata_admin: { groups },
  };
}

/** Reference oracle: the invariant restated, independent of the implementation. */
function shouldAllow(id, m) {
  if (!id) return false;
  if (id.state !== 'active') return false;
  if (m.skipAccessCheck) return true;
  const userGroups = id.metadata_admin?.groups ?? [];
  return m.accessGroups.some((g) => userGroups.includes(g));
}

// ─── §16 enumerated matrix ──────────────────────────────────────────────────

test('matrix: null id → DENY', () => {
  const m = manifest('immich', { accessGroups: ['memories'] });
  assert.equal(enforceAccessGate(identity(null), 'immich', m).allowed, false);
});

test('matrix: inactive identity in the bound group → DENY (state gate)', () => {
  const m = manifest('immich', { accessGroups: ['memories'] });
  const id = identity(['memories'], 'inactive');
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, false);
});

test('matrix: active, NOT in the bound group → DENY', () => {
  const m = manifest('immich', { accessGroups: ['memories'] });
  const id = identity(['family']);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, false);
});

test('matrix: active in an UNBOUND group → DENY (group not in accessGroups)', () => {
  // User is in `access-immich` (the OLD prefix-derived name) but the manifest
  // binds `memories`. The prefix-based gate would ALLOW here; the new gate must
  // DENY — this case is the one that flips the matrix.
  const m = manifest('immich', { accessGroups: ['memories'] });
  const id = identity(['access-immich']);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, false);
});

test('matrix: active in a bound group → ALLOW', () => {
  const m = manifest('immich', { accessGroups: ['memories'] });
  const id = identity(['memories']);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, true);
});

test('matrix: skipAccessCheck + active → ALLOW (membership bypassed)', () => {
  const m = manifest('immich', { accessGroups: [], skipAccessCheck: true });
  const id = identity(['anything']);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, true);
});

test('matrix: skipAccessCheck + INACTIVE → DENY (state never bypassed)', () => {
  const m = manifest('immich', { accessGroups: [], skipAccessCheck: true });
  const id = identity(['anything'], 'inactive');
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, false);
});

test('matrix: multi-group OR — access:[a,b], user has only b → ALLOW', () => {
  const m = manifest('immich', { accessGroups: ['admin-memories', 'memories'] });
  const id = identity(['memories']);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, true);
});

test('matrix: groups:[] → DENY', () => {
  const m = manifest('immich', { accessGroups: ['memories'] });
  const id = identity([]);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, false);
});

test('matrix: manifest with empty accessGroups, no skip → DENY (no implicit access)', () => {
  const m = manifest('immich', { accessGroups: [] });
  const id = identity(['memories']);
  assert.equal(enforceAccessGate(id, 'immich', m).allowed, false);
});

// access-observe regression: a flat (prefixed) name is still a valid binding.
// The live dag binds `access-observe`; a member must still get in through the
// rerouted gate so the deploy does not regress.
test('regression: access-observe is a valid flat binding → ALLOW', () => {
  const m = manifest('observe', { accessGroups: ['access-observe'] });
  const id = identity(['access-observe']);
  assert.equal(enforceAccessGate(id, 'observe', m).allowed, true);
});

// ─── property: implementation matches the oracle over randomized inputs ──────

test('property: enforceAccessGate matches the fail-closed oracle for ALL inputs', () => {
  const groupName = fc.constantFrom(
    'memories', 'admin-memories', 'family', 'access-immich', 'access-observe',
    'friends', 'kids', 'admin', 'observe',
  );
  fc.assert(
    fc.property(
      // identity groups, or null for a failed lookup
      fc.option(fc.array(groupName), { nil: null }),
      fc.constantFrom('active', 'inactive', undefined),
      fc.array(groupName),       // manifest accessGroups
      fc.boolean(),              // skipAccessCheck
      fc.string({ minLength: 1, maxLength: 8 }), // clientId (must not leak in)
      (groups, state, accessGroups, skipAccessCheck, clientId) => {
        const m = manifest(clientId, { accessGroups, skipAccessCheck });
        const id = identity(groups, state);
        const got = enforceAccessGate(id, clientId, m).allowed;
        const want = shouldAllow(id, m);
        assert.equal(got, want);
      },
    ),
    { numRuns: 2000 },
  );
});

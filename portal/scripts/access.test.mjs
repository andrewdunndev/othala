// Tests for src/lib/access.ts — Effective Access computation.
//
// Run with: tsx --test scripts/access.test.mjs
//
// Imports the canonical implementation directly. There is no longer a second
// implementation to reconcile against: computeEffectiveAccess and the
// consent/token path both call the SINGLE resolver `lookupRole` in
// src/lib/claims.ts. (The Go `consent/` service whose `manifest.go LookupRole`
// this file once cross-checked was retired in ac469fa.) What these tests pin is
// therefore the resolver's contract, which the admin UI and the issued token
// share by construction.
//
// Coverage focus:
//   - normalizeGroupOrder: identity groups first in OTHALA_IDENTITY_GROUPS
//     order, then ALL remaining groups alphabetically. The `access-` prefix
//     partition is RETIRED — a group's position is a function of its name
//     alone.
//   - computeEffectiveAccess:
//     * access gate (in none of manifest.accessGroups = no row)
//     * override wins over group-map
//     * group-map resolves the HIGHEST-RANKED matched role, where rank is the
//       role's index in manifest.roles (0 = highest). It does NOT take the
//       first match in stored group order, and stored order cannot change the
//       answer — see `lookupRole` in src/lib/claims.ts for why that mechanism
//       was retired: an admin holds both `<svc>-access` and `<svc>-admin`,
//       alphabetical normalization stores the lower-ranked one first, and
//       metadata_admin.groups written through the Kratos admin API carries no
//       ordering guarantee at all.
//     * no-roles manifest yields default + 'no-roles' source
//     * access granted but no group match = first declared role
//   - multi-manifest: rows only for accessible clients
//
// NON-VACUITY: every fixture in the rank-resolution block is built so that
// first-match-wins and highest-rank-wins give DIFFERENT answers. A fixture
// whose winning role happens to sit at rank 0 cannot distinguish the current
// resolver from the retired one and is worth nothing here; reverting
// claims.ts `lookupRole` to a first-match walk must turn that block RED.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeGroupOrder, computeEffectiveAccess } from '../src/lib/access.ts';

// Helper: build a manifest fixture. computeEffectiveAccess gates on
// accessGroups (the load-bearing binding), defaulting to the
// conventional [access-<clientId>] so the existing fixtures (which assign
// `access-<slug>` identity groups) keep exercising the access gate.
function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: opts.clientName ?? clientId,
    redirectUris: [],
    postLogoutRedirectUris: [],
    scopes: [],
    audience: [],
    grantTypes: [],
    skipConsent: false,
    backchannelLogoutUri: '',
    accessGroup: opts.accessGroup ?? `access-${clientId}`,
    accessGroups: opts.accessGroups ?? [`access-${clientId}`],
    skipAccessCheck: opts.skipAccessCheck ?? false,
    roles: opts.roles ?? [],
    groupRoleMap: opts.groupRoleMap ?? {},
  };
}

// Helper: build identity fixture.
function identity(groups, roles = {}) {
  return {
    id: 'test-id',
    traits: { username: 'tester', email: 'tester@example.org', displayName: 'Tester' },
    metadata_admin: { groups, roles },
  };
}

// ===== normalizeGroupOrder =====

test('normalizeGroupOrder: identity groups in canonical order', () => {
  assert.deepEqual(
    normalizeGroupOrder(['friends', 'admin', 'family', 'kids']),
    ['admin', 'family', 'friends', 'kids'],
  );
});

// The `access-` prefix no longer partitions group order.
// The split is identity-vs-everything (identity = OTHALA_IDENTITY_GROUPS, which
// in the test env is just ['admin', <default>]); identity groups come first in
// env order, then ALL remaining groups alphabetically — names like `access-*`,
// `family`, `elder` are sorted together, their position a function of the name
// alone, not a prefix.
test('normalizeGroupOrder: non-identity groups sort alphabetically after identity groups', () => {
  assert.deepEqual(
    normalizeGroupOrder(['access-tune', 'admin', 'access-keep', 'family']),
    ['admin', 'access-keep', 'access-tune', 'family'],
  );
});

test('normalizeGroupOrder: all non-identity groups (access-* and bare) interleave alphabetically', () => {
  assert.deepEqual(
    normalizeGroupOrder(['service', 'admin', 'access-foo', 'elder']),
    ['admin', 'access-foo', 'elder', 'service'],
  );
});

test('normalizeGroupOrder: idempotent', () => {
  const once = normalizeGroupOrder(['kids', 'family', 'access-memory']);
  const twice = normalizeGroupOrder(once);
  assert.deepEqual(twice, once);
});

test('normalizeGroupOrder: empty input → empty output', () => {
  assert.deepEqual(normalizeGroupOrder([]), []);
});

// ===== computeEffectiveAccess: access gate =====

test('access: no access-<slug> group → no row for that client', () => {
  const m = [manifest('keep', { roles: [{ name: 'user', description: '' }] })];
  const id = identity(['family']); // no access-keep
  assert.deepEqual(computeEffectiveAccess(id, m), []);
});

test('access: access-<slug> present → row appears', () => {
  const m = [manifest('keep', { roles: [{ name: 'user', description: '' }] })];
  const id = identity(['family', 'access-keep']);
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].clientId, 'keep');
});

// ===== override path =====

test('override: metadata_admin.roles[clientId] wins over group-map', () => {
  const m = [manifest('keep', {
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { family: 'user' },
  })];
  const id = identity(['family', 'access-keep'], { keep: 'admin' });
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'admin');
  assert.equal(rows[0].source.kind, 'override');
});

test('override: empty roles object is ignored (group-map applies)', () => {
  const m = [manifest('keep', {
    roles: [{ name: 'user', description: '' }],
    groupRoleMap: { family: 'user' },
  })];
  const id = identity(['family', 'access-keep'], {});
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].source.kind, 'group');
});

test('override: non-string role value is dropped', () => {
  const m = [manifest('keep', {
    roles: [{ name: 'user', description: '' }],
    groupRoleMap: { family: 'user' },
  })];
  const id = identity(['family', 'access-keep'], { keep: 123 });
  const rows = computeEffectiveAccess(id, m);
  // Non-string roles ignored; group map kicks in.
  assert.equal(rows[0].source.kind, 'group');
});

// ===== group-map resolves by RANK, not by stored order =====
//
// Every fixture below is DISCRIMINATING: the first match in stored group order
// and the highest-ranked matched role are different roles, and the assertion
// names the highest-ranked one. Reverting `lookupRole` (src/lib/claims.ts) to a
// first-match walk must make each of these fail. Fixtures whose winner is also
// the first stored match — which is what these three replaced — stay green
// under both resolvers and prove nothing.

test('group-map: highest-ranked role wins over the first stored match (admin holds both groups)', () => {
  // The live shape: entry comes from `keep-access` for EVERYONE, admins
  // included, and an admin is additionally assigned `keep-admin` by hand. Both
  // groups map to a role, so two roles are in play for one identity. Mirrors
  // e2e/manifests/grafana.yaml, where group_role_map binds both
  // `grafana-access` and `grafana-admin` but only `grafana-access` grants entry.
  const m = [manifest('keep', {
    accessGroups: ['keep-access'],
    // Descending privilege — the declaration-order convention lookupRole reads.
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { 'keep-access': 'user', 'keep-admin': 'admin' },
  })];
  // normalizeGroupOrder sorts non-identity groups alphabetically, which stores
  // the LOWER-ranked group first. Pinned, because that ordering is precisely
  // what makes this fixture able to fail.
  const stored = normalizeGroupOrder(['keep-admin', 'keep-access']);
  assert.deepEqual(stored, ['keep-access', 'keep-admin']);

  const rows = computeEffectiveAccess(identity(stored), m);
  // First stored match: keep-access -> 'user' (rank 1). Rank resolution
  // takes 'admin' (rank 0).
  assert.equal(rows[0].role, 'admin');
  assert.equal(rows[0].source.kind, 'group');
  assert.equal(rows[0].source.group, 'keep-admin');
});

test('group-map: highest rank wins when a lower-ranked group sorts first (no override, no admin)', () => {
  const m = [manifest('keep', {
    accessGroups: ['keep-access'],
    roles: [
      { name: 'editor', description: '' },
      { name: 'viewer', description: '' },
      { name: 'guest', description: '' },
    ],
    groupRoleMap: { 'keep-access': 'guest', family: 'viewer', 'keep-editors': 'editor' },
  })];
  // None of these are identity groups, so all three sort alphabetically: the
  // winner is the LAST group stored, and two lower-ranked matches precede it.
  const stored = normalizeGroupOrder(['keep-editors', 'family', 'keep-access']);
  assert.deepEqual(stored, ['family', 'keep-access', 'keep-editors']);

  const rows = computeEffectiveAccess(identity(stored), m);
  // First stored match: family -> 'viewer' (rank 1). Rank resolution takes
  // 'editor' (rank 0) from the last group in the list.
  assert.equal(rows[0].role, 'editor');
  assert.equal(rows[0].source.kind, 'group');
  assert.equal(rows[0].source.group, 'keep-editors');
});

test('group-map: role is a function of the group SET — every permutation agrees', () => {
  // metadata_admin.groups is an admin-API-written array with no ordering
  // promise for identities touched outside the admin form, so order-independence
  // is a requirement, not belt-and-braces. `admin` is an identity group and is
  // therefore stored FIRST unconditionally — here it maps to the LOWER-ranked
  // role, so identity-group primacy must not win either.
  const m = [manifest('keep', {
    accessGroups: ['keep-access'],
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { 'keep-access': 'user', admin: 'user', 'keep-admin': 'admin' },
  })];
  const permutations = [
    ['keep-access', 'keep-admin'],
    ['keep-admin', 'keep-access'],
    normalizeGroupOrder(['keep-admin', 'keep-access', 'admin']),
    ['keep-admin', 'admin', 'keep-access'],
    ['admin', 'keep-access', 'keep-admin'],
  ];
  // The canonical stored form leads with the identity group, whose mapping is
  // rank 1 — the hostile case for a first-match walk.
  assert.deepEqual(permutations[2], ['admin', 'keep-access', 'keep-admin']);

  for (const groups of permutations) {
    const label = `permutation [${groups.join(', ')}]`;
    const rows = computeEffectiveAccess(identity(groups), m);
    assert.equal(rows.length, 1, label);
    assert.equal(rows[0].role, 'admin', label);
    assert.equal(rows[0].source.kind, 'group', label);
    assert.equal(rows[0].source.group, 'keep-admin', label);
  }
});

// ===== no-roles manifest =====

test('no-roles: manifest with empty roles → default role + no-roles source', () => {
  const m = [manifest('keep', { roles: [], groupRoleMap: {} })];
  const id = identity(['family', 'access-keep']);
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'default');
  assert.equal(rows[0].source.kind, 'no-roles');
});

// ===== access granted, no group match =====

test('access granted but no group match → first declared role', () => {
  const m = [manifest('keep', {
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { admin: 'admin' },
  })];
  const id = identity(['family', 'access-keep']); // not in admin group
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'admin'); // first declared role
  assert.equal(rows[0].source.kind, 'no-roles');
});

// ===== multi-manifest =====

test('multi-manifest: rows only for accessible clients, preserves order', () => {
  const m = [
    manifest('keep', { roles: [{ name: 'user', description: '' }], groupRoleMap: { family: 'user' } }),
    manifest('observe', { roles: [{ name: 'viewer', description: '' }], groupRoleMap: { family: 'viewer' } }),
    manifest('forge', { roles: [{ name: 'admin', description: '' }], groupRoleMap: { admin: 'admin' } }),
  ];
  // Has keep + observe but not forge access.
  const id = identity(['family', 'access-keep', 'access-observe']);
  const rows = computeEffectiveAccess(id, m);
  assert.deepEqual(rows.map((r) => r.clientId), ['keep', 'observe']);
});

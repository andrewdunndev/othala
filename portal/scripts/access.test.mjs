// Tests for src/lib/access.ts — Effective Access computation.
//
// Run with: tsx --test scripts/access.test.mjs
//
// Imports the canonical implementation directly. This is the C4
// reconciliation surface: both this module and `consent/manifest.go
// LookupRole` must produce identical role assignments for the same
// input.
//
// Coverage focus:
//   - normalizeGroupOrder: identity groups in canonical order,
//     access-* in alphabetical, unknowns between
//   - computeEffectiveAccess:
//     * access gate (no access-<slug> = no row)
//     * override wins over group-map
//     * group-map walks STORED order, not lexical
//     * no-roles manifest yields default + 'no-roles' source
//     * access granted but no group match = first declared role
//   - multi-manifest: rows only for accessible clients

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeGroupOrder, computeEffectiveAccess } from '../src/lib/access.ts';

// Helper: build a manifest fixture.
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

test('normalizeGroupOrder: access-* alphabetised after identity groups', () => {
  assert.deepEqual(
    normalizeGroupOrder(['access-tune', 'admin', 'access-keep', 'family']),
    ['admin', 'family', 'access-keep', 'access-tune'],
  );
});

test('normalizeGroupOrder: unknown groups go in alphabetical, between identity and access', () => {
  assert.deepEqual(
    normalizeGroupOrder(['service', 'admin', 'access-foo', 'elder']),
    ['admin', 'elder', 'service', 'access-foo'],
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

// ===== group-map walks stored order =====

test('group-map: stored order is precedence (admin before family)', () => {
  const m = [manifest('keep', {
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { admin: 'admin', family: 'user' },
  })];
  // Stored order: admin first.
  const id = identity(normalizeGroupOrder(['family', 'access-keep', 'admin']));
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'admin');
  assert.equal(rows[0].source.kind, 'group');
  assert.equal(rows[0].source.group, 'admin');
});

test('group-map: stored order picks first match (no override, no admin)', () => {
  const m = [manifest('keep', {
    roles: [{ name: 'user', description: '' }, { name: 'viewer', description: '' }],
    groupRoleMap: { family: 'user', friends: 'viewer' },
  })];
  const id = identity(normalizeGroupOrder(['friends', 'family', 'access-keep']));
  const rows = computeEffectiveAccess(id, m);
  // family precedes friends in stored canonical order
  assert.equal(rows[0].role, 'user');
  assert.equal(rows[0].source.group, 'family');
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

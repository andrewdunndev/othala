// Invariant: effective access is computed from bindings and roles, never from group naming.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { normalizeGroupOrder, computeEffectiveAccess } from '../src/lib/access.ts';

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

function identity(groups, roles = {}) {
  return {
    id: 'test-id',
    traits: { username: 'tester', email: 'tester@example.org', displayName: 'Tester' },
    metadata_admin: { groups, roles },
  };
}

test('normalizeGroupOrder: identity groups in canonical order', () => {
  assert.deepEqual(
    normalizeGroupOrder(['friends', 'admin', 'family', 'kids']),
    ['admin', 'family', 'friends', 'kids'],
  );
});

test('normalizeGroupOrder: non-identity groups sort alphabetically after identity groups', () => {
  assert.deepEqual(
    normalizeGroupOrder(['access-statuspage', 'admin', 'access-filedrop', 'family']),
    ['admin', 'access-filedrop', 'access-statuspage', 'family'],
  );
});

test('normalizeGroupOrder: all non-identity groups (access-* and bare) interleave alphabetically', () => {
  assert.deepEqual(
    normalizeGroupOrder(['service', 'admin', 'access-foo', 'elder']),
    ['admin', 'access-foo', 'elder', 'service'],
  );
});

test('normalizeGroupOrder: idempotent', () => {
  const once = normalizeGroupOrder(['kids', 'family', 'access-promptdesk']);
  const twice = normalizeGroupOrder(once);
  assert.deepEqual(twice, once);
});

test('normalizeGroupOrder: empty input → empty output', () => {
  assert.deepEqual(normalizeGroupOrder([]), []);
});

test('access: no access-<slug> group → no row for that client', () => {
  const m = [manifest('filedrop', { roles: [{ name: 'user', description: '' }] })];
  const id = identity(['family']); // no access-filedrop
  assert.deepEqual(computeEffectiveAccess(id, m), []);
});

test('access: access-<slug> present → row appears', () => {
  const m = [manifest('filedrop', { roles: [{ name: 'user', description: '' }] })];
  const id = identity(['family', 'access-filedrop']);
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].clientId, 'filedrop');
});

test('override: metadata_admin.roles[clientId] wins over group-map', () => {
  const m = [manifest('filedrop', {
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { family: 'user' },
  })];
  const id = identity(['family', 'access-filedrop'], { filedrop: 'admin' });
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'admin');
  assert.equal(rows[0].source.kind, 'override');
});

test('override: empty roles object is ignored (group-map applies)', () => {
  const m = [manifest('filedrop', {
    roles: [{ name: 'user', description: '' }],
    groupRoleMap: { family: 'user' },
  })];
  const id = identity(['family', 'access-filedrop'], {});
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].source.kind, 'group');
});

test('override: non-string role value is dropped', () => {
  const m = [manifest('filedrop', {
    roles: [{ name: 'user', description: '' }],
    groupRoleMap: { family: 'user' },
  })];
  const id = identity(['family', 'access-filedrop'], { filedrop: 123 });
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].source.kind, 'group');
});

test('group-map: highest-ranked role wins over the first stored match (admin holds both groups)', () => {
  const m = [manifest('filedrop', {
    accessGroups: ['filedrop-access'],
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { 'filedrop-access': 'user', 'filedrop-admin': 'admin' },
  })];
  const stored = normalizeGroupOrder(['filedrop-admin', 'filedrop-access']);
  assert.deepEqual(stored, ['filedrop-access', 'filedrop-admin']);

  const rows = computeEffectiveAccess(identity(stored), m);
  assert.equal(rows[0].role, 'admin');
  assert.equal(rows[0].source.kind, 'group');
  assert.equal(rows[0].source.group, 'filedrop-admin');
});

test('group-map: highest rank wins when a lower-ranked group sorts first (no override, no admin)', () => {
  const m = [manifest('filedrop', {
    accessGroups: ['filedrop-access'],
    roles: [
      { name: 'editor', description: '' },
      { name: 'viewer', description: '' },
      { name: 'guest', description: '' },
    ],
    groupRoleMap: { 'filedrop-access': 'guest', family: 'viewer', 'filedrop-editors': 'editor' },
  })];
  const stored = normalizeGroupOrder(['filedrop-editors', 'family', 'filedrop-access']);
  assert.deepEqual(stored, ['family', 'filedrop-access', 'filedrop-editors']);

  const rows = computeEffectiveAccess(identity(stored), m);
  assert.equal(rows[0].role, 'editor');
  assert.equal(rows[0].source.kind, 'group');
  assert.equal(rows[0].source.group, 'filedrop-editors');
});

test('group-map: role is a function of the group SET — every permutation agrees', () => {
  const m = [manifest('filedrop', {
    accessGroups: ['filedrop-access'],
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { 'filedrop-access': 'user', admin: 'user', 'filedrop-admin': 'admin' },
  })];
  const permutations = [
    ['filedrop-access', 'filedrop-admin'],
    ['filedrop-admin', 'filedrop-access'],
    normalizeGroupOrder(['filedrop-admin', 'filedrop-access', 'admin']),
    ['filedrop-admin', 'admin', 'filedrop-access'],
    ['admin', 'filedrop-access', 'filedrop-admin'],
  ];
  assert.deepEqual(permutations[2], ['admin', 'filedrop-access', 'filedrop-admin']);

  for (const groups of permutations) {
    const label = `permutation [${groups.join(', ')}]`;
    const rows = computeEffectiveAccess(identity(groups), m);
    assert.equal(rows.length, 1, label);
    assert.equal(rows[0].role, 'admin', label);
    assert.equal(rows[0].source.kind, 'group', label);
    assert.equal(rows[0].source.group, 'filedrop-admin', label);
  }
});

test('no-roles: manifest with empty roles → default role + no-roles source', () => {
  const m = [manifest('filedrop', { roles: [], groupRoleMap: {} })];
  const id = identity(['family', 'access-filedrop']);
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'default');
  assert.equal(rows[0].source.kind, 'no-roles');
});

test('access granted but no group match → first declared role', () => {
  const m = [manifest('filedrop', {
    roles: [{ name: 'admin', description: '' }, { name: 'user', description: '' }],
    groupRoleMap: { admin: 'admin' },
  })];
  const id = identity(['family', 'access-filedrop']); // not in admin group
  const rows = computeEffectiveAccess(id, m);
  assert.equal(rows[0].role, 'admin'); // first declared role
  assert.equal(rows[0].source.kind, 'no-roles');
});

test('multi-manifest: rows only for accessible clients, preserves order', () => {
  const m = [
    manifest('filedrop', { roles: [{ name: 'user', description: '' }], groupRoleMap: { family: 'user' } }),
    manifest('proxywatch', { roles: [{ name: 'viewer', description: '' }], groupRoleMap: { family: 'viewer' } }),
    manifest('audiobookshelf', { roles: [{ name: 'admin', description: '' }], groupRoleMap: { admin: 'admin' } }),
  ];
  const id = identity(['family', 'access-filedrop', 'access-proxywatch']);
  const rows = computeEffectiveAccess(id, m);
  assert.deepEqual(rows.map((r) => r.clientId), ['filedrop', 'proxywatch']);
});

// Tests for src/lib/claims.ts — id_token claim mapping (CU1 item 3).
//
// Run with: npx vitest run scripts/claims.test.mjs
//
// Mirrors BuildIDTokenClaims in consent/claims.go against the family
// identity schema (traits: username/email/displayName).

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  buildIDTokenClaims,
  deepMergeClaims,
  composeIDTokenClaims,
  lookupRole,
} from '../src/lib/claims.ts';

function base(overrides = {}) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'ada', email: 'a@othala.test', displayName: 'Ada Lovelace' },
    metadata_admin: { groups: ['access-grafana'] },
    verifiable_addresses: [{ value: 'a@othala.test', verified: true, via: 'email', status: 'completed' }],
    ...overrides,
  };
}

test('email + email_verified from traits.email and verifiable_addresses', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.email_verified, true);
});

test('email_verified omitted when no verifiable_addresses', () => {
  const c = buildIDTokenClaims(base({ verifiable_addresses: [] }));
  assert.equal(c.email, 'a@othala.test');
  assert.equal('email_verified' in c, false);
});

test('email_verified falls back to first address when no exact match', () => {
  const c = buildIDTokenClaims(base({
    verifiable_addresses: [{ value: 'other@othala.test', verified: false, via: 'email', status: 'completed' }],
  }));
  assert.equal(c.email_verified, false);
});

test('preferred_username = traits.username', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.preferred_username, 'ada');
});

test('name = traits.displayName when present', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.name, 'Ada Lovelace');
});

test('name falls back to username when no displayName', () => {
  const c = buildIDTokenClaims(base({ traits: { username: 'ada', email: 'a@othala.test' } }));
  assert.equal(c.name, 'ada');
});

test('groups always included from metadata_admin', () => {
  const c = buildIDTokenClaims(base());
  assert.deepEqual(c.groups, ['access-grafana']);
});

test('groups omitted when metadata_admin has none', () => {
  const c = buildIDTokenClaims(base({ metadata_admin: {} }));
  assert.equal('groups' in c, false);
});

test('null identity yields empty claims', () => {
  assert.deepEqual(buildIDTokenClaims(null), {});
});

// ── deepMergeClaims (H1) ──────────────────────────────────────────────────

test('deepMergeClaims: array conflict becomes union, dst order preserved', () => {
  const dst = { groups: ['a', 'b'] };
  const src = { groups: ['b', 'c'] };
  deepMergeClaims(dst, src);
  assert.deepEqual(dst.groups, ['a', 'b', 'c']);
});

test('deepMergeClaims: scalar conflict still src-wins', () => {
  const dst = { x: 1 };
  const src = { x: 2 };
  deepMergeClaims(dst, src);
  assert.equal(dst.x, 2);
});

// ── Prototype-pollution guard ─────────────────────────────────────────────────

test('deepMergeClaims: __proto__ key is silently dropped (no pollution)', () => {
  // JSON.parse produces a parsed object where __proto__ is a plain string key.
  // Without the guard, dst["__proto__"] = ... writes onto Object.prototype.
  const src = JSON.parse('{"__proto__":{"polluted":true},"safe":"value"}');
  const dst = { existing: 1 };
  deepMergeClaims(dst, src);
  // __proto__ key must not have been written
  assert.equal(Object.prototype.polluted, undefined, '__proto__ must not pollute Object.prototype');
  // Other keys are still merged normally
  assert.equal(dst.safe, 'value');
  assert.equal(dst.existing, 1);
});

test('deepMergeClaims: constructor key is silently dropped (no pollution)', () => {
  // A crafted src with a "constructor" key: without the guard, recursive merge
  // into dst.constructor (a function) would throw or corrupt prototype state.
  const src = { constructor: { prototype: { polluted: 'constructor-path' } }, safe: 'ok' };
  const dst = { existing: 2 };
  deepMergeClaims(dst, src);
  // constructor key must not have been written onto dst
  assert.equal(Object.prototype.polluted, undefined, 'constructor path must not pollute prototype');
  // dst.constructor must still be the normal Object constructor
  assert.equal(dst.constructor, Object);
  // Other keys are still merged normally
  assert.equal(dst.safe, 'ok');
});

test('deepMergeClaims: prototype key is silently dropped (no pollution)', () => {
  const src = { prototype: { polluted: 'prototype-path' }, safe: 'also-ok' };
  const dst = {};
  deepMergeClaims(dst, src);
  // prototype key must not appear on dst
  assert.equal(Object.getOwnPropertyDescriptor(dst, 'prototype'), undefined);
  assert.equal(dst.safe, 'also-ok');
});

// ── Minimal manifest helper for composeIDTokenClaims tests ────────────────

/**
 * Build a minimal ClientManifest sufficient for composeIDTokenClaims:
 * emit_groups_claim defaults true (null = absent → default true),
 * a single role "member" with the given claim_emit, and groupRoleMap
 * mapping the provided group to that role.
 */
function manifest({ group, roleClaimEmit, emitGroupsClaim = null } = {}) {
  return {
    clientId: 'filedrop',
    presentationOnly: false,
    clientName: 'Filedrop',
    redirectUris: ['https://filedrop.othala.test/'],
    postLogoutRedirectUris: [],
    scopes: ['openid', 'email', 'profile', 'groups'],
    scope: 'openid email profile groups',
    audience: ['https://filedrop.othala.test'],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroups: [group ?? 'filedrop'],
    roles: [
      {
        name: 'member',
        description: 'Filedrop member',
        claimEmit: roleClaimEmit ?? { groups: ['filedrop-user'] },
      },
    ],
    groupRoleMap: { [group ?? 'filedrop']: 'member' },
    emitGroupsClaim,
    skipAccessCheck: false,
    sourcePath: 'filedrop.yaml',
  };
}

/** Identity with given groups in metadata_admin. */
function identityWithGroups(groups) {
  return base({ metadata_admin: { groups } });
}

// ── composeIDTokenClaims H1: real memberships survive role claim_emit ─────

test('composeIDTokenClaims H1: filedrop member only — groups is union of real + role', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest({ group: 'filedrop', roleClaimEmit: { groups: ['filedrop-user'] } });
  const c = composeIDTokenClaims(id, m);
  assert.ok(Array.isArray(c.groups), 'groups is an array');
  // Real membership preserved; role claim additive
  assert.ok(c.groups.includes('filedrop'), 'filedrop preserved');
  assert.ok(c.groups.includes('filedrop-user'), 'filedrop-user added');
});

test('composeIDTokenClaims H1: filedrop-admin only — admin membership preserved', () => {
  const id = identityWithGroups(['filedrop-admin']);
  const m = manifest({ group: 'filedrop-admin', roleClaimEmit: { groups: ['filedrop-user'] } });
  const c = composeIDTokenClaims(id, m);
  assert.ok(c.groups.includes('filedrop-admin'), 'filedrop-admin preserved');
  assert.ok(c.groups.includes('filedrop-user'), 'filedrop-user added');
});

test('composeIDTokenClaims H1: filedrop+filedrop-admin — both preserved, no duplicates', () => {
  // groupRoleMap: filedrop → member, filedrop-admin → member (same role, first match wins)
  const id = identityWithGroups(['filedrop', 'filedrop-admin']);
  const m = {
    ...manifest({ group: 'filedrop', roleClaimEmit: { groups: ['filedrop-user'] } }),
    groupRoleMap: { filedrop: 'member', 'filedrop-admin': 'member' },
    accessGroups: ['filedrop', 'filedrop-admin'],
  };
  const c = composeIDTokenClaims(id, m);
  assert.ok(c.groups.includes('filedrop'), 'filedrop preserved');
  assert.ok(c.groups.includes('filedrop-admin'), 'filedrop-admin preserved');
  assert.ok(c.groups.includes('filedrop-user'), 'filedrop-user additive');
  // No duplicates
  const groups = c.groups;
  assert.equal(groups.length, new Set(groups).size, 'no duplicates');
});

// ── composeIDTokenClaims H2: scope-gate ───────────────────────────────────

test('composeIDTokenClaims H2: requestedScope [openid] — no email/name/groups', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid']);
  assert.equal('email' in c, false, 'email absent');
  assert.equal('email_verified' in c, false, 'email_verified absent');
  assert.equal('name' in c, false, 'name absent');
  assert.equal('preferred_username' in c, false, 'preferred_username absent');
  assert.equal('groups' in c, false, 'groups absent');
});

test('composeIDTokenClaims H2: requestedScope [openid, email] — email present, name/groups absent', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid', 'email']);
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.email_verified, true);
  assert.equal('name' in c, false, 'name absent');
  assert.equal('preferred_username' in c, false, 'preferred_username absent');
  assert.equal('groups' in c, false, 'groups absent');
});

test('composeIDTokenClaims H2: requestedScope [openid, email, profile, groups] — all claims present', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid', 'email', 'profile', 'groups']);
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.email_verified, true);
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.preferred_username, 'ada');
  assert.ok(Array.isArray(c.groups), 'groups is an array');
});

// ── composeIDTokenClaims back-compat: omitting requestedScope emits all ───

test('composeIDTokenClaims back-compat: no requestedScope → all claims emitted', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m);
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.preferred_username, 'ada');
  assert.ok(Array.isArray(c.groups), 'groups is an array');
});

// ── issue #7: lookupRole resolves by RANK, not stored group order ────────
//
// Issue #7 claimed lookupRole takes the FIRST match in metadata_admin.groups
// stored order, so an identity holding both <svc>-access and <svc>-admin
// could resolve 'user' whenever access is stored first (which
// normalizeGroupOrder's alphabetical sort always does — "access" < "admin").
// That is not what the code does: lookupRole walks EVERY stored group and
// keeps the LOWEST role index (highest rank) over the whole matched set (see
// its "WHY step 2 is no longer first-stored-match" doc comment), so the
// result is a pure function of the group SET, not its order. Both storage
// orders below must resolve the same higher-ranked 'admin' role.

const rankedManifest = {
  ...manifest({ group: 'filedrop-access' }),
  roles: [
    { name: 'admin', description: '', claimEmit: { groups: ['filedrop-admin-claim'] } },
    { name: 'user', description: '', claimEmit: { groups: ['filedrop-user-claim'] } },
  ],
  groupRoleMap: { 'filedrop-access': 'user', 'filedrop-admin': 'admin' },
};

test('lookupRole: access-then-admin storage order resolves the higher-ranked admin role', () => {
  const result = lookupRole(rankedManifest, { groups: ['filedrop-access', 'filedrop-admin'] });
  assert.equal(result?.roleName, 'admin');
});

test('lookupRole: admin-then-access storage order resolves the SAME higher-ranked admin role', () => {
  const result = lookupRole(rankedManifest, { groups: ['filedrop-admin', 'filedrop-access'] });
  assert.equal(result?.roleName, 'admin');
});

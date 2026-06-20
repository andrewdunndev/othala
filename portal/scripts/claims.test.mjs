// Tests for src/lib/claims.ts — id_token claim mapping (CU1 item 3).
//
// Run with: tsx --test scripts/claims.test.mjs
//
// Mirrors BuildIDTokenClaims in consent/claims.go against the family
// identity schema (traits: username/email/displayName).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIDTokenClaims, deepMergeClaims, composeIDTokenClaims } from '../src/lib/claims.ts';

function base(overrides = {}) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'ada', email: 'a@dunn.dev', displayName: 'Ada Lovelace' },
    metadata_admin: { groups: ['access-grafana'] },
    verifiable_addresses: [{ value: 'a@dunn.dev', verified: true, via: 'email', status: 'completed' }],
    ...overrides,
  };
}

test('email + email_verified from traits.email and verifiable_addresses', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.email, 'a@dunn.dev');
  assert.equal(c.email_verified, true);
});

test('email_verified omitted when no verifiable_addresses', () => {
  const c = buildIDTokenClaims(base({ verifiable_addresses: [] }));
  assert.equal(c.email, 'a@dunn.dev');
  assert.equal('email_verified' in c, false);
});

test('email_verified falls back to first address when no exact match', () => {
  const c = buildIDTokenClaims(base({
    verifiable_addresses: [{ value: 'other@dunn.dev', verified: false, via: 'email', status: 'completed' }],
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
  const c = buildIDTokenClaims(base({ traits: { username: 'ada', email: 'a@dunn.dev' } }));
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

// ── Minimal manifest helper for composeIDTokenClaims tests ────────────────

/**
 * Build a minimal ClientManifest sufficient for composeIDTokenClaims:
 * emit_groups_claim defaults true (null = absent → default true),
 * a single role "member" with the given claim_emit, and groupRoleMap
 * mapping the provided group to that role.
 */
function manifest({ group, roleClaimEmit, emitGroupsClaim = null } = {}) {
  return {
    clientId: 'larder',
    presentationOnly: false,
    clientName: 'Larder',
    redirectUris: ['https://larder.dunn.dev/'],
    postLogoutRedirectUris: [],
    scopes: ['openid', 'email', 'profile', 'groups'],
    scope: 'openid email profile groups',
    audience: ['https://larder.dunn.dev'],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroups: [group ?? 'larder'],
    roles: [
      {
        name: 'member',
        description: 'Larder member',
        claimEmit: roleClaimEmit ?? { groups: ['larder-user'] },
      },
    ],
    groupRoleMap: { [group ?? 'larder']: 'member' },
    emitGroupsClaim,
    skipAccessCheck: false,
    sourcePath: 'larder.yaml',
  };
}

/** Identity with given groups in metadata_admin. */
function identityWithGroups(groups) {
  return base({ metadata_admin: { groups } });
}

// ── composeIDTokenClaims H1: real memberships survive role claim_emit ─────

test('composeIDTokenClaims H1: larder member only — groups is union of real + role', () => {
  const id = identityWithGroups(['larder']);
  const m = manifest({ group: 'larder', roleClaimEmit: { groups: ['larder-user'] } });
  const c = composeIDTokenClaims(id, m);
  assert.ok(Array.isArray(c.groups), 'groups is an array');
  // Real membership preserved; role claim additive
  assert.ok(c.groups.includes('larder'), 'larder preserved');
  assert.ok(c.groups.includes('larder-user'), 'larder-user added');
});

test('composeIDTokenClaims H1: larder-admin only — admin membership preserved', () => {
  const id = identityWithGroups(['larder-admin']);
  const m = manifest({ group: 'larder-admin', roleClaimEmit: { groups: ['larder-user'] } });
  const c = composeIDTokenClaims(id, m);
  assert.ok(c.groups.includes('larder-admin'), 'larder-admin preserved');
  assert.ok(c.groups.includes('larder-user'), 'larder-user added');
});

test('composeIDTokenClaims H1: larder+larder-admin — both preserved, no duplicates', () => {
  // groupRoleMap: larder → member, larder-admin → member (same role, first match wins)
  const id = identityWithGroups(['larder', 'larder-admin']);
  const m = {
    ...manifest({ group: 'larder', roleClaimEmit: { groups: ['larder-user'] } }),
    groupRoleMap: { larder: 'member', 'larder-admin': 'member' },
    accessGroups: ['larder', 'larder-admin'],
  };
  const c = composeIDTokenClaims(id, m);
  assert.ok(c.groups.includes('larder'), 'larder preserved');
  assert.ok(c.groups.includes('larder-admin'), 'larder-admin preserved');
  assert.ok(c.groups.includes('larder-user'), 'larder-user additive');
  // No duplicates
  const groups = c.groups;
  assert.equal(groups.length, new Set(groups).size, 'no duplicates');
});

// ── composeIDTokenClaims H2: scope-gate ───────────────────────────────────

test('composeIDTokenClaims H2: requestedScope [openid] — no email/name/groups', () => {
  const id = identityWithGroups(['larder']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid']);
  assert.equal('email' in c, false, 'email absent');
  assert.equal('email_verified' in c, false, 'email_verified absent');
  assert.equal('name' in c, false, 'name absent');
  assert.equal('preferred_username' in c, false, 'preferred_username absent');
  assert.equal('groups' in c, false, 'groups absent');
});

test('composeIDTokenClaims H2: requestedScope [openid, email] — email present, name/groups absent', () => {
  const id = identityWithGroups(['larder']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid', 'email']);
  assert.equal(c.email, 'a@dunn.dev');
  assert.equal(c.email_verified, true);
  assert.equal('name' in c, false, 'name absent');
  assert.equal('preferred_username' in c, false, 'preferred_username absent');
  assert.equal('groups' in c, false, 'groups absent');
});

test('composeIDTokenClaims H2: requestedScope [openid, email, profile, groups] — all claims present', () => {
  const id = identityWithGroups(['larder']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid', 'email', 'profile', 'groups']);
  assert.equal(c.email, 'a@dunn.dev');
  assert.equal(c.email_verified, true);
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.preferred_username, 'ada');
  assert.ok(Array.isArray(c.groups), 'groups is an array');
});

// ── composeIDTokenClaims back-compat: omitting requestedScope emits all ───

test('composeIDTokenClaims back-compat: no requestedScope → all claims emitted', () => {
  const id = identityWithGroups(['larder']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m);
  assert.equal(c.email, 'a@dunn.dev');
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.preferred_username, 'ada');
  assert.ok(Array.isArray(c.groups), 'groups is an array');
});

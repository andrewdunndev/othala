// Tests for src/lib/claims.ts — id_token claim mapping (CU1 item 3).
//
// Run with: tsx --test scripts/claims.test.mjs
//
// Mirrors BuildIDTokenClaims in consent/claims.go against the family
// identity schema (traits: username/email/displayName).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIDTokenClaims } from '../src/lib/claims.ts';

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

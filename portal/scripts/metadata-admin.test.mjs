// Tests for src/lib/metadata-admin.ts — the load-bearing validator
// (LB-8 / MEDIUM-3 in the security review).
//
// Run with: tsx --test scripts/metadata-admin.test.mjs
//
// Imports the canonical validator directly. The schema mirror lives
// alongside identity.schema.json's metadata_admin shape:
//   { groups?: string[]; roles?: Record<string, string> }
//   - groups: array of lowercase-dash-strings, 1..64 chars,
//             regex ^[a-z][a-z0-9.\-]*$, no duplicates
//   - roles: object with keys ^[a-z][a-z0-9]*$ → values matching
//            ^[a-z][a-z0-9_\-]*$ length 1..64
//   - no other top-level keys allowed

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateMetadataAdmin, MetadataAdminError } from '../src/lib/metadata-admin.ts';

// ===== Top-level shape =====

test('null/undefined → empty object', () => {
  assert.deepEqual(validateMetadataAdmin(null), {});
  assert.deepEqual(validateMetadataAdmin(undefined), {});
});

test('empty object → empty object', () => {
  assert.deepEqual(validateMetadataAdmin({}), {});
});

test('non-object input → error', () => {
  assert.throws(() => validateMetadataAdmin('a string'), MetadataAdminError);
  assert.throws(() => validateMetadataAdmin(42), MetadataAdminError);
  assert.throws(() => validateMetadataAdmin(true), MetadataAdminError);
});

test('array input → error', () => {
  assert.throws(() => validateMetadataAdmin(['groups']), MetadataAdminError);
});

test('unknown top-level field → error (catches typos like "grupos")', () => {
  // The whole point of LB-8: typos must fail loud.
  assert.throws(
    () => validateMetadataAdmin({ grupos: ['admin'] }),
    /unknown field "grupos"/,
  );
  assert.throws(
    () => validateMetadataAdmin({ groups: ['admin'], role: { keep: 'admin' } }),
    /unknown field "role"/,
  );
});

// ===== Groups =====

test('groups: well-formed array round-trips', () => {
  const result = validateMetadataAdmin({ groups: ['admin', 'family', 'access-keep'] });
  assert.deepEqual(result.groups, ['admin', 'family', 'access-keep']);
});

test('groups: non-array → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: 'admin' }),
    /must be an array/,
  );
});

test('groups: non-string element → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['admin', 42] }),
    /must be a string/,
  );
});

test('groups: empty string → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: [''] }),
    /length must be 1\.\.64/,
  );
});

test('groups: too-long string → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['a' + 'b'.repeat(64)] }),
    /length must be 1\.\.64/,
  );
});

test('groups: regex violation → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['Admin'] }), // uppercase
    /must match/,
  );
  assert.throws(
    () => validateMetadataAdmin({ groups: ['0invalid'] }), // starts with digit
    /must match/,
  );
  assert.throws(
    () => validateMetadataAdmin({ groups: ['has space'] }), // space
    /must match/,
  );
});

test('groups: duplicate → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['admin', 'family', 'admin'] }),
    /duplicate entry "admin"/,
  );
});

test('groups: allows dots and hyphens in middle', () => {
  const result = validateMetadataAdmin({ groups: ['family.beta', 'access-keep-v2'] });
  assert.deepEqual(result.groups, ['family.beta', 'access-keep-v2']);
});

test('groups: empty array → empty result', () => {
  const result = validateMetadataAdmin({ groups: [] });
  assert.deepEqual(result.groups, []);
});

// ===== Roles =====

test('roles: well-formed object round-trips', () => {
  const result = validateMetadataAdmin({ roles: { keep: 'admin', observe: 'viewer' } });
  assert.deepEqual(result.roles, { keep: 'admin', observe: 'viewer' });
});

test('roles: non-object → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: ['admin'] }),
    /must be an object/,
  );
  assert.throws(
    () => validateMetadataAdmin({ roles: 'admin' }),
    /must be an object/,
  );
});

test('roles: invalid client_id key → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { 'Keep-V2': 'admin' } }), // hyphen + capital
    /client_id "Keep-V2"/,
  );
  assert.throws(
    () => validateMetadataAdmin({ roles: { '0bad': 'admin' } }), // starts with digit
    /client_id "0bad"/,
  );
});

test('roles: non-string role value → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { keep: 42 } }),
    /must be a string/,
  );
});

test('roles: empty role value → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { keep: '' } }),
    /length must be 1\.\.64/,
  );
});

test('roles: too-long role value → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { keep: 'a'.repeat(65) } }),
    /length must be 1\.\.64/,
  );
});

test('roles: role value regex violation → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { keep: 'Admin' } }), // uppercase
    /role name "Admin"/,
  );
  assert.throws(
    () => validateMetadataAdmin({ roles: { keep: 'has space' } }),
    /role name "has space"/,
  );
});

test('roles: allows underscores and hyphens', () => {
  const result = validateMetadataAdmin({ roles: { keep: 'org_admin', observe: 'read-only' } });
  assert.deepEqual(result.roles, { keep: 'org_admin', observe: 'read-only' });
});

test('roles: empty object → empty result', () => {
  const result = validateMetadataAdmin({ roles: {} });
  assert.deepEqual(result.roles, {});
});

// ===== Combined =====

test('combined: groups + roles', () => {
  const result = validateMetadataAdmin({
    groups: ['admin', 'family', 'access-keep'],
    roles: { keep: 'admin' },
  });
  assert.deepEqual(result.groups, ['admin', 'family', 'access-keep']);
  assert.deepEqual(result.roles, { keep: 'admin' });
});

test('combined: groups only (no roles)', () => {
  const result = validateMetadataAdmin({ groups: ['family'] });
  assert.deepEqual(result.groups, ['family']);
  assert.equal(result.roles, undefined);
});

test('combined: roles only (no groups)', () => {
  const result = validateMetadataAdmin({ roles: { keep: 'admin' } });
  assert.equal(result.groups, undefined);
  assert.deepEqual(result.roles, { keep: 'admin' });
});

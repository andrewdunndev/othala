// Invariant: metadata_admin input is validated strictly; unknown fields and wrong types are errors.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { validateMetadataAdmin, MetadataAdminError } from '../src/lib/metadata-admin.ts';

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
  assert.throws(
    () => validateMetadataAdmin({ grupos: ['admin'] }),
    /unknown field "grupos"/,
  );
  assert.throws(
    () => validateMetadataAdmin({ groups: ['admin'], role: { filedrop: 'admin' } }),
    /unknown field "role"/,
  );
});

test('groups: well-formed array round-trips', () => {
  const result = validateMetadataAdmin({ groups: ['admin', 'family', 'access-filedrop'] });
  assert.deepEqual(result.groups, ['admin', 'family', 'access-filedrop']);
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
    () => validateMetadataAdmin({ groups: ['has space'] }), // space
    /must match/,
  );
  assert.throws(
    () => validateMetadataAdmin({ groups: ['under_score'] }), // underscore
    /must match/,
  );
  assert.throws(
    () => validateMetadataAdmin({ groups: ['-leading'] }), // leading hyphen
    /must match/,
  );
});

test('groups: duplicate → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['admin', 'family', 'admin'] }),
    /duplicate entry "admin"/,
  );
});

test('groups: hyphens in the middle are allowed', () => {
  const result = validateMetadataAdmin({ groups: ['access-filedrop-v2'] });
  assert.deepEqual(result.groups, ['access-filedrop-v2']);
});

test('groups: a dot is rejected — the canonical form has no dot', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['family.beta'] }),
    /must match/,
  );
});

test('groups: a leading digit is rejected — the canonical form starts with a letter', () => {
  assert.throws(
    () => validateMetadataAdmin({ groups: ['2fa-required'] }),
    /must match/,
  );
});

test('groups: empty array → empty result', () => {
  const result = validateMetadataAdmin({ groups: [] });
  assert.deepEqual(result.groups, []);
});

test('roles: well-formed object round-trips', () => {
  const result = validateMetadataAdmin({ roles: { filedrop: 'admin', proxywatch: 'viewer' } });
  assert.deepEqual(result.roles, { filedrop: 'admin', proxywatch: 'viewer' });
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
    () => validateMetadataAdmin({ roles: { 'Filedrop-V2': 'admin' } }), // hyphen + capital
    /client_id "Filedrop-V2"/,
  );
  assert.throws(
    () => validateMetadataAdmin({ roles: { '0bad': 'admin' } }), // starts with digit
    /client_id "0bad"/,
  );
});

test('roles: non-string role value → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { filedrop: 42 } }),
    /must be a string/,
  );
});

test('roles: empty role value → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { filedrop: '' } }),
    /length must be 1\.\.64/,
  );
});

test('roles: too-long role value → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { filedrop: 'a'.repeat(65) } }),
    /length must be 1\.\.64/,
  );
});

test('roles: role value regex violation → error', () => {
  assert.throws(
    () => validateMetadataAdmin({ roles: { filedrop: 'Admin' } }), // uppercase
    /role name "Admin"/,
  );
  assert.throws(
    () => validateMetadataAdmin({ roles: { filedrop: 'has space' } }),
    /role name "has space"/,
  );
});

test('roles: allows underscores and hyphens', () => {
  const result = validateMetadataAdmin({ roles: { filedrop: 'org_admin', proxywatch: 'read-only' } });
  assert.deepEqual(result.roles, { filedrop: 'org_admin', proxywatch: 'read-only' });
});

test('roles: empty object → empty result', () => {
  const result = validateMetadataAdmin({ roles: {} });
  assert.deepEqual(result.roles, {});
});

test('combined: groups + roles', () => {
  const result = validateMetadataAdmin({
    groups: ['admin', 'family', 'access-filedrop'],
    roles: { filedrop: 'admin' },
  });
  assert.deepEqual(result.groups, ['admin', 'family', 'access-filedrop']);
  assert.deepEqual(result.roles, { filedrop: 'admin' });
});

test('combined: groups only (no roles)', () => {
  const result = validateMetadataAdmin({ groups: ['family'] });
  assert.deepEqual(result.groups, ['family']);
  assert.equal(result.roles, undefined);
});

test('combined: roles only (no groups)', () => {
  const result = validateMetadataAdmin({ roles: { filedrop: 'admin' } });
  assert.equal(result.groups, undefined);
  assert.deepEqual(result.roles, { filedrop: 'admin' });
});

test('admin: true accepted (boolean strict)', () => {
  const result = validateMetadataAdmin({ admin: true });
  assert.equal(result.admin, true);
});

test('admin: false accepted (boolean strict)', () => {
  const result = validateMetadataAdmin({ admin: false });
  assert.equal(result.admin, false);
});

test('admin: string "true" rejected (non-boolean)', () => {
  assert.throws(
    () => validateMetadataAdmin({ admin: 'true' }),
    /must be a strict boolean/,
  );
});

test('admin: number 1 rejected (non-boolean)', () => {
  assert.throws(
    () => validateMetadataAdmin({ admin: 1 }),
    /must be a strict boolean/,
  );
});

test('admin: null rejected (non-boolean)', () => {
  assert.throws(
    () => validateMetadataAdmin({ admin: null }),
    /must be a strict boolean/,
  );
});

test('admin: object rejected (non-boolean)', () => {
  assert.throws(
    () => validateMetadataAdmin({ admin: {} }),
    /must be a strict boolean/,
  );
});

test('admin: absent → not present on output', () => {
  const result = validateMetadataAdmin({ groups: ['family'] });
  assert.equal(result.admin, undefined);
});

test('combined: groups + roles + admin:true', () => {
  const result = validateMetadataAdmin({
    groups: ['admin', 'family'],
    roles: { filedrop: 'admin' },
    admin: true,
  });
  assert.deepEqual(result.groups, ['admin', 'family']);
  assert.deepEqual(result.roles, { filedrop: 'admin' });
  assert.equal(result.admin, true);
});

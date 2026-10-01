// Invariant: an identity carrying the admin marker is never issued a recovery link.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { shouldRefuseRecovery } from '../src/lib/access.ts';
import { identity } from '../src/lib/test-builders.ts';

const withAdmin = (metadataAdmin) => identity({ metadataAdmin });

test('identity with metadata_admin.admin===true is refused', () => {
  assert.equal(shouldRefuseRecovery(withAdmin({ admin: true, groups: ['admin', 'family'] })), true);
});

test('identity with metadata_admin.admin===true is refused even without admin group', () => {
  assert.equal(shouldRefuseRecovery(withAdmin({ admin: true, groups: ['family'] })), true); // no 'admin' group
});

test('identity with metadata_admin.admin===false is allowed (marker present but false)', () => {
  assert.equal(shouldRefuseRecovery(withAdmin({ admin: false, groups: ['admin', 'family'] })), false);
});

test('non-admin identity (no admin marker) is allowed', () => {
  assert.equal(shouldRefuseRecovery(withAdmin({ groups: ['family', 'access-filedrop'] })), false);
});

test('identity with no metadata_admin is allowed (fail-safe for non-admin)', () => {
  assert.equal(shouldRefuseRecovery(identity()), false);
});

test('identity with metadata_admin.admin as string "true" is allowed (wrong type, fail-closed strict equality)', () => {
  assert.equal(shouldRefuseRecovery(withAdmin({ admin: 'true' })), false);
});

test('identity with metadata_admin.admin as number 1 is allowed (wrong type, fail-closed strict equality)', () => {
  assert.equal(shouldRefuseRecovery(withAdmin({ admin: 1 })), false);
});

test('null/undefined identity is allowed (no admin marker)', () => {
  assert.equal(shouldRefuseRecovery(null), false);
  assert.equal(shouldRefuseRecovery(undefined), false);
});

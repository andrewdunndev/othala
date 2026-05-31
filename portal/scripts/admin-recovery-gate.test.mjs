// Test for the HIGH-3 admin-to-admin recovery refusal gate.
//
// Run with: tsx --test scripts/admin-recovery-gate.test.mjs
//
// The gate logic lives in src/lib/access.ts (shouldRefuseRecovery)
// and is consumed by src/pages/admin/users/[id].astro action=
// issue-recovery. Importing the helper directly keeps this test
// aligned with the .astro consumer (a refactor that re-inlines the
// check breaks compile, not just this test).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shouldRefuseRecovery } from '../src/lib/access.ts';

test('admin identity is refused', () => {
  const identity = {
    id: 'a-1',
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('non-admin identity is allowed', () => {
  const identity = {
    id: 'b-1',
    metadata_admin: { groups: ['family', 'access-keep'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with no metadata_admin is allowed (non-admin by default)', () => {
  const identity = { id: 'c-1' };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with empty groups is allowed (non-admin)', () => {
  const identity = { id: 'd-1', metadata_admin: { groups: [] } };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('admin in a non-first position is still refused', () => {
  const identity = {
    id: 'e-1',
    metadata_admin: { groups: ['family', 'admin', 'access-keep'] },
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

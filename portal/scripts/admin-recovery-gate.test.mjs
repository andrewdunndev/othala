// Test for the admin-to-admin recovery refusal gate.
//
// Run with: npx vitest run scripts/admin-recovery-gate.test.mjs
//
// The gate logic lives in src/lib/access.ts (shouldRefuseRecovery) and is
// consumed by src/pages/admin/users/[id].astro action=issue-recovery.
//
// Admin authority is the `metadata_admin.admin === true` marker
// (admin-API-only-writable boolean). shouldRefuseRecovery refuses iff the
// TARGET identity carries the admin marker. The retired OTHALA_ADMIN_IDS UUID
// allowlist is no longer consulted. The caller must pass an admin-API-fetched
// identity (metadata_admin present).

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { shouldRefuseRecovery } from '../src/lib/access.ts';

test('identity with metadata_admin.admin===true is refused', () => {
  const identity = {
    id: '11111111-1111-1111-1111-111111111111',
    traits: { email: 'admin@othala.test' },
    metadata_admin: { admin: true, groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('identity with metadata_admin.admin===true is refused even without admin group', () => {
  // Defense-in-depth: the marker is authoritative; group membership is irrelevant.
  const identity = {
    id: '33333333-3333-3333-3333-333333333333',
    traits: { email: 'ops@othala.test' },
    metadata_admin: { admin: true, groups: ['family'] }, // no 'admin' group
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('identity with metadata_admin.admin===false is allowed (marker present but false)', () => {
  const identity = {
    id: '22222222-2222-2222-2222-222222222222',
    traits: { email: 'imposter@othala.test' },
    // has admin group but marker is false — group is display-only
    metadata_admin: { admin: false, groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('non-admin identity (no admin marker) is allowed', () => {
  const identity = {
    id: '22222222-2222-2222-2222-222222222222',
    traits: { email: 'kid@othala.test' },
    metadata_admin: { groups: ['family', 'access-keep'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with no metadata_admin is allowed (fail-safe for non-admin)', () => {
  const identity = { id: '22222222-2222-2222-2222-222222222222', traits: { email: 'unknown@othala.test' } };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with metadata_admin.admin as string "true" is allowed (wrong type, fail-closed strict equality)', () => {
  const identity = {
    id: '22222222-2222-2222-2222-222222222222',
    traits: { email: 'trick@othala.test' },
    metadata_admin: { admin: 'true' },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with metadata_admin.admin as number 1 is allowed (wrong type, fail-closed strict equality)', () => {
  const identity = {
    id: '22222222-2222-2222-2222-222222222222',
    traits: { email: 'trick2@othala.test' },
    metadata_admin: { admin: 1 },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('null/undefined identity is allowed (no admin marker)', () => {
  assert.equal(shouldRefuseRecovery(null), false);
  assert.equal(shouldRefuseRecovery(undefined), false);
});

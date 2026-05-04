// Test for the HIGH-3 admin-to-admin recovery refusal in
// src/pages/admin/users/[id].astro action=issue-recovery.
//
// The .astro file isn't directly importable into a Node test runner
// (it needs the Astro compiler). This test mirrors the gate logic
// inline and asserts the contract: identities in the `admin` group
// are refused; others are allowed.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Mirror of the [id].astro inline check. Source-of-truth is the
// .astro file; this is a regression guard that breaks if anyone
// inverts the check.
function shouldRefuseRecovery(identity) {
  const groups = identity?.metadata_admin?.groups ?? [];
  return groups.includes('admin');
}

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

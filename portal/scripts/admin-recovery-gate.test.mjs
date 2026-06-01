// Test for the admin-to-admin recovery refusal gate (CU3 B2 update).
//
// Run with: tsx --test scripts/admin-recovery-gate.test.mjs
//
// The gate logic lives in src/lib/access.ts (shouldRefuseRecovery) and is
// consumed by src/pages/admin/users/[id].astro action=issue-recovery.
//
// CU3 B2: admin authority is now the AUTH_ADMIN_SUBJECTS allowlist, NOT the
// `admin` metadata_admin group. shouldRefuseRecovery refuses iff the TARGET
// identity's EMAIL is on the allowlist. The `admin` group is display-only
// and no longer gates recovery.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { shouldRefuseRecovery } from '../src/lib/access.ts';

beforeEach(() => {
  process.env.AUTH_ADMIN_SUBJECTS = 'andrew@dunn.dev,ops@dunn.dev';
});

test('allowlisted admin identity is refused', () => {
  const identity = {
    id: 'a-1',
    traits: { email: 'andrew@dunn.dev' },
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('allowlisted admin is refused even after self-demoting out of the admin group', () => {
  const identity = {
    id: 'a-2',
    traits: { email: 'ops@dunn.dev' },
    metadata_admin: { groups: ['family'] }, // no 'admin' group
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('group-admin NOT on the allowlist is allowed (group is display-only)', () => {
  const identity = {
    id: 'b-1',
    traits: { email: 'imposter@dunn.dev' },
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('non-admin identity is allowed', () => {
  const identity = {
    id: 'b-2',
    traits: { email: 'kid@dunn.dev' },
    metadata_admin: { groups: ['family', 'access-keep'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with no traits/email is allowed (non-admin by default, fail-open for recovery of unknowns)', () => {
  const identity = { id: 'c-1' };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('null/undefined identity is allowed (no admin)', () => {
  assert.equal(shouldRefuseRecovery(null), false);
  assert.equal(shouldRefuseRecovery(undefined), false);
});

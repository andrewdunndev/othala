// Test for the admin-to-admin recovery refusal gate (CU3 B2 / CVP-P1 update).
//
// Run with: tsx --test scripts/admin-recovery-gate.test.mjs
//
// The gate logic lives in src/lib/access.ts (shouldRefuseRecovery) and is
// consumed by src/pages/admin/users/[id].astro action=issue-recovery.
//
// CVP-P1: admin authority is now the OTHALA_ADMIN_IDS allowlist keyed on the
// IMMUTABLE identity `id` (a Kratos UUID). shouldRefuseRecovery refuses iff
// the TARGET identity's ID is on the allowlist. The `admin` group and the
// email trait are display-only / user-editable and no longer gate recovery.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { shouldRefuseRecovery } from '../src/lib/access.ts';

const ADMIN_UUID = '11111111-1111-1111-1111-111111111111';
const OPS_UUID   = '33333333-3333-3333-3333-333333333333';
const OTHER_UUID = '22222222-2222-2222-2222-222222222222';

beforeEach(() => {
  process.env.OTHALA_ADMIN_IDS = `${ADMIN_UUID},${OPS_UUID}`;
});

test('allowlisted admin identity is refused', () => {
  const identity = {
    id: ADMIN_UUID,
    traits: { email: 'andrew@dunn.dev' },
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('allowlisted admin is refused even after self-demoting out of the admin group', () => {
  const identity = {
    id: OPS_UUID,
    traits: { email: 'ops@dunn.dev' },
    metadata_admin: { groups: ['family'] }, // no 'admin' group
  };
  assert.equal(shouldRefuseRecovery(identity), true);
});

test('group-admin NOT on the allowlist is allowed (group is display-only)', () => {
  const identity = {
    id: OTHER_UUID,
    traits: { email: 'imposter@dunn.dev' },
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('non-admin identity is allowed', () => {
  const identity = {
    id: OTHER_UUID,
    traits: { email: 'kid@dunn.dev' },
    metadata_admin: { groups: ['family', 'access-keep'] },
  };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('identity with no id is allowed (no admin by default, fail-open for recovery of unknowns)', () => {
  const identity = { traits: { email: 'unknown@dunn.dev' } };
  assert.equal(shouldRefuseRecovery(identity), false);
});

test('null/undefined identity is allowed (no admin)', () => {
  assert.equal(shouldRefuseRecovery(null), false);
  assert.equal(shouldRefuseRecovery(undefined), false);
});

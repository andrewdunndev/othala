// Tests for src/lib/admin-auth.ts — the admin allowlist (CU3 B2, CVP-P1).
//
// Run with: tsx --test scripts/admin-auth.test.mjs
//
// Proves OTHALA_ADMIN_IDS (identity UUIDs) is AUTHORITATIVE and neither the
// `admin` group nor the email trait is consulted for admin authority:
//   - allowlisted UUID -> admin; non-allowlisted -> not admin.
//   - a user in the `admin` GROUP but NOT on the allowlist is NOT an admin
//     (via shouldRefuseRecovery, which now reads the ID allowlist).
//   - self-demote: an allowlisted admin who removed the `admin` group from
//     their own identity is STILL an admin (recovery still refused).
//   - fail-closed: unset/empty list -> no admins.
//   - case + whitespace folding (UUIDs are case-insensitive).

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { isAdminId, adminIds } from '../src/lib/admin-auth.ts';
import { shouldRefuseRecovery } from '../src/lib/access.ts';

const ADMIN_UUID = '11111111-1111-1111-1111-111111111111';
const OTHER_UUID = '22222222-2222-2222-2222-222222222222';
const OPS_UUID   = '33333333-3333-3333-3333-333333333333';

beforeEach(() => {
  delete process.env.OTHALA_ADMIN_IDS;
});

test('allowlisted UUID is an admin; others are not', () => {
  process.env.OTHALA_ADMIN_IDS = ADMIN_UUID;
  assert.equal(isAdminId(ADMIN_UUID), true);
  assert.equal(isAdminId(OTHER_UUID), false);
});

test('multiple comma-separated UUIDs, with whitespace + case folding', () => {
  process.env.OTHALA_ADMIN_IDS = ` ${ADMIN_UUID.toUpperCase()} , ${OPS_UUID} `;
  assert.deepEqual([...adminIds()].sort(), [ADMIN_UUID, OPS_UUID].sort());
  assert.equal(isAdminId(ADMIN_UUID.toUpperCase()), true);
  assert.equal(isAdminId(`  ${OPS_UUID}  `), true);
});

test('fail-closed: unset list yields no admins', () => {
  assert.equal(isAdminId(ADMIN_UUID), false);
});

test('fail-closed: empty / whitespace-only list yields no admins', () => {
  process.env.OTHALA_ADMIN_IDS = '   ,  , ';
  assert.equal(adminIds().size, 0);
  assert.equal(isAdminId(ADMIN_UUID), false);
});

test('missing / empty id is never an admin', () => {
  process.env.OTHALA_ADMIN_IDS = ADMIN_UUID;
  assert.equal(isAdminId(undefined), false);
  assert.equal(isAdminId(null), false);
  assert.equal(isAdminId(''), false);
});

// ── allowlist is authoritative; the `admin` GROUP is display-only ──────────

test('user in the admin GROUP but NOT on the allowlist is DENIED admin', () => {
  process.env.OTHALA_ADMIN_IDS = ADMIN_UUID;
  // shouldRefuseRecovery is one of the admin gates; it now reads the allowlist
  // by TARGET identity id, not the group. A group-only "admin" is not refused.
  const groupAdminNotAllowlisted = {
    id: OTHER_UUID,
    traits: { email: 'imposter@dunn.dev' },
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(groupAdminNotAllowlisted), false);
  assert.equal(isAdminId(groupAdminNotAllowlisted.id), false);
});

test('self-demote: allowlisted admin who dropped the admin GROUP is STILL admin', () => {
  process.env.OTHALA_ADMIN_IDS = ADMIN_UUID;
  const selfDemoted = {
    id: ADMIN_UUID,
    traits: { email: 'andrew@dunn.dev' },
    // self-demoted: removed 'admin' from their own groups
    metadata_admin: { groups: ['family'] },
  };
  // Still an admin -> recovery still refused (escalation NOT lost).
  assert.equal(isAdminId(selfDemoted.id), true);
  assert.equal(shouldRefuseRecovery(selfDemoted), true);
});

test('shouldRefuseRecovery: non-allowlisted target is allowed recovery', () => {
  process.env.OTHALA_ADMIN_IDS = ADMIN_UUID;
  const target = { id: OTHER_UUID, traits: { email: 'kid@dunn.dev' }, metadata_admin: { groups: ['kids'] } };
  assert.equal(shouldRefuseRecovery(target), false);
});

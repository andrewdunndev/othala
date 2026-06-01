// Tests for src/lib/admin-auth.ts — the admin allowlist (CU3 B2).
//
// Run with: tsx --test scripts/admin-auth.test.mjs
//
// Proves OTHALA_ADMIN_SUBJECTS is AUTHORITATIVE and the `admin` group is no
// longer consulted for admin authority:
//   - allowlisted email -> admin; non-allowlisted -> not admin.
//   - a user in the `admin` GROUP but NOT on the allowlist is NOT an admin
//     (via shouldRefuseRecovery, which now reads the allowlist).
//   - self-demote: an allowlisted admin who removed the `admin` group from
//     their own identity is STILL an admin (recovery still refused).
//   - fail-closed: unset/empty list -> no admins.
//   - case + whitespace folding.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { isAdminSubject, adminSubjects } from '../src/lib/admin-auth.ts';
import { shouldRefuseRecovery } from '../src/lib/access.ts';

beforeEach(() => {
  delete process.env.OTHALA_ADMIN_SUBJECTS;
});

test('allowlisted email is an admin; others are not', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = 'andrew@dunn.dev';
  assert.equal(isAdminSubject('andrew@dunn.dev'), true);
  assert.equal(isAdminSubject('someone@dunn.dev'), false);
});

test('multiple comma-separated subjects, with whitespace + case folding', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = ' Andrew@Dunn.dev , ops@dunn.dev ';
  assert.deepEqual([...adminSubjects()].sort(), ['andrew@dunn.dev', 'ops@dunn.dev']);
  assert.equal(isAdminSubject('ANDREW@dunn.dev'), true);
  assert.equal(isAdminSubject('  ops@dunn.dev  '), true);
});

test('fail-closed: unset list yields no admins', () => {
  assert.equal(isAdminSubject('andrew@dunn.dev'), false);
});

test('fail-closed: empty / whitespace-only list yields no admins', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = '   ,  , ';
  assert.equal(adminSubjects().size, 0);
  assert.equal(isAdminSubject('andrew@dunn.dev'), false);
});

test('missing / empty email is never an admin', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = 'andrew@dunn.dev';
  assert.equal(isAdminSubject(undefined), false);
  assert.equal(isAdminSubject(null), false);
  assert.equal(isAdminSubject(''), false);
});

// ── allowlist is authoritative; the `admin` GROUP is display-only ──────────

test('user in the admin GROUP but NOT on the allowlist is DENIED admin', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = 'andrew@dunn.dev';
  // shouldRefuseRecovery is one of the admin gates; it now reads the allowlist
  // by TARGET email, not the group. A group-only "admin" is not refused.
  const groupAdminNotAllowlisted = {
    id: 'g-1',
    traits: { email: 'imposter@dunn.dev' },
    metadata_admin: { groups: ['admin', 'family'] },
  };
  assert.equal(shouldRefuseRecovery(groupAdminNotAllowlisted), false);
  assert.equal(isAdminSubject(groupAdminNotAllowlisted.traits.email), false);
});

test('self-demote: allowlisted admin who dropped the admin GROUP is STILL admin', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = 'andrew@dunn.dev';
  const selfDemoted = {
    id: 's-1',
    traits: { email: 'andrew@dunn.dev' },
    // self-demoted: removed 'admin' from their own groups
    metadata_admin: { groups: ['family'] },
  };
  // Still an admin -> recovery still refused (escalation NOT lost).
  assert.equal(isAdminSubject(selfDemoted.traits.email), true);
  assert.equal(shouldRefuseRecovery(selfDemoted), true);
});

test('shouldRefuseRecovery: non-allowlisted target is allowed recovery', () => {
  process.env.OTHALA_ADMIN_SUBJECTS = 'andrew@dunn.dev';
  const target = { id: 'u-1', traits: { email: 'kid@dunn.dev' }, metadata_admin: { groups: ['kids'] } };
  assert.equal(shouldRefuseRecovery(target), false);
});

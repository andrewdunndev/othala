// Tests for src/lib/access.ts confirmsInviteAddress (D1 best-practice
// bundle: send-time address confirmation for send-invite-email).
//
// Run with: tsx --test scripts/confirm-invite-address.test.mjs
//
// Same style as admin-recovery-gate.test.mjs: imports the real TS function
// directly and exercises it as a pure predicate — no Kratos, no HTTP, no
// Astro. The function is the SERVER-SIDE half of the confirmation check
// (portal/src/pages/admin/users/[id].astro calls it in the action handler
// before sendInviteRecoveryEmail is ever reached); a UI-only check is not
// an invariant, so this is the half that has to be provably correct.
//
// Coverage:
//   - exact match returns true
//   - any byte difference (case, whitespace, substring) returns false —
//     the comparison is byte-equal, not case-folded or trimmed
//   - empty confirmation (field left blank / omitted) returns false

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { confirmsInviteAddress } from '../src/lib/access.ts';

test('identical strings match', () => {
  assert.equal(confirmsInviteAddress('member@othala.test', 'member@othala.test'), true);
});

test('different address does not match', () => {
  assert.equal(confirmsInviteAddress('other@othala.test', 'member@othala.test'), false);
});

test('case difference does not match (byte-equal, not case-folded)', () => {
  assert.equal(confirmsInviteAddress('Member@othala.test', 'member@othala.test'), false);
});

test('leading/trailing whitespace does not match (byte-equal, not trimmed)', () => {
  assert.equal(confirmsInviteAddress(' member@othala.test', 'member@othala.test'), false);
  assert.equal(confirmsInviteAddress('member@othala.test ', 'member@othala.test'), false);
});

test('empty confirmation does not match a non-empty target', () => {
  assert.equal(confirmsInviteAddress('', 'member@othala.test'), false);
});

test('substring / prefix of the target does not match', () => {
  assert.equal(confirmsInviteAddress('member@othala', 'member@othala.test'), false);
});

test('both empty matches (degenerate case; callers must reject an empty target upstream)', () => {
  assert.equal(confirmsInviteAddress('', ''), true);
});

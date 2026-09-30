// Invariant: an invite email is sent only to a confirmed address.

import { test } from 'vitest';
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

// Tests for portal/src/lib/access-groups.ts — parseAccessGroups precedence.
//
// Run with: tsx --test scripts/access-groups.test.mjs
//
// Dual-read parse precedence:
//   1. presentation.access non-empty list → use it.
//   2. else presentation.access_group non-empty → [access_group] (compat shim).
//   3. else [] (no `everyone` fallback at this layer).
//
// Phase 1 is non-breaking: bad charset names are skipped, never thrown.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAccessGroups } from '../src/lib/access-groups.ts';

// ── (1) the `access:` list path ───────────────────────────────────────────────

test('parseAccessGroups: single-element access list is used', () => {
  assert.deepEqual(parseAccessGroups({ access: ['memories'] }), ['memories']);
});

test('parseAccessGroups: multi-element access list preserves declared order', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['memories', 'admin-memories', 'family'] }),
    ['memories', 'admin-memories', 'family'],
  );
});

test('parseAccessGroups: access list wins over access_group', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['memories'], access_group: 'access-photos' }),
    ['memories'],
    'a non-empty access: list supersedes the compat access_group field',
  );
});

test('parseAccessGroups: arbitrary adopter names (no prefix) are accepted', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['photos-team', 'family'] }),
    ['photos-team', 'family'],
  );
});

test('parseAccessGroups: duplicates within access list are de-duped, order kept', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['family', 'family', 'memories'] }),
    ['family', 'memories'],
  );
});

// ── (2) the [access_group] compat path ────────────────────────────────────────

test('parseAccessGroups: only access_group → one-element list (compat shim)', () => {
  assert.deepEqual(
    parseAccessGroups({ access_group: 'access-photos' }),
    ['access-photos'],
    'the access-<slug> name is a valid group name; no prefix validation applied',
  );
});

test('parseAccessGroups: compat shim trims whitespace', () => {
  assert.deepEqual(parseAccessGroups({ access_group: '  memories  ' }), ['memories']);
});

// ── (3) the empty [] path ─────────────────────────────────────────────────────

test('parseAccessGroups: neither field present → []', () => {
  assert.deepEqual(parseAccessGroups({}), []);
});

test('parseAccessGroups: empty access list with no access_group → []', () => {
  assert.deepEqual(parseAccessGroups({ access: [] }), []);
});

test('parseAccessGroups: empty access list falls back to access_group', () => {
  assert.deepEqual(
    parseAccessGroups({ access: [], access_group: 'memories' }),
    ['memories'],
    'an empty access: list is not "non-empty", so the compat shim applies',
  );
});

test('parseAccessGroups: empty access_group string → []', () => {
  assert.deepEqual(parseAccessGroups({ access_group: '' }), []);
});

// ── non-breaking charset handling (Phase 1: skip, never throw) ─────────────────

test('parseAccessGroups: bad-charset name in access list is skipped, not thrown', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['memories', 'Bad Name!', 'family'] }),
    ['memories', 'family'],
  );
});

test('parseAccessGroups: all-bad access list falls through to access_group', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['-leading-dash', 'UPPER'], access_group: 'memories' }),
    ['memories'],
    'no valid name survives the list, so the compat shim takes over',
  );
});

test('parseAccessGroups: bad-charset access_group → []', () => {
  assert.deepEqual(parseAccessGroups({ access_group: 'Has Spaces' }), []);
});

test('parseAccessGroups: non-array access value falls back to access_group', () => {
  assert.deepEqual(
    parseAccessGroups({ access: 'memories', access_group: 'compat' }),
    ['compat'],
    'a scalar `access:` is not a list; the compat shim applies',
  );
});

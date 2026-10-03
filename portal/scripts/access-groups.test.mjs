// Invariant: parseAccessGroups reads only the access list, keeps declared order and de-dupes.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { parseAccessGroups } from '../src/lib/access-groups.ts';

test('parseAccessGroups: single-element access list is used', () => {
  assert.deepEqual(parseAccessGroups({ access: ['memories'] }), ['memories']);
});

test('parseAccessGroups: multi-element access list preserves declared order', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['memories', 'admin-memories', 'family'] }),
    ['memories', 'admin-memories', 'family'],
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

test('parseAccessGroups: no access list → []', () => {
  assert.deepEqual(parseAccessGroups({}), []);
});

test('parseAccessGroups: empty access list → []', () => {
  assert.deepEqual(parseAccessGroups({ access: [] }), []);
});

test('parseAccessGroups: bad-charset name in access list is skipped, not thrown', () => {
  assert.deepEqual(
    parseAccessGroups({ access: ['memories', 'Bad Name!', 'family'] }),
    ['memories', 'family'],
  );
});

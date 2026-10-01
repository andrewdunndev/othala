// Invariant: stored groups are ordered canonically, so the stored array is a pure function of the group set.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { normalizeGroupOrder } from '../src/lib/access.ts';

test('normalizeGroupOrder: identity groups in canonical order', () => {
  assert.deepEqual(
    normalizeGroupOrder(['friends', 'admin', 'family', 'kids']),
    ['admin', 'family', 'friends', 'kids'],
  );
});

test('normalizeGroupOrder: non-identity groups sort alphabetically after identity groups', () => {
  assert.deepEqual(
    normalizeGroupOrder(['access-statuspage', 'admin', 'access-filedrop', 'family']),
    ['admin', 'access-filedrop', 'access-statuspage', 'family'],
  );
});

test('normalizeGroupOrder: all non-identity groups (access-* and bare) interleave alphabetically', () => {
  assert.deepEqual(
    normalizeGroupOrder(['service', 'admin', 'access-foo', 'elder']),
    ['admin', 'access-foo', 'elder', 'service'],
  );
});

test('normalizeGroupOrder: idempotent', () => {
  const once = normalizeGroupOrder(['kids', 'family', 'access-promptdesk']);
  const twice = normalizeGroupOrder(once);
  assert.deepEqual(twice, once);
});

test('normalizeGroupOrder: empty input → empty output', () => {
  assert.deepEqual(normalizeGroupOrder([]), []);
});

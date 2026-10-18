// Invariant: the reference-check job runs a tagged reference, never a moving branch, since it executes with CI tokens.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const ci = readFileSync(fileURLToPath(new URL('../../.gitlab-ci.yml', import.meta.url)), 'utf8');

test('reference_ref is a release tag', () => {
  assert.match(ci, /^\s+reference_ref: v\d+\.\d+\.\d+$/m);
});

test('the deviation register parses and every entry carries a reason and an owner', () => {
  const entries = parse(readFileSync(fileURLToPath(new URL('../../.deviations.yaml', import.meta.url)), 'utf8'));
  assert.ok(Array.isArray(entries) && entries.length > 0);
  for (const e of entries) {
    for (const k of ['standard', 'assertion', 'reason', 'owner']) assert.ok(String(e[k] ?? '').trim() !== '', k);
  }
});

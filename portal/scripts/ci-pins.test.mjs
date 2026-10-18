// Invariant: the reference-check job runs a tagged reference, never a moving branch, since it executes with CI tokens.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ci = readFileSync(fileURLToPath(new URL('../../.gitlab-ci.yml', import.meta.url)), 'utf8');

test('reference_ref is a release tag', () => {
  assert.match(ci, /^\s+reference_ref: v\d+\.\d+\.\d+$/m);
});

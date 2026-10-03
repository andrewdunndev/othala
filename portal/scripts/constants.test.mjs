// Invariant: fixed topology and policy come from constants.ts; only `astro dev` may point MANIFEST_DIR elsewhere.

import { test, vi, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { manifestDir, setManifestDir } from '../src/lib/manifests.ts';

afterEach(() => {
  vi.unstubAllEnvs();
  delete process.env.MANIFEST_DIR;
  setManifestDir(undefined);
});

test('production ignores MANIFEST_DIR in the environment', () => {
  vi.stubEnv('DEV', false);
  process.env.MANIFEST_DIR = '/elsewhere';
  assert.equal(manifestDir(), '/etc/portal/manifests');
});

test('dev honours MANIFEST_DIR in the environment', () => {
  vi.stubEnv('DEV', true);
  process.env.MANIFEST_DIR = '/elsewhere';
  assert.equal(manifestDir(), '/elsewhere');
});

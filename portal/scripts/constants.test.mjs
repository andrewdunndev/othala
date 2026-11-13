// Invariant: fixed topology and policy come from constants.ts; only `astro dev` may point CONTENT_DIR elsewhere.

import { test, vi, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { appsDir, contentDir, setContentDir } from '../src/lib/manifests.ts';

afterEach(() => {
  vi.unstubAllEnvs();
  delete process.env.CONTENT_DIR;
  setContentDir(undefined);
});

test('production ignores CONTENT_DIR in the environment', () => {
  vi.stubEnv('DEV', false);
  process.env.CONTENT_DIR = '/elsewhere';
  assert.equal(contentDir(), '/etc/othala');
  assert.equal(appsDir(), '/etc/othala/apps');
});

test('dev honours CONTENT_DIR in the environment', () => {
  vi.stubEnv('DEV', true);
  process.env.CONTENT_DIR = '/elsewhere';
  assert.equal(contentDir(), '/elsewhere');
  assert.equal(appsDir(), '/elsewhere/apps');
});

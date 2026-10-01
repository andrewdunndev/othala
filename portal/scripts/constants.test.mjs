// Invariant: fixed topology and policy come from constants.ts, never from the environment.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { manifestDir, setManifestDir } from '../src/lib/manifests.ts';

test('the manifest dir ignores MANIFEST_DIR in the environment', () => {
  process.env.MANIFEST_DIR = '/elsewhere';
  try {
    assert.equal(manifestDir(), '/etc/portal/manifests');
  } finally {
    delete process.env.MANIFEST_DIR;
  }
  setManifestDir('/tmp/x');
  assert.equal(manifestDir(), '/tmp/x');
  setManifestDir(undefined);
  assert.equal(manifestDir(), '/etc/portal/manifests');
});

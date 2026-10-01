// Invariant: fixed topology and policy come from constants.ts, never from the environment.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import * as constants from '../src/lib/constants.ts';
import { manifestDir, setManifestDir } from '../src/lib/manifests.ts';

test('golden topology constants', () => {
  assert.equal(constants.KRATOS_ADMIN_URL, 'http://kratos:4434');
  assert.equal(constants.HYDRA_ADMIN_URL, 'http://hydra:4445');
  assert.equal(constants.MANIFEST_DIR, '/etc/portal/manifests');
  assert.equal(constants.DEFAULT_GROUP, 'everyone');
  assert.deepEqual([...constants.IDENTITY_GROUPS], ['admin', 'everyone']);
  assert.equal(constants.ADMIN_FRESHNESS_HOURS, 1);
});

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

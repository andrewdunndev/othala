// Invariant: parseTile resolves access groups from manifests with a safe fallback.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

async function withTilesModule({ MANIFEST_DIR: dir }, callback) {
  const { setManifestDir } = await import('../src/lib/manifests.ts');
  setManifestDir(dir);
  try {
    const bust = `?bust=${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const mod = await import(/* @vite-ignore */ `../src/lib/tiles.ts${bust}`);
    return await callback(mod);
  } finally {
    setManifestDir(undefined);
  }
}

async function parseSingleTile(yamlContent) {
  const dir = mkdtempSync(join(tmpdir(), 'tiles-test-'));
  try {
    writeFileSync(join(dir, 'testapp.yaml'), yamlContent);
    return await withTilesModule({ MANIFEST_DIR: dir }, (mod) => {
      const tiles = mod.loadTiles();
      return tiles[0];
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('parseTile: explicit access_group passes through unchanged', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: oidc
  access_group: access-testapp
  order: 10
`);
  assert.ok(tile, 'tile must be parsed');
  assert.equal(tile.accessGroup, 'access-testapp');
});

test('parseTile: absent access_group falls back to default group (everyone)', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: external
  order: 10
`);
  assert.ok(tile, 'tile must be parsed');
  assert.equal(tile.accessGroup, 'everyone',
    'absent access_group must fall back to the default group (everyone)');
});

test('parseTile: empty access_group string falls back to default group', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: external
  access_group: ""
  order: 10
`);
  assert.ok(tile, 'tile must be parsed');
  assert.equal(tile.accessGroup, 'everyone',
    'empty access_group must fall back to the default group');
});

test('parseTile: presentation.access list populates accessGroups', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: oidc
  access:
    - memories
    - family
  order: 10
`);
  assert.ok(tile, 'tile must be parsed');
  assert.deepEqual(tile.accessGroups, ['memories', 'family']);
});

test('parseTile: only access_group populates accessGroups via compat shim', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: oidc
  access_group: access-testapp
  order: 10
`);
  assert.ok(tile, 'tile must be parsed');
  assert.deepEqual(tile.accessGroups, ['access-testapp']);
  assert.equal(tile.accessGroup, 'access-testapp');
});

test('parseTile: neither access nor access_group → accessGroups is empty', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: external
  order: 10
`);
  assert.ok(tile, 'tile must be parsed');
  assert.deepEqual(tile.accessGroups, [],
    'no access binding → empty accessGroups (no everyone fallback at this layer)');
  assert.equal(tile.accessGroup, 'everyone');
});

test('parseTile: manifest without presentation block returns no tile', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tiles-test-nopres-'));
  try {
    writeFileSync(join(dir, 'oidconly.yaml'), `
oidc:
  client_id: oidconly
consent: {}
`);
    const count = await withTilesModule({ MANIFEST_DIR: dir }, (mod) => mod.loadTiles().length);
    assert.equal(count, 0, 'OIDC-only manifest must yield no tile');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('parseTile: disabled tile is excluded from loadTiles', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tiles-test-disabled-'));
  try {
    writeFileSync(join(dir, 'hidden.yaml'), `
presentation:
  name: Hidden App
  description: Disabled
  url: https://hidden.othala.test
  icon: HI
  auth_kind: external
  disabled: true
  order: 10
`);
    const count = await withTilesModule({ MANIFEST_DIR: dir }, (mod) => mod.loadTiles().length);
    assert.equal(count, 0, 'disabled tile must be excluded from loadTiles');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('parseTile: external tile without access_group uses default group (statuspage pattern)', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Statuspage
  description: Public status and incident history.
  url: https://status.othala.test
  icon: ST
  icon_fallback: statuspage
  auth_kind: external
  order: 200
`);
  assert.ok(tile, 'statuspage-pattern tile must be parsed');
  assert.equal(tile.authKind, 'external');
  assert.equal(tile.accessGroup, 'everyone',
    'external tile without access_group must gate on the default group');
});

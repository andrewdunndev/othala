// Invariant: parseTile resolves access groups from manifests with a safe fallback.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { tileAccessGroups } from '../src/lib/tiles.ts';

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

test('parseTile: no access binding falls back to the default group (everyone)', async () => {
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
  assert.deepEqual(tileAccessGroups(tile), ['everyone'],
    'no access binding must fall back to the default group (everyone)');
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

test('parseTile: no access list → accessGroups is empty', async () => {
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
  assert.deepEqual(tileAccessGroups(tile), ['everyone']);
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

test('parseTile: external tile without access uses default group (statuspage pattern)', async () => {
  const tile = await parseSingleTile(`
presentation:
  name: Statuspage
  description: Public status and incident history.
  url: https://status.othala.test
  icon: ST
  auth_kind: external
  order: 200
`);
  assert.ok(tile, 'statuspage-pattern tile must be parsed');
  assert.equal(tile.authKind, 'external');
  assert.deepEqual(tileAccessGroups(tile), ['everyone'],
    'external tile without access must gate on the default group');
});

const SIDECAR_YAML = `
presentation:
  name: Side
  description: d
  url: https://side.othala.test
  icon: SI
  auth_kind: external
`;

async function loadWithSidecar(svg) {
  const dir = mkdtempSync(join(tmpdir(), 'tiles-test-svg-'));
  try {
    writeFileSync(join(dir, 'side.yaml'), SIDECAR_YAML);
    if (svg !== undefined) writeFileSync(join(dir, 'side.svg'), svg);
    return await withTilesModule({ MANIFEST_DIR: dir }, (mod) => mod.loadTiles()[0]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('sidecar: <stem>.svg beside the manifest gives the tile an href', async () => {
  const tile = await loadWithSidecar('<svg viewBox="0 0 1 1"></svg>');
  assert.equal(tile.iconHref, '/icons/side.svg');
  assert.equal(tile.iconBleed, false);
});

test('sidecar: no file leaves the monogram', async () => {
  const tile = await loadWithSidecar(undefined);
  assert.equal(tile.iconHref, undefined);
  assert.equal(tile.iconReason, undefined);
});

test('sidecar: an oversize file or a non-svg root gives no href and a reason, and the tile still loads', async () => {
  const big = await loadWithSidecar('<svg>' + ' '.repeat(33 * 1024) + '</svg>');
  assert.equal(big.iconHref, undefined);
  assert.match(big.iconReason, /over the/);
  const html = await loadWithSidecar('<html><svg></svg></html>');
  assert.equal(html.iconHref, undefined);
  assert.match(html.iconReason, /<svg> root/);
});

test('sidecar: a non-regular <stem>.svg gives no href and a reason', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tiles-test-svg-'));
  try {
    writeFileSync(join(dir, 'side.yaml'), SIDECAR_YAML);
    mkdirSync(join(dir, 'side.svg'));
    const tile = await withTilesModule({ MANIFEST_DIR: dir }, (mod) => mod.loadTiles()[0]);
    assert.equal(tile.iconHref, undefined);
    assert.match(tile.iconReason, /regular file/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sidecar: bleed is read from the sidecar', async () => {
  const tile = await loadWithSidecar('<svg viewBox="0 0 8 8"><rect width="8" height="8" fill="#123456"/></svg>');
  assert.equal(tile.iconBleed, true);
});

test('sidecar: retired icon_slug and icon_fallback are ignored at serve', async () => {
  const tile = await parseSingleTile(SIDECAR_YAML + '  icon_slug: grafana\n  icon_fallback: grafana\n');
  assert.equal(tile.iconHref, undefined);
});

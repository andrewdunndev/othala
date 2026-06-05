// Tests for portal/src/lib/tiles.ts — parseTile access_group fallback.
//
// Run with: tsx --test scripts/tiles.test.mjs
//
// Coverage:
//   - explicit access_group passes through unchanged
//   - absent access_group falls back to OTHALA_DEFAULT_GROUP (default 'everyone')
//   - OTHALA_DEFAULT_GROUP env override is respected
//   - presentation-only tile without access_group uses default group
//   - non-presentation manifest (no presentation: block) returns null
//   - disabled tile parses correctly

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Load the tiles module in a fresh ESM context with the given env, call a
 * callback, then restore env. The callback runs INSIDE the env window so
 * MANIFEST_DIR and OTHALA_* vars are still set when loadTiles() reads them.
 *
 * Note: tiles.ts reads MANIFEST_DIR at CALL TIME (runtime, not module load),
 * so the env must still be set when loadTiles() is invoked. We keep the env
 * set while the callback runs, then restore it afterward.
 */
async function withTilesModule(env, callback) {
  const saved = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('OTHALA_') || key === 'MANIFEST_DIR') delete process.env[key];
  }
  Object.assign(process.env, env);
  try {
    const bust = `?bust=${Date.now()}-${Math.random()}`;
    const mod = await import(`../src/lib/tiles.ts${bust}`);
    return await callback(mod);
  } finally {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('OTHALA_') || key === 'MANIFEST_DIR') delete process.env[key];
    }
    Object.assign(process.env, saved);
  }
}

/**
 * Write a minimal presentation YAML to a temp dir and call loadTiles.
 * Returns the first tile parsed (or undefined if none).
 * The MANIFEST_DIR env var is set while loadTiles() is called.
 */
async function parseSingleTile(yamlContent, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'tiles-test-'));
  try {
    writeFileSync(join(dir, 'testapp.yaml'), yamlContent);
    return await withTilesModule({ MANIFEST_DIR: dir, ...env }, (mod) => {
      const tiles = mod.loadTiles();
      return tiles[0];
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── access_group fallback tests ───────────────────────────────────────────────

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

test('parseTile: absent access_group respects OTHALA_DEFAULT_GROUP override', async () => {
  const tile = await parseSingleTile(
    `
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: external
  order: 10
`,
    { OTHALA_DEFAULT_GROUP: 'family' },
  );
  assert.ok(tile, 'tile must be parsed');
  assert.equal(tile.accessGroup, 'family',
    'OTHALA_DEFAULT_GROUP=family must override the default');
});

test('parseTile: explicit access_group wins over OTHALA_DEFAULT_GROUP', async () => {
  const tile = await parseSingleTile(
    `
presentation:
  name: Test App
  description: A test application
  url: https://testapp.othala.test
  icon: TA
  auth_kind: oidc
  access_group: access-specific
  order: 10
`,
    { OTHALA_DEFAULT_GROUP: 'everyone' },
  );
  assert.ok(tile, 'tile must be parsed');
  assert.equal(tile.accessGroup, 'access-specific',
    'explicit access_group must override OTHALA_DEFAULT_GROUP');
});

test('parseTile: empty access_group string falls back to default group', async () => {
  // An explicitly empty string in YAML parses as '' (falsy) — treated as absent.
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

// ── non-presentation manifest ─────────────────────────────────────────────────

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

// ── disabled tile ─────────────────────────────────────────────────────────────

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

// ── default-group fallback for external tile (the statuspage pattern) ─────────

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

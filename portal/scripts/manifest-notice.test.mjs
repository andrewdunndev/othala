// Invariant: a file the loaders drop is named with its reason in the admin notice; a clean catalog shows nothing.

import { test, beforeAll, afterAll } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { getViteConfig } from 'astro/config';
import { createServer } from 'vite';

let server, AstroContainer, Notice, manifests, store, tiles;

beforeAll(async () => {
  const inline = await getViteConfig({ server: { middlewareMode: true } })({ command: 'serve', mode: 'test' });
  server = await createServer({ ...inline, server: { middlewareMode: true }, appType: 'custom', logLevel: 'silent' });
  ({ experimental_AstroContainer: AstroContainer } = await server.ssrLoadModule('astro/container'));
  Notice = (await server.ssrLoadModule('/src/components/ManifestNotice.astro')).default;
  manifests = await server.ssrLoadModule('/src/lib/manifests.ts');
  store = await server.ssrLoadModule('/src/lib/manifest-store.ts');
  tiles = await server.ssrLoadModule('/src/lib/tiles.ts');
});

afterAll(async () => {
  manifests?.setManifestDir(undefined);
  if (server) await server.close();
});

const GOOD = 'presentation:\n  name: Good\n  url: https://good.example.test\n  access: [staff]\n';

async function render(files) {
  const dir = mkdtempSync(join(tmpdir(), 'notice-'));
  try {
    for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
    manifests.setManifestDir(dir);
    manifests.invalidateManifestCache();
    const health = store.manifestHealth();
    health.dropped = [...health.dropped, ...tiles.rejectedIcons(tiles.loadTiles())];
    const container = await AstroContainer.create();
    return await container.renderToString(Notice, { props: { health } });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('a dropped manifest and a rejected sidecar are listed with their reasons', async () => {
  const html = await render({
    'good.yaml': GOOD,
    'broken.yaml': 'oidc: [unclosed\n',
    'open.yaml': 'presentation:\n  name: Open\n  access: [everyone]\n',
    'good.svg': '<html></html>',
  });
  assert.match(html, /<code[^>]*>broken\.yaml<\/code>/);
  assert.match(html, /<code[^>]*>open\.yaml<\/code>: [^<]*identity group/);
  assert.match(html, /<code[^>]*>good\.svg<\/code>: [^<]*&lt;svg&gt; root/);
});

test('a clean catalog renders nothing', async () => {
  assert.equal((await render({ 'good.yaml': GOOD, 'good.svg': '<svg viewBox="0 0 1 1"></svg>' })).trim(), '');
});

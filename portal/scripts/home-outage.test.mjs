// Invariant: the home page shows the outage page, never the signed-out home, whenever the session check itself fails,
// including when Kratos answers its liveness probe but cannot read its database.

import { test, beforeAll, afterAll, afterEach, vi } from 'vitest';
import assert from 'node:assert/strict';
import { getViteConfig } from 'astro/config';
import { createServer } from 'vite';

let server;
let AstroContainer;
let Home;

beforeAll(async () => {
  const inline = await getViteConfig({ server: { middlewareMode: true } })({ command: 'serve', mode: 'test' });
  server = await createServer({ ...inline, server: { middlewareMode: true }, appType: 'custom', logLevel: 'silent' });
  ({ experimental_AstroContainer: AstroContainer } = await server.ssrLoadModule('astro/container'));
  Home = (await server.ssrLoadModule('/src/pages/index.astro')).default;
});

afterAll(async () => {
  if (server) await server.close();
});

afterEach(() => vi.unstubAllGlobals());

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

async function home(kratos) {
  vi.stubGlobal('fetch', async (input) => kratos(String(input?.url ?? input)));
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const container = await AstroContainer.create();
  return container.renderToString(Home, {
    request: new Request('http://localhost/', { headers: { cookie: 'ory_kratos_session=x' } }),
  });
}

test('a session check that fails while Kratos is alive shows the outage page', async () => {
  const html = await home((url) => (url.includes('/health/alive') ? json(200, { status: 'ok' }) : json(500, { error: { code: 500 } })));
  assert.match(html, /Sign-in is starting up/);
  assert.doesNotMatch(html, /Welcome home/);
});

test('an unreachable Kratos shows the outage page', async () => {
  const html = await home(() => {
    throw new TypeError('fetch failed');
  });
  assert.match(html, /Sign-in is starting up/);
});

test('a rejected session on a healthy Kratos shows the signed-out home', async () => {
  const html = await home((url) => (url.includes('/health/alive') ? json(200, { status: 'ok' }) : json(401, { error: { code: 401 } })));
  assert.match(html, /Welcome home/);
  assert.doesNotMatch(html, /Sign-in is starting up/);
});

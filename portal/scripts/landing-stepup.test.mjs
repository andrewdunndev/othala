// Invariant: the home page sends a live below-aal2 session that holds a second factor to the aal2 login flow, and
// renders for everyone else, including a visit with ?ask= and a failed identity lookup.

import { test, beforeAll, afterAll, afterEach, vi } from 'vitest';
import assert from 'node:assert/strict';
import { getViteConfig } from 'astro/config';
import { createServer } from 'vite';
import { asAdmin, identity, session, withPasskey, withTotp } from '../src/lib/test-builders.ts';

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

async function visit(aal, full, path = '/', lookupStatus = 200) {
  vi.stubGlobal('fetch', async (input) => {
    const url = String(input?.url ?? input);
    if (url.includes('/admin/identities/')) return json(lookupStatus, lookupStatus === 200 ? full : { error: { code: lookupStatus } });
    return json(200, session(aal, ['password'], { identity: full }));
  });
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const container = await AstroContainer.create();
  return container.renderToResponse(Home, {
    request: new Request(`http://localhost${path}`, { headers: { cookie: 'ory_kratos_session=x' } }),
  });
}

const adminTotp = () => withTotp(asAdmin(identity({ id: 'id-1', password: true })));

test('aal1 admin with totp is sent to the aal2 flow', async () => {
  const res = await visit('aal1', adminTotp());
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/self-service/login/browser?aal=aal2&return_to=%2F');
});

test('an aal2 session sees the greeting', async () => {
  const res = await visit('aal2', adminTotp());
  assert.equal(res.status, 200);
  assert.match(await res.text(), /id="greeting"/);
});

test('an aal1 passkey-only member sees the greeting', async () => {
  const res = await visit('aal1', withPasskey(identity({ id: 'id-1', metadataAdmin: { groups: ['grafana-access'] } })));
  assert.equal(res.status, 200);
  assert.match(await res.text(), /id="greeting"/);
});

test('the ?ask= contact visit is not redirected', async () => {
  const res = await visit('aal1', adminTotp(), '/?ask=problem');
  assert.equal(res.status, 200);
});

test('a failed identity lookup renders instead of redirecting', async () => {
  const res = await visit('aal1', adminTotp(), '/', 500);
  assert.equal(res.status, 200);
});

test('return_to keeps a non-empty search', async () => {
  const res = await visit('aal1', adminTotp(), '/?tab=x');
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/self-service/login/browser?aal=aal2&return_to=%2F%3Ftab%3Dx');
});

test('return_to is a single-slash path for a //host path', async () => {
  const res = await visit('aal1', adminTotp(), '//evil.example');
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/self-service/login/browser?aal=aal2&return_to=%2Fevil.example');
});

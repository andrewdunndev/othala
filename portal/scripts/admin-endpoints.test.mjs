// Invariant: the Ory admin clients call the fixed golden endpoints with no bearer, whatever the environment says.

import { test, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { getIdentity } from '../src/lib/admin-api.ts';
import { hydraAdmin } from '../src/lib/ory-fetch.ts';

const realFetch = globalThis.fetch;
const envKeys = ['KRATOS_ADMIN_URL', 'KRATOS_ADMIN_TOKEN', 'HYDRA_ADMIN_URL', 'HYDRA_ADMIN_TOKEN'];

afterEach(() => {
  globalThis.fetch = realFetch;
  for (const k of envKeys) delete process.env[k];
});

function capture() {
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), headers: new Headers(init?.headers) });
    return new Response(JSON.stringify({ id: 'x', client_id: 'x' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  return calls;
}

function setOverrides() {
  process.env.KRATOS_ADMIN_URL = 'http://override.invalid:1';
  process.env.KRATOS_ADMIN_TOKEN = 'kratos-token';
  process.env.HYDRA_ADMIN_URL = 'http://override.invalid:2';
  process.env.HYDRA_ADMIN_TOKEN = 'hydra-token';
}

test('Kratos admin client targets http://kratos:4434 and sends no Authorization', async () => {
  setOverrides();
  const calls = capture();
  await getIdentity('abc');
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.startsWith('http://kratos:4434/admin/identities/abc'), calls[0].url);
  assert.equal(calls[0].headers.get('authorization'), null);
});

test('Hydra admin client targets http://hydra:4445 and sends no Authorization', async () => {
  setOverrides();
  const calls = capture();
  await hydraAdmin().getOAuth2Client({ id: 'x' });
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.startsWith('http://hydra:4445/admin/clients/x'), calls[0].url);
  assert.equal(calls[0].headers.get('authorization'), null);
});

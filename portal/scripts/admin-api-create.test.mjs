// Invariant: the portal never sends schema_id when creating an identity; Kratos applies identity.default_schema_id.

import { test, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { createIdentity } from '../src/lib/admin-api.ts';

const realFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = realFetch;
});

test('createIdentity: request body carries no schema_id', async () => {
  let sent;
  globalThis.fetch = async (_url, init) => {
    sent = JSON.parse(init.body);
    return new Response(JSON.stringify({ id: 'new-id', schema_id: 'family', traits: sent.traits }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  const created = await createIdentity({
    traits: { username: 'alice', email: 'alice@example.com' },
    metadataAdmin: { groups: ['family'] },
  });
  assert.equal(created.id, 'new-id');
  assert.ok(!('schema_id' in sent), 'schema_id must be left to Kratos default_schema_id');
  assert.deepEqual(sent.traits, { username: 'alice', email: 'alice@example.com' });
});

test('createIdentity: the email trait is declared verified (admin vouches), value lowercased to match Kratos', async () => {
  let sent;
  globalThis.fetch = async (_url, init) => {
    sent = JSON.parse(init.body);
    return new Response(JSON.stringify({ id: 'new-id', traits: sent.traits }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  await createIdentity({
    traits: { username: 'alice', email: 'Alice@Example.com' },
    metadataAdmin: { groups: ['family'] },
  });
  assert.deepEqual(sent.verifiable_addresses, [
    { value: 'alice@example.com', via: 'email', verified: true, status: 'completed' },
  ]);
});

test('createIdentity: no credentials block is sent, and a password in the input is ignored', async () => {
  let sent;
  globalThis.fetch = async (_url, init) => {
    sent = JSON.parse(init.body);
    return new Response(JSON.stringify({ id: 'new-id', traits: sent.traits }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  await createIdentity({
    traits: { username: 'alice', email: 'alice@example.com' },
    metadataAdmin: { groups: ['family'] },
    credentials: { password: { config: { password: 'hunter2hunter2' } } },
    password: 'hunter2hunter2',
  });
  assert.ok(!('credentials' in sent));
  assert.ok(!JSON.stringify(sent).includes('hunter2'));
});

// Invariant: the portal reads the shapes Kratos and Hydra actually send. The fixtures are full responses laid out
// from the generated SDK models (round-tripped below, so a key the SDK does not know cannot hide in them), and
// each drives the real SDK client and our handler over a stubbed fetch.

import { test, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { OAuth2ConsentRequestFromJSON, OAuth2ConsentRequestToJSON, SessionFromJSON, SessionToJSON } from '@ory/client-fetch';
import { getSession } from '../src/lib/kratos.ts';
import { handleConsent, loginRememberFor } from '../src/lib/oauth2-handlers.ts';
import { parseManifest } from '../src/lib/manifests.ts';
import { identity } from '../src/lib/test-builders.ts';

const fixture = (name) => JSON.parse(readFileSync(fileURLToPath(new URL(`../src/lib/fixtures/${name}`, import.meta.url)), 'utf8'));
const whoami = fixture('kratos-whoami-aal2.json');
const consentRequest = fixture('hydra-consent-request.json');

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

const wire = (model) => JSON.parse(JSON.stringify(model));
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

test('the fixtures are exactly what the SDK models serialize, so they carry no key the SDK would drop', () => {
  assert.deepEqual(wire(SessionToJSON(SessionFromJSON(whoami))), whoami);
  assert.deepEqual(wire(OAuth2ConsentRequestToJSON(OAuth2ConsentRequestFromJSON(consentRequest))), consentRequest);
});

test('a Kratos whoami body comes back from getSession as the session the gates read', async () => {
  const seen = [];
  globalThis.fetch = async (input, init) => {
    const req = new Request(input, init);
    seen.push(`${req.method} ${new URL(req.url).pathname}`);
    return json(whoami);
  };
  const session = await getSession('ory_kratos_session=abc');
  assert.deepEqual(seen, ['GET /sessions/whoami']);
  assert.equal(session.active, true);
  assert.equal(session.authenticator_assurance_level, 'aal2');
  assert.equal(session.identity.id, whoami.identity.id);
  assert.deepEqual(session.authentication_methods.map((m) => m.method), ['password', 'totp']);
  assert.equal(session.identity.traits.username, 'ada.lovelace');
  // The remembered sign-in lasts as long as the session: 24 hours from the fixture's issue time.
  assert.equal(loginRememberFor(session, new Date(whoami.issued_at).getTime()), 24 * 60 * 60);
});

test('a Hydra consent request is read and accepted with the scopes it asked for', async () => {
  const manifest = parseManifest(
    readFileSync(fileURLToPath(new URL('../../e2e/content/apps/grafana.yaml', import.meta.url)), 'utf8'),
    'grafana.yaml',
  );
  const member = identity({ id: consentRequest.subject, metadataAdmin: { groups: ['grafana-access'] } });
  let accepted;
  globalThis.fetch = async (input, init) => {
    const req = new Request(input, init);
    const { pathname } = new URL(req.url);
    if (req.method === 'GET' && pathname === '/admin/oauth2/auth/requests/consent') return json(consentRequest);
    if (req.method === 'PUT' && pathname === '/admin/oauth2/auth/requests/consent/accept') {
      accepted = await req.json();
      return json({ redirect_to: 'https://sso.othala.test/oauth2/auth?consent_verifier=v' });
    }
    throw new Error(`unexpected ${req.method} ${pathname}`);
  };
  const res = await handleConsent(new Request('https://sso.othala.test/auth/consent?consent_challenge=c0ffee'), {
    getIdentity: async () => member,
    manifest: (clientId) => (clientId === 'grafana' ? manifest : undefined),
  });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('Location'), 'https://sso.othala.test/oauth2/auth?consent_verifier=v');
  assert.deepEqual(accepted.grant_scope, consentRequest.requested_scope);
  assert.equal(accepted.remember, false);
});

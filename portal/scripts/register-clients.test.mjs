// Tests for the in-app OIDC client registrar in src/lib/register-clients.ts
// (CU2 item 2). Field-mapping (manifest oidc: → Hydra OAuth2Client body) is
// proven against a STUB OAuth2Api — no live Hydra is contacted. Create vs
// update branching, secret resolution, the consent-block exclusion, and the
// pre-flight lint are all exercised.
//
// Run with: tsx --test scripts/register-clients.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest } from '../src/lib/manifests.ts';
import {
  buildClientBody,
  registerClient,
  registerManifests,
  secretEnvVar,
} from '../src/lib/register-clients.ts';

// A 404-shaped error the registrar treats as "client does not exist".
// Mirrors @ory/client-fetch ResponseError: instanceof check + .response.status.
import { ResponseError } from '@ory/client-fetch';

function notFound() {
  return new ResponseError(new Response('', { status: 404 }), 'Not Found');
}

// Stub OAuth2Api recording calls. `existing` is the set of client_ids that
// already exist (so getOAuth2Client resolves); everything else 404s.
function stubApi(existing = new Set()) {
  const calls = { get: [], create: [], set: [] };
  return {
    calls,
    async getOAuth2Client({ id }) {
      calls.get.push(id);
      if (existing.has(id)) return { client_id: id };
      throw notFound();
    },
    async createOAuth2Client({ oAuth2Client }) {
      calls.create.push(oAuth2Client);
      return oAuth2Client;
    },
    async setOAuth2Client({ id, oAuth2Client }) {
      calls.set.push({ id, oAuth2Client });
      return oAuth2Client;
    },
  };
}

const KEEP_YAML = `
oidc:
  client_id: keep
  client_name: Vault
  grant_types:
    - authorization_code
    - refresh_token
  response_types:
    - code
  scope: openid email profile groups offline_access
  redirect_uris:
    - https://keep.othala.test/identity/connect/oidc-signin
  post_logout_redirect_uris:
    - https://keep.othala.test/
  token_endpoint_auth_method: client_secret_basic
  audience:
    - https://keep.othala.test
  skip_consent: true
  backchannel_logout_uri: https://keep.othala.test/identity/connect/oidc-logout
presentation:
  access:
    - keep
consent:
  emit_groups_claim: true
  roles:
    user:
      description: viewer
      claim_emit:
        groups: ["family"]
  group_role_map:
    family: user
`;

// ── buildClientBody field mapping ──────────────────────────────────────────

test('buildClientBody maps every oidc field exactly as apply-clients.sh did', () => {
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  const body = buildClientBody(m, 's3cr3t');

  assert.equal(body.client_id, 'keep');
  assert.equal(body.client_name, 'Vault');
  assert.deepEqual(body.grant_types, ['authorization_code', 'refresh_token']);
  assert.deepEqual(body.response_types, ['code']);
  // scope is the on-the-wire space-separated string, not an array.
  assert.equal(body.scope, 'openid email profile groups offline_access');
  assert.deepEqual(body.redirect_uris, ['https://keep.othala.test/identity/connect/oidc-signin']);
  assert.deepEqual(body.post_logout_redirect_uris, ['https://keep.othala.test/']);
  assert.equal(body.token_endpoint_auth_method, 'client_secret_basic');
  assert.deepEqual(body.audience, ['https://keep.othala.test']);
  assert.equal(body.skip_consent, true);
  assert.equal(
    body.backchannel_logout_uri,
    'https://keep.othala.test/identity/connect/oidc-logout',
  );
  assert.equal(body.client_secret, 's3cr3t');
});

test('buildClientBody NEVER forwards any consent: block field to Hydra', () => {
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  const body = buildClientBody(m, 's3cr3t');
  const keys = Object.keys(body);
  for (const forbidden of [
    'roles',
    'group_role_map',
    'emit_groups_claim',
    'skip_access_check',
    'claim_emit',
    'consent',
  ]) {
    assert.ok(!keys.includes(forbidden), `Hydra body leaked consent field: ${forbidden}`);
  }
});

test('buildClientBody omits empty optional fields (client_credentials shape)', () => {
  const m = parseManifest(
    `
oidc:
  client_id: api
  client_name: API Service
  grant_types:
    - client_credentials
  response_types: []
  scope: api
  audience:
    - https://api.othala.test
  token_endpoint_auth_method: client_secret_basic
  skip_consent: true
consent:
  skip_access_check: true
`,
    'api.yaml',
  );
  const body = buildClientBody(m, 'apisecret');
  assert.equal(body.scope, 'api');
  assert.deepEqual(body.grant_types, ['client_credentials']);
  // No redirect_uris / response_types / post_logout / backchannel for a c_c client.
  assert.ok(!('redirect_uris' in body));
  assert.ok(!('response_types' in body));
  assert.ok(!('post_logout_redirect_uris' in body));
  assert.ok(!('backchannel_logout_uri' in body));
});

test('buildClientBody sets backchannel_logout_session_required only when true', () => {
  const off = buildClientBody(parseManifest(KEEP_YAML, 'keep.yaml'), 'x');
  assert.ok(!('backchannel_logout_session_required' in off));

  const on = buildClientBody(
    parseManifest(
      `
oidc:
  client_id: keep
  backchannel_logout_session_required: true
  audience: [https://keep.othala.test]
consent: {}
`,
      'keep.yaml',
    ),
    'x',
  );
  assert.equal(on.backchannel_logout_session_required, true);
});

test('buildClientBody omits client_secret when undefined (dry-run posture)', () => {
  const body = buildClientBody(parseManifest(KEEP_YAML, 'keep.yaml'), undefined);
  assert.ok(!('client_secret' in body));
});

// ── secretEnvVar naming ────────────────────────────────────────────────────

test('secretEnvVar uppercases the client_id (apply-clients.sh convention)', () => {
  assert.equal(secretEnvVar('keep'), 'KEEP_CLIENT_SECRET');
  assert.equal(secretEnvVar('llm'), 'LLM_CLIENT_SECRET');
  assert.equal(secretEnvVar('promptdesk'), 'PROMPTDESK_CLIENT_SECRET');
  assert.equal(secretEnvVar('my_app'), 'MY_APP_CLIENT_SECRET');
});

test('secretEnvVar throws loudly on a hyphenated client_id (fail-loud contract)', () => {
  // "prompt-desk" → "PROMPT-DESK_CLIENT_SECRET" is an INVALID POSIX env var.
  // The function must throw with a clear message naming the client_id and the
  // would-be env var name, NOT silently return the broken string.
  assert.throws(
    () => secretEnvVar('prompt-desk'),
    (err) =>
      /POSIX env-var stem/.test(err.message) &&
      /prompt-desk/.test(err.message) &&
      /PROMPT-DESK_CLIENT_SECRET/.test(err.message),
    'expected a loud throw, not a silent invalid env var name',
  );
});

test('secretEnvVar throws on a client_id with a dot', () => {
  assert.throws(
    () => secretEnvVar('my.app'),
    (err) => /POSIX env-var stem/.test(err.message) && /MY\.APP_CLIENT_SECRET/.test(err.message),
  );
});

test('secretEnvVar throws on a client_id starting with a digit', () => {
  assert.throws(
    () => secretEnvVar('2app'),
    (err) => /POSIX env-var stem/.test(err.message),
  );
});

// ── create vs update branching ─────────────────────────────────────────────

test('registerClient CREATES when the client does not exist (404)', async () => {
  const api = stubApi(new Set());
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  const res = await registerClient(api, m, 'sec');
  assert.equal(res.action, 'created');
  assert.equal(api.calls.create.length, 1);
  assert.equal(api.calls.set.length, 0);
  assert.equal(api.calls.create[0].client_id, 'keep');
});

test('registerClient UPDATES when the client already exists (200)', async () => {
  const api = stubApi(new Set(['keep']));
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  const res = await registerClient(api, m, 'sec');
  assert.equal(res.action, 'updated');
  assert.equal(api.calls.set.length, 1);
  assert.equal(api.calls.create.length, 0);
  assert.equal(api.calls.set[0].id, 'keep');
});

test('registerClient rethrows a non-404 error (does not silently create)', async () => {
  const api = {
    calls: { get: [], create: [], set: [] },
    async getOAuth2Client() {
      throw new ResponseError(new Response('', { status: 500 }), 'boom');
    },
    async createOAuth2Client() {
      throw new Error('should not be called');
    },
    async setOAuth2Client() {
      throw new Error('should not be called');
    },
  };
  await assert.rejects(() => registerClient(api, parseManifest(KEEP_YAML, 'keep.yaml'), 'sec'));
});

// ── registerManifests: secret resolution + lint pre-flight ─────────────────

test('registerManifests reads each secret from the injected env', async () => {
  const api = stubApi(new Set());
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  await registerManifests([m], {
    api,
    env: { KEEP_CLIENT_SECRET: 'env-secret' },
  });
  assert.equal(api.calls.create[0].client_secret, 'env-secret');
});

test('registerManifests throws when a required secret is missing', async () => {
  const api = stubApi(new Set());
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  await assert.rejects(
    () => registerManifests([m], { api, env: {} }),
    /KEEP_CLIENT_SECRET not set/,
  );
});

test('registerManifests tolerates a missing secret with allowMissingSecret (dry run)', async () => {
  const api = stubApi(new Set());
  const m = parseManifest(KEEP_YAML, 'keep.yaml');
  await registerManifests([m], { api, env: {}, allowMissingSecret: true });
  assert.ok(!('client_secret' in api.calls.create[0]));
});

test('registerManifests runs the validateClients lint pre-flight and ABORTS on a bad set', async () => {
  const api = stubApi(new Set());
  // Missing audience → validateClients fails → nothing is registered.
  const bad = parseManifest(
    `
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
consent: {}
`,
    'novel.yaml',
  );
  await assert.rejects(
    () => registerManifests([bad], { api, env: { NOVEL_CLIENT_SECRET: 'x' } }),
    /manifest validation failed/,
  );
  assert.equal(api.calls.create.length, 0, 'no client should be registered on a failed lint');
});

test('registerManifests with skipValidation registers a crafted single manifest', async () => {
  const api = stubApi(new Set());
  const m = parseManifest(
    `
oidc:
  client_id: solo
  audience: [https://solo.othala.test]
  redirect_uris: [https://solo.othala.test/cb]
consent: {}
`,
    'solo.yaml',
  );
  const res = await registerManifests([m], {
    api,
    env: { SOLO_CLIENT_SECRET: 's' },
    skipValidation: true,
  });
  assert.equal(res.length, 1);
  assert.equal(res[0].action, 'created');
});

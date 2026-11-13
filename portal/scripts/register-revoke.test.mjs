// Invariant: a served manifest's access-relevant change, or a registered app's manifest going absent, ends that app's grants once; nothing else does, and no client is ever deleted.

import { test, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ResponseError } from '@ory/client-fetch';
import { parseManifest, setContentDir, invalidateManifestCache } from '../src/lib/manifests.ts';
import { accessFingerprint, registerAllClients, registerManifests } from '../src/lib/register-clients.ts';

const manifestYaml = (id, { access = [id], map = '', extra = '', scope = 'openid profile', name = id } = {}) => `
oidc:
  client_id: ${id}
  client_name: ${name}
  scope: ${scope}
  audience:
    - https://${id}.example.com
  redirect_uris:
    - https://${id}.example.com/cb
presentation:
  access:
${access.map((g) => `    - ${g}`).join('\n')}
consent:
  roles:
    admin: { description: a, claim_emit: { groups: [${id}-admin] } }
    user: { description: u, claim_emit: { groups: [${id}-user] } }
${map}${extra}`;

const wiki = (opts) => parseManifest(manifestYaml('wiki', opts), 'wiki.yaml');

function hydra(initial = {}) {
  const clients = new Map(Object.entries(initial));
  const log = [];
  return {
    clients,
    log,
    async getOAuth2Client({ id }) {
      if (!clients.has(id)) throw new ResponseError(new Response('', { status: 404 }), 'nf');
      return structuredClone(clients.get(id));
    },
    async createOAuth2Client({ oAuth2Client }) {
      log.push(['create', oAuth2Client.client_id]);
      clients.set(oAuth2Client.client_id, structuredClone(oAuth2Client));
      return oAuth2Client;
    },
    async setOAuth2Client({ id, oAuth2Client }) {
      log.push(['set', id]);
      clients.set(id, structuredClone(oAuth2Client));
      return oAuth2Client;
    },
    async revokeOAuth2ConsentSessions({ subject, client }) {
      log.push(['revoke', client, subject]);
    },
    async listOAuth2ClientsRaw() {
      log.push(['list']);
      return { value: async () => [...clients.values()].map((c) => structuredClone(c)), raw: { headers: new Headers() } };
    },
    async patchOAuth2Client({ id, jsonPatch }) {
      log.push(['patch', id]);
      const c = clients.get(id);
      for (const op of jsonPatch) {
        assert.equal(op.path, '/metadata');
        c.metadata = op.value;
      }
    },
    async deleteOAuth2Client() {
      assert.fail('a client is never deleted');
    },
  };
}

const subjects = async () => ['ada', 'grace'];
const env = { WIKI_CLIENT_SECRET: 's', GRAFANA_CLIENT_SECRET: 's' };
const reconcile = (api, manifests) => registerManifests(manifests, { api, env, subjects });
const revokes = (api) => api.log.filter((e) => e[0] === 'revoke');

test('first sight of a client stores its fingerprint and revokes nothing', async () => {
  const api = hydra();
  await reconcile(api, [wiki()]);
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, accessFingerprint(wiki()));
  assert.deepEqual(revokes(api), []);
});

test('an unchanged manifest revokes nothing on the next reconcile', async () => {
  const api = hydra();
  await reconcile(api, [wiki()]);
  await reconcile(api, [wiki({ name: 'Renamed', extra: '' })]);
  assert.deepEqual(revokes(api), []);
});

test('an existing client with no stored fingerprint is baselined, not revoked', async () => {
  const api = hydra({ wiki: { client_id: 'wiki' } });
  await reconcile(api, [wiki()]);
  assert.deepEqual(revokes(api), []);
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, accessFingerprint(wiki()));
});

test('an access change revokes that client for every identity, then stores the new fingerprint; it survives a restart', async () => {
  const api = hydra();
  await reconcile(api, [wiki()]);
  api.log.length = 0;
  // A new process has no memory: the stored fingerprint is all it has.
  await reconcile(api, [wiki({ access: ['wiki', 'kids'] })]);
  assert.deepEqual(revokes(api), [['revoke', 'wiki', 'ada'], ['revoke', 'wiki', 'grace']]);
  assert.ok(api.log.findIndex((e) => e[0] === 'revoke') < api.log.findIndex((e) => e[0] === 'set'), 'revoke runs before the new fingerprint is stored');
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, accessFingerprint(wiki({ access: ['wiki', 'kids'] })));
  api.log.length = 0;
  await reconcile(api, [wiki({ access: ['wiki', 'kids'] })]);
  assert.deepEqual(revokes(api), [], 'once only');
});

test('a failed revoke leaves the old fingerprint so the next reconcile retries', async () => {
  const api = hydra();
  await reconcile(api, [wiki()]);
  const stored = api.clients.get('wiki').metadata.othala.fingerprint;
  const real = api.revokeOAuth2ConsentSessions;
  api.revokeOAuth2ConsentSessions = async () => { throw new ResponseError(new Response('', { status: 500 }), 'down'); };
  await assert.rejects(() => reconcile(api, [wiki({ access: ['wiki', 'kids'] })]), /wiki/);
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, stored);
  api.revokeOAuth2ConsentSessions = real;
  api.log.length = 0;
  await reconcile(api, [wiki({ access: ['wiki', 'kids'] })]);
  assert.equal(revokes(api).length, 2);
});

test('a subject with nothing to revoke is not an error', async () => {
  const api = hydra();
  await reconcile(api, [wiki()]);
  api.revokeOAuth2ConsentSessions = async () => { throw new ResponseError(new Response('', { status: 404 }), 'nf'); };
  await reconcile(api, [wiki({ access: ['wiki', 'kids'] })]);
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, accessFingerprint(wiki({ access: ['wiki', 'kids'] })));
});

test('each access-relevant field moves the fingerprint; presentation and transport fields do not', () => {
  const base = accessFingerprint(wiki());
  const moves = {
    access: wiki({ access: ['wiki', 'kids'] }),
    group_role_map: wiki({ map: '  group_role_map:\n    parents: admin\n' }),
    roles: parseManifest(manifestYaml('wiki').replace('\n    user:', '\n    guest: { description: g, claim_emit: { groups: [g] } }\n    user:'), 'wiki.yaml'),
    claim_emit: parseManifest(manifestYaml('wiki').replace('[wiki-admin]', '[wiki-owner]'), 'wiki.yaml'),
    emit_groups_claim: wiki({ extra: '  emit_groups_claim: false\n' }),
    scopes: wiki({ scope: 'openid profile groups' }),
    skip_access_check: wiki({ extra: '  skip_access_check: true\n' }),
  };
  for (const [field, m] of Object.entries(moves)) assert.notEqual(accessFingerprint(m), base, field);
  assert.equal(accessFingerprint(wiki({ name: 'Another name' })), base);
  assert.equal(accessFingerprint(parseManifest(manifestYaml('wiki').replace('https://wiki.example.com/cb', 'https://wiki.example.com/other'), 'wiki.yaml')), base);
  assert.equal(accessFingerprint(wiki({ access: ['wiki'], scope: 'profile  openid' })), accessFingerprint(wiki({ scope: 'openid profile' })), 'scope order is not access');
});

// registerAllClients reads the manifest directory: these tests build one.
const roots = [];
afterEach(() => {
  setContentDir(undefined);
  invalidateManifestCache();
  while (roots.length) rmSync(roots.pop(), { recursive: true, force: true });
});
function apps(files) {
  const root = mkdtempSync(join(tmpdir(), 'register-revoke-'));
  roots.push(root);
  mkdirSync(join(root, 'apps'));
  for (const [name, text] of Object.entries(files)) writeFileSync(join(root, 'apps', name), text);
  setContentDir(root);
  invalidateManifestCache();
  return root;
}
const ours = (fingerprint = 'x', extra = {}) => ({ metadata: { othala: { fingerprint, ...extra } } });
const retire = (api) => registerAllClients({ api, env, subjects });

test('a registered client whose manifest is absent is revoked once and marked retired, never deleted', async () => {
  apps({ 'wiki.yaml': manifestYaml('wiki') });
  const api = hydra({ gone: { client_id: 'gone', ...ours() }, stranger: { client_id: 'stranger', metadata: { team: 'x' } }, plain: { client_id: 'plain' } });
  await retire(api);
  assert.deepEqual(revokes(api), [['revoke', 'gone', 'ada'], ['revoke', 'gone', 'grace']]);
  assert.equal(api.clients.get('gone').metadata.othala.retired, true);
  assert.equal(api.clients.get('gone').metadata.othala.fingerprint, 'x');
  assert.deepEqual(api.clients.get('stranger').metadata, { team: 'x' });
  assert.ok(api.clients.has('gone') && api.clients.has('stranger') && api.clients.has('plain'));
  api.log.length = 0;
  await retire(api);
  assert.deepEqual(revokes(api), [], 'once only');
});

test('a repeated client page token stops the retire pass with an error and retires nothing further', async () => {
  apps({ 'wiki.yaml': manifestYaml('wiki') });
  const api = hydra({ gone: { client_id: 'gone', ...ours() } });
  api.listOAuth2ClientsRaw = async () => ({
    value: async () => [],
    raw: { headers: new Headers({ link: '<http://hydra/admin/clients?page_token=t2>; rel="next"' }) },
  });
  await assert.rejects(() => retire(api), /repeated page token/);
});

test('a retired client whose manifest returns is served again without a revoke', async () => {
  apps({ 'wiki.yaml': manifestYaml('wiki') });
  const api = hydra();
  await retire(api);
  const fp = api.clients.get('wiki').metadata.othala.fingerprint;
  api.clients.get('wiki').metadata.othala.retired = true;
  api.log.length = 0;
  await retire(api);
  assert.equal(api.clients.get('wiki').metadata.othala.retired, undefined);
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, fp);
  assert.deepEqual(revokes(api), []);
});

test('nothing is retired while any manifest file is quarantined', async () => {
  apps({ 'wiki.yaml': manifestYaml('wiki'), 'typo.yaml': manifestYaml('typo').replace('skip_consent', 'x') + '\n  skip_access_check: no\n' });
  const api = hydra({ gone: { client_id: 'gone', ...ours() } });
  await retire(api);
  assert.deepEqual(revokes(api), []);
  assert.ok(!api.log.some((e) => e[0] === 'list' || e[0] === 'patch'));
});

test('nothing is retired when no manifest is served', async () => {
  apps({});
  const api = hydra({ gone: { client_id: 'gone', ...ours() } });
  await retire(api);
  assert.deepEqual(api.log, []);
});

test('nothing is retired when the apps directory is missing or unreadable', async () => {
  const root = apps({});
  setContentDir(join(root, 'nowhere'));
  invalidateManifestCache();
  let api = hydra({ gone: { client_id: 'gone', ...ours() } });
  await retire(api);
  assert.deepEqual(api.log, []);
  writeFileSync(join(root, 'apps-as-file'), '');
  mkdirSync(join(root, 'file-root'));
  writeFileSync(join(root, 'file-root', 'apps'), 'not a directory');
  setContentDir(join(root, 'file-root'));
  invalidateManifestCache();
  api = hydra({ gone: { client_id: 'gone', ...ours() } });
  await retire(api).catch(() => {});
  assert.ok(!api.log.some((e) => e[0] === 'revoke' || e[0] === 'patch'));
});

test('a broken manifest for an existing client revokes nothing and keeps the stored fingerprint', async () => {
  apps({ 'wiki.yaml': manifestYaml('wiki') + '\n  skip_access_check: no\n', 'grafana.yaml': manifestYaml('grafana') });
  const api = hydra({ wiki: { client_id: 'wiki', ...ours('previous') }, grafana: { client_id: 'grafana' } });
  await retire(api);
  assert.deepEqual(revokes(api), []);
  assert.equal(api.clients.get('wiki').metadata.othala.fingerprint, 'previous');
  assert.ok(!api.log.some((e) => e[0] === 'patch'));
});

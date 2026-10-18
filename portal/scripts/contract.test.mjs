// Invariant: contract/*.schema.json pins exactly what the portal depends on in the Ory configs and nothing else, so
// a change to any other template value never fails a consumer whose files still meet it; every pinned key fails when
// mutated; secrets and instance values accept any placeholder; the pins agree with the routes and pages they name.

import { afterAll, test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse, stringify } from 'yaml';
import { checkOry } from '../src/lib/contract.ts';
import { render, SECRETS } from '../src/lib/render.ts';
import { ADMIN_POST } from '../src/server/listen.ts';

const root = fileURLToPath(new URL('../../', import.meta.url));
const portal = fileURLToPath(new URL('../', import.meta.url));
const example = join(root, 'deploy/example');
const scratch = mkdtempSync(join(tmpdir(), 'othala-contract-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const env = {
  ...Object.fromEntries(
    readFileSync(join(example, 'othala.env.example'), 'utf8')
      .split('\n')
      .filter((l) => /^[A-Z_][A-Z0-9_]*=/.test(l))
      .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
  ),
  ...Object.fromEntries(SECRETS.map((n) => [n, `fake-${n.toLowerCase()}`])),
};
const rendered = Object.fromEntries(render(root, join(example, 'content'), env).map((f) => [f.path, f.content]));
const kratos = parse(rendered['kratos/kratos.yml']);
const hydra = parse(rendered['hydra/hydra.yml']);

let n = 0;
function files(k, h) {
  const dir = join(scratch, String(n++));
  const kratosFile = join(dir, 'kratos.yml');
  const hydraFile = join(dir, 'hydra.yml');
  mkdirSync(dir);
  writeFileSync(kratosFile, stringify(k));
  writeFileSync(hydraFile, stringify(h));
  return { kratos: kratosFile, hydra: hydraFile };
}
const run = (k = kratos, h = hydra) => checkOry(root, files(structuredClone(k), structuredClone(h)));
const edit = (doc, fn) => {
  const d = structuredClone(doc);
  fn(d);
  return d;
};

test('the rendered deploy/example passes, through the CLI', () => {
  assert.deepEqual(run(), []);
  const dir = join(scratch, 'cli');
  mkdirSync(dir);
  for (const [path, out] of [['kratos/kratos.yml', 'k.yml'], ['hydra/hydra.yml', 'h.yml'], ['kratos/identity.schema.json', 'i.json'], ['kratos/hooks/recovery-gate.jsonnet', 'g.jsonnet']]) {
    writeFileSync(join(dir, out), rendered[path]);
  }
  const cli = (...args) => spawnSync(join(portal, 'node_modules/.bin/tsx'), [join(portal, 'src/server/config-cli.ts'), 'check-ory', '--policy', root, ...args], { encoding: 'utf8' });
  const ok = ['--kratos', join(dir, 'k.yml'), '--hydra', join(dir, 'h.yml'), '--identity-schema', join(dir, 'i.json'), '--jsonnet', join(dir, 'g.jsonnet')];
  assert.equal(cli(...ok).status, 0);
  assert.equal(cli('--kratos', join(dir, 'k.yml')).status, 2);
  writeFileSync(join(dir, 'k.yml'), stringify(edit(kratos, (k) => (k.session.whoami.required_aal = 'SECRET-VALUE'))));
  const bad = cli(...ok);
  assert.equal(bad.status, 1);
  assert.ok(bad.stderr.includes('/session/whoami/required_aal'));
  assert.ok(!bad.stderr.includes('SECRET-VALUE'));
});

const hook = (k, ...path) => path.reduce((o, p) => o[p], k.selfservice.flows);
// pointer, mutation, consumer: each pinned key, where the portal depends on it (a symbol, never a line).
const KRATOS_PINS = [
  ['/serve/admin/base_url', (k) => (k.serve.admin.base_url = 'http://kratos:9/'), 'KRATOS_ADMIN_URL, constants.ts'],
  ['/serve/admin/port', (k) => (k.serve.admin.port = 1), 'KRATOS_ADMIN_URL, constants.ts'],
  ['/serve/public/port', (k) => (k.serve.public = { port: 1 }), 'KRATOS_PUBLIC_URL, constants.ts'],
  ['/serve/admin/host', (k) => (k.serve.admin.host = 1), 'KRATOS_ADMIN_BIND_HOST, env-names.ts'],
  ...['error', 'settings', 'recovery', 'verification', 'login', 'registration'].map((f) => [`/selfservice/flows/${f}/ui_url`, (k) => (k.selfservice.flows[f].ui_url = 'https://a.example/x'), `pages/auth/${f}.astro`]),
  ['/selfservice/flows/settings/after/passkey/hooks', (k) => (hook(k, 'settings', 'after', 'passkey').hooks[0].config.url += 'x'), 'handlePasskeyPrune, listen.ts'],
  ['/selfservice/flows/settings/after/webauthn/hooks', (k) => (hook(k, 'settings', 'after', 'webauthn').hooks[0].config.method = 'GET'), 'handleSecondFactorGate, listen.ts'],
  ['/selfservice/flows/settings/after/totp/hooks', (k) => (hook(k, 'settings', 'after', 'totp').hooks[0].config.auth.config.name = 'X-Key'), 'handleSecondFactorGate, listen.ts'],
  ['/selfservice/flows/settings/after/profile/hooks', (k) => hook(k, 'settings', 'after', 'profile').hooks.pop(), 'handleProfileSessions, listen.ts'],
  ['/selfservice/flows/settings/after/profile/hooks', (k) => (hook(k, 'settings', 'after', 'profile').hooks[0].config.auth.config.value = 'Bearer'), 'refuseUnlessHookBearer, listen.ts'],
  ['/selfservice/flows/recovery/after/hooks', (k) => (hook(k, 'recovery', 'after').hooks[0].config.auth.type = 'basic_auth'), 'handleRecoveryGate, listen.ts'],
  ['/selfservice/flows/recovery/after/hooks', (k) => (hook(k, 'recovery', 'after').hooks[0].config.auth.config.value = 'Bearer two words'), 'refuseUnlessHookBearer, listen.ts'],
  ['/selfservice/flows/login/after/code/hooks', (k) => (hook(k, 'login', 'after', 'code').hooks[0].config.auth.config.in = 'cookie'), 'handleLoginCodeGate, listen.ts'],
  ['/session/whoami/required_aal', (k) => (k.session.whoami.required_aal = 'highest_available'), 'getSession, kratos.ts; handleForwardAuth, api/forward-auth.ts'],
  ['/session/cookie/name', (k) => (k.session.cookie.name = 'sid'), 'getSession, kratos.ts'],
  ['/session/cookie/domain', (k) => (k.session.cookie.domain = 1), 'OTHALA_APEX, config.ts'],
  ['/identity/default_schema_id', (k) => (k.identity.default_schema_id = 'other'), 'schema_id, admin-api.ts'],
  ['/identity/schemas', (k) => (k.identity.schemas[0].id = 'other'), 'schema_id, admin-api.ts'],
  ['/identity/schemas', (k) => (k.identity.schemas[0].url = 'file:///etc/schema.json'), 'identity.schema.json, Containerfile'],
  ['/selfservice/flows/login/after', (k) => delete k.selfservice.flows.login.after, 'handleLoginCodeGate, listen.ts'],
];
const HYDRA_PINS = [
  ...['login', 'consent', 'logout'].map((p) => [`/urls/${p}`, (h) => (h.urls[p] = 'https://a.example/x'), `pages/oauth2/${p}.ts`]),
  ['/urls', (h) => delete h.urls.consent, 'pages/oauth2/consent.ts'],
  ['/serve/admin/port', (h) => (h.serve.admin.port = 1), 'HYDRA_ADMIN_URL, constants.ts'],
  ['/serve/admin/host', (h) => (h.serve.admin.host = 1), 'HYDRA_ADMIN_BIND_HOST, env-names.ts'],
];

test.each(KRATOS_PINS)('kratos %s fails when mutated (consumer: %s)', (pointer, mutate) => {
  const v = run(edit(kratos, mutate), hydra);
  assert.ok(v.some((x) => x.startsWith(`kratos: ${pointer}`)), v.join('\n'));
});

test.each(HYDRA_PINS)('hydra %s fails when mutated (consumer: %s)', (pointer, mutate) => {
  const v = run(kratos, edit(hydra, mutate));
  assert.ok(v.some((x) => x.startsWith(`hydra: ${pointer}`)), v.join('\n'));
});

test('a value outside the contract changes freely', () => {
  const k = edit(kratos, (d) => {
    d.session.lifespan = '1h';
    d.log = { level: 'debug', format: 'text' };
    d.selfservice.flows.settings.privileged_session_max_age = '1m';
    d.selfservice.flows.settings.after.passkey.hooks[0].config.can_interrupt = true;
    d.extra = { anything: [1, 2] };
  });
  const h = edit(hydra, (d) => {
    d.ttl = { login_consent_request: '1h' };
    d.log = { level: 'debug' };
  });
  assert.deepEqual(run(k, h), []);
});

test('consumer placeholders pass wherever the template has a secret or an instance value', () => {
  const ph = (name) => `\${sops:example.${name}}`;
  const k = edit(kratos, (d) => {
    for (const h of [...hook(d, 'settings', 'after', 'profile').hooks, hook(d, 'recovery', 'after').hooks[0]]) h.config.auth.config.value = `Bearer ${ph('gate')}`;
    d.dsn = ph('dsn');
    d.secrets = { cookie: [ph('cookie')], cipher: [ph('cipher')] };
    d.serve.admin.host = ph('bind');
    d.serve.public.base_url = ph('url');
    d.session.cookie.domain = ph('apex');
    d.selfservice.flows.login.ui_url = `${ph('url')}/auth/login`;
  });
  assert.deepEqual(run(k, edit(hydra, (d) => (d.secrets = { system: [ph('system')] }))), []);
});

test('the policy files must equal the image copies, compared as JSON and as trimmed text', () => {
  const identity = rendered['kratos/identity.schema.json'];
  const jsonnet = rendered['kratos/hooks/recovery-gate.jsonnet'];
  const check = (i, j) => {
    const dir = join(scratch, `policy${n++}`);
    mkdirSync(dir);
    writeFileSync(join(dir, 'i.json'), i);
    writeFileSync(join(dir, 'g.jsonnet'), j);
    return checkOry(root, { ...files(kratos, hydra), identitySchema: join(dir, 'i.json'), jsonnet: join(dir, 'g.jsonnet') });
  };
  const reordered = JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(identity)).reverse()));
  assert.deepEqual(check(reordered, `${jsonnet}\n\n  \n`), []);
  assert.equal(check(identity.replace('"traits"', '"traitz"'), jsonnet).length, 1);
  assert.equal(check(identity, `${jsonnet}// edit`).length, 1);
  assert.equal(check('not json', jsonnet).length, 1);
});

const pathsOf = (doc) => JSON.stringify(doc).match(/"const":"([^"]+)"/g) ?? [];

test('the contract names exactly the admin webhook routes', () => {
  const schema = JSON.parse(readFileSync(join(root, 'contract/kratos.schema.json'), 'utf8'));
  const paths = new Set(pathsOf(schema).map((c) => c.slice(9, -1)).filter((u) => u.startsWith('http://othala:4431')).map((u) => new URL(u).pathname));
  assert.deepEqual([...paths].sort(), [...ADMIN_POST.keys()].sort());
});

test('every ui_url and oauth2 page the contract names exists', () => {
  const pin = (name, re) => [...readFileSync(join(root, `contract/${name}.schema.json`), 'utf8').matchAll(re)].map((m) => m[1]);
  const auth = readdirSync(join(portal, 'src/pages/auth')).map((f) => f.replace(/\.\w+$/, ''));
  const oauth2 = readdirSync(join(portal, 'src/pages/oauth2')).map((f) => f.replace(/\.\w+$/, ''));
  const flows = pin('kratos', /"pattern": "\/auth\/(\w+)\$"/g);
  assert.equal(flows.length, 6);
  // Registration is disabled in the template, so no page serves its ui_url.
  for (const f of flows.filter((x) => x !== 'registration')) assert.ok(auth.includes(f), f);
  const grants = pin('hydra', /"pattern": "\/oauth2\/(\w+)\$"/g);
  assert.equal(grants.length, 3);
  for (const f of grants) assert.ok(oauth2.includes(f), f);
});

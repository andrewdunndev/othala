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
import { PRIVILEGED_WINDOW_MS } from '../src/lib/settings-view.ts';
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
  writeFileSync(join(dir, 'i.json'), rendered['kratos/identity.schema.json']);
  writeFileSync(join(dir, 'g.jsonnet'), rendered['kratos/hooks/recovery-gate.jsonnet']);
  return { kratos: kratosFile, hydra: hydraFile, identitySchema: join(dir, 'i.json'), jsonnet: join(dir, 'g.jsonnet') };
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
  const good = cli(...ok);
  assert.equal(good.status, 0);
  assert.equal(good.stderr, '');
  for (const drop of [0, 2, 4, 6]) assert.equal(cli(...ok.filter((_, i) => i !== drop && i !== drop + 1)).status, 2);
  writeFileSync(join(dir, 'k.yml'), stringify(edit(kratos, (k) => (hook(k, 'recovery', 'after').hooks[0].config.auth.config.value = 'Bearer two SECRET-VALUE'))));
  const bad = cli(...ok);
  assert.equal(bad.status, 1);
  assert.ok(bad.stderr.includes('/selfservice/flows/recovery/after/hooks'));
  assert.ok(!bad.stderr.includes('SECRET-VALUE'));
}, 30_000);

const hook = (k, ...path) => path.reduce((o, p) => o[p], k.selfservice.flows);
// pointer, mutation, consumer: each pinned key, where the portal depends on it (a symbol, never a line).
const KRATOS_PINS = [
  ['/serve/admin/port', (k) => (k.serve.admin.port = 1), 'KRATOS_ADMIN_URL, constants.ts'],
  ['/serve/public/port', (k) => (k.serve.public = { port: 1 }), 'KRATOS_PUBLIC_URL, constants.ts'],
  ...['error', 'settings', 'recovery', 'verification', 'login'].map((f) => [`/selfservice/flows/${f}/ui_url`, (k) => (k.selfservice.flows[f].ui_url = 'https://a.example/x'), `pages/auth/${f}.astro`]),
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
  ['/selfservice/flows/registration/enabled', (k) => (k.selfservice.flows.registration.enabled = true), 'no signup route: members arrive by invite, admin-api.ts'],
  ['/selfservice/flows/registration', (k) => delete k.selfservice.flows.registration, 'no signup route: members arrive by invite, admin-api.ts'],
  ['/selfservice/methods/code/mfa_enabled', (k) => (k.selfservice.methods.code.mfa_enabled = true), 'handleLoginCodeGate, listen.ts: code login must stay a first factor'],
  ['/selfservice/flows/settings/required_aal', (k) => (k.selfservice.flows.settings.required_aal = 'aal1'), 'handleSecondFactorGate, listen.ts'],
  ['', (k) => (k.oauth2_provider = { url: 'http://hydra:4445' }), 'oauth2 challenges ride Hydra urls, oauth2-handlers.ts'],
  ['/session/whoami', (k) => delete k.session.whoami.required_aal, 'getSession, kratos.ts'],
  ['/identity/schemas', (k) => k.identity.schemas.unshift({ id: 'family', url: 'file:///elsewhere.json' }), 'schema_id, admin-api.ts'],
  ['/identity/schemas', (k) => (k.identity.schemas[0].url = 'file:///etc/config/kratos/other/identity.schema.json'), 'identity.schema.json, Containerfile'],
  ['/identity/default_schema_id', (k) => (k.identity.default_schema_id = 'other'), 'schema_id, admin-api.ts'],
  ['/identity/schemas', (k) => (k.identity.schemas[0].id = 'other'), 'schema_id, admin-api.ts'],
  ['/identity/schemas', (k) => (k.identity.schemas[0].url = 'file:///etc/schema.json'), 'identity.schema.json, Containerfile'],
  ['/selfservice/flows/settings/privileged_session_max_age', (k) => (k.selfservice.flows.settings.privileged_session_max_age = '1h'), 'PRIVILEGED_WINDOW_MS, settings-view.ts'],
  ['/selfservice/flows/settings/after/passkey/hooks', (k) => (hook(k, 'settings', 'after', 'passkey').hooks[0].config.can_interrupt = true), 'handlePasskeyPrune, listen.ts: a failed prune must not block the save'],
  ['/selfservice/flows/settings/after/profile/hooks', (k) => (hook(k, 'settings', 'after', 'profile').hooks[1].config.can_interrupt = true), 'handleProfileSessions, listen.ts: best-effort'],
  ['/selfservice/flows/settings/after/webauthn/hooks', (k) => (hook(k, 'settings', 'after', 'webauthn').hooks[0].config.can_interrupt = false), 'handleSecondFactorGate, listen.ts: a gate refuses by interrupting'],
  ['/selfservice/flows/recovery/after/hooks', (k) => (hook(k, 'recovery', 'after').hooks[0].config.can_interrupt = false), 'handleRecoveryGate, listen.ts'],
  ['/selfservice/flows/login/after/code/hooks', (k) => (hook(k, 'login', 'after', 'code').hooks[0].config.can_interrupt = false), 'handleLoginCodeGate, listen.ts'],
  ['/selfservice/flows/recovery/after/hooks', (k) => (hook(k, 'recovery', 'after').hooks[0].config.response.ignore = true), 'handleRecoveryGate, listen.ts: a 403 must reach the flow'],
  ['/selfservice/flows/settings/after/passkey/hooks', (k) => (hook(k, 'settings', 'after', 'passkey').hooks[0].config.response.ignore = false), 'handlePasskeyPrune, listen.ts'],
  ['/selfservice/flows/login/after/code/hooks', (k) => (hook(k, 'login', 'after', 'code').hooks[0].config.response.parse = true), 'handleLoginCodeGate, listen.ts'],
  ['/selfservice/flows/recovery/after/hooks', (k) => (hook(k, 'recovery', 'after').hooks[0].config.body = 'file:///x.jsonnet'), 'recovery-gate.jsonnet, Containerfile'],
  ['/selfservice/flows/settings/after/totp/hooks', (k) => delete hook(k, 'settings', 'after', 'totp').hooks[0].config.body, 'recovery-gate.jsonnet, Containerfile'],
  ['/selfservice/flows/login/after', (k) => delete k.selfservice.flows.login.after, 'handleLoginCodeGate, listen.ts'],
];
const HYDRA_PINS = [
  ...['login', 'consent', 'logout'].map((p) => [`/urls/${p}`, (h) => (h.urls[p] = 'https://a.example/x'), `pages/oauth2/${p}.ts`]),
  ['/urls', (h) => delete h.urls.consent, 'pages/oauth2/consent.ts'],
  ['/urls/error', (h) => (h.urls.error = 'https://a.example/x'), 'pages/auth/error.astro'],
  ['/urls/device/verification', (h) => (h.urls.device.verification = 'https://a.example/x'), 'pages/device/verify.astro'],
  ['/urls/device/success', (h) => (h.urls.device.success = 'https://a.example/x'), 'pages/device/done.astro'],
  ['/urls/device', (h) => delete h.urls.device, 'pages/device/verify.astro'],
  ['/serve/admin/port', (h) => (h.serve.admin.port = 1), 'HYDRA_ADMIN_URL, constants.ts'],
];

test.each(KRATOS_PINS)('kratos %s fails when mutated (consumer: %s)', (pointer, mutate) => {
  const v = run(edit(kratos, mutate), hydra);
  assert.ok(v.some((x) => x.startsWith(`kratos: ${pointer}`)), v.join('\n'));
});

test.each(HYDRA_PINS)('hydra %s fails when mutated (consumer: %s)', (pointer, mutate) => {
  const v = run(kratos, edit(hydra, mutate));
  assert.ok(v.some((x) => x.startsWith(`hydra: ${pointer}`)), v.join('\n'));
});

test('a YAML merge key is resolved before the contract applies', () => {
  const doc = stringify(kratos).replace(/( {2}whoami:\n) {4}required_aal: aal1/, '$1    <<: {required_aal: highest_available}');
  const dir = join(scratch, 'merge');
  mkdirSync(dir);
  writeFileSync(join(dir, 'k.yml'), doc);
  const f = files(kratos, hydra);
  const v = checkOry(root, { ...f, kratos: join(dir, 'k.yml') });
  assert.ok(v.some((x) => x.includes('/session/whoami/required_aal violates const')), v.join('\n'));
});

test('a value outside the contract changes freely', () => {
  const k = edit(kratos, (d) => {
    d.session.lifespan = '1h';
    d.log = { level: 'debug', format: 'text' };
    d.selfservice.flows.settings.after.passkey.hooks[0].config.extra = true;
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
  });
  assert.deepEqual(run(k, edit(hydra, (d) => (d.secrets = { system: [ph('system')] }))), []);
  const bare = edit(k, (d) => (hook(d, 'recovery', 'after').hooks[0].config.auth.config.value = ph('gate')));
  assert.ok(run(bare, hydra).length > 0);
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
  assert.deepEqual(check(reordered, `${jsonnet}\n\n  \n`.replace(/\n/g, '\r\n')), []);
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

test('every ui_url, oauth2 and device page the contract names exists', () => {
  const pin = (name, re) => [...readFileSync(join(root, `contract/${name}.schema.json`), 'utf8').matchAll(re)].map((m) => m[1]);
  const pages = (dir) => readdirSync(join(portal, 'src/pages', dir)).map((f) => f.replace(/\.\w+$/, ''));
  const auth = [...pin('kratos', /"pattern": "\/auth\/(\w+)\$"/g), ...pin('hydra', /"pattern": "\/auth\/(\w+)\$"/g)];
  assert.equal(auth.length, 6);
  const oauth2 = pin('hydra', /"pattern": "\/oauth2\/(\w+)\$"/g);
  const device = pin('hydra', /"pattern": "\/device\/(\w+)\$"/g);
  assert.equal(oauth2.length, 3);
  assert.equal(device.length, 2);
  for (const [dir, names] of [['auth', auth], ['oauth2', oauth2], ['device', device]]) {
    for (const f of names) assert.ok(pages(dir).includes(f), `${dir}/${f}`);
  }
});

test('the pinned privileged window equals the portal constant', () => {
  const schema = JSON.parse(readFileSync(join(root, 'contract/kratos.schema.json'), 'utf8'));
  const age = schema.properties.selfservice.properties.flows.properties.settings.properties.privileged_session_max_age.const;
  assert.equal(PRIVILEGED_WINDOW_MS, { s: 1e3, m: 6e4, h: 36e5 }[age.slice(-1)] * parseInt(age, 10));
});

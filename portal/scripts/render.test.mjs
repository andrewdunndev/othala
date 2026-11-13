// Invariant: the render keeps the substitution rules byte for byte, refuses a missing secret or a leftover ${,
// writes owner-only files, keeps the last good render on refusal, refuses retired or unknown names, and gen-secrets
// mints every secret it can. Assertions name variables only, so no secret value reaches the test log.

import { afterAll, test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseOryYaml } from '../src/lib/contract.ts';
import { check, courierDefaults, generateSecrets, render, renderTemplate, SECRETS, writeRendered } from '../src/lib/render.ts';

const root = fileURLToPath(new URL('../../', import.meta.url));
const portal = fileURLToPath(new URL('../', import.meta.url));

const VALUES = {
  OTHALA_PUBLIC_URL: 'https://auth.example.org',
  OTHALA_APEX: 'example.org',
  OTHALA_INSTANCE_NAME: 'Example Household',
  OTHALA_CONTACT_RECIPIENT: 'ops@example.org',
  KRATOS_ADMIN_BIND_HOST: '10.0.0.1',
  HYDRA_ADMIN_BIND_HOST: '10.0.0.2',
};
const FAKE_SECRETS = Object.fromEntries(SECRETS.map((n) => [n, `fake-${n.toLowerCase()}`]));
FAKE_SECRETS.KRATOS_CIPHER_SECRET_CURRENT = 'c'.repeat(32);
const ENV = { ...VALUES, ...FAKE_SECRETS };

// An empty content tree: no apps, so no client secret is required and no courier override applies.
const CONTENT = mkdtempSync(join(tmpdir(), 'othala-content-'));
mkdirSync(join(CONTENT, 'apps'));
afterAll(() => rmSync(CONTENT, { recursive: true, force: true }));

const OUTPUTS = [
  'caddy/othala.caddy',
  'hydra/hydra.yml',
  'kratos/courier/login_code.body.html.gotmpl',
  'kratos/courier/login_code.body.plaintext.gotmpl',
  'kratos/courier/login_code.subject.gotmpl',
  'kratos/courier/recovery_code.body.html.gotmpl',
  'kratos/courier/recovery_code.body.plaintext.gotmpl',
  'kratos/courier/recovery_code.subject.gotmpl',
  'kratos/courier/verification_code.body.html.gotmpl',
  'kratos/courier/verification_code.body.plaintext.gotmpl',
  'kratos/courier/verification_code.subject.gotmpl',
  'kratos/hooks/recovery-gate.jsonnet',
  'kratos/identity.schema.json',
  'kratos/kratos.yml',
];

function withDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'othala-render-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function policyCopy(dir) {
  cpSync(join(root, 'kratos'), join(dir, 'kratos'), { recursive: true });
  cpSync(join(root, 'hydra'), join(dir, 'hydra'), { recursive: true });
  cpSync(join(root, 'caddy'), join(dir, 'caddy'), { recursive: true });
  return dir;
}

// Expected bytes are the output of the shell renderer this module replaced, for the same inputs.
const RULE_ENV = { A: 'a\\"b', B: 'v', ON: 'on', GATE_ON: '1', GATE_OFF: '', E: '', N: 'Tom & <J> "q" \'a\'' };
const RULE_CASES = [
  {
    path: 'fixture.yml',
    src:
      '# header ${COMMENT_ONLY} is not required\na: "${A}"\nb: "x ${B} y" # trailing ${COMMENT_INLINE}\n' +
      'c: "file:///s.json#frag-${B}"\n  # indented ${A} is substituted where needed\n#@if GATE_ON\non: "${ON}"\n' +
      '#@endif\n  #@if GATE_OFF\noff: "${OFF_ONLY}"\n#@endif\nd: ${A}\n',
    out:
      '# header ${COMMENT_ONLY} is not required\na: "a\\\\\\"b"\nb: "x v y" # trailing ${COMMENT_INLINE}\n' +
      'c: "file:///s.json#frag-v"\n  # indented a\\\\\\"b is substituted where needed\non: "on"\nd: a\\\\\\"b\n',
  },
  { path: 'empty.yml', src: 'x: "${E}"\n', out: 'x: ""\n' },
  { path: 'crlf.yml', src: 'crlf: "${B}"\r\nend: 1', out: 'crlf: "v"\nend: 1' },
  {
    path: 'x.body.html.gotmpl',
    src: '<p>${N} {{ .Code }}</p>\n',
    out: '<p>Tom &amp; &lt;J&gt; &quot;q&quot; &#x27;a&#x27; {{ .Code }}</p>\n',
  },
  { path: 'x.subject.gotmpl', src: 'Hi ${N}, {{ .Code }}', out: 'Hi Tom & <J> "q" \'a\', {{ .Code }}' },
];

test('substitution rules match the shell renderer byte for byte', () => {
  for (const { path, src, out } of RULE_CASES) assert.equal(renderTemplate(path, src, RULE_ENV), out, path);
});

test('template structure errors and missing variables are refused by name', () => {
  assert.throws(() => renderTemplate('t.yml', '#@if A\n#@if B\n#@endif\n', RULE_ENV), /nested #@if at line 2/);
  assert.throws(() => renderTemplate('t.yml', '#@endif\n', RULE_ENV), /#@endif without a matching #@if/);
  assert.throws(() => renderTemplate('t.yml', '#@if A\nx: 1\n', RULE_ENV), /unterminated #@if 'A'/);
  assert.throws(() => renderTemplate('t.yml', 'x: "${NOPE}"\n', RULE_ENV), /missing render variable\(s\): NOPE/);
});

test('render emits the full tree: templates rendered, literal policy copied as it is', () => {
  const files = render(root, CONTENT, ENV);
  assert.deepEqual(files.map((f) => f.path).sort(), OUTPUTS);
  for (const path of ['kratos/identity.schema.json', 'kratos/hooks/recovery-gate.jsonnet']) {
    assert.equal(files.find((f) => f.path === path).content, readFileSync(join(root, path), 'utf8'), path);
  }
  for (const { path, content } of files) assert.equal(content.includes('${'), false, path);
});

test('render refuses any missing or blank secret, naming it', () => {
  for (const name of SECRETS) {
    for (const env of [{ ...ENV, [name]: undefined }, { ...ENV, [name]: ' ' }]) {
      let message = '';
      try {
        render(root, CONTENT, env);
      } catch (err) {
        message = err.message;
      }
      assert.ok(message.includes(`missing secret(s): ${name}`), name);
      for (const value of Object.values(FAKE_SECRETS)) assert.ok(!message.includes(value), `${name}: error carries a value`);
    }
  }
});

test('render refuses output with a ${ left in it', () => {
  withDir((dir) => {
    policyCopy(dir);
    const kratos = join(dir, 'kratos/kratos.yml');
    writeFileSync(kratos, `# names \${UNUSED} in a comment\n${readFileSync(kratos, 'utf8')}`);
    assert.throws(() => render(dir, CONTENT, ENV), /kratos\/kratos\.yml: \$\{ left in the rendered output/);
  });
});

test('render refuses output that is not well-formed YAML', () => {
  withDir((dir) => {
    policyCopy(dir);
    writeFileSync(join(dir, 'hydra/hydra.yml'), 'a: "${OTHALA_APEX}"\n  b: [\n');
    assert.throws(() => render(dir, CONTENT, ENV), /hydra\/hydra\.yml: rendered output is not well-formed YAML/);
  });
});

test('render resolves merge keys as check-ory does, so a broken merge is refused', () => {
  withDir((dir) => {
    policyCopy(dir);
    const hydra = join(dir, 'hydra/hydra.yml');
    writeFileSync(hydra, `${readFileSync(hydra, 'utf8')}\nbroken:\n  <<: 5\n`);
    assert.throws(() => render(dir, CONTENT, ENV), /hydra\/hydra\.yml: rendered output is not well-formed YAML/);
  });
});

test('a retired or unknown name fails check and render with its fix; other names are ignored', () => {
  const retired = { OTHALA_SITE_NAME: 'Retired Value', OTHALA_SMTP_FROM_ADDRESS: 'x@example.org', OTHALA_TYPO: 'typo-value' };
  const expected = [
    'OTHALA_SITE_NAME is retired: rename it OTHALA_INSTANCE_NAME',
    'OTHALA_SMTP_FROM_ADDRESS is retired: delete it; mail comes from noreply@<OTHALA_APEX>',
  ];
  const errors = check(root, CONTENT, { ...VALUES, ...retired });
  assert.deepEqual(errors.slice(0, 2), expected);
  assert.match(errors[2], /^OTHALA_TYPO is not an othala setting: delete it \(othala reads OTHALA_PUBLIC_URL, /);
  assert.equal(errors.length, 3);
  for (const value of Object.values(retired)) assert.ok(!errors.join('\n').includes(value), 'error carries a value');
  assert.throws(() => render(root, CONTENT, { ...ENV, ...retired }), /OTHALA_SITE_NAME is retired/);
  assert.deepEqual(render(root, CONTENT, { ...ENV, UNRELATED: '1' }), render(root, CONTENT, ENV));
});

test('check runs without secrets and names a missing value or policy file', () => {
  assert.deepEqual(check(root, CONTENT, VALUES), []);
  assert.deepEqual(check(root, CONTENT, { ...VALUES, OTHALA_APEX: undefined }), [
    'kratos/kratos.yml: missing render variable(s): OTHALA_APEX',
  ]);
  assert.ok(check(root, CONTENT, { ...VALUES, HYDRA_ADMIN_BIND_HOST: ' ' }).includes('hydra/hydra.yml: HYDRA_ADMIN_BIND_HOST must not be empty'));
  withDir((dir) => {
    policyCopy(dir);
    rmSync(join(dir, 'kratos/identity.schema.json'));
    assert.deepEqual(check(dir, CONTENT, VALUES), [`${dir}: missing policy file kratos/identity.schema.json`]);
  });
});

test('rendered files and directories are owner-only, but the secret-free edge snippets are readable', () => {
  withDir((dir) => {
    const files = render(root, CONTENT, ENV);
    writeRendered(dir, files);
    for (const path of OUTPUTS.filter((p) => !p.startsWith('caddy/'))) {
      assert.equal(statSync(join(dir, path)).mode & 0o777, 0o600, path);
    }
    for (const path of ['kratos', 'kratos/courier', 'kratos/hooks', 'hydra']) {
      assert.equal(statSync(join(dir, path)).mode & 0o077, 0, path);
    }
    assert.equal(statSync(join(dir, 'caddy/othala.caddy')).mode & 0o777, 0o644);
    assert.equal(statSync(join(dir, 'caddy')).mode & 0o777, 0o755);
    const caddy = files.find((f) => f.path === 'caddy/othala.caddy').content;
    for (const name of SECRETS) assert.ok(!caddy.includes(FAKE_SECRETS[name]), `${name} reached the edge snippets`);
  });
});

test('a render replaces the earlier trees and leaves no stale files', () => {
  withDir((dir) => {
    mkdirSync(join(dir, 'kratos'), { recursive: true });
    writeFileSync(join(dir, 'kratos/stale.txt'), 'old');
    writeRendered(dir, render(root, CONTENT, ENV));
    assert.equal(existsSync(join(dir, 'kratos/stale.txt')), false);
    for (const path of OUTPUTS) assert.equal(existsSync(join(dir, path)), true, path);
  });
});

test('a re-render clears nested stale entries and leaves nothing staged', () => {
  withDir((dir) => {
    writeRendered(dir, render(root, CONTENT, ENV));
    mkdirSync(join(dir, 'kratos/old/deeper'), { recursive: true });
    writeFileSync(join(dir, 'kratos/old/deeper/stale.txt'), 'old');
    writeRendered(dir, render(root, CONTENT, ENV));
    assert.equal(existsSync(join(dir, 'kratos/old')), false);
    for (const path of OUTPUTS) assert.equal(existsSync(join(dir, path)), true, path);
    const staged = readdirSync(dir, { recursive: true }).filter((f) => String(f).includes('.render-'));
    assert.deepEqual(staged, []);
  });
});

test('a render empties each tree in place, so a tree can be a mount point', () => {
  withDir((dir) => {
    for (const top of ['kratos', 'hydra', 'caddy']) mkdirSync(join(dir, top), { mode: 0o755 });
    writeFileSync(join(dir, 'kratos/stale.txt'), 'old');
    const before = statSync(join(dir, 'kratos')).ino;
    writeRendered(dir, render(root, CONTENT, ENV));
    assert.equal(statSync(join(dir, 'kratos')).ino, before);
    assert.equal(existsSync(join(dir, 'kratos/stale.txt')), false);
    assert.equal(statSync(join(dir, 'kratos')).mode & 0o077, 0);
    assert.equal(statSync(join(dir, 'caddy')).mode & 0o777, 0o755);
  });
});

const cli = (args, env) =>
  spawnSync(join(portal, 'node_modules/.bin/tsx'), [join(portal, 'src/server/config-cli.ts'), ...args], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, ...env },
    encoding: 'utf8',
  });

const snapshot = (out) =>
  Object.fromEntries(OUTPUTS.map((path) => [path, readFileSync(join(out, path), 'utf8')]));

test('a refused render through the CLI writes nothing and keeps the last good render', () => {
  withDir((dir) => {
    const out = join(dir, 'out');
    const refused = { ...ENV, CSRF_SECRET: '' };
    const r = cli(['render', '--policy', root, '--content', CONTENT, '--out', out], refused);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /missing secret\(s\): CSRF_SECRET/);
    assert.equal(existsSync(out), false);
    writeRendered(out, render(root, CONTENT, ENV));
    const before = snapshot(out);
    const again = cli(['render', '--policy', root, '--content', CONTENT, '--out', out], refused);
    assert.equal(again.status, 1);
    assert.match(again.stderr, /kept/);
    assert.deepEqual(snapshot(out), before);
  });
});

test('a refused cookie-secret pair keeps the last good render and fails closed', () => {
  withDir((dir) => {
    const out = join(dir, 'out');
    writeRendered(out, render(root, CONTENT, ENV));
    const before = snapshot(out);
    const refused = { ...ENV, KRATOS_COOKIE_SECRET_CURRENT: 'k'.repeat(64), KRATOS_COOKIE_SECRET_PREVIOUS: 'p'.repeat(32) };
    const r = cli(['render', '--policy', root, '--content', CONTENT, '--out', out], refused);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /KRATOS_COOKIE_SECRET_CURRENT must be 16, 24 or 32/);
    assert.deepEqual(snapshot(out), before);
  });
});

test('render refuses a cookie or system secret under 16 characters, set or not _PREVIOUS', () => {
  for (const name of ['KRATOS_COOKIE_SECRET_CURRENT', 'HYDRA_COOKIE_SECRET_CURRENT', 'HYDRA_SYSTEM_SECRET']) {
    assert.throws(() => render(root, CONTENT, { ...ENV, [name]: 's'.repeat(15) }), new RegExp(`${name} must be at least 16 characters`));
    assert.doesNotThrow(() => render(root, CONTENT, { ...ENV, [name]: 's'.repeat(16) }), name);
  }
});

test('render refuses a _PREVIOUS equal to its _CURRENT', () => {
  const pairs = [
    ['KRATOS_COOKIE_SECRET', 'k'.repeat(32)],
    ['KRATOS_CIPHER_SECRET', 'c'.repeat(32)],
    ['HYDRA_COOKIE_SECRET', 'h'.repeat(32)],
  ];
  for (const [base, value] of pairs) {
    const env = { ...ENV, [`${base}_CURRENT`]: value, [`${base}_PREVIOUS`]: value };
    assert.throws(() => render(root, CONTENT, env), new RegExp(`${base}_PREVIOUS must differ from ${base}_CURRENT`), base);
  }
  const system = { ...ENV, HYDRA_SYSTEM_SECRET: 's'.repeat(32), HYDRA_SYSTEM_SECRET_PREVIOUS: 's'.repeat(32) };
  assert.throws(() => render(root, CONTENT, system), /HYDRA_SYSTEM_SECRET_PREVIOUS must differ from HYDRA_SYSTEM_SECRET/);
});

test('check reports a short secret and a repeated _PREVIOUS', () => {
  const args = ['check', '--policy', root, '--content', CONTENT];
  assert.match(cli(args, { ...ENV, HYDRA_COOKIE_SECRET_CURRENT: 'short' }).stderr, /HYDRA_COOKIE_SECRET_CURRENT must be at least 16/);
  const same = { ...ENV, HYDRA_COOKIE_SECRET_CURRENT: 'h'.repeat(32), HYDRA_COOKIE_SECRET_PREVIOUS: 'h'.repeat(32) };
  assert.match(cli(args, same).stderr, /HYDRA_COOKIE_SECRET_PREVIOUS must differ/);
});

test('check refuses what render would refuse, with or without secrets in the environment', () => {
  const args = ['check', '--policy', root, '--content', CONTENT];
  const pair = { KRATOS_COOKIE_SECRET_CURRENT: 'k'.repeat(64), KRATOS_COOKIE_SECRET_PREVIOUS: 'p'.repeat(32) };
  const bad = cli(args, { ...ENV, ...pair });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /KRATOS_COOKIE_SECRET_CURRENT must be 16, 24 or 32/);
  assert.equal(cli(args, ENV).status, 0);
  assert.equal(cli(args, VALUES).status, 0);
});

test('a filesystem error during the write empties an earlier render', () => {
  withDir((dir) => {
    const out = join(dir, 'out');
    writeRendered(out, render(root, CONTENT, ENV));
    rmSync(join(out, 'hydra/hydra.yml'));
    mkdirSync(join(out, 'hydra/hydra.yml/blocker'), { recursive: true });
    const r = cli(['render', '--policy', root, '--content', CONTENT, '--out', out], ENV);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /earlier output cleared/);
    for (const top of ['kratos', 'hydra', 'caddy']) assert.deepEqual(readdirSync(join(out, top)), [], top);
  });
});

test('gen-secrets mints every secret but the SMTP URI, fresh each run, and the render accepts them', () => {
  const r = cli(['gen-secrets', '--content', CONTENT], {});
  assert.equal(r.status, 0);
  const minted = Object.fromEntries(r.stdout.trim().split('\n').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  assert.deepEqual(Object.keys(minted).sort(), SECRETS.filter((n) => n !== 'OTHALA_SMTP_CONNECTION_URI').sort());
  for (const [name, value] of Object.entries(minted)) {
    const length = name === 'KRATOS_CIPHER_SECRET_CURRENT' || name === 'KRATOS_COOKIE_SECRET_CURRENT' ? 32 : 64;
    assert.ok(new RegExp(`^[0-9a-f]{${length}}$`).test(value), `${name} is not ${length} hex characters`);
  }
  const again = generateSecrets(CONTENT);
  for (const [name, value] of Object.entries(minted)) assert.ok(!again.includes(value), `${name} repeated across runs`);
  const env = { ...VALUES, ...minted, OTHALA_SMTP_CONNECTION_URI: 'smtp://relay.example.org:25' };
  assert.doesNotThrow(() => render(root, CONTENT, env));
});

function contentTree(dir, files) {
  mkdirSync(join(dir, 'apps'), { recursive: true });
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(dir, path, '..'), { recursive: true });
    writeFileSync(join(dir, path), body);
  }
  return dir;
}

const courierOut = (files, name) => files.find((f) => f.path === `kratos/courier/${name}`).content;

test('courier: a default with no override renders as shipped, an override wins and is rendered with the same rules', () => {
  withDir((dir) => {
    const content = contentTree(dir, { 'courier/login_code.subject.gotmpl': 'Code for ${OTHALA_INSTANCE_NAME} & co' });
    const merged = render(root, content, ENV);
    const shipped = render(root, CONTENT, ENV);
    assert.deepEqual(merged.map((f) => f.path).sort(), OUTPUTS);
    assert.equal(courierOut(merged, 'login_code.subject.gotmpl'), 'Code for Example Household & co');
    for (const name of courierDefaults(root).filter((n) => n !== 'login_code.subject.gotmpl')) {
      assert.equal(courierOut(merged, name), courierOut(shipped, name), name);
    }
  });
});

test('courier: an override HTML body is HTML-escaped like the default', () => {
  withDir((dir) => {
    const content = contentTree(dir, { 'courier/login_code.body.html.gotmpl': '<p>${OTHALA_INSTANCE_NAME}</p>' });
    const files = render(root, content, { ...ENV, OTHALA_INSTANCE_NAME: 'A <b> & B' });
    assert.equal(courierOut(files, 'login_code.body.html.gotmpl'), '<p>A &lt;b&gt; &amp; B</p>');
  });
});

test('courier: an override whose name matches no shipped default is refused, naming the valid names', () => {
  withDir((dir) => {
    const content = contentTree(dir, { 'courier/login.subject.gotmpl': 'x' });
    const errors = check(root, content, VALUES);
    assert.deepEqual(errors, [`courier/login.subject.gotmpl: no shipped template has this name; an override is one of ${courierDefaults(root).join(', ')}`]);
    assert.equal(courierDefaults(root).length, 9);
    assert.throws(() => render(root, content, ENV), /courier\/login\.subject\.gotmpl: no shipped template has this name/);
  });
});

test('courier: an override may not name a secret or any value outside the identity set', () => {
  withDir((dir) => {
    const content = contentTree(dir, { 'courier/recovery_code.subject.gotmpl': '${CSRF_SECRET} ${OTHALA_APEX}' });
    assert.deepEqual(check(root, content, VALUES), [
      'courier/recovery_code.subject.gotmpl: an override may name only OTHALA_APEX, OTHALA_INSTANCE_NAME, OTHALA_PUBLIC_URL; remove CSRF_SECRET',
    ]);
    let message = '';
    try {
      render(root, content, ENV);
    } catch (err) {
      message = err.message;
    }
    assert.match(message, /remove CSRF_SECRET/);
    assert.ok(!message.includes(FAKE_SECRETS.CSRF_SECRET), 'error carries a value');
  });
});

const CONFIDENTIAL = 'presentation:\n  name: Wiki\n  url: https://wiki.example.org\n  access: [family]\noidc:\n  client_id: wiki\n  redirect_uris: [https://wiki.example.org/cb]\n  audience: [https://wiki.example.org]\n  token_endpoint_auth_method: client_secret_basic\n';
const PUBLIC = 'presentation:\n  name: Cli\n  url: https://cli.example.org\n  access: [family]\noidc:\n  client_id: cli\n  redirect_uris: [http://127.0.0.1/cb]\n  audience: [http://127.0.0.1]\n  token_endpoint_auth_method: none\n';

test('render needs no client secret and ignores app problems, which check still reports', () => {
  withDir((dir) => {
    const content = contentTree(dir, {
      'apps/wiki.yaml': CONFIDENTIAL,
      'apps/cli.yaml': PUBLIC,
      'apps/wiki.svg': '<html></html>',
      'groups.yaml': '- not a mapping\n',
    });
    assert.deepEqual(check(root, content, VALUES), [
      'groups.yaml: must be a mapping of group name to { title, description, order }',
      'apps/wiki.svg does not open with an <svg> root',
    ]);
    assert.deepEqual(check(root, content, VALUES, 'render'), []);
    assert.doesNotThrow(() => render(root, content, ENV));
  });
});

test('render still refuses a bad courier override', () => {
  withDir((dir) => {
    const content = contentTree(dir, { 'apps/wiki.yaml': CONFIDENTIAL, 'courier/nope.gotmpl': 'x' });
    assert.throws(() => render(root, content, ENV), /courier\/nope\.gotmpl: no shipped template has this name/);
  });
});

test('gen-secrets mints a client secret for each confidential manifest in the content dir, and the render accepts it', () => {
  withDir((dir) => {
    const content = contentTree(dir, { 'apps/wiki.yaml': CONFIDENTIAL, 'apps/cli.yaml': PUBLIC });
    const r = cli(['gen-secrets', '--content', content], {});
    assert.equal(r.status, 0);
    const minted = Object.fromEntries(r.stdout.trim().split('\n').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
    assert.match(minted.WIKI_CLIENT_SECRET, /^[0-9a-f]{64}$/);
    assert.equal('CLI_CLIENT_SECRET' in minted, false);
    const env = { ...VALUES, ...minted, OTHALA_SMTP_CONNECTION_URI: 'smtp://relay.example.org:25' };
    assert.doesNotThrow(() => render(root, content, env));
  });
});

test('the CLI check runs offline against a content dir argument and fails on a bad tree', () => {
  const good = cli(['check', '--policy', root, '--content', join(root, 'e2e/content')], VALUES);
  assert.equal(good.status, 0, good.stderr);
  withDir((dir) => {
    const bad = cli(['check', '--policy', root, '--content', contentTree(dir, { 'stray.txt': '' })], VALUES);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /stray\.txt: not part of the content layout \(apps\/, groups\.yaml, courier\/\); delete it/);
  });
});

test('render refuses a Kratos cipher secret that is not exactly 32 characters', () => {
  for (const length of [31, 33]) {
    const env = { ...ENV, KRATOS_CIPHER_SECRET_CURRENT: 'c'.repeat(length) };
    assert.throws(() => render(root, CONTENT, env), /KRATOS_CIPHER_SECRET_CURRENT must be exactly 32 characters/);
  }
});

const secretsOf = (env, file) => parseOryYaml(render(root, CONTENT, env).find((f) => f.path === file).content).secrets;
const PREVIOUS = {
  KRATOS_COOKIE_SECRET_PREVIOUS: 'p'.repeat(32),
  KRATOS_CIPHER_SECRET_PREVIOUS: 'q'.repeat(32),
  HYDRA_SYSTEM_SECRET_PREVIOUS: 'old-system',
  HYDRA_COOKIE_SECRET_PREVIOUS: 'old-hcookie',
};

test('with no _PREVIOUS set, or one set empty, each secret list is the single current entry', () => {
  const single = { cookie: ['fake-kratos_cookie_secret_current'], cipher: ['c'.repeat(32)] };
  assert.deepEqual(secretsOf(ENV, 'kratos/kratos.yml'), single);
  assert.deepEqual(secretsOf({ ...ENV, KRATOS_COOKIE_SECRET_PREVIOUS: '' }, 'kratos/kratos.yml'), single);
  assert.deepEqual(secretsOf(ENV, 'hydra/hydra.yml'), { system: ['fake-hydra_system_secret'], cookie: ['fake-hydra_cookie_secret_current'] });
});

test('a _PREVIOUS renders as the second entry, after the current one', () => {
  const env = { ...ENV, KRATOS_COOKIE_SECRET_CURRENT: 'n'.repeat(32), ...PREVIOUS };
  assert.deepEqual(secretsOf(env, 'kratos/kratos.yml'), { cookie: ['n'.repeat(32), 'p'.repeat(32)], cipher: ['c'.repeat(32), 'q'.repeat(32)] });
  assert.deepEqual(secretsOf(env, 'hydra/hydra.yml'), {
    system: ['fake-hydra_system_secret', 'old-system'],
    cookie: ['fake-hydra_cookie_secret_current', 'old-hcookie'],
  });
});

test('render refuses a Kratos cookie pair with an entry that is not 16, 24 or 32 characters, and a cipher _PREVIOUS that is not 32', () => {
  const pair = { ...ENV, KRATOS_COOKIE_SECRET_CURRENT: 'n'.repeat(32), KRATOS_COOKIE_SECRET_PREVIOUS: 'p'.repeat(24) };
  assert.doesNotThrow(() => render(root, CONTENT, pair));
  assert.throws(() => render(root, CONTENT, { ...pair, KRATOS_COOKIE_SECRET_PREVIOUS: 'p'.repeat(64) }), /KRATOS_COOKIE_SECRET_PREVIOUS must be 16, 24 or 32/);
  assert.throws(() => render(root, CONTENT, { ...pair, KRATOS_COOKIE_SECRET_CURRENT: 'n'.repeat(64) }), /KRATOS_COOKIE_SECRET_CURRENT must be 16, 24 or 32/);
  assert.throws(() => render(root, CONTENT, { ...ENV, KRATOS_CIPHER_SECRET_PREVIOUS: 'q'.repeat(31) }), /KRATOS_CIPHER_SECRET_PREVIOUS must be exactly 32/);
});

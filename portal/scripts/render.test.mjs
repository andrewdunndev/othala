// Invariant: the render keeps the substitution rules byte for byte, refuses a missing secret or a leftover ${,
// writes owner-only files and nothing on refusal, ignores names it does not know, and gen-secrets mints every
// secret it can. Assertions name variables only, so no secret value reaches the test log.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, generateSecrets, render, renderTemplate, SECRETS, writeRendered } from '../src/lib/render.ts';

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

const OUTPUTS = [
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
  const files = render(root, ENV);
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
        render(root, env);
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
    assert.throws(() => render(dir, ENV), /kratos\/kratos\.yml: \$\{ left in the rendered output/);
  });
});

test('render refuses output that is not well-formed YAML', () => {
  withDir((dir) => {
    policyCopy(dir);
    writeFileSync(join(dir, 'hydra/hydra.yml'), 'a: "${OTHALA_APEX}"\n  b: [\n');
    assert.throws(() => render(dir, ENV), /hydra\/hydra\.yml: rendered output is not well-formed YAML/);
  });
});

test('names outside the contract are ignored, as the portal config ignores them', () => {
  const extra = { OTHALA_SITE_NAME: 'Retired', OTHALA_SMTP_FROM_ADDRESS: 'x@example.org', UNRELATED: '1' };
  assert.deepEqual(render(root, { ...ENV, ...extra }), render(root, ENV));
  assert.deepEqual(check(root, { ...VALUES, ...extra }), []);
});

test('check runs without secrets and names a missing value or policy file', () => {
  assert.deepEqual(check(root, VALUES), []);
  assert.deepEqual(check(root, { ...VALUES, OTHALA_APEX: undefined }), [
    'kratos/kratos.yml: missing render variable(s): OTHALA_APEX',
  ]);
  assert.ok(check(root, { ...VALUES, HYDRA_ADMIN_BIND_HOST: ' ' }).includes('hydra/hydra.yml: HYDRA_ADMIN_BIND_HOST must not be empty'));
  withDir((dir) => {
    policyCopy(dir);
    rmSync(join(dir, 'kratos/identity.schema.json'));
    assert.deepEqual(check(dir, VALUES), [`${dir}: missing policy file kratos/identity.schema.json`]);
  });
});

test('rendered files and directories are owner-only', () => {
  withDir((dir) => {
    writeRendered(dir, render(root, ENV));
    for (const path of OUTPUTS) assert.equal(statSync(join(dir, path)).mode & 0o777, 0o600, path);
    for (const path of ['kratos', 'kratos/courier', 'kratos/hooks', 'hydra']) {
      assert.equal(statSync(join(dir, path)).mode & 0o077, 0, path);
    }
  });
});

test('a render replaces the earlier trees and leaves no stale files', () => {
  withDir((dir) => {
    mkdirSync(join(dir, 'kratos'), { recursive: true });
    writeFileSync(join(dir, 'kratos/stale.txt'), 'old');
    writeRendered(dir, render(root, ENV));
    assert.equal(existsSync(join(dir, 'kratos/stale.txt')), false);
    for (const path of OUTPUTS) assert.equal(existsSync(join(dir, path)), true, path);
  });
});

const cli = (args, env) =>
  spawnSync(join(portal, 'node_modules/.bin/tsx'), [join(portal, 'src/server/config-cli.ts'), ...args], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, ...env },
    encoding: 'utf8',
  });

test('the CLI writes nothing when the render is refused', () => {
  withDir((dir) => {
    const out = join(dir, 'out');
    const r = cli(['render', '--policy', root, '--out', out], { ...ENV, CSRF_SECRET: '' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /missing secret\(s\): CSRF_SECRET/);
    assert.equal(existsSync(out), false);
  });
});

test('gen-secrets mints every secret but the SMTP URI, fresh each run, and the render accepts them', () => {
  const r = cli(['gen-secrets'], {});
  assert.equal(r.status, 0);
  const minted = Object.fromEntries(r.stdout.trim().split('\n').map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
  assert.deepEqual(Object.keys(minted).sort(), SECRETS.filter((n) => n !== 'OTHALA_SMTP_CONNECTION_URI').sort());
  for (const [name, value] of Object.entries(minted)) {
    const length = name === 'KRATOS_CIPHER_SECRET_CURRENT' ? 32 : 64;
    assert.ok(new RegExp(`^[0-9a-f]{${length}}$`).test(value), `${name} is not ${length} hex characters`);
  }
  const again = generateSecrets();
  for (const [name, value] of Object.entries(minted)) assert.ok(!again.includes(value), `${name} repeated across runs`);
  const env = { ...VALUES, ...minted, OTHALA_SMTP_CONNECTION_URI: 'smtp://relay.example.org:25' };
  assert.doesNotThrow(() => render(root, env));
});

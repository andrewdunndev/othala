// Invariant: the shipped Ory templates carry the policy as literals, trace only when OTHALA_OTLP_ENDPOINT is set,
// and derive CORS and WebAuthn from the identity vars; e2e alone turns the breach check off, by overlay.
// Code emails name the household without letting its value inject template actions or HTML.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const root = fileURLToPath(new URL('../../', import.meta.url));

const BASE_ENV = {
  PATH: process.env.PATH,
  OTHALA_PUBLIC_URL: 'https://auth.example.com',
  OTHALA_APEX: 'example.com',
  OTHALA_INSTANCE_NAME: 'Acme',
  OTHALA_SMTP_CONNECTION_URI: 'smtp://relay:1025',
  KRATOS_PG_PASS: 'kp',
  HYDRA_PG_PASS: 'hp',
  KRATOS_COOKIE_SECRET_CURRENT: 'cookie',
  KRATOS_CIPHER_SECRET_CURRENT: 'c'.repeat(32),
  HYDRA_SYSTEM_SECRET: 'sys',
  HYDRA_COOKIE_SECRET_CURRENT: 'hcookie',
  RECOVERY_GATE_SECRET: 'gate',
  KRATOS_ADMIN_BIND_HOST: '10.0.0.1',
  HYDRA_ADMIN_BIND_HOST: '10.0.0.2',
};

function renderText(template, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ory-config-'));
  try {
    const out = join(dir, 'out');
    execFileSync('bash', [join(root, 'scripts/render-config.sh'), join(root, template), out], {
      env: { ...BASE_ENV, ...extra },
      stdio: 'pipe',
    });
    return readFileSync(out, 'utf8');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const render = (template, extra) => parse(renderText(template, extra));

test('kratos: breach check on and minimum length 12 are literals', () => {
  const cfg = render('kratos/kratos.yml');
  const pw = cfg.selfservice.methods.password.config;
  assert.equal(pw.haveibeenpwned_enabled, true);
  assert.equal(pw.min_password_length, 12);
  assert.equal(pw.ignore_network_errors, false);
});

test('kratos: golden service hosts are literal and WebAuthn derives from the identity vars', () => {
  const cfg = render('kratos/kratos.yml');
  assert.match(cfg.dsn, /@postgres:5432\/kratos/);
  assert.equal(cfg.serve.admin.base_url, 'http://kratos:4434/');
  assert.equal(cfg.selfservice.methods.passkey.config.rp.id, 'example.com');
  assert.deepEqual(cfg.selfservice.methods.passkey.config.rp.origins, ['https://auth.example.com']);
  const text = JSON.stringify(cfg);
  assert.ok(text.includes('http://othala:4431/admin/recovery-gate'));
});

test('hydra: Postgres host is literal and CORS allows only the public URL', () => {
  const cfg = render('hydra/hydra.yml');
  assert.match(cfg.dsn, /@postgres:5432\/hydra/);
  assert.deepEqual(cfg.serve.public.cors.allowed_origins, ['https://auth.example.com']);
});

test('tracing blocks are absent unless OTHALA_OTLP_ENDPOINT is set', () => {
  assert.equal('tracing' in render('kratos/kratos.yml'), false);
  assert.equal('tracing' in render('hydra/hydra.yml'), false);
  assert.equal('tracing' in render('kratos/kratos.yml', { OTHALA_OTLP_ENDPOINT: '' }), false);
});

test('tracing blocks use the fixed provider, service name and environment', () => {
  const env = { OTHALA_OTLP_ENDPOINT: 'alloy:4318' };
  for (const [template, service] of [['kratos/kratos.yml', 'kratos'], ['hydra/hydra.yml', 'hydra']]) {
    const t = render(template, env).tracing;
    assert.equal(t.provider, 'otel');
    assert.equal(t.service_name, service);
    assert.equal(t.deployment_environment, 'production');
    assert.equal(t.providers.otlp.server_url, 'alloy:4318');
    assert.equal(t.providers.otlp.sampling.sampling_ratio, 0.1);
  }
});

test('the e2e overlay turns off only the breach check', () => {
  const overlay = parse(readFileSync(join(root, 'e2e/kratos.e2e.yml'), 'utf8'));
  assert.deepEqual(overlay, { selfservice: { methods: { password: { config: { haveibeenpwned_enabled: false } } } } });
});

test('render refuses an empty Ory admin bind', () => {
  for (const [template, name] of [['kratos/kratos.yml', 'KRATOS_ADMIN_BIND_HOST'], ['hydra/hydra.yml', 'HYDRA_ADMIN_BIND_HOST']]) {
    for (const bad of ['', '  ']) {
      assert.throws(() => render(template, { [name]: bad }), `${name}=${JSON.stringify(bad)}`);
    }
    assert.doesNotThrow(() => render(template, { [name]: '0.0.0.0' }));
  }
});

const MAIL = {
  recovery_code: { code: '{{ .RecoveryCode }}', subject: /recover/i },
  login_code: { code: '{{ .LoginCode }}', subject: /to log in/i },
  verification_code: { code: '{{ .VerificationCode }}', subject: /verif/i },
};
const PARTS = ['subject', 'body.html', 'body.plaintext'];
const mailFiles = () => Object.keys(MAIL).flatMap((id) => PARTS.map((part) => `kratos/courier/${id}.${part}.gotmpl`));

test('kratos: every code email part is a vendored template', () => {
  const templates = render('kratos/kratos.yml').courier.templates;
  assert.deepEqual(Object.keys(templates).sort(), Object.keys(MAIL).sort());
  for (const id of Object.keys(MAIL)) {
    const { subject, body } = templates[id].valid.email;
    for (const [part, uri] of [['subject', subject], ['body.html', body.html], ['body.plaintext', body.plaintext]]) {
      assert.equal(uri, `file:///etc/config/kratos/courier/${id}.${part}.gotmpl`);
      assert.ok(existsSync(join(root, `kratos/courier/${id}.${part}.gotmpl`)), uri);
    }
  }
});

test('mail: subjects match the flow, bodies lead with the code and take the lifetime from Kratos', () => {
  for (const [id, { code, subject }] of Object.entries(MAIL)) {
    assert.match(renderText(`kratos/courier/${id}.subject.gotmpl`), subject);
    for (const part of ['body.html', 'body.plaintext']) {
      const body = renderText(`kratos/courier/${id}.${part}.gotmpl`);
      assert.ok(body.includes(code), `${id}.${part}`);
      assert.ok(body.includes('{{ .ExpiresInMinutes }}'), `${id}.${part}`);
      assert.doesNotMatch(body.slice(0, body.indexOf(code)), /\d/, `${id}.${part}`);
      assert.doesNotMatch(body, /15|code=|href|:\/\//, `${id}.${part}`);
    }
  }
});

test('mail: the household name renders into every part, escaped in HTML only', () => {
  const name = 'Tom & <Jerry>';
  for (const file of mailFiles()) {
    const out = renderText(file, { OTHALA_INSTANCE_NAME: name });
    if (file.endsWith('.html.gotmpl')) {
      assert.ok(out.includes('Tom &amp; &lt;Jerry&gt;'), file);
      assert.ok(!out.includes(name), file);
    } else {
      assert.ok(out.includes(name), file);
    }
  }
});

test('mail: render refuses a value carrying template delimiters', () => {
  for (const file of mailFiles()) {
    for (const bad of ['{{ .Identity }}', 'Acme {{', 'Acme }}']) {
      assert.throws(() => renderText(file, { OTHALA_INSTANCE_NAME: bad }), `${file} ${bad}`);
    }
  }
});

test('mail: only the recovery email branches on the invite flag and prints nothing from the payload', () => {
  for (const file of mailFiles()) {
    const src = readFileSync(join(root, file), 'utf8');
    const reads = src.match(/\.TransientPayload\S*/g) ?? [];
    assert.deepEqual(reads, file.includes('/recovery_code.') ? ['.TransientPayload.invite'] : [], file);
    assert.equal(reads.length, (src.match(/\{\{ if \.TransientPayload\.invite -?\}\}/g) ?? []).length, file);
  }
});

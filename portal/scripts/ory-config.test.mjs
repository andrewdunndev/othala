// Invariant: the shipped Ory templates carry the policy as literals, trace only when OTHALA_OTLP_ENDPOINT is set,
// and derive CORS and WebAuthn from the identity vars; e2e alone turns the breach check off, by overlay.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
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

function render(template, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ory-config-'));
  try {
    const out = join(dir, 'out.yml');
    execFileSync('bash', [join(root, 'scripts/render-config.sh'), join(root, template), out], {
      env: { ...BASE_ENV, ...extra },
      stdio: 'pipe',
    });
    return parse(readFileSync(out, 'utf8'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

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

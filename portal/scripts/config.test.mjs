// Invariant: portal env config validates required values at load, takes no knob for fixed topology, and refuses a
// retired or unknown name by name.

import { test } from 'vitest';
import assert from 'node:assert/strict';

const MANAGED = (key) => key.startsWith('OTHALA_') || key === 'NODE_ENV' || key === 'CSRF_SECRET' || key === 'RECOVERY_GATE_SECRET' || key === 'UNRELATED_SETTING' || key.endsWith('_CLIENT_SECRET');

async function loadConfig(env = {}) {
  const saved = { ...process.env };
  for (const key of Object.keys(process.env)) if (MANAGED(key)) delete process.env[key];
  Object.assign(process.env, env);

  try {
    const bust = `?bust=${Date.now()}-${Math.random().toString(36).slice(2)}`;
    return await import(/* @vite-ignore */ `../src/lib/config.ts${bust}`);
  } finally {
    for (const key of Object.keys(process.env)) if (MANAGED(key)) delete process.env[key];
    Object.assign(process.env, saved);
  }
}

const PROD = {
  NODE_ENV: 'production',
  OTHALA_PUBLIC_URL: 'https://auth.example.com',
  OTHALA_APEX: 'example.com',
  OTHALA_INSTANCE_NAME: 'Acme SSO',
  OTHALA_SMTP_CONNECTION_URI: 'smtps://u:p@smtp.example.com:465',
  OTHALA_CONTACT_RECIPIENT: 'ops@example.com',
  CSRF_SECRET: 'c'.repeat(32),
  RECOVERY_GATE_SECRET: 'r'.repeat(32),
};

test('production loads when every required var is set', async () => {
  const mod = await loadConfig(PROD);
  assert.equal(mod.publicUrl, 'https://auth.example.com');
  assert.equal(mod.apex, 'example.com');
  assert.equal(mod.instanceName, 'Acme SSO');
  assert.equal(mod.smtpConnectionUri, 'smtps://u:p@smtp.example.com:465');
  assert.equal(mod.contactRecipient, 'ops@example.com');
});

for (const name of [
  'OTHALA_PUBLIC_URL',
  'OTHALA_APEX',
  'OTHALA_INSTANCE_NAME',
  'OTHALA_SMTP_CONNECTION_URI',
  'OTHALA_CONTACT_RECIPIENT',
  'CSRF_SECRET',
  'RECOVERY_GATE_SECRET',
]) {
  test(`${name}: throws in production when absent or blank`, async () => {
    const { [name]: _omit, ...rest } = PROD;
    await assert.rejects(() => loadConfig(rest), new RegExp(name));
    await assert.rejects(() => loadConfig({ ...rest, [name]: '   ' }), new RegExp(name));
  });
}

test('dev defaults apply outside production', async () => {
  for (const NODE_ENV of ['development', 'test']) {
    const mod = await loadConfig({ NODE_ENV });
    assert.equal(mod.publicUrl, 'http://localhost:4321');
    assert.equal(mod.apex, 'localhost');
    assert.equal(mod.instanceName, 'Othala');
    assert.equal(mod.smtpConnectionUri, 'smtp://lab:lab@localhost:1025');
    assert.equal(mod.contactRecipient, 'admin@localhost');
  }
});

test('publicUrl: strips trailing slashes', async () => {
  const { publicUrl } = await loadConfig({ ...PROD, OTHALA_PUBLIC_URL: 'https://auth.example.com///' });
  assert.equal(publicUrl, 'https://auth.example.com');
});

test('a retired name throws in every mode, naming the fix and never the value', async () => {
  for (const NODE_ENV of ['test', 'production']) {
    const base = NODE_ENV === 'production' ? PROD : { NODE_ENV };
    await assert.rejects(
      () => loadConfig({ ...base, OTHALA_SITE_NAME: 'Acme Portal' }),
      (err) => /OTHALA_SITE_NAME is retired: rename it OTHALA_INSTANCE_NAME/.test(err.message) && !err.message.includes('Acme Portal'),
    );
  }
});

test('every retired knob throws by name', async () => {
  for (const name of [
    'OTHALA_DEFAULT_SCHEMA_ID',
    'OTHALA_DEFAULT_GROUP',
    'OTHALA_IDENTITY_GROUPS',
    'OTHALA_ADMIN_CONTACT',
    'OTHALA_ADMIN_FRESHNESS_HOURS',
    'OTHALA_SMTP_FROM_ADDRESS',
  ]) {
    await assert.rejects(() => loadConfig({ NODE_ENV: 'test', [name]: 'x' }), new RegExp(`${name} is retired: `));
  }
});

test('an unknown OTHALA_ name throws and lists the names othala reads', async () => {
  await assert.rejects(() => loadConfig({ NODE_ENV: 'test', OTHALA_PUBLIC_URLS: 'https://a.example' }), /OTHALA_PUBLIC_URLS is not an othala setting: delete it \(othala reads OTHALA_PUBLIC_URL, /);
});

test('names outside the OTHALA_ prefix and the retired table are left alone', async () => {
  await assert.doesNotReject(() => loadConfig({ ...PROD, UNRELATED_SETTING: '1', GRAFANA_CLIENT_SECRET: 'x' }));
});

test('smtpFromAddress: always noreply@<OTHALA_APEX>', async () => {
  const { smtpFromAddress } = await loadConfig({ NODE_ENV: 'test', OTHALA_APEX: 'example.org' });
  assert.equal(smtpFromAddress, 'noreply@example.org');
});

test('secret: reads CSRF_SECRET and RECOVERY_GATE_SECRET lazily, undefined when blank', async () => {
  const { secret } = await loadConfig({ NODE_ENV: 'test' });
  process.env.CSRF_SECRET = 'x'.repeat(40);
  process.env.RECOVERY_GATE_SECRET = '  ';
  try {
    assert.equal(secret('CSRF_SECRET'), 'x'.repeat(40));
    assert.equal(secret('RECOVERY_GATE_SECRET'), undefined);
  } finally {
    delete process.env.CSRF_SECRET;
    delete process.env.RECOVERY_GATE_SECRET;
  }
});

// Invariant: portal env config validates required values at load and takes no knob for fixed topology.

import { test } from 'vitest';
import assert from 'node:assert/strict';

const MANAGED = (key) => key.startsWith('OTHALA_') || key === 'NODE_ENV' || key === 'CSRF_SECRET' || key === 'RECOVERY_GATE_SECRET';

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

test('instanceName: the one brand name, with no OTHALA_SITE_NAME fallback', async () => {
  const mod = await loadConfig({ NODE_ENV: 'test', OTHALA_SITE_NAME: 'Acme Portal' });
  assert.equal(mod.instanceName, 'Othala');
  assert.equal('siteName' in mod, false);
});

test('smtpFromAddress: always noreply@<OTHALA_APEX>, the old override is ignored', async () => {
  const { smtpFromAddress } = await loadConfig({ NODE_ENV: 'test', OTHALA_APEX: 'example.org', OTHALA_SMTP_FROM_ADDRESS: 'other@x.test' });
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

test('retired knobs are gone: config exports no default schema id, group, contact or freshness setting', async () => {
  const mod = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_DEFAULT_SCHEMA_ID: 'family',
    OTHALA_DEFAULT_GROUP: 'family',
    OTHALA_IDENTITY_GROUPS: 'family,friends',
    OTHALA_ADMIN_CONTACT: 'help@example.com',
    OTHALA_ADMIN_FRESHNESS_HOURS: '5',
  });
  for (const gone of ['defaultSchemaId', 'defaultGroup', 'identityGroups', 'adminContact', 'adminFreshnessHours']) {
    assert.equal(gone in mod, false, gone);
  }
});

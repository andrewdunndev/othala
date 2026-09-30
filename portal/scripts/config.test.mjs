// Invariant: portal env config validates required values and rejects unsafe ones at load.

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';

async function loadConfig(env = {}) {
  const saved = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('OTHALA_') || key === 'NODE_ENV') delete process.env[key];
  }
  Object.assign(process.env, env);

  try {
    const bust = `?bust=${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const mod = await import(/* @vite-ignore */ `../src/lib/config.ts${bust}`);
    return mod;
  } finally {
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('OTHALA_') || key === 'NODE_ENV') delete process.env[key];
    }
    Object.assign(process.env, saved);
  }
}

test('publicUrl: throws in production when OTHALA_PUBLIC_URL is absent', async () => {
  await assert.rejects(
    () => loadConfig({ NODE_ENV: 'production' }),
    /OTHALA_PUBLIC_URL/,
  );
});

test('publicUrl: throws in production when OTHALA_PUBLIC_URL is blank', async () => {
  await assert.rejects(
    () => loadConfig({ NODE_ENV: 'production', OTHALA_PUBLIC_URL: '   ' }),
    /OTHALA_PUBLIC_URL/,
  );
});

test('publicUrl: returns dev default in development when absent', async () => {
  const { publicUrl } = await loadConfig({ NODE_ENV: 'development' });
  assert.equal(publicUrl, 'http://localhost:4321');
});

test('publicUrl: returns dev default in test when absent', async () => {
  const { publicUrl } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(publicUrl, 'http://localhost:4321');
});

const PROD_REQUIRED = {
  OTHALA_APEX: 'example.com',
  OTHALA_SMTP_CONNECTION_URI: 'smtps://u:p@smtp.example.com:465',
  OTHALA_CONTACT_RECIPIENT: 'ops@example.com',
};

test('publicUrl: uses explicit value when set', async () => {
  const { publicUrl } = await loadConfig({
    NODE_ENV: 'production',
    OTHALA_PUBLIC_URL: 'https://auth.example.com',
    ...PROD_REQUIRED,
  });
  assert.equal(publicUrl, 'https://auth.example.com');
});

test('publicUrl: strips trailing slash from explicit value', async () => {
  const { publicUrl } = await loadConfig({
    NODE_ENV: 'production',
    OTHALA_PUBLIC_URL: 'https://auth.example.com/',
    ...PROD_REQUIRED,
  });
  assert.equal(publicUrl, 'https://auth.example.com');
});

test('publicUrl: strips multiple trailing slashes', async () => {
  const { publicUrl } = await loadConfig({
    NODE_ENV: 'production',
    OTHALA_PUBLIC_URL: 'https://auth.example.com///',
    ...PROD_REQUIRED,
  });
  assert.equal(publicUrl, 'https://auth.example.com');
});

test('smtpConnectionUri: throws in production when absent', async () => {
  await assert.rejects(
    () => loadConfig({ NODE_ENV: 'production', OTHALA_PUBLIC_URL: 'https://a.example.com', OTHALA_APEX: 'example.com' }),
    /OTHALA_SMTP_CONNECTION_URI/,
  );
});

test('smtpConnectionUri: returns dev default outside production', async () => {
  const { smtpConnectionUri } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(smtpConnectionUri, 'smtp://lab:lab@localhost:1025');
});

test('smtpConnectionUri: uses explicit value', async () => {
  const { smtpConnectionUri } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_SMTP_CONNECTION_URI: 'smtps://x:y@relay:465',
  });
  assert.equal(smtpConnectionUri, 'smtps://x:y@relay:465');
});

test('contactRecipient: uses explicit value when set', async () => {
  const { contactRecipient } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_CONTACT_RECIPIENT: 'ops@example.com',
  });
  assert.equal(contactRecipient, 'ops@example.com');
});

test('contactRecipient: throws in production when OTHALA_CONTACT_RECIPIENT is not set', async () => {
  await assert.rejects(
    () =>
      loadConfig({
        NODE_ENV: 'production',
        OTHALA_PUBLIC_URL: 'https://a.example.com',
        OTHALA_APEX: 'example.com',
        OTHALA_SMTP_CONNECTION_URI: 'smtps://u:p@relay:465',
      }),
    /contact recipient/,
  );
});

test('siteName: defaults to "Othala" when unset', async () => {
  const { siteName } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(siteName, 'Othala');
});

test('siteName: uses explicit value', async () => {
  const { siteName } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_SITE_NAME: 'Acme Portal',
  });
  assert.equal(siteName, 'Acme Portal');
});

test('adminContact: defaults to "your administrator" when unset', async () => {
  const { adminContact } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(adminContact, 'your administrator');
});

test('adminContact: uses explicit value', async () => {
  const { adminContact } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_ADMIN_CONTACT: 'helpdesk@example.com',
  });
  assert.equal(adminContact, 'helpdesk@example.com');
});

test('instanceName: falls back to siteName default when neither is set', async () => {
  const { instanceName, siteName } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(instanceName, siteName); // both 'Othala'
});

test('instanceName: falls back to OTHALA_SITE_NAME when only site name is set', async () => {
  const { instanceName } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_SITE_NAME: 'Acme Portal',
  });
  assert.equal(instanceName, 'Acme Portal');
});

test('instanceName: uses explicit OTHALA_INSTANCE_NAME when set', async () => {
  const { instanceName } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_SITE_NAME: 'Acme Portal',
    OTHALA_INSTANCE_NAME: 'Acme SSO',
  });
  assert.equal(instanceName, 'Acme SSO');
});

test('apex: throws in production when OTHALA_APEX is absent or blank', async () => {
  const env = { NODE_ENV: 'production', OTHALA_PUBLIC_URL: 'https://auth.example.com' };
  await assert.rejects(() => loadConfig(env), /OTHALA_APEX/);
  await assert.rejects(() => loadConfig({ ...env, OTHALA_APEX: '  ' }), /OTHALA_APEX/);
});

test('apex: dev default outside production, explicit value otherwise', async () => {
  assert.equal((await loadConfig({ NODE_ENV: 'test' })).apex, 'localhost');
  assert.equal((await loadConfig({ NODE_ENV: 'test', OTHALA_APEX: 'example.org' })).apex, 'example.org');
});

test('smtpFromAddress: derived as noreply@<OTHALA_APEX>', async () => {
  const { smtpFromAddress } = await loadConfig({ NODE_ENV: 'test', OTHALA_APEX: 'example.org' });
  assert.equal(smtpFromAddress, 'noreply@example.org');
});

test('smtpFromAddress: OTHALA_SMTP_FROM_ADDRESS overrides the derived value', async () => {
  const { smtpFromAddress } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_APEX: 'example.org',
    OTHALA_SMTP_FROM_ADDRESS: 'sso@mail.example.org',
  });
  assert.equal(smtpFromAddress, 'sso@mail.example.org');
});

test('config no longer exports a default schema id', async () => {
  const mod = await loadConfig({ NODE_ENV: 'test', OTHALA_DEFAULT_SCHEMA_ID: 'family' });
  assert.equal('defaultSchemaId' in mod, false);
});

test('identityGroups: defaults to ["admin", "everyone"] when unset (admin + default group)', async () => {
  const { identityGroups } = await loadConfig({ NODE_ENV: 'test' });
  assert.deepEqual(identityGroups, ['admin', 'everyone']);
});

test('identityGroups: parses comma-separated list with admin first, default group appended', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'admin,family,friends,work',
  });
  assert.deepEqual(identityGroups, ['admin', 'family', 'friends', 'work', 'everyone']);
});

test('identityGroups: prepends admin even when omitted from the list', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'family,friends',
  });
  assert.equal(identityGroups[0], 'admin');
  assert.ok(identityGroups.includes('family'));
  assert.ok(identityGroups.includes('friends'));
});

test('identityGroups: deduplicates admin if specified mid-list', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'family,admin,friends',
  });
  assert.deepEqual(identityGroups.filter((g) => g === 'admin').length, 1);
  assert.equal(identityGroups[0], 'admin');
});

test('identityGroups: lowercases group names', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'Family,FRIENDS',
  });
  assert.ok(identityGroups.includes('family'));
  assert.ok(identityGroups.includes('friends'));
});

test('identityGroups: trims whitespace around group names', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: ' family , friends ',
  });
  assert.ok(identityGroups.includes('family'));
  assert.ok(identityGroups.includes('friends'));
  assert.ok(!identityGroups.includes(' family '));
});

test('defaultGroup: defaults to "everyone" when unset', async () => {
  const { defaultGroup } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(defaultGroup, 'everyone');
});

test('defaultGroup: uses explicit value when set', async () => {
  const { defaultGroup } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_DEFAULT_GROUP: 'family',
  });
  assert.equal(defaultGroup, 'family');
});

test('identityGroups: default group appended when not already in list', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'admin,family,friends',
    OTHALA_DEFAULT_GROUP: 'everyone',
  });
  assert.ok(identityGroups.includes('everyone'),
    'default group must be appended to identityGroups');
  assert.equal(identityGroups[0], 'admin', 'admin must remain first');
});

test('identityGroups: default group not duplicated when already in list', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'admin,family,everyone',
    OTHALA_DEFAULT_GROUP: 'everyone',
  });
  const everyoneCount = identityGroups.filter((g) => g === 'everyone').length;
  assert.equal(everyoneCount, 1, 'default group must appear exactly once');
});

test('identityGroups: custom default group appended automatically', async () => {
  const { identityGroups, defaultGroup } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'admin,family',
    OTHALA_DEFAULT_GROUP: 'household',
  });
  assert.equal(defaultGroup, 'household');
  assert.ok(identityGroups.includes('household'),
    'custom default group must appear in identityGroups');
});

test('identityGroups: default group (everyone) appended to bare ["admin"] default', async () => {
  const { identityGroups } = await loadConfig({ NODE_ENV: 'test' });
  assert.deepEqual(identityGroups, ['admin', 'everyone']);
});

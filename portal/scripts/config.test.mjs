// Tests for src/lib/config.ts — the Othala portal env-config module.
//
// Run with: tsx --test scripts/config.test.mjs
//
// Coverage:
//   - required-no-default vars throw in production when absent
//   - required-no-default vars return dev defaults outside production
//   - neutral-default vars return their documented defaults when unset
//   - explicit env values override every default
//   - OTHALA_INSTANCE_NAME falls back to OTHALA_SITE_NAME
//   - OTHALA_IDENTITY_GROUPS: parsing, ordering, 'admin' invariant
//   - trailing-slash normalisation on OTHALA_PUBLIC_URL

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Import config.ts with a controlled env snapshot. Each call re-imports the
 * module in a fresh context (bypassing Node's ESM cache) by appending a
 * bust parameter so the module-load-time code re-runs.
 */
async function loadConfig(env = {}) {
  // Snapshot + override
  const saved = { ...process.env };
  // Clear all OTHALA_* vars first so stale values don't leak between tests.
  for (const key of Object.keys(process.env)) {
    if (key.startsWith('OTHALA_') || key === 'NODE_ENV') delete process.env[key];
  }
  Object.assign(process.env, env);

  try {
    const bust = `?bust=${Date.now()}-${Math.random()}`;
    const mod = await import(`../src/lib/config.ts${bust}`);
    return mod;
  } finally {
    // Restore original env
    for (const key of Object.keys(process.env)) {
      if (key.startsWith('OTHALA_') || key === 'NODE_ENV') delete process.env[key];
    }
    Object.assign(process.env, saved);
  }
}

// ── OTHALA_PUBLIC_URL ─────────────────────────────────────────────────────────

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

// The other required-in-prod vars must also be present or module load throws
// before reaching the publicUrl assertion. Bundle them into the prod-success
// env so these cases isolate the publicUrl behaviour under test.
const PROD_REQUIRED = {
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

// ── OTHALA_SMTP_CONNECTION_URI ────────────────────────────────────────────────

test('smtpConnectionUri: throws in production when absent', async () => {
  await assert.rejects(
    () => loadConfig({ NODE_ENV: 'production', OTHALA_PUBLIC_URL: 'https://a.example.com' }),
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

// ── OTHALA_CONTACT_RECIPIENT ──────────────────────────────────────────────────

test('contactRecipient: uses explicit value when set', async () => {
  const { contactRecipient } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_CONTACT_RECIPIENT: 'ops@example.com',
  });
  assert.equal(contactRecipient, 'ops@example.com');
});

test('contactRecipient: throws in production when OTHALA_CONTACT_RECIPIENT is not set', async () => {
  // Admin authority is the metadata_admin.admin marker (ADR 08), so no admin
  // email list exists to serve as a contact-form recipient fallback.
  // OTHALA_CONTACT_RECIPIENT is required in production.
  await assert.rejects(
    () =>
      loadConfig({
        NODE_ENV: 'production',
        OTHALA_PUBLIC_URL: 'https://a.example.com',
        OTHALA_SMTP_CONNECTION_URI: 'smtps://u:p@relay:465',
      }),
    /contact recipient/,
  );
});

// ── OTHALA_SITE_NAME ──────────────────────────────────────────────────────────

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

// ── OTHALA_ADMIN_CONTACT ──────────────────────────────────────────────────────

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

// ── OTHALA_INSTANCE_NAME ──────────────────────────────────────────────────────

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

// ── OTHALA_DEFAULT_SCHEMA_ID ──────────────────────────────────────────────────

test('defaultSchemaId: defaults to "default" when unset', async () => {
  const { defaultSchemaId } = await loadConfig({ NODE_ENV: 'test' });
  assert.equal(defaultSchemaId, 'default');
});

test('defaultSchemaId: uses explicit value', async () => {
  const { defaultSchemaId } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_DEFAULT_SCHEMA_ID: 'family',
  });
  assert.equal(defaultSchemaId, 'family');
});

// ── OTHALA_IDENTITY_GROUPS ────────────────────────────────────────────────────

test('identityGroups: defaults to ["admin", "everyone"] when unset (admin + default group)', async () => {
  const { identityGroups } = await loadConfig({ NODE_ENV: 'test' });
  assert.deepEqual(identityGroups, ['admin', 'everyone']);
});

test('identityGroups: parses comma-separated list with admin first, default group appended', async () => {
  const { identityGroups } = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_IDENTITY_GROUPS: 'admin,family,friends,work',
  });
  // 'everyone' (default OTHALA_DEFAULT_GROUP) is appended automatically.
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

// ── OTHALA_DEFAULT_GROUP ──────────────────────────────────────────────────────

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
  // When OTHALA_IDENTITY_GROUPS is unset the list starts as ['admin'];
  // defaultGroup ('everyone') must be appended.
  const { identityGroups } = await loadConfig({ NODE_ENV: 'test' });
  assert.deepEqual(identityGroups, ['admin', 'everyone']);
});

// ── aggregate config object ───────────────────────────────────────────────────

test('config object mirrors individual exports', async () => {
  const mod = await loadConfig({
    NODE_ENV: 'test',
    OTHALA_SITE_NAME: 'Test Site',
  });
  assert.equal(mod.config.siteName, mod.siteName);
  assert.equal(mod.config.publicUrl, mod.publicUrl);
  assert.equal(mod.config.adminContact, mod.adminContact);
  assert.equal(mod.config.instanceName, mod.instanceName);
  assert.equal(mod.config.defaultSchemaId, mod.defaultSchemaId);
  assert.equal(mod.config.defaultGroup, mod.defaultGroup);
  assert.deepEqual(mod.config.identityGroups, mod.identityGroups);
});

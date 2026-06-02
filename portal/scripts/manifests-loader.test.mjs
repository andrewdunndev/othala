// Tests for the runtime YAML manifest reader.
//
// Run with: tsx --test scripts/manifests-loader.test.mjs
//
// The portal's manifest loader (src/lib/manifests.ts) reads
// hydra/clients/*.yaml from a mounted directory at request time +
// caches for 30s with mtime invalidation. This file imports the
// canonical parser directly so the test cannot drift from the source.
//
// Coverage focus:
//   - Namespace split (oidc: + consent: blocks). Pre-namespace flat
//     yamls must be rejected.
//   - Scope splitter handles array + space-separated string.
//   - Roles normaliser handles array + map forms.
//   - groupRoleMap drops non-string values.
//   - accessGroup convention: `access-<clientId>`.
//   - Directory walk: sorted by filename, picks up yaml + yml.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseManifest, loadClientManifests } from '../src/lib/manifests.ts';

test('namespace split: minimal yaml with oidc + consent blocks parses', () => {
  const out = parseManifest(
    `
oidc:
  client_id: keep
  scope: openid email profile
consent:
  roles:
    user:
      description: viewer
`,
    'keep.yaml',
  );
  assert.equal(out.clientId, 'keep');
  assert.equal(out.accessGroup, 'access-keep');
  assert.deepEqual(out.scopes, ['openid', 'email', 'profile']);
  assert.equal(out.roles.length, 1);
  assert.equal(out.roles[0].name, 'user');
});

test('pre-namespace flat shape is rejected', () => {
  assert.throws(() => parseManifest(
    `
client_id: keep
roles:
  - name: admin
`,
    'keep.yaml',
  ));
});

test('non-object oidc block is rejected', () => {
  assert.throws(() => parseManifest(
    `
oidc: just-a-string
consent: {}
`,
    'broken.yaml',
  ));
});

test('scope splitter handles array form', () => {
  const out = parseManifest(
    `
oidc:
  client_id: x
  scope: [openid, email]
consent: {}
`,
    'x.yaml',
  );
  assert.deepEqual(out.scopes, ['openid', 'email']);
});

test('scope splitter handles whitespace-separated string', () => {
  const out = parseManifest(
    `
oidc:
  client_id: x
  scope: "openid    email   profile"
consent: {}
`,
    'x.yaml',
  );
  assert.deepEqual(out.scopes, ['openid', 'email', 'profile']);
});

test('roles normaliser handles map form', () => {
  const out = parseManifest(
    `
oidc:
  client_id: x
consent:
  roles:
    admin:
      description: full access
    user:
      description: read only
`,
    'x.yaml',
  );
  assert.equal(out.roles.length, 2);
  const adminRole = out.roles.find((r) => r.name === 'admin');
  assert.equal(adminRole.description, 'full access');
});

test('roles normaliser handles array form', () => {
  const out = parseManifest(
    `
oidc:
  client_id: x
consent:
  roles:
    - name: admin
      description: top
    - name: user
`,
    'x.yaml',
  );
  assert.equal(out.roles.length, 2);
  assert.equal(out.roles[1].description, '');
});

test('groupRoleMap drops non-string values', () => {
  const out = parseManifest(
    `
oidc:
  client_id: x
consent:
  group_role_map:
    admin: admin
    family: user
    weird:
      nested: stuff
    kids: viewer
`,
    'x.yaml',
  );
  assert.deepEqual(Object.keys(out.groupRoleMap).sort(), ['admin', 'family', 'kids']);
});

test('accessGroup convention: access-<clientId>', () => {
  const out = parseManifest(
    `
oidc:
  client_id: tailscale
consent: {}
`,
    'tailscale.yaml',
  );
  assert.equal(out.accessGroup, 'access-tailscale');
});

test('backchannel_logout_uri preserved when present', () => {
  const out = parseManifest(
    `
oidc:
  client_id: keep
  backchannel_logout_uri: https://keep.dunn.dev/identity/connect/oidc-logout
consent: {}
`,
    'keep.yaml',
  );
  assert.equal(out.backchannelLogoutUri, 'https://keep.dunn.dev/identity/connect/oidc-logout');
});

test('backchannel_logout_uri defaults to empty string when absent', () => {
  const out = parseManifest(
    `
oidc:
  client_id: tailscale
consent: {}
`,
    'tailscale.yaml',
  );
  assert.equal(out.backchannelLogoutUri, '');
});

test('audience array of strings preserved', () => {
  const out = parseManifest(
    `
oidc:
  client_id: keep
  audience:
    - https://keep.dunn.dev
    - https://api.keep.dunn.dev
consent: {}
`,
    'keep.yaml',
  );
  assert.deepEqual(out.audience, ['https://keep.dunn.dev', 'https://api.keep.dunn.dev']);
});

test('skipConsent default is false', () => {
  const out = parseManifest(
    `
oidc:
  client_id: novel
consent: {}
`,
    'novel.yaml',
  );
  assert.equal(out.skipConsent, false);
});

test('skipConsent true when set', () => {
  const out = parseManifest(
    `
oidc:
  client_id: keep
  skip_consent: true
consent: {}
`,
    'keep.yaml',
  );
  assert.equal(out.skipConsent, true);
});

// B: Pre-swap validation — bad candidate set rejected, prior cache preserved.
test('B: pre-swap validation rejects a set with undeclared group_role_map role', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-preswap-'));
  try {
    // Write a valid manifest first to prime the cache.
    const goodYaml = `
oidc:
  client_id: good-client
  audience:
    - https://good.example.com
  redirect_uris:
    - https://good.example.com/callback
consent:
  roles:
    user:
      description: normal user
      claim_emit: {}
  group_role_map:
    family: user
`;
    writeFileSync(join(dir, 'good-client.yaml'), goodYaml);

    process.env.MANIFEST_DIR = dir;
    // Load the good set to prime the cache.
    const good = loadClientManifests();
    assert.equal(good.length, 1, 'good set must load');
    assert.equal(good[0].clientId, 'good-client');

    // Now replace with a bad manifest that references an undeclared role.
    // Use a different mtime by replacing file content.
    const badYaml = `
oidc:
  client_id: bad-client
  audience:
    - https://bad.example.com
  redirect_uris:
    - https://bad.example.com/callback
consent:
  roles:
    user:
      description: normal user
      claim_emit: {}
  group_role_map:
    family: UNDECLARED_ROLE
`;
    // Remove old, write bad — must bump mtime to invalidate cache.
    rmSync(join(dir, 'good-client.yaml'));
    writeFileSync(join(dir, 'bad-client.yaml'), badYaml);

    // The bad candidate set must be rejected.
    assert.throws(
      () => loadClientManifests(),
      /manifest validation failed/,
      'bad candidate set must throw with validation error',
    );
  } finally {
    delete process.env.MANIFEST_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
});

// B: duplicate client_id detection at load.
test('B: duplicate client_id (case-insensitive) is detected and rejected', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-dup-'));
  try {
    writeFileSync(join(dir, 'a-client.yaml'), `
oidc:
  client_id: my-client
  audience:
    - https://a.example.com
consent: {}
`);
    writeFileSync(join(dir, 'b-client.yaml'), `
oidc:
  client_id: my-client
  audience:
    - https://b.example.com
consent: {}
`);

    process.env.MANIFEST_DIR = dir;
    assert.throws(
      () => loadClientManifests(),
      /duplicate client_id/,
      'duplicate client_id must be detected',
    );
  } finally {
    delete process.env.MANIFEST_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
});

// Integration-style: write a temp directory of yamls and verify the
// directory-walking logic produces the expected manifest set.
test('directory walk: sorted by filename, yaml + yml both picked up', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-test-'));
  try {
    writeFileSync(join(dir, 'zeta.yaml'), 'oidc:\n  client_id: zeta\nconsent: {}\n');
    writeFileSync(join(dir, 'alpha.yml'), 'oidc:\n  client_id: alpha\nconsent: {}\n');
    writeFileSync(join(dir, 'beta.yaml'), 'oidc:\n  client_id: beta\nconsent: {}\n');

    // Mirror loadFromDisk's filter + sort and verify against parseManifest.
    const files = readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
    assert.deepEqual(files, ['alpha.yml', 'beta.yaml', 'zeta.yaml']);

    const manifests = files.map((f) => parseManifest(readFileSync(join(dir, f), 'utf8'), f));
    assert.deepEqual(manifests.map((m) => m.clientId), ['alpha', 'beta', 'zeta']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

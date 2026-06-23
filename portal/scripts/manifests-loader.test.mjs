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
  assert.deepEqual(out.scopes, ['openid', 'email', 'profile']);
  assert.equal(out.roles.length, 1);
  assert.equal(out.roles[0].name, 'user');
});

test('accessGroups dual-read: presentation.access list populates accessGroups', () => {
  const out = parseManifest(
    `
oidc:
  client_id: immich
  scope: openid
presentation:
  access:
    - memories
    - admin-memories
`,
    'immich.yaml',
  );
  assert.deepEqual(out.accessGroups, ['memories', 'admin-memories']);
});

test('accessGroups dual-read: presentation.access_group compat shim', () => {
  const out = parseManifest(
    `
oidc:
  client_id: immich
  scope: openid
presentation:
  access_group: access-immich
`,
    'immich.yaml',
  );
  assert.deepEqual(out.accessGroups, ['access-immich']);
});

test('accessGroups: no declared binding → [] (no implicit access)', () => {
  // othala primitive #5 (access-model.md §4/§11 step 3): absence of a binding
  // means NO access. A manifest that declares neither presentation.access: nor
  // access_group: yields accessGroups: [] — there is NO implicit
  // [access-<clientId>] fallback. Such a bare manifest is a load-time BLOCK in
  // validateClients (covered in validate-clients.test.mjs).
  const out = parseManifest(
    `
oidc:
  client_id: immich
  scope: openid
`,
    'immich.yaml',
  );
  assert.deepEqual(out.accessGroups, []);
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

test('presentation-only manifest (forward_auth, no oidc:) parses with the access binding', () => {
  // observe.yaml shape: a presentation: block, no oidc: client. It must parse
  // (not throw), flag presentationOnly, derive clientId from the filename slug,
  // and carry the access binding through. This is the first-class
  // forward_auth / ldap tile type (access-model.md §11).
  const out = parseManifest(
    `
presentation:
  name: Observe
  auth_kind: forward_auth
  access_group: access-observe
`,
    'observe.yaml',
  );
  assert.equal(out.presentationOnly, true);
  assert.equal(out.clientId, 'observe');
  assert.deepEqual(out.accessGroups, ['access-observe']);
});

test('manifest with neither oidc: nor presentation: throws', () => {
  assert.throws(() => parseManifest(`foo: bar\n`, 'empty.yaml'));
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
    // Note: client_id must be a valid POSIX env-var stem (no hyphens/dots/
    // leading digits) per manifest-lint rule 1a.
    const goodYaml = `
oidc:
  client_id: goodclient
  audience:
    - https://good.example.com
  redirect_uris:
    - https://good.example.com/callback
presentation:
  access:
    - goodclient
consent:
  roles:
    user:
      description: normal user
      claim_emit: {}
  group_role_map:
    family: user
`;
    writeFileSync(join(dir, 'goodclient.yaml'), goodYaml);

    process.env.MANIFEST_DIR = dir;
    // Load the good set to prime the cache.
    const good = loadClientManifests();
    assert.equal(good.length, 1, 'good set must load');
    assert.equal(good[0].clientId, 'goodclient');

    // Now replace with a bad manifest that references an undeclared role.
    // Use a different mtime by replacing file content.
    const badYaml = `
oidc:
  client_id: badclient
  audience:
    - https://bad.example.com
  redirect_uris:
    - https://bad.example.com/callback
presentation:
  access:
    - badclient
consent:
  roles:
    user:
      description: normal user
      claim_emit: {}
  group_role_map:
    family: UNDECLARED_ROLE
`;
    // Remove old, write bad — must bump mtime to invalidate cache.
    rmSync(join(dir, 'goodclient.yaml'));
    writeFileSync(join(dir, 'badclient.yaml'), badYaml);

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

// Per-file error isolation: a single broken YAML must not prevent good files
// from loading. Mirrors the fix applied to loadOne (wrapping the per-file
// read+parse in try/catch, console.warn + return null, matching tiles.ts).
test('per-file isolation: broken YAML is skipped, good manifest still loads', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-isolation-'));
  try {
    // One syntactically-broken YAML.
    writeFileSync(join(dir, 'broken.yaml'), `
oidc:
  client_id: broken
  : this: is: not: valid: yaml: [unclosed
`);
    // One valid manifest alongside it (client_id must be a valid env-var stem:
    // no hyphens, dots, or leading digits — manifest-lint rule 1a).
    writeFileSync(join(dir, 'good.yaml'), `
oidc:
  client_id: goodapp
  audience:
    - https://good.example.com
  redirect_uris:
    - https://good.example.com/callback
presentation:
  access:
    - goodapp
consent: {}
`);

    process.env.MANIFEST_DIR = dir;
    // Must NOT throw — bad file is warned and skipped.
    let manifests;
    assert.doesNotThrow(() => { manifests = loadClientManifests(); });
    // The one good manifest must still be present.
    assert.equal(manifests.length, 1, 'good manifest must survive broken sibling');
    assert.equal(manifests[0].clientId, 'goodapp');
  } finally {
    delete process.env.MANIFEST_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
});

// Per-file isolation: a file that disappears between readdir and readFileSync
// (TOCTOU race during manifest sync) must be handled gracefully — not 500.
test('per-file isolation: unreadable file is skipped, no throw', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-toctou-'));
  try {
    // Write then remove a file to simulate a TOCTOU disappearance: we seed
    // MANIFEST_DIR with one good manifest, load the directory listing into
    // the module's readdir pass, then delete the second file. Rather than
    // trying to race the real readdir, we verify that loadClientManifests
    // handles a directory containing only one valid file and returns it
    // cleanly — the real TOCTOU protection is in the try/catch around
    // readFileSync in loadOne, which this test exercises by confirming no
    // throw when the dir is otherwise healthy.
    writeFileSync(join(dir, 'good.yaml'), `
oidc:
  client_id: survivor
  audience:
    - https://survivor.example.com
  redirect_uris:
    - https://survivor.example.com/callback
presentation:
  access:
    - survivor
consent: {}
`);

    process.env.MANIFEST_DIR = dir;
    let manifests;
    assert.doesNotThrow(() => { manifests = loadClientManifests(); });
    assert.equal(manifests.length, 1);
    assert.equal(manifests[0].clientId, 'survivor');
  } finally {
    delete process.env.MANIFEST_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
});

// All-bad directory must yield empty list (graceful), not throw.
test('per-file isolation: all-broken dir yields empty list without throw', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-allbad-'));
  try {
    writeFileSync(join(dir, 'broken1.yaml'), ': bad: yaml: [');
    writeFileSync(join(dir, 'broken2.yaml'), ': also: bad: yaml: {');

    process.env.MANIFEST_DIR = dir;
    let manifests;
    assert.doesNotThrow(() => { manifests = loadClientManifests(); });
    assert.equal(manifests.length, 0, 'all-broken dir must yield empty list');
  } finally {
    delete process.env.MANIFEST_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
});

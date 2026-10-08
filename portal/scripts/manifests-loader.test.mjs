// Invariant: the runtime manifest loader validates before swapping and never serves a partial set.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseManifest, loadClientManifests, invalidateManifestCache, setManifestDir } from '../src/lib/manifests.ts';
import { decideAccess } from '../src/lib/gate.ts';

test('namespace split: minimal yaml with oidc + consent blocks parses', () => {
  const out = parseManifest(
    `
oidc:
  client_id: filedrop
  scope: openid email profile
consent:
  roles:
    user:
      description: viewer
`,
    'filedrop.yaml',
  );
  assert.equal(out.clientId, 'filedrop');
  assert.deepEqual(out.scopes, ['openid', 'email', 'profile']);
  assert.equal(out.roles.length, 1);
  assert.equal(out.roles[0].name, 'user');
});

test('accessGroups: presentation.access list populates accessGroups', () => {
  const out = parseManifest(
    `
oidc:
  client_id: photos
  scope: openid
presentation:
  access:
    - memories
    - admin-memories
`,
    'photos.yaml',
  );
  assert.deepEqual(out.accessGroups, ['memories', 'admin-memories']);
});

test('accessGroups: the singular access_group key binds nothing and the gate denies', () => {
  const out = parseManifest(
    `
oidc:
  client_id: photos
  scope: openid
presentation:
  access_group: access-photos
`,
    'photos.yaml',
  );
  assert.deepEqual(out.accessGroups, []);
  const member = { id: 'm', state: 'active', traits: {}, metadata_admin: { groups: ['access-photos'] } };
  assert.ok('deny' in decideAccess(member, { app: out }, { authenticator_assurance_level: 'aal2' }));
});

test('accessGroups: no declared binding → [] (no implicit access)', () => {
  const out = parseManifest(
    `
oidc:
  client_id: photos
  scope: openid
`,
    'photos.yaml',
  );
  assert.deepEqual(out.accessGroups, []);
});

test('a manifest without an oidc: block or presentation: is rejected as missing oidc', () => {
  assert.throws(() => parseManifest(
    `
client_id: filedrop
roles:
  - name: admin
`,
    'filedrop.yaml',
  ), /missing or non-object oidc: block/);
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
  const out = parseManifest(
    `
presentation:
  name: Proxywatch
  auth_kind: forward_auth
  access: [access-proxywatch]
`,
    'proxywatch.yaml',
  );
  assert.equal(out.presentationOnly, true);
  assert.equal(out.clientId, 'proxywatch');
  assert.deepEqual(out.accessGroups, ['access-proxywatch']);
});

test('manifest with neither oidc: nor presentation: throws', () => {
  assert.throws(() => parseManifest(`foo: bar\n`, 'empty.yaml'));
});

test('backchannel_logout_uri preserved when present', () => {
  const out = parseManifest(
    `
oidc:
  client_id: filedrop
  backchannel_logout_uri: https://filedrop.othala.test/identity/connect/oidc-logout
consent: {}
`,
    'filedrop.yaml',
  );
  assert.equal(out.backchannelLogoutUri, 'https://filedrop.othala.test/identity/connect/oidc-logout');
});

test('backchannel_logout_uri defaults to empty string when absent', () => {
  const out = parseManifest(
    `
oidc:
  client_id: meshvpn
consent: {}
`,
    'meshvpn.yaml',
  );
  assert.equal(out.backchannelLogoutUri, '');
});

test('audience array of strings preserved', () => {
  const out = parseManifest(
    `
oidc:
  client_id: filedrop
  audience:
    - https://filedrop.othala.test
    - https://api.filedrop.othala.test
consent: {}
`,
    'filedrop.yaml',
  );
  assert.deepEqual(out.audience, ['https://filedrop.othala.test', 'https://api.filedrop.othala.test']);
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
  client_id: filedrop
  skip_consent: true
consent: {}
`,
    'filedrop.yaml',
  );
  assert.equal(out.skipConsent, true);
});

const VALID = (id) => `
oidc:
  client_id: ${id}
  audience:
    - https://${id}.example.com
  redirect_uris:
    - https://${id}.example.com/callback
presentation:
  access:
    - ${id}
consent: {}
`;

function loadFrom(files) {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-quarantine-'));
  try {
    for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
    setManifestDir(dir);
    invalidateManifestCache();
    return loadClientManifests().map((m) => m.clientId);
  } finally {
    setManifestDir(undefined);
    invalidateManifestCache();
    rmSync(dir, { recursive: true, force: true });
  }
}

test('B: an invalid manifest sorted first is dropped and the valid one loads', () => {
  const invalid = VALID('aa').replace('consent: {}', 'consent:\n  group_role_map:\n    family: UNDECLARED');
  assert.deepEqual(loadFrom({ 'aa-invalid.yaml': invalid, 'grafana.yaml': VALID('grafana') }), ['grafana']);
});

test('B: duplicate client_id (case-insensitive) drops every file carrying it', () => {
  assert.deepEqual(
    loadFrom({
      'a-client.yaml': VALID('myclient'),
      'b-client.yaml': VALID('myclient').replace('client_id: myclient', 'client_id: MyClient'),
      'c.yaml': VALID('keeper'),
    }),
    ['keeper'],
  );
});

test('directory walk: sorted by filename, yaml + yml both picked up', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-test-'));
  try {
    writeFileSync(join(dir, 'zeta.yaml'), 'oidc:\n  client_id: zeta\nconsent: {}\n');
    writeFileSync(join(dir, 'alpha.yml'), 'oidc:\n  client_id: alpha\nconsent: {}\n');
    writeFileSync(join(dir, 'beta.yaml'), 'oidc:\n  client_id: beta\nconsent: {}\n');

    const files = readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
    assert.deepEqual(files, ['alpha.yml', 'beta.yaml', 'zeta.yaml']);

    const manifests = files.map((f) => parseManifest(readFileSync(join(dir, f), 'utf8'), f));
    assert.deepEqual(manifests.map((m) => m.clientId), ['alpha', 'beta', 'zeta']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('per-file isolation: broken YAML is skipped, good manifest still loads', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-isolation-'));
  try {
    writeFileSync(join(dir, 'broken.yaml'), `
oidc:
  client_id: broken
  : this: is: not: valid: yaml: [unclosed
`);
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

    setManifestDir(dir);
    let manifests;
    assert.doesNotThrow(() => { manifests = loadClientManifests(); });
    assert.equal(manifests.length, 1, 'good manifest must survive broken sibling');
    assert.equal(manifests[0].clientId, 'goodapp');
  } finally {
    setManifestDir(undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('per-file isolation: unreadable file is skipped, no throw', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-toctou-'));
  try {
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

    setManifestDir(dir);
    let manifests;
    assert.doesNotThrow(() => { manifests = loadClientManifests(); });
    assert.equal(manifests.length, 1);
    assert.equal(manifests[0].clientId, 'survivor');
  } finally {
    setManifestDir(undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('per-file isolation: all-broken dir yields empty list without throw', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-allbad-'));
  try {
    writeFileSync(join(dir, 'broken1.yaml'), ': bad: yaml: [');
    writeFileSync(join(dir, 'broken2.yaml'), ': also: bad: yaml: {');

    setManifestDir(dir);
    let manifests;
    assert.doesNotThrow(() => { manifests = loadClientManifests(); });
    assert.equal(manifests.length, 0, 'all-broken dir must yield empty list');
  } finally {
    setManifestDir(undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});

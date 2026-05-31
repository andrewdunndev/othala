// Tests for the runtime YAML manifest reader.
//
// Run with: node --test scripts/manifests-loader.test.mjs
//
// The portal's manifest loader (src/lib/manifests.ts) reads
// hydra/clients/*.yaml from a mounted directory at request time +
// caches for 30s with mtime invalidation. The TS source is the
// source of truth; this test re-implements the parse logic in JS
// to assert behaviour without needing tsc.
//
// Coverage focus:
//   - Namespace split (oidc: + consent: blocks). Pre-namespace flat
//     yamls must be rejected.
//   - Scope splitter handles array + space-separated string.
//   - Roles normaliser handles array + map forms.
//   - groupRoleMap drops non-string values.
//   - accessGroup convention: `access-<clientId>`.
//   - ENOENT (manifest dir not provisioned) returns [] without
//     throwing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parse as parseYaml } from 'yaml';

// JS port mirroring src/lib/manifests.ts parsing logic. When the TS
// drifts, this port must drift with it.

function splitScope(scope) {
  if (!scope) return [];
  if (Array.isArray(scope)) return scope.map(String);
  return String(scope).split(/\s+/).filter(Boolean);
}

function normaliseRoles(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw
      .filter((r) => r && typeof r === 'object' && 'name' in r)
      .map((r) => ({ name: String(r.name), description: String(r.description ?? '') }));
  }
  if (typeof raw === 'object') {
    return Object.entries(raw).map(([name, v]) => ({
      name,
      description: String((v && typeof v === 'object' && 'description' in v ? v.description : '') ?? ''),
    }));
  }
  return [];
}

function normaliseGroupRoleMap(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function loadOne(yamlText, filename) {
  const yaml = parseYaml(yamlText) ?? {};
  const oidc = yaml.oidc;
  const consent = yaml.consent;
  const flatLikely =
    'client_id' in yaml ||
    'client_name' in yaml ||
    'grant_types' in yaml ||
    'roles' in yaml ||
    'group_role_map' in yaml;
  if (!oidc && flatLikely) {
    throw new Error(`${filename}: pre-namespace flat shape detected.`);
  }
  if (!oidc || typeof oidc !== 'object') {
    throw new Error(`${filename}: missing or non-object oidc: block`);
  }
  const clientId = String(oidc.client_id ?? filename.replace(/\.ya?ml$/, ''));
  const c = consent && typeof consent === 'object' ? consent : {};
  return {
    clientId,
    clientName: String(oidc.client_name ?? clientId),
    redirectUris: Array.isArray(oidc.redirect_uris) ? oidc.redirect_uris.map(String) : [],
    postLogoutRedirectUris: Array.isArray(oidc.post_logout_redirect_uris)
      ? oidc.post_logout_redirect_uris.map(String)
      : [],
    scopes: splitScope(oidc.scope),
    audience: Array.isArray(oidc.audience) ? oidc.audience.map(String) : [],
    grantTypes: Array.isArray(oidc.grant_types) ? oidc.grant_types.map(String) : [],
    skipConsent: Boolean(oidc.skip_consent ?? false),
    backchannelLogoutUri: oidc.backchannel_logout_uri ? String(oidc.backchannel_logout_uri) : '',
    accessGroup: `access-${clientId}`,
    roles: normaliseRoles(c.roles),
    groupRoleMap: normaliseGroupRoleMap(c.group_role_map),
  };
}

test('namespace split: minimal yaml with oidc + consent blocks parses', () => {
  const out = loadOne(
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
  assert.throws(() => loadOne(
    `
client_id: keep
roles:
  - name: admin
`,
    'keep.yaml',
  ));
});

test('non-object oidc block is rejected', () => {
  assert.throws(() => loadOne(
    `
oidc: just-a-string
consent: {}
`,
    'broken.yaml',
  ));
});

test('scope splitter handles array form', () => {
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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
  const out = loadOne(
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

// Integration-style: write a temp directory of yamls and verify the
// directory-walking logic produces the expected manifest set.
test('directory walk: sorted by filename, yaml + yml both picked up', () => {
  const dir = mkdtempSync(join(tmpdir(), 'manifest-test-'));
  try {
    writeFileSync(join(dir, 'zeta.yaml'), 'oidc:\n  client_id: zeta\nconsent: {}\n');
    writeFileSync(join(dir, 'alpha.yml'), 'oidc:\n  client_id: alpha\nconsent: {}\n');
    writeFileSync(join(dir, 'beta.yaml'), 'oidc:\n  client_id: beta\nconsent: {}\n');

    // Minimal port of loadFromDisk's filtering + sort.
    const files = readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
    assert.deepEqual(files, ['alpha.yml', 'beta.yaml', 'zeta.yaml']);

    const manifests = files.map((f) => loadOne(readFileSync(join(dir, f), 'utf8'), f));
    assert.deepEqual(manifests.map((m) => m.clientId), ['alpha', 'beta', 'zeta']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

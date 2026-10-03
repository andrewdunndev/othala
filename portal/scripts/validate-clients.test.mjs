// Invariant: every validateClients rule fires on a crafted bad manifest and the real manifest set is clean.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseManifest,
  validateClients,
  assertManifestsValid,
  shouldEmitGroups,
  CLIENT_ID_RE,
} from '../src/lib/manifests.ts';

const here = dirname(fileURLToPath(import.meta.url));
const clientsDir = join(here, '..', '..', 'hydra', 'clients');

function fromYaml(yamlText, filename = 'crafted.yaml') {
  return parseManifest(yamlText, filename);
}

test('CLIENT_ID_RE: lowercase ids pass', () => {
  for (const id of ['filedrop', 'promptdesk', 'llm', 'app123']) {
    assert.ok(CLIENT_ID_RE.test(id), `expected ${JSON.stringify(id)} to be valid`);
  }
});

test('CLIENT_ID_RE: rejects hyphens, dots, underscores, capitals and leading digits', () => {
  for (const id of ['prompt-desk', 'my.app', '1app', 'app-', 'a b', 'my_app', '_app', 'App123']) {
    assert.ok(!CLIENT_ID_RE.test(id), `expected ${JSON.stringify(id)} to be rejected`);
  }
});

test('rule 1a: hyphenated client_id fires the client_id error', () => {
  const m = fromYaml(`
oidc:
  client_id: prompt-desk
  redirect_uris:
    - https://prompt-desk.othala.test/cb
  audience:
    - https://prompt-desk.othala.test
consent:
  skip_access_check: true
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some(
      (e) =>
        e.includes('prompt-desk') &&
        e.includes('must match'),
    ),
    `expected client_id error, got:\n${errs.join('\n')}`,
  );
});

test('rule 1a: client_id with a dot fires the client_id error', () => {
  const m = fromYaml(`
oidc:
  client_id: my.app
  audience:
    - https://my-app.othala.test
consent:
  skip_access_check: true
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('"my.app"') && e.includes('must match')),
    `expected client_id error, got:\n${errs.join('\n')}`,
  );
});

test('rule 1a: client_id starting with a digit fires the client_id error', () => {
  const m = fromYaml(`
oidc:
  client_id: 2app
  audience:
    - https://app.othala.test
consent:
  skip_access_check: true
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('must match')),
    `expected client_id error, got:\n${errs.join('\n')}`,
  );
});

test('rule 1a: valid client_id without hyphens does NOT fire the client_id error', () => {
  const m = fromYaml(`
oidc:
  client_id: promptdesk
  redirect_uris:
    - https://promptdesk.othala.test/cb
  audience:
    - https://promptdesk.othala.test
presentation:
  access:
    - access-llm
consent: {}
`);
  const errs = validateClients([m]);
  assert.equal(
    errs.filter((e) => e.includes('must match')).length,
    0,
    `promptdesk should not trigger the client_id rule:\n${errs.join('\n')}`,
  );
});

test('rule 1a: assertManifestsValid surfaces the client_id error in the thrown message', () => {
  const m = fromYaml(`
oidc:
  client_id: prompt-desk
  redirect_uris:
    - https://prompt-desk.othala.test/cb
  audience:
    - https://prompt-desk.othala.test
consent:
  skip_access_check: true
`);
  assert.throws(
    () => assertManifestsValid([m]),
    (err) =>
      /manifest validation failed/.test(err.message) &&
      /must match/.test(err.message) &&
      /prompt-desk/.test(err.message),
  );
});

test('rule: empty audience fires (every client needs an audience)', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
consent: {}
`);
  const errs = validateClients([m]);
  assert.ok(errs.some((e) => e.includes('oidc.audience is empty')), errs.join('\n'));
});

test('rule: audience that matches no redirect origin fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://wrong.othala.test
consent: {}
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('no oidc.audience origin matches')),
    errs.join('\n'),
  );
});

test('rule: exact-origin audience+redirect passes the audience sub-check', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
consent: {}
`);
  const errs = validateClients([m]);
  assert.equal(
    errs.filter((e) => e.includes('audience')).length,
    0,
    errs.join('\n'),
  );
});

test('rule: client_credentials client with audience but no redirect passes (machine-to-machine shape)', () => {
  const m = fromYaml(`
oidc:
  client_id: api
  grant_types:
    - client_credentials
  audience:
    - https://api.othala.test
presentation:
  access:
    - api
consent: {}
`);
  const errs = validateClients([m]);
  assert.deepEqual(errs, [], errs.join('\n'));
});

test('rule: group_role_map referencing an undeclared role fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
consent:
  roles:
    user:
      description: viewer
      claim_emit: {}
  group_role_map:
    admin: superuser
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some(
      (e) =>
        e.includes('group_role_map') &&
        e.includes('superuser') &&
        e.includes('not declared'),
    ),
    errs.join('\n'),
  );
});

test('rule: group_role_map all mapping to declared roles passes', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
presentation:
  access:
    - novel
consent:
  roles:
    user:
      description: viewer
      claim_emit: {}
  group_role_map:
    family: user
`);
  assert.deepEqual(validateClients([m]), []);
});

test('rule: declared role with no claim_emit key fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
consent:
  roles:
    user:
      description: viewer
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('has no claim_emit')),
    errs.join('\n'),
  );
});

test('rule: empty claim_emit {} is NOT a violation (identity-only clients)', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
consent:
  roles:
    user:
      description: identity only
      claim_emit: {}
`);
  const errs = validateClients([m]);
  assert.equal(errs.filter((e) => e.includes('claim_emit')).length, 0, errs.join('\n'));
});

test('rule: M10 contradiction (emit_groups_claim:false + role groups claim) fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
consent:
  emit_groups_claim: false
  roles:
    user:
      description: viewer
      claim_emit:
        groups: ["family"]
  group_role_map:
    family: user
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some(
      (e) =>
        e.includes('emit_groups_claim:false') && e.includes('claim_emit.groups'),
    ),
    errs.join('\n'),
  );
});

test('rule: emit_groups_claim:false WITHOUT a role groups claim does NOT fire M10', () => {
  const m = fromYaml(`
oidc:
  client_id: meshvpn
  redirect_uris:
    - https://login.meshvpn.example/cb
  audience:
    - https://login.meshvpn.example
consent:
  emit_groups_claim: false
  roles:
    user:
      description: identity only
      claim_emit: {}
  group_role_map:
    family: user
`);
  const errs = validateClients([m]);
  assert.equal(errs.filter((e) => e.includes('emit_groups_claim')).length, 0, errs.join('\n'));
});

test('rule: emit_groups_claim:true + role groups claim is fine (no contradiction)', () => {
  const m = fromYaml(`
oidc:
  client_id: filedrop
  redirect_uris:
    - https://filedrop.othala.test/cb
  audience:
    - https://filedrop.othala.test
consent:
  emit_groups_claim: true
  roles:
    user:
      description: viewer
      claim_emit:
        groups: ["family"]
  group_role_map:
    family: user
`);
  const errs = validateClients([m]);
  assert.equal(errs.filter((e) => e.includes('emit_groups_claim')).length, 0, errs.join('\n'));
});

test('shouldEmitGroups: absent emit_groups_claim defaults true', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
consent: {}
`);
  assert.equal(m.emitGroupsClaim, null);
  assert.equal(shouldEmitGroups(m), true);
});

test('shouldEmitGroups: explicit false suppresses', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
consent:
  emit_groups_claim: false
`);
  assert.equal(m.emitGroupsClaim, false);
  assert.equal(shouldEmitGroups(m), false);
});

test('assertManifestsValid throws on a bad set, with all findings in the message', () => {
  const bad = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
consent:
  roles:
    user:
      description: no claim_emit
`);
  assert.throws(
    () => assertManifestsValid([bad]),
    (err) =>
      /manifest validation failed/.test(err.message) &&
      /oidc.audience is empty/.test(err.message) &&
      /has no claim_emit/.test(err.message),
  );
});

test('assertManifestsValid does not throw on a clean set', () => {
  const good = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
presentation:
  access:
    - novel
consent:
  roles:
    user:
      description: viewer
      claim_emit: {}
  group_role_map:
    family: user
`);
  assert.doesNotThrow(() => assertManifestsValid([good]));
});

test('BLOCK: bare manifest (no access binding, no skip) is a load-time hard-fail', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.othala.test/cb
  audience:
    - https://novel.othala.test
consent: {}
`);
  assert.deepEqual(m.accessGroups, []);
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('presentation.access is empty') && e.includes('unreachable')),
    errs.join('\n'),
  );
  assert.throws(() => assertManifestsValid([m]), /manifest validation failed/);
});

test('BLOCK: skip_access_check bypasses the empty-binding block', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  audience:
    - https://novel.othala.test
consent:
  skip_access_check: true
`);
  const errs = validateClients([m]);
  assert.equal(
    errs.filter((e) => e.includes('presentation.access is empty')).length,
    0,
    errs.join('\n'),
  );
});

test('BLOCK: a group listed twice in the access binding fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  audience:
    - https://novel.othala.test
presentation:
  access:
    - memories
    - memories
consent: {}
`);
  m.accessGroups = ['memories', 'memories'];
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('more than once')),
    errs.join('\n'),
  );
});

test('presentation-only manifest is valid WITHOUT an oidc: block (audience rule skipped)', () => {
  const m = fromYaml(`
presentation:
  name: Proxywatch
  auth_kind: forward_auth
  access: [access-proxywatch]
`, 'proxywatch.yaml');
  assert.equal(m.presentationOnly, true);
  assert.deepEqual(validateClients([m]), []);
});

test('presentation-only manifest with NO access binding is still a BLOCK', () => {
  const m = fromYaml(`
presentation:
  name: Lonely
  auth_kind: forward_auth
`, 'lonely.yaml');
  const errs = validateClients([m]);
  assert.ok(errs.some((e) => e.includes('unreachable')), errs.join('\n'));
});

const e2eClientsDir = join(here, '..', '..', 'e2e', 'manifests');

test('every e2e/manifests/*.yaml round-trips AND the set passes validateClients', () => {
  const files = readdirSync(e2eClientsDir)
    .filter((f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml');
  assert.ok(files.length > 0, 'expected at least one e2e fixture manifest');
  const manifests = files
    .map((f) => parseManifest(readFileSync(join(e2eClientsDir, f), 'utf8'), f))
    .filter((m) => !m.presentationOnly);
  const errs = validateClients(manifests);
  assert.deepEqual(errs, [], `e2e fixtures should be clean:\n${errs.join('\n')}`);
});

test('promptdesk.yaml: parses correctly — client_id, access binding, redirect, audience, roles', () => {
  const yaml = readFileSync(join(e2eClientsDir, 'promptdesk.yaml'), 'utf8');
  const m = parseManifest(yaml, 'promptdesk.yaml');

  assert.equal(m.clientId, 'promptdesk', 'client_id must be promptdesk');
  assert.equal(m.presentationOnly, false, 'must be an OIDC client, not presentation-only');

  assert.deepEqual(m.accessGroups, ['prompt-access'], 'must bind exactly the prompt-access group');

  assert.deepEqual(m.redirectUris, ['https://prompt.othala.test/oauth/oidc/callback']);
  assert.deepEqual(m.postLogoutRedirectUris, ['https://prompt.othala.test/']);
  assert.deepEqual(m.audience, ['https://prompt.othala.test']);
  assert.equal(m.skipConsent, true);
  assert.ok(m.scopes.includes('openid'), 'must request openid scope');
  assert.ok(m.scopes.includes('offline_access'), 'must request offline_access for refresh_token');
  assert.ok(m.scopes.includes('groups'), 'must request groups scope for role claim');

  assert.ok(m.emitGroupsClaim !== false, 'emit_groups_claim must not be suppressed');
  const adminRole = m.roles.find((r) => r.name === 'admin');
  const userRole = m.roles.find((r) => r.name === 'user');
  assert.ok(adminRole, 'admin role must be declared');
  assert.ok(userRole, 'user role must be declared');
  assert.ok(adminRole.claimEmit !== null, 'admin role must have claim_emit');
  assert.ok(userRole.claimEmit !== null, 'user role must have claim_emit');

  assert.equal(m.groupRoleMap['prompt-admin'], 'admin');
  assert.equal(m.groupRoleMap['prompt-access'], 'user');

  const errs = validateClients([m]);
  assert.deepEqual(errs, [], `promptdesk.yaml must validate clean:\n${errs.join('\n')}`);
});

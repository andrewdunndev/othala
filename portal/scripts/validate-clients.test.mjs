// Tests for the full validateClients lint port in src/lib/manifests.ts
// (CU2 item 3). Every rule from consent/manifest.go's validateClients is
// proven to fire on a crafted bad manifest, and the real on-disk manifest
// set is proven clean.
//
// Run with: tsx --test scripts/validate-clients.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseManifest,
  validateClients,
  assertManifestsValid,
  shouldEmitGroups,
} from '../src/lib/manifests.ts';

const here = dirname(fileURLToPath(import.meta.url));
const clientsDir = join(here, '..', '..', 'hydra', 'clients');

function fromYaml(yamlText, filename = 'crafted.yaml') {
  return parseManifest(yamlText, filename);
}

// ── Rule 2 + 3: audience presence + audienceMatchesRedirect ────────────────

test('rule: empty audience fires (every client needs an audience)', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.dunn.dev/cb
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
    - https://novel.dunn.dev/cb
  audience:
    - https://wrong.dunn.dev
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
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
consent: {}
`);
  const errs = validateClients([m]);
  assert.equal(
    errs.filter((e) => e.includes('audience')).length,
    0,
    errs.join('\n'),
  );
});

test('rule: client_credentials client with audience but no redirect passes (llm shape)', () => {
  const m = fromYaml(`
oidc:
  client_id: llm
  grant_types:
    - client_credentials
  audience:
    - https://llm.dunn.dev
presentation:
  access:
    - llm
consent: {}
`);
  const errs = validateClients([m]);
  assert.deepEqual(errs, [], errs.join('\n'));
});

// ── Rule 4: group_role_map points at an undeclared role ────────────────────

test('rule: group_role_map referencing an undeclared role fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
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
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
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

// ── Rule 5: declared role missing claim_emit ───────────────────────────────

test('rule: declared role with no claim_emit key fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
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
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
consent:
  roles:
    user:
      description: identity only
      claim_emit: {}
`);
  const errs = validateClients([m]);
  assert.equal(errs.filter((e) => e.includes('claim_emit')).length, 0, errs.join('\n'));
});

// ── Rule 6: M10 emit_groups_claim:false + role claim_emit.groups ───────────

test('rule: M10 contradiction (emit_groups_claim:false + role groups claim) fires', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
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
  client_id: tailscale
  redirect_uris:
    - https://login.tailscale.com/cb
  audience:
    - https://login.tailscale.com
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
  client_id: keep
  redirect_uris:
    - https://keep.dunn.dev/cb
  audience:
    - https://keep.dunn.dev
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

// ── shouldEmitGroups default semantics ─────────────────────────────────────

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

// ── assertManifestsValid throws on violation ───────────────────────────────

test('assertManifestsValid throws on a bad set, with all findings in the message', () => {
  const bad = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.dunn.dev/cb
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
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
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

// ── access-binding BLOCK wired into the load-time hard-fail (§11, primitive #5) ─

test('BLOCK: bare manifest (no access binding, no skip) is a load-time hard-fail', () => {
  // othala primitive #5: absence of a binding means NO access. A manifest with
  // accessGroups: [] and no skip_access_check is definitionally unreachable and
  // must be LOUDLY rejected at load (not silently dark).
  const m = fromYaml(`
oidc:
  client_id: novel
  redirect_uris:
    - https://novel.dunn.dev/cb
  audience:
    - https://novel.dunn.dev
consent: {}
`);
  assert.deepEqual(m.accessGroups, []);
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('presentation.access is empty') && e.includes('unreachable')),
    errs.join('\n'),
  );
  // And the hard-fail surfaces through assertManifestsValid.
  assert.throws(() => assertManifestsValid([m]), /manifest validation failed/);
});

test('BLOCK: skip_access_check bypasses the empty-binding block', () => {
  const m = fromYaml(`
oidc:
  client_id: novel
  audience:
    - https://novel.dunn.dev
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
    - https://novel.dunn.dev
presentation:
  access:
    - memories
    - memories
consent: {}
`);
  // parseAccessGroups de-dupes, so craft the duplicate directly on the object to
  // prove validateClients' guard bites regardless of how it got there.
  m.accessGroups = ['memories', 'memories'];
  const errs = validateClients([m]);
  assert.ok(
    errs.some((e) => e.includes('more than once')),
    errs.join('\n'),
  );
});

test('presentation-only manifest is valid WITHOUT an oidc: block (audience rule skipped)', () => {
  // observe.yaml shape: forward_auth tile, no OIDC client. It must validate
  // clean — the audience / redirect rules do not apply — as long as it names an
  // access group (which it does, satisfying the binding BLOCK).
  const m = fromYaml(`
presentation:
  name: Observe
  auth_kind: forward_auth
  access_group: access-observe
`, 'observe.yaml');
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

// ── The real on-disk manifest set must be clean ────────────────────────────

test('every real hydra/clients/*.yaml round-trips AND the set passes validateClients', () => {
  let files;
  try {
    files = readdirSync(clientsDir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    // hydra/clients/ not in this checkout — skip.
    return;
  }
  assert.ok(files.length > 0, 'expected at least one client manifest');
  const manifests = files.map((f) =>
    parseManifest(readFileSync(join(clientsDir, f), 'utf8'), f),
  );
  // Round-trip sanity: every manifest has a non-empty clientId + a non-empty
  // access binding. access-model Phase 2: the binding is the accessGroups list
  // (sourced from presentation.access: with the conventional fallback) — the
  // load-bearing gate field — not the singular access-<clientId> name.
  for (const m of manifests) {
    assert.ok(m.clientId.length > 0, `${m.sourcePath}: empty clientId`);
    assert.ok(m.accessGroups.length > 0, `${m.sourcePath}: empty accessGroups`);
  }
  const errs = validateClients(manifests);
  assert.deepEqual(errs, [], `real manifests should be clean:\n${errs.join('\n')}`);
});

// ── e2e fixture set must be clean (mirrors the hydra/clients check above) ──

const e2eClientsDir = join(here, '..', '..', 'e2e', 'manifests');

test('every e2e/manifests/*.yaml round-trips AND the set passes validateClients', () => {
  let files;
  try {
    files = readdirSync(e2eClientsDir)
      .filter((f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml');
  } catch {
    // e2e/manifests/ not in this checkout — skip.
    return;
  }
  assert.ok(files.length > 0, 'expected at least one e2e fixture manifest');
  const manifests = files
    .map((f) => {
      try {
        return parseManifest(readFileSync(join(e2eClientsDir, f), 'utf8'), f);
      } catch {
        return null;
      }
    })
    // presentation-only manifests (no oidc: block) are returned null by
    // loadOne; filter them out for the OIDC-client validateClients pass.
    .filter((m) => m !== null && !m.presentationOnly);
  const errs = validateClients(manifests);
  assert.deepEqual(errs, [], `e2e fixtures should be clean:\n${errs.join('\n')}`);
});

// ── llm.yaml (Open WebUI SSO) parses correctly and validates clean ──────────

test('llm.yaml: parses correctly — client_id, access binding, redirect, audience, roles', () => {
  const yaml = readFileSync(join(e2eClientsDir, 'llm.yaml'), 'utf8');
  const m = parseManifest(yaml, 'llm.yaml');

  assert.equal(m.clientId, 'open-webui', 'client_id must be open-webui');
  assert.equal(m.presentationOnly, false, 'must be an OIDC client, not presentation-only');

  // Access binding: access-llm group gate.
  assert.deepEqual(m.accessGroups, ['access-llm'], 'must bind the access-llm group');

  // OIDC fields.
  assert.deepEqual(m.redirectUris, ['https://chat.othala.test/oauth/oidc/callback']);
  assert.deepEqual(m.postLogoutRedirectUris, ['https://chat.othala.test/']);
  assert.deepEqual(m.audience, ['https://chat.othala.test']);
  assert.equal(m.skipConsent, true);
  assert.ok(m.scopes.includes('openid'), 'must request openid scope');
  assert.ok(m.scopes.includes('offline_access'), 'must request offline_access for refresh_token');
  assert.ok(m.scopes.includes('groups'), 'must request groups scope for role claim');

  // Consent: roles declared with claim_emit; emit_groups_claim active.
  assert.ok(m.emitGroupsClaim !== false, 'emit_groups_claim must not be suppressed');
  const adminRole = m.roles.find((r) => r.name === 'admin');
  const userRole = m.roles.find((r) => r.name === 'user');
  assert.ok(adminRole, 'admin role must be declared');
  assert.ok(userRole, 'user role must be declared');
  assert.ok(adminRole.claimEmit !== null, 'admin role must have claim_emit');
  assert.ok(userRole.claimEmit !== null, 'user role must have claim_emit');

  // group_role_map: admin → admin, family → user.
  assert.equal(m.groupRoleMap['admin'], 'admin');
  assert.equal(m.groupRoleMap['family'], 'user');

  // Full validation must pass (audience matches redirect origin, roles clean).
  const errs = validateClients([m]);
  assert.deepEqual(errs, [], `llm.yaml must validate clean:\n${errs.join('\n')}`);
});

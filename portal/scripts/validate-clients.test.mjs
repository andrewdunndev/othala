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
  CLIENT_ID_ENV_STEM_RE,
} from '../src/lib/manifests.ts';

const here = dirname(fileURLToPath(import.meta.url));
const clientsDir = join(here, '..', '..', 'hydra', 'clients');

function fromYaml(yamlText, filename = 'crafted.yaml') {
  return parseManifest(yamlText, filename);
}

// ── Rule 1a: client_id must be a valid env-var stem ───────────────────────
// Root cause: S08 staleness ledger; overnight Tasks 1+2.
// A hyphenated client_id ("open-webui") produces "OPEN-WEBUI_CLIENT_SECRET"
// which is not a valid POSIX env var and silently fails to resolve.

test('CLIENT_ID_ENV_STEM_RE: valid stems pass', () => {
  for (const id of ['keep', 'openwebui', 'llm', 'my_app', '_app', 'App123']) {
    assert.ok(CLIENT_ID_ENV_STEM_RE.test(id), `expected ${JSON.stringify(id)} to be a valid stem`);
  }
});

test('CLIENT_ID_ENV_STEM_RE: invalid stems are rejected (hyphens, dots, leading digits)', () => {
  for (const id of ['open-webui', 'my.app', '1app', 'app-', 'a b']) {
    assert.ok(!CLIENT_ID_ENV_STEM_RE.test(id), `expected ${JSON.stringify(id)} to be rejected`);
  }
});

test('rule 1a: hyphenated client_id fires the env-var-stem error', () => {
  const m = fromYaml(`
oidc:
  client_id: open-webui
  redirect_uris:
    - https://open-webui.othala.test/cb
  audience:
    - https://open-webui.othala.test
consent:
  skip_access_check: true
`);
  const errs = validateClients([m]);
  assert.ok(
    errs.some(
      (e) =>
        e.includes('open-webui') &&
        e.includes('POSIX env var') &&
        e.includes('OPEN-WEBUI_CLIENT_SECRET'),
    ),
    `expected env-var-stem error, got:\n${errs.join('\n')}`,
  );
});

test('rule 1a: client_id with a dot fires the env-var-stem error', () => {
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
    errs.some((e) => e.includes('POSIX env var') && e.includes('MY.APP_CLIENT_SECRET')),
    `expected env-var-stem error, got:\n${errs.join('\n')}`,
  );
});

test('rule 1a: client_id starting with a digit fires the env-var-stem error', () => {
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
    errs.some((e) => e.includes('POSIX env var')),
    `expected env-var-stem error, got:\n${errs.join('\n')}`,
  );
});

test('rule 1a: valid client_id without hyphens does NOT fire the env-var-stem error', () => {
  const m = fromYaml(`
oidc:
  client_id: openwebui
  redirect_uris:
    - https://openwebui.othala.test/cb
  audience:
    - https://openwebui.othala.test
presentation:
  access:
    - access-llm
consent: {}
`);
  const errs = validateClients([m]);
  assert.equal(
    errs.filter((e) => e.includes('POSIX env var')).length,
    0,
    `openwebui should not trigger the env-var-stem rule:\n${errs.join('\n')}`,
  );
});

test('rule 1a: assertManifestsValid surfaces the env-var-stem error in the thrown message', () => {
  const m = fromYaml(`
oidc:
  client_id: open-webui
  redirect_uris:
    - https://open-webui.othala.test/cb
  audience:
    - https://open-webui.othala.test
consent:
  skip_access_check: true
`);
  assert.throws(
    () => assertManifestsValid([m]),
    (err) =>
      /manifest validation failed/.test(err.message) &&
      /POSIX env var/.test(err.message) &&
      /OPEN-WEBUI_CLIENT_SECRET/.test(err.message),
  );
});

// ── Rule 2 + 3: audience presence + audienceMatchesRedirect ────────────────

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

// ── Rule 4: group_role_map points at an undeclared role ────────────────────

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

// ── Rule 5: declared role missing claim_emit ───────────────────────────────

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

// ── Rule 6: M10 emit_groups_claim:false + role claim_emit.groups ───────────

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
    - https://keep.othala.test/cb
  audience:
    - https://keep.othala.test
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

// ── access-binding BLOCK wired into the load-time hard-fail (§11, primitive #5) ─

test('BLOCK: bare manifest (no access binding, no skip) is a load-time hard-fail', () => {
  // othala primitive #5: absence of a binding means NO access. A manifest with
  // accessGroups: [] and no skip_access_check is definitionally unreachable and
  // must be LOUDLY rejected at load (not silently dark).
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
  // And the hard-fail surfaces through assertManifestsValid.
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

// ── e2e/manifests/ is now the canonical on-disk fixture set ────────────────
// hydra/clients/ was removed at M3 (dual-source-of-truth cleanup). The iac
// catalog under services/dag/catalog/ is the operator source of truth; the
// e2e/manifests/ fixtures here are the OSS-generic worked examples that CI
// validates. The hydra/clients/ directory no longer exists in this repo.

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

// ── open-webui.yaml (Open WebUI SSO) parses correctly and validates clean ───

test('open-webui.yaml: parses correctly — client_id, access binding, redirect, audience, roles', () => {
  const yaml = readFileSync(join(e2eClientsDir, 'open-webui.yaml'), 'utf8');
  const m = parseManifest(yaml, 'open-webui.yaml');

  assert.equal(m.clientId, 'openwebui', 'client_id must be openwebui');
  assert.equal(m.presentationOnly, false, 'must be an OIDC client, not presentation-only');

  // Access binding: access-llm group gate.
  assert.deepEqual(m.accessGroups, ['access-llm'], 'must bind the access-llm group');

  // OIDC fields.
  assert.deepEqual(m.redirectUris, ['https://prompt.othala.test/oauth/oidc/callback']);
  assert.deepEqual(m.postLogoutRedirectUris, ['https://prompt.othala.test/']);
  assert.deepEqual(m.audience, ['https://prompt.othala.test']);
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
  assert.deepEqual(errs, [], `open-webui.yaml must validate clean:\n${errs.join('\n')}`);
});

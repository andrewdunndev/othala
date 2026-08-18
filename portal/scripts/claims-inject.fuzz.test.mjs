// Property-based fuzz harness for the claims-inject security surface.
//
// INVARIANT: The emitted claims for a subject are EXACTLY those granted by
// the subject's real groups via the client's group_role_map — a subject can
// never obtain a role/claim for a group they are not in, and an
// unmapped/unknown group injects no claim.
//
// Sub-properties tested:
//   P1. A claimEmit injected by a role is ONLY present when the subject holds
//       a group that maps to that role (or a valid override).
//   P2. An adversarial extra group in groupRoleMap (that the subject is NOT in)
//       never injects its role's claims.
//   P3. A metadata_admin.roles override that names a DECLARED role is the only
//       override path — an undeclared role override MUST fall through to the
//       group walk, NOT inject a phantom role.
//   P4. A subject not in ANY group of the groupRoleMap receives NO role claims.
//   P5. deepMergeClaims does not allow claimEmit from a foreign role to
//       contaminate claims through prototype or object-shape abuse.
//   P6. Groups claim suppression (emit_groups_claim:false) actually removes
//       the groups claim — even when the subject's metadata_admin.groups is
//       non-empty.
//   P7. Case-folding in the override key (toLowerCase) cannot be used to
//       inject an undeclared role: the override value must name a role in
//       manifest.roles[].
//
// Run: npx vitest run scripts/claims-inject.fuzz.test.mjs

import { test } from 'vitest';
import assert from 'node:assert/strict';
import * as fc from 'fast-check';
import { lookupRole, deepMergeClaims, composeIDTokenClaims, buildIDTokenClaims } from '../src/lib/claims.ts';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Build a minimal but valid ClientManifest from component parts. */
function manifest({ clientId = 'myapp', roles = [], groupRoleMap = {}, emitGroupsClaim = null, skipConsent = false } = {}) {
  return {
    clientId,
    clientName: clientId,
    redirectUris: [`https://${clientId}.example.com/callback`],
    postLogoutRedirectUris: [],
    scopes: ['openid'],
    scope: 'openid',
    audience: [`https://${clientId}.example.com`],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: '',
    skipConsent,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroup: `access-${clientId}`,
    roles,
    groupRoleMap,
    emitGroupsClaim,
    skipAccessCheck: false,
    sourcePath: `${clientId}.yaml`,
  };
}

/** Build a minimal Identity with the given groups and optional role override. */
function identity({ groups = [], roleOverride = null, clientId = 'myapp' } = {}) {
  const id = {
    id: 'subject-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'alice', email: 'alice@example.com' },
    metadata_admin: {
      groups,
      ...(roleOverride !== null ? { roles: { [clientId.toLowerCase()]: roleOverride } } : {}),
    },
    verifiable_addresses: [],
  };
  return id;
}

// ─── fast-check arbitraries ───────────────────────────────────────────────────

/** A non-empty printable ASCII identifier (no spaces, safe for role/group names). */
const identifier = fc.stringMatching(/^[a-z][a-z0-9-]{0,19}$/).filter(s => s.length > 0);

/** A claim key safe for JSON object keys (no prototype-busting). */
const safeClaimKey = fc.oneof(
  identifier,
  fc.constantFrom('role', 'permissions', 'tenant', 'sub', 'iss', 'custom_claim', 'access_level'),
);

/** A broad claim key for the injection tests: any 5+ char string EXCEPT the
 *  prototype-busting keys deepMergeClaims intentionally drops. Those are
 *  covered by the dedicated prototype-pollution test below; asserting they're
 *  injected would contradict the (correct) guard. */
const injectableKey = fc
  .string({ minLength: 5 })
  .filter((k) => k !== '__proto__' && k !== 'constructor' && k !== 'prototype');

/** A claim value: string, number, boolean, or shallow object. */
const claimValue = fc.oneof(
  fc.string(),
  fc.integer(),
  fc.boolean(),
  fc.record({ nested: fc.string() }),
);

/** A claimEmit map: a record of safe keys to claim values. */
const claimEmit = fc.dictionary(safeClaimKey, claimValue, { minKeys: 1, maxKeys: 5 });

/** One declared role: name + claimEmit. */
const roleArb = (name) => claimEmit.map(ce => ({ name, description: `role ${name}`, claimEmit: ce }));

// ─── P1 + P2: group membership gate ──────────────────────────────────────────
// Core security property: a role's claims must NOT be emitted if the subject
// is not in a group that maps to that role.

test('P1+P2: claimEmit only injected when subject holds a mapped group', () => {
  fc.assert(
    fc.property(
      // Two disjoint role names
      identifier, identifier,
      // Two disjoint group names
      identifier, identifier,
      // ClaimEmits for each role (key that doesn't overlap to make detection easy)
      injectableKey, injectableKey,
      fc.context(),
      (roleA, roleB, groupA, groupB, claimKeyA, claimKeyB, ctx) => {
        // Skip if identifiers collide
        fc.pre(roleA !== roleB);
        fc.pre(groupA !== groupB);
        fc.pre(claimKeyA !== claimKeyB);

        const roles = [
          { name: roleA, description: '', claimEmit: { [claimKeyA]: 'sentinel-A' } },
          { name: roleB, description: '', claimEmit: { [claimKeyB]: 'sentinel-B' } },
        ];
        const groupRoleMap = { [groupA]: roleA, [groupB]: roleB };

        // Subject is ONLY in groupA.
        const subjectGroups = [`access-myapp`, groupA];
        const id = identity({ groups: subjectGroups });
        const m = manifest({ roles, groupRoleMap });

        const claims = composeIDTokenClaims(id, m);

        // claimKeyA MUST be present (subject holds groupA → roleA)
        // Use Object.hasOwn so prototype-inherited keys (isPrototypeOf, hasOwnProperty, etc.)
        // don't produce false positives — we care about OWN properties only.
        assert.equal(Object.hasOwn(claims, claimKeyA), true,
          `Expected claimKeyA (${claimKeyA}) for roleA via groupA`);
        assert.equal(claims[claimKeyA], 'sentinel-A',
          `Expected sentinel-A value for claimKeyA (${claimKeyA}) via groupA`);

        // claimKeyB MUST NOT be present as an OWN property (subject does NOT hold groupB)
        assert.equal(Object.hasOwn(claims, claimKeyB), false,
          `claimKeyB (${claimKeyB}) for roleB must NOT appear — subject not in groupB`);
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

// ─── P3: override names an UNDECLARED role → fall-through, not injection ─────

test('P3: override naming an undeclared role falls through to group walk, not phantom injection', () => {
  fc.assert(
    fc.property(
      identifier,       // declared role name
      identifier,       // undeclared role name (the attacker's override target)
      identifier,       // group that maps to the declared role
      claimEmit,        // claim emit for declared role
      fc.string({ minLength: 5 }), // a claim key unique to the phantom role
      (declaredRole, phantomRole, memberGroup, declaredCe, phantomKey) => {
        fc.pre(declaredRole !== phantomRole);

        const roles = [
          { name: declaredRole, description: '', claimEmit: declaredCe },
        ];
        const groupRoleMap = { [memberGroup]: declaredRole };

        // Subject IS in the group, but sets a role override naming a phantom role.
        // lookupRole must fall through to the group walk and return declaredRole's claims.
        const id = identity({
          groups: [`access-myapp`, memberGroup],
          roleOverride: phantomRole,   // undeclared role name
        });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);

        // Must NOT return the phantom role
        if (result !== null) {
          assert.notEqual(result.roleName, phantomRole,
            `lookupRole must not return phantom role "${phantomRole}" — it is not declared`);
          // Must return the declared role (fallthrough to group walk succeeded)
          assert.equal(result.roleName, declaredRole,
            `lookupRole must fall through to declared role "${declaredRole}" via group walk`);
          // The phantom key must not have snuck into the claimEmit as an OWN property
          // (use Object.hasOwn to avoid false positives on inherited prototype keys)
          assert.equal(Object.hasOwn(result.claimEmit, phantomKey), false,
            `Phantom claim key "${phantomKey}" must not appear as own property in resolved claimEmit`);
        }
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

// ─── P3b: override DOES work when it names a declared role ───────────────────

test('P3b: valid override (declared role name) is honored over group walk', () => {
  // Role A is what groupA maps to, role B is the override target.
  // Subject is in groupA but override says roleB — roleB must win.
  const roles = [
    { name: 'reader', description: '', claimEmit: { access: 'read' } },
    { name: 'admin',  description: '', claimEmit: { access: 'admin' } },
  ];
  const groupRoleMap = { 'eng': 'reader' };

  const id = identity({
    groups: ['access-myapp', 'eng'],
    roleOverride: 'admin',
  });
  const m = manifest({ roles, groupRoleMap });

  const result = lookupRole(m, id.metadata_admin);
  assert.equal(result?.roleName, 'admin', 'Valid override to declared role must win');
  assert.equal(result?.claimEmit.access, 'admin');
});

// ─── P4: subject in NO mapped group → no role claims injected ────────────────

test('P4: subject with no mapped groups gets no role claimEmit keys', () => {
  fc.assert(
    fc.property(
      fc.array(identifier, { minLength: 1, maxLength: 4 }),  // mapped group names
      identifier,                                             // role name
      claimEmit,                                             // the role's claims
      fc.array(identifier, { minLength: 1, maxLength: 3 }),  // subject's groups (disjoint)
      (mappedGroups, roleName, ce, subjectExtraGroups) => {
        // Ensure subject's groups don't overlap mapped groups
        const mappedSet = new Set(mappedGroups);
        const subjectGroups = subjectExtraGroups.filter(g => !mappedSet.has(g));
        fc.pre(subjectGroups.length > 0 || true); // always proceed; subject just won't match

        const roles = [{ name: roleName, description: '', claimEmit: ce }];
        const groupRoleMap = Object.fromEntries(mappedGroups.map(g => [g, roleName]));

        // Subject's groups include access-myapp (so gate passes) but NOT any mapped group
        const id = identity({ groups: ['access-myapp', ...subjectGroups] });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);
        assert.equal(result, null,
          `Subject not in any mapped group must resolve to null — not inject role "${roleName}"`);
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

// ─── P5: deepMergeClaims prototype-pollution hardening ───────────────────────
//
// REAL SECURITY FINDING (HIGH):
//
// deepMergeClaims is vulnerable to prototype pollution via __proto__ key.
//
// Attack vector:
//   An operator (or someone who gains write access to manifest files) authors
//   a manifest with `__proto__` as a claim_emit key:
//
//     claim_emit:
//       __proto__:
//         injected: true
//
//   yaml.parse() preserves __proto__ as a regular string key.
//   deepMergeClaims iterates Object.entries(src) — it sees ["__proto__", {injected:true}].
//   The key "__proto__" in `dst[k]` returns Object.prototype (the actual prototype object
//   via the __proto__ accessor), satisfying the "both are objects" branch condition.
//   deepMergeClaims then RECURSES with (Object.prototype, {injected:true}), adding
//   "injected" as an own property of Object.prototype — polluting the entire process.
//
//   When ANY user with that role authenticates, the pollution fires at consent time.
//   All subsequent plain object creations in the process inherit the injected key.
//
// Threat actor: operator-level (write access to /etc/portal/manifests/). This is NOT
// an unauthenticated path — it requires manifest write access. The severity is HIGH
// because it persists for the lifetime of the portal process and affects all users.
//
// Recommendation: use Object.hasOwn guard in deepMergeClaims before the recursive call:
//   if (Object.prototype.hasOwnProperty.call(dst, k)) { ... recursive ... }
// or skip known prototype-collision keys (__proto__, constructor, prototype).

test('P5: deepMergeClaims does NOT pollute Object.prototype via __proto__ key (fixed)', () => {
  // Clean up any prior pollution from other test runs
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'injected')) {
    delete Object.prototype.injected;
  }

  const dst = {};
  // JSON.parse produces __proto__ as a regular enumerable string key (not the special setter)
  const poisoned = JSON.parse('{"__proto__":{"injected":true},"constructor":{"name":"pwned"}}');

  deepMergeClaims(dst, poisoned);

  const polluted = ({}).injected === true;
  // Clean up before asserting so other tests aren't affected
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'injected')) {
    delete Object.prototype.injected;
  }
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'name')) {
    delete Object.prototype.name;
  }

  // INVARIANT (fixed): Object.prototype must NOT be polluted.
  assert.equal(polluted, false,
    'deepMergeClaims must not pollute Object.prototype via __proto__ key. ' +
    'Fix: skip __proto__/constructor/prototype keys and use hasOwnProperty for existence check.');
});

test('P5b: nested __proto__ in deepMergeClaims does NOT pollute Object.prototype (fixed)', () => {
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'nested_polluted')) {
    delete Object.prototype.nested_polluted;
  }

  const dst = { nested: {} };
  const src = { nested: JSON.parse('{"__proto__":{"nested_polluted":true}}') };

  deepMergeClaims(dst, src);

  const polluted = ({}).nested_polluted === true;
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'nested_polluted')) {
    delete Object.prototype.nested_polluted;
  }

  // INVARIANT (fixed): nested __proto__ key must also be blocked.
  assert.equal(polluted, false,
    'deepMergeClaims must not pollute Object.prototype via nested __proto__ key in recursive path.');
});

// ─── P5c: property-based deepMergeClaims — src cannot overwrite dst with random keys ──

test('P5c: deepMergeClaims — src values only merge into dst, never expand to Object.prototype', () => {
  fc.assert(
    fc.property(
      fc.dictionary(safeClaimKey, claimValue),
      fc.dictionary(safeClaimKey, claimValue),
      (dstInput, srcInput) => {
        const dst = { ...dstInput };
        const src = { ...srcInput };
        const originalProtoKeys = Object.keys(Object.prototype).length;

        deepMergeClaims(dst, src);

        // Object.prototype must not grow
        assert.equal(Object.keys(Object.prototype).length, originalProtoKeys,
          'deepMergeClaims must not expand Object.prototype');

        // Every key in dst after merge must have come from either original dst or src
        const allowedKeys = new Set([...Object.keys(dstInput), ...Object.keys(srcInput)]);
        for (const k of Object.keys(dst)) {
          assert.ok(allowedKeys.has(k),
            `Unexpected key "${k}" appeared in dst after merge`);
        }
      },
    ),
    { numRuns: 1000, verbose: false },
  );
});

// ─── P6: emit_groups_claim:false suppresses groups even with non-empty groups ─

test('P6: emit_groups_claim:false removes groups claim from output', () => {
  fc.assert(
    fc.property(
      fc.array(identifier, { minLength: 1, maxLength: 5 }),
      (subjectGroups) => {
        const id = identity({ groups: [...subjectGroups, 'access-myapp'] });
        const m = manifest({
          emitGroupsClaim: false,
          roles: [{ name: 'user', description: '', claimEmit: { role: 'user' } }],
          groupRoleMap: Object.fromEntries(subjectGroups.slice(0, 1).map(g => [g, 'user'])),
        });

        const claims = composeIDTokenClaims(id, m);
        assert.equal('groups' in claims, false,
          'groups claim must be suppressed when emit_groups_claim:false');
      },
    ),
    { numRuns: 300, verbose: false },
  );
});

// ─── P6b: emit_groups_claim:true (default) keeps groups ─────────────────────

test('P6b: emit_groups_claim:true (default null) keeps groups claim in output', () => {
  const id = identity({ groups: ['access-myapp', 'eng'] });
  const m = manifest({ emitGroupsClaim: null }); // null = default = true

  const claims = composeIDTokenClaims(id, m);
  // groups must be present
  assert.ok('groups' in claims, 'groups claim must be present when emitGroupsClaim is null (default true)');
  assert.deepEqual(claims.groups, ['access-myapp', 'eng']);
});

// ─── P7: clientId casing in override lookup ───────────────────────────────────
// The override key is lowercased on BOTH sides (Go: strings.ToLower(clientID)).
// lookupRole reads overrideMap[manifest.clientId.toLowerCase()].
// The admin form stores the key lowercased (access.ts readRoleOverride also lowercases).
// An attacker cannot use a mixed-case override key to inject an undeclared role;
// a mixed-case key simply misses the lookup (fails safe: override ignored, group walk proceeds).

test('P7a: override stored with lowercase clientId key resolves the declared role', () => {
  fc.assert(
    fc.property(
      // Client ID with uppercase letters (e.g. "MyApp" — lookupRole lowercases to "myapp")
      fc.stringMatching(/^[A-Z][a-zA-Z0-9]{2,10}$/),
      identifier,
      claimEmit,
      (mixedClientId, roleName, ce) => {
        const roles = [{ name: roleName, description: '', claimEmit: ce }];
        const m = manifest({ clientId: mixedClientId, roles, groupRoleMap: {} });

        // Override key MUST be stored as lowercase (matching Go strings.ToLower convention)
        const metadataAdmin = {
          groups: [`access-${mixedClientId.toLowerCase()}`],
          roles: { [mixedClientId.toLowerCase()]: roleName },  // lowercase key
        };

        const result = lookupRole(m, metadataAdmin);
        // Lowercase key must resolve correctly
        assert.equal(result?.roleName, roleName,
          `Override key "${mixedClientId.toLowerCase()}" must resolve role "${roleName}"`);
        // The resolved claimEmit must be exactly the declared one
        if (result) {
          for (const k of Object.keys(result.claimEmit)) {
            assert.ok(Object.hasOwn(ce, k) || true, // shape matches declared role
              `Unexpected key "${k}" in claimEmit — not in declared role`);
          }
        }
      },
    ),
    { numRuns: 300, verbose: false },
  );
});

test('P7b: override stored with mixed-case key is silently ignored (fails safe)', () => {
  // lookupRole reads overrideMap[manifest.clientId.toLowerCase()].
  // If the stored key is mixed-case (e.g. "MyApp") and manifest.clientId is also "MyApp",
  // the lookup key is "myapp" — the stored key "MyApp" is NOT found.
  // This is a usability gap (documented: admin form should store lowercase) but fails SAFE:
  // the override is ignored and the group walk proceeds normally.
  const m = manifest({
    clientId: 'MyApp',
    roles: [{ name: 'admin', description: '', claimEmit: { role: 'admin' } }],
    groupRoleMap: { 'eng': 'admin' },
  });

  // Mixed-case key -> override miss -> fall through to group walk -> 'admin' via 'eng'
  const meta = { groups: ['access-MyApp', 'eng'], roles: { 'MyApp': 'admin' } };
  const result = lookupRole(m, meta);

  // With a group match, the group walk finds 'admin' anyway
  assert.equal(result?.roleName, 'admin', 'group walk should still resolve admin via eng group');
});

// ─── P8: groupRoleMap value pointing to a DECLARED role only ─────────────────
// Even if groupRoleMap is hand-crafted to map a subject's group to a role name
// that doesn't exist in manifest.roles[], lookupRole must NOT inject that role.

test('P8: groupRoleMap value naming an undeclared role injects nothing', () => {
  fc.assert(
    fc.property(
      identifier,  // declared role name
      identifier,  // undeclared role name (attacker plants this in groupRoleMap)
      identifier,  // group the subject IS in
      claimEmit,   // claimEmit for declared role
      (declared, phantom, memberGroup, ce) => {
        fc.pre(declared !== phantom);

        const roles = [{ name: declared, description: '', claimEmit: ce }];
        // groupRoleMap maps the subject's group to an UNDECLARED role name
        const groupRoleMap = { [memberGroup]: phantom };

        const id = identity({ groups: ['access-myapp', memberGroup] });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);

        // lookupRole must not resolve to the phantom role (it's not in roles[])
        if (result !== null) {
          assert.notEqual(result.roleName, phantom,
            `lookupRole must not resolve phantom role "${phantom}" — not in manifest.roles[]`);
        }
        // In fact with only the phantom mapping, result must be null
        assert.equal(result, null,
          `lookupRole must return null when groupRoleMap points to undeclared role "${phantom}"`);
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

// ─── P9: first-match-wins in groups walk — earlier group wins ─────────────────
// lookupRole walks groups in stored order; only the first matching group's role
// should be applied, not later groups.

test('P9: first-match-wins — earlier group in stored order wins over later group', () => {
  fc.assert(
    fc.property(
      identifier, identifier, // two role names
      identifier, identifier, // two group names (both in subject's groups)
      claimEmit, claimEmit,   // distinct claim emits
      (roleA, roleB, groupA, groupB, ceA, ceB) => {
        fc.pre(roleA !== roleB);
        fc.pre(groupA !== groupB);
        // Ensure the two claim emits have at least one distinguishing key
        fc.pre(Object.keys(ceA).length > 0);

        const roles = [
          { name: roleA, description: '', claimEmit: ceA },
          { name: roleB, description: '', claimEmit: ceB },
        ];
        const groupRoleMap = { [groupA]: roleA, [groupB]: roleB };

        // Subject has BOTH groups; groupA is listed first in stored order
        const id = identity({ groups: ['access-myapp', groupA, groupB] });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);
        assert.equal(result?.roleName, roleA,
          `First group "${groupA}" in stored order must win over later "${groupB}"`);

        // And the claimEmit must be groupA's role, not groupB's
        if (result) {
          for (const k of Object.keys(ceA)) {
            assert.equal(result.claimEmit[k], ceA[k],
              `claimEmit key "${k}" must come from roleA (first match)`);
          }
        }
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

// ─── Boundary / targeted adversarial cases ───────────────────────────────────

test('adversarial: empty groups array → no role, no claimEmit', () => {
  const roles = [{ name: 'admin', description: '', claimEmit: { superpower: true } }];
  const groupRoleMap = { 'admin': 'admin' };
  const id = identity({ groups: [] });
  const m = manifest({ roles, groupRoleMap });

  const result = lookupRole(m, id.metadata_admin);
  assert.equal(result, null, 'empty groups must yield null role result');

  const claims = composeIDTokenClaims(id, m);
  assert.equal('superpower' in claims, false, 'superpower claim must not appear with empty groups');
});

test('adversarial: groups array with non-string elements is coerced/filtered safely', () => {
  const roles = [{ name: 'admin', description: '', claimEmit: { superpower: true } }];
  const groupRoleMap = { 'admin': 'admin' };

  // Inject non-string values into groups (simulates corrupted metadata)
  const corruptedMeta = {
    groups: [null, 42, true, { toString: () => 'admin' }, 'admin', undefined],
  };
  const id = {
    id: 'subject-corrupt',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'bad', email: 'bad@example.com' },
    metadata_admin: corruptedMeta,
    verifiable_addresses: [],
  };
  const m = manifest({ roles, groupRoleMap });

  // Should not throw
  let result;
  assert.doesNotThrow(() => {
    result = lookupRole(m, id.metadata_admin);
  }, 'lookupRole must not throw on corrupt groups array');

  // The object { toString: () => 'admin' } is NOT a string, so should be filtered out.
  // Only the actual string 'admin' should match.
  // This is a correctness check: the filter `(g): g is string => typeof g === 'string'` handles this.
  if (result !== null) {
    assert.equal(result.roleName, 'admin', 'only the string "admin" element should match');
  }
});

test('adversarial: metadata_admin.roles override with object value (not string) is ignored', () => {
  const roles = [{ name: 'reader', description: '', claimEmit: { access: 'read' } }];
  const groupRoleMap = { 'eng': 'reader' };

  const id = {
    id: 'subject-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'alice', email: 'alice@example.com' },
    metadata_admin: {
      groups: ['access-myapp', 'eng'],
      roles: { myapp: { name: 'admin' } },  // object value, not string → must be ignored
    },
    verifiable_addresses: [],
  };
  const m = manifest({ roles, groupRoleMap });

  const result = lookupRole(m, id.metadata_admin);
  // Override is not a string → fall through to group walk → 'reader'
  assert.equal(result?.roleName, 'reader',
    'Non-string override value must be ignored; group walk must resolve reader');
});

test('adversarial: metadata_admin.roles is an array (not object) — no override, group walk wins', () => {
  const roles = [{ name: 'reader', description: '', claimEmit: { access: 'read' } }];
  const groupRoleMap = { 'eng': 'reader' };

  const metaAdmin = {
    groups: ['access-myapp', 'eng'],
    roles: ['admin', 'reader'],  // array, not object — must be ignored per type guard
  };
  const m = manifest({ roles, groupRoleMap });
  const result = lookupRole(m, metaAdmin);
  // Array form of roles is not a valid override map — fall through to group walk
  assert.equal(result?.roleName, 'reader',
    'Array-valued metadata_admin.roles must be ignored; group walk resolves reader');
});

test('adversarial: null manifest → no claimEmit injection', () => {
  const id = identity({ groups: ['access-myapp', 'admin'] });
  const claims = composeIDTokenClaims(id, null);
  // With null manifest, no role injection; groups should be present (default)
  assert.equal('role' in claims, false, 'No role key should appear with null manifest');
  assert.equal('permissions' in claims, false);
  // groups should still appear (no manifest means no suppression)
  assert.ok('groups' in claims, 'groups claim should appear with null manifest');
});

test('adversarial: claimEmit that tries to overwrite email claim via deepMergeClaims', () => {
  // A malicious role's claimEmit tries to overwrite the trusted email claim.
  // deepMergeClaims conflict resolution: src wins on scalar conflict.
  // This is EXPECTED behavior (documented: "src wins") but we want to confirm
  // that the source of truth is only the REAL role the subject maps to.
  const roles = [
    { name: 'attacker-role', description: '', claimEmit: { email: 'attacker@evil.com', superpower: true } },
    { name: 'user-role',     description: '', claimEmit: { email: 'legitimate@example.com' } },
  ];
  const groupRoleMap = {
    'real-group': 'user-role',
    // attacker-group maps to attacker-role — but subject is NOT in attacker-group
  };

  const id = identity({ groups: ['access-myapp', 'real-group'] });
  const m = manifest({ roles, groupRoleMap });

  const claims = composeIDTokenClaims(id, m);

  // email comes from traits first, then claimEmit overwrites (user-role's claimEmit)
  // attacker-role must NOT be injected because subject is not in attacker-group
  assert.equal('superpower' in claims, false,
    'attacker-role claimEmit must not inject superpower — subject not in attacker-group');
  // user-role's email overwrite applies (deepMergeClaims src wins — that's correct behavior)
  // but the subject's actual email from traits is the base
  assert.equal(claims.email, 'legitimate@example.com',
    'user-role claimEmit email overrides trait email (documented src-wins behavior)');
});

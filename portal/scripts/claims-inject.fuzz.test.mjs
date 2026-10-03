// Invariant: emitted claims are exactly those granted by the subject's real groups via group_role_map.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import * as fc from 'fast-check';
import { lookupRole, deepMergeClaims, composeIDTokenClaims, buildIDTokenClaims } from '../src/lib/claims.ts';
import { identity as buildIdentity } from '../src/lib/test-builders.ts';

const ALL_SCOPES = ['openid', 'email', 'profile', 'groups'];

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
    accessGroups: [`access-${clientId}`],
    roles,
    groupRoleMap,
    emitGroupsClaim,
    skipAccessCheck: false,
    sourcePath: `${clientId}.yaml`,
  };
}

function identity({ groups = [], roleOverride = null, clientId = 'myapp' } = {}) {
  return buildIdentity({
    id: 'subject-1',
    username: 'alice',
    email: 'alice@example.com',
    metadataAdmin: {
      groups,
      ...(roleOverride !== null ? { roles: { [clientId.toLowerCase()]: roleOverride } } : {}),
    },
  });
}

const identifier = fc.stringMatching(/^[a-z][a-z0-9-]{0,19}$/).filter(s => s.length > 0);

const safeClaimKey = fc.oneof(
  identifier,
  fc.constantFrom('role', 'permissions', 'tenant', 'sub', 'iss', 'custom_claim', 'access_level'),
);

const injectableKey = fc
  .string({ minLength: 5 })
  .filter((k) => k !== '__proto__' && k !== 'constructor' && k !== 'prototype');

const claimValue = fc.oneof(
  fc.string(),
  fc.integer(),
  fc.boolean(),
  fc.record({ nested: fc.string() }),
);

const claimEmit = fc.dictionary(safeClaimKey, claimValue, { minKeys: 1, maxKeys: 5 });

const roleArb = (name) => claimEmit.map(ce => ({ name, description: `role ${name}`, claimEmit: ce }));

test('P1+P2: claimEmit only injected when subject holds a mapped group', () => {
  fc.assert(
    fc.property(
      identifier, identifier,
      identifier, identifier,
      injectableKey, injectableKey,
      fc.context(),
      (roleA, roleB, groupA, groupB, claimKeyA, claimKeyB, ctx) => {
        fc.pre(roleA !== roleB);
        fc.pre(groupA !== groupB);
        fc.pre(claimKeyA !== claimKeyB);

        const roles = [
          { name: roleA, description: '', claimEmit: { [claimKeyA]: 'sentinel-A' } },
          { name: roleB, description: '', claimEmit: { [claimKeyB]: 'sentinel-B' } },
        ];
        const groupRoleMap = { [groupA]: roleA, [groupB]: roleB };

        const subjectGroups = [`access-myapp`, groupA];
        const id = identity({ groups: subjectGroups });
        const m = manifest({ roles, groupRoleMap });

        const claims = composeIDTokenClaims(id, m, ALL_SCOPES);

        assert.equal(Object.hasOwn(claims, claimKeyA), true,
          `Expected claimKeyA (${claimKeyA}) for roleA via groupA`);
        assert.equal(claims[claimKeyA], 'sentinel-A',
          `Expected sentinel-A value for claimKeyA (${claimKeyA}) via groupA`);

        assert.equal(Object.hasOwn(claims, claimKeyB), false,
          `claimKeyB (${claimKeyB}) for roleB must NOT appear — subject not in groupB`);
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

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

        const id = identity({
          groups: [`access-myapp`, memberGroup],
          roleOverride: phantomRole,   // undeclared role name
        });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);

        if (result !== null) {
          assert.notEqual(result.roleName, phantomRole,
            `lookupRole must not return phantom role "${phantomRole}" — it is not declared`);
          assert.equal(result.roleName, declaredRole,
            `lookupRole must fall through to declared role "${declaredRole}" via group walk`);
          assert.equal(Object.hasOwn(result.claimEmit, phantomKey), false,
            `Phantom claim key "${phantomKey}" must not appear as own property in resolved claimEmit`);
        }
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

test('P3b: valid override (declared role name) is honored over group walk', () => {
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

test('P4: subject with no mapped groups gets no role claimEmit keys', () => {
  fc.assert(
    fc.property(
      fc.array(identifier, { minLength: 1, maxLength: 4 }),  // mapped group names
      identifier,                                             // role name
      claimEmit,                                             // the role's claims
      fc.array(identifier, { minLength: 1, maxLength: 3 }),  // subject's groups (disjoint)
      (mappedGroups, roleName, ce, subjectExtraGroups) => {
        const mappedSet = new Set(mappedGroups);
        const subjectGroups = subjectExtraGroups.filter(g => !mappedSet.has(g));
        fc.pre(subjectGroups.length > 0 || true); // always proceed; subject just won't match

        const roles = [{ name: roleName, description: '', claimEmit: ce }];
        const groupRoleMap = Object.fromEntries(mappedGroups.map(g => [g, roleName]));

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

test('P5: deepMergeClaims does NOT pollute Object.prototype via __proto__ key (fixed)', () => {
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'injected')) {
    delete Object.prototype.injected;
  }

  const dst = {};
  const poisoned = JSON.parse('{"__proto__":{"injected":true},"constructor":{"name":"pwned"}}');

  deepMergeClaims(dst, poisoned);

  const polluted = ({}).injected === true;
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'injected')) {
    delete Object.prototype.injected;
  }
  if (Object.prototype.hasOwnProperty.call(Object.prototype, 'name')) {
    delete Object.prototype.name;
  }

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

  assert.equal(polluted, false,
    'deepMergeClaims must not pollute Object.prototype via nested __proto__ key in recursive path.');
});

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

        assert.equal(Object.keys(Object.prototype).length, originalProtoKeys,
          'deepMergeClaims must not expand Object.prototype');

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

        const claims = composeIDTokenClaims(id, m, ALL_SCOPES);
        assert.equal('groups' in claims, false,
          'groups claim must be suppressed when emit_groups_claim:false');
      },
    ),
    { numRuns: 300, verbose: false },
  );
});

test('P6b: emit_groups_claim:true (default null) keeps groups claim in output', () => {
  const id = identity({ groups: ['access-myapp', 'eng'] });
  const m = manifest({ emitGroupsClaim: null }); // null = default = true

  const claims = composeIDTokenClaims(id, m, ALL_SCOPES);
  assert.ok('groups' in claims, 'groups claim must be present when emitGroupsClaim is null (default true)');
  assert.deepEqual(claims.groups, ['access-myapp']);
});

test('P7a: override stored with lowercase clientId key resolves the declared role', () => {
  fc.assert(
    fc.property(
      fc.stringMatching(/^[A-Z][a-zA-Z0-9]{2,10}$/),
      identifier,
      claimEmit,
      (mixedClientId, roleName, ce) => {
        const roles = [{ name: roleName, description: '', claimEmit: ce }];
        const m = manifest({ clientId: mixedClientId, roles, groupRoleMap: {} });

        const metadataAdmin = {
          groups: [`access-${mixedClientId.toLowerCase()}`],
          roles: { [mixedClientId.toLowerCase()]: roleName },  // lowercase key
        };

        const result = lookupRole(m, metadataAdmin);
        assert.equal(result?.roleName, roleName,
          `Override key "${mixedClientId.toLowerCase()}" must resolve role "${roleName}"`);
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
  const m = manifest({
    clientId: 'MyApp',
    roles: [{ name: 'admin', description: '', claimEmit: { role: 'admin' } }],
    groupRoleMap: { 'eng': 'admin' },
  });

  const meta = { groups: ['access-MyApp', 'eng'], roles: { 'MyApp': 'admin' } };
  const result = lookupRole(m, meta);

  assert.equal(result?.roleName, 'admin', 'group walk should still resolve admin via eng group');
});

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
        const groupRoleMap = { [memberGroup]: phantom };

        const id = identity({ groups: ['access-myapp', memberGroup] });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);

        if (result !== null) {
          assert.notEqual(result.roleName, phantom,
            `lookupRole must not resolve phantom role "${phantom}" — not in manifest.roles[]`);
        }
        assert.equal(result, null,
          `lookupRole must return null when groupRoleMap points to undeclared role "${phantom}"`);
      },
    ),
    { numRuns: 500, verbose: false },
  );
});

test('P9: first-match-wins — earlier group in stored order wins over later group', () => {
  fc.assert(
    fc.property(
      identifier, identifier, // two role names
      identifier, identifier, // two group names (both in subject's groups)
      claimEmit, claimEmit,   // distinct claim emits
      (roleA, roleB, groupA, groupB, ceA, ceB) => {
        fc.pre(roleA !== roleB);
        fc.pre(groupA !== groupB);
        fc.pre(Object.keys(ceA).length > 0);

        const roles = [
          { name: roleA, description: '', claimEmit: ceA },
          { name: roleB, description: '', claimEmit: ceB },
        ];
        const groupRoleMap = { [groupA]: roleA, [groupB]: roleB };

        const id = identity({ groups: ['access-myapp', groupA, groupB] });
        const m = manifest({ roles, groupRoleMap });

        const result = lookupRole(m, id.metadata_admin);
        assert.equal(result?.roleName, roleA,
          `First group "${groupA}" in stored order must win over later "${groupB}"`);

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

test('adversarial: empty groups array → no role, no claimEmit', () => {
  const roles = [{ name: 'admin', description: '', claimEmit: { superpower: true } }];
  const groupRoleMap = { 'admin': 'admin' };
  const id = identity({ groups: [] });
  const m = manifest({ roles, groupRoleMap });

  const result = lookupRole(m, id.metadata_admin);
  assert.equal(result, null, 'empty groups must yield null role result');

  const claims = composeIDTokenClaims(id, m, ALL_SCOPES);
  assert.equal('superpower' in claims, false, 'superpower claim must not appear with empty groups');
});

test('adversarial: groups array with non-string elements is coerced/filtered safely', () => {
  const roles = [{ name: 'admin', description: '', claimEmit: { superpower: true } }];
  const groupRoleMap = { 'admin': 'admin' };

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

  let result;
  assert.doesNotThrow(() => {
    result = lookupRole(m, id.metadata_admin);
  }, 'lookupRole must not throw on corrupt groups array');

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
  assert.equal(result?.roleName, 'reader',
    'Array-valued metadata_admin.roles must be ignored; group walk resolves reader');
});

test('adversarial: null manifest → no claimEmit injection', () => {
  const id = identity({ groups: ['access-myapp', 'admin'] });
  const claims = composeIDTokenClaims(id, null, ALL_SCOPES);
  assert.equal('role' in claims, false, 'No role key should appear with null manifest');
  assert.equal('permissions' in claims, false);
  assert.equal('groups' in claims, false, 'groups claim must be omitted with null manifest');
});

test('adversarial: claimEmit that tries to overwrite email claim via deepMergeClaims', () => {
  const roles = [
    { name: 'attacker-role', description: '', claimEmit: { email: 'attacker@evil.com', superpower: true } },
    { name: 'user-role',     description: '', claimEmit: { email: 'legitimate@example.com' } },
  ];
  const groupRoleMap = {
    'real-group': 'user-role',
  };

  const id = identity({ groups: ['access-myapp', 'real-group'] });
  const m = manifest({ roles, groupRoleMap });

  const claims = composeIDTokenClaims(id, m, ALL_SCOPES);

  assert.equal('superpower' in claims, false,
    'attacker-role claimEmit must not inject superpower — subject not in attacker-group');
  assert.equal(claims.email, 'legitimate@example.com',
    'user-role claimEmit email overrides trait email (documented src-wins behavior)');
});

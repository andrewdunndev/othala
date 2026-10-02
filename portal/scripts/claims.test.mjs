// Invariant: id_token claims map only from real memberships and declared roles.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  buildIDTokenClaims,
  deepMergeClaims,
  composeIDTokenClaims,
  lookupRole,
} from '../src/lib/claims.ts';
import { identity } from '../src/lib/test-builders.ts';

function base(overrides = {}) {
  return {
    ...identity({ id: 'id-1', username: 'ada', email: 'a@othala.test', displayName: 'Ada Lovelace', metadataAdmin: { groups: ['access-grafana'] } }),
    ...overrides,
  };
}

test('email + email_verified from traits.email and verifiable_addresses', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.email_verified, true);
});

test('email_verified omitted when no verifiable_addresses', () => {
  const c = buildIDTokenClaims(base({ verifiable_addresses: [] }));
  assert.equal(c.email, 'a@othala.test');
  assert.equal('email_verified' in c, false);
});

test('email_verified is false when no address matches the email trait, even if another is verified', () => {
  const i = identity({ email: 'ada@othala.test', recoveryEmail: 'other@othala.test', verified: true });
  const c = buildIDTokenClaims({
    ...i,
    verifiable_addresses: i.verifiable_addresses.filter((a) => a.value === 'other@othala.test'),
  });
  assert.equal(c.email, 'ada@othala.test');
  assert.equal(c.email_verified, false);
});

test('email_verified reads the email trait\'s own address, not the first entry', () => {
  const i = identity({ email: 'ada@othala.test', recoveryEmail: 'other@othala.test', verified: false });
  const [own, other] = i.verifiable_addresses;
  const c = buildIDTokenClaims({ ...i, verifiable_addresses: [{ ...other, verified: true }, own] });
  assert.equal(c.email_verified, false);
});

test('email_verified matches the address case-insensitively', () => {
  const i = identity({ email: 'ada@othala.test', verified: true });
  const c = buildIDTokenClaims({ ...i, traits: { ...i.traits, email: 'Ada@Othala.TEST' } });
  assert.equal(c.email_verified, true);
});

test('preferred_username = traits.username', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.preferred_username, 'ada');
});

test('name = traits.displayName when present', () => {
  const c = buildIDTokenClaims(base());
  assert.equal(c.name, 'Ada Lovelace');
});

test('name falls back to username when no displayName', () => {
  const c = buildIDTokenClaims(base({ traits: { username: 'ada', email: 'a@othala.test' } }));
  assert.equal(c.name, 'ada');
});

test('groups always included from metadata_admin', () => {
  const c = buildIDTokenClaims(base());
  assert.deepEqual(c.groups, ['access-grafana']);
});

test('groups omitted when metadata_admin has none', () => {
  const c = buildIDTokenClaims(base({ metadata_admin: {} }));
  assert.equal('groups' in c, false);
});

test('null identity yields empty claims', () => {
  assert.deepEqual(buildIDTokenClaims(null), {});
});

test('deepMergeClaims: array conflict becomes union, dst order preserved', () => {
  const dst = { groups: ['a', 'b'] };
  const src = { groups: ['b', 'c'] };
  deepMergeClaims(dst, src);
  assert.deepEqual(dst.groups, ['a', 'b', 'c']);
});

test('deepMergeClaims: scalar conflict still src-wins', () => {
  const dst = { x: 1 };
  const src = { x: 2 };
  deepMergeClaims(dst, src);
  assert.equal(dst.x, 2);
});

test('deepMergeClaims: __proto__ key is silently dropped (no pollution)', () => {
  const src = JSON.parse('{"__proto__":{"polluted":true},"safe":"value"}');
  const dst = { existing: 1 };
  deepMergeClaims(dst, src);
  assert.equal(Object.prototype.polluted, undefined, '__proto__ must not pollute Object.prototype');
  assert.equal(dst.safe, 'value');
  assert.equal(dst.existing, 1);
});

test('deepMergeClaims: constructor key is silently dropped (no pollution)', () => {
  const src = { constructor: { prototype: { polluted: 'constructor-path' } }, safe: 'ok' };
  const dst = { existing: 2 };
  deepMergeClaims(dst, src);
  assert.equal(Object.prototype.polluted, undefined, 'constructor path must not pollute prototype');
  assert.equal(dst.constructor, Object);
  assert.equal(dst.safe, 'ok');
});

test('deepMergeClaims: prototype key is silently dropped (no pollution)', () => {
  const src = { prototype: { polluted: 'prototype-path' }, safe: 'also-ok' };
  const dst = {};
  deepMergeClaims(dst, src);
  assert.equal(Object.getOwnPropertyDescriptor(dst, 'prototype'), undefined);
  assert.equal(dst.safe, 'also-ok');
});

function manifest({ group, roleClaimEmit, emitGroupsClaim = null } = {}) {
  return {
    clientId: 'filedrop',
    presentationOnly: false,
    clientName: 'Filedrop',
    redirectUris: ['https://filedrop.othala.test/'],
    postLogoutRedirectUris: [],
    scopes: ['openid', 'email', 'profile', 'groups'],
    scope: 'openid email profile groups',
    audience: ['https://filedrop.othala.test'],
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroups: [group ?? 'filedrop'],
    roles: [
      {
        name: 'member',
        description: 'Filedrop member',
        claimEmit: roleClaimEmit ?? { groups: ['filedrop-user'] },
      },
    ],
    groupRoleMap: { [group ?? 'filedrop']: 'member' },
    emitGroupsClaim,
    skipAccessCheck: false,
    sourcePath: 'filedrop.yaml',
  };
}

function identityWithGroups(groups) {
  return base({ metadata_admin: { groups } });
}

test('composeIDTokenClaims H1: filedrop member only — groups is union of real + role', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest({ group: 'filedrop', roleClaimEmit: { groups: ['filedrop-user'] } });
  const c = composeIDTokenClaims(id, m);
  assert.ok(Array.isArray(c.groups), 'groups is an array');
  assert.ok(c.groups.includes('filedrop'), 'filedrop preserved');
  assert.ok(c.groups.includes('filedrop-user'), 'filedrop-user added');
});

test('composeIDTokenClaims H1: filedrop-admin only — admin membership preserved', () => {
  const id = identityWithGroups(['filedrop-admin']);
  const m = manifest({ group: 'filedrop-admin', roleClaimEmit: { groups: ['filedrop-user'] } });
  const c = composeIDTokenClaims(id, m);
  assert.ok(c.groups.includes('filedrop-admin'), 'filedrop-admin preserved');
  assert.ok(c.groups.includes('filedrop-user'), 'filedrop-user added');
});

test('composeIDTokenClaims H1: filedrop+filedrop-admin — both preserved, no duplicates', () => {
  const id = identityWithGroups(['filedrop', 'filedrop-admin']);
  const m = {
    ...manifest({ group: 'filedrop', roleClaimEmit: { groups: ['filedrop-user'] } }),
    groupRoleMap: { filedrop: 'member', 'filedrop-admin': 'member' },
    accessGroups: ['filedrop', 'filedrop-admin'],
  };
  const c = composeIDTokenClaims(id, m);
  assert.ok(c.groups.includes('filedrop'), 'filedrop preserved');
  assert.ok(c.groups.includes('filedrop-admin'), 'filedrop-admin preserved');
  assert.ok(c.groups.includes('filedrop-user'), 'filedrop-user additive');
  const groups = c.groups;
  assert.equal(groups.length, new Set(groups).size, 'no duplicates');
});

test('composeIDTokenClaims binds groups: identity and other apps groups dropped, role-map-only key kept', () => {
  const id = identityWithGroups(['admin', 'everyone', 'other-access', 'filedrop-admin', 'filedrop']);
  const m = {
    ...manifest({ group: 'filedrop', roleClaimEmit: { groups: ['filedrop-user'] } }),
    groupRoleMap: { filedrop: 'member', 'filedrop-admin': 'member' },
  };
  assert.deepEqual(composeIDTokenClaims(id, m).groups, ['filedrop-admin', 'filedrop', 'filedrop-user']);
});

test('composeIDTokenClaims binds groups: nothing bound omits the claim, null manifest omits it', () => {
  const id = identityWithGroups(['admin', 'everyone']);
  assert.equal('groups' in composeIDTokenClaims(id, manifest({ group: 'filedrop' })), false);
  assert.equal('groups' in composeIDTokenClaims(id, null), false);
});

test('composeIDTokenClaims H2: requestedScope [openid] — no email/name/groups', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid']);
  assert.equal('email' in c, false, 'email absent');
  assert.equal('email_verified' in c, false, 'email_verified absent');
  assert.equal('name' in c, false, 'name absent');
  assert.equal('preferred_username' in c, false, 'preferred_username absent');
  assert.equal('groups' in c, false, 'groups absent');
});

test('composeIDTokenClaims H2: requestedScope [openid, email] — email present, name/groups absent', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid', 'email']);
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.email_verified, true);
  assert.equal('name' in c, false, 'name absent');
  assert.equal('preferred_username' in c, false, 'preferred_username absent');
  assert.equal('groups' in c, false, 'groups absent');
});

test('composeIDTokenClaims H2: requestedScope [openid, email, profile, groups] — all claims present', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m, ['openid', 'email', 'profile', 'groups']);
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.email_verified, true);
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.preferred_username, 'ada');
  assert.ok(Array.isArray(c.groups), 'groups is an array');
});

test('composeIDTokenClaims back-compat: no requestedScope → all claims emitted', () => {
  const id = identityWithGroups(['filedrop']);
  const m = manifest();
  const c = composeIDTokenClaims(id, m);
  assert.equal(c.email, 'a@othala.test');
  assert.equal(c.name, 'Ada Lovelace');
  assert.equal(c.preferred_username, 'ada');
  assert.ok(Array.isArray(c.groups), 'groups is an array');
});

const rankedManifest = {
  ...manifest({ group: 'filedrop-access' }),
  roles: [
    { name: 'admin', description: '', claimEmit: { groups: ['filedrop-admin-claim'] } },
    { name: 'user', description: '', claimEmit: { groups: ['filedrop-user-claim'] } },
  ],
  groupRoleMap: { 'filedrop-access': 'user', 'filedrop-admin': 'admin' },
};

test('lookupRole: access-then-admin storage order resolves the higher-ranked admin role', () => {
  const result = lookupRole(rankedManifest, { groups: ['filedrop-access', 'filedrop-admin'] });
  assert.equal(result?.roleName, 'admin');
});

test('lookupRole: admin-then-access storage order resolves the SAME higher-ranked admin role', () => {
  const result = lookupRole(rankedManifest, { groups: ['filedrop-admin', 'filedrop-access'] });
  assert.equal(result?.roleName, 'admin');
});

// Invariant: the access gate admits only active identities holding the bound group.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import {
  enforceAccessGate,
  enforceGroupGate,
  hasGroup,
  nonCanonicalGroups,
} from '../src/lib/gate.ts';
import { parseIdentity } from '../src/lib/identity-facts.ts';
import { identity as buildIdentity } from '../src/lib/test-builders.ts';

const identity = (overrides = {}) => ({ ...buildIdentity({ metadataAdmin: { groups: ['memories'] } }), ...overrides });
const identityGroups = (i) => parseIdentity(i).groups;

function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: clientId,
    accessGroups: opts.accessGroups ?? [`access-${clientId}`],
    skipAccessCheck: opts.skipAccessCheck ?? false,
    roles: [],
    groupRoleMap: {},
  };
}

test('identityGroups / hasGroup read metadata_admin.groups defensively', () => {
  assert.deepEqual(identityGroups(identity()), ['memories']);
  assert.equal(hasGroup(identity(), 'memories'), true);
  assert.equal(hasGroup(identity(), 'other'), false);
  assert.deepEqual(identityGroups(identity({ metadata_admin: {} })), []);
  assert.deepEqual(identityGroups(identity({ metadata_admin: undefined })), []);
  assert.deepEqual(identityGroups(null), []);
});

test('gate ALLOWS an active member of a bound access group', () => {
  const r = enforceAccessGate(identity(), manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, true);
  assert.equal(r.reason, undefined);
});

test('gate ALLOWS via OR-semantics when the user is in any one bound group', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['memories'] } }),
    manifest('photos', { accessGroups: ['admin-memories', 'memories'] }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when the user is in NONE of the bound groups', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['other'] } }),
    manifest('photos', { accessGroups: ['memories'] }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /not in any of the access group/);
});

test('gate DENIES when the manifest binds no access groups (no implicit access)', () => {
  const r = enforceAccessGate(identity(), manifest('photos', { accessGroups: [] }));
  assert.equal(r.allowed, false);
  assert.match(r.reason, /no access group bound/);
});

test('gate DENIES when no manifest is supplied (fail-closed)', () => {
  const r = enforceAccessGate(identity(), undefined);
  assert.equal(r.allowed, false);
});

test('skip_access_check bypasses the group check for an active identity', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: [] } }),
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, true);
});

test('gate DENIES when state is inactive (deactivated identity)', () => {
  const r = enforceAccessGate(identity({ state: 'inactive' }), manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES when state is missing (fail-closed)', () => {
  const r = enforceAccessGate(identity({ state: undefined }), manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('skip_access_check NEVER bypasses the state check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive' }),
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES on null identity (lookup failure, fail-closed)', () => {
  const r = enforceAccessGate(null, manifest('photos', { accessGroups: ['memories'] }));
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity lookup failed');
});

test('state check precedes group check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive', metadata_admin: { groups: [] } }),
    manifest('photos', { accessGroups: ['memories'] }),
  );
  assert.equal(r.reason, 'identity not active');
});

test('regression: access-proxywatch flat binding still admits a member', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['access-proxywatch'] } }),
    manifest('proxywatch', { accessGroups: ['access-proxywatch'] }),
  );
  assert.equal(r.allowed, true);
});

test('enforceGroupGate: active member of the named group → allow', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['access-proxywatch'] } }), 'access-proxywatch');
  assert.equal(r.allowed, true);
});

test('enforceGroupGate: not a member → deny', () => {
  const r = enforceGroupGate(identity({ metadata_admin: { groups: ['other'] } }), 'access-proxywatch');
  assert.equal(r.allowed, false);
});

test('hasGroup does NOT match a mixed-case stored group against a lowercase query', () => {
  const id = identity({ metadata_admin: { groups: ['Access-Grafana'] } });
  assert.equal(hasGroup(id, 'access-grafana'), false);
});

test('hasGroup does NOT match a lowercase stored group against a mixed-case query', () => {
  const id = identity({ metadata_admin: { groups: ['access-grafana'] } });
  assert.equal(hasGroup(id, 'Access-Grafana'), false);
});

test('hasGroup does NOT match an UPPERCASE stored group against a lowercase query', () => {
  const id = identity({ metadata_admin: { groups: ['ACCESS-GRAFANA'] } });
  assert.equal(hasGroup(id, 'access-grafana'), false);
});

test('hasGroup rejects a different group name', () => {
  const id = identity({ metadata_admin: { groups: ['access-grafana'] } });
  assert.equal(hasGroup(id, 'access-photos'), false);
});

test('nonCanonicalGroups reports exactly the stored names that miss GROUP_RE', () => {
  const id = identity({ metadata_admin: { groups: ['access-proxywatch', 'Access-Grafana', 'has space'] } });
  assert.deepEqual(nonCanonicalGroups(id), ['Access-Grafana', 'has space']);
  assert.deepEqual(nonCanonicalGroups(identity()), []);
  assert.deepEqual(nonCanonicalGroups(null), []);
});

test('enforceGroupGate DENIES when a stored group is non-canonical, naming it', () => {
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['Access-Proxywatch'] } }),
    'access-proxywatch',
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /non-canonical/);
  assert.match(r.reason, /Access-Proxywatch/);
});

test('enforceGroupGate DENIES a group the identity legitimately holds when ANOTHER is non-canonical', () => {
  const r = enforceGroupGate(
    identity({ metadata_admin: { groups: ['access-proxywatch', 'Access-Grafana'] } }),
    'access-proxywatch',
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /Access-Grafana/);
});

test('enforceAccessGate DENIES on a non-canonical stored group, even with skip_access_check', () => {
  const r = enforceAccessGate(
    identity({ metadata_admin: { groups: ['Access-Proxywatch'] } }),
    manifest('photos', { accessGroups: [], skipAccessCheck: true }),
  );
  assert.equal(r.allowed, false);
  assert.match(r.reason, /non-canonical/);
});

test('the state check still precedes the non-canonical refusal', () => {
  const r = enforceGroupGate(
    identity({ state: 'inactive', metadata_admin: { groups: ['Access-Proxywatch'] } }),
    'access-proxywatch',
  );
  assert.equal(r.reason, 'identity not active');
});

// Tests for src/lib/gate.ts — the COMPLETE access gate (CU1 item 2).
//
// Run with: tsx --test scripts/gate.test.mjs
//
// Imports the canonical implementation directly. Mirrors enforceAccessGate in
// consent/handlers.go: group membership in access-<clientId> AND state==active,
// both fail-closed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  enforceAccessGate,
  hasGroup,
  identityGroups,
  requiredGroupFor,
} from '../src/lib/gate.ts';

function identity(overrides = {}) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'tester', email: 'a@dunn.dev' },
    metadata_admin: { groups: ['access-grafana'] },
    ...overrides,
  };
}

test('requiredGroupFor derives access-<lowercased clientId>', () => {
  assert.equal(requiredGroupFor('grafana'), 'access-grafana');
  assert.equal(requiredGroupFor('Grafana'), 'access-grafana');
});

test('identityGroups / hasGroup read metadata_admin.groups defensively', () => {
  assert.deepEqual(identityGroups(identity()), ['access-grafana']);
  assert.equal(hasGroup(identity(), 'access-grafana'), true);
  assert.equal(hasGroup(identity(), 'access-other'), false);
  assert.deepEqual(identityGroups(identity({ metadata_admin: {} })), []);
  assert.deepEqual(identityGroups(identity({ metadata_admin: undefined })), []);
  assert.deepEqual(identityGroups(null), []);
});

test('gate ALLOWS an active member of the access group', () => {
  const r = enforceAccessGate(identity(), 'grafana');
  assert.equal(r.allowed, true);
  assert.equal(r.reason, undefined);
});

test('gate DENIES when missing the access group (login+consent share this)', () => {
  const r = enforceAccessGate(identity({ metadata_admin: { groups: ['other'] } }), 'grafana');
  assert.equal(r.allowed, false);
  assert.match(r.reason, /access-grafana group/);
});

test('gate DENIES when state is inactive (deactivated identity)', () => {
  const r = enforceAccessGate(identity({ state: 'inactive' }), 'grafana');
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES when state is missing (fail-closed)', () => {
  const r = enforceAccessGate(identity({ state: undefined }), 'grafana');
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity not active');
});

test('gate DENIES on null identity (lookup failure, fail-closed)', () => {
  const r = enforceAccessGate(null, 'grafana');
  assert.equal(r.allowed, false);
  assert.equal(r.reason, 'identity lookup failed');
});

test('state check precedes group check', () => {
  const r = enforceAccessGate(
    identity({ state: 'inactive', metadata_admin: { groups: [] } }),
    'grafana',
  );
  assert.equal(r.reason, 'identity not active');
});

test('clientId is lowercased for the group check', () => {
  const r = enforceAccessGate(identity(), 'Grafana');
  assert.equal(r.allowed, true);
});

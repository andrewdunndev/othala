// Invariant: manifest lint blocks or warns on each access-binding mistake it is built to catch.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { lintManifests, lintBlockers } from '../src/lib/manifest-lint.ts';

function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: opts.clientName ?? clientId,
    redirectUris: [],
    postLogoutRedirectUris: [],
    scopes: [],
    scope: '',
    audience: [],
    grantTypes: [],
    responseTypes: [],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroup: `access-${clientId}`,
    accessGroups: opts.accessGroups ?? [`access-${clientId}`],
    roles: opts.roles ?? [],
    groupRoleMap: opts.groupRoleMap ?? {},
    emitGroupsClaim: null,
    skipAccessCheck: opts.skipAccessCheck ?? false,
    sourcePath: opts.sourcePath ?? `${clientId}.yaml`,
  };
}

const known = ['admin', 'family', 'memories', 'access-photos', 'access-proxywatch'];

test('BLOCK: empty accessGroups without skip_access_check', () => {
  const f = lintManifests([manifest('photos', { accessGroups: [] })], known);
  const b = f.filter((x) => x.severity === 'block');
  assert.equal(b.length, 1);
  assert.match(b[0].message, /unreachable/);
});

test('BLOCK is suppressed when skip_access_check is set', () => {
  const f = lintManifests(
    [manifest('photos', { accessGroups: [], skipAccessCheck: true })],
    known,
  );
  assert.equal(f.filter((x) => x.severity === 'block').length, 0);
});

test('BLOCK: duplicate group within one manifest', () => {
  const f = lintManifests(
    [manifest('photos', { accessGroups: ['memories', 'memories'] })],
    known,
  );
  const b = f.filter((x) => x.severity === 'block');
  assert.equal(b.length, 1);
  assert.match(b[0].message, /more than once/);
});

test('BLOCK: group_role_map key maps to an undeclared role', () => {
  const f = lintManifests(
    [
      manifest('photos', {
        accessGroups: ['memories'],
        roles: [{ name: 'viewer', description: '', claimEmit: {} }],
        groupRoleMap: { memories: 'editor' }, // editor not declared
      }),
    ],
    known,
  );
  const b = f.filter((x) => x.severity === 'block');
  assert.equal(b.length, 1);
  assert.match(b[0].message, /not declared/);
});

test('WARN: a group referenced but not in the known set (typo → lockout)', () => {
  const f = lintManifests([manifest('photos', { accessGroups: ['memmories'] })], known);
  const w = f.filter((x) => x.severity === 'warn');
  assert.ok(w.some((x) => /locks everyone out/.test(x.message)));
});

test('WARN: charset miss', () => {
  const f = lintManifests([manifest('photos', { accessGroups: ['Bad_Name'] })], known);
  const w = f.filter((x) => x.severity === 'warn');
  assert.ok(w.some((x) => /safe charset/.test(x.message)));
});

test('WARN: charset miss on a group_role_map KEY', () => {
  const f = lintManifests(
    [
      manifest('photos', {
        roles: [{ name: 'admin', claimEmit: {} }],
        groupRoleMap: { 'Access-Photos': 'admin' },
      }),
    ],
    known,
  );
  const w = f.filter((x) => x.severity === 'warn');
  assert.ok(w.some((x) => /safe charset/.test(x.message) && /Access-Photos/.test(x.message)));
});

test('a canonical group_role_map key does NOT fire the charset warn', () => {
  const f = lintManifests(
    [
      manifest('photos', {
        accessGroups: ['memories'],
        roles: [{ name: 'admin', claimEmit: {} }],
        groupRoleMap: { memories: 'admin' },
      }),
    ],
    known,
  );
  assert.equal(f.filter((x) => /safe charset/.test(x.message)).length, 0);
});

test('clean manifest with a known bound group yields no findings', () => {
  const f = lintManifests(
    [
      manifest('photos', {
        accessGroups: ['memories'],
        roles: [{ name: 'viewer', description: '', claimEmit: {} }],
        groupRoleMap: { memories: 'viewer' },
      }),
    ],
    known,
  );
  assert.deepEqual(f, []);
});

test('lintBlockers returns only BLOCK findings', () => {
  const f = lintBlockers(
    [manifest('photos', { accessGroups: ['memmories'] })], // 1 warn only
    known,
  );
  assert.equal(f.length, 0);
});

test('access-proxywatch is a known flat name — no typo warning', () => {
  const f = lintManifests([manifest('proxywatch', { accessGroups: ['access-proxywatch'] })], known);
  assert.deepEqual(f.filter((x) => /locks everyone out/.test(x.message)), []);
});

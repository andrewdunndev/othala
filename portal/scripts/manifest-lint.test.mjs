// Invariant: manifest lint blocks or warns on each access-binding mistake it is built to catch.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { lintManifests, lintBlockers } from '../src/lib/manifest-lint.ts';
import { parseManifest } from '../src/lib/manifests.ts';

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
    accessGroups: opts.accessGroups ?? [`access-${clientId}`],
    roles: opts.roles ?? [],
    groupRoleMap: opts.groupRoleMap ?? {},
    emitGroupsClaim: null,
    skipAccessCheck: opts.skipAccessCheck ?? false,
    sourcePath: opts.sourcePath ?? `${clientId}.yaml`,
    retiredIcon: opts.retiredIcon ?? false,
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

test('BLOCK: a retired icon_slug or icon_fallback points at <stem>.svg', () => {
  const b = lintBlockers([manifest('photos', { retiredIcon: true })], known);
  assert.equal(b.length, 1);
  assert.match(b[0].message, /<stem>\.svg/);
});

const launchManifest = (launch) =>
  parseManifest(
    `presentation:\n  name: Widget\n  url: https://widget.othala.test/\n  access: [access-widget]\n${launch ? `  launch_url: ${launch}\n` : ''}`,
    'widget.yaml',
  );

test('BLOCK: a launch_url that is http or on another host', () => {
  for (const bad of ['http://widget.othala.test/x', 'https://elsewhere.test/x', 'https://widget.othala.test:8443/x']) {
    const b = lintBlockers([launchManifest(bad)], ['access-widget']);
    assert.equal(b.length, 1, bad);
    assert.match(b[0].message, /launch_url/);
  }
});

test('clean: a same-host launch_url with a path and fragment', () => {
  const m = launchManifest("'https://widget.othala.test/app/#/sso?identifier=dag'");
  assert.equal(m.launchUrlProblem, undefined);
  assert.deepEqual(lintBlockers([m], ['access-widget']), []);
});

test('BLOCK: skip_step_up on a presentation-only manifest', () => {
  const m = parseManifest('presentation:\n  name: Widget\n  url: https://widget.othala.test/\n  access: [access-widget]\nconsent:\n  skip_step_up: true\n', 'widget.yaml');
  const b = lintBlockers([m], ['access-widget']);
  assert.equal(b.length, 1);
  assert.match(b[0].message, /skip_step_up/);
});

test('BLOCK: skip_step_up with a device_code grant; clean on an authorization_code client', () => {
  const doc = (grant) =>
    `oidc:\n  client_id: widget\n  scope: openid\n  grant_types: [${grant}]\npresentation:\n  access: [access-widget]\nconsent:\n  skip_step_up: true\n`;
  const bad = lintBlockers([parseManifest(doc('urn:ietf:params:oauth:grant-type:device_code'), 'widget.yaml')], ['access-widget']);
  assert.equal(bad.length, 1);
  assert.match(bad[0].message, /device_code/);
  assert.deepEqual(lintBlockers([parseManifest(doc('authorization_code'), 'widget.yaml')], ['access-widget']), []);
});

// Invariant: an audience matches only an exact origin (scheme, host, port) of a known client.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { audienceMatchesRedirect } from '../src/lib/manifests.ts';

function manifest(redirectUris) {
  return {
    clientId: 'grafana',
    clientName: 'Grafana',
    redirectUris,
    postLogoutRedirectUris: [],
    scopes: [],
    audience: [],
    grantTypes: [],
    skipConsent: true,
    backchannelLogoutUri: '',
    roles: [],
    groupRoleMap: {},
  };
}

const m = manifest(['https://grafana.othala.test/login/generic_oauth']);

test('exact-origin audience is accepted', () => {
  assert.equal(audienceMatchesRedirect(m, ['https://grafana.othala.test']), true);
});

test('REJECTS a suffix-attack audience (prefix/HasPrefix hole closed)', () => {
  assert.equal(audienceMatchesRedirect(m, ['https://grafana.othala.test.evil.com']), false);
});

test('REJECTS a scheme mismatch', () => {
  assert.equal(audienceMatchesRedirect(m, ['http://grafana.othala.test']), false);
});

test('REJECTS a port mismatch (origin includes port)', () => {
  assert.equal(audienceMatchesRedirect(m, ['https://grafana.othala.test:8443']), false);
});

test('REJECTS unknown client (undefined manifest, no silent allow)', () => {
  assert.equal(audienceMatchesRedirect(undefined, ['https://grafana.othala.test']), false);
});

test('REJECTS when manifest has no usable redirect origins (no silent allow)', () => {
  assert.equal(audienceMatchesRedirect(manifest([]), ['https://grafana.othala.test']), false);
  assert.equal(audienceMatchesRedirect(manifest(['app://custom']), ['https://grafana.othala.test']), false);
});

test('empty / absent audience is unconstrained -> true', () => {
  assert.equal(audienceMatchesRedirect(m, []), true);
  assert.equal(audienceMatchesRedirect(m, undefined), true);
});

test('REJECTS a non-URL audience', () => {
  assert.equal(audienceMatchesRedirect(m, ['not-a-url']), false);
});

test('REJECTS when one of several audiences fails', () => {
  assert.equal(
    audienceMatchesRedirect(m, ['https://grafana.othala.test', 'https://other.othala.test']),
    false,
  );
});

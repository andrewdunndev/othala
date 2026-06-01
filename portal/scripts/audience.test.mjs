// Tests for audienceMatchesRedirect in src/lib/manifests.ts (CU1 item 5/6).
//
// Run with: tsx --test scripts/audience.test.mjs
//
// The tightened validator requires EXACT-ORIGIN match and is fail-closed: it
// drops the Go version's HasPrefix-style host compare and its silent
// `return true` paths.

import { test } from 'node:test';
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
    accessGroup: 'access-grafana',
    roles: [],
    groupRoleMap: {},
  };
}

const m = manifest(['https://grafana.dunn.dev/login/generic_oauth']);

test('exact-origin audience is accepted', () => {
  assert.equal(audienceMatchesRedirect(m, ['https://grafana.dunn.dev']), true);
});

test('REJECTS a suffix-attack audience (prefix/HasPrefix hole closed)', () => {
  assert.equal(audienceMatchesRedirect(m, ['https://grafana.dunn.dev.evil.com']), false);
});

test('REJECTS a scheme mismatch', () => {
  assert.equal(audienceMatchesRedirect(m, ['http://grafana.dunn.dev']), false);
});

test('REJECTS a port mismatch (origin includes port)', () => {
  assert.equal(audienceMatchesRedirect(m, ['https://grafana.dunn.dev:8443']), false);
});

test('REJECTS unknown client (undefined manifest, no silent allow)', () => {
  assert.equal(audienceMatchesRedirect(undefined, ['https://grafana.dunn.dev']), false);
});

test('REJECTS when manifest has no usable redirect origins (no silent allow)', () => {
  assert.equal(audienceMatchesRedirect(manifest([]), ['https://grafana.dunn.dev']), false);
  assert.equal(audienceMatchesRedirect(manifest(['app://custom']), ['https://grafana.dunn.dev']), false);
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
    audienceMatchesRedirect(m, ['https://grafana.dunn.dev', 'https://other.dunn.dev']),
    false,
  );
});

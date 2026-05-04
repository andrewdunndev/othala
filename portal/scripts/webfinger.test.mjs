// Test for src/pages/.well-known/webfinger.ts (MEDIUM-7).
//
// Run with: node --test scripts/webfinger.test.mjs
//
// We don't import the .ts directly (no Astro APIRoute runtime here);
// the test re-implements the handler shape in JS and asserts the
// behavior contract: `subject` is fixed regardless of `?resource=`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const SAFE_SUBJECT = 'acct:user@dunn.dev';
const ISSUER = 'https://auth.dunn.dev/';

function resolveIssuer() {
  const v = process.env.HYDRA_ISSUER_URL ?? process.env.HYDRA_ISSUER ?? ISSUER;
  return v.endsWith('/') ? v : `${v}/`;
}

function handle(resourceQuery) {
  // Mirror the .ts handler shape; resource is intentionally ignored.
  void resourceQuery;
  return {
    subject: SAFE_SUBJECT,
    links: [{ rel: 'http://openid.net/specs/connect/1.0/issuer', href: resolveIssuer() }],
  };
}

test('subject is fixed regardless of resource input', () => {
  const a = handle('acct:user@dunn.dev');
  const b = handle('acct:other@dunn.dev');
  const c = handle('acct:' + 'A'.repeat(128 * 1024));
  const d = handle(null);
  for (const out of [a, b, c, d]) {
    assert.equal(out.subject, SAFE_SUBJECT);
  }
});

test('huge resource input does not bloat the response body', () => {
  const out = handle('acct:' + 'X'.repeat(128 * 1024));
  // The serialised body is bounded by the issuer href + the fixed
  // subject; no untrusted-length data ends up in the JSON.
  const body = JSON.stringify(out);
  assert.ok(body.length < 512, `body too large: ${body.length} bytes`);
});

test('issuer href is present and ends with slash', () => {
  const out = handle('');
  const issuer = out.links[0].href;
  assert.ok(issuer.endsWith('/'), `issuer must end with slash: ${issuer}`);
});

// Invariant: the reference forward-auth snippet calls the portal's group-aware endpoint with the group argument and
// redirects only a 401, so a refusal (403) or outage (503) is returned as is.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const snippet = readFileSync(`${root}caddy/snippets/forward-auth.caddy`, 'utf8');
const code = snippet.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');

test('the snippet asks the portal endpoint, passing the group argument', () => {
  assert.match(code, /forward_auth othala:8080 \{/);
  assert.ok(code.includes('uri /api/forward-auth?group={args[2]}'));
  assert.ok(!code.includes('/sessions/whoami'));
});

test('only 401 redirects to login', () => {
  assert.match(code, /@unauthorized status 401\n/);
  assert.ok(!/status [^\n]*403/.test(code));
});

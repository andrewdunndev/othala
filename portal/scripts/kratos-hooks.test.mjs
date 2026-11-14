// Invariant: the settings hooks are wired as the portal relies on: grants end on every credential change, only a
// password save ends the other sessions, and the privileged window stays short.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

test('the privileged settings window is at most 5 minutes', () => {
  const file = fileURLToPath(new URL('../../kratos/kratos.yml', import.meta.url));
  const age = parse(readFileSync(file, 'utf8')).selfservice.flows.settings.privileged_session_max_age;
  const m = /^(\d+)([smh])$/.exec(String(age));
  assert.ok(m, `unparseable privileged_session_max_age: ${age}`);
  assert.ok(Number(m[1]) * { s: 1, m: 60, h: 3600 }[m[2]] <= 300, `privileged_session_max_age ${age} exceeds 5m`);
});

function afterHooks(method) {
  const file = fileURLToPath(new URL('../../kratos/kratos.yml', import.meta.url));
  return parse(readFileSync(file, 'utf8')).selfservice.flows.settings.after[method]?.hooks ?? [];
}

test.each(['password', 'passkey', 'webauthn', 'totp', 'lookup_secret'])('a %s change ends app grants through a non-interrupting, detached web_hook', (method) => {
  const grants = afterHooks(method).find((h) => h.hook === 'web_hook' && h.config.url === 'http://othala:4431/admin/revoke-grants');
  assert.ok(grants, `settings.after.${method} has no revoke-grants hook`);
  assert.equal(grants.config.can_interrupt, false);
  assert.equal(grants.config.response.ignore, true);
  assert.match(grants.config.auth.config.value, /^Bearer \$\{RECOVERY_GATE_SECRET\}$/);
});

test('every post-persist web_hook after a settings change is detached; only the pre-persist gates answer the flow', () => {
  const file = fileURLToPath(new URL('../../kratos/kratos.yml', import.meta.url));
  const after = parse(readFileSync(file, 'utf8')).selfservice.flows.settings.after;
  for (const [method, { hooks = [] }] of Object.entries(after)) {
    for (const h of hooks.filter((x) => x.hook === 'web_hook')) {
      assert.equal(h.config.response.ignore, !h.config.can_interrupt, `settings.after.${method} ${h.config.url}`);
    }
  }
});

test('a password save still ends the other sessions', () => {
  assert.ok(afterHooks('password').some((h) => h.hook === 'revoke_active_sessions'));
});

test('only a password save revokes the other sessions; adding or removing a credential keeps them (it ends app grants instead)', () => {
  assert.ok(afterHooks('password').some((h) => h.hook === 'revoke_active_sessions'));
  for (const m of ['passkey', 'webauthn', 'totp', 'lookup_secret']) {
    assert.ok(!afterHooks(m).some((h) => h.hook === 'revoke_active_sessions'), `${m} must not revoke sessions`);
  }
});

test('settings.after.passkey prunes names through a non-interrupting post-persist web_hook', () => {
  const hooks = afterHooks('passkey');
  const { url, auth, can_interrupt: interrupt } = hooks[0].config;
  assert.equal(hooks[0].hook, 'web_hook');
  assert.equal(url, 'http://othala:4431/admin/passkey-prune');
  assert.equal(auth.config.value, 'Bearer ${RECOVERY_GATE_SECRET}');
  assert.equal(interrupt, false);
});

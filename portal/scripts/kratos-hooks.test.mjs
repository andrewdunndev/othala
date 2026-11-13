// Invariant: every hook list in kratos.yml uses hook names the Kratos config schema allows.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const SETTINGS_AUTH = ['web_hook', 'revoke_active_sessions'];
const SETTINGS_PROFILE = ['web_hook', 'show_verification_ui', 'b2b_sso', 'organization'];
const LOGIN = ['revoke_active_sessions', 'require_verified_address', 'web_hook', 'verification', 'show_verification_ui', 'b2b_sso', 'organization'];
const REGISTRATION = ['session', 'web_hook', 'show_verification_ui', 'b2b_sso', 'organization'];

const ALLOWED = {
  'recovery.after': ['web_hook', 'revoke_active_sessions'],
  'settings.after.profile': SETTINGS_PROFILE,
  'login.after': LOGIN,
};
for (const m of ['password', 'totp', 'oidc', 'webauthn', 'passkey', 'lookup_secret']) ALLOWED[`settings.after.${m}`] = SETTINGS_AUTH;
for (const m of ['password', 'webauthn', 'passkey', 'code', 'totp', 'lookup_secret']) ALLOWED[`login.after.${m}`] = LOGIN;
for (const m of ['password', 'webauthn', 'passkey']) ALLOWED[`registration.after.${m}`] = REGISTRATION;

function hookLists(node, path, out) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) return out;
  for (const [k, v] of Object.entries(node)) {
    if (k === 'hooks' && Array.isArray(v)) out.push([path, v]);
    else hookLists(v, path ? `${path}.${k}` : k, out);
  }
  return out;
}

test('every kratos.yml hook is one the v26.2.0 schema allows at its placement', () => {
  const file = fileURLToPath(new URL('../../kratos/kratos.yml', import.meta.url));
  const lists = hookLists(parse(readFileSync(file, 'utf8')).selfservice.flows, '', []);
  assert.ok(lists.length >= 7, `only ${lists.length} hook lists found`);
  for (const [path, hooks] of lists) {
    assert.ok(ALLOWED[path], `${path}: placement not in the schema table`);
    for (const h of hooks) assert.ok(ALLOWED[path].includes(h.hook), `${path}: ${h.hook} is not allowed here`);
  }
});

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

test('a password save ends app grants through a non-interrupting web_hook that still ends the other sessions', () => {
  const hooks = afterHooks('password');
  assert.ok(hooks.some((h) => h.hook === 'revoke_active_sessions'));
  const grants = hooks.find((h) => h.hook === 'web_hook' && h.config.url === 'http://othala:4431/admin/revoke-grants');
  assert.ok(grants, 'settings.after.password has no revoke-grants hook');
  assert.equal(grants.config.can_interrupt, false);
  assert.equal(grants.config.response.ignore, false);
  assert.match(grants.config.auth.config.value, /^Bearer \$\{RECOVERY_GATE_SECRET\}$/);
});

test('only a password save revokes the other sessions; adding or removing a credential keeps them', () => {
  assert.ok(afterHooks('password').some((h) => h.hook === 'revoke_active_sessions'));
  for (const m of ['passkey', 'webauthn', 'totp', 'lookup_secret']) {
    assert.ok(!afterHooks(m).some((h) => h.hook === 'revoke_active_sessions'), `${m} must not revoke sessions`);
  }
});

test('settings.after.passkey prunes names through a non-interrupting post-persist web_hook', () => {
  const hooks = afterHooks('passkey');
  assert.equal(hooks.length, 1);
  const { url, auth, can_interrupt: interrupt } = hooks[0].config;
  assert.equal(hooks[0].hook, 'web_hook');
  assert.equal(url, 'http://othala:4431/admin/passkey-prune');
  assert.equal(auth.config.value, 'Bearer ${RECOVERY_GATE_SECRET}');
  assert.equal(interrupt, false);
});

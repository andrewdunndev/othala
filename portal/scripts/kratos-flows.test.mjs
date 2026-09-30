// Invariant: browserFlows URL builders target the configured public URL.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { browserFlows } from '../src/lib/kratos.ts';

const BASE = ''; // browser-flow initiators are same-origin relative paths

test('login: no opts', () => {
  assert.equal(browserFlows.login(), `${BASE}/self-service/login/browser`);
});

test('login: aal2', () => {
  assert.equal(browserFlows.login({ aal: 'aal2' }), `${BASE}/self-service/login/browser?aal=aal2`);
});

test('login: aal2 + refresh', () => {
  const url = browserFlows.login({ aal: 'aal2', refresh: true });
  assert.ok(url.includes('aal=aal2'));
  assert.ok(url.includes('refresh=true'));
});

test('login: aal2 + refresh + returnTo with reserved chars', () => {
  const url = browserFlows.login({
    aal: 'aal2',
    refresh: true,
    returnTo: 'https://sso.othala.test/admin/users/abc-123?tab=overview',
  });
  assert.ok(url.includes('return_to=https%3A%2F%2Fsso.othala.test%2Fadmin%2Fusers%2Fabc-123%3Ftab%3Doverview'));
});

test('login: bare returnTo (no aal)', () => {
  const url = browserFlows.login({ returnTo: '/auth/settings' });
  assert.equal(url, `${BASE}/self-service/login/browser?return_to=%2Fauth%2Fsettings`);
});

test('registration: no opts', () => {
  assert.equal(browserFlows.registration(), `${BASE}/self-service/registration/browser`);
});

test('registration: with returnTo', () => {
  assert.equal(
    browserFlows.registration('/welcome'),
    `${BASE}/self-service/registration/browser?return_to=%2Fwelcome`,
  );
});

test('settings: with returnTo', () => {
  assert.equal(
    browserFlows.settings('/auth/settings'),
    `${BASE}/self-service/settings/browser?return_to=%2Fauth%2Fsettings`,
  );
});

test('recovery: with returnTo containing special chars', () => {
  assert.ok(browserFlows.recovery('https://example.com/?k=v').includes('%3F'));
});

test('verification: no opts', () => {
  assert.equal(browserFlows.verification(), `${BASE}/self-service/verification/browser`);
});

test('logout: with returnTo', () => {
  assert.equal(
    browserFlows.logout('/'),
    `${BASE}/self-service/logout/browser?return_to=%2F`,
  );
});

test('all builders: omit query string when no opts', () => {
  assert.ok(!browserFlows.login().includes('?'));
  assert.ok(!browserFlows.registration().includes('?'));
  assert.ok(!browserFlows.settings().includes('?'));
  assert.ok(!browserFlows.recovery().includes('?'));
  assert.ok(!browserFlows.verification().includes('?'));
  assert.ok(!browserFlows.logout().includes('?'));
});

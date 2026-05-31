// Tests for src/lib/kratos.ts browserFlows URL builders.
//
// Run with: KRATOS_PUBLIC_URL=https://test.example node --test scripts/kratos-flows.test.mjs
//
// The browserFlows URL builders are pure functions; mirroring them in
// JS lets us assert URL shape without booting Kratos. The TS file is
// canonical; this is regression protection for the query-string
// construction (return_to encoding, aal/refresh handling, etc.).

import { test } from 'node:test';
import assert from 'node:assert/strict';

const BASE = process.env.KRATOS_PUBLIC_URL ?? 'https://auth.dunn.dev';

const browserFlows = {
  login(opts = {}) {
    const p = new URLSearchParams();
    if (opts.aal) p.set('aal', opts.aal);
    if (opts.refresh) p.set('refresh', 'true');
    if (opts.returnTo) p.set('return_to', opts.returnTo);
    const qs = p.toString();
    return `${BASE}/self-service/login/browser${qs ? `?${qs}` : ''}`;
  },
  registration(returnTo) {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${BASE}/self-service/registration/browser${qs}`;
  },
  settings(returnTo) {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${BASE}/self-service/settings/browser${qs}`;
  },
  recovery(returnTo) {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${BASE}/self-service/recovery/browser${qs}`;
  },
  verification(returnTo) {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${BASE}/self-service/verification/browser${qs}`;
  },
  logout(returnTo) {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${BASE}/self-service/logout/browser${qs}`;
  },
};

test('login: no opts', () => {
  assert.equal(browserFlows.login(), `${BASE}/self-service/login/browser`);
});

test('login: aal2', () => {
  assert.equal(browserFlows.login({ aal: 'aal2' }), `${BASE}/self-service/login/browser?aal=aal2`);
});

test('login: aal2 + refresh', () => {
  const url = browserFlows.login({ aal: 'aal2', refresh: true });
  // Query order is insertion order for URLSearchParams; assert both keys present.
  assert.ok(url.includes('aal=aal2'));
  assert.ok(url.includes('refresh=true'));
});

test('login: aal2 + refresh + returnTo with reserved chars', () => {
  // The admin AAL2 step-up flow passes the current page as return_to.
  // Reserved chars (=, &, /) MUST be encoded so Kratos sees them as
  // values, not query separators.
  const url = browserFlows.login({
    aal: 'aal2',
    refresh: true,
    returnTo: 'https://auth.dunn.dev/admin/users/abc-123?tab=overview',
  });
  // URLSearchParams encodes : / ? = & properly
  assert.ok(url.includes('return_to=https%3A%2F%2Fauth.dunn.dev%2Fadmin%2Fusers%2Fabc-123%3Ftab%3Doverview'));
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
  // Defensive: don't emit "?" alone when there's nothing to add.
  assert.ok(!browserFlows.login().includes('?'));
  assert.ok(!browserFlows.registration().includes('?'));
  assert.ok(!browserFlows.settings().includes('?'));
  assert.ok(!browserFlows.recovery().includes('?'));
  assert.ok(!browserFlows.verification().includes('?'));
  assert.ok(!browserFlows.logout().includes('?'));
});

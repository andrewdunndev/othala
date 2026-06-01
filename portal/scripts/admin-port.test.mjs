// Contract tests for the D-listener admin mux (CU1 item 4/6).
//
// Run with: tsx --test scripts/admin-port.test.mjs
//
// Asserts the admin port serves ONLY /healthz + /readyz and that every
// public/challenge path 404s there — i.e. the admin routes are NOT reachable
// on the public mux and vice versa (the two muxes are disjoint). Imports the
// pure helpers from listen.mjs without binding any socket or loading the SSR
// handler.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAdminRoute, handleAdminRequest, ADMIN_ROUTES } from '../src/server/listen.mjs';

function fakeRes() {
  return {
    statusCode: 0,
    body: '',
    headers: null,
    writeHead(code, headers) { this.statusCode = code; this.headers = headers; return this; },
    end(chunk) { if (chunk) this.body += chunk; },
  };
}

test('admin mux serves exactly /healthz and /readyz', () => {
  assert.deepEqual([...ADMIN_ROUTES].sort(), ['/healthz', '/readyz']);
  assert.equal(isAdminRoute('GET', '/healthz'), true);
  assert.equal(isAdminRoute('GET', '/readyz'), true);
});

test('admin mux does NOT serve any public/challenge path', () => {
  for (const p of ['/', '/auth/login', '/admin', '/oauth2/login', '/oauth2/consent', '/oauth2/logout']) {
    assert.equal(isAdminRoute('GET', p), false, `${p} must not be an admin route`);
  }
});

test('challenge + public paths 404 on the admin port', () => {
  const paths = [
    '/oauth2/login?login_challenge=x',
    '/oauth2/consent?consent_challenge=x',
    '/oauth2/logout?logout_challenge=x',
    '/',
    '/admin',
    '/auth/login',
  ];
  for (const p of paths) {
    const res = fakeRes();
    handleAdminRequest({ method: 'GET', url: p }, res);
    assert.equal(res.statusCode, 404, `${p} should 404 on admin port`);
  }
});

test('healthz/readyz return 200 ok on the admin port', () => {
  for (const p of ['/healthz', '/readyz']) {
    const res = fakeRes();
    handleAdminRequest({ method: 'GET', url: p }, res);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(JSON.parse(res.body), { status: 'ok' });
  }
});

test('healthz tolerates a query string', () => {
  const res = fakeRes();
  handleAdminRequest({ method: 'GET', url: '/healthz?probe=1' }, res);
  assert.equal(res.statusCode, 200);
});

test('non-GET admin route is rejected (404)', () => {
  assert.equal(isAdminRoute('POST', '/healthz'), false);
  const res = fakeRes();
  handleAdminRequest({ method: 'POST', url: '/healthz' }, res);
  assert.equal(res.statusCode, 404);
});

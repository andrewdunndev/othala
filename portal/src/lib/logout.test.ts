import { describe, it, expect, beforeEach } from 'vitest';
import { logoutAuthorized, sameOriginRequest, signLogoutToken } from './logout.js';
import { signToken, _resetForTests } from './csrf.js';
import { session } from './test-builders.js';

const self = session().identity!.id;
const other = 'ffffffff-1111-2222-3333-444444444444';

beforeEach(() => {
  _resetForTests();
  process.env['CSRF_SECRET'] = 'a-test-secret-that-is-at-least-32-chars!!';
});

describe('logoutAuthorized', () => {
  it('accepts a POST carrying a sign-out token for this identity', () => {
    expect(logoutAuthorized('POST', signLogoutToken(self), self)).toBe(true);
  });

  it('refuses a GET even with a valid token', () => {
    expect(logoutAuthorized('GET', signLogoutToken(self), self)).toBe(false);
  });

  it('refuses a POST with no token', () => {
    expect(logoutAuthorized('POST', null, self)).toBe(false);
    expect(logoutAuthorized('POST', '', self)).toBe(false);
  });

  it('refuses a malformed or tampered token', () => {
    expect(logoutAuthorized('POST', 'not-a-token', self)).toBe(false);
    const t = signLogoutToken(self);
    expect(logoutAuthorized('POST', `${t.slice(0, -2)}xx`, self)).toBe(false);
  });

  it('refuses a token minted for another identity', () => {
    expect(logoutAuthorized('POST', signLogoutToken(other), self)).toBe(false);
  });

  it('refuses a token minted for another action or none', () => {
    expect(logoutAuthorized('POST', signToken(self, 'consent'), self)).toBe(false);
    expect(logoutAuthorized('POST', signToken(self), self)).toBe(false);
  });

  it('refuses a replayed token', () => {
    const t = signLogoutToken(self);
    expect(logoutAuthorized('POST', t, self)).toBe(true);
    expect(logoutAuthorized('POST', t, self)).toBe(false);
  });

  it('refuses a file upload in place of the token', () => {
    const f = new File(['x'], 'x.txt');
    expect(logoutAuthorized('POST', f, self)).toBe(false);
  });

  it('fails closed when the signing secret is unset', () => {
    const t = signLogoutToken(self);
    delete process.env['CSRF_SECRET'];
    expect(logoutAuthorized('POST', t, self)).toBe(false);
  });
});

describe('sameOriginRequest', () => {
  const own = 'https://auth.example.test';

  it('accepts a matching Origin', () => {
    expect(sameOriginRequest(own, null, own)).toBe(true);
  });

  it('refuses a different or opaque Origin even with a same-origin Referer', () => {
    expect(sameOriginRequest('https://other.example.test', `${own}/x`, own)).toBe(false);
    expect(sameOriginRequest('null', `${own}/x`, own)).toBe(false);
  });

  it('accepts no Origin with a same-origin Referer', () => {
    expect(sameOriginRequest(null, `${own}/auth/logout`, own)).toBe(true);
  });

  it('refuses no Origin with a missing, foreign or malformed Referer', () => {
    expect(sameOriginRequest(null, null, own)).toBe(false);
    expect(sameOriginRequest(null, 'https://other.example.test/', own)).toBe(false);
    expect(sameOriginRequest(null, 'not a url', own)).toBe(false);
  });
});

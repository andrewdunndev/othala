import { describe, it, expect, beforeEach, vi } from 'vitest';

const { revokeHydraSessionsMock } = vi.hoisted(() => ({ revokeHydraSessionsMock: vi.fn() }));
vi.mock('./revoke', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./revoke.js')>()),
  revokeHydraSessions: revokeHydraSessionsMock,
}));

import { endAppSignIns, logoutAuthorized, signLogoutToken } from './logout.js';
import { RevokeError } from './revoke.js';
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

  it('refuses a token minted for another action', () => {
    expect(logoutAuthorized('POST', signToken(self, 'consent'), self)).toBe(false);
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

describe('endAppSignIns', () => {
  it('ends the identity\'s Hydra sessions and reports success', async () => {
    revokeHydraSessionsMock.mockReset().mockResolvedValue(undefined);
    expect(await endAppSignIns(self)).toBe(true);
    expect(revokeHydraSessionsMock).toHaveBeenCalledWith(self);
  });

  it('logs the failed step and returns false instead of throwing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    revokeHydraSessionsMock.mockReset().mockRejectedValue(new RevokeError('hydra-admin', 'revoke-login-sessions', 'Verify HYDRA_ADMIN_URL.'));
    expect(await endAppSignIns(self)).toBe(false);
    revokeHydraSessionsMock.mockRejectedValue(new Error('boom'));
    expect(await endAppSignIns(self)).toBe(false);
    expect(warn.mock.calls.map((c) => String(c[0]))).toEqual([
      expect.stringMatching(/^\[othala\/logout\] .*revoke-login-sessions/),
      expect.stringMatching(/^\[othala\/logout\] .*unknown/),
    ]);
    warn.mockRestore();
  });
});

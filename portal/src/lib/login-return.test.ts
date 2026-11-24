import { describe, it, expect } from 'vitest';
import { LOGIN_RETURN_COOKIE, clearLoginReturn, flowSpent, isLoginReturn, keepLoginReturn, loginReturnOf, readLoginReturn } from './login-return.js';

const RETURN = '/oauth2/login?login_challenge=abc_DEF-123.x';
const header = (set: string) => set.split(';')[0];

describe('login-return', () => {
  it('keeps a relative /oauth2/login return and reads it back', () => {
    const [set] = keepLoginReturn(RETURN);
    expect(set).toMatch(new RegExp(`^${LOGIN_RETURN_COOKIE}=`));
    expect(set).toContain('HttpOnly');
    expect(set).toContain('Secure');
    expect(set).toContain('SameSite=Lax');
    expect(set).toContain('Path=/');
    expect(readLoginReturn(`a=1; ${header(set)}; b=2`)).toBe(RETURN);
  });

  it('keeps nothing that is not a relative /oauth2/login return', () => {
    for (const bad of [
      'https://evil.test/oauth2/login?login_challenge=x',
      '//evil.test/oauth2/login?login_challenge=x',
      '/oauth2/login?login_challenge=',
      '/oauth2/login?login_challenge=x&next=/admin',
      '/oauth2/consent?consent_challenge=x',
      `/oauth2/login?login_challenge=${'a'.repeat(4000)}`,
    ]) {
      expect(isLoginReturn(bad), bad).toBe(false);
      expect(keepLoginReturn(bad), bad).toEqual([]);
    }
  });

  it('reads nothing from a planted or malformed value', () => {
    expect(readLoginReturn(undefined)).toBeUndefined();
    expect(readLoginReturn('')).toBeUndefined();
    expect(readLoginReturn(`${LOGIN_RETURN_COOKIE}=${encodeURIComponent('https://evil.test/')}`)).toBeUndefined();
    expect(readLoginReturn(`${LOGIN_RETURN_COOKIE}=%E0%A4%A`)).toBeUndefined();
    expect(readLoginReturn(`othala_login_return=${encodeURIComponent(RETURN)}`)).toBeUndefined();
  });

  it('clears with Max-Age=0 on the same name and path', () => {
    expect(clearLoginReturn()).toMatch(new RegExp(`^${LOGIN_RETURN_COOKIE}=; Path=/; Max-Age=0`));
  });

  it('reads a flow return_to stored relative or absolute on the same origin only', () => {
    const origin = 'https://sso.othala.test';
    expect(loginReturnOf(RETURN, origin)).toBe(RETURN);
    expect(loginReturnOf(`${origin}${RETURN}`, origin)).toBe(RETURN);
    expect(loginReturnOf(`https://evil.test${RETURN}`, origin)).toBeUndefined();
    expect(loginReturnOf(`${origin}/`, origin)).toBeUndefined();
    expect(loginReturnOf(undefined, origin)).toBeUndefined();
  });

  it('calls a flow spent exactly when Kratos would answer its POST with the bare redirect', () => {
    const live = (aal: 'aal1' | 'aal2') => ({ active: true, authenticator_assurance_level: aal });
    // The production case: the first factor is done, the aal1 flow is still on the page.
    expect(flowSpent({ requested_aal: 'aal1' }, live('aal1'))).toBe(true);
    expect(flowSpent({ requested_aal: 'aal1' }, live('aal2'))).toBe(true);
    expect(flowSpent({ requested_aal: 'aal2' }, live('aal2'))).toBe(true);
    // Still runnable: a step-up for an aal1 session, a refresh, or no session.
    expect(flowSpent({ requested_aal: 'aal2' }, live('aal1'))).toBe(false);
    expect(flowSpent({ requested_aal: 'aal1', refresh: true }, live('aal1'))).toBe(false);
    expect(flowSpent({ requested_aal: 'aal1' }, null)).toBe(false);
    expect(flowSpent({ requested_aal: 'aal1' }, { active: false, authenticator_assurance_level: 'aal1' })).toBe(false);
  });
});

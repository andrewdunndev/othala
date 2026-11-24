import { describe, it, expect } from 'vitest';
import { LOGIN_RETURN_COOKIE, clearLoginReturn, isLoginReturn, keepLoginReturn, readLoginReturn } from './login-return.js';

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
});

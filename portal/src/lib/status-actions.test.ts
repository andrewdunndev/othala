import { describe, it, expect } from 'vitest';
import { statusActions, isTransient } from './status-actions';

const labels = (status: number, signedIn: boolean, retry = '/x') => statusActions(status, signedIn, retry).map((a) => a.label);

describe('statusActions', () => {
  it('offers Try again for a hiccup, signed in or not, and never Sign in', () => {
    for (const status of [429, 500, 503]) {
      expect(labels(status, false)).toEqual(['Try again', 'Go home']);
      expect(labels(status, true)).toEqual(['Try again', 'Go home']);
    }
  });
  it('drops Go home when Try again already goes home', () => {
    expect(labels(503, false, '/')).toEqual(['Try again']);
  });
  it('offers Sign in only to the signed out on a refusal or a missing page', () => {
    for (const status of [400, 403, 404]) {
      expect(labels(status, false)).toEqual(['Go home', 'Sign in']);
      expect(labels(status, true)).toEqual(['Go home']);
    }
  });
  it('leads with Sign in when the session expired', () => {
    expect(statusActions(401, false, '/x')[0]).toMatchObject({ label: 'Sign in', primary: true });
  });
  it('treats only 429 and 5xx as transient', () => {
    expect([401, 403, 404, 429, 500, 503].map(isTransient)).toEqual([false, false, false, true, true, true]);
  });
});

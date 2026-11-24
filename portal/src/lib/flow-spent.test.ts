import { describe, it, expect } from 'vitest';
import { flowSpent, loginReturnOf } from './flow-spent.js';

const RETURN = '/oauth2/login?login_challenge=abc_DEF-123.x';

describe('flow-spent', () => {
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

  it('reads a flow return_to stored relative or absolute on the same origin only', () => {
    const origin = 'https://sso.othala.test';
    expect(loginReturnOf(RETURN, origin)).toBe(RETURN);
    expect(loginReturnOf(`${origin}${RETURN}`, origin)).toBe(RETURN);
    expect(loginReturnOf(`https://evil.test${RETURN}`, origin)).toBeUndefined();
    expect(loginReturnOf('//evil.test/oauth2/login?login_challenge=x', origin)).toBeUndefined();
    // Only the challenge rides on: anything else in the query is dropped.
    expect(loginReturnOf(`${RETURN}&next=/admin`, origin)).toBe(RETURN);
    expect(loginReturnOf('/oauth2/consent?consent_challenge=x', origin)).toBeUndefined();
    expect(loginReturnOf('/oauth2/login', origin)).toBeUndefined();
    // A long challenge with URL-encoded characters round-trips.
    const long = `/oauth2/login?${new URLSearchParams({ login_challenge: 'a+b/c='.repeat(800) }).toString()}`;
    expect(loginReturnOf(long, origin)).toBe(long);
    expect(loginReturnOf(`${origin}/`, origin)).toBeUndefined();
    expect(loginReturnOf(undefined, origin)).toBeUndefined();
  });
});

// Invariant: a stale aal2 session is redirected to step-up before any admin fetch.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { getSessionMock, getIdentityMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  getIdentityMock: vi.fn(),
}));

vi.mock('./kratos', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./kratos.js')>();
  return { ...actual, getSession: getSessionMock };
});

vi.mock('./admin-api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./admin-api.js')>();
  return { ...actual, getIdentity: getIdentityMock };
});

import { isSessionFresh, requireAdminSession } from './admin.js';
import type { Session } from './types.js';
import type { SessionAuthenticationMethod } from '@ory/client-fetch';
import { identity, session as buildSession, whoamiIdentity } from './test-builders.js';

const HOUR = 60 * 60 * 1000;

function withMethods(...methods: Array<{ aal?: unknown; completed_at?: unknown }>): Session {
  return buildSession('aal2', methods as SessionAuthenticationMethod[], { authenticated_at: undefined });
}

describe('isSessionFresh — aal2 authentication_methods, within/outside window', () => {
  it.each([
    ['within window', -1 * HOUR, 2, true],
    ['just inside the window', -1.9 * HOUR, 2, true],
    ['outside window', -3 * HOUR, 2, false],
  ])('%s', (_label, offsetMs, windowHours, expected) => {
    const session = withMethods({ aal: 'aal2', completed_at: new Date(Date.now() + offsetMs) });
    expect(isSessionFresh(session, windowHours)).toBe(expected);
  });
});

describe('isSessionFresh — multiple aal2 entries: most-recent wins', () => {
  it('stale entry present, but a fresh entry decides true', () => {
    const session = withMethods(
      { aal: 'aal2', completed_at: new Date(Date.now() - 10 * HOUR) },
      { aal: 'aal2', completed_at: new Date(Date.now() - 0.5 * HOUR) },
    );
    expect(isSessionFresh(session, 1)).toBe(true);
  });

  it('array order does not matter — most-recent by value still wins', () => {
    const session = withMethods(
      { aal: 'aal2', completed_at: new Date(Date.now() - 0.5 * HOUR) },
      { aal: 'aal2', completed_at: new Date(Date.now() - 10 * HOUR) },
    );
    expect(isSessionFresh(session, 1)).toBe(true);
  });
});

describe('isSessionFresh — fallback to authenticated_at when no aal2 entries', () => {
  it('within window (no authentication_methods)', () => {
    const session = buildSession('aal1', [], { authentication_methods: undefined, authenticated_at: new Date(Date.now() - HOUR) });
    expect(isSessionFresh(session, 2)).toBe(true);
  });

  it('outside window (no authentication_methods)', () => {
    const session = buildSession('aal1', [], { authentication_methods: undefined, authenticated_at: new Date(Date.now() - 3 * HOUR) });
    expect(isSessionFresh(session, 2)).toBe(false);
  });

  it('authentication_methods present but no aal2 entries falls back too', () => {
    const session = withMethods({ aal: 'aal1', completed_at: new Date() });
    (session as unknown as Record<string, unknown>)['authenticated_at'] = new Date(Date.now() - 10 * HOUR);
    expect(isSessionFresh(session, 1)).toBe(false);
  });
});

describe('isSessionFresh — both sources unreadable → fail-closed false', () => {
  it('no authentication_methods, no authenticated_at', () => {
    expect(isSessionFresh(buildSession('aal1', [], { authentication_methods: undefined, authenticated_at: undefined }), 24)).toBe(false);
  });

  it('authenticated_at present but unparseable', () => {
    const session = { id: 's', authenticated_at: 'not-a-date' } as unknown as Session;
    expect(isSessionFresh(session, 24)).toBe(false);
  });
});

describe('isSessionFresh — malformed entries are skipped, not fatal', () => {
  it('skips non-object entries and finds the valid one', () => {
    const session = withMethods(
      null as unknown as { aal?: unknown },
      { aal: 'aal2', completed_at: new Date(Date.now() - HOUR) },
    );
    expect(isSessionFresh(session, 2)).toBe(true);
  });

  it('skips an entry with an unparseable completed_at, falls back to authenticated_at', () => {
    const session = withMethods({ aal: 'aal2', completed_at: 'garbage' });
    (session as unknown as Record<string, unknown>)['authenticated_at'] = new Date(Date.now() - HOUR);
    expect(isSessionFresh(session, 2)).toBe(true);
  });
});

function fakeAstro(pathname = '/admin', search = '') {
  return {
    request: { headers: { get: (name: string) => (name === 'cookie' ? 'ory_session=x' : null) } },
    url: new URL(`http://localhost${pathname}${search}`),
    redirect: vi.fn((location: string) => ({ location })),
    response: { headers: { set: vi.fn() } },
  };
}

beforeEach(() => {
  getSessionMock.mockReset();
  getIdentityMock.mockReset();
});

describe('requireAdminSession — aal2-but-stale redirects before the admin-marker fetch', () => {
  it('redirects to the aal2+refresh step-up and never calls getIdentity', async () => {
    const stale = new Date(Date.now() - 100 * HOUR); // far outside any sane window
    getSessionMock.mockResolvedValue(
      buildSession(
        'aal2',
        [
          { method: 'password', aal: 'aal1', completed_at: stale },
          { method: 'totp', aal: 'aal2', completed_at: stale },
        ],
        { identity: whoamiIdentity(identity({ id: 'user-1' })), authenticated_at: stale },
      ),
    );

    const astro = fakeAstro('/admin/users', '?q=a%26b');
    const result = await requireAdminSession(astro);

    expect(getIdentityMock).not.toHaveBeenCalled();
    expect(astro.redirect).toHaveBeenCalledTimes(1);
    const [target] = astro.redirect.mock.calls[0] as [string];
    const parsed = new URL(target, 'http://localhost');
    expect(parsed.pathname).toBe('/self-service/login/browser');
    expect(parsed.searchParams.get('aal')).toBe('aal2');
    expect(parsed.searchParams.get('refresh')).toBe('true');
    expect(parsed.searchParams.get('return_to')).toBe('/admin/users?q=a%26b');
    expect(result).toEqual({ location: target });
  });
});

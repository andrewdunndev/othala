/**
 * admin.test.ts — isSessionFresh + requireAdminSession freshness wiring.
 *
 * Coverage:
 *   isSessionFresh:
 *   - aal2 authentication_methods entry within/outside the window
 *   - multiple aal2 entries: most-recent completed_at wins
 *   - no authentication_methods: falls back to authenticated_at,
 *     within/outside the window
 *   - both sources unreadable → false (fail-closed)
 *   - malformed entries (non-object, wrong aal, bad completed_at) skipped
 *   requireAdminSession:
 *   - aal2-but-stale session redirects to the aal2+refresh step-up BEFORE
 *     the admin-marker fetch (order asserted via a not-called mock)
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// vi.mock is hoisted above imports; referenced mocks must be too.
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

const HOUR = 60 * 60 * 1000;

function withMethods(...methods: Array<{ aal?: unknown; completed_at?: unknown }>): Session {
  return { id: 's', authentication_methods: methods } as unknown as Session;
}

// ── isSessionFresh ───────────────────────────────────────────────────────────

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
    const session = { id: 's', authenticated_at: new Date(Date.now() - HOUR) } as unknown as Session;
    expect(isSessionFresh(session, 2)).toBe(true);
  });

  it('outside window (no authentication_methods)', () => {
    const session = { id: 's', authenticated_at: new Date(Date.now() - 3 * HOUR) } as unknown as Session;
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
    expect(isSessionFresh({ id: 's' } as Session, 24)).toBe(false);
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

// ── requireAdminSession — freshness gate ordering ───────────────────────────

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
    getSessionMock.mockResolvedValue({
      id: 'sess-1',
      active: true,
      identity: { id: 'user-1' },
      authenticator_assurance_level: 'aal2',
      authenticated_at: new Date(Date.now() - 100 * HOUR), // far outside any sane window
    } as unknown as Session);

    const astro = fakeAstro('/admin', '');
    const result = await requireAdminSession(astro);

    expect(getIdentityMock).not.toHaveBeenCalled();
    expect(astro.redirect).toHaveBeenCalledTimes(1);
    const [target] = astro.redirect.mock.calls[0] as [string];
    const parsed = new URL(target, 'http://localhost');
    expect(parsed.pathname).toBe('/self-service/login/browser');
    expect(parsed.searchParams.get('aal')).toBe('aal2');
    expect(parsed.searchParams.get('refresh')).toBe('true');
    expect(parsed.searchParams.has('return_to')).toBe(true);
    expect(result).toEqual({ location: target });
  });
});

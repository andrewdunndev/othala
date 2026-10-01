// Admin SSR guard + Hydra read-only wrapper. requireAdminSession enforces
// session + AAL2 + freshness + admin marker at the SSR layer, the
// identity-level checks the upstream proxy cannot make.

import { getSession, browserFlows } from './kratos';
import { decideAccess } from './gate';
import { revokeSubject, type RevokeResult } from './revoke';
import { ADMIN_FRESHNESS_HOURS } from './constants';
import type { Session } from './types';
import { getIdentity } from './admin-api';

/**
 * Pure freshness computation behind requireAdminSession. True when the newest
 * aal2 completed_at (falling back to authenticated_at) is within the window;
 * false when stale or when both timestamps are unreadable (fail closed).
 */
export function isSessionFresh(session: Session, windowHours: number): boolean {
  // Primary source: the most recent completed_at among aal2 authentication_methods.
  let authAt: Date | null = null;

  try {
    const raw = session as unknown as Record<string, unknown>;
    const methods = raw['authentication_methods'];
    if (Array.isArray(methods)) {
      for (const m of methods) {
        if (!m || typeof m !== 'object') continue;
        const entry = m as Record<string, unknown>;
        if (entry['aal'] !== 'aal2') continue;
        const completedAt = entry['completed_at'];
        let candidate: Date | null = null;
        if (completedAt instanceof Date && Number.isFinite(completedAt.getTime())) {
          candidate = completedAt;
        } else if (typeof completedAt === 'string') {
          const parsed = new Date(completedAt);
          if (Number.isFinite(parsed.getTime())) candidate = parsed;
        }
        // Keep the most recent parseable completed_at.
        if (candidate !== null && (authAt === null || candidate > authAt)) {
          authAt = candidate;
        }
      }
    }
  } catch {
    // Malformed authentication_methods: fall back below.
  }

  // Fallback: the session's own authenticated_at.
  if (authAt === null) {
    try {
      const rawAuthAt = (session as unknown as Record<string, unknown>)['authenticated_at'];
      if (rawAuthAt instanceof Date && Number.isFinite(rawAuthAt.getTime())) {
        authAt = rawAuthAt;
      } else if (typeof rawAuthAt === 'string') {
        const parsed = new Date(rawAuthAt);
        if (Number.isFinite(parsed.getTime())) authAt = parsed;
      }
    } catch {
      // Malformed authenticated_at — fall through.
    }
  }

  if (authAt === null) {
    return false;
  }

  const ageMs = Date.now() - authAt.getTime();
  const windowMs = windowHours * 60 * 60 * 1000;
  return ageMs <= windowMs;
}

/**
 * SSR guard for /admin/* routes, in order: (a) active session, else login
 * redirect; (b) AAL2, else step-up redirect; (c) freshness, same step-up;
 * (d) metadata_admin.admin === true read from the admin API.
 *
 *   const guard = await requireAdminSession(Astro);
 *   if (guard instanceof Response) return guard;
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireAdminSession(astro: any): Promise<Session | Response> {
  const cookie = astro.request.headers.get('cookie') ?? undefined;

  // (a) Active session check.
  let session: Session | null;
  try {
    session = await getSession(cookie);
  } catch {
    return astro.redirect('/auth/error?reason=auth-unreachable');
  }

  if (!session?.active || !session.identity?.id) {
    const returnTo = encodeURIComponent(astro.url.pathname + astro.url.search);
    return astro.redirect(`/auth/login?return_to=${returnTo}`);
  }

  // (b, c) AAL2 within the freshness window (gate.ts decideAccess), settled before the admin-marker fetch.
  const facts = { ...session, fresh: isSessionFresh(session, ADMIN_FRESHNESS_HOURS) };
  if ('stepUp' in decideAccess(null, 'admin', facts)) {
    const returnTo = encodeURIComponent(astro.url.pathname + astro.url.search);
    return astro.redirect(browserFlows.login({ aal: 'aal2', refresh: true, returnTo }));
  }

  // (d) Admin marker, read fresh from the admin API (whoami omits metadata_admin); fail closed.
  let adminIdentity;
  try {
    adminIdentity = await getIdentity(session.identity.id);
  } catch {
    return astro.redirect('/auth/error?reason=auth-unreachable');
  }

  if (!('allow' in decideAccess(adminIdentity, 'admin', facts))) {
    return astro.redirect('/auth/error?reason=not-admin');
  }

  // Keep admin/identity data out of intermediate caches.
  astro.response.headers.set('Cache-Control', 'no-store, max-age=0');

  return session;
}

/**
 * Force re-login for an identity (admin "revoke user"): revokeSubject cuts
 * Kratos sessions and Hydra login + consent, without deactivating the identity.
 * Throws a prescriptive RevokeError on a hard-cut failure.
 */
export type RevokeUserResult = RevokeResult;

export async function revokeUserSessions(subject: string): Promise<RevokeUserResult> {
  return revokeSubject(subject);
}

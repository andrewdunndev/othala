// Admin SSR guard. requireAdminSession enforces
// session + AAL2 + freshness + admin marker at the SSR layer, the
// identity-level checks the upstream proxy cannot make.

import { getSession, browserFlows } from './kratos';
import { decideAccess } from './gate';
import { ADMIN_FRESHNESS_HOURS } from './constants';
import type { Session } from './types';
import { atMs, type AuthMethod } from './profile-gate';
import { getIdentity } from './admin-api';

/**
 * Pure freshness computation behind requireAdminSession. True when the newest
 * aal2 completed_at (falling back to authenticated_at) is within the window;
 * false when stale or when both timestamps are unreadable (fail closed).
 */
export function isSessionFresh(session: Session, windowHours: number): boolean {
  const raw = session as unknown as { authentication_methods?: unknown; authenticated_at?: unknown } | null;
  const methods = (Array.isArray(raw?.authentication_methods) ? raw.authentication_methods : []) as (AuthMethod | null)[];
  const aal2 = methods.filter((m) => m?.aal === 'aal2').map((m) => atMs(m?.completed_at)).filter((t) => !Number.isNaN(t));
  const at = aal2.length > 0 ? Math.max(...aal2) : atMs(raw?.authenticated_at);
  if (Number.isNaN(at)) return false;
  return Date.now() - at <= windowHours * 60 * 60 * 1000;
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

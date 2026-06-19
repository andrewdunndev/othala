// Admin SSR guard + Hydra read-only wrapper.
//
// Kratos admin API wrappers live in `./admin-api.ts`; this file re-exports
// them so existing call sites that import from `./admin` keep working.
//
// AAL2 enforcement happens at the SSR layer because Kratos AAL is
// per-flow / global, not per-route. Caddy already gates "session present"
// upstream of this guard.

import { browserFlows, getSession } from './kratos';
import { isAdminId } from './admin-auth';
import { revokeSubject, type RevokeResult } from './revoke';
import { publicUrl, adminFreshnessHours } from './config';
import type { Session } from './types';

/**
 * Pure freshness computation extracted from requireAdminSession for testability.
 *
 * Returns:
 *   true  — session authenticated within the window
 *   false — session is stale (confirmed out of window)
 *   null  — indeterminate / fail-open (no parseable timestamp found)
 *
 * Primary source: authentication_methods entries with aal === 'aal2', using
 * the most-recent completed_at timestamp among those entries. Fallback to
 * session.authenticated_at if the array is absent or yields no parseable entry.
 * Only if BOTH sources are unreadable does the function return null (fail-open).
 *
 * TODO: validate the exact field shapes against a live Kratos session;
 * authentication_methods.completed_at shape and authenticated_at update
 * semantics need live-gate confirmation before tightening.
 */
export function isSessionFresh(session: Session, windowHours: number): boolean | null {
  // Primary source: authentication_methods[].completed_at for aal2 entries.
  // Kratos populates this array on every step-up; the most-recent aal2 entry
  // is the canonical "when did the user last satisfy AAL2".
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
        } else if (typeof completedAt === 'string' && completedAt.trim() !== '') {
          const parsed = new Date(completedAt);
          if (Number.isFinite(parsed.getTime())) candidate = parsed;
        }
        // Keep the most-recent parseable completed_at among all aal2 entries.
        if (candidate !== null && (authAt === null || candidate > authAt)) {
          authAt = candidate;
        }
      }
    }
  } catch {
    // Malformed authentication_methods — skip, fall back below.
  }

  // Fallback: authenticated_at on the session itself (SDK may deserialise as Date).
  if (authAt === null) {
    try {
      const rawAuthAt = (session as unknown as Record<string, unknown>)['authenticated_at'];
      if (rawAuthAt instanceof Date && Number.isFinite(rawAuthAt.getTime())) {
        authAt = rawAuthAt;
      } else if (typeof rawAuthAt === 'string' && rawAuthAt.trim() !== '') {
        const parsed = new Date(rawAuthAt);
        if (Number.isFinite(parsed.getTime())) authAt = parsed;
      }
    } catch {
      // Malformed authenticated_at — fall through to null.
    }
  }

  if (authAt === null) {
    // Both sources unreadable — fail open (see FAIL-OPEN INVARIANT in caller).
    return null;
  }

  const ageMs = Date.now() - authAt.getTime();
  const windowMs = windowHours * 60 * 60 * 1000;
  return ageMs <= windowMs;
}

export {
  listIdentities,
  getIdentity,
  createIdentity,
  updateIdentity,
  deleteIdentity,
  deactivateIdentity,
  reactivateIdentity,
  getRecoveryLink,
} from './admin-api';
export type {
  CreateIdentityInput,
  UpdateIdentityInput,
  IdentityTraits,
  MetadataAdmin,
  RecoveryLink,
} from './admin-api';

/**
 * SSR guard for /admin/* routes.
 *
 *   const guard = await requireAdminSession(Astro);
 *   if (guard instanceof Response) return guard;
 *   const session = guard;
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireAdminSession(astro: any): Promise<Session | Response> {
  const cookie = astro.request.headers.get('cookie') ?? undefined;
  let session: Session | null;
  try {
    session = await getSession(cookie);
  } catch {
    return astro.redirect('/auth/error?reason=auth-unreachable');
  }

  if (!session?.active || !session.identity) {
    const returnTo = encodeURIComponent(astro.url.pathname + astro.url.search);
    return astro.redirect(`/auth/login?return_to=${returnTo}`);
  }

  // CVP-P1: admin authority is the OTHALA_ADMIN_IDS allowlist keyed on the
  // IMMUTABLE identity `id` (a Kratos UUID), NOT the user-editable email
  // trait. `session.identity.id` is always present in a valid whoami response
  // and is never writable via the self-service profile flow, so it cannot be
  // escalated by editing a trait. The `admin` group is display-only and gates
  // nothing here.
  if (!isAdminId(session.identity.id)) {
    return astro.redirect('/auth/error?reason=not-admin');
  }

  if (session.authenticator_assurance_level !== 'aal2') {
    // return_to must be the PUBLIC origin (publicUrl), not astro.url — behind the
    // Caddy edge astro.url is the internal bind (localhost:PORT), so astro.url.href
    // would send the user to an unroutable host after step-up. Path+search are safe.
    const returnTo = `${publicUrl}${astro.url.pathname}${astro.url.search}`;
    return astro.redirect(browserFlows.login({ refresh: true, aal: 'aal2', returnTo }));
  }

  // AAL2 FRESHNESS CHECK — MEDIUM-C / hardening §7
  //
  // Having AAL2 "present" is not enough when the session lifetime is 90 days.
  // A stolen admin browser with an existing AAL2 session would pass the level
  // check for the full session lifetime. We additionally require that the admin
  // authenticated within the last OTHALA_ADMIN_FRESHNESS_HOURS hours (default 8).
  //
  // Primary source: authentication_methods[].completed_at for aal2 entries —
  // the most-recent aal2 entry is the canonical "when did the admin last satisfy
  // AAL2". Fallback to session.authenticated_at if the array is absent or yields
  // no parseable entry. Both the field shapes (Date vs ISO string) and
  // authenticated_at update semantics (refresh=true vs any AAL2 completion) still
  // warrant live-Kratos confirmation before tightening — see isSessionFresh.
  //
  // FAIL-OPEN INVARIANT: if all timestamp sources are absent, unparseable, or any
  // error occurs, we ALLOW access rather than redirect. A redirect on bad data
  // would create an unbreakable redirect loop for the admin. We only redirect when
  // we can POSITIVELY confirm the session is stale (isSessionFresh returns false).
  if (adminFreshnessHours > 0) {
    try {
      const fresh = isSessionFresh(session, adminFreshnessHours);
      if (fresh === false) {
        // Confirmed stale — force step-up re-authentication.
        const returnTo = `${publicUrl}${astro.url.pathname}${astro.url.search}`;
        return astro.redirect(browserFlows.login({ refresh: true, aal: 'aal2', returnTo }));
      }
      // fresh === true → within window; fresh === null → indeterminate, fail open.
    } catch {
      // Any unexpected error in the freshness computation: fail open (see above).
    }
  }

  // Prevent admin/identity data from being stored in any intermediate cache.
  // Done here (not in middleware) so it's tightly coupled to the admin guard.
  astro.response.headers.set('Cache-Control', 'no-store, max-age=0');

  return session;
}

/**
 * Force re-login for an identity (admin "revoke user" trigger).
 *
 * The portal -> consent-service HTTP hop (POST /admin/revoke-user, guarded
 * by the overloaded CONSENT_ADMIN_BEARER) is GONE. The fan-out is now
 * in-process: revokeSubject runs steps 2-5 (Kratos sessions, Hydra login +
 * consent revoke, best-effort LDAP bind-cache flush). deactivate is NOT set
 * here — admin force-logout cuts sessions without marking the identity
 * inactive.
 *
 * Throws a prescriptive RevokeError on a hard-cut (step 2-4) failure; the
 * caller surfaces dependency + next-action without leaking raw upstream
 * errors. Best-effort step 5 failures land in result.bestEffortFailures.
 */
export type RevokeUserResult = RevokeResult;

export async function revokeUserSessions(subject: string): Promise<RevokeUserResult> {
  return revokeSubject(subject);
}

// Admin SSR guard + Hydra read-only wrapper.
//
// Kratos admin API wrappers live in `./admin-api.ts`; this file re-exports
// them so existing call sites that import from `./admin` keep working.
//
// AAL2 enforcement happens at the SSR layer (ADR 08): Kratos AAL is
// per-flow / global, not per-route. requireAdminSession enforces the SP-3
// trinity: active session + AAL2 + admin marker (metadata_admin.admin===true
// from the admin API). Caddy already gates "session present" upstream; this
// guard adds the identity-level checks Caddy cannot make.

import { getSession, browserFlows } from './kratos';
import { isAdminMarker } from './admin-auth';
import { revokeSubject, type RevokeResult } from './revoke';
import type { Session } from './types';
import {
  getIdentity,
  listIdentities,
  createIdentity,
  updateIdentity,
  deleteIdentity,
  deactivateIdentity,
  reactivateIdentity,
  getRecoveryLink,
  patchAdminMarker,
} from './admin-api';
import type {
  CreateIdentityInput,
  UpdateIdentityInput,
  IdentityTraits,
  MetadataAdmin,
  RecoveryLink,
} from './admin-api';

/**
 * Pure freshness computation extracted from requireAdminSession for testability.
 *
 * Returns:
 *   true  — session authenticated within the window
 *   false — session is stale (confirmed out of window) OR timestamps
 *           unreadable (fail-CLOSED)
 *
 * Primary source: authentication_methods entries with aal === 'aal2', using
 * the most-recent completed_at timestamp among those entries. Fallback to
 * session.authenticated_at if the array is absent or yields no parseable entry.
 * If BOTH sources are unreadable the function returns false (fail-closed).
 *
 * Decision: this function is NOT wired into the requireAdminSession gate.
 * The explicit `session.authenticator_assurance_level === 'aal2'` check (with a
 * step-up redirect on AAL1) is the correct enforcement mechanism per ADR 08.
 * isSessionFresh is retained for future use (e.g. a "sudo timeout" freshness
 * window on destructive actions) and is unit-tested to prove correctness before
 * that use-case is wired in. When it is wired in, it should augment, not replace,
 * the explicit AAL check.
 *
 * Note: authentication_methods.completed_at shape and authenticated_at update
 * semantics should be validated against a live Kratos session before wiring
 * isSessionFresh into any gate.
 */
export function isSessionFresh(session: Session, windowHours: number): boolean {
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
      // Malformed authenticated_at — fall through.
    }
  }

  if (authAt === null) {
    // Both sources unreadable — fail closed (deny).
    return false;
  }

  const ageMs = Date.now() - authAt.getTime();
  const windowMs = windowHours * 60 * 60 * 1000;
  return ageMs <= windowMs;
}

// Re-export admin-API symbols for call sites that import from './admin'.
export {
  listIdentities,
  getIdentity,
  createIdentity,
  updateIdentity,
  deleteIdentity,
  deactivateIdentity,
  reactivateIdentity,
  getRecoveryLink,
  patchAdminMarker,
};
export type { CreateIdentityInput, UpdateIdentityInput, IdentityTraits, MetadataAdmin, RecoveryLink };

/**
 * SSR guard for /admin/* routes. Enforces the SP-3 trinity (ADR 08):
 *
 *   (a) Active Kratos session with a resolved identity — else redirect to login.
 *   (b) AAL2 server-side — session.authenticator_assurance_level must equal
 *       'aal2'. An AAL1 session triggers a step-up redirect to Kratos with
 *       ?aal=aal2&refresh=true. A 200 from whoami does NOT imply AAL2 (the
 *       LDAP bridge uses aal1 sessions on the same Kratos instance).
 *   (c) Admin marker — identity.metadata_admin.admin === true (boolean strict),
 *       read fresh from the Kratos admin API. The whoami response does NOT carry
 *       metadata_admin (Kratos v26.2.0 excludes it); the admin-API fetch is
 *       non-optional.
 *
 *   const guard = await requireAdminSession(Astro);
 *   if (guard instanceof Response) return guard;
 *   const session = guard;
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

  // (b) AAL2 enforcement — server-side, not inferred from a 200.
  // session.authenticator_assurance_level is the canonical AAL string from
  // whoami; it must be exactly 'aal2'. On 'aal1' we redirect to the Kratos
  // step-up flow (?aal=aal2&refresh=true). Any other value (missing, unknown)
  // is treated as fail-closed: deny with a redirect to the step-up flow.
  const aal = (session as unknown as Record<string, unknown>)['authenticator_assurance_level'];
  if (aal !== 'aal2') {
    // Step-up: Kratos will re-authenticate the user at AAL2 and return here.
    const returnTo = encodeURIComponent(astro.url.pathname + astro.url.search);
    return astro.redirect(browserFlows.login({ aal: 'aal2', refresh: true, returnTo }));
  }

  // (c) Admin marker — fetch identity fresh from the admin API (metadata_admin
  // is NOT present in the whoami response). Fail-closed on lookup error.
  let adminIdentity;
  try {
    adminIdentity = await getIdentity(session.identity.id);
  } catch {
    return astro.redirect('/auth/error?reason=auth-unreachable');
  }

  if (!isAdminMarker(adminIdentity)) {
    return astro.redirect('/auth/error?reason=not-admin');
  }

  // Prevent admin/identity data from being stored in any intermediate cache.
  // Done here (not in middleware) so it's tightly coupled to the admin guard.
  astro.response.headers.set('Cache-Control', 'no-store, max-age=0');

  return session;
}

/**
 * Force re-login for an identity (admin "revoke user" trigger).
 *
 * The fan-out is in-process: revokeSubject runs steps 2-5 (Kratos sessions,
 * Hydra login + consent revoke, best-effort LDAP bind-cache flush). deactivate
 * is NOT set here — admin force-logout cuts sessions without marking the
 * identity inactive.
 *
 * Throws a prescriptive RevokeError on a hard-cut (step 2-4) failure; the
 * caller surfaces dependency + next-action without leaking raw upstream
 * errors. Best-effort step 5 failures land in result.bestEffortFailures.
 */
export type RevokeUserResult = RevokeResult;

export async function revokeUserSessions(subject: string): Promise<RevokeUserResult> {
  return revokeSubject(subject);
}

// Admin SSR guard + Hydra read-only wrapper.
//
// Kratos admin API wrappers live in `./admin-api.ts`; this file re-exports
// them so existing call sites that import from `./admin` keep working.
//
// AAL2 enforcement happens at the SSR layer because Kratos AAL is
// per-flow / global, not per-route. Caddy already gates "session present"
// upstream of this guard.

import { getSession } from './kratos';
import { isAdminId } from './admin-auth';
import { revokeSubject, type RevokeResult } from './revoke';
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

  // ADMIN ELEVATION — Kratos AAL2 step-up REMOVED (2026-06-20).
  //
  // Admin elevation is enforced at the EDGE by Caddy basic_auth on /admin/*
  // (per-admin bcrypt creds), NOT by a Kratos AAL2 step-up. The AAL2 flow was
  // half-implemented (login.astro never rendered the second-factor methods, so
  // the step-up page was blank → admin un-enterable via the UI, forcing
  // terminal/admin-API use to manage the instance) AND redundant with that
  // basic_auth gate. We meet the security analysis's intent (multi-factor for
  // privileged access) with an equivalent-or-stronger, reliable control:
  //   - possession:    a hardware passkey session (the active+identity check above)
  //   - knowledge:     the /admin/* basic_auth password (edge, per-admin)
  //   - authorization: the OTHALA_ADMIN_IDS allowlist (the isAdminId check above)
  // Consciously traded away: the AAL2 freshness / "sudo timeout" (basic_auth
  // caches for the browser session). Acceptable at family scale; if ever needed,
  // require a fresh re-auth on destructive actions only. isSessionFresh() is
  // retained (exported, unit-tested) for that future use. See the dated
  // security-review doc, §AAL2 deviation.

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

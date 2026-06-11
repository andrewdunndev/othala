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
  // `session.authenticated_at` is a Date (Ory SDK v1+) updated by Kratos on every
  // `refresh=true` re-authentication. We compare it to now.
  //
  // FAIL-OPEN INVARIANT: if authenticated_at is absent, unparseable, or any error
  // occurs computing the age, we ALLOW access rather than redirect. A redirect here
  // on bad data would create an unbreakable redirect loop for the admin. We only
  // redirect when we can POSITIVELY confirm the session is stale.
  //
  // TODO: validate the exact freshness behaviour against a live Kratos session.
  // The field shape (Date vs ISO string) and update semantics (refresh=true vs any
  // AAL2 completion) need live gate confirmation before tightening.
  if (adminFreshnessHours > 0) {
    try {
      const rawAuthAt = (session as unknown as Record<string, unknown>).authenticated_at;
      // The SDK deserialises authenticated_at as Date; accept either Date or ISO string.
      let authAt: Date | null = null;
      if (rawAuthAt instanceof Date && Number.isFinite(rawAuthAt.getTime())) {
        authAt = rawAuthAt;
      } else if (typeof rawAuthAt === 'string' && rawAuthAt.trim() !== '') {
        const parsed = new Date(rawAuthAt);
        if (Number.isFinite(parsed.getTime())) authAt = parsed;
      }
      if (authAt !== null) {
        const ageMs = Date.now() - authAt.getTime();
        const windowMs = adminFreshnessHours * 60 * 60 * 1000;
        if (ageMs > windowMs) {
          const returnTo = `${publicUrl}${astro.url.pathname}${astro.url.search}`;
          return astro.redirect(browserFlows.login({ refresh: true, aal: 'aal2', returnTo }));
        }
      }
      // authAt === null → authenticated_at absent or unparseable: fail open (see above).
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

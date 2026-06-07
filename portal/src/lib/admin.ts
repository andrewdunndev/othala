// Admin SSR guard + Hydra read-only wrapper.
//
// Kratos admin API wrappers live in `./admin-api.ts`; this file re-exports
// them so existing call sites that import from `./admin` keep working.
//
// AAL2 enforcement happens at the SSR layer because Kratos AAL is
// per-flow / global, not per-route. Caddy already gates "session present"
// upstream of this guard.

import { browserFlows, getSession } from './kratos';
import { getIdentity } from './admin-api';
import { isAdminSubject } from './admin-auth';
import { revokeSubject, type RevokeResult } from './revoke';
import { publicUrl } from './config';
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

  // B2: admin authority is the OTHALA_ADMIN_SUBJECTS allowlist, NOT the
  // `admin` metadata_admin group. Read the admin's email from the
  // session traits (whoami strips metadata_admin but returns traits) and
  // consult the allowlist. The `admin` group is display-only now and
  // gates nothing here. Fetch the full identity only to resolve the
  // canonical email when the session traits omit it; failures downgrade
  // to "auth-unreachable" rather than a silent non-admin.
  let adminEmail = session.identity.traits?.email as string | undefined;
  if (!adminEmail) {
    try {
      const fullIdentity = await getIdentity(session.identity.id);
      adminEmail = fullIdentity.traits?.email as string | undefined;
    } catch {
      return astro.redirect('/auth/error?reason=auth-unreachable');
    }
  }
  if (!isAdminSubject(adminEmail)) {
    return astro.redirect('/auth/error?reason=not-admin');
  }

  if (session.authenticator_assurance_level !== 'aal2') {
    // return_to must be the PUBLIC origin (publicUrl), not astro.url — behind the
    // Caddy edge astro.url is the internal bind (localhost:PORT), so astro.url.href
    // would send the user to an unroutable host after step-up. Path+search are safe.
    const returnTo = `${publicUrl}${astro.url.pathname}${astro.url.search}`;
    return astro.redirect(browserFlows.login({ refresh: true, aal: 'aal2', returnTo }));
  }

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

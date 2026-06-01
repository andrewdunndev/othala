// Admin SSR guard + Hydra read-only wrapper.
//
// Kratos admin API wrappers live in `./admin-api.ts`; this file re-exports
// them so existing call sites that import from `./admin` keep working.
//
// AAL2 enforcement happens at the SSR layer because Kratos AAL is
// per-flow / global, not per-route. Caddy already gates "session present"
// upstream of this guard.

import { Configuration, OAuth2Api, type OAuth2Client } from '@ory/client-fetch';
import { getSession } from './kratos';
import { getIdentity } from './admin-api';
import { isAdminSubject } from './admin-auth';
import { revokeSubject, type RevokeResult } from './revoke';
import type { Session } from './types';

export {
  listIdentities,
  getIdentity,
  createIdentity,
  updateIdentity,
  deleteIdentity,
  deactivateIdentity,
  getRecoveryLink,
} from './admin-api';
export type {
  CreateIdentityInput,
  UpdateIdentityInput,
  IdentityTraits,
  MetadataAdmin,
  RecoveryLink,
} from './admin-api';

/** Backwards-compat alias used by older skeleton pages. */
export { getRecoveryLink as generateRecoveryURL } from './admin-api';

function hydraAdminBase(): string {
  // Portal and Hydra both run on carmine; the admin port is reachable
  // directly at the in-pod hostname. Same posture as Kratos admin: no
  // auth by default, network-isolation gates it.
  return process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445';
}

// Behaviour-preserving auth: configure the SDK bearer only when
// HYDRA_ADMIN_TOKEN is set, matching the legacy raw-fetch code that
// omitted Authorization when the token env was empty.
function oauth2Api(): OAuth2Api {
  const token = process.env.HYDRA_ADMIN_TOKEN ?? '';
  return new OAuth2Api(
    new Configuration({
      basePath: hydraAdminBase(),
      ...(token ? { accessToken: token } : {}),
    }),
  );
}

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

  // B2: admin authority is the AUTH_ADMIN_SUBJECTS allowlist, NOT the
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
    const returnTo = encodeURIComponent(
      `https://auth.dunn.dev${astro.url.pathname}${astro.url.search}`,
    );
    const kratosUrl =
      `https://auth.dunn.dev/self-service/login/browser` +
      `?refresh=true&aal=aal2&return_to=${returnTo}`;
    return astro.redirect(kratosUrl);
  }

  return session;
}

/** Hydra admin (read-only): used by the OAuth2 viewer to confirm clients exist. */
export async function listOAuth2Clients(): Promise<OAuth2Client[]> {
  return oauth2Api().listOAuth2Clients();
}

/**
 * Force re-login for an identity (admin "revoke user" trigger).
 *
 * The portal -> consent-service HTTP hop (POST /admin/revoke-user, guarded
 * by the overloaded CONSENT_ADMIN_BEARER) is GONE. The fan-out is now
 * in-process: revokeSubject runs steps 2-6 (Kratos sessions, Hydra login +
 * consent revoke, identity-cache invalidate, best-effort LDAP bind-cache
 * flush). deactivate is NOT set here — admin force-logout cuts sessions
 * without marking the identity inactive.
 *
 * Throws a prescriptive RevokeError on a hard-cut (step 2-4) failure; the
 * caller surfaces dependency + next-action without leaking raw upstream
 * errors. Best-effort step 5-6 failures land in result.bestEffortFailures.
 */
export type RevokeUserResult = RevokeResult;

export async function revokeUserSessions(subject: string): Promise<RevokeUserResult> {
  return revokeSubject(subject);
}

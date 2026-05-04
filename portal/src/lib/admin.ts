// Admin SSR guard + Hydra read-only wrapper.
//
// Kratos admin API wrappers live in `./admin-api.ts`; this file re-exports
// them so existing call sites that import from `./admin` keep working.
//
// AAL2 enforcement happens at the SSR layer because Kratos AAL is
// per-flow / global, not per-route. Caddy already gates "session present"
// upstream of this guard.

import { getSession } from './kratos';
import { getIdentity } from './admin-api';
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

function hydraAdminAuthHeaders(): HeadersInit {
  const headers: Record<string, string> = { Accept: 'application/json' };
  const token = process.env.HYDRA_ADMIN_TOKEN ?? '';
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
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

  // F1: Kratos /sessions/whoami strips metadata_admin (admin-only,
  // never returned to public surfaces). Fetch the identity via the
  // admin API to read the admin's group membership for the access
  // gate. Failures here downgrade to "auth-unreachable" rather than
  // silent fall-through, since a missing metadata_admin would cause
  // every admin to look like a non-admin.
  let adminGroups: string[] = [];
  try {
    const fullIdentity = await getIdentity(session.identity.id);
    adminGroups = fullIdentity.metadata_admin?.groups ?? [];
  } catch {
    return astro.redirect('/auth/error?reason=auth-unreachable');
  }
  if (!adminGroups.includes('admin')) {
    return astro.redirect('/auth/error?reason=not-admin');
  }

  if (session.authenticator_assurance_level !== 'aal2') {
    const returnTo = encodeURIComponent(
      `https://home.dunn.dev${astro.url.pathname}${astro.url.search}`,
    );
    const kratosUrl =
      `https://auth.dunn.dev/self-service/login/browser` +
      `?refresh=true&aal=aal2&return_to=${returnTo}`;
    return astro.redirect(kratosUrl);
  }

  return session;
}

/** Hydra admin (read-only): used by the OAuth2 viewer to confirm clients exist. */
export async function listOAuth2Clients(): Promise<unknown[]> {
  const res = await fetch(`${hydraAdminBase()}/admin/clients`, {
    headers: hydraAdminAuthHeaders(),
  });
  if (!res.ok) throw new Error(`listOAuth2Clients: ${res.status}`);
  return (await res.json()) as unknown[];
}

/**
 * Force re-login for an identity.
 *
 * Calls the consent service's POST /admin/revoke-user, which:
 *  1. Deletes every Kratos session for the identity.
 *  2. Invalidates the consent service's in-process identity cache.
 *  3. Posts a signed OIDC back-channel logout token to every RP that
 *     supports it (yamls with `oidc.backchannel_logout_uri`).
 *
 * Apps without back-channel logout (Tailscale, vLLM, BookLore, current
 * Jellyfin SSO plugin) keep their local session until it expires; the
 * result includes a `failures` array that the UI surfaces inline so
 * the operator knows where the gap is.
 *
 * Auth: shared bearer in CONSENT_ADMIN_BEARER. Same value lives on the
 * consent service's env. Caddy on auth.dunn.dev/admin/* layers an
 * additional bearer check (defense-in-depth).
 */
export interface RevokeUserResult {
  subject: string;
  kratos_sessions_revoked: number;
  backchannel_logout_sent: string[];
  failures: Array<{ client_id: string; endpoint: string; error: string }>;
  identity_cache_invalidated: boolean;
}

export async function revokeUserSessions(subject: string): Promise<RevokeUserResult> {
  const base = process.env.CONSENT_ADMIN_URL ?? 'https://auth.dunn.dev';
  const bearer = process.env.CONSENT_ADMIN_BEARER ?? '';
  if (!bearer) {
    throw new Error('CONSENT_ADMIN_BEARER is unset; admin revoke disabled');
  }
  const res = await fetch(`${base}/admin/revoke-user`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${bearer}`,
      Accept: 'application/json',
    },
    body: JSON.stringify({ subject }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`revoke-user: ${res.status} ${body}`);
  }
  return (await res.json()) as RevokeUserResult;
}

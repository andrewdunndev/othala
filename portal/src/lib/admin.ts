// Admin-side helpers: AAL2 enforcement, Kratos admin API wrapper,
// Hydra admin API wrapper.
//
// All callers are SSR Astro pages under /admin. The admin token
// for Kratos lives in a server-side env var; never exposed to the
// browser bundle.

import type { Session } from './kratos';
import { whoami } from './kratos';

const KRATOS_ADMIN = import.meta.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';
const HYDRA_ADMIN = import.meta.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445';
const KRATOS_ADMIN_TOKEN = import.meta.env.KRATOS_ADMIN_TOKEN;
const CONSENT_URL = import.meta.env.CONSENT_URL ?? 'https://auth.dunn.dev';

/**
 * Server-side guard for /admin/* routes.
 *
 * Returns the validated session if the user is admin AND aal2;
 * returns a Response (redirect) if not.
 *
 * Usage in admin page front-matter:
 *
 *   const guard = await requireAdminSession(Astro);
 *   if (guard instanceof Response) return guard;
 *   const session = guard;
 *
 * AAL2 enforcement happens HERE, not at Caddy. Per adversarial review,
 * Kratos AAL is per-flow, not per-route, so app-layer enforcement is
 * the documented Ory pattern.
 */
export async function requireAdminSession(astro: any): Promise<Session | Response> {
  const cookie = astro.request.headers.get('cookie') ?? undefined;
  let session: Session | null;
  try {
    session = await whoami(cookie);
  } catch (err) {
    return astro.redirect('/auth/error?reason=auth-unreachable');
  }

  if (!session?.active || !session.identity) {
    const returnTo = encodeURIComponent(astro.url.pathname + astro.url.search);
    return astro.redirect(`/auth/login?return_to=${returnTo}`);
  }

  // Identity must be in admin group
  const groups = session.identity.metadata_admin?.groups ?? [];
  if (!groups.includes('admin')) {
    return astro.redirect('/auth/error?reason=not-admin');
  }

  // AAL2 step-up: if session is below aal2, redirect to Kratos refresh
  // login with aal=aal2.
  if (session.authenticator_assurance_level !== 'aal2') {
    const returnTo = encodeURIComponent(`https://home.dunn.dev${astro.url.pathname}${astro.url.search}`);
    const kratosUrl = `https://auth.dunn.dev/self-service/login/browser?refresh=true&aal=aal2&return_to=${returnTo}`;
    return astro.redirect(kratosUrl);
  }

  return session;
}

// --- Kratos admin API wrappers ---

export async function listIdentities(): Promise<unknown[]> {
  const res = await fetch(`${KRATOS_ADMIN}/admin/identities?per_page=100`, {
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${KRATOS_ADMIN_TOKEN}`,
    },
  });
  if (!res.ok) throw new Error(`listIdentities: ${res.status}`);
  return await res.json() as unknown[];
}

export async function getIdentity(id: string): Promise<unknown> {
  const res = await fetch(`${KRATOS_ADMIN}/admin/identities/${id}?include_credential=password,webauthn,totp`, {
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${KRATOS_ADMIN_TOKEN}`,
    },
  });
  if (!res.ok) throw new Error(`getIdentity: ${res.status}`);
  return await res.json();
}

export async function createIdentity(traits: Record<string, unknown>, groups: string[]): Promise<unknown> {
  const body = {
    schema_id: 'family',
    traits,
    metadata_admin: { groups },
  };
  const res = await fetch(`${KRATOS_ADMIN}/admin/identities`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${KRATOS_ADMIN_TOKEN}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`createIdentity: ${res.status}`);
  return await res.json();
}

export async function generateRecoveryURL(identityId: string): Promise<{ recovery_link: string; expires_at: string }> {
  const res = await fetch(`${KRATOS_ADMIN}/admin/recovery/link`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${KRATOS_ADMIN_TOKEN}`,
    },
    body: JSON.stringify({ identity_id: identityId, expires_in: '1h' }),
  });
  if (!res.ok) throw new Error(`generateRecoveryURL: ${res.status}`);
  return await res.json() as { recovery_link: string; expires_at: string };
}

export async function deactivateIdentity(id: string): Promise<void> {
  // Kratos doesn't have a native "deactivate" — pattern is to set state=inactive.
  const res = await fetch(`${KRATOS_ADMIN}/admin/identities/${id}`, {
    method: 'PATCH',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json-patch+json',
      Authorization: `Bearer ${KRATOS_ADMIN_TOKEN}`,
    },
    body: JSON.stringify([{ op: 'replace', path: '/state', value: 'inactive' }]),
  });
  if (!res.ok) throw new Error(`deactivateIdentity: ${res.status}`);
  // Also revoke active sessions
  await fetch(`${KRATOS_ADMIN}/admin/identities/${id}/sessions`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${KRATOS_ADMIN_TOKEN}` },
  });
}

// --- Hydra admin API wrappers (read-only for the admin UI) ---
// All Hydra writes happen via the hydra/apply-clients.sh script, NOT
// through the admin UI. The UI shows current state read-only.

export async function listOAuth2Clients(): Promise<unknown[]> {
  const res = await fetch(`${HYDRA_ADMIN}/admin/clients`, {
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`listOAuth2Clients: ${res.status}`);
  return await res.json() as unknown[];
}

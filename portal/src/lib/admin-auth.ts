// Admin authority — metadata_admin marker gate (ADR 0008).
//
// ADR 0008 (accepted 2026-06-25): admin authority moves from an env-based
// UUID allowlist (OTHALA_ADMIN_IDS) to a tamper-proof marker in Kratos
// `metadata_admin.admin`. The marker is:
//   - writable ONLY via the Kratos admin API (never via self-service flows
//     or OIDC claim mapping, which land in traits only)
//   - absent from the public /sessions/whoami response (Kratos v26.2.0
//     excludes metadata_admin from whoami — ADR 0008 Consequences)
//   - read by callers via a fresh admin-API getIdentity call, never from
//     the session object returned by whoami
//
// Authority check: metadata_admin.admin === true (boolean strict equality).
// Fail-closed: absent key, wrong type (string "true", number 1, null, etc.),
// or any malformed identity object yields false.

import type { Identity } from './types';
import { getIdentity } from './admin-api';

/**
 * Authoritative admin marker check (ADR 0008 Tier 1).
 *
 * Returns true iff `identity.metadata_admin.admin === true` (boolean strict
 * equality). The caller MUST supply an identity fetched fresh from the Kratos
 * admin API — never the identity object embedded in a /sessions/whoami
 * response, which Kratos v26.2.0 strips of metadata_admin. Fail-closed on
 * null/undefined identity, missing key, or any non-boolean-true value.
 */
export function isAdminMarker(identity: Identity | null | undefined): boolean {
  if (!identity) return false;
  try {
    const meta = identity.metadata_admin as Record<string, unknown> | undefined;
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return false;
    return meta['admin'] === true;
  } catch {
    return false;
  }
}

/**
 * Cosmetic admin-chrome check for SSR pages (ADR 0008).
 *
 * Fetches the full identity from the Kratos admin API (which includes
 * metadata_admin, stripped from /sessions/whoami by Kratos v26.2.0) and
 * applies isAdminMarker. Fail-closed: any lookup failure returns false.
 *
 * NOTE: this adds one Kratos admin-API call per render of pages that call it
 * (index and apps/[slug]). That is acceptable for cosmetic chrome (the admin
 * nav link); real authority is enforced by requireAdminSession. A caching
 * optimization can be added later if render latency becomes a concern.
 *
 * The caller must pass the identity id from the session (session.identity.id),
 * which is always present on an authenticated session.
 */
export async function isAdminBySession(id: string): Promise<boolean> {
  try {
    const identity = await getIdentity(id);
    return isAdminMarker(identity);
  } catch {
    return false;
  }
}

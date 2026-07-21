// Admin authority — the `metadata_admin.admin` marker on the Kratos
// identity is the sole admin authority: admin-API-only-writable, read fresh
// via getIdentity, and absent from /sessions/whoami in Kratos v26.2.0.
// Decided in docs/adr/08-admin-authority-model.md.

import type { Identity } from './types';
import { getIdentity } from './admin-api';

/**
 * Authoritative admin marker check (ADR 08 Tier 1).
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
 * Cosmetic admin-chrome check for SSR pages (ADR 08).
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

// Admin authority — the `metadata_admin.admin` marker on the Kratos
// identity is the sole admin authority: admin-API-only-writable, read fresh
// via getIdentity, and absent from /sessions/whoami in Kratos v26.2.0.

import type { Identity } from './types';

/**
 * Authoritative admin marker check — the sole admin authority.
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

// Access gate — the COMPLETE gate (CU1 item 2).
//
// Ported from consent/handlers.go (enforceAccessGate /
// enforceAccessGateFromGroups) + consent/manifest.go (identityGroups). Two
// checks, both FAIL-CLOSED, applied on BOTH the login and consent challenge
// handlers (oauth2-handlers.ts):
//
//   1. identity.state must be exactly "active" — deactivated identities are
//      denied. The Go service relies on Kratos returning no session for a
//      deactivated identity on the fresh-login path; here we make the check
//      explicit and unconditional so the skip-login path and the consent
//      path (which read the identity via the admin API, where `state` is
//      present) also reject inactive identities.
//   2. identity must be a member of the "access-<clientId>" group, read from
//      admin-managed metadata_admin.groups. clientId is lowercased to match
//      the Go gate (accessGroupPrefix + strings.ToLower(clientID)).
//
// These are pure functions over an already-fetched identity so they can be
// unit-tested without a running Kratos. The handler treats an identity
// lookup failure as a closed gate (passes null here -> denied).

import type { Identity } from './types';

/** Per-app entry-gate group convention: "access-<clientId>". */
export const ACCESS_GROUP_PREFIX = 'access-';

/** The group a client requires for access: "access-<lowercased clientId>". */
export function requiredGroupFor(clientId: string): string {
  return ACCESS_GROUP_PREFIX + clientId.toLowerCase();
}

/** Read metadata_admin.groups defensively (tolerates any/undefined shape). */
export function identityGroups(identity: Identity | null | undefined): string[] {
  const meta = identity?.metadata_admin as { groups?: unknown } | undefined;
  const raw = meta?.groups;
  if (!Array.isArray(raw)) return [];
  return raw.filter((g): g is string => typeof g === 'string');
}

/** Report whether the identity is a member of the named group. */
export function hasGroup(identity: Identity | null | undefined, group: string): boolean {
  return identityGroups(identity).includes(group);
}

/** Result of an access-gate evaluation. */
export interface GateResult {
  allowed: boolean;
  /** Human-readable denial reason; undefined when allowed. */
  reason?: string;
}

/**
 * Evaluate the access gate for an identity against a client. FAIL-CLOSED:
 * any missing precondition denies. Mirrors enforceAccessGate in handlers.go,
 * with the state check made explicit (CU1 item 2).
 */
export function enforceAccessGate(
  identity: Identity | null | undefined,
  clientId: string,
): GateResult {
  // Fail-closed: no identity == no access (lookup failed upstream).
  if (!identity) {
    return { allowed: false, reason: 'identity lookup failed' };
  }

  // Fail-closed: deactivated identities are denied. State must be exactly
  // "active"; any other (or missing) value is denied.
  if (identity.state !== 'active') {
    return { allowed: false, reason: 'identity not active' };
  }

  const expected = requiredGroupFor(clientId);
  if (!hasGroup(identity, expected)) {
    return { allowed: false, reason: `User is not in ${expected} group` };
  }

  return { allowed: true };
}

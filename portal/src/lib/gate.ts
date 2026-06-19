// Access gate — the COMPLETE gate (CU1 item 2, C skip_access_check).
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
// skip_access_check escape hatch (C): if the client manifest sets
// consent.skip_access_check:true, check (2) is bypassed. Check (1) — the
// active-state gate — is NEVER bypassed (skip_access_check is access-group
// only, matching Go enforceAccessGate/enforceAccessGateFromGroups which also
// only skip the slices.Contains check, not the identity lookup or the state
// check implicit in the caller).
//
// These are pure functions over an already-fetched identity so they can be
// unit-tested without a running Kratos. The handler treats an identity
// lookup failure as a closed gate (passes null here -> denied).

import type { Identity } from './types';
import type { ClientManifest } from './manifests';

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
 * Evaluate the access gate for an identity against an ARBITRARY required
 * group (not derived from a clientId). FAIL-CLOSED: any missing precondition
 * denies. Used by /api/forward-auth, where the required group arrives as a
 * query param (e.g. "access-observe") rather than from a client manifest.
 *
 * Same two checks as enforceAccessGate, in the same order, with NO
 * skip_access_check escape hatch (forward_auth has no manifest):
 *   1. identity present (lookup succeeded) — null denies.
 *   2. identity.state === "active" — anything else denies.
 *   3. membership in `group` (metadata_admin.groups) — absent denies.
 */
export function enforceGroupGate(
  identity: Identity | null | undefined,
  group: string,
): GateResult {
  if (!identity) {
    return { allowed: false, reason: 'identity lookup failed' };
  }
  if (identity.state !== 'active') {
    return { allowed: false, reason: 'identity not active' };
  }
  if (!hasGroup(identity, group)) {
    return { allowed: false, reason: `User is not in ${group} group` };
  }
  return { allowed: true };
}

/**
 * Evaluate the access gate for an identity against a client. FAIL-CLOSED:
 * any missing precondition denies. Mirrors enforceAccessGate in handlers.go,
 * with the state check made explicit (CU1 item 2).
 *
 * skip_access_check (C): if manifest.skipAccessCheck is true, the
 * access-<clientId> group membership check is bypassed. The state===active
 * check is NEVER bypassed — matching Go's two-function design where
 * SkipAccessCheck only skips the slices.Contains check.
 */
export function enforceAccessGate(
  identity: Identity | null | undefined,
  clientId: string,
  manifest?: ClientManifest | undefined,
): GateResult {
  // Fail-closed: no identity == no access (lookup failed upstream).
  if (!identity) {
    return { allowed: false, reason: 'identity lookup failed' };
  }

  // Fail-closed: deactivated identities are denied. State must be exactly
  // "active"; any other (or missing) value is denied. This check is NEVER
  // skipped by skip_access_check (access-group bypass only).
  if (identity.state !== 'active') {
    return { allowed: false, reason: 'identity not active' };
  }

  // skip_access_check escape hatch: bypass access-group membership check
  // but NOT the state check above. Matches Go enforceAccessGateFromGroups
  // which returns false (not rejected) before the slices.Contains check
  // when cm.Consent.SkipAccessCheck is true.
  if (manifest?.skipAccessCheck) {
    return { allowed: true };
  }

  // Identity + state already verified above; the only remaining check is the
  // access-<clientId> group membership, which enforceGroupGate performs
  // (it re-runs the identity/state checks idempotently — both already pass here).
  return enforceGroupGate(identity, requiredGroupFor(clientId));
}

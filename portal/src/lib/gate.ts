// Access gate, FAIL-CLOSED, applied on the login and consent challenges: (1) identity.state is exactly "active";
// (2) the identity holds ANY group in manifest.accessGroups (OR), read from metadata_admin.groups; (3) every stored
// group matches GROUP_RE (refuseNonCanonical). consent.skip_access_check bypasses only (2), never (1) or (3).
// Pure functions over a fetched identity; a failed lookup passes null and is denied.

import type { Identity } from './types';
import type { ClientManifest } from './manifests';
import { GROUP_RE } from './access-groups';

const LEGACY_ADMIN_GROUP = 'admin';

/** Read metadata_admin.groups defensively (tolerates any/undefined shape). */
export function identityGroups(identity: Identity | null | undefined): string[] {
  const meta = identity?.metadata_admin as { groups?: unknown } | undefined;
  const raw = meta?.groups;
  if (!Array.isArray(raw)) return [];
  return raw.filter((g): g is string => typeof g === 'string');
}

/** Whether the identity holds the group. Compared VERBATIM: GROUP_RE is the one canonical form, so a case fold would only match names no owned boundary could write. */
export function hasGroup(identity: Identity | null | undefined, group: string): boolean {
  return identityGroups(identity).some((g) => g === group);
}

/** Stored group names that violate GROUP_RE; every owned write path rejects them, so a hit means the identity was written through the Kratos admin API. */
export function nonCanonicalGroups(identity: Identity | null | undefined): string[] {
  return identityGroups(identity).filter((g) => !GROUP_RE.test(g));
}

/**
 * The read-boundary check shared by both gates: a stored name we could not have written denies the gate and names the
 * group. Coercing it would admit an identity no owned boundary creates; skipping it would go unnoticed. Denying is the
 * only outcome that neither grants access nor hides. It returns rather than throws so the admin pages and repair form still load.
 */
function refuseNonCanonical(identity: Identity): GateResult | null {
  const bad = nonCanonicalGroups(identity);
  if (bad.length === 0) return null;
  return {
    allowed: false,
    reason: `non-canonical group(s) stored on this identity: ${bad.join(', ')}`,
  };
}

/** Result of an access-gate evaluation. */
export interface GateResult {
  allowed: boolean;
  /** Human-readable denial reason; undefined when allowed. */
  reason?: string;
}

/**
 * Gate an identity against an ARBITRARY required group (no manifest, no skip_access_check); used by /api/forward-auth,
 * where the group arrives as a query param. Order: identity present, state active, canonical groups, membership.
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
  const refusal = refuseNonCanonical(identity);
  if (refusal) return refusal;
  if (!hasGroup(identity, group)) {
    return { allowed: false, reason: `User is not in ${group} group` };
  }
  return { allowed: true };
}

/**
 * Gate an identity against a client, FAIL-CLOSED. Entry needs membership in ANY manifest.accessGroups (OR); the binding,
 * not the name, makes a group access-bearing. `clientId` is kept for caller parity. manifest.skipAccessCheck bypasses
 * only the membership check. A missing manifest denies: there is no implicit access.
 */
export function enforceAccessGate(
  identity: Identity | null | undefined,
  _clientId: string,
  manifest?: ClientManifest | undefined,
): GateResult {
  if (!identity) {
    return { allowed: false, reason: 'identity lookup failed' };
  }

  // Deny unless state is exactly "active"; never skipped by skip_access_check.
  if (identity.state !== 'active') {
    return { allowed: false, reason: 'identity not active' };
  }

  // A stored group we could not have written means an out-of-band edit; a fact about the identity, so it sits above the skip hatch.
  const refusal = refuseNonCanonical(identity);
  if (refusal) return refusal;

  // skip_access_check bypasses membership only (Go enforceAccessGateFromGroups).
  if (manifest?.skipAccessCheck) {
    return { allowed: true };
  }

  // No manifest or no binding: no group can satisfy the gate, so deny.
  const accessGroups = manifest?.accessGroups ?? [];
  if (accessGroups.length === 0) {
    return { allowed: false, reason: 'no access group bound for this app' };
  }

  // OR-semantics over the bound groups.
  const userGroups = identityGroups(identity);
  if (!accessGroups.some((g) => userGroups.includes(g))) {
    const list = accessGroups.join(', ');
    return { allowed: false, reason: `User is not in any of the access group(s): ${list}` };
  }
  return { allowed: true };
}

/** What one save of the admin edit form is allowed to write. */
export interface GroupSavePlan {
  /** Canonical names to store. The caller applies the canonical ORDER. */
  groups: string[];
  /** Stored non-canonical names the operator did NOT clear. */
  kept: string[];
  /** Stored non-canonical names the operator explicitly cleared. */
  removed: string[];
  /** Non-null when the save must be refused; names every kept group. */
  refusal: string | null;
}

/**
 * Plan the group write for one save of the admin edit form (users/[id].astro, action="save"), the REPAIR surface for
 * the state refuseNonCanonical denies. Decisions are taken against the identity as STORED: `submitted` checkboxes
 * contribute only GROUP_RE names (a hand-crafted one would make this form a creation surface); `cleared` is
 * intersected with the stored non-canonical names; anything stored, non-canonical and not cleared is `kept`, so
 * omitting the field removes nothing. A non-empty `kept` yields a `refusal` because updateIdentity's validateGroups
 * applies the same GROUP_RE, so no owned path can re-write it, and teaching one to would retire the property that a
 * non-canonical hit means an out-of-band write. The caller shows `refusal` and writes NOTHING.
 */
export function planGroupSave(
  identity: Identity | null | undefined,
  submitted: readonly string[],
  cleared: readonly string[],
): GroupSavePlan {
  const stored = nonCanonicalGroups(identity);
  const clearedSet = new Set(cleared);
  const removed = stored.filter((g) => clearedSet.has(g));
  const kept = stored.filter((g) => !clearedSet.has(g));

  // The legacy `admin` identity group confers nothing (admin status is metadata_admin.admin), so a save never stores it.
  const groups: string[] = [];
  for (const g of submitted) {
    if (GROUP_RE.test(g) && g !== LEGACY_ADMIN_GROUP && !groups.includes(g)) groups.push(g);
  }

  const refusal =
    kept.length === 0
      ? null
      : `Unrecognised group(s) still stored on this identity: ${kept.join(', ')}. ` +
        'They are why every app denies this person, and no write path here can ' +
        'store them again, so nothing was saved. Tick Remove on each one to save, ' +
        'or correct the name directly in Kratos.';

  return { groups, kept, removed, refusal };
}

// Access gate — the COMPLETE gate (CU1 item 2, C skip_access_check).
//
// Three checks, all FAIL-CLOSED, applied on BOTH the login and consent
// challenge handlers (oauth2-handlers.ts):
//
//   1. identity.state must be exactly "active" — deactivated identities are
//      denied. The Go service relies on Kratos returning no session for a
//      deactivated identity on the fresh-login path; here we make the check
//      explicit and unconditional so the skip-login path and the consent
//      path (which read the identity via the admin API, where `state` is
//      present) also reject inactive identities.
//   2. identity must be a member of ANY group the client's manifest binds for
//      access (manifest.accessGroups, OR-semantics), read from admin-managed
//      metadata_admin.groups. The access-bearing group(s) come from the
//      manifest BINDING, not a derived `access-<clientId>` name: a group's
//      access-bearing status is a property of the binding, never of its name.
//   3. every group stored on the identity must match the canonical group-name
//      policy (GROUP_RE, access-groups.ts). Kratos's admin API is the one
//      write path this codebase does not own, so this is the read-side check
//      that a name we could never have written cannot pass unnoticed —
//      see refuseNonCanonical for why it denies rather than skipping.
//
// skip_access_check escape hatch (C): if the client manifest sets
// consent.skip_access_check:true, check (2) is bypassed. Checks (1) and (3)
// are NEVER bypassed (skip_access_check is access-group only, matching Go
// enforceAccessGate/enforceAccessGateFromGroups which also only skip the
// slices.Contains check, not the identity lookup or the state check implicit
// in the caller).
//
// These are pure functions over an already-fetched identity so they can be
// unit-tested without a running Kratos. The handler treats an identity
// lookup failure as a closed gate (passes null here -> denied).

import type { Identity } from './types';
import type { ClientManifest } from './manifests';
import { GROUP_RE } from './access-groups';

/** Read metadata_admin.groups defensively (tolerates any/undefined shape). */
export function identityGroups(identity: Identity | null | undefined): string[] {
  const meta = identity?.metadata_admin as { groups?: unknown } | undefined;
  const raw = meta?.groups;
  if (!Array.isArray(raw)) return [];
  return raw.filter((g): g is string => typeof g === 'string');
}

/**
 * Report whether the identity is a member of the named group. Names are
 * compared VERBATIM — there is one canonical form (GROUP_RE, access-groups.ts)
 * and every boundary this codebase owns validates against it, so a case fold
 * here would only ever match a name no owned boundary could have produced.
 * Every other group comparison in portal/src compares raw; this one used to
 * lowercase, and being the most permissive of them made it the odd one out.
 */
export function hasGroup(identity: Identity | null | undefined, group: string): boolean {
  return identityGroups(identity).some((g) => g === group);
}

/**
 * Stored group names that violate the canonical policy (GROUP_RE,
 * access-groups.ts). Every write path this codebase owns rejects such a name
 * (metadata-admin.ts validateGroups), so a non-empty result means the identity
 * was written straight through the Kratos admin API — the one boundary we do
 * not own.
 */
export function nonCanonicalGroups(identity: Identity | null | undefined): string[] {
  return identityGroups(identity).filter((g) => !GROUP_RE.test(g));
}

/**
 * The READ-boundary check, shared by both gates below. A stored name we could
 * not have written is refused LOUDLY: the whole gate denies and names the
 * offending group in `reason`.
 *
 * Why this failure mode. The alternatives both hide it. Coercing the name
 * (lowercasing it) admits an identity no owned boundary would have created.
 * Skipping the name makes it behave exactly like a group that was never
 * stored — nothing denies, nothing reports, and the admin UI renders the
 * identity as though the name were not there. Denying every app and naming the
 * group is the only outcome that can neither grant access nor go unnoticed:
 * the person is locked out until an admin looks, and only an admin could have
 * created the state in the first place.
 *
 * It returns rather than throws on purpose: the admin pages that render this
 * identity — and the form that repairs it — must still load.
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
 * Evaluate the access gate for an identity against an ARBITRARY required
 * group (not derived from a clientId). FAIL-CLOSED: any missing precondition
 * denies. Used by /api/forward-auth, where the required group arrives as a
 * query param (e.g. "access-proxywatch") rather than from a client manifest.
 *
 * Same checks as enforceAccessGate, in the same order, with NO
 * skip_access_check escape hatch (forward_auth has no manifest):
 *   1. identity present (lookup succeeded) — null denies.
 *   2. identity.state === "active" — anything else denies.
 *   3. every stored group matches GROUP_RE — any that does not denies
 *      (refuseNonCanonical).
 *   4. membership in `group` (metadata_admin.groups) — absent denies.
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
 * Evaluate the access gate for an identity against a client. FAIL-CLOSED:
 * any missing precondition denies. The state check is explicit (CU1 item 2).
 *
 * The access-bearing group(s) come from the manifest BINDING
 * (`manifest.accessGroups`), with OR-semantics —
 * membership in ANY bound group grants entry. The group's access-bearing
 * status is a property of the manifest binding, not its name. `clientId` is
 * retained for the caller's logging/parity; the manifest binding is the sole
 * source of the access-bearing group.
 *
 * skip_access_check (C): if manifest.skipAccessCheck is true, the group
 * membership check is bypassed. The state===active check is NEVER bypassed —
 * matching Go's two-function design where SkipAccessCheck only skips the
 * slices.Contains check.
 *
 * Fail-closed without a manifest: a missing manifest (unknown client) has no
 * binding to satisfy, so it denies (unless an explicit skip is impossible to
 * express without a manifest — there is no implicit access).
 */
export function enforceAccessGate(
  identity: Identity | null | undefined,
  _clientId: string,
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

  // Fail-closed: a stored group we could not have written means the record was
  // altered out of band. Like the state check, this is a fact about the
  // identity rather than about this app's binding, so skip_access_check does
  // NOT bypass it — the check sits above the hatch for that reason.
  const refusal = refuseNonCanonical(identity);
  if (refusal) return refusal;

  // skip_access_check escape hatch: bypass the group-membership check but NOT
  // the state check above. Matches Go enforceAccessGateFromGroups.
  if (manifest?.skipAccessCheck) {
    return { allowed: true };
  }

  // Fail-closed: no manifest, or a manifest with no access binding, means no
  // group can satisfy the gate. There is no implicit access: absence of a
  // binding denies rather than admitting everyone.
  const accessGroups = manifest?.accessGroups ?? [];
  if (accessGroups.length === 0) {
    return { allowed: false, reason: 'no access group bound for this app' };
  }

  // OR-semantics: membership in ANY bound access group grants entry. Identity +
  // state are already verified above.
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
 * Plan the group write for one save of the admin edit form
 * (portal/src/pages/admin/users/[id].astro, action="save") — the REPAIR
 * surface for the state refuseNonCanonical above denies.
 *
 * It is a repair surface, not a creation surface, so every decision is taken
 * against the identity as STORED and the submission supplies only choices
 * ABOUT that stored state:
 *
 *   - `submitted` is the checkbox composition (identity groups + access
 *     groups). Only names matching GROUP_RE reach `groups`. Those checkbox
 *     sets are rendered from vocabularies this codebase owns, so a
 *     non-canonical name arriving here was hand-crafted, and honouring it
 *     would make this form the very creation surface that put the identity
 *     into the denied state.
 *   - `cleared` is the operator's explicit per-name removal tick. It is
 *     intersected with the STORED non-canonical names, so it can neither
 *     strip a canonical group nor name anything the identity does not hold.
 *   - Anything stored and non-canonical that was not cleared is `kept`.
 *     Absence is therefore PRESERVING: a submission that omits the field
 *     entirely — an older render, a form that never grew the row — removes
 *     nothing. Removal only ever happens on an affirmative tick.
 *
 * Why a non-empty `kept` yields a `refusal` rather than a carry-through: the
 * one write path is portal/src/lib/admin-api.ts `updateIdentity`, which hands
 * the whole list to portal/src/lib/metadata-admin.ts `validateGroups` — the
 * same GROUP_RE. A stored non-canonical name therefore cannot be re-written by
 * any path this codebase owns, and teaching one to emit it would retire the
 * property that makes nonCanonicalGroups meaningful (a hit means the record
 * was written out of band). Refusing is the only outcome that neither drops
 * the name silently nor grants an owned write path the ability to produce one.
 * The caller surfaces `refusal` as a form error and writes NOTHING.
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

  const groups: string[] = [];
  for (const g of submitted) {
    if (GROUP_RE.test(g) && !groups.includes(g)) groups.push(g);
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

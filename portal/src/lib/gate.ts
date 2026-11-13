
/** The front-door ask: step-up, only for an identity that can answer it. */
export function stepUpAtLanding(session: Parameters<typeof needsStepUp>[0], identity: Identity | null | undefined, manifests?: ClientManifest[]): boolean {
  return needsStepUp(session, identity, manifests) && parseIdentity(identity).hasSecondFactor;
}
// Access policy, fail-closed, as pure functions over a fetched identity; a failed lookup passes null and is denied.
// consent.skip_access_check bypasses only group membership, never the active-state or canonical-group checks.

import type { Identity, Session } from './types';
import type { ClientManifest } from './manifests';
import { GROUP_RE } from './access-groups';
import { parseIdentity } from './identity-facts';
import { lookupRole } from './claims';
import { servingManifests } from './manifest-store';

/** Compared verbatim: a case fold would only match names no owned boundary could write. */
export function hasGroup(identity: Identity | null | undefined, group: string): boolean {
  return parseIdentity(identity).groups.some((g) => g === group);
}

/** Stored group names that violate GROUP_RE; every owned write path rejects them, so a hit means the identity was written through the Kratos admin API. */
export function nonCanonicalGroups(identity: Identity | null | undefined): string[] {
  return parseIdentity(identity).groups.filter((g) => !GROUP_RE.test(g));
}

/**
 * The refusal both gates start with: no identity, an inactive one, or a stored group name we could not have written.
 * A non-canonical name denies and is named: coercing would admit it, skipping would hide it. It returns rather than
 * throws so the admin pages and repair form still load.
 */
function refuseIdentity(identity: Identity | null | undefined): GateResult | null {
  if (!identity) return { allowed: false, reason: 'identity lookup failed' };
  if (identity.state !== 'active') return { allowed: false, reason: 'identity not active' };
  const bad = nonCanonicalGroups(identity);
  if (bad.length === 0) return null;
  return {
    allowed: false,
    reason: `non-canonical group(s) stored on this identity: ${bad.join(', ')}`,
  };
}

export interface GateResult {
  allowed: boolean;
  reason?: string;
}

/** Gate an identity against a group named by the caller, with no manifest and no skip_access_check. */
export function enforceGroupGate(
  identity: Identity | null | undefined,
  group: string,
): GateResult {
  const refusal = refuseIdentity(identity);
  if (refusal) return refusal;
  if (!hasGroup(identity, group)) {
    return { allowed: false, reason: `User is not in ${group} group` };
  }
  return { allowed: true };
}

/** Entry needs any one of the app's access groups; a missing manifest or an empty binding denies. */
export function enforceAccessGate(
  identity: Identity | null | undefined,
  _clientId: string,
  manifest?: ClientManifest | undefined,
): GateResult {
  const refusal = refuseIdentity(identity);
  if (refusal) return refusal;
  if (manifest?.skipAccessCheck) {
    return { allowed: true };
  }
  const accessGroups = manifest?.accessGroups ?? [];
  if (accessGroups.length === 0) {
    return { allowed: false, reason: 'no access group bound for this app' };
  }
  const userGroups = parseIdentity(identity).groups;
  if (!accessGroups.some((g) => userGroups.includes(g))) {
    const list = accessGroups.join(', ');
    return { allowed: false, reason: `User is not in any of the access group(s): ${list}` };
  }
  return { allowed: true };
}

const rankOf = (m: ClientManifest, roleName: string) => m.roles.findIndex((r) => r.name === roleName);

/** An app's entry role rank: the lowest role its access groups map to, else the last declared role (0 is highest). */
function entryRank(m: ClientManifest): number {
  const ranks = m.accessGroups.map((g) => rankOf(m, m.groupRoleMap[g] ?? '')).filter((r) => r >= 0);
  return ranks.length > 0 ? Math.max(...ranks) : m.roles.length - 1;
}

/** True when the identity resolves, in any served manifest, to a role ranked above that app's entry role. */
export function holdsElevatedRole(identity: Identity | null | undefined, manifests: ClientManifest[] = servingManifests()): boolean {
  return manifests.some((m) => {
    const role = lookupRole(m, identity?.metadata_admin);
    return role !== null && rankOf(m, role.roleName) < entryRank(m);
  });
}

/**
 * Step-up below aal2 (a missing AAL counts as below): the identity holds a second factor, the admin marker, or a role
 * above an app's entry role. The identity must come from the admin API (getIdentity).
 */
export function needsStepUp(
  session: Pick<Session, 'authenticator_assurance_level'> | null | undefined,
  identity: Identity | null | undefined,
  manifests?: ClientManifest[],
): boolean {
  if (session?.authenticator_assurance_level === 'aal2') return false;
  const facts = parseIdentity(identity);
  return facts.isAdmin || facts.hasSecondFactor || holdsElevatedRole(identity, manifests);
}

/**
 * What a session asks to reach: an OIDC app by its manifest, a forward-auth group, the admin pages, or a session from
 * an emailed code (code sign-in, recovery, and the setup links the admin pages make).
 */
export type AccessTarget = { app: ClientManifest | undefined } | { group: string } | 'admin' | 'emailed-code';
export type AccessDecision = { allow: true } | { stepUp: true } | { deny: string };
/** `fresh`: the session is within the admin freshness window; only the admin pages read it. */
export type SessionFacts = Pick<Session, 'authenticator_assurance_level'> & { fresh?: boolean };

/**
 * The access policy for app sign-in, forward-auth, the admin pages and emailed codes. Apps and groups: the gate first
 * (a denial outranks a step-up), then step-up. Admin pages: aal2 within the freshness window, then the admin marker;
 * that session rule reads no identity, so the caller can settle it (identity null) before reading the admin API.
 * Emailed codes: never for an admin account, whose sign-in needs a key.
 */
export function decideAccess(
  identity: Identity | null | undefined,
  target: AccessTarget,
  session: SessionFacts | null | undefined,
  manifests?: ClientManifest[],
): AccessDecision {
  if (target === 'emailed-code') return parseIdentity(identity).isAdmin ? { deny: 'admin account' } : { allow: true };
  if (target === 'admin') {
    if (session?.authenticator_assurance_level !== 'aal2' || session.fresh !== true) return { stepUp: true };
    return parseIdentity(identity).isAdmin ? { allow: true } : { deny: 'not an admin' };
  }
  const gate =
    'group' in target ? enforceGroupGate(identity, target.group) : enforceAccessGate(identity, target.app?.clientId ?? '', target.app);
  if (!gate.allowed) return { deny: gate.reason ?? '' };
  return needsStepUp(session, identity, manifests) ? { stepUp: true } : { allow: true };
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
 * Plan one save of the admin edit form, the repair surface for what refuseNonCanonical denies. `submitted` contributes
 * only GROUP_RE names, so the form never creates a non-canonical one. A stored non-canonical name not in `cleared` is
 * kept and refuses the save, since no owned path may write it back; the caller shows `refusal` and writes nothing.
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

// Effective access computation.
//
// Given a Kratos identity and the OIDC client catalog, compute the per-app
// role each user actually receives. Uses the same shared lookupRole()
// function that the token/consent path calls — there is now a single
// implementation in portal/src/lib/claims.ts, not two to keep aligned.
//
// Algorithm per client:
//   1. If user is not in `access-<clientId>` group -> no row (no access).
//   2. Look up `metadata_admin.roles[clientId]`. If set, that's the role
//      and the source is "override".
//   3. Otherwise, walk the user's identity groups in stored order and
//      pick the first match in the client's `group_role_map`. Source is
//      `via <group>`.
//   4. If the manifest declares no roles at all, the row reports role
//      `default` with source `no role mapping`.
//
// C4 reconciliation:
//
//   Both this function and the consent/token path (via lookupRole in
//   claims.ts) walk the user's stored group order. Stored order is
//   normalized at the admin-form save boundary (see `normalizeGroupOrder`):
//   identity groups first in canonical order, then access-* groups in
//   alphabetical order. This guarantees portal "Effective Access" and
//   the token-injection path issue identical roles for the same input.
//
//   The canonical identity-group order is driven by OTHALA_IDENTITY_GROUPS
//   (see $lib/config). 'admin' is always first. New identity groups are
//   added via that env var — no code change required.

import type { ClientManifest } from './manifests';
import type { Identity } from './types';
import { isAdminSubject } from './admin-auth';
import { lookupRole } from './claims';
import { identityGroups } from './config';

export type AccessSource =
  | { kind: 'override' }
  | { kind: 'group'; group: string }
  | { kind: 'no-roles' }
  /** Override key was present in metadata_admin.roles but named an undeclared
   *  role; lookupRole fell through to the group walk. The resolved role and
   *  group are correct; the override was silently ignored. */
  | { kind: 'override-ignored'; group: string };

export interface EffectiveAccessRow {
  clientId: string;
  clientName: string;
  role: string;
  source: AccessSource;
}

/**
 * Canonical identity-group order. The admin form writes
 * `metadata_admin.groups` in this order (identity groups first), so
 * stored order == canonical order, and a stored-order walk produces
 * the same answer as a precedence walk.
 *
 * Driven by OTHALA_IDENTITY_GROUPS (see $lib/config). Adding a new
 * identity group means setting (or extending) that env var — no code
 * change required. 'admin' is always first regardless of env content.
 */
export const IDENTITY_GROUP_ORDER: readonly string[] = identityGroups;

/**
 * Sort an unordered list of groups into the canonical stored shape:
 *   1. Identity groups in IDENTITY_GROUP_ORDER order.
 *   2. Unknown identity groups (not in IDENTITY_GROUP_ORDER and not
 *      access-*) in alphabetical order, after the canonical block.
 *   3. access-* groups in alphabetical order.
 *
 * The admin form calls this on every save so the order in
 * `metadata_admin.groups` is deterministic and both code paths
 * (this file and `consent/manifest.go`) agree on which group wins.
 */
export function normalizeGroupOrder(groups: string[]): string[] {
  const set = new Set(groups);
  const ordered: string[] = [];
  for (const g of IDENTITY_GROUP_ORDER) {
    if (set.has(g)) {
      ordered.push(g);
      set.delete(g);
    }
  }
  const remaining = Array.from(set);
  const accessGroups = remaining.filter((g) => g.startsWith('access-')).sort();
  const otherIdentityGroups = remaining.filter((g) => !g.startsWith('access-')).sort();
  return [...ordered, ...otherIdentityGroups, ...accessGroups];
}

/**
 * Determine whether a role resolution was via override (metadata_admin.roles)
 * or via group walk. Used for source-type labeling in the admin UI.
 *
 * Matches Go overrideRole semantics: reads metadata_admin.roles[clientId.toLowerCase()].
 * Fixed: uses .toLowerCase() on clientId key to match Go strings.ToLower(clientID).
 */
function readRoleOverride(identity: Identity, clientId: string): string | null {
  const meta = identity.metadata_admin as Record<string, unknown> | undefined;
  if (!meta) return null;
  const raw = meta.roles;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const overrideMap = raw as Record<string, unknown>;
  // Key is lowercased to match Go overrideRole's strings.ToLower(clientID).
  const v = overrideMap[clientId.toLowerCase()];
  return typeof v === 'string' && v !== '' ? v : null;
}

export function computeEffectiveAccess(
  identity: Identity,
  manifests: ClientManifest[],
): EffectiveAccessRow[] {
  const userGroups = identity.metadata_admin?.groups ?? [];
  const rows: EffectiveAccessRow[] = [];

  for (const m of manifests) {
    if (!userGroups.includes(m.accessGroup)) continue;

    if (m.roles.length === 0) {
      rows.push({
        clientId: m.clientId,
        clientName: m.clientName,
        role: 'default',
        source: { kind: 'no-roles' },
      });
      continue;
    }

    // Determine source-type for UI display. Source-type detection stays
    // here (UI-only metadata not present in lookupRole's return value),
    // but we delegate role resolution to the shared lookupRole resolver to
    // ensure algorithm parity with the consent path (A1).
    const overrideRoleName = readRoleOverride(identity, m.clientId);
    const resolvedRole = lookupRole(m, identity.metadata_admin);

    if (resolvedRole) {
      // Determine source-kind: if the override key exists in metadata_admin.roles
      // and it matches the resolved role, source is 'override'.
      const isOverride = overrideRoleName !== null && overrideRoleName === resolvedRole.roleName;
      if (isOverride) {
        rows.push({
          clientId: m.clientId,
          clientName: m.clientName,
          role: resolvedRole.roleName,
          source: { kind: 'override' },
        });
      } else {
        // Determine the matching group for the 'group' source kind.
        let matchingGroup = '';
        for (const g of userGroups) {
          if (m.groupRoleMap[g] === resolvedRole.roleName) {
            matchingGroup = g;
            break;
          }
        }
        // If an override was attempted but named an undeclared role, lookupRole
        // fell through to the group walk (typo-tolerance). Label the source
        // honestly so the admin UI reflects the ignored override.
        const overrideIgnored = overrideRoleName !== null && !isOverride;
        const source: AccessSource = overrideIgnored
          ? { kind: 'override-ignored', group: matchingGroup }
          : matchingGroup
            ? { kind: 'group', group: matchingGroup }
            : { kind: 'no-roles' };
        rows.push({
          clientId: m.clientId,
          clientName: m.clientName,
          role: resolvedRole.roleName,
          source,
        });
      }
    } else {
      // Access granted but no role mapping; surface the first declared role
      // as a sensible default and flag it.
      rows.push({
        clientId: m.clientId,
        clientName: m.clientName,
        role: m.roles[0].name,
        source: { kind: 'no-roles' },
      });
    }
  }

  return rows;
}

/**
 * HIGH-3 gate: refuse admin-to-admin recovery via the UI. The Kratos
 * admin-issued recovery link bypasses the recovery-gate webhook (the
 * gate only fires for the public /self-service/recovery/code flow),
 * so admin recovery is console-only. See
 * docs/runbooks/admin-recovery.md "Console recovery for an admin".
 *
 * B2: admin status is the OTHALA_ADMIN_SUBJECTS allowlist, NOT the `admin`
 * metadata_admin group. Refuse iff the TARGET identity's email is on the
 * allowlist. A user carrying the (display-only) `admin` group but not on
 * the allowlist is NOT an admin and recovery is allowed for them; an
 * allowlisted admin who self-demoted out of the group is STILL refused.
 */
export function shouldRefuseRecovery(identity: Identity | undefined | null): boolean {
  const email = identity?.traits?.email as string | undefined;
  return isAdminSubject(email);
}

/** Pretty-print an access source for the admin UI. */
export function describeSource(s: AccessSource): string {
  switch (s.kind) {
    case 'override':
      return 'override';
    case 'group':
      return `via ${s.group}`;
    case 'no-roles':
      return 'no role mapping';
    case 'override-ignored':
      return s.group
        ? `override ignored (undeclared role) — resolved via ${s.group}`
        : 'override ignored (undeclared role) — resolved via group';
  }
}

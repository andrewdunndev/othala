// Effective access computation.
//
// Given a Kratos identity and the OIDC client catalog, compute the per-app
// role each user actually receives. Uses the same shared lookupRole()
// function that the token/consent path calls — there is now a single
// implementation in portal/src/lib/claims.ts, not two to keep aligned.
//
// Algorithm per client:
//   1. If user is not in ANY of the manifest's bound access groups
//      (`manifest.accessGroups`, OR-semantics) -> no row (no access). This is
//      the SAME binding the OIDC gate keys off — no derived
//      `access-<clientId>` group.
//   2. If the manifest declares no roles at all, the row reports role
//      `default` with source `no role mapping`.
//   3. Otherwise the ROLE is whatever `lookupRole(manifest, metadata_admin)`
//      returns. This file does not resolve roles itself and must not start:
//      claims.ts is the single implementation, shared with the consent/token
//      path. Everything below step 3 here is UI LABELLING of an answer that
//      has already been decided.
//
// C4 reconciliation — parity is structural, not a matched walk:
//
//   The two paths agree because there is ONE resolver, not because two walks
//   happen to visit groups in the same order. Do not reintroduce a local walk
//   "for the UI" — that is exactly the dual-source bug C4 closed.
//
//   How lookupRole resolves (claims.ts is authoritative; this is a summary
//   that must be re-checked against it, never trusted over it):
//     - An override in `metadata_admin.roles[clientId.toLowerCase()]` wins IF
//       it names a role the manifest declares. An override naming an
//       UNDECLARED role is ignored and resolution falls through — this file
//       labels that case `override-ignored` so the admin UI is honest about it.
//     - Otherwise every group in `metadata_admin.groups` is mapped through
//       `group_role_map`, and among the roles that ARE declared the
//       HIGHEST-RANKED one wins. Rank is position in `manifest.roles`, index 0
//       highest. It is NOT the first match in stored order — that rule is
//       RETIRED, and this comment used to describe it.
//
//   Why the retirement matters here: an admin holds BOTH `<svc>-access` and
//   `<svc>-admin` explicitly, so two role-mapping groups on one identity is the
//   normal case, not an edge case. `normalizeGroupOrder` sorts non-identity
//   groups alphabetically, which puts `grafana-access` before `grafana-admin` —
//   a first-match walk would have handed every admin the lesser role.
//
//   `normalizeGroupOrder` (below) is therefore COSMETIC: stable display, stable
//   diffs in `metadata_admin.groups`. It is not what makes role resolution
//   deterministic, and role resolution no longer depends on it. The one place
//   stored order still shows through is the `matchingGroup` label lookup in
//   computeEffectiveAccess: when two groups map to the same resolved role, the
//   first in stored order is the one named in "via <group>". That is a caption,
//   not a decision.

import type { ClientManifest } from './manifests';
import type { Identity } from './types';
import { isAdminMarker } from './admin-auth';
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
 * `metadata_admin.groups` in this order (identity groups first), which makes
 * the stored array a pure function of the group SET — stable to read, stable
 * to diff. It does NOT decide any role: `lookupRole` (claims.ts) is
 * order-independent by construction.
 *
 * Driven by OTHALA_IDENTITY_GROUPS (see $lib/config). Adding a new
 * identity group means setting (or extending) that env var — no code
 * change required. 'admin' is always first regardless of env content.
 */
export const IDENTITY_GROUP_ORDER: readonly string[] = identityGroups;

/**
 * Sort an unordered list of groups into the canonical stored shape:
 *   1. Identity groups (those in IDENTITY_GROUP_ORDER) in that fixed order.
 *   2. All remaining groups in alphabetical order.
 *
 * This RETIRES the old `access-` prefix partition: a group's position is no
 * longer a function of its name. The partition is now identity-vs-everything,
 * driven by the env-configured identity-group set — exactly what the group
 * registry types as `identity`. Both partitions sort within themselves (fixed
 * env order; alphabetical), so the stored order is a pure function of the
 * inputs (determinism proof, §10).
 *
 * Worked example (§10): groups [family-editors, family, admin] with
 * IDENTITY_GROUP_ORDER=[admin, family] → [admin, family, family-editors].
 * That is the whole effect: a stable stored array. It does NOT decide which
 * of `family` and `family-editors` supplies the role — `lookupRole`
 * (claims.ts) maps both through `group_role_map` and takes the role ranked
 * highest in `manifest.roles`, in any permutation of the input. To change
 * which role a person gets, change the manifest's role order or the person's
 * groups; reordering this array changes nothing but the display.
 *
 * The admin form calls this on every save so `metadata_admin.groups` has one
 * canonical shape per group set — readable in the admin UI, quiet in diffs,
 * and free of the implication that position carries meaning.
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
  const remaining = Array.from(set).sort();
  return [...ordered, ...remaining];
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
    // Gate on the manifest's bound access groups (OR-semantics), the SAME
    // field the OIDC entry gate uses — not a derived
    // `access-<clientId>` name. skip_access_check grants access without a group.
    const hasAccess =
      m.skipAccessCheck || m.accessGroups.some((g) => userGroups.includes(g));
    if (!hasAccess) continue;

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
 * Admin status is the `metadata_admin.admin === true` marker
 * (writable only via the Kratos admin API). The caller MUST pass a target
 * identity fetched from the admin API (e.g. via getIdentity) — the public
 * /sessions/whoami response strips metadata_admin (Kratos v26). Refuse iff
 * the TARGET identity carries the admin marker.
 */
export function shouldRefuseRecovery(identity: Identity | undefined | null): boolean {
  return isAdminMarker(identity);
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

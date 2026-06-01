// Effective access computation.
//
// Given a Kratos identity and the OIDC client catalog, compute the per-app
// role each user actually receives. Mirrors the algorithm the consent
// service uses when injecting role claims; keep the two aligned.
//
// Algorithm per client:
//   1. If user is not in `access-<clientId>` group -> no row (no access).
//   2. Look up `metadata_admin.roles[clientId]`. If set, that's the role
//      and the source is "override".
//   3. Otherwise, walk the user's identity groups in stored order and
//      pick the first match in the client's `group_role_map`. Source is
//      `via <group>`.
//   4. If the manifest declares no roles at all, the row reports role
//      `default` with source `(no roles declared)`.
//
// C4 reconciliation:
//
//   Both this function and `consent/manifest.go LookupRole` walk the
//   user's stored group order. Stored order is normalized at the
//   admin-form save boundary (see `normalizeGroupOrder`): identity
//   groups first in canonical order, then access-* groups in
//   alphabetical order. This guarantees portal "Effective Access" and
//   the consent service issue identical roles for the same input.
//
//   The canonical identity-group order is:
//     admin, family, friends, kids
//
//   New identity groups (e.g., service, elder) MUST be added to
//   IDENTITY_GROUP_ORDER below AND to the admin forms' IDENTITY_GROUPS
//   list. Adding to one without the other re-introduces the C4 drift.

import type { ClientManifest } from './manifests';
import type { Identity } from './types';
import { isAdminSubject } from './admin-auth';

export type AccessSource =
  | { kind: 'override' }
  | { kind: 'group'; group: string }
  | { kind: 'no-roles' };

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
 * Adding a new identity group means appending it here AND to the
 * admin form's IDENTITY_GROUPS list (`portal/src/pages/admin/users/new.astro`
 * and `[id].astro`). Otherwise the form will write the group out of
 * canonical order and the cross-implementation invariant breaks.
 */
export const IDENTITY_GROUP_ORDER = ['admin', 'family', 'friends', 'kids'] as const;

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

/** Read `metadata_admin.roles` defensively from an identity. */
function readRoleOverrides(id: Identity): Record<string, string> {
  const meta = id.metadata_admin as Record<string, unknown> | undefined;
  if (!meta) return {};
  const raw = meta.roles;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

/**
 * Pick the first user-stored group that maps to a role in the client's
 * group_role_map. Walks stored order, matching the consent service's
 * `LookupRole` semantics.
 */
function pickIdentityGroup(userGroups: string[], map: Record<string, string>): string | null {
  for (const g of userGroups) {
    if (map[g]) return g;
  }
  return null;
}

export function computeEffectiveAccess(
  identity: Identity,
  manifests: ClientManifest[],
): EffectiveAccessRow[] {
  const userGroups = identity.metadata_admin?.groups ?? [];
  const overrides = readRoleOverrides(identity);
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

    if (overrides[m.clientId]) {
      rows.push({
        clientId: m.clientId,
        clientName: m.clientName,
        role: overrides[m.clientId],
        source: { kind: 'override' },
      });
      continue;
    }

    const group = pickIdentityGroup(userGroups, m.groupRoleMap);
    if (group) {
      rows.push({
        clientId: m.clientId,
        clientName: m.clientName,
        role: m.groupRoleMap[group],
        source: { kind: 'group', group },
      });
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
  }
}

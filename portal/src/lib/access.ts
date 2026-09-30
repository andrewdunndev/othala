// Effective access: per client, the role each identity receives. A user outside every manifest.accessGroups (OR, the
// binding the OIDC gate uses) gets no row; a manifest without roles reports `default` / `no role mapping`; otherwise
// the role is whatever lookupRole (claims.ts) returns. Do not add a local group walk here: parity with the consent
// path is structural (one resolver). This file only labels the source, and the `override-ignored` label marks an
// override naming an undeclared role. normalizeGroupOrder is cosmetic; stored order shows only in the "via <group>" caption.

import type { ClientManifest } from './manifests';
import type { Identity } from './types';
import { isAdminMarker } from './admin-auth';
import { lookupRole } from './claims';
import { identityGroups } from './config';

export type AccessSource =
  | { kind: 'override' }
  | { kind: 'group'; group: string }
  | { kind: 'no-roles' }
  /** Override key named an undeclared role; lookupRole fell through to the group walk and the override was ignored. */
  | { kind: 'override-ignored'; group: string };

export interface EffectiveAccessRow {
  clientId: string;
  clientName: string;
  role: string;
  source: AccessSource;
}

/**
 * Canonical identity-group order for `metadata_admin.groups` (identity groups first), so the stored array is a pure
 * function of the group SET. It decides no role (lookupRole is order-independent). Driven by OTHALA_IDENTITY_GROUPS;
 * 'admin' is always first.
 */
export const IDENTITY_GROUP_ORDER: readonly string[] = identityGroups;

/**
 * Sort groups into the canonical stored shape: identity groups (IDENTITY_GROUP_ORDER) in that order, then the rest
 * alphabetically. Example: [family-editors, family, admin] with order [admin, family] -> [admin, family, family-editors].
 * Position carries no meaning: lookupRole ranks by `manifest.roles`, so reordering this array changes only the display.
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

/** The role override for a client (`metadata_admin.roles[clientId.toLowerCase()]`, as Go overrideRole), or null; labels the source in the admin UI. */
function readRoleOverride(identity: Identity, clientId: string): string | null {
  const meta = identity.metadata_admin as Record<string, unknown> | undefined;
  if (!meta) return null;
  const raw = meta.roles;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const overrideMap = raw as Record<string, unknown>;
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
    // Gate on the manifest's bound access groups (OR), as the OIDC entry gate does; skip_access_check grants without a group.
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

    // Source-type is UI-only metadata; the role itself comes from the shared lookupRole.
    const overrideRoleName = readRoleOverride(identity, m.clientId);
    const resolvedRole = lookupRole(m, identity.metadata_admin);

    if (resolvedRole) {
      // 'override' when the override key matches the resolved role.
      const isOverride = overrideRoleName !== null && overrideRoleName === resolvedRole.roleName;
      if (isOverride) {
        rows.push({
          clientId: m.clientId,
          clientName: m.clientName,
          role: resolvedRole.roleName,
          source: { kind: 'override' },
        });
      } else {
        // Matching group for the 'group' source kind.
        let matchingGroup = '';
        for (const g of userGroups) {
          if (m.groupRoleMap[g] === resolvedRole.roleName) {
            matchingGroup = g;
            break;
          }
        }
        // An override naming an undeclared role fell through to the group walk; label it honestly.
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
      // Access granted but no role mapping: surface the first declared role and flag it.
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
 * HIGH-3 gate: refuse admin-to-admin recovery via the UI (admin recovery stays console-only, see
 * docs/runbooks/admin-recovery.md). Refuses iff the TARGET carries the `metadata_admin.admin` marker; the caller must
 * pass an admin-API identity, since public whoami strips metadata_admin.
 */
export function shouldRefuseRecovery(identity: Identity | undefined | null): boolean {
  return isAdminMarker(identity);
}

/**
 * Server-side half of the send-invite-email address confirmation (called from users/[id].astro before
 * sendInviteRecoveryEmail). Byte-equal, not case-folded: Kratos keeps the `email` trait as the literal string on file.
 */
export function confirmsInviteAddress(confirm: string, targetEmail: string): boolean {
  return confirm === targetEmail;
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

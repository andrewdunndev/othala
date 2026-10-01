// Stored-group helpers for the admin pages: the canonical group order, the admin-recovery refusal and the invite address
// check. What access a person holds on an app is read by access-rows.ts through the consent resolver (claims.ts lookupRole).

import type { Identity } from './types';
import { isAdminMarker } from './admin-auth';
import { IDENTITY_GROUPS } from './constants';

/**
 * Canonical identity-group order for `metadata_admin.groups` (identity groups first), so the stored array is a pure
 * function of the group SET. It decides no role (lookupRole is order-independent). 'admin' is always first.
 */
export const IDENTITY_GROUP_ORDER: readonly string[] = IDENTITY_GROUPS;

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

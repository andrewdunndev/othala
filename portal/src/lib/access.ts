// Stored-group helpers for the admin pages: the canonical group order, the admin-recovery refusal and the invite address
// check. What access a person holds on an app is read by access-rows.ts through the consent resolver (claims.ts lookupRole).

import type { Identity } from './types';
import { decideAccess } from './gate';
import { IDENTITY_GROUPS } from './constants';

/**
 * Sort groups into the canonical stored shape: identity groups (IDENTITY_GROUPS) in that order, then the rest
 * alphabetically, so the stored array is a pure function of the group set. Example: [family, everyone, admin] -> [everyone, admin, family].
 * Position carries no meaning: lookupRole ranks by `manifest.roles`, so reordering this array changes only the display.
 */
export function normalizeGroupOrder(groups: string[]): string[] {
  const set = new Set(groups);
  const ordered: string[] = [];
  for (const g of IDENTITY_GROUPS) {
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
 * docs/runbooks/admin-recovery.md): decideAccess's emailed-code rule, applied to the TARGET; the caller must
 * pass an admin-API identity, since public whoami strips metadata_admin.
 */
export function shouldRefuseRecovery(identity: Identity | undefined | null): boolean {
  return 'deny' in decideAccess(identity, 'emailed-code', null);
}

/**
 * Server-side half of the send-invite-email address confirmation (called from users/[id].astro before
 * sendInviteRecoveryEmail). Byte-equal, not case-folded: Kratos keeps the `email` trait as the literal string on file.
 */
export function confirmsInviteAddress(confirm: string, targetEmail: string): boolean {
  return confirm === targetEmail;
}

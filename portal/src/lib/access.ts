// Stored-group helpers for the admin pages.

import type { Identity } from './types';
import { decideAccess } from './gate';
import { IDENTITY_GROUPS } from './constants';

/** Identity groups first in IDENTITY_GROUPS order, then the rest alphabetically; position carries no meaning. */
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

/** An admin account is never sent a recovery code. Pass an admin-API identity: public whoami strips metadata_admin. */
export function shouldRefuseRecovery(identity: Identity | undefined | null): boolean {
  return 'deny' in decideAccess(identity, 'emailed-code', null);
}

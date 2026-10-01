// Second-factor step-up for app sign-in and forward-auth: a session below aal2
// steps up when the identity holds a second factor (parseIdentity), the admin marker or a role above an app's entry
// role. The identity must come from the admin API (getIdentity); a missing AAL counts as below aal2.

import type { Identity, Session } from './types';
import type { ClientManifest } from './manifests';
import { parseIdentity } from './identity-facts';
import { lookupRole } from './claims';
import { servingManifests } from './manifest-store';

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

export function needsStepUp(
  session: Pick<Session, 'authenticator_assurance_level'> | null | undefined,
  identity: Identity | null | undefined,
): boolean {
  if (session?.authenticator_assurance_level === 'aal2') return false;
  const facts = parseIdentity(identity);
  return facts.isAdmin || facts.hasSecondFactor || holdsElevatedRole(identity);
}

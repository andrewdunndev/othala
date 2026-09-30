// Group registry: a group's type comes from its bindings, never its name.
// `identity`: listed in OTHALA_IDENTITY_GROUPS. `access`: a manifest's
// `accessGroups` binds it. `role`: a manifest's `group_role_map` references it.
// A group can carry several kinds; derived from the cached manifests plus env
// groups, it feeds the admin UI split and the lint.

import type { ClientManifest } from './manifests';
import { identityGroups as envIdentityGroups } from './config';
import { servingManifests } from './manifest-store';
import { GROUP_RE } from './access-groups';

export type GroupKind = 'identity' | 'access' | 'role';

export interface GroupEntry {
  name: string;
  kinds: Set<GroupKind>;
  /** clientIds whose manifest `accessGroups` lists this group. */
  accessFor: string[];
  /** clientIds whose `group_role_map` references this group as a key. */
  roleFor: string[];
}

export type GroupRegistry = Map<string, GroupEntry>;

/** Get-or-create the entry for `name`, mutated in place by the builder. */
function entryFor(reg: GroupRegistry, name: string): GroupEntry {
  let e = reg.get(name);
  if (!e) {
    e = { name, kinds: new Set(), accessFor: [], roleFor: [] };
    reg.set(name, e);
  }
  return e;
}

/**
 * Build the registry: seed `identity` from OTHALA_IDENTITY_GROUPS, then per
 * manifest mark `accessGroups[]` entries `access` and `group_role_map` keys
 * `role`. A group's type is the union of its bindings. Prefer the memoized
 * getGroupRegistry().
 */
export function buildGroupRegistry(
  manifests: ClientManifest[],
  identityGroupNames: readonly string[],
): GroupRegistry {
  const reg: GroupRegistry = new Map();

  for (const name of identityGroupNames) {
    entryFor(reg, name).kinds.add('identity');
  }

  for (const m of manifests) {
    for (const g of m.accessGroups) {
      const e = entryFor(reg, g);
      e.kinds.add('access');
      if (!e.accessFor.includes(m.clientId)) e.accessFor.push(m.clientId);
    }
    for (const g of Object.keys(m.groupRoleMap)) {
      const e = entryFor(reg, g);
      e.kinds.add('role');
      if (!e.roleFor.includes(m.clientId)) e.roleFor.push(m.clientId);
    }
  }

  return reg;
}

// Memoized on the servingManifests() array identity: the same reference while
// the manifest cache is warm (and through a load failure), a fresh one on
// reload. It reads the serving set, not the strict loader, so a broken manifest
// cannot 500 the pages the operator uses to see that it is broken.
let memoManifests: ClientManifest[] | null = null;
let memoRegistry: GroupRegistry | null = null;

/** The registry for the served manifest set, memoized on the servingManifests() array identity. Never throws. */
export function getGroupRegistry(): GroupRegistry {
  const manifests = servingManifests();
  if (memoRegistry !== null && memoManifests === manifests) {
    return memoRegistry;
  }
  memoRegistry = buildGroupRegistry(manifests, envIdentityGroups);
  memoManifests = manifests;
  return memoRegistry;
}

/** True when the registry types `name` as (at least) an identity group. */
export function isIdentityGroup(reg: GroupRegistry, name: string): boolean {
  return reg.get(name)?.kinds.has('identity') ?? false;
}

/** True when the registry types `name` as (at least) an access group. */
export function isAccessGroup(reg: GroupRegistry, name: string): boolean {
  return reg.get(name)?.kinds.has('access') ?? false;
}

/**
 * Every group name with any binding. The lint cross-checks manifest references
 * against a caller-supplied baseline to flag a typo'd group that would lock
 * everyone out.
 */
export function knownGroupNames(reg: GroupRegistry): Set<string> {
  return new Set(reg.keys());
}

/** Every group name typed `kind`, sorted. */
export function namesOfKind(reg: GroupRegistry, kind: GroupKind): string[] {
  return Array.from(reg.values())
    .filter((e) => e.kinds.has(kind))
    .map((e) => e.name)
    .sort();
}

/**
 * Stored groups the admin edit form offers no checkbox for: canonical names
 * that are neither a configured identity group nor bound for access by any
 * served manifest (a role-only binding, or a group whose config was removed).
 * The save carries these through unless the operator removes one explicitly.
 */
export function unconfiguredGroups(reg: GroupRegistry, stored: readonly string[]): string[] {
  return stored.filter((g) => GROUP_RE.test(g) && !isIdentityGroup(reg, g) && !isAccessGroup(reg, g));
}

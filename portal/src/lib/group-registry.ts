// Group registry: a group's type comes from its bindings, never its name.
// `identity`: one of IDENTITY_GROUPS (constants.ts). `access`: a manifest's
// `accessGroups` binds it. `role`: a manifest's `group_role_map` references it.
// A group can carry several kinds; derived from the manifests plus the fixed
// identity groups, it feeds the admin UI split and the lint.

import type { ClientManifest } from './manifests';
import { GROUP_RE } from './access-groups';

export type GroupKind = 'identity' | 'access' | 'role';

export interface GroupEntry {
  name: string;
  kinds: Set<GroupKind>;
}

export type GroupRegistry = Map<string, GroupEntry>;

/** Get-or-create the entry for `name`, mutated in place by the builder. */
function entryFor(reg: GroupRegistry, name: string): GroupEntry {
  let e = reg.get(name);
  if (!e) {
    e = { name, kinds: new Set() };
    reg.set(name, e);
  }
  return e;
}

/**
 * Build the registry: seed `identity` from the fixed identity groups, then per
 * manifest mark `accessGroups[]` entries `access` and `group_role_map` keys
 * `role`. A group's type is the union of its bindings.
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
    for (const g of m.accessGroups) entryFor(reg, g).kinds.add('access');
    for (const g of Object.keys(m.groupRoleMap)) entryFor(reg, g).kinds.add('role');
  }

  return reg;
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

/**
 * Stored groups the admin edit form offers no checkbox for: canonical names
 * that are neither a configured identity group nor bound for access by any
 * served manifest (a role-only binding, or a group whose config was removed).
 * The save carries these through unless the operator removes one explicitly.
 */
export function unconfiguredGroups(reg: GroupRegistry, stored: readonly string[]): string[] {
  return stored.filter((g) => GROUP_RE.test(g) && !isIdentityGroup(reg, g) && !isAccessGroup(reg, g));
}

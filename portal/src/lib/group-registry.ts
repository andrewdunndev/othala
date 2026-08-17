// Group registry — the derived type-tag for groups.
//
// Earlier revisions inferred a group's *type* (identity / access / role) from
// its NAME: anything matching `access-*` was treated as an access group,
// everything else as an identity group. That overloaded the `access-` prefix as
// both a naming convention AND a runtime discriminator. This registry retires
// that hidden duty: a group's type comes from its BINDINGS, never its name.
//
//   - `identity` — the group is listed in OTHALA_IDENTITY_GROUPS (env).
//   - `access`   — some manifest's `accessGroups` binds it (grants entry).
//   - `role`     — some manifest's `group_role_map` references it (grants role).
//
// A single group can carry multiple kinds (e.g. `family` could be an identity
// group that is ALSO bound for access by an app). The registry is the one
// source of truth for: the admin-UI identity/access column split, the lint's
// known-group set, and admin discoverability (Group → Apps).
//
// It is derived purely from the already-cached manifest set + the env identity
// groups, so it is cheap to rebuild; callers memoize on the manifest cache key
// (see getGroupRegistry) to avoid recomputing per request.

import type { ClientManifest } from './manifests';
import { identityGroups as envIdentityGroups } from './config';
import { servingManifests } from './manifest-store';

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
 * Build the registry from the manifest set + the configured identity groups.
 *
 * Seeds the `identity` kind from `OTHALA_IDENTITY_GROUPS`; then, per manifest,
 * marks every `accessGroups[]` entry as `access` (recording the clientId in
 * `accessFor`) and every `group_role_map` key as `role` (recording it in
 * `roleFor`). A group's type is the UNION of its bindings — never its name.
 *
 * O(M×G); cheap enough to rebuild, but callers should prefer getGroupRegistry()
 * which memoizes on the manifest cache key.
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

// ── memoized accessor ─────────────────────────────────────────────────────
//
// The registry is a pure function of (manifest set, env identity groups). The
// env groups are fixed for the process lifetime, so we memoize on the manifest
// array identity: servingManifests() returns the SAME array reference while the
// underlying 30s/mtime cache is warm and a FRESH one on reload, so an identity
// compare is a correct, allocation-free cache key. It also holds one reference
// steady for the whole duration of a load failure (the last known good set, or
// the empty set), so a broken manifest does not thrash this memo.
//
// The registry reads the SERVING set (lib/manifest-store.ts), not the strict
// loader: /auth/settings and three admin pages render from it, and a manifest
// the operator broke a moment ago must not 500 the page they would use to see
// that it is broken.

let memoManifests: ClientManifest[] | null = null;
let memoRegistry: GroupRegistry | null = null;

/**
 * The registry for the currently served manifest set, memoized on the manifest
 * cache key (the servingManifests() array identity). Rebuilds transparently
 * when the manifest cache turns over. Never throws.
 */
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
 * The set of all KNOWN group names — every group the registry has any binding
 * for. The lint cross-checks manifest references against this set to flag a
 * typo'd group that would silently lock everyone out (fail-closed). A group
 * known ONLY because a manifest references it (access/role) is still "known";
 * the lint's job is to catch names referenced by NO binding at all relative to
 * a caller-supplied baseline (see lintManifests).
 */
export function knownGroupNames(reg: GroupRegistry): Set<string> {
  return new Set(reg.keys());
}

// App access as app x level, the admin's whole vocabulary for who can use what. Storage stays groups and role overrides
// (metadata_admin); this module maps between the two and never reads or writes Kratos. Levels run from least to most
// privilege (manifests declare roles most-privileged first). `none` is no access; an app with no roles offers `use`.

import type { ClientManifest } from './manifests';
import { lookupRole } from './claims';
import { DEFAULT_GROUP, IDENTITY_GROUPS } from './constants';

export const NO_ACCESS = 'none';
export const CAN_USE = 'use';

export interface AccessLevel {
  value: string;
  label: string;
  hint: string;
}

export interface AccessStored {
  groups: readonly string[];
  roles: Readonly<Record<string, string>>;
}

const IDENTITY = new Set<string>(IDENTITY_GROUPS);

function capitalise(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Open to everyone: the default group enters it (or the gate is off), so no per-person level applies. */
export function isOpenToEveryone(m: ClientManifest): boolean {
  return m.skipAccessCheck || m.accessGroups.includes(DEFAULT_GROUP);
}

/** The levels above No access, least to most privilege, each with its role description as a hint. */
export function levelsFor(m: ClientManifest): AccessLevel[] {
  if (m.roles.length === 0) return [{ value: CAN_USE, label: 'Can use', hint: '' }];
  return [...m.roles].reverse().map((r) => ({ value: r.name, label: capitalise(r.name), hint: r.description }));
}

/** The level a person effectively holds on an app: `none` without access, else the resolved role (the lowest when the
 *  access group carries no role). */
export function currentLevel(m: ClientManifest, meta: { groups?: string[]; roles?: Record<string, string> } | undefined): string {
  const groups = meta?.groups ?? [];
  if (!(m.skipAccessCheck || m.accessGroups.some((g) => groups.includes(g)))) return NO_ACCESS;
  if (m.roles.length === 0) return CAN_USE;
  return lookupRole(m, meta)?.roleName ?? levelsFor(m)[0].value;
}

/** True when `level` is the highest the app offers (and the app has roles to rank). */
export function isTopLevel(m: ClientManifest, level: string): boolean {
  return m.roles.length > 1 && level === m.roles[0].name;
}

/** The group that holds `level` by group_role_map, when one exists outside the identity groups. */
function roleGroup(m: ClientManifest, level: string): string | undefined {
  return Object.keys(m.groupRoleMap).find((g) => m.groupRoleMap[g] === level && !IDENTITY.has(g));
}

/** The app's own groups: its access groups and the groups its role map names, minus the household identity groups. */
function appGroups(m: ClientManifest): string[] {
  return [...new Set([...m.accessGroups, ...Object.keys(m.groupRoleMap)])].filter((g) => !IDENTITY.has(g));
}

export interface AccessStorage {
  groups: string[];
  roles: Record<string, string>;
}

/**
 * Turn the submitted app -> level choices into storage. Only apps whose choice differs from their current level are
 * rewritten: their groups and role override are cleared first (a contradicting override never survives), then the level
 * is stored as the lowest level (access group), a mapped level (access group plus its role group) or any other level
 * (access group plus a role override). Groups an unchanged app still relies on are never removed. Unknown apps and
 * levels are ignored, and apps open to everyone are not editable here.
 */
export function accessToStorage(
  manifests: readonly ClientManifest[],
  choices: Readonly<Record<string, string>>,
  stored: AccessStored,
): AccessStorage {
  const meta = { groups: [...stored.groups], roles: { ...stored.roles } };
  const changed: ClientManifest[] = [];
  const unchanged: ClientManifest[] = [];
  for (const m of manifests) {
    const choice = choices[m.clientId];
    const valid = choice === NO_ACCESS || levelsFor(m).some((l) => l.value === choice);
    if (isOpenToEveryone(m) || choice === undefined || !valid || choice === currentLevel(m, meta)) {
      unchanged.push(m);
    } else {
      changed.push(m);
    }
  }

  const relied = new Set<string>();
  for (const m of unchanged) {
    if (!isOpenToEveryone(m) && currentLevel(m, meta) !== NO_ACCESS) for (const g of appGroups(m)) relied.add(g);
  }
  const cleared = new Set<string>();
  for (const m of changed) for (const g of appGroups(m)) if (!relied.has(g)) cleared.add(g);

  const groups = new Set(meta.groups.filter((g) => !cleared.has(g)));
  const roles = { ...meta.roles };
  for (const m of changed) {
    delete roles[m.clientId];
    const level = choices[m.clientId];
    if (level === NO_ACCESS) continue;
    const access = m.accessGroups.find((g) => !IDENTITY.has(g));
    if (access) groups.add(access);
    if (level === levelsFor(m)[0].value) continue;
    const mapped = roleGroup(m, level);
    if (mapped) groups.add(mapped);
    else roles[m.clientId] = level;
  }
  return { groups: [...groups], roles };
}

/** The app -> level choices a form posted as `level:<clientId>` fields. */
export function choicesFromForm(fd: FormData): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of fd.entries()) {
    if (key.startsWith('level:') && typeof value === 'string') out[key.slice('level:'.length)] = value;
  }
  return out;
}

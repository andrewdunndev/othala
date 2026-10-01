// What the admin pages show about people and apps, in household words. Pure: pages hand in identities, manifests and
// tiles, so the vocabulary rules (names, chips, badges, filters) are testable without Kratos or the filesystem.

import type { ClientManifest } from './manifests';
import type { AppTile } from './tiles';
import type { Identity } from './types';
import { HOUSEHOLD_GROUPS, IDENTITY_GROUPS } from './constants';
import { GROUP_RE } from './access-groups';
import { currentLevel, isOpenToEveryone, isTopLevel, levelsFor, NO_ACCESS } from './access-rows';
import { isAdminMarker } from './admin-auth';

export const ADMIN_NAV = [
  { href: '/admin/users', label: 'People' },
  { href: '/admin/oauth2', label: 'Apps' },
];

/** The one error string for a people read that failed. */
export const PEOPLE_LOAD_ERROR = "Couldn't load people. Check that the sign-in service is running, then reload.";

/** People past this many get a search box and a Show filter; fewer get just the list. */
export const FILTER_THRESHOLD = 8;

/** Chips on a row before the rest fold into +N. */
export const CHIP_LIMIT = 3;

export interface AdminApp {
  clientId: string;
  slug: string;
  name: string;
  description: string;
  url: string;
  tile?: AppTile;
  manifest: ClientManifest;
}

/** Join each served manifest to its tile by file stem; a manifest without a tile still reads by its client name. */
export function joinApps(manifests: readonly ClientManifest[], tiles: readonly AppTile[]): AdminApp[] {
  const bySlug = new Map(tiles.map((t) => [t.slug, t] as const));
  return manifests.map((manifest) => {
    const slug = (manifest.sourcePath || manifest.clientId).replace(/^.*\//, '').replace(/\.ya?ml$/, '');
    const tile = bySlug.get(slug);
    return {
      clientId: manifest.clientId,
      slug,
      name: tile?.name || manifest.clientName || manifest.clientId,
      description: tile?.description ?? '',
      url: tile?.url ?? '',
      tile,
      manifest,
    };
  });
}

/** The name people go by: display name, else username, else the id. */
export function personName(i: Identity): string {
  const t = i.traits as { displayName?: string; username?: string } | undefined;
  return t?.displayName?.trim() || t?.username || i.id;
}

/** True when the email trait's own address is verified (case-insensitive); anything else reads as unverified. */
export function emailIsVerified(i: Identity): boolean {
  const email = String((i.traits as { email?: unknown } | undefined)?.email ?? '').toLowerCase();
  return (i.verifiable_addresses ?? []).some((a) => a.verified === true && String(a.value).toLowerCase() === email);
}

/** Every group a served app binds: access groups and role-map groups. */
export function appGroupNames(manifests: readonly ClientManifest[]): Set<string> {
  const out = new Set<string>();
  for (const m of manifests) {
    for (const g of m.accessGroups) out.add(g);
    for (const g of Object.keys(m.groupRoleMap)) out.add(g);
  }
  return out;
}

/** Stored groups nothing uses: not a household or identity group, not bound by any served app, or not a valid name at all. */
export function unrecognisedGroups(i: Identity, manifests: readonly ClientManifest[]): string[] {
  const known = appGroupNames(manifests);
  const identity = new Set<string>(IDENTITY_GROUPS);
  return (i.metadata_admin?.groups ?? []).filter((g) => !GROUP_RE.test(g) || (!identity.has(g) && !known.has(g)));
}

export interface AppChip {
  name: string;
  /** Holds the app's highest level. */
  top: boolean;
}

/** Apps this person can use, by name, with their level where it is the highest the app offers. */
export function appChips(i: Identity, apps: readonly AdminApp[]): AppChip[] {
  const chips: AppChip[] = [];
  for (const a of apps) {
    const m = a.manifest;
    if (isOpenToEveryone(m)) {
      chips.push({ name: a.name, top: false });
      continue;
    }
    const level = currentLevel(m, i.metadata_admin);
    if (level !== NO_ACCESS) chips.push({ name: a.name, top: isTopLevel(m, level) });
  }
  return chips;
}

export interface PersonRow {
  id: string;
  name: string;
  /** Username and email, muted under the name. */
  sub: string;
  chips: AppChip[];
  admin: boolean;
  off: boolean;
  verified: boolean;
  unrecognised: string[];
  /** Client ids of the apps they can use, for the Show filter. */
  appIds: string[];
  /** Lowercase text the search box matches. */
  haystack: string;
}

export function personRow(i: Identity, apps: readonly AdminApp[]): PersonRow {
  const t = i.traits as { username?: string; email?: string; displayName?: string } | undefined;
  const chips = appChips(i, apps);
  const appIds = apps
    .filter((a) => isOpenToEveryone(a.manifest) || currentLevel(a.manifest, i.metadata_admin) !== NO_ACCESS)
    .map((a) => a.clientId);
  return {
    id: i.id,
    name: personName(i),
    sub: [t?.username, t?.email].filter(Boolean).join(' · '),
    chips,
    admin: isAdminMarker(i),
    off: i.state === 'inactive',
    verified: emailIsVerified(i),
    unrecognised: unrecognisedGroups(i, apps.map((a) => a.manifest)),
    appIds,
    haystack: [t?.displayName, t?.username, t?.email].filter(Boolean).join(' ').toLowerCase(),
  };
}

/** Rows sorted by name, so the list reads the same on every load. */
export function personRows(identities: readonly Identity[], apps: readonly AdminApp[]): PersonRow[] {
  return identities.map((i) => personRow(i, apps)).sort((a, b) => a.name.localeCompare(b.name));
}

export interface ShowOption {
  value: string;
  label: string;
}

/** The Show select: Everyone, Household admins, No apps yet, Sign-in off, then one "Can use <app>" per app. */
export function showOptions(apps: readonly AdminApp[]): ShowOption[] {
  return [
    { value: 'all', label: 'Everyone' },
    { value: 'admins', label: 'Household admins' },
    { value: 'noapps', label: 'No apps yet' },
    { value: 'off', label: 'Sign-in off' },
    ...apps.map((a) => ({ value: `app:${a.clientId}`, label: `Can use ${a.name}` })),
  ];
}

/** The search and Show filter both the server render and the live script apply. An unknown Show value shows everyone. */
export function rowMatches(row: PersonRow, q: string, show: string): boolean {
  const needle = q.trim().toLowerCase();
  if (needle && !row.haystack.includes(needle)) return false;
  if (show === 'admins') return row.admin;
  if (show === 'noapps') return row.chips.length === 0;
  if (show === 'off') return row.off;
  if (show.startsWith('app:')) return row.appIds.includes(show.slice('app:'.length));
  return true;
}

export interface Attention {
  text: string;
  /** People it concerns, each linking to their page. */
  people: { id: string; name: string }[];
}

/** Things worth a look above the list, only when true. Catalog health is the page's own notice. */
export function attentionItems(rows: readonly PersonRow[]): Attention[] {
  const items: Attention[] = [];
  const noApps = rows.filter((r) => r.chips.length === 0 && !r.off);
  if (noApps.length > 0) items.push({ text: 'Has no apps yet', people: noApps.map(({ id, name }) => ({ id, name })) });
  const stray = rows.filter((r) => r.unrecognised.length > 0);
  if (stray.length > 0) items.push({ text: 'Has a group no app uses', people: stray.map(({ id, name }) => ({ id, name })) });
  return items;
}

/** Plain access-level label for a person's level on an app, e.g. for the app page's "Who can use it" chips. */
export function levelLabel(m: ClientManifest, level: string): string {
  return levelsFor(m).find((l) => l.value === level)?.label ?? level;
}

/** The household groups a person page offers, with a plain label. */
export function householdChoices(): { value: string; label: string }[] {
  return HOUSEHOLD_GROUPS.map((g) => ({ value: g, label: g === 'everyone' ? 'Everyone in the household' : g }));
}

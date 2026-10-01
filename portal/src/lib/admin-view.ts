// What the admin pages show about people and apps, in household words. Pure: pages hand in identities, manifests and
// tiles, so the vocabulary rules (names, chips, badges, filters) are testable without Kratos or the filesystem.

import type { ClientManifest } from './manifests';
import type { AppTile } from './tiles';
import type { Identity } from './types';
import { HOUSEHOLD_GROUPS, IDENTITY_GROUPS } from './constants';
import { GROUP_RE } from './access-groups';
import { currentLevel, isOpenToEveryone, isTopLevel, levelsFor, NO_ACCESS } from './access-rows';
import { parseIdentity } from './identity-facts';

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
  /** For the logo beside the name; absent reads as a monogram. */
  tile?: AppTile;
}

/** Apps this person was given, by name, with their level where it is the highest the app offers. Apps open to everyone are not listed. */
export function appChips(i: Identity, apps: readonly AdminApp[]): AppChip[] {
  const chips: AppChip[] = [];
  for (const a of apps) {
    const m = a.manifest;
    if (isOpenToEveryone(m)) continue;
    const level = currentLevel(m, i.metadata_admin);
    if (level !== NO_ACCESS) chips.push({ name: a.name, top: isTopLevel(m, level), tile: a.tile });
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
    admin: parseIdentity(i).isAdmin,
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
  /** Page section the link lands on, when the thing to fix sits below the top. */
  anchor?: string;
  /** People it concerns, each linking to their page. */
  people: { id: string; name: string }[];
}

/** Things worth a look above the list, only when true. Catalog health is the page's own notice. */
export function attentionItems(rows: readonly PersonRow[]): Attention[] {
  const items: Attention[] = [];
  const noApps = rows.filter((r) => r.chips.length === 0 && !r.off);
  if (noApps.length > 0) items.push({ text: 'Has no apps yet', people: noApps.map(({ id, name }) => ({ id, name })) });
  const stray = rows.filter((r) => r.unrecognised.length > 0);
  if (stray.length > 0) items.push({ text: 'Belongs to a group no app uses', anchor: 'groups', people: stray.map(({ id, name }) => ({ id, name })) });
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

const USERNAME_SHAPE = /^[a-z0-9]+(?:\.[a-z0-9]+)+$/;

/** A username suggested from the name (first.last) or, for one word, from the email's local part; empty when neither fits the rule. */
export function suggestUsername(name: string, email: string): string {
  const words = name
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .split(/\s+/)
    .map((w) => w.replace(/[^a-z0-9]/g, ''))
    .filter(Boolean);
  if (words.length > 1) return words.join('.');
  const local = email.split('@')[0].toLowerCase();
  return USERNAME_SHAPE.test(local) ? local : '';
}

/** A Kratos duration like `24h` or `30m` in words, for the expiry line; anything else is shown as written. */
export function describeTtl(ttl: string): string {
  const m = /^(\d+)([hm])$/.exec(ttl);
  if (!m) return ttl;
  const n = Number(m[1]);
  const unit = m[2] === 'h' ? 'hour' : 'minute';
  return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

export interface SignInMethod {
  /** The Kratos credential type, which is also what an admin removal posts. */
  key: string;
  label: string;
  /** Plain status in the account page's words: Set, Not set, a count, Saved. */
  value: string;
  enrolled: boolean;
}

function configOf(i: Identity, key: string): Record<string, unknown> | undefined {
  const c = (i.credentials as Record<string, { config?: Record<string, unknown> } | undefined> | undefined)?.[key];
  return c ? (c.config ?? {}) : undefined;
}

/** Stored passkeys; only a credentials array counts, so an empty entry is no key. */
function passkeyCount(i: Identity): number {
  const keys = configOf(i, 'passkey')?.credentials;
  return Array.isArray(keys) ? keys.length : 0;
}

/** How a person signs in, one row per method, in the words of the account settings page. */
export function signInMethods(i: Identity): SignInMethod[] {
  const passkeys = passkeyCount(i);
  const keys = parseIdentity(i).securityKeys;
  const password = configOf(i, 'password');
  const passwordSet = password !== undefined && (Object.keys(password).length === 0 || Boolean(password.hashed_password));
  const totp = parseIdentity(i).authenticator;
  const codes = configOf(i, 'lookup_secret') !== undefined;
  return [
    { key: 'passkey', label: 'Passkeys', value: passkeys > 0 ? String(passkeys) : 'None', enrolled: passkeys > 0 },
    { key: 'password', label: 'Password', value: passwordSet ? 'Set' : 'Not set', enrolled: passwordSet },
    { key: 'totp', label: 'Authenticator app', value: totp ? 'Set' : 'Not set', enrolled: totp },
    { key: 'webauthn', label: 'Security keys', value: keys > 0 ? String(keys) : 'None', enrolled: keys > 0 },
    { key: 'lookup_secret', label: 'Backup codes', value: codes ? 'Saved' : 'Not saved', enrolled: codes },
  ];
}

export interface PersonLimits {
  /** Why "Make household admin" is not offered, or null when it is. */
  grant: string | null;
  /** Why "Remove household admin" is not offered, or null when it is. */
  revoke: string | null;
  /** Why "Turn off sign-in" is not offered, or null when it is. */
  deactivate: string | null;
}

/** The refusals the server would give, as reasons the page shows instead of the action. */
export function personLimits(i: Identity, o: { first: string; isSelf: boolean; lastAdmin: boolean }): PersonLimits {
  const only = o.isSelf ? "You're the only household admin." : `${o.first} is the only household admin.`;
  return {
    grant: parseIdentity(i).hasSecondFactor ? null : `Needs an authenticator app or security key first. Send a setup link so ${o.first} can add one.`,
    revoke: o.lastAdmin ? `${only} Make someone else an admin first.` : null,
    deactivate: o.isSelf
      ? "You can't turn off your own sign-in. Ask another admin."
      : o.lastAdmin
        ? `${only} Make someone else an admin first.`
        : null,
  };
}

/** Why a sign-in method can't be removed (it is an admin's last second factor), or null when it can. */
export function removalBlock(i: Identity, credType: string, isSelf: boolean): string | null {
  if (!isSelf && !parseIdentity(i).isAdmin) return null;
  const creds = { ...((i.credentials ?? {}) as Record<string, unknown>) };
  delete creds[credType];
  if (parseIdentity({ ...i, credentials: creds as Identity['credentials'] }).hasSecondFactor) return null;
  return 'Admins keep at least one authenticator app or security key.';
}

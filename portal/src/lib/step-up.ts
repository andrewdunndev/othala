// Second-factor step-up for app sign-in and forward-auth: a session below aal2
// steps up when the identity holds a second factor, the admin marker or a role above an app's entry role. Count
// what Kratos counts: a totp entry with a totp_url, or a webauthn entry with a
// non-passwordless key (an empty webauthn entry is not enrolment). The identity
// must come from the admin API (getIdentity); a missing AAL counts as below aal2.

import type { Identity, Session } from './types';
import type { ClientManifest } from './manifests';
import { isAdminMarker } from './admin-auth';
import { lookupRole } from './claims';
import { servingManifests } from './manifest-store';

function configOf(creds: Record<string, unknown>, type: string): Record<string, unknown> | null {
  const cred = creds[type] as { config?: unknown } | undefined;
  const config = cred?.config;
  return config && typeof config === 'object' && !Array.isArray(config) ? (config as Record<string, unknown>) : null;
}

function totpEnrolled(creds: Record<string, unknown>): boolean {
  const url = configOf(creds, 'totp')?.['totp_url'];
  return typeof url === 'string' && url.length > 0;
}

function webauthnEnrolled(creds: Record<string, unknown>): boolean {
  const keys = configOf(creds, 'webauthn')?.['credentials'];
  return Array.isArray(keys) && keys.some((k) => Boolean(k) && (k as { is_passwordless?: unknown }).is_passwordless !== true);
}

/** How many security keys (non-passwordless webauthn credentials) count as a second factor. */
export function securityKeyCount(identity: Identity | null | undefined): number {
  const creds = identity?.credentials as Record<string, unknown> | undefined;
  if (!creds || typeof creds !== 'object') return 0;
  const keys = configOf(creds, 'webauthn')?.['credentials'];
  return Array.isArray(keys) ? keys.filter((k) => Boolean(k) && (k as { is_passwordless?: unknown }).is_passwordless !== true).length : 0;
}

/** True when an authenticator app is enrolled (a totp entry with its url). */
export function authenticatorEnrolled(identity: Identity | null | undefined): boolean {
  const creds = identity?.credentials as Record<string, unknown> | undefined;
  return !!creds && typeof creds === 'object' && totpEnrolled(creds);
}

/** True when the identity has a totp or webauthn second factor enrolled. */
export function hasSecondFactor(identity: Identity | null | undefined): boolean {
  const creds = identity?.credentials as Record<string, unknown> | undefined;
  if (!creds || typeof creds !== 'object') return false;
  return totpEnrolled(creds) || webauthnEnrolled(creds);
}

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
  return isAdminMarker(identity) || hasSecondFactor(identity) || holdsElevatedRole(identity);
}

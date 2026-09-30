// Second-factor step-up for app sign-in and forward-auth: a session below aal2
// steps up when the identity holds a second factor or the admin marker. Count
// what Kratos counts: a totp entry with a totp_url, or a webauthn entry with a
// non-passwordless key (an empty webauthn entry is not enrolment). The identity
// must come from the admin API (getIdentity); a missing AAL counts as below aal2.

import type { Identity, Session } from './types';
import { isAdminMarker } from './admin-auth';

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

/** True when the identity has a totp or webauthn second factor enrolled. */
export function hasSecondFactor(identity: Identity | null | undefined): boolean {
  const creds = identity?.credentials as Record<string, unknown> | undefined;
  if (!creds || typeof creds !== 'object') return false;
  return totpEnrolled(creds) || webauthnEnrolled(creds);
}

export function needsStepUp(
  session: Pick<Session, 'authenticator_assurance_level'> | null | undefined,
  identity: Identity | null | undefined,
): boolean {
  if (session?.authenticator_assurance_level === 'aal2') return false;
  return isAdminMarker(identity) || hasSecondFactor(identity);
}

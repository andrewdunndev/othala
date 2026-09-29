// Second-factor step-up for app sign-in and forward-auth.
//
// A session below aal2 must step up when the identity holds a second factor
// (totp or webauthn) or carries the admin marker. Passkey, password, email
// code and backup codes alone never force a step-up: backup codes are a
// recovery path for a second factor, not one to be asked for on their own.
//
// A key in the credentials map is not an enrolment. The identity schema marks
// the username and email as webauthn identifiers, so Kratos keeps a webauthn
// entry with an empty config on every identity. The checks below count what
// Kratos itself counts as a second factor: a totp entry with a totp_url, and a
// webauthn entry holding at least one key that is not passwordless.
//
// The identity MUST come from the admin API with the totp and webauthn
// configs included (lib/admin-api.ts getIdentity); credentials and
// metadata_admin are absent from /sessions/whoami. A missing AAL counts as
// below aal2.

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

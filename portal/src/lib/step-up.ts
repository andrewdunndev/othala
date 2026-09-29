// Second-factor step-up for app sign-in and forward-auth.
//
// A session below aal2 must step up when the identity holds a second factor
// (totp or webauthn) or carries the admin marker. Passkey, password, email
// code and backup codes alone never force a step-up: backup codes are a
// recovery path for a second factor, not one to be asked for on their own.
//
// The identity MUST come from the admin API (credentials and metadata_admin
// are absent from /sessions/whoami). A missing AAL counts as below aal2.

import type { Identity, Session } from './types';
import { isAdminMarker } from './admin-auth';

const SECOND_FACTORS = ['totp', 'webauthn'] as const;

/** True when the identity has a totp or webauthn credential enrolled. */
export function hasSecondFactor(identity: Identity | null | undefined): boolean {
  const creds = identity?.credentials as Record<string, unknown> | undefined;
  if (!creds || typeof creds !== 'object') return false;
  return SECOND_FACTORS.some((t) => Boolean(creds[t]));
}

export function needsStepUp(
  session: Pick<Session, 'authenticator_assurance_level'> | null | undefined,
  identity: Identity | null | undefined,
): boolean {
  if (session?.authenticator_assurance_level === 'aal2') return false;
  return isAdminMarker(identity) || hasSecondFactor(identity);
}

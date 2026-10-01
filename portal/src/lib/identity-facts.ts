// The one read of a Kratos identity that every gate decides from. Hand it an identity from the admin API
// (getIdentity): /sessions/whoami strips metadata_admin and credentials, so a whoami identity reads as a non-admin
// with no factors. Every read is fail-closed on a malformed shape.

import type { Identity } from './types';

export interface IdentityFacts {
  state: string | undefined;
  /** `metadata_admin.admin === true` (strict), the sole admin authority; no group grants it. */
  isAdmin: boolean;
  /** `metadata_admin.groups`, strings only, as stored (canonical or not). */
  groups: string[];
  /** An authenticator app: a totp entry with its totp_url. */
  authenticator: boolean;
  /** Security keys: webauthn keys that are not passwordless (an empty webauthn entry is not enrolment). */
  securityKeys: number;
  /** What Kratos counts as a second factor: an authenticator app or a security key. */
  hasSecondFactor: boolean;
  /**
   * A password hash, a passkey, or a passwordless webauthn key. Kratos keeps a password and a webauthn entry with an
   * empty config on every identity (schema identifiers), so an entry alone is not a key. Missing credentials count as
   * keyed: the read did not carry them.
   */
  firstFactorKey: boolean;
}

function plainObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function configOf(creds: Record<string, unknown>, type: string): Record<string, unknown> | null {
  return plainObject((creds[type] as { config?: unknown } | undefined)?.config);
}

function keysOf(creds: Record<string, unknown>, type: string): Array<{ is_passwordless?: unknown }> {
  const keys = configOf(creds, type)?.['credentials'];
  return Array.isArray(keys) ? keys.filter(Boolean) : [];
}

export function parseIdentity(identity: Identity | null | undefined): IdentityFacts {
  const meta = plainObject(identity?.metadata_admin);
  const rawGroups = meta?.['groups'];
  const rawCreds = identity?.credentials;
  const creds = plainObject(rawCreds);
  const totpUrl = creds ? configOf(creds, 'totp')?.['totp_url'] : undefined;
  const authenticator = typeof totpUrl === 'string' && totpUrl.length > 0;
  const webauthn = creds ? keysOf(creds, 'webauthn') : [];
  const securityKeys = webauthn.filter((k) => k.is_passwordless !== true).length;
  const hash = creds ? configOf(creds, 'password')?.['hashed_password'] : undefined;
  return {
    state: identity?.state,
    isAdmin: meta?.['admin'] === true,
    groups: Array.isArray(rawGroups) ? rawGroups.filter((g): g is string => typeof g === 'string') : [],
    authenticator,
    securityKeys,
    hasSecondFactor: authenticator || securityKeys > 0,
    firstFactorKey:
      !rawCreds ||
      typeof rawCreds !== 'object' ||
      (typeof hash === 'string' && hash.length > 0) ||
      (creds !== null && keysOf(creds, 'passkey').length > 0) ||
      webauthn.some((k) => k.is_passwordless === true),
  };
}

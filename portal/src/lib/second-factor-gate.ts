// The Kratos hook context carries neither credentials nor the form, so the verdict assumes the worst removal the method allows.

import type { Identity } from './types';
import type { ClientManifest } from './manifests';
import { parseIdentity } from './identity-facts';
import { holdsElevatedRole } from './gate';

export const SECOND_FACTOR_KEEP = 'Admin accounts keep at least one authenticator app or security key.';
export const SECOND_FACTOR_UNAVAILABLE = 'This change is unavailable right now. Try again later.';

export type SecondFactorVerdict = { refuse: false } | { refuse: true; text: string };

type Creds = Record<string, unknown>;

function withCreds(i: Identity, creds: Creds): Identity {
  return { ...i, credentials: creds as Identity['credentials'] };
}

function without(creds: Creds, type: string): Creds {
  const next = { ...creds };
  delete next[type];
  return next;
}

function removalOutcomes(stored: Identity, creds: Creds, method: 'totp' | 'webauthn'): Creds[] {
  if (method === 'totp') {
    const totpOnly = parseIdentity(withCreds(stored, { totp: creds.totp })).hasSecondFactor;
    return totpOnly ? [without(creds, 'totp')] : [];
  }
  const entry = creds.webauthn as { config?: { credentials?: unknown } } | undefined;
  const keys = entry?.config?.credentials;
  if (!Array.isArray(keys)) return [];
  return keys.map((_, n) => ({
    ...creds,
    webauthn: { ...entry, config: { ...entry!.config, credentials: keys.filter((__, k) => k !== n) } },
  }));
}

export function secondFactorChangeVerdict(
  stored: Identity | null | undefined,
  method: string,
  manifests?: ClientManifest[],
): SecondFactorVerdict {
  if (!stored || typeof stored !== 'object' || (method !== 'totp' && method !== 'webauthn')) {
    return { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
  }
  const facts = parseIdentity(stored);
  if (!facts.isAdmin && !holdsElevatedRole(stored, manifests)) return { refuse: false };
  // An entry without its config means the read omitted credential configs, which proves nothing about enrolment.
  const creds = stored.credentials as Creds | undefined;
  if (!creds || typeof creds !== 'object') return { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
  for (const type of ['totp', 'webauthn']) {
    const entry = creds[type] as { config?: unknown } | undefined;
    if (entry && (!entry.config || typeof entry.config !== 'object')) {
      return { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
    }
  }
  if (!facts.hasSecondFactor) return { refuse: false };
  const losesLast = removalOutcomes(stored, creds, method).some((after) => !parseIdentity(withCreds(stored, after)).hasSecondFactor);
  return losesLast ? { refuse: true, text: SECOND_FACTOR_KEEP } : { refuse: false };
}

// Verdict for the settings.after.totp and settings.after.webauthn web_hooks.
//
// An admin-marked identity keeps at least one second factor through
// self-service settings. Kratos runs the interrupting hook before it persists
// the change, but the hook context carries the identity without credentials
// and not the submitted form, so the verdict works from the stored identity
// (admin API, totp and webauthn configs included) and the method alone:
//
//   totp      Kratos unlinks when a totp is enrolled and links otherwise
//             (selfservice/strategy/totp/settings.go continueSettingsFlow),
//             so the outcome is known.
//   webauthn  the submission either adds a key or removes one of the stored
//             keys, and the hook cannot tell which. Every removal is
//             considered; if any would leave no second factor, the change is
//             refused, so an admin whose only second factor is one security
//             key adds an authenticator app before touching keys.
//
// "Second factor" is hasSecondFactor's: an enrolled totp, or a webauthn key
// that is not passwordless. An identity without one has nothing to keep.

import type { Identity } from './types';
import { isAdminMarker } from './admin-auth';
import { hasSecondFactor } from './step-up';

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

/** Each credential map the submission can produce by removing something. */
function removalOutcomes(stored: Identity, creds: Creds, method: 'totp' | 'webauthn'): Creds[] {
  if (method === 'totp') {
    const totpOnly = hasSecondFactor(withCreds(stored, { totp: creds.totp }));
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

/**
 * Decide whether a totp or webauthn settings change may proceed. `stored` is
 * the identity from the admin API before the change; `method` is the settings
 * method the hook was wired to. Anything unreadable refuses.
 */
export function secondFactorChangeVerdict(stored: Identity | null | undefined, method: string): SecondFactorVerdict {
  if (!stored || typeof stored !== 'object' || (method !== 'totp' && method !== 'webauthn')) {
    return { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
  }
  if (!isAdminMarker(stored)) return { refuse: false };
  // A totp or webauthn entry without its config means the read did not
  // include credential configs, and proves nothing about enrolment.
  const creds = stored.credentials as Creds | undefined;
  if (!creds || typeof creds !== 'object') return { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
  for (const type of ['totp', 'webauthn']) {
    const entry = creds[type] as { config?: unknown } | undefined;
    if (entry && (!entry.config || typeof entry.config !== 'object')) {
      return { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
    }
  }
  if (!hasSecondFactor(stored)) return { refuse: false };
  const losesLast = removalOutcomes(stored, creds, method).some((after) => !hasSecondFactor(withCreds(stored, after)));
  return losesLast ? { refuse: true, text: SECOND_FACTOR_KEEP } : { refuse: false };
}

// Verdicts for the settings.after.profile web_hook: username stays fixed, and an account
// with a passkey or password changes its emails only from a session whose newest
// aal1 sign-in used one of them (an emailed code proves the mailbox, not the
// person); identities with neither are unchanged. Stored identity comes from the
// admin API, authentication_methods from the hook body; missing data on a keyed identity refuses.

import type { Identity } from './types';
import { parseIdentity } from './identity-facts';

export const EMAIL_CHANGE_REFUSAL = 'To change an email address, sign in again with your passkey or password.';

const EMAIL_TRAITS = ['email', 'recoveryEmail'] as const;
const FIRST_FACTOR_METHODS = new Set(['password', 'passkey', 'webauthn']);

export type EmailChangeVerdict = { refuse: false } | { refuse: true; text: string; pointers: string[] };

type AuthMethod = { method?: unknown; aal?: unknown; completed_at?: unknown };

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

/** Method of the newest aal1 entry with a parseable completed_at, or null. */
export function newestFirstFactorMethod(methods: unknown): string | null {
  if (!Array.isArray(methods)) return null;
  let best: { at: number; method: string } | null = null;
  for (const m of methods as AuthMethod[]) {
    if (!m || m.aal !== 'aal1' || typeof m.method !== 'string') continue;
    const raw = m.completed_at;
    const at = raw instanceof Date ? raw.getTime() : typeof raw === 'string' ? Date.parse(raw) : NaN;
    if (Number.isNaN(at)) continue;
    if (best === null || at >= best.at) best = { at, method: m.method };
  }
  return best?.method ?? null;
}

/**
 * Decide whether a profile save may change email or recoveryEmail. `stored` is
 * the pre-save identity with credentials; `proposed` the submitted traits;
 * `methods` the session's authentication_methods.
 */
export function emailChangeVerdict(
  stored: Identity | null | undefined,
  proposed: Record<string, unknown> | null | undefined,
  methods: unknown,
): EmailChangeVerdict {
  const current = (stored?.traits ?? {}) as Record<string, unknown>;
  const pointers = EMAIL_TRAITS.filter((t) => asString(proposed?.[t]) !== asString(current[t])).map((t) => `#/traits/${t}`);
  if (pointers.length === 0 || !parseIdentity(stored).firstFactorKey) return { refuse: false };
  const newest = newestFirstFactorMethod(methods);
  if (newest !== null && FIRST_FACTOR_METHODS.has(newest)) return { refuse: false };
  return { refuse: true, text: EMAIL_CHANGE_REFUSAL, pointers };
}

/** True when a change to the email trait from this session would be refused (the settings page renders the inputs read-only). */
export function emailChangeLocked(stored: Identity | null | undefined, methods: unknown): boolean {
  const email = asString((stored?.traits as Record<string, unknown> | undefined)?.email);
  return emailChangeVerdict(stored, { email: `${email}\n` }, methods).refuse;
}

/** Username gate text: the username keys some apps' accounts, so only an administrator changes it. */
export const USERNAME_CHANGE_REFUSAL = 'Your username can only be changed by a household admin.';
export const PROFILE_UPDATE_UNAVAILABLE = 'Profile changes are unavailable right now. Try again later.';

/** Username-gate verdict (pure): refuse unless `stored` (pre-save) and `proposed` are the same non-empty string. */
export function usernameChangeVerdict(stored: Identity | null | undefined, proposed: unknown): { refuse: false } | { refuse: true; text: string } {
  const current = (stored?.traits as Record<string, unknown> | undefined)?.username;
  if (typeof current !== 'string' || current.length === 0 || typeof proposed !== 'string') {
    return { refuse: true, text: PROFILE_UPDATE_UNAVAILABLE };
  }
  if (proposed !== current) return { refuse: true, text: USERNAME_CHANGE_REFUSAL };
  return { refuse: false };
}

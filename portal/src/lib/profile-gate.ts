// Verdict for the email part of the settings.after.profile web_hook. An account
// with a passkey or password changes its emails only from a session whose newest
// aal1 sign-in used one of them (an emailed code proves the mailbox, not the
// person); identities with neither are unchanged. Stored identity comes from the
// admin API, authentication_methods from the hook body; missing data on a keyed identity refuses.

import type { Identity } from './types';

export const EMAIL_CHANGE_REFUSAL = 'To change an email address, sign in again with your passkey or password.';

const EMAIL_TRAITS = ['email', 'recoveryEmail'] as const;
const FIRST_FACTOR_METHODS = new Set(['password', 'passkey', 'webauthn']);

export type EmailChangeVerdict = { refuse: false } | { refuse: true; text: string; pointers: string[] };

type AuthMethod = { method?: unknown; aal?: unknown; completed_at?: unknown };

function asString(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function configOf(creds: Record<string, unknown>, type: string): Record<string, unknown> | null {
  const config = (creds[type] as { config?: unknown } | undefined)?.config;
  return config && typeof config === 'object' && !Array.isArray(config) ? (config as Record<string, unknown>) : null;
}

function keysOf(creds: Record<string, unknown>, type: string): unknown[] {
  const keys = configOf(creds, type)?.['credentials'];
  return Array.isArray(keys) ? keys.filter(Boolean) : [];
}

/**
 * True when the stored identity holds a password hash, a passkey, or a passwordless webauthn key. Kratos keeps
 * a password and a webauthn entry with an empty config on every identity (schema identifiers), so an entry
 * alone is not a key. Missing credentials count as keyed: the read did not carry them.
 */
export function hasFirstFactorKey(identity: Identity | null | undefined): boolean {
  const creds = identity?.credentials as Record<string, unknown> | undefined;
  if (!creds || typeof creds !== 'object') return true;
  const hash = configOf(creds, 'password')?.['hashed_password'];
  return (
    (typeof hash === 'string' && hash.length > 0) ||
    keysOf(creds, 'passkey').length > 0 ||
    keysOf(creds, 'webauthn').some((k) => (k as { is_passwordless?: unknown }).is_passwordless === true)
  );
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
  if (pointers.length === 0 || !hasFirstFactorKey(stored)) return { refuse: false };
  const newest = newestFirstFactorMethod(methods);
  if (newest !== null && FIRST_FACTOR_METHODS.has(newest)) return { refuse: false };
  return { refuse: true, text: EMAIL_CHANGE_REFUSAL, pointers };
}

/** True when a change to the email trait from this session would be refused (the settings page renders the inputs read-only). */
export function emailChangeLocked(stored: Identity | null | undefined, methods: unknown): boolean {
  const email = asString((stored?.traits as Record<string, unknown> | undefined)?.email);
  return emailChangeVerdict(stored, { email: `${email}\n` }, methods).refuse;
}

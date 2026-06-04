// Contact/request-form validation + in-process rate limiting (pure).
//
// Kept SEPARATE from the API route and the mailer so it is unit-testable
// without an HTTP request or a live SMTP relay. The route parses the form,
// calls validateContact(), checks rateLimit(), then hands the clean payload
// to lib/mailer.sendContactRequest().
//
// Fail-closed posture: anything ambiguous (missing field, over-length, an
// unknown request type, a body that is all whitespace or all links) is
// rejected with a stable, client-safe reason.

/** The request-type allowlist — mirrors the dashboard <select> options. */
export const REQUEST_TYPES = ['access', 'new', 'problem', 'other'] as const;
export type RequestType = (typeof REQUEST_TYPES)[number];

/** Length caps. Generous for humans, tight enough to bound abuse. */
export const LIMITS = {
  nameMax: 80,
  messageMin: 4,
  messageMax: 4000,
} as const;

export interface CleanContact {
  name: string;
  type: RequestType;
  message: string;
}

export type ValidateResult =
  | { ok: true; value: CleanContact }
  | { ok: false; reason: string };

function isRequestType(v: string): v is RequestType {
  return (REQUEST_TYPES as readonly string[]).includes(v);
}

/**
 * Validate + normalize raw form fields. Returns a discriminated result; the
 * `reason` strings are safe to return to the client (no internals leaked).
 */
export function validateContact(raw: {
  name?: unknown;
  type?: unknown;
  message?: unknown;
}): ValidateResult {
  const name = typeof raw.name === 'string' ? raw.name.trim() : '';
  const type = typeof raw.type === 'string' ? raw.type.trim() : '';
  const message = typeof raw.message === 'string' ? raw.message.trim() : '';

  if (!name) return { ok: false, reason: 'Please enter your name.' };
  if (name.length > LIMITS.nameMax) {
    return { ok: false, reason: `Name must be ${LIMITS.nameMax} characters or fewer.` };
  }

  if (!type) return { ok: false, reason: 'Please choose a request type.' };
  if (!isRequestType(type)) return { ok: false, reason: 'Unknown request type.' };

  if (message.length < LIMITS.messageMin) {
    return { ok: false, reason: 'Please write a short message.' };
  }
  if (message.length > LIMITS.messageMax) {
    return { ok: false, reason: `Message must be ${LIMITS.messageMax} characters or fewer.` };
  }

  // Obvious-abuse rejection: a body that is mostly URLs is spam, not a request.
  const urlCount = (message.match(/https?:\/\//gi) ?? []).length;
  if (urlCount >= 4) {
    return { ok: false, reason: 'Too many links in the message.' };
  }
  // Reject ASCII control characters (except tab) anywhere — they signal
  // header-injection / smuggling probes. The name is single-line, so a
  // CR/LF in it is also rejected.
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(name + message)) {
    return { ok: false, reason: 'Message contains invalid characters.' };
  }
  if (/[\r\n]/.test(name)) {
    return { ok: false, reason: 'Name must be a single line.' };
  }

  return { ok: true, value: { name, type, message } };
}

// ── In-process rate limiter ────────────────────────────────────────────────
//
// Sliding-window counter keyed by client (caller passes a key, typically the
// source IP). Single-process portal at family scale (same posture as csrf.ts's
// consumed-nonce store): no Redis needed. A sweep on each check bounds memory.

const WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MAX_PER_WINDOW = 5; // 5 submissions per key per window

const hits = new Map<string, number[]>();

/**
 * Record an attempt for `key` and report whether it is allowed. Returns
 * `{ allowed, retryAfterSec }`. A blocked caller gets a retry hint.
 */
export function rateLimit(
  key: string,
  now: number = Date.now(),
): { allowed: boolean; retryAfterSec: number } {
  const cutoff = now - WINDOW_MS;
  const recent = (hits.get(key) ?? []).filter((t) => t > cutoff);

  if (recent.length >= MAX_PER_WINDOW) {
    hits.set(key, recent); // keep the pruned window
    const oldest = recent[0];
    const retryAfterSec = Math.max(1, Math.ceil((oldest + WINDOW_MS - now) / 1000));
    return { allowed: false, retryAfterSec };
  }

  recent.push(now);
  hits.set(key, recent);

  // Opportunistic global sweep so idle keys don't accumulate forever.
  if (hits.size > 1000) {
    for (const [k, ts] of hits) {
      const live = ts.filter((t) => t > cutoff);
      if (live.length === 0) hits.delete(k);
      else hits.set(k, live);
    }
  }

  return { allowed: true, retryAfterSec: 0 };
}

/** Test-only: clear the rate-limit state. */
export function _resetForTests(): void {
  hits.clear();
}

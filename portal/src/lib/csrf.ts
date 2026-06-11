// Per-request CSRF tokens for /admin/* form POSTs.
//
// Why (HIGH-1):
//
//   The Kratos session cookie is SameSite=Lax with the parent-domain
//   cookie domain. Browsers consider the Othala host and any sibling
//   app subdomain same-site (shared registrable parent), so a
//   compromised app on `<app>.<parent-domain>` can host a top-level
//   form that POSTs to `<othala-host>/admin/users/<id>` and the browser
//   includes the session cookie. The admin UI's `requireAdminSession`
//   already passed AAL2 for the active admin, so the malicious form
//   rides that.
//
//   Mitigation: a per-request signed token tied to identity_id. Token
//   embedded in every admin form, verified server-side on POST. Single-
//   use (consumed on verify), 30-minute TTL, fails closed.
//
// Token shape:
//
//   <ts>.<identityId>.<nonce>.<sig>           (identity-only token, action="")
//   <ts>.<identityId>.<nonce>.<action>.<sig>  (action-scoped token)
//
//   - ts:        unix seconds at issuance
//   - identityId: the admin's identity id; binds the token to one user
//   - nonce:     16 bytes from randomBytes (URL-safe base64)
//   - action:    optional verb that limits which POST action the token can
//                authorise (e.g. "issue-recovery", "force-relogin",
//                "deactivate"). Present only when signToken() is called with
//                an action string. Backward-compatible: callers that omit
//                action still produce/verify 4-part tokens.
//   - sig:       HMAC-SHA256(secret, <everything before the sig dot>) base64url
//
// Single-use replay defence is in-memory: every consumed nonce is held
// for the TTL window. The portal runs as a single Node SSR pod (no
// horizontal replicas in production: see docs/STATUS.md "Astro adapter"
// row). If we ever scale out, the consumed-nonce store moves to Redis
// or Postgres; the API is the same.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const TOKEN_TTL_MS = 30 * 60 * 1000; // 30 min

const SECRET_ENV = 'CSRF_SECRET';

/**
 * Lazily resolve the signing secret. Failing-closed if unset is
 * deliberate: an admin POST without a working CSRF gate is the exact
 * shape this finding flagged.
 */
function secret(): Buffer {
  const v = process.env[SECRET_ENV];
  if (!v || v.length < 32) {
    throw new CSRFError(
      `${SECRET_ENV} is unset or shorter than 32 chars. ` +
        'Set it on the portal pod (random 32+ bytes; rotate on a fresh deploy).',
    );
  }
  return Buffer.from(v, 'utf8');
}

/**
 * In-memory consumed-nonce store. Single-process portal at family scale
 * is the production posture. Each entry holds an expiry timestamp; a
 * sweep on insert keeps the store from growing unboundedly.
 */
const consumedNonces = new Map<string, number>();

function sweepExpired(now: number): void {
  for (const [nonce, expiresAt] of consumedNonces) {
    if (expiresAt <= now) consumedNonces.delete(nonce);
  }
}

export class CSRFError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CSRFError';
  }
}

/**
 * Mint a CSRF token for the given admin identity. Embed in a hidden
 * form input named `csrf_token`. The token expires 30 min after issue.
 *
 * @param identityId  The admin's Kratos identity id.
 * @param action      Optional action verb (e.g. "issue-recovery"). When
 *                    provided the token is action-scoped: verifyToken will
 *                    reject it if the submitted action does not match.
 *                    Omit (or pass undefined) for identity-only tokens
 *                    (backward-compatible with existing call sites).
 */
export function signToken(identityId: string, action?: string): string {
  if (!identityId || !identityId.trim()) {
    throw new CSRFError('identityId is required to sign a CSRF token');
  }
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('base64url');
  // Action is included in the signed body when provided so it cannot be
  // stripped or swapped without invalidating the HMAC.
  const body = action
    ? `${ts}.${identityId}.${nonce}.${action}`
    : `${ts}.${identityId}.${nonce}`;
  const sig = createHmac('sha256', secret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/**
 * Verify a CSRF token against the active admin's identity id. Throws
 * CSRFError on missing, malformed, expired, replayed, or wrong-identity
 * tokens. On success, the nonce is recorded as consumed: the token
 * cannot be replayed.
 *
 * @param presented   The token string from the form submission.
 * @param identityId  The admin's Kratos identity id.
 * @param action      Expected action string. When provided, the token must
 *                    have been minted with the same action (action-scoped
 *                    tokens). When omitted, an identity-only (4-part) token
 *                    is expected; passing an action-scoped token for a
 *                    call site that doesn't require one is rejected (the
 *                    signature would mismatch).
 */
export function verifyToken(
  presented: string | null | undefined,
  identityId: string,
  action?: string,
): void {
  if (!presented) {
    throw new CSRFError('CSRF token missing');
  }
  if (!identityId) {
    throw new CSRFError('identityId required for verify');
  }
  const parts = presented.split('.');

  // A token without an action has 4 parts: ts.identity.nonce.sig
  // A token with an action has 5 parts: ts.identity.nonce.action.sig
  // Action strings are simple verbs (letters, hyphens) and cannot contain
  // dots, so the split is unambiguous.
  if (action) {
    if (parts.length !== 5) {
      throw new CSRFError('CSRF token malformed (expected action-scoped token)');
    }
  } else {
    if (parts.length !== 4) {
      throw new CSRFError('CSRF token malformed');
    }
  }

  let tsStr: string;
  let presentedIdentityId: string;
  let nonce: string;
  let presentedAction: string | undefined;
  let presentedSig: string;

  if (action) {
    [tsStr, presentedIdentityId, nonce, presentedAction, presentedSig] = parts as [
      string, string, string, string, string,
    ];
  } else {
    [tsStr, presentedIdentityId, nonce, presentedSig] = parts as [
      string, string, string, string,
    ];
  }

  const ts = Number.parseInt(tsStr, 10);
  if (!Number.isFinite(ts) || ts <= 0) {
    throw new CSRFError('CSRF token timestamp invalid');
  }

  const now = Date.now();
  if (now - ts * 1000 > TOKEN_TTL_MS) {
    throw new CSRFError('CSRF token expired');
  }
  if (ts * 1000 - now > 60_000) {
    // 60s clock skew tolerance.
    throw new CSRFError('CSRF token issued in the future');
  }

  if (presentedIdentityId !== identityId) {
    throw new CSRFError('CSRF token bound to a different identity');
  }

  // For action-scoped tokens, verify the action matches before checking
  // the signature so the error is informative. Timing-safe: action mismatch
  // is not a secret; the HMAC mismatch below is the definitive gate.
  // FIX-H: sanitize the reflected presentedAction to prevent attacker-controlled
  // input from appearing verbatim in the 403 body (defence-in-depth; text/plain,
  // but still reduces reflection surface). Cap to 32 chars of safe characters.
  if (action && presentedAction !== action) {
    const safePresented = presentedAction
      ? presentedAction.replace(/[^a-z0-9:-]/gi, '').slice(0, 32)
      : '';
    throw new CSRFError(`CSRF token action mismatch (expected '${action}'${safePresented ? `, got '${safePresented}'` : ''})`);
  }

  const signedBody = action
    ? `${tsStr}.${presentedIdentityId}.${nonce}.${presentedAction}`
    : `${tsStr}.${presentedIdentityId}.${nonce}`;
  const expectedSig = createHmac('sha256', secret()).update(signedBody).digest();
  let presentedSigBuf: Buffer;
  try {
    presentedSigBuf = Buffer.from(presentedSig, 'base64url');
  } catch {
    throw new CSRFError('CSRF token signature malformed');
  }
  if (presentedSigBuf.length !== expectedSig.length) {
    throw new CSRFError('CSRF token signature length mismatch');
  }
  if (!timingSafeEqual(presentedSigBuf, expectedSig)) {
    throw new CSRFError('CSRF token signature invalid');
  }

  // Single-use: reject if the nonce was already consumed within the TTL.
  sweepExpired(now);
  if (consumedNonces.has(nonce)) {
    throw new CSRFError('CSRF token already used');
  }
  consumedNonces.set(nonce, ts * 1000 + TOKEN_TTL_MS);
}

/** Test-only helper: drop the in-memory consumed-nonce store. */
export function _resetForTests(): void {
  consumedNonces.clear();
}

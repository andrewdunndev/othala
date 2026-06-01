// Per-request CSRF tokens for /admin/* form POSTs.
//
// Why (HIGH-1):
//
//   The Kratos session cookie is SameSite=Lax with the parent domain
//   `.dunn.dev`. Browsers consider `dag.dunn.dev` and `<app>.dunn.dev`
//   same-site (registrable parent), so a compromised app on
//   `<app>.dunn.dev` can host a top-level form that POSTs to
//   `https://dag.dunn.dev/admin/users/<id>` and the browser includes
//   the session cookie. The admin UI's `requireAdminSession` already
//   passed AAL2 for the active admin, so the malicious form rides that.
//
//   Mitigation: a per-request signed token tied to identity_id. Token
//   embedded in every admin form, verified server-side on POST. Single-
//   use (consumed on verify), 30-minute TTL, fails closed.
//
// Token shape:
//
//   <ts>.<identityId>.<nonce>.<sig>
//
//   - ts:        unix seconds at issuance
//   - identityId: the admin's identity id; binds the token to one user
//   - nonce:     16 bytes from crypto.randomUUID() (URL-safe)
//   - sig:       HMAC-SHA256(secret, ts.identityId.nonce) base64url
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
 */
export function signToken(identityId: string): string {
  if (!identityId) {
    throw new CSRFError('identityId is required to sign a CSRF token');
  }
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('base64url');
  const body = `${ts}.${identityId}.${nonce}`;
  const sig = createHmac('sha256', secret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/**
 * Verify a CSRF token against the active admin's identity id. Throws
 * CSRFError on missing, malformed, expired, replayed, or wrong-identity
 * tokens. On success, the nonce is recorded as consumed: the token
 * cannot be replayed.
 */
export function verifyToken(presented: string | null | undefined, identityId: string): void {
  if (!presented) {
    throw new CSRFError('CSRF token missing');
  }
  if (!identityId) {
    throw new CSRFError('identityId required for verify');
  }
  const parts = presented.split('.');
  if (parts.length !== 4) {
    throw new CSRFError('CSRF token malformed');
  }
  const [tsStr, presentedIdentityId, nonce, presentedSig] = parts;

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

  const expectedSig = createHmac('sha256', secret())
    .update(`${tsStr}.${presentedIdentityId}.${nonce}`)
    .digest();
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

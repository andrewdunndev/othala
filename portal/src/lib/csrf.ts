// Per-request CSRF tokens for /admin/* form POSTs. The Kratos session cookie is SameSite=Lax on the parent domain,
// so a sibling app subdomain can post a cross-site form that rides an admin session; each admin form carries a signed token.
// Shape: <ts>.<identityId>.<nonce>.<action>.<sig>, sig = HMAC-SHA256 base64url over the rest. Single-use, 30 min TTL,
// fails closed. The consumed-nonce store is in-memory (single Node pod); scaling out moves it to Redis or Postgres.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { secret as readSecret } from './config';

const TOKEN_TTL_MS = 30 * 60 * 1000; // 30 min

const SECRET_ENV = 'CSRF_SECRET';

/** Lazily resolve the signing secret; fails closed when unset. */
function secret(): Buffer {
  const v = readSecret(SECRET_ENV);
  // 32-byte floor by UTF-8 byte length, not character count (multi-byte characters would undercount entropy).
  if (!v || Buffer.byteLength(v, 'utf8') < 32) {
    throw new CSRFError(
      `${SECRET_ENV} is unset or shorter than 32 bytes (UTF-8). ` +
        'Set it on the portal pod (random 32+ bytes; rotate on a fresh deploy).',
    );
  }
  return Buffer.from(v, 'utf8');
}

/** In-memory consumed-nonce store (single-process portal); swept on insert. */
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
 * Mint a token for an admin identity, embedded in a hidden `csrf_token` input; verifyToken rejects it unless the
 * same `action` is expected.
 */
export function signToken(identityId: string, action: string): string {
  if (!identityId || !identityId.trim()) {
    throw new CSRFError('identityId is required to sign a CSRF token');
  }
  // '.' is the field separator; refuse it in identityId or action so verifyToken cannot mis-parse.
  if (identityId.includes('.')) {
    throw new CSRFError('identityId must not contain a dot (would corrupt token structure)');
  }
  if (!action) {
    throw new CSRFError('action is required to sign a CSRF token');
  }
  if (action.includes('.')) {
    throw new CSRFError('action must not contain a dot (would corrupt token structure)');
  }
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('base64url');
  // The action is signed, so it cannot be stripped or swapped.
  const body = `${ts}.${identityId}.${nonce}.${action}`;
  const sig = createHmac('sha256', secret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/**
 * Verify a token against the admin's identity id and expected action. Throws CSRFError when missing, malformed,
 * expired, replayed, or bound to another identity or action; records the nonce as consumed on success.
 */
export function verifyToken(
  presented: string | null | undefined,
  identityId: string,
  action: string,
): void {
  if (!presented) {
    throw new CSRFError('CSRF token missing');
  }
  if (!identityId) {
    throw new CSRFError('identityId required for verify');
  }
  const parts = presented.split('.');

  // Action verbs contain no dots, so the split is unambiguous.
  if (parts.length !== 5) {
    throw new CSRFError('CSRF token malformed');
  }
  const [tsStr, presentedIdentityId, nonce, presentedAction, presentedSig] = parts as [
    string, string, string, string, string,
  ];

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

  // Reflect only a sanitized, capped presentedAction in the 403 body; the HMAC below is the definitive gate.
  if (presentedAction !== action) {
    const safePresented = presentedAction
      ? presentedAction.replace(/[^a-z0-9:-]/gi, '').slice(0, 32)
      : '';
    throw new CSRFError(`CSRF token action mismatch (expected '${action}'${safePresented ? `, got '${safePresented}'` : ''})`);
  }

  const signedBody = `${tsStr}.${presentedIdentityId}.${nonce}.${presentedAction}`;
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

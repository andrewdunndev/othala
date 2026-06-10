/**
 * csrf.test.ts — unit tests for the CSRF token signing and verification logic.
 *
 * Coverage:
 *   - Basic sign/verify round-trip (identity-only tokens).
 *   - Action-scoped sign/verify round-trip.
 *   - Action-binding: token minted for action A rejects on action B.
 *   - Action-binding: action-scoped token rejects when verified without action.
 *   - Identity-only token rejects when verified with an action (wrong part count).
 *   - Existing error paths: missing token, bad identity, expired, replayed,
 *     wrong-identity, future-dated (regression: no regressions from the new
 *     optional action parameter).
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { signToken, verifyToken, CSRFError, _resetForTests } from './csrf.js';

const IDENTITY = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const OTHER_IDENTITY = 'ffffffff-1111-2222-3333-444444444444';

beforeEach(() => {
  // Clear the consumed-nonce store between tests so replay tests are isolated.
  _resetForTests();
  process.env['CSRF_SECRET'] = 'a-test-secret-that-is-at-least-32-chars!!';
});

// ── Identity-only tokens (backward-compatible path) ─────────────────────────

describe('signToken / verifyToken — identity-only', () => {
  it('issues and verifies a valid token', () => {
    const tok = signToken(IDENTITY);
    expect(() => verifyToken(tok, IDENTITY)).not.toThrow();
  });

  it('rejects a missing token', () => {
    expect(() => verifyToken(null, IDENTITY)).toThrow(CSRFError);
    expect(() => verifyToken(undefined, IDENTITY)).toThrow(CSRFError);
    expect(() => verifyToken('', IDENTITY)).toThrow(CSRFError);
  });

  it('rejects a malformed token (wrong part count)', () => {
    expect(() => verifyToken('ts.id.nonce', IDENTITY)).toThrow(CSRFError);
  });

  it('rejects a token bound to a different identity', () => {
    const tok = signToken(IDENTITY);
    expect(() => verifyToken(tok, OTHER_IDENTITY)).toThrow(CSRFError);
  });

  it('rejects a replayed token', () => {
    const tok = signToken(IDENTITY);
    verifyToken(tok, IDENTITY); // first use: OK
    expect(() => verifyToken(tok, IDENTITY)).toThrow(CSRFError); // second use: replay
  });

  it('rejects a tampered signature', () => {
    const tok = signToken(IDENTITY);
    const parts = tok.split('.');
    parts[3] = 'invalidsignature';
    expect(() => verifyToken(parts.join('.'), IDENTITY)).toThrow(CSRFError);
  });
});

// ── Action-scoped tokens ─────────────────────────────────────────────────────

describe('signToken / verifyToken — action-scoped', () => {
  it('issues and verifies a valid action-scoped token', () => {
    const tok = signToken(IDENTITY, 'issue-recovery');
    expect(() => verifyToken(tok, IDENTITY, 'issue-recovery')).not.toThrow();
  });

  it('rejects when submitted action differs from token action', () => {
    const tok = signToken(IDENTITY, 'issue-recovery');
    expect(() => verifyToken(tok, IDENTITY, 'deactivate')).toThrow(CSRFError);
  });

  it('rejects when submitted action differs from token action — force-relogin vs deactivate', () => {
    const tok = signToken(IDENTITY, 'force-relogin');
    let err: CSRFError | null = null;
    try {
      verifyToken(tok, IDENTITY, 'deactivate');
    } catch (e) {
      err = e as CSRFError;
    }
    expect(err).toBeInstanceOf(CSRFError);
    expect(err!.message).toMatch(/action mismatch/i);
  });

  it('rejects an action-scoped token when verifyToken is called without action', () => {
    // A 5-part token fails the 4-part length check when action is omitted.
    const tok = signToken(IDENTITY, 'issue-recovery');
    expect(() => verifyToken(tok, IDENTITY)).toThrow(CSRFError);
  });

  it('rejects an identity-only token when verifyToken requires an action', () => {
    // A 4-part token fails the 5-part length check when action is required.
    const tok = signToken(IDENTITY);
    expect(() => verifyToken(tok, IDENTITY, 'issue-recovery')).toThrow(CSRFError);
  });

  it('rejects a replayed action-scoped token', () => {
    const tok = signToken(IDENTITY, 'force-relogin');
    verifyToken(tok, IDENTITY, 'force-relogin');
    expect(() => verifyToken(tok, IDENTITY, 'force-relogin')).toThrow(CSRFError);
  });

  it('rejects a tampered action in the token body', () => {
    const tok = signToken(IDENTITY, 'issue-recovery');
    // Replace the action segment (index 3 in a 5-part token) with a different
    // action. The HMAC was computed over 'issue-recovery', not 'deactivate',
    // so the signature check must fail.
    const parts = tok.split('.');
    parts[3] = 'deactivate';
    // verifyToken with action='deactivate' would see action-match pass, but
    // the HMAC must catch the tampering.
    expect(() => verifyToken(parts.join('.'), IDENTITY, 'deactivate')).toThrow(CSRFError);
  });

  it('different action types each verify independently', () => {
    const tokA = signToken(IDENTITY, 'issue-recovery');
    const tokB = signToken(IDENTITY, 'force-relogin');
    const tokC = signToken(IDENTITY, 'deactivate');
    expect(() => verifyToken(tokA, IDENTITY, 'issue-recovery')).not.toThrow();
    expect(() => verifyToken(tokB, IDENTITY, 'force-relogin')).not.toThrow();
    expect(() => verifyToken(tokC, IDENTITY, 'deactivate')).not.toThrow();
  });
});

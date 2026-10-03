// Invariant: a token verifies only for its identity and action, once, before expiry, and only if its HMAC holds.

import { createHmac } from 'node:crypto';
import { describe, it, expect, beforeEach } from 'vitest';
import { signToken, verifyToken, CSRFError, _resetForTests } from './csrf.js';

const IDENTITY = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const OTHER_IDENTITY = 'ffffffff-1111-2222-3333-444444444444';

beforeEach(() => {
  _resetForTests();
  process.env['CSRF_SECRET'] = 'a-test-secret-that-is-at-least-32-chars!!';
});

describe('signToken / verifyToken — errors', () => {
  it('round-trips', () => {
    const tok = signToken(IDENTITY, 'save');
    expect(() => verifyToken(tok, IDENTITY, 'save')).not.toThrow();
  });

  it('rejects missing token', () => {
    expect(() => verifyToken(null, IDENTITY, 'save')).toThrow(CSRFError);
    expect(() => verifyToken(undefined, IDENTITY, 'save')).toThrow(CSRFError);
    expect(() => verifyToken('', IDENTITY, 'save')).toThrow(CSRFError);
  });

  it('rejects malformed token', () => {
    expect(() => verifyToken('ts.id.nonce', IDENTITY, 'save')).toThrow(CSRFError);
    expect(() => verifyToken('not-a-token', IDENTITY, 'save')).toThrow(CSRFError);
    expect(() => verifyToken('a.b.c', IDENTITY, 'save')).toThrow(CSRFError);
  });

  it('rejects a 4-part token without an action', () => {
    const body = `${Math.floor(Date.now() / 1000)}.${IDENTITY}.nonce`;
    const sig = createHmac('sha256', Buffer.from(process.env['CSRF_SECRET']!, 'utf8')).update(body).digest('base64url');
    const tok = `${body}.${sig}`;
    expect(() => (verifyToken as (t: string, i: string, a?: string) => void)(tok, IDENTITY)).toThrow(CSRFError);
  });

  it('requires an action to sign', () => {
    expect(() => (signToken as (i: string, a?: string) => string)(IDENTITY)).toThrow(CSRFError);
  });

  it('rejects wrong identity', () => {
    const tok = signToken(IDENTITY, 'save');
    expect(() => verifyToken(tok, OTHER_IDENTITY, 'save')).toThrow(CSRFError);
  });

  it('rejects replay', () => {
    const tok = signToken(IDENTITY, 'save');
    verifyToken(tok, IDENTITY, 'save');
    expect(() => verifyToken(tok, IDENTITY, 'save')).toThrow(CSRFError);
  });

  it('rejects a tampered signature', () => {
    const tok = signToken(IDENTITY, 'save');
    const parts = tok.split('.');
    parts[4] = 'invalidsignature';
    expect(() => verifyToken(parts.join('.'), IDENTITY, 'save')).toThrow(CSRFError);
  });
});

describe('signToken / verifyToken — action-scoped', () => {
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

  it('rejects a tampered action in the token body', () => {
    const tok = signToken(IDENTITY, 'issue-recovery');
    const parts = tok.split('.');
    parts[3] = 'deactivate';
    expect(() => verifyToken(parts.join('.'), IDENTITY, 'deactivate')).toThrow(CSRFError);
  });
});

describe('signToken / verifyToken — expiry, dots, secret, message hygiene', () => {
  it('rejects an expired token', () => {
    const parts = signToken(IDENTITY, 'save').split('.');
    const body = `${Math.floor(Date.now() / 1000) - 31 * 60}.${parts[1]}.${parts[2]}.${parts[3]}`;
    const sig = createHmac('sha256', Buffer.from(process.env['CSRF_SECRET']!, 'utf8')).update(body).digest('base64url');
    expect(() => verifyToken(`${body}.${sig}`, IDENTITY, 'save')).toThrow(/expired/);
  });

  it('CRYPTO-1: signToken throws on a dotted identityId', () => {
    expect(() => signToken('admin.1', 'save')).toThrow(/dot/);
  });

  it('CRYPTO-1: signToken throws on a dotted action', () => {
    expect(() => signToken('admin-1', 'issue.recovery')).toThrow(/dot/);
  });

  it('CRYPTO-2: a 32-ASCII-char secret passes the byte-length gate', () => {
    process.env['CSRF_SECRET'] = 'a'.repeat(32);
    expect(() => signToken('admin-1', 'save')).not.toThrow();
  });

  it('FIX-H: action mismatch message never reflects raw attacker characters', () => {
    const parts = signToken('admin-1', 'consent').split('.');
    parts[3] = '<script>alert(1)</script>' + 'A'.repeat(100);
    let msg = '';
    try {
      verifyToken(parts.join('.'), 'admin-1', 'consent');
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).not.toMatch(/[<>]/);
    expect(msg).toContain("'consent'");
  });

  it('FIX-H: a safe presented action stays readable in the mismatch message', () => {
    let msg = '';
    try {
      verifyToken(signToken('admin-1', 'deactivate'), 'admin-1', 'consent');
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain("'consent'");
    expect(msg).toContain("'deactivate'");
  });
});

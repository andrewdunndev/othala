// Tests for src/lib/csrf.ts.
//
// Run with: npx vitest run scripts/csrf.test.mjs
//
// Imports the canonical signer directly. Sets CSRF_SECRET before
// invoking signToken/verifyToken; the module reads process.env lazily,
// so an early process.env.CSRF_SECRET assignment is sufficient.

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

// Set the secret before any signToken/verifyToken call.
process.env.CSRF_SECRET = 'a'.repeat(64);

const { signToken, verifyToken, _resetForTests } = await import('../src/lib/csrf.ts');

beforeEach(() => {
  _resetForTests();
});

test('signs a token whose round-trip verifies', () => {
  const tok = signToken('admin-1');
  assert.doesNotThrow(() => verifyToken(tok, 'admin-1'));
});

test('rejects token bound to a different identity', () => {
  const tok = signToken('admin-1');
  assert.throws(() => verifyToken(tok, 'admin-2'), /different identity/);
});

test('rejects missing token', () => {
  assert.throws(() => verifyToken('', 'admin-1'), /missing/);
  assert.throws(() => verifyToken(null, 'admin-1'), /missing/);
});

test('rejects malformed token', () => {
  assert.throws(() => verifyToken('not-a-token', 'admin-1'), /malformed/);
  assert.throws(() => verifyToken('a.b.c', 'admin-1'), /malformed/);
});

test('rejects replayed token (single-use)', () => {
  const tok = signToken('admin-1');
  verifyToken(tok, 'admin-1');
  assert.throws(() => verifyToken(tok, 'admin-1'), /already used/);
});

test('rejects expired token', () => {
  // Forge an old timestamp + matching signature so we exercise the
  // expiry branch deterministically (no fake timers).
  const tok = signToken('admin-1');
  const parts = tok.split('.');
  const oldTs = Math.floor(Date.now() / 1000) - 31 * 60;
  const body = `${oldTs}.${parts[1]}.${parts[2]}`;
  const sig = createHmac('sha256', Buffer.from(process.env.CSRF_SECRET, 'utf8'))
    .update(body)
    .digest('base64url');
  const old = `${body}.${sig}`;
  assert.throws(() => verifyToken(old, 'admin-1'), /expired/);
});

test('rejects token with tampered signature', () => {
  const tok = signToken('admin-1');
  const tampered = tok.slice(0, -4) + 'xxxx';
  assert.throws(() => verifyToken(tampered, 'admin-1'), /signature/);
});

// ── CRYPTO-1: dot invariant enforced at sign time ────────────────────────────

test('CRYPTO-1: signToken throws on dotted identityId', () => {
  assert.throws(
    () => signToken('admin.1'),
    /dot/,
    'signToken must throw when identityId contains a dot',
  );
});

test('CRYPTO-1: signToken throws on dotted action', () => {
  assert.throws(
    () => signToken('admin-1', 'issue.recovery'),
    /dot/,
    'signToken must throw when action contains a dot',
  );
});

test('CRYPTO-1: signToken accepts identityId and action without dots', () => {
  assert.doesNotThrow(() => signToken('admin-1', 'issue-recovery'));
});

// ── CRYPTO-2: secret byte-length check ───────────────────────────────────────

test('CRYPTO-2: a 32-ASCII-char secret passes the byte-length gate', () => {
  // 32 ASCII chars = 32 UTF-8 bytes, must be accepted.
  process.env.CSRF_SECRET = 'a'.repeat(32);
  // Importing the module is already done; the secret() fn is lazy — we just need
  // to call signToken which invokes secret() internally.
  assert.doesNotThrow(() => signToken('admin-1'));
  process.env.CSRF_SECRET = 'a'.repeat(64); // restore
});

// ── FIX-H: action mismatch message does not reflect raw attacker input ────────

test('FIX-H: action mismatch message does not contain raw attacker-controlled characters', () => {
  // Mint a token with action 'consent'.
  const tok = signToken('admin-1', 'consent');
  // Tamper: swap the action segment to a long payload with special chars.
  const parts = tok.split('.');
  // parts: [ts, identityId, nonce, action, sig]
  const maliciousAction = '<script>alert(1)</script>' + 'A'.repeat(100);
  parts[3] = maliciousAction;
  const tampered = parts.join('.');

  // verifyToken should throw a CSRFError; the message must NOT contain raw HTML.
  let threw = false;
  try {
    verifyToken(tampered, 'admin-1', 'consent');
  } catch (err) {
    threw = true;
    const msg = err.message;
    // The sanitized form must not contain < > or the full 100-char padding.
    assert.ok(!msg.includes('<script>'), 'message must not reflect raw HTML');
    assert.ok(!msg.includes('>'), 'message must not contain ">');
    assert.ok(!msg.includes('<'), "message must not contain '<'");
    // The expected action name must still appear.
    assert.ok(msg.includes("'consent'"), "expected action must appear in message");
  }
  assert.ok(threw, 'verifyToken must throw on action mismatch');
});

test('FIX-H: action mismatch message with safe presented action still readable', () => {
  const tok = signToken('admin-1', 'deactivate');
  // Verify as a different (expected) action to trigger the mismatch path.
  let msg = '';
  try {
    verifyToken(tok, 'admin-1', 'consent');
  } catch (err) {
    msg = err.message;
  }
  // 'deactivate' contains only safe chars and fits in 32 — should appear.
  assert.ok(msg.includes("'consent'"), "expected action must appear");
  assert.ok(msg.includes("'deactivate'"), "sanitized presented action should appear when safe");
});

// Tests for src/lib/csrf.ts.
//
// Run with: tsx --test scripts/csrf.test.mjs
//
// Imports the canonical signer directly. Sets CSRF_SECRET before
// invoking signToken/verifyToken; the module reads process.env lazily,
// so an early process.env.CSRF_SECRET assignment is sufficient.

import { test, beforeEach } from 'node:test';
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

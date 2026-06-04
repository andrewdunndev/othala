// Tests for src/lib/contact.ts (validation + rate limit) and the SMTP-URI
// parser in src/lib/mailer.ts.
//
// Run with: tsx --test scripts/contact.test.mjs

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const {
  validateContact,
  rateLimit,
  LIMITS,
  _resetForTests,
} = await import('../src/lib/contact.ts');

beforeEach(() => {
  _resetForTests();
});

// ── validateContact ────────────────────────────────────────────────────────

test('accepts a well-formed submission and normalizes whitespace', () => {
  const r = validateContact({ name: '  Ashley ', type: 'access', message: '  please grant access  ' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { name: 'Ashley', type: 'access', message: 'please grant access' });
});

test('rejects an empty name', () => {
  const r = validateContact({ name: '   ', type: 'access', message: 'a real message' });
  assert.equal(r.ok, false);
});

test('rejects an over-length name', () => {
  const r = validateContact({ name: 'x'.repeat(LIMITS.nameMax + 1), type: 'access', message: 'a real message' });
  assert.equal(r.ok, false);
});

test('rejects an unknown request type (allowlist)', () => {
  const r = validateContact({ name: 'X', type: 'evil', message: 'a real message' });
  assert.equal(r.ok, false);
});

test('rejects a too-short message', () => {
  const r = validateContact({ name: 'X', type: 'other', message: 'hi' });
  assert.equal(r.ok, false);
});

test('rejects an over-length message', () => {
  const r = validateContact({ name: 'X', type: 'other', message: 'm'.repeat(LIMITS.messageMax + 1) });
  assert.equal(r.ok, false);
});

test('rejects header-injection control characters', () => {
  const r = validateContact({ name: 'X\r\nBcc: evil@x', type: 'other', message: 'a real message body' });
  assert.equal(r.ok, false);
});

test('rejects a body that is mostly links (spam)', () => {
  const r = validateContact({
    name: 'X',
    type: 'other',
    message: 'http://a.com http://b.com http://c.com http://d.com',
  });
  assert.equal(r.ok, false);
});

test('rejects non-string fields', () => {
  const r = validateContact({ name: 123, type: ['access'], message: {} });
  assert.equal(r.ok, false);
});

// ── rateLimit ────────────────────────────────────────────────────────────────

test('allows up to the window cap then blocks', () => {
  const key = '1.2.3.4';
  for (let i = 0; i < 5; i++) {
    assert.equal(rateLimit(key).allowed, true, `attempt ${i + 1} should be allowed`);
  }
  const blocked = rateLimit(key);
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterSec > 0, 'a blocked caller gets a retry hint');
});

test('rate limit is per-key', () => {
  for (let i = 0; i < 5; i++) rateLimit('a');
  assert.equal(rateLimit('a').allowed, false);
  assert.equal(rateLimit('b').allowed, true, 'a different key has its own budget');
});

test('the window slides — old hits expire', () => {
  const key = 'slide';
  const t0 = 1_000_000_000_000;
  for (let i = 0; i < 5; i++) rateLimit(key, t0);
  assert.equal(rateLimit(key, t0).allowed, false);
  // 11 minutes later (> 10-min window) the budget is fresh.
  assert.equal(rateLimit(key, t0 + 11 * 60 * 1000).allowed, true);
});

// ── parseSmtpUri ─────────────────────────────────────────────────────────────

const { parseSmtpUri, MailerError } = await import('../src/lib/mailer.ts');

test('parses an smtps URI as secure with auth', () => {
  const o = parseSmtpUri('smtps://user%40d:p%40ss@smtp.example.com:465');
  assert.deepEqual(o, {
    host: 'smtp.example.com',
    port: 465,
    secure: true,
    auth: { user: 'user@d', pass: 'p@ss' },
  });
});

test('parses a plain smtp URI as non-secure, default port 587, no auth', () => {
  const o = parseSmtpUri('smtp://mailpit:1025');
  assert.deepEqual(o, { host: 'mailpit', port: 1025, secure: false });
});

test('defaults the port by scheme when absent', () => {
  assert.equal(parseSmtpUri('smtps://h').port, 465);
  assert.equal(parseSmtpUri('smtp://h').port, 587);
});

test('rejects an unsupported scheme', () => {
  assert.throws(() => parseSmtpUri('http://h:80'), MailerError);
});

test('rejects a non-URL', () => {
  assert.throws(() => parseSmtpUri('not a uri'), MailerError);
});

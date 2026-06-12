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

// CR/LF handling — design call:
// - name is header-bound (used in email From/Subject) -> CR/LF must be rejected.
// - message goes into the email BODY only -> multi-line content is legitimate;
//   CR/LF is NOT rejected in message so users can write multi-paragraph requests.
// The /[\r\n]/ guard on name (contact.ts line ~77) covers the only header-injection
// vector. This test documents both sides of that decision explicitly.
test('name rejects CR/LF (header injection guard)', () => {
  const r = validateContact({ name: 'Alice\r\nBcc: evil@x', type: 'other', message: 'a real message body' });
  assert.equal(r.ok, false, 'name with CR/LF must be rejected (header-injection guard)');
});

test('message allows embedded newlines (multi-line textarea — body-only, not header-bound)', () => {
  const r = validateContact({
    name: 'Alice',
    type: 'problem',
    message: 'Line one.\r\nLine two.\nLine three.',
  });
  assert.equal(r.ok, true, 'message with CR/LF must be accepted (goes to body, not a header)');
  // Trimmed value is returned verbatim (newlines preserved for the mailer body).
  assert.ok(r.value.message.includes('\n'), 'embedded newlines must be preserved in the clean value');
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

// ── DOS-2: hard cap on Map size ──────────────────────────────────────────────

test('DOS-2: hits Map does not exceed HITS_MAP_MAX under many distinct keys', () => {
  // Import the internals we need. HITS_MAP_MAX is 10_000 in the source;
  // we simulate a flood of 11_000 distinct keys with a fake timestamp so
  // the sweep does not expire any of them.
  const now = Date.now();
  // Fill the map past the sweep trigger (> 1000) and past HITS_MAP_MAX.
  // Each key gets one hit so nothing expires. The cap must fire and clear.
  for (let i = 0; i < 11_000; i++) {
    rateLimit(`flood-key-${i}`, now);
  }
  // After 11_000 distinct keys the cap should have fired and cleared the map.
  // We cannot directly inspect `hits` from outside, but we CAN verify that
  // a previously-blocked key is now allowed again (map was cleared).
  // Fill key 'flood-key-0' to exhaustion first, then trigger the cap clear.
  _resetForTests();
  const key = 'sentinel';
  for (let i = 0; i < 5; i++) rateLimit(key, now);
  assert.equal(rateLimit(key, now).allowed, false, 'sentinel should be blocked before clear');

  // Now flood with distinct keys to trigger the cap.
  for (let i = 0; i < 11_000; i++) {
    rateLimit(`flood2-${i}`, now);
  }
  // After the clear, the sentinel bucket is gone — a fresh call should be allowed.
  assert.equal(rateLimit(key, now).allowed, true, 'Map cap clear must reset all buckets including sentinel');
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

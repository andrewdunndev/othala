// Invariant: contact input is validated (name is header-bound, message is body-only), submissions are rate-limited per key, and SMTP URIs parse strictly.

import { describe, it, expect, beforeEach } from 'vitest';
import { rateLimit, _resetForTests, validateContact, LIMITS } from './contact.js';
import { parseSmtpUri, smtpTransportOptions, MailerError } from './mailer.js';

beforeEach(() => {
  _resetForTests();
});

describe('validateContact()', () => {
  it('accepts a well-formed submission and normalizes whitespace', () => {
    const r = validateContact({ name: '  Robin ', type: 'access', message: '  please grant access  ' });
    expect(r.ok).toBe(true);
    expect(r.ok && r.value).toEqual({ name: 'Robin', type: 'access', message: 'please grant access' });
  });

  it('rejects an empty name', () => {
    expect(validateContact({ name: '   ', type: 'access', message: 'a real message' }).ok).toBe(false);
  });

  it('rejects an over-length name', () => {
    expect(validateContact({ name: 'x'.repeat(LIMITS.nameMax + 1), type: 'access', message: 'a real message' }).ok).toBe(false);
  });

  it('rejects an unknown request type (allowlist)', () => {
    expect(validateContact({ name: 'X', type: 'evil', message: 'a real message' }).ok).toBe(false);
  });

  it('rejects a too-short message', () => {
    expect(validateContact({ name: 'X', type: 'other', message: 'hi' }).ok).toBe(false);
  });

  it('rejects an over-length message', () => {
    expect(validateContact({ name: 'X', type: 'other', message: 'm'.repeat(LIMITS.messageMax + 1) }).ok).toBe(false);
  });

  it('rejects control characters in the name or the message', () => {
    for (const raw of [
      { name: 'X\x1b', type: 'other', message: 'a real message body' },
      { name: 'X', type: 'other', message: 'ok \x00 body' },
      { name: 'X', type: 'other', message: 'ok \x7f body' },
    ]) {
      expect(validateContact(raw)).toEqual({ ok: false, reason: 'Message contains invalid characters.' });
    }
  });

  it('name rejects CR/LF (header injection guard)', () => {
    expect(validateContact({ name: 'Alice\r\nBcc: evil@x', type: 'other', message: 'a real message body' }).ok).toBe(false);
  });

  it('message allows embedded newlines (body-only, not header-bound)', () => {
    const r = validateContact({ name: 'Alice', type: 'problem', message: 'Line one.\r\nLine two.\nLine three.' });
    expect(r.ok).toBe(true);
    expect(r.ok && r.value.message).toContain('\n');
  });

  it('rejects a body that is mostly links (spam)', () => {
    const message = 'http://a.com http://b.com http://c.com HTTPS://d.com';
    expect(validateContact({ name: 'X', type: 'other', message }).ok).toBe(false);
  });

  it('rejects non-string fields', () => {
    expect(validateContact({ name: 123, type: ['access'], message: {} } as never).ok).toBe(false);
  });
});

describe('rateLimit()', () => {
  it('allows the first 5 attempts (MAX_PER_WINDOW = 5)', () => {
    const key = 'test-key-1';
    for (let i = 0; i < 5; i++) {
      const result = rateLimit(key);
      expect(result.allowed, `attempt ${i + 1} should be allowed`).toBe(true);
      expect(result.retryAfterSec).toBe(0);
    }
  });

  it('blocks the 6th attempt with a positive retry hint', () => {
    const key = 'test-key-2';
    for (let i = 0; i < 5; i++) rateLimit(key);
    const blocked = rateLimit(key);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSec).toBeGreaterThan(0);
  });

  it('per-key isolation', () => {
    for (let i = 0; i < 5; i++) rateLimit('addr-a');
    expect(rateLimit('addr-a').allowed).toBe(false);
    expect(rateLimit('addr-b').allowed).toBe(true);
  });

  it('sliding window: attempts outside the 10-min window expire', () => {
    const t0 = 1_000_000_000_000;
    for (let i = 0; i < 5; i++) rateLimit('test-key-slide', t0);
    expect(rateLimit('test-key-slide', t0).allowed).toBe(false);
    expect(rateLimit('test-key-slide', t0 + 5 * 60 * 1000).allowed).toBe(false);
    expect(rateLimit('test-key-slide', t0 + 11 * 60 * 1000).allowed).toBe(true);
  });

  it('DOS-2: hits Map does not exceed HITS_MAP_MAX under many distinct keys', () => {
    const now = Date.now();
    for (let i = 0; i < 11_000; i++) rateLimit(`flood-key-${i}`, now);
    _resetForTests();
    const key = 'sentinel';
    for (let i = 0; i < 5; i++) rateLimit(key, now);
    expect(rateLimit(key, now).allowed, 'sentinel blocked before clear').toBe(false);
    for (let i = 0; i < 11_000; i++) rateLimit(`flood2-${i}`, now);
    expect(rateLimit(key, now).allowed, 'cap clear resets all buckets').toBe(true);
  }, 60_000);
});

describe('parseSmtpUri()', () => {
  it('parses an smtps URI as secure with auth', () => {
    expect(parseSmtpUri('smtps://user%40d:p%40ss@smtp.example.com:465')).toEqual({
      host: 'smtp.example.com',
      port: 465,
      secure: true,
      auth: { user: 'user@d', pass: 'p@ss' },
    });
  });

  it('parses a plain smtp URI as non-secure, no auth', () => {
    expect(parseSmtpUri('smtp://mailpit:1025')).toEqual({ host: 'mailpit', port: 1025, secure: false });
  });

  it('defaults the port by scheme when absent', () => {
    expect(parseSmtpUri('smtps://h').port).toBe(465);
    expect(parseSmtpUri('smtp://h').port).toBe(587);
  });

  it('rejects an unsupported scheme', () => {
    expect(() => parseSmtpUri('http://h:80')).toThrow(MailerError);
  });

  it('rejects a non-URL', () => {
    expect(() => parseSmtpUri('not a uri')).toThrow(MailerError);
  });
});

describe('smtpTransportOptions()', () => {
  it('bounds connection, greeting and socket time', () => {
    expect(smtpTransportOptions()).toMatchObject({
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 30_000,
    });
  });
});

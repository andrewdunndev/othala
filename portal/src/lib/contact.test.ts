/**
 * contact.test.ts — rate-limiter regression tests using _resetForTests.
 *
 * Coverage: src/lib/contact.ts rateLimit() + _resetForTests().
 *
 * These complement the existing scripts/contact.test.mjs suite (which also
 * covers validateContact() + parseSmtpUri()). This file focuses on the
 * rate-limiter boundary cases that are most likely to regress:
 *
 *   1. Window capacity: 5 allowed, 6th blocked.
 *   2. Reset clears state — after _resetForTests() the budget is fresh.
 *   3. Per-key isolation — exhausting one key does not affect another.
 *   4. retryAfterSec is positive on block.
 *
 * The `_resetForTests` hook is called in beforeEach so tests are isolated
 * from each other's rate-limit state (the hits Map is module-level).
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { rateLimit, _resetForTests, validateContact, LIMITS } from './contact.js';

beforeEach(() => {
  _resetForTests();
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

  it('blocks the 6th attempt', () => {
    const key = 'test-key-2';
    for (let i = 0; i < 5; i++) rateLimit(key);
    const blocked = rateLimit(key);
    expect(blocked.allowed, '6th attempt must be blocked').toBe(false);
    expect(blocked.retryAfterSec, 'blocked caller must receive a positive retry hint').toBeGreaterThan(0);
  });

  it('_resetForTests clears state — budget is fresh after reset', () => {
    const key = 'test-key-3';
    // Exhaust the budget.
    for (let i = 0; i < 5; i++) rateLimit(key);
    expect(rateLimit(key).allowed, 'must be blocked before reset').toBe(false);

    // Reset — beforeEach fires before each test, but this inline reset tests
    // the _resetForTests semantics directly (the hook clears the hits Map).
    _resetForTests();

    // Budget must be fresh.
    expect(rateLimit(key).allowed, 'must be allowed after reset').toBe(true);
  });

  it('per-key isolation — exhausting key A does not affect key B', () => {
    const keyA = 'addr-a';
    const keyB = 'addr-b';
    for (let i = 0; i < 5; i++) rateLimit(keyA);
    expect(rateLimit(keyA).allowed, 'keyA must be blocked').toBe(false);
    expect(rateLimit(keyB).allowed, 'keyB must still be allowed').toBe(true);
  });

  it('sliding window — attempts outside the 10-min window expire', () => {
    const key = 'test-key-slide';
    const t0 = 1_000_000_000_000; // fixed epoch
    for (let i = 0; i < 5; i++) rateLimit(key, t0);
    expect(rateLimit(key, t0).allowed, 'must be blocked within window').toBe(false);
    // 11 minutes later the window has slid past all earlier timestamps.
    const t1 = t0 + 11 * 60 * 1000;
    expect(rateLimit(key, t1).allowed, 'must be allowed after window expiry').toBe(true);
  });
});

describe('validateContact() — smoke (mirrors scripts/contact.test.mjs)', () => {
  it('accepts a valid submission', () => {
    const r = validateContact({ name: 'Alice', type: 'access', message: 'please grant access' });
    expect(r.ok).toBe(true);
  });

  it('rejects an empty name', () => {
    expect(validateContact({ name: '', type: 'access', message: 'some message' }).ok).toBe(false);
  });

  it('rejects an over-length name', () => {
    expect(validateContact({ name: 'x'.repeat(LIMITS.nameMax + 1), type: 'access', message: 'msg' }).ok).toBe(false);
  });

  it('rejects unknown request type', () => {
    expect(validateContact({ name: 'Alice', type: 'hack', message: 'a real message' }).ok).toBe(false);
  });
});

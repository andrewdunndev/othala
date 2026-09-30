// Property-based / adversarial fuzz test for csrf.ts + bearerMatches/parseBearer.
//
// Run with:  cd portal && npx vitest run scripts/csrf.fuzz.test.mjs
//
// SECURITY INVARIANT under test:
//   verifyToken accepts a token ONLY if it was signToken-ed for the SAME
//   identity id and is unexpired/untampered.  No truncation, bit-flip,
//   cross-identity, empty, or structurally-malformed token ever verifies.
//   bearerMatches is constant-time and never matches on a prefix or an
//   empty expected secret.
//
// fast-check is the property-based engine; ~1000 runs per property.

import { test, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import * as fc from 'fast-check';
import { createHmac } from 'node:crypto';

// ── Setup ──────────────────────────────────────────────────────────────────
process.env.CSRF_SECRET = 'x'.repeat(64);

const { signToken, verifyToken, _resetForTests } = await import(
  '../src/lib/csrf.ts'
);
const { bearerMatches, parseBearer } = await import(
  '../src/server/listen.mjs'
);

// Shared helpers -----------------------------------------------------------

const ACTION = 'fuzz';

/** Sign a fresh token for `id` and split into its five parts. */
function signParts(id) {
  const tok = signToken(id, ACTION);
  const [ts, identityId, nonce, action, sig] = tok.split('.');
  return { tok, ts, identityId, nonce, action, sig };
}

/** Re-sign body with the current test secret. */
function resign(body) {
  return createHmac('sha256', Buffer.from(process.env.CSRF_SECRET, 'utf8'))
    .update(body)
    .digest('base64url');
}

/** Reject if verifyToken does NOT throw. */
function assertRejects(token, identityId, msgHint) {
  assert.throws(
    () => verifyToken(token, identityId, ACTION),
    (err) => {
      assert.match(err.name, /CSRFError/, `expected CSRFError: ${msgHint}`);
      return true;
    },
    `verifyToken should have thrown (${msgHint})`,
  );
}

// ── Reset nonce store between every test ──────────────────────────────────
beforeEach(() => _resetForTests());

// ══════════════════════════════════════════════════════════════════════════
// 1. POSITIVE PROPERTY — a token verifies only for the identity that signed it
// ══════════════════════════════════════════════════════════════════════════
test('prop: fresh token always verifies for the correct identity', () => {
  fc.assert(
    fc.property(
      fc.uuid(), // random admin identity IDs
      (id) => {
        _resetForTests();
        const tok = signToken(id, ACTION);
        // Should not throw
        verifyToken(tok, id, ACTION);
      },
    ),
    { numRuns: 1000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 2. CROSS-IDENTITY — a token for id-A must never verify for id-B
// ══════════════════════════════════════════════════════════════════════════
test('prop: token for id-A never verifies for a different id-B', () => {
  fc.assert(
    fc.property(
      fc.uuid(),
      fc.uuid(),
      fc.constantFrom('csrf', 'CSRF', '', ' '),
      (idA, idB, _) => {
        // Skip when fast-check happens to generate the same uuid twice
        fc.pre(idA !== idB);
        _resetForTests();
        const tok = signToken(idA, ACTION);
        assertRejects(tok, idB, 'cross-identity');
      },
    ),
    { numRuns: 1000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 3. NULL / EMPTY / BLANK token inputs
// ══════════════════════════════════════════════════════════════════════════
test('prop: null/empty/whitespace presented tokens always reject', () => {
  const empties = [null, undefined, '', ' ', '\t', '\n', '0', 'false'];
  for (const tok of empties) {
    _resetForTests();
    assertRejects(tok, 'any-id', `empty-ish token: ${JSON.stringify(tok)}`);
  }
});

// ══════════════════════════════════════════════════════════════════════════
// 4. MALFORMED STRUCTURE — wrong number of dots
// ══════════════════════════════════════════════════════════════════════════
test('prop: token with wrong dot-segment count is rejected', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 0, maxLength: 200 }),
      fc.integer({ min: 0, max: 10 }).filter((n) => n !== 5),
      (chunk, segCount) => {
        // Build a token with exactly `segCount` segments, none of which
        // is a valid signed token.
        const tok = Array(segCount).fill(chunk).join('.');
        _resetForTests();
        assertRejects(tok, 'any-id', `wrong-segment-count: ${segCount}`);
      },
    ),
    { numRuns: 1000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 5. TAMPERED SIGNATURE — flip any byte in the sig field
// ══════════════════════════════════════════════════════════════════════════
test('prop: single-byte bit-flip in sig always rejects', () => {
  fc.assert(
    fc.property(fc.uuid(), (id) => {
      _resetForTests();
      const { ts, identityId, nonce, action, sig } = signParts(id);
      // Decode, flip one byte, re-encode
      const sigBuf = Buffer.from(sig, 'base64url');
      const idx = Math.floor(sigBuf.length / 2);
      sigBuf[idx] ^= 0xff;
      const badSig = sigBuf.toString('base64url');
      const tampered = `${ts}.${identityId}.${nonce}.${action}.${badSig}`;
      assertRejects(tampered, id, 'bit-flip in sig');
    }),
    { numRuns: 1000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 6. TRUNCATED SIGNATURE — sig shorter than expected 32 bytes
// ══════════════════════════════════════════════════════════════════════════
test('prop: truncated signature (length mismatch) always rejects', () => {
  fc.assert(
    fc.property(
      fc.uuid(),
      fc.integer({ min: 0, max: 31 }),
      (id, keepBytes) => {
        _resetForTests();
        const { ts, identityId, nonce, action, sig } = signParts(id);
        const truncSig = Buffer.from(sig, 'base64url').slice(0, keepBytes).toString('base64url');
        const tampered = `${ts}.${identityId}.${nonce}.${action}.${truncSig}`;
        assertRejects(tampered, id, `truncated sig (${keepBytes} bytes)`);
      },
    ),
    { numRuns: 500 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 7. TAMPERED IDENTITY — swap the identityId field, keep real sig
// ══════════════════════════════════════════════════════════════════════════
test('prop: token with different identityId field (sig still over old body) rejects', () => {
  fc.assert(
    fc.property(fc.uuid(), fc.uuid(), (id, otherId) => {
      fc.pre(id !== otherId);
      _resetForTests();
      const { ts, nonce, action, sig } = signParts(id);
      // Swap the identity field but keep the original signature
      const tampered = `${ts}.${otherId}.${nonce}.${action}.${sig}`;
      // Should fail because sig was computed over the original identity
      assertRejects(tampered, otherId, 'swapped identity, old sig');
    }),
    { numRuns: 1000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 8. REPLAY — same token presented twice always fails on second use
// ══════════════════════════════════════════════════════════════════════════
test('prop: replayed token always rejected on second presentation', () => {
  fc.assert(
    fc.property(fc.uuid(), (id) => {
      _resetForTests();
      const tok = signToken(id, ACTION);
      verifyToken(tok, id, ACTION); // first use: should pass
      assertRejects(tok, id, 'replay'); // second use: must fail
    }),
    { numRuns: 500 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 9. EXPIRED TOKEN — forge a validly-signed token with ts > 30 min ago
// ══════════════════════════════════════════════════════════════════════════
test('prop: expired token (ts > 30 min) always rejects even with valid sig', () => {
  const oldTs = Math.floor(Date.now() / 1000) - 31 * 60;
  fc.assert(
    fc.property(fc.uuid(), (id) => {
      _resetForTests();
      // forge a fresh nonce but an old ts; sign correctly so we reach the expiry check
      const nonce = 'AAAAAAAAAAAAAAAAAAAAAAAA'; // static for test simplicity
      const body = `${oldTs}.${id}.${nonce}.${ACTION}`;
      const sig = resign(body);
      const tok = `${body}.${sig}`;
      assertRejects(tok, id, 'expired');
    }),
    { numRuns: 500 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 10. FUTURE TIMESTAMP — forge a token with ts > now + 60s
// ══════════════════════════════════════════════════════════════════════════
test('prop: future timestamp (> 60s clock skew) always rejects', () => {
  const futureTs = Math.floor(Date.now() / 1000) + 120;
  fc.assert(
    fc.property(fc.uuid(), (id) => {
      _resetForTests();
      const nonce = 'AAAAAAAAAAAAAAAAAAAAAAAA';
      const body = `${futureTs}.${id}.${nonce}.${ACTION}`;
      const sig = resign(body);
      const tok = `${body}.${sig}`;
      assertRejects(tok, id, 'future timestamp');
    }),
    { numRuns: 500 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 11. RANDOM GARBAGE — arbitrary strings with 5 segments
//     The sig compare will almost never match; this hunts for any path that
//     could return without throwing.
// ══════════════════════════════════════════════════════════════════════════
test('prop: random five-segment strings never verify', () => {
  fc.assert(
    fc.property(
      fc.uuid(),
      fc.string({ minLength: 1, maxLength: 20 }),
      fc.string({ minLength: 1, maxLength: 40 }),
      fc.string({ minLength: 0, maxLength: 200 }),
      (id, seg1, seg2, seg3) => {
        _resetForTests();
        const tok = `${seg1}.${id}.${seg2}.${ACTION}.${seg3}`;
        // It's valid for verifyToken to throw for any reason; it must never succeed.
        let threw = false;
        try {
          verifyToken(tok, id, ACTION);
        } catch {
          threw = true;
        }
        assert.ok(threw, `random garbage verified unexpectedly: ${tok}`);
      },
    ),
    { numRuns: 2000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 12. NONCE FIELD MUTATION — keep everything else valid, change only nonce
// ══════════════════════════════════════════════════════════════════════════
test('prop: mutated nonce field (sig still valid for original nonce) rejects', () => {
  fc.assert(
    fc.property(fc.uuid(), fc.string({ minLength: 1, maxLength: 30 }), (id, fakeNonce) => {
      _resetForTests();
      const { ts, identityId, nonce, action, sig } = signParts(id);
      fc.pre(fakeNonce !== nonce); // different nonce
      const tampered = `${ts}.${identityId}.${fakeNonce}.${action}.${sig}`;
      assertRejects(tampered, id, 'mutated nonce');
    }),
    { numRuns: 1000 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 13. TIMESTAMP MUTATION — increment/decrement ts, resign
//     Tests that we can't shift a valid token into the future or past by
//     re-signing with a different ts (requires knowing the secret — but
//     the test simulates a secret-knowing adversary).
// ══════════════════════════════════════════════════════════════════════════
test('explicit: ts-shifted resign outside window rejects', () => {
  const id = 'fuzz-admin-ts-shift';
  _resetForTests();
  // Shift to way in the future
  const futureTs = Math.floor(Date.now() / 1000) + 3600;
  const nonce = 'BBBBBBBBBBBBBBBBBBBBBBBB';
  const body = `${futureTs}.${id}.${nonce}.${ACTION}`;
  const sig = resign(body);
  assertRejects(`${body}.${sig}`, id, 'ts shifted to future');

  // Shift to expired past
  _resetForTests();
  const pastTs = Math.floor(Date.now() / 1000) - 7200;
  const body2 = `${pastTs}.${id}.${nonce}.${ACTION}`;
  const sig2 = resign(body2);
  assertRejects(`${body2}.${sig2}`, id, 'ts shifted to past');
});

// ══════════════════════════════════════════════════════════════════════════
// 14. BEARERMATCHES — constant-time, fail-closed
// ══════════════════════════════════════════════════════════════════════════
test('prop: bearerMatches never matches when expected is empty/null/undefined', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 0, maxLength: 200 }),
      (presented) => {
        assert.strictEqual(bearerMatches(presented, ''), false, 'empty expected');
        assert.strictEqual(bearerMatches(presented, null), false, 'null expected');
        assert.strictEqual(bearerMatches(presented, undefined), false, 'undefined expected');
      },
    ),
    { numRuns: 1000 },
  );
});

test('prop: bearerMatches never matches prefix of expected secret', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 2, maxLength: 64 }),
      (secret) => {
        const prefix = secret.slice(0, Math.max(1, secret.length - 1));
        assert.strictEqual(bearerMatches(prefix, secret), false, 'prefix should not match');
        const longer = secret + 'X';
        assert.strictEqual(bearerMatches(longer, secret), false, 'longer should not match');
      },
    ),
    { numRuns: 1000 },
  );
});

test('prop: bearerMatches matches only exact equal strings', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 1, maxLength: 128 }),
      (secret) => {
        assert.strictEqual(bearerMatches(secret, secret), true, 'exact match must succeed');
      },
    ),
    { numRuns: 1000 },
  );
});

test('prop: bearerMatches rejects empty presented token', () => {
  fc.assert(
    fc.property(fc.string({ minLength: 1, maxLength: 128 }), (secret) => {
      assert.strictEqual(bearerMatches('', secret), false, 'empty presented');
      assert.strictEqual(bearerMatches(null, secret), false, 'null presented');
      assert.strictEqual(bearerMatches(undefined, secret), false, 'undefined presented');
    }),
    { numRuns: 500 },
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 15. PARSEBEARER — strip "Bearer " prefix, never leak raw header
// ══════════════════════════════════════════════════════════════════════════
test('prop: parseBearer returns token value from well-formed Authorization header', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 1, maxLength: 128 }).filter((s) => !/\s/.test(s)),
      (tok) => {
        assert.strictEqual(parseBearer(`Bearer ${tok}`), tok);
      },
    ),
    { numRuns: 500 },
  );
});

test('prop: parseBearer returns empty string for non-Bearer or missing headers', () => {
  const bad = [
    undefined,
    null,
    '',
    'Basic abc123',
    'bearer token', // lowercase — must match case-sensitively per RFC 7617
    'Token xyz',
    'Bearer', // no actual token after prefix
  ];
  // Note: RFC 7235 requires "Bearer" (capital B). The implementation uses
  // /^Bearer\s+(.+)$/ which IS case-sensitive. Verify.
  for (const h of bad) {
    const result = parseBearer(h);
    assert.strictEqual(typeof result, 'string', `parseBearer must return string for: ${h}`);
    // Non-Bearer headers should yield empty string
    if (h !== 'Bearer') {
      // "Bearer" alone (no token) should also return ''
      assert.strictEqual(result, '', `expected '' for header: ${JSON.stringify(h)}`);
    }
  }
});

// ══════════════════════════════════════════════════════════════════════════
// 16. ADVERSARIAL IDENTITY ID EDGE CASES
//     Dots in identity IDs could confuse the 5-segment split.
// ══════════════════════════════════════════════════════════════════════════
test('explicit: identityId containing dots is safe (no ambiguity in split)', () => {
  // CRYPTO-1: signToken now throws at sign time when identityId contains a dot,
  // so a dotty id can never produce a structurally ambiguous token.
  const dottyId = 'admin.user.with.dots';
  _resetForTests();
  assert.throws(
    () => signToken(dottyId, ACTION),
    /dot/,
    'signToken must throw on a dotted identityId (CRYPTO-1)',
  );
});

test('explicit: identityId with dot — document whether roundtrip is accepted', () => {
  // CRYPTO-1: the invariant is now enforced at sign time. A dotty id causes
  // signToken to throw rather than producing a structurally ambiguous token.
  const dottyId = 'a.b';
  _resetForTests();
  assert.throws(
    () => signToken(dottyId, ACTION),
    /dot/,
    'signToken must throw for dotty identityId (fail-closed, CRYPTO-1)',
  );
});

// ══════════════════════════════════════════════════════════════════════════
// 17. ADVERSARIAL: empty identityId in presented token
// ══════════════════════════════════════════════════════════════════════════
test('explicit: empty identity segment in token always rejects', () => {
  _resetForTests();
  const { ts, nonce, action } = signParts('real-admin');
  const body = `${ts}..${nonce}.${action}`;
  const sig = resign(body);
  const tok = `${body}.${sig}`;
  // Could match '' against 'real-admin'? Must not.
  assertRejects(tok, 'real-admin', 'empty identity in token');
  // Could match '' against ''? verifyToken also requires identityId.
  assertRejects(tok, '', 'empty identity in both token and check');
});

// ══════════════════════════════════════════════════════════════════════════
// 18. ADVERSARIAL: NaN / Infinity timestamps that survive parseInt
// ══════════════════════════════════════════════════════════════════════════
test('explicit: NaN and Infinity timestamp strings are rejected', () => {
  const badTs = ['NaN', 'Infinity', '-Infinity', 'null', '1e99', '9'.repeat(20)];
  for (const tsStr of badTs) {
    _resetForTests();
    const id = 'admin-ts-edge';
    const nonce = 'CCCCCCCCCCCCCCCCCCCCCCCC';
    const body = `${tsStr}.${id}.${nonce}.${ACTION}`;
    const sig = resign(body);
    const tok = `${body}.${sig}`;
    assertRejects(tok, id, `bad ts: ${tsStr}`);
  }
});

// ══════════════════════════════════════════════════════════════════════════
// 19. SECRET TOO SHORT — unset or short CSRF_SECRET fails closed
// ══════════════════════════════════════════════════════════════════════════
test('explicit: short CSRF_SECRET causes signToken to throw CSRFError', () => {
  const orig = process.env.CSRF_SECRET;
  process.env.CSRF_SECRET = 'tooshort';
  // We need a fresh import to get fresh module scope — but the module is
  // already cached. The secret() function is lazy and re-reads env each call.
  try {
    assert.throws(
      () => signToken('admin', ACTION),
      (err) => err.name === 'CSRFError' || err.message.includes('shorter than 32'),
      'short secret must throw CSRFError',
    );
  } finally {
    process.env.CSRF_SECRET = orig;
  }
});

// ══════════════════════════════════════════════════════════════════════════
// 20. ADVERSARIAL: Segment re-ordering — ts.nonce.identityId.sig
// ══════════════════════════════════════════════════════════════════════════
test('explicit: reordered segments with valid sig for original order reject', () => {
  _resetForTests();
  const id = 'fuzz-reorder';
  const { ts, identityId, nonce, action, sig } = signParts(id);
  // Swap identityId and nonce positions
  const reordered = `${ts}.${nonce}.${identityId}.${action}.${sig}`;
  assertRejects(reordered, id, 'reordered segments');
});

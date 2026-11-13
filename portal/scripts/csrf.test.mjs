// Invariants: a token verifies only for its identity and action, once, before expiry, and only if its HMAC holds;
// no mutated CSRF token or bearer value verifies.

import { test, beforeEach, describe, it, expect } from 'vitest';
import assert from 'node:assert/strict';
import * as fc from 'fast-check';
import { createHmac } from 'node:crypto';

process.env.CSRF_SECRET = 'x'.repeat(64);

const { signToken, verifyToken, CSRFError, _resetForTests } = await import(
  '../src/lib/csrf.ts'
);
const { bearerMatches, parseBearer } = await import(
  '../src/server/listen.ts'
);

const ACTION = 'fuzz';

function signParts(id) {
  const tok = signToken(id, ACTION);
  const [ts, identityId, nonce, action, sig] = tok.split('.');
  return { tok, ts, identityId, nonce, action, sig };
}

function resign(body) {
  return createHmac('sha256', Buffer.from(process.env.CSRF_SECRET, 'utf8'))
    .update(body)
    .digest('base64url');
}

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

beforeEach(() => _resetForTests());

test('prop: fresh token always verifies for the correct identity', () => {
  fc.assert(
    fc.property(
      fc.uuid(), // random admin identity IDs
      (id) => {
        _resetForTests();
        const tok = signToken(id, ACTION);
        verifyToken(tok, id, ACTION);
      },
    ),
    { numRuns: 1000 },
  );
});

test('prop: token for id-A never verifies for a different id-B', () => {
  fc.assert(
    fc.property(
      fc.uuid(),
      fc.uuid(),
      fc.constantFrom('csrf', 'CSRF', '', ' '),
      (idA, idB, _) => {
        fc.pre(idA !== idB);
        _resetForTests();
        const tok = signToken(idA, ACTION);
        assertRejects(tok, idB, 'cross-identity');
      },
    ),
    { numRuns: 1000 },
  );
});

test('prop: null/empty/whitespace presented tokens always reject', () => {
  const empties = [null, undefined, '', ' ', '\t', '\n', '0', 'false'];
  for (const tok of empties) {
    _resetForTests();
    assertRejects(tok, 'any-id', `empty-ish token: ${JSON.stringify(tok)}`);
  }
});

test('prop: token with wrong dot-segment count is rejected', () => {
  fc.assert(
    fc.property(
      fc.string({ minLength: 0, maxLength: 200 }),
      fc.integer({ min: 0, max: 10 }).filter((n) => n !== 5),
      (chunk, segCount) => {
        const tok = Array(segCount).fill(chunk).join('.');
        _resetForTests();
        assertRejects(tok, 'any-id', `wrong-segment-count: ${segCount}`);
      },
    ),
    { numRuns: 1000 },
  );
});

test('prop: single-byte bit-flip in sig always rejects', () => {
  fc.assert(
    fc.property(fc.uuid(), (id) => {
      _resetForTests();
      const { ts, identityId, nonce, action, sig } = signParts(id);
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

test('prop: token with different identityId field (sig still over old body) rejects', () => {
  fc.assert(
    fc.property(fc.uuid(), fc.uuid(), (id, otherId) => {
      fc.pre(id !== otherId);
      _resetForTests();
      const { ts, nonce, action, sig } = signParts(id);
      const tampered = `${ts}.${otherId}.${nonce}.${action}.${sig}`;
      assertRejects(tampered, otherId, 'swapped identity, old sig');
    }),
    { numRuns: 1000 },
  );
});

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

test('prop: expired token (ts > 30 min) always rejects even with valid sig', () => {
  const oldTs = Math.floor(Date.now() / 1000) - 31 * 60;
  fc.assert(
    fc.property(fc.uuid(), (id) => {
      _resetForTests();
      const nonce = 'AAAAAAAAAAAAAAAAAAAAAAAA'; // static for test simplicity
      const body = `${oldTs}.${id}.${nonce}.${ACTION}`;
      const sig = resign(body);
      const tok = `${body}.${sig}`;
      assertRejects(tok, id, 'expired');
    }),
    { numRuns: 500 },
  );
});

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
  for (const h of bad) {
    const result = parseBearer(h);
    assert.strictEqual(typeof result, 'string', `parseBearer must return string for: ${h}`);
    if (h !== 'Bearer') {
      assert.strictEqual(result, '', `expected '' for header: ${JSON.stringify(h)}`);
    }
  }
});

test('explicit: empty identity segment in token always rejects', () => {
  _resetForTests();
  const { ts, nonce, action } = signParts('real-admin');
  const body = `${ts}..${nonce}.${action}`;
  const sig = resign(body);
  const tok = `${body}.${sig}`;
  assertRejects(tok, 'real-admin', 'empty identity in token');
  assertRejects(tok, '', 'empty identity in both token and check');
});

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

test('explicit: short CSRF_SECRET causes signToken to throw CSRFError', () => {
  const orig = process.env.CSRF_SECRET;
  process.env.CSRF_SECRET = 'tooshort';
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

test('explicit: reordered segments with valid sig for original order reject', () => {
  _resetForTests();
  const id = 'fuzz-reorder';
  const { ts, identityId, nonce, action, sig } = signParts(id);
  const reordered = `${ts}.${nonce}.${identityId}.${action}.${sig}`;
  assertRejects(reordered, id, 'reordered segments');
});

describe('token rules', () => {
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
      expect(() => verifyToken(signToken(IDENTITY, 'save') + '.x', IDENTITY, 'save')).toThrow(/malformed/);
    });

    it('rejects a 4-part token without an action', () => {
      const body = `${Math.floor(Date.now() / 1000)}.${IDENTITY}.nonce`;
      const sig = createHmac('sha256', Buffer.from(process.env['CSRF_SECRET'], 'utf8')).update(body).digest('base64url');
      const tok = `${body}.${sig}`;
      expect(() => verifyToken(tok, IDENTITY)).toThrow(CSRFError);
    });

    it('requires an action to sign', () => {
      expect(() => signToken(IDENTITY)).toThrow(CSRFError);
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
      let err = null;
      try {
        verifyToken(tok, IDENTITY, 'deactivate');
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(CSRFError);
      expect(err.message).toMatch(/action mismatch/i);
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
      const sig = createHmac('sha256', Buffer.from(process.env['CSRF_SECRET'], 'utf8')).update(body).digest('base64url');
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
        msg = e.message;
      }
      expect(msg).not.toMatch(/[<>]/);
      expect(msg).toContain("'consent'");
    });

    it('FIX-H: a safe presented action stays readable in the mismatch message', () => {
      let msg = '';
      try {
        verifyToken(signToken('admin-1', 'deactivate'), 'admin-1', 'consent');
      } catch (e) {
        msg = e.message;
      }
      expect(msg).toContain("'consent'");
      expect(msg).toContain("'deactivate'");
    });
  });
});

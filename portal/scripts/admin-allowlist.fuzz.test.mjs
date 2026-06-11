// Adversarial property-based fuzz harness for admin-auth.ts (CVP-P1)
//
// Surface: admin-allowlist — isAdminId + adminIds parsing
// Invariant: isAdminId returns true ONLY for an exact (normalized) member
//   of OTHALA_ADMIN_IDS. No case/whitespace/injection trick makes a
//   non-listed UUID admin. Empty/whitespace allowlist is fail-closed
//   (nobody is admin). Missing/null/empty id is never admin.
//
// Run: tsx --test scripts/admin-allowlist.fuzz.test.mjs
//
// This file is a durable security artifact — leave it in place.

import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { isAdminId, adminIds } from '../src/lib/admin-auth.ts';

// ── helpers ─────────────────────────────────────────────────────────────────

const SEED_IDS = [
  '11111111-1111-1111-1111-111111111111',
  '22222222-2222-2222-2222-222222222222',
  '33333333-3333-3333-3333-333333333333',
  'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
];

/** UUID-shaped arbitrary (lowercase hex + dashes). */
const hexSegment = (len) => fc.stringMatching(new RegExp(`^[0-9a-f]{${len}}$`));
const uuidArb = fc.tuple(
  hexSegment(8),
  hexSegment(4),
  hexSegment(4),
  hexSegment(4),
  hexSegment(12),
).map(([a, b, c, d, e]) => `${a}-${b}-${c}-${d}-${e}`);

/** Install allowlist in env and call fn, then clean up. */
function withAllowlist(ids, fn) {
  process.env.OTHALA_ADMIN_IDS = ids;
  try {
    return fn();
  } finally {
    delete process.env.OTHALA_ADMIN_IDS;
  }
}

// Save/restore env so tests stay isolated even if they throw
let savedEnv;
beforeEach(() => {
  savedEnv = process.env.OTHALA_ADMIN_IDS;
  delete process.env.OTHALA_ADMIN_IDS;
});
afterEach(() => {
  if (savedEnv === undefined) {
    delete process.env.OTHALA_ADMIN_IDS;
  } else {
    process.env.OTHALA_ADMIN_IDS = savedEnv;
  }
});

// ── invariant helpers ────────────────────────────────────────────────────────

/**
 * Core invariant check for a single (allowlist, candidate) pair.
 * The candidate should be admin iff its normalized form is in the allowlist.
 */
function assertInvariant(allowlistRaw, candidateId) {
  withAllowlist(allowlistRaw, () => {
    const ids = adminIds();
    const normalized = typeof candidateId === 'string'
      ? candidateId.trim().toLowerCase()
      : '';

    const inSet = normalized !== '' && ids.has(normalized);
    const result = isAdminId(candidateId);

    if (inSet) {
      assert.equal(result, true,
        `INVARIANT VIOLATION: "${candidateId}" normalized to "${normalized}" IS in allowlist ${JSON.stringify([...ids])} but isAdminId returned false`);
    } else {
      assert.equal(result, false,
        `INVARIANT VIOLATION: "${candidateId}" normalized to "${normalized}" is NOT in allowlist ${JSON.stringify([...ids])} but isAdminId returned true`);
    }
  });
}

// ── Section 1: Fail-closed properties ────────────────────────────────────────

test('fail-closed: unset env → no id is admin', () => {
  // OTHALA_ADMIN_IDS is deleted in beforeEach
  for (const id of SEED_IDS) {
    assert.equal(isAdminId(id), false, `Unset allowlist: "${id}" should not be admin`);
  }
});

test('fail-closed: empty string allowlist → no id is admin', () => {
  withAllowlist('', () => {
    for (const id of SEED_IDS) {
      assert.equal(isAdminId(id), false, `Empty allowlist: "${id}" should not be admin`);
    }
  });
});

test('fail-closed: whitespace-only / comma-only allowlist → no id is admin', () => {
  const whitespaceAllowlists = [
    '   ',
    ',',
    ' , ',
    ',,',
    ' , , , ',
    '\t',
    '\n',
    '\r\n',
    '   ,   ,   ',
  ];
  for (const raw of whitespaceAllowlists) {
    withAllowlist(raw, () => {
      assert.equal(adminIds().size, 0,
        `Allowlist "${JSON.stringify(raw)}" should parse to empty set`);
      for (const id of SEED_IDS) {
        assert.equal(isAdminId(id), false,
          `Whitespace allowlist "${JSON.stringify(raw)}": "${id}" should not be admin`);
      }
    });
  }
});

test('fail-closed: null/undefined/empty id is never admin regardless of allowlist', () => {
  for (const id of SEED_IDS) {
    withAllowlist(id, () => {
      assert.equal(isAdminId(null), false, 'null id → false');
      assert.equal(isAdminId(undefined), false, 'undefined id → false');
      assert.equal(isAdminId(''), false, 'empty-string id → false');
      assert.equal(isAdminId('   '), false, 'whitespace-only id → false');
    });
  }
});

// ── Section 2: Non-member should never become admin ──────────────────────────

test('adversarial: non-listed id never becomes admin (seed allowlist + seed input)', () => {
  for (const adminId of SEED_IDS) {
    withAllowlist(adminId, () => {
      for (const otherId of SEED_IDS.filter((x) => x !== adminId)) {
        assert.equal(isAdminId(otherId), false,
          `Non-member "${otherId}" must not be admin when only "${adminId}" is allowed`);
      }
    });
  }
});

test('adversarial: case-folding is symmetric — listed-as-upper matches lower candidate', () => {
  const id = SEED_IDS[0];
  const upper = id.toUpperCase();
  withAllowlist(upper, () => {
    assert.equal(isAdminId(id), true,
      `Listed as "${upper}", candidate "${id}" (lower) should be admin`);
    assert.equal(isAdminId(upper), true,
      `Listed as "${upper}", candidate "${upper}" (same upper) should be admin`);
    assert.equal(isAdminId(SEED_IDS[1]), false,
      `Non-member "${SEED_IDS[1]}" must not be admin`);
  });
});

test('adversarial: extra whitespace variants in candidate id', () => {
  const id = SEED_IDS[0];
  withAllowlist(id, () => {
    // These SHOULD be admitted (trailing/leading whitespace trimmed)
    assert.equal(isAdminId(`  ${id}`), true, `Leading space: "${id}" should be admin after trim`);
    assert.equal(isAdminId(`${id}  `), true, `Trailing space: "${id}" should be admin after trim`);
    assert.equal(isAdminId(`  ${id}  `), true, `Both: "${id}" should be admin after trim`);
  });
});

// ── Section 3: Injection / parsing attacks on the env value ──────────────────

test('adversarial: env value with embedded newlines — newline must not act as separator', () => {
  const injected = `${SEED_IDS[0]}\n${SEED_IDS[1]}`;
  withAllowlist(injected, () => {
    const ids = adminIds();
    // The injected value is ONE token (with the internal newline).
    // Neither UUID on its own should be found via exact match.
    assert.equal(isAdminId(SEED_IDS[0]), false,
      'Newline injection: first UUID alone must NOT be admitted when listed as multi-line blob');
    assert.equal(isAdminId(SEED_IDS[1]), false,
      'Newline injection: second UUID alone must NOT be admitted');
    const arr = [...ids];
    assert.equal(arr.length <= 1, true,
      `Newline-embedded allowlist should parse to at most one token, got: ${JSON.stringify(arr)}`);
  });
});

test('adversarial: null bytes in id must not bypass allowlist', () => {
  const id = SEED_IDS[0];
  withAllowlist(id, () => {
    const nullVariants = [
      `${id.slice(0, 8)}\x00${id.slice(8)}`,
      `\x00${id}`,
    ];
    for (const v of nullVariants) {
      assert.equal(isAdminId(v), false,
        `Null-byte variant "${JSON.stringify(v)}" must not be admin`);
    }
  });
});

test('adversarial: very long id strings do not crash or grant access', () => {
  const huge = 'a'.repeat(100_000);
  withAllowlist(SEED_IDS[0], () => {
    assert.equal(isAdminId(huge), false, 'Huge id must not be admin');
  });
});

test('adversarial: special regex / injection characters in id must not grant access', () => {
  withAllowlist(SEED_IDS[0], () => {
    const special = [
      '.*',
      '.+',
      `^${SEED_IDS[0]}$`,
      `${SEED_IDS[0]}|${SEED_IDS[1]}`,
      `${SEED_IDS[0]}"`,
      `${SEED_IDS[0]}'`,
    ];
    for (const addr of special) {
      assert.equal(isAdminId(addr), false,
        `Special-char id "${addr}" must not be admin`);
    }
  });
});

// ── Section 4: Allowlist parsing edge cases ───────────────────────────────────

test('parsing: trailing comma does not admit empty string as admin id', () => {
  withAllowlist(`${SEED_IDS[0]},`, () => {
    const ids = adminIds();
    assert.ok(!ids.has(''), 'empty string must not be in admin set');
    assert.equal(isAdminId(''), false);
    assert.equal(isAdminId(undefined), false);
    assert.equal(isAdminId(null), false);
    assert.equal(isAdminId(SEED_IDS[0]), true);
  });
});

test('parsing: leading comma does not admit empty string as admin id', () => {
  withAllowlist(`,${SEED_IDS[0]}`, () => {
    const ids = adminIds();
    assert.ok(!ids.has(''), 'empty string must not be in admin set');
    assert.equal(isAdminId(SEED_IDS[0]), true);
  });
});

test('parsing: duplicate entries do not multiply-admit (Set deduplication)', () => {
  const id = SEED_IDS[0];
  withAllowlist(`${id},${id},${id.toUpperCase()}`, () => {
    const ids = adminIds();
    assert.equal(ids.size, 1, 'Duplicate entries should collapse to one');
    assert.equal(isAdminId(id), true);
  });
});

// ── Section 5: Full property test — core invariant ───────────────────────────

test('CORE INVARIANT: isAdminId ↔ exact normalized membership (500 runs)', () => {
  fc.assert(
    fc.property(
      fc.array(uuidArb, { minLength: 0, maxLength: 5 }),
      uuidArb,
      (allowedList, candidate) => {
        const rawAllowlist = allowedList.join(',');
        assertInvariant(rawAllowlist, candidate);
      },
    ),
    { numRuns: 500, seed: 20260611 },
  );
});

test('CORE INVARIANT: case-folded allowlist entries — random mixed-case (300 runs)', () => {
  fc.assert(
    fc.property(
      uuidArb,
      fc.boolean(), // whether to upper-case the allowlist entry
      fc.boolean(), // whether to upper-case the candidate
      (id, upperAllowlist, upperCandidate) => {
        const allowlistEntry = upperAllowlist ? id.toUpperCase() : id.toLowerCase();
        const candidateEntry = upperCandidate ? id.toUpperCase() : id.toLowerCase();
        withAllowlist(allowlistEntry, () => {
          assert.equal(isAdminId(candidateEntry), true,
            `Mixed-case: allowlist="${allowlistEntry}" candidate="${candidateEntry}" should be admin`);
        });
      },
    ),
    { numRuns: 300 },
  );
});

test('CORE INVARIANT: no non-member ever becomes admin under random adversarial inputs (500 runs)', () => {
  const adminId = SEED_IDS[0];
  withAllowlist(adminId, () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 200 }).filter(
          (s) => s.trim().toLowerCase() !== adminId,
        ),
        (candidate) => {
          assert.equal(isAdminId(candidate), false,
            `Non-member "${candidate}" must not be admin`);
        },
      ),
      { numRuns: 500 },
    );
  });
});

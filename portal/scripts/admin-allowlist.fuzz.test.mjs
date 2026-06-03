// Adversarial property-based fuzz harness for admin-auth.ts
//
// Surface: admin-allowlist — isAdminSubject + adminSubjects parsing
// Invariant: isAdminSubject returns true ONLY for an exact (normalized) member
//   of OTHALA_ADMIN_SUBJECTS. No case/whitespace/unicode/sub-address/injection
//   trick makes a non-listed email admin. Empty/whitespace allowlist is
//   fail-closed (nobody is admin). Missing/null/empty email is never admin.
//
// Run: tsx --test scripts/admin-allowlist.fuzz.test.mjs
//
// This file is a durable security artifact — leave it in place.

import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { isAdminSubject, adminSubjects } from '../src/lib/admin-auth.ts';

// ── helpers ─────────────────────────────────────────────────────────────────

const SEED_EMAILS = [
  'admin@example.com',
  'andrew@dunn.dev',
  'ops@dunn.dev',
  'root@local',
];

/** Install allowlist in env and call fn, then clean up. */
function withAllowlist(subjects, fn) {
  process.env.OTHALA_ADMIN_SUBJECTS = subjects;
  try {
    return fn();
  } finally {
    delete process.env.OTHALA_ADMIN_SUBJECTS;
  }
}

// Save/restore env so tests stay isolated even if they throw
let savedEnv;
beforeEach(() => {
  savedEnv = process.env.OTHALA_ADMIN_SUBJECTS;
  delete process.env.OTHALA_ADMIN_SUBJECTS;
});
afterEach(() => {
  if (savedEnv === undefined) {
    delete process.env.OTHALA_ADMIN_SUBJECTS;
  } else {
    process.env.OTHALA_ADMIN_SUBJECTS = savedEnv;
  }
});

// ── invariant helpers ────────────────────────────────────────────────────────

/**
 * Core invariant check for a single (allowlist, candidate) pair.
 * The candidate should be admin iff its normalized form is in the allowlist.
 */
function assertInvariant(allowlistRaw, candidateEmail) {
  withAllowlist(allowlistRaw, () => {
    const subjects = adminSubjects();
    const normalized = typeof candidateEmail === 'string'
      ? candidateEmail.trim().toLowerCase()
      : '';

    // Exact-member check: if normalized form is in the set, it must be admin.
    const inSet = normalized !== '' && subjects.has(normalized);
    const result = isAdminSubject(candidateEmail);

    if (inSet) {
      assert.equal(result, true,
        `INVARIANT VIOLATION: "${candidateEmail}" normalized to "${normalized}" IS in allowlist ${JSON.stringify([...subjects])} but isAdminSubject returned false`);
    } else {
      assert.equal(result, false,
        `INVARIANT VIOLATION: "${candidateEmail}" normalized to "${normalized}" is NOT in allowlist ${JSON.stringify([...subjects])} but isAdminSubject returned true`);
    }
  });
}

// ── Section 1: Fail-closed properties ────────────────────────────────────────

test('fail-closed: unset env → no email is admin', () => {
  // OTHALA_ADMIN_SUBJECTS is deleted in beforeEach
  fc.assert(
    fc.property(fc.emailAddress(), (email) => {
      assert.equal(isAdminSubject(email), false,
        `Unset allowlist: "${email}" should not be admin`);
    }),
    { numRuns: 500 },
  );
});

test('fail-closed: empty string allowlist → no email is admin', () => {
  fc.assert(
    fc.property(fc.emailAddress(), (email) => {
      withAllowlist('', () => {
        assert.equal(isAdminSubject(email), false,
          `Empty allowlist: "${email}" should not be admin`);
      });
    }),
    { numRuns: 500 },
  );
});

test('fail-closed: whitespace-only / comma-only allowlist → no email is admin', () => {
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
      assert.equal(adminSubjects().size, 0,
        `Allowlist "${JSON.stringify(raw)}" should parse to empty set`);
      for (const email of SEED_EMAILS) {
        assert.equal(isAdminSubject(email), false,
          `Whitespace allowlist "${JSON.stringify(raw)}": "${email}" should not be admin`);
      }
    });
  }
});

test('fail-closed: null/undefined/empty email is never admin regardless of allowlist', () => {
  for (const email of SEED_EMAILS) {
    withAllowlist(email, () => {
      assert.equal(isAdminSubject(null), false, 'null email → false');
      assert.equal(isAdminSubject(undefined), false, 'undefined email → false');
      assert.equal(isAdminSubject(''), false, 'empty-string email → false');
      assert.equal(isAdminSubject('   '), false, 'whitespace-only email → false');
    });
  }
});

// ── Section 2: Non-member should never become admin ──────────────────────────

test('adversarial: non-listed email never becomes admin (random allowlist + random input)', () => {
  fc.assert(
    fc.property(
      // allowlist: 1-3 seed emails in random order
      fc.shuffledSubarray(SEED_EMAILS, { minLength: 1 }),
      // candidate: a different email not in the seed list
      fc.emailAddress().filter((e) => !SEED_EMAILS.includes(e.toLowerCase())),
      (allowedArr, candidate) => {
        assertInvariant(allowedArr.join(','), candidate);
      },
    ),
    { numRuns: 1000 },
  );
});

test('adversarial: unicode look-alike characters must not bypass the allowlist', () => {
  // Unicode homoglyphs and confusables that could look like ASCII chars
  // but won't equal after ASCII toLowerCase.
  const lookalikes = [
    // Full-width latin
    'ａｄｍｉｎ＠ｅｘａｍｐｌｅ．ｃｏｍ',
    // Mixed full-width
    'admin@ｅxample.com',
    // Dotless i (Turkish) — toLowerCase('İ') ≠ 'i' in some locales but JS is unicode-based
    'Admın@example.com',
    // Zero-width characters injected into email
    'admin​@example.com',
    'admin@example​.com',
    // Right-to-left override (RTLO)
    'admin@example‮.com',
    // Combining diacritics that look like plain letters
    'admiǹ@example.com',
    // NFKC decompositions — ℂ ℍ etc.
    'ℂ@example.com',
  ];
  withAllowlist('admin@example.com', () => {
    for (const candidate of lookalikes) {
      assert.equal(isAdminSubject(candidate), false,
        `Unicode lookalike "${candidate}" must not be admin when only "admin@example.com" is allowed`);
    }
  });
});

test('adversarial: sub-addressing (plus-addressing) must not bypass allowlist', () => {
  // RFC 5321 sub-addresses: admin+something@example.com — NOT the same as admin@example.com
  withAllowlist('admin@example.com', () => {
    const subAddresses = [
      'admin+anything@example.com',
      'admin+@example.com',
      'admin++@example.com',
      'admin+admin@example.com',
      'ADMIN+BYPASS@example.com',
    ];
    for (const addr of subAddresses) {
      assert.equal(isAdminSubject(addr), false,
        `Sub-address "${addr}" must not be admin (allowlist only has "admin@example.com")`);
    }
  });
});

test('adversarial: extra whitespace variants in candidate email', () => {
  // The function does trim the candidate, so "  admin@example.com  " should work
  // when admin@example.com is listed. This proves BOTH directions:
  //   - trimmed listed email → admin (expected true after trim)
  //   - padded non-listed email → false
  withAllowlist('admin@example.com', () => {
    // These SHOULD be admitted (trailing/leading whitespace trimmed by the function)
    const shouldBeAdmin = [
      '  admin@example.com',
      'admin@example.com  ',
      '  admin@example.com  ',
    ];
    for (const addr of shouldBeAdmin) {
      assert.equal(isAdminSubject(addr), true,
        `"${addr}" should be admin after trim (listed as "admin@example.com")`);
    }

    // Whitespace INSIDE the local part or domain is not a valid email but
    // must not grant access if the normalized form isn't in the set.
    const shouldNotBeAdmin = [
      'admin @example.com',   // space inside
      'admin@ example.com',   // space inside
      '\tadmin@example.com',  // tab (trimmed, but then "admin@example.com" — actually this IS trim-equivalent)
    ];
    // '\tadmin@example.com' trims to 'admin@example.com' — it WOULD match.
    // Only test the space-inside-local variants.
    assert.equal(isAdminSubject('admin @example.com'), false,
      '"admin @example.com" (space inside local) must not be admin');
    assert.equal(isAdminSubject('admin@ example.com'), false,
      '"admin@ example.com" (space after @) must not be admin');
  });
});

test('adversarial: case-folding is symmetric — listed-as-upper matches lower candidate', () => {
  fc.assert(
    fc.property(
      fc.emailAddress(),
      (email) => {
        const upper = email.toUpperCase();
        withAllowlist(upper, () => {
          // The lower-case form should be admitted (allowlist normalized to lower)
          assert.equal(isAdminSubject(email), true,
            `Listed as "${upper}", candidate "${email}" (lower) should be admin`);
          // The exact upper-case form should also be admitted
          assert.equal(isAdminSubject(upper), true,
            `Listed as "${upper}", candidate "${upper}" (same upper) should be admin`);
          // A different email should not be admitted
          assert.equal(isAdminSubject('definitely.not.listed@example.invalid'), false);
        });
      },
    ),
    { numRuns: 300 },
  );
});

// ── Section 3: Injection / parsing attacks on the env value ──────────────────

test('adversarial: env value with embedded newlines — newline must not act as separator', () => {
  // The parser only splits on commas. A newline in the env value is part of
  // the token; after trim it may still contain internal newlines.
  // e.g. "admin@example.com\nevil@evil.com" — evildoer tries to inject a
  // second email by embedding a newline.
  const injected = 'admin@example.com\nevil@evil.com';
  withAllowlist(injected, () => {
    const subjects = adminSubjects();
    // The injected value is ONE token: "admin@example.com\nevil@evil.com"
    // (with the internal newline). Neither email on its own should be found.
    assert.equal(isAdminSubject('admin@example.com'), false,
      'Newline injection: "admin@example.com" alone must NOT be admitted when listed as multi-line blob');
    assert.equal(isAdminSubject('evildoer@evil.com'), false,
      'Newline injection: injected "evildoer@evil.com" must not be admitted');
    // The combined blob (with trimming of leading/trailing whitespace, not internal)
    // might match if someone sends the exact blob — that's the token stored.
    // Just verify the set has exactly one member (the blob) or zero after trim.
    const arr = [...subjects];
    assert.equal(arr.length <= 1, true,
      `Newline-embedded allowlist should parse to at most one token, got: ${JSON.stringify(arr)}`);
  });
});

test('adversarial: null bytes in email must not bypass allowlist', () => {
  withAllowlist('admin@example.com', () => {
    const nullVariants = [
      'admin\x00@example.com',
      'adm\x00in@example.com',
      '\x00admin@example.com',
    ];
    for (const v of nullVariants) {
      assert.equal(isAdminSubject(v), false,
        `Null-byte variant "${JSON.stringify(v)}" must not be admin`);
    }
  });
});

test('adversarial: very long email strings do not crash or grant access', () => {
  const huge = 'a'.repeat(100_000) + '@example.com';
  withAllowlist('admin@example.com', () => {
    assert.equal(isAdminSubject(huge), false, 'Huge email must not be admin');
  });
  // Also test huge allowlist value does not grant access to a non-member
  withAllowlist('a'.repeat(100_000) + '@example.com,admin@example.com', () => {
    assert.equal(isAdminSubject('admin@example.com'), true, 'admin still in huge allowlist');
    assert.equal(isAdminSubject('other@example.com'), false, 'non-member not admin in huge allowlist');
  });
});

test('adversarial: special regex / injection characters in email must not grant access', () => {
  withAllowlist('admin@example.com', () => {
    const special = [
      '.*@example.com',
      '.+@example.com',
      '^admin@example.com$',
      'admin|root@example.com',
      'admin"@example.com',
      "admin'@example.com",
      'admin`@example.com',
      '%(admin)s@example.com',
      '${admin}@example.com',
      '<script>@example.com',
      '../admin@example.com',
    ];
    for (const addr of special) {
      assert.equal(isAdminSubject(addr), false,
        `Special-char address "${addr}" must not be admin`);
    }
  });
});

// ── Section 4: Allowlist parsing edge cases ───────────────────────────────────

test('parsing: trailing comma does not admit empty string as admin email', () => {
  withAllowlist('admin@example.com,', () => {
    const subjects = adminSubjects();
    assert.ok(!subjects.has(''), 'empty string must not be in admin set');
    assert.equal(isAdminSubject(''), false);
    assert.equal(isAdminSubject(undefined), false);
    assert.equal(isAdminSubject(null), false);
    // The listed one still works
    assert.equal(isAdminSubject('admin@example.com'), true);
  });
});

test('parsing: leading comma does not admit empty string as admin email', () => {
  withAllowlist(',admin@example.com', () => {
    const subjects = adminSubjects();
    assert.ok(!subjects.has(''), 'empty string must not be in admin set');
    assert.equal(isAdminSubject('admin@example.com'), true);
  });
});

test('parsing: duplicate entries do not multiply-admit (Set deduplication)', () => {
  withAllowlist('admin@example.com,admin@example.com,ADMIN@EXAMPLE.COM', () => {
    const subjects = adminSubjects();
    assert.equal(subjects.size, 1, 'Duplicate entries should collapse to one');
    assert.equal(isAdminSubject('admin@example.com'), true);
  });
});

test('parsing: purely numeric / non-email tokens in allowlist do not crash', () => {
  withAllowlist('12345,admin@example.com,not-an-email', () => {
    // Should not throw; numeric/malformed tokens are stored but won't match real emails
    const subjects = adminSubjects();
    assert.ok(subjects.has('12345'));
    assert.ok(subjects.has('admin@example.com'));
    assert.ok(subjects.has('not-an-email'));
    assert.equal(isAdminSubject('admin@example.com'), true);
    assert.equal(isAdminSubject('12345'), true); // technically in the set
    assert.equal(isAdminSubject('imposter@example.com'), false);
  });
});

// ── Section 5: Full property test — core invariant ───────────────────────────

test('CORE INVARIANT: isAdminSubject ↔ exact normalized membership (1000 runs)', () => {
  const emailArb = fc.emailAddress();
  const allowlistArb = fc.array(emailArb, { minLength: 0, maxLength: 5 });

  fc.assert(
    fc.property(allowlistArb, emailArb, (allowedList, candidate) => {
      const rawAllowlist = allowedList.join(',');
      assertInvariant(rawAllowlist, candidate);
    }),
    { numRuns: 1000, seed: 20260603 },
  );
});

test('CORE INVARIANT: case-folded allowlist entries — random mixed-case (500 runs)', () => {
  // Generate emails and randomly vary their case in the allowlist
  const emailArb = fc.emailAddress();
  fc.assert(
    fc.property(
      emailArb,
      fc.boolean(), // whether to upper-case the allowlist entry
      fc.boolean(), // whether to upper-case the candidate
      (email, upperAllowlist, upperCandidate) => {
        const allowlistEntry = upperAllowlist ? email.toUpperCase() : email.toLowerCase();
        const candidateEntry = upperCandidate ? email.toUpperCase() : email.toLowerCase();
        withAllowlist(allowlistEntry, () => {
          // Both should resolve to the same normalized form → always true
          assert.equal(isAdminSubject(candidateEntry), true,
            `Mixed-case: allowlist="${allowlistEntry}" candidate="${candidateEntry}" should be admin`);
        });
      },
    ),
    { numRuns: 500 },
  );
});

test('CORE INVARIANT: no non-member ever becomes admin under random adversarial inputs (1000 runs)', () => {
  // The candidate is generated from a different alphabet than the allowlist
  // to virtually guarantee it won't accidentally match.
  const adminEmail = 'admin@fixture.test';
  withAllowlist(adminEmail, () => {
    fc.assert(
      fc.property(
        // Random string — unlikely to be exactly "admin@fixture.test"
        fc.string({ minLength: 0, maxLength: 200 }).filter(
          (s) => s.trim().toLowerCase() !== adminEmail,
        ),
        (candidate) => {
          assert.equal(isAdminSubject(candidate), false,
            `Non-member "${candidate}" must not be admin`);
        },
      ),
      { numRuns: 1000 },
    );
  });
});

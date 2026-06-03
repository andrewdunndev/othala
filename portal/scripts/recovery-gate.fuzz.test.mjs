// Property-based / adversarial fuzz harness for recoveryGateVerdict.
//
// Run with: tsx --test scripts/recovery-gate.fuzz.test.mjs
//
// SECURITY INVARIANT (what an attacker wants to break):
//   recoveryGateVerdict NEVER returns { refuse: false } for an identity
//   whose email is on the OTHALA_ADMIN_SUBJECTS allowlist (admins must not
//   self-recover via email). It fails CLOSED (refuse: true) on
//   missing/malformed/ambiguous/unidentifiable payloads.
//
// In formal terms, for any input (payload, isAdminSubject):
//   verdict.refuse === false  =>  isAdminSubject(email) === false
//                                 AND email is a non-empty string.
//
// A violation means an attacker can construct a Kratos webhook payload that
// lets an admin account receive a recovery email instead of being refused.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { recoveryGateVerdict } from '../src/server/listen.mjs';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A simple isAdminSubject that treats a fixed set as admin. */
function makeAdminPredicate(adminEmails) {
  const normalized = new Set(adminEmails.map((e) => e.trim().toLowerCase()));
  return (email) => {
    if (typeof email !== 'string') return false;
    return normalized.has(email.trim().toLowerCase());
  };
}

const ADMIN_EMAILS = ['andrew@dunn.dev', 'ops@example.com', 'ROOT@DUNN.DEV'];
const isAdminSubject = makeAdminPredicate(ADMIN_EMAILS);

// Canonical Kratos-style webhook payload shape.
function kratosPayload(email) {
  return { identity: { traits: { email } } };
}

// Flat shape (without `.identity` wrapper — the fn supports both via `payload?.identity ?? payload`).
function flatPayload(email) {
  return { traits: { email } };
}

// ---------------------------------------------------------------------------
// Core invariant assertion
// ---------------------------------------------------------------------------

/**
 * THE invariant: if verdict is "allow" (refuse===false), then:
 *   1. the email must be a non-empty string
 *   2. isAdminSubject(email) must be false
 *
 * A violation of either sub-clause is a security bug.
 */
function assertInvariant(payload, verdict, label) {
  if (!verdict.refuse) {
    // Sub-invariant 1: we must have identified a real email
    const identity = payload?.identity ?? payload;
    const email = identity?.traits?.email;
    assert.ok(
      typeof email === 'string' && email.length > 0,
      `${label}: allowed without a real email — fail-closed violation. email=${JSON.stringify(email)}`,
    );
    // Sub-invariant 2: the allowed email must not be an admin subject
    assert.ok(
      !isAdminSubject(email),
      `${label}: admin subject received ALLOW verdict — HIGH-3 violation. email=${JSON.stringify(email)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Explicit named cases (invariant-first)
// ---------------------------------------------------------------------------

test('null payload refuses (fail-closed)', () => {
  const v = recoveryGateVerdict(null, isAdminSubject);
  assert.equal(v.refuse, true, 'null payload must refuse');
  assertInvariant(null, v, 'null payload');
});

test('undefined payload refuses (fail-closed)', () => {
  const v = recoveryGateVerdict(undefined, isAdminSubject);
  assert.equal(v.refuse, true, 'undefined payload must refuse');
  assertInvariant(undefined, v, 'undefined payload');
});

test('empty object refuses (fail-closed)', () => {
  const v = recoveryGateVerdict({}, isAdminSubject);
  assert.equal(v.refuse, true, 'empty object must refuse');
  assertInvariant({}, v, 'empty object');
});

test('canonical admin email is refused (kratos shape)', () => {
  const p = kratosPayload('andrew@dunn.dev');
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true, 'admin must be refused');
  assertInvariant(p, v, 'admin kratos shape');
});

test('admin email in UPPERCASE refuses (case-insensitive allowlist)', () => {
  // isAdminSubject is supposed to fold case; check that recoveryGateVerdict
  // passes the raw email as-is to isAdminSubject so the predicate can decide.
  // If the gate strips/folds before passing, that's fine too — must still refuse.
  const p = kratosPayload('ANDREW@DUNN.DEV');
  const v = recoveryGateVerdict(p, makeAdminPredicate(['andrew@dunn.dev']));
  assert.equal(v.refuse, true, 'upper-case admin email must refuse');
  assertInvariant(p, v, 'uppercase admin email');
});

test('admin email with leading/trailing whitespace refuses', () => {
  const p = kratosPayload('  andrew@dunn.dev  ');
  const v = recoveryGateVerdict(p, makeAdminPredicate(['andrew@dunn.dev']));
  // The predicate normalizes; the gate passes raw. Invariant: refuse must be true.
  assert.equal(v.refuse, true, 'whitespace-padded admin email must refuse');
  assertInvariant(p, v, 'whitespace admin email');
});

test('admin email in flat payload shape refuses', () => {
  const p = flatPayload('andrew@dunn.dev');
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true, 'flat-shape admin must refuse');
  assertInvariant(p, v, 'flat payload admin');
});

test('non-admin email is allowed (kratos shape)', () => {
  const p = kratosPayload('alice@example.com');
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, false, 'non-admin must be allowed');
  assertInvariant(p, v, 'non-admin kratos shape');
});

test('non-admin email is allowed (flat shape)', () => {
  const p = flatPayload('alice@example.com');
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, false, 'non-admin flat must be allowed');
  assertInvariant(p, v, 'non-admin flat shape');
});

test('missing traits refuses (fail-closed)', () => {
  const p = { identity: { id: 'x' } }; // no traits
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'missing traits');
});

test('null email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: null } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'null email');
});

test('empty string email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: '' } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'empty string email');
});

test('numeric email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: 12345 } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'numeric email');
});

test('array email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: ['andrew@dunn.dev'] } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'array email');
});

test('object email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: { toString: () => 'andrew@dunn.dev' } } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'object email');
});

test('boolean email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: true } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'boolean email');
});

// Whitespace-only string — gate now checks email.trim().length === 0 (fixed).
test('whitespace-only email refuses (fail-closed)', () => {
  const p = { identity: { traits: { email: '   ' } } };
  const v = recoveryGateVerdict(p, isAdminSubject);
  // INVARIANT (fixed): the gate checks `email.trim().length === 0`, so a
  // whitespace-only email is refused as an unidentifiable subject.
  assert.equal(v.refuse, true,
    'whitespace-only email must refuse — fail-closed invariant now holds after fix');
  assertInvariant(p, v, 'whitespace-only email');
});

// Null prototype object — prototype-pollution-adjacent test.
test('null-prototype payload does not crash or allow admin', () => {
  const p = Object.create(null);
  p.identity = Object.create(null);
  p.identity.traits = Object.create(null);
  p.identity.traits.email = 'andrew@dunn.dev';
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true, 'null-prototype admin must refuse');
  assertInvariant(p, v, 'null-prototype payload');
});

// Identity wrapper confusion: both `identity` and top-level traits present.
test('both identity wrapper AND top-level traits: identity takes precedence', () => {
  const p = {
    identity: { traits: { email: 'andrew@dunn.dev' } }, // admin
    traits: { email: 'alice@example.com' },              // non-admin
  };
  const v = recoveryGateVerdict(p, isAdminSubject);
  // The gate resolves: identity = payload.identity ?? payload
  // So identity = { traits: { email: 'andrew@dunn.dev' } } — admin — must refuse.
  assert.equal(v.refuse, true, 'identity wrapper takes precedence; admin must refuse');
  assertInvariant(p, v, 'precedence conflict');
});

// Attacker swaps to flat shape with admin email but wraps in an extra layer.
test('double-wrapped payload refuses (fail-closed on unidentifiable)', () => {
  const p = { identity: { identity: { traits: { email: 'andrew@dunn.dev' } } } };
  // gate reads: identity = p.identity = { identity: { traits: ... } }
  // then email = identity.traits?.email = undefined → refuse
  const v = recoveryGateVerdict(p, isAdminSubject);
  assert.equal(v.refuse, true, 'double-wrapped must refuse (no traits on inner identity wrapper)');
  assertInvariant(p, v, 'double-wrapped');
});

// Prototype-polluted email field via __proto__ injection (JSON.parse safe; direct property test).
test('prototype-polluted email does not allow admin recovery', () => {
  // Simulate what JSON.parse does with {"__proto__":{"email":"andrew@dunn.dev"}}
  // Modern V8 / JSON.parse ignores __proto__ as a key for prototype assignment,
  // but we test the direct case.
  const p = { identity: { traits: {} } };
  Object.getPrototypeOf(p.identity.traits).email = 'andrew@dunn.dev';
  try {
    const v = recoveryGateVerdict(p, isAdminSubject);
    // The gate reads identity.traits?.email — if inherited, it would be 'andrew@dunn.dev'.
    // If the gate allows this, it's a prototype-pollution bypass.
    if (!v.refuse) {
      // Check if the email was inherited via prototype
      const email = p.identity.traits.email;
      assert.fail(
        `Prototype-polluted email "${email}" was ALLOWED — prototype pollution bypass!`,
      );
    }
    assertInvariant(p, v, 'prototype-polluted traits');
  } finally {
    // Clean up the prototype pollution
    delete Object.getPrototypeOf(p.identity.traits).email;
  }
});

// ---------------------------------------------------------------------------
// Property-based fuzzing (fast-check, 1000 runs)
// ---------------------------------------------------------------------------

test('property: NEVER allow an admin subject (1000 random payloads)', () => {
  const adminSet = ['admin@example.com', 'root@corp.org', 'ops@dunn.dev'];
  const pred = makeAdminPredicate(adminSet);

  fc.assert(
    fc.property(
      // Generate a payload: choose one of several shapes
      fc.oneof(
        // canonical Kratos shape with arbitrary email
        fc.record({ identity: fc.record({ traits: fc.record({ email: fc.string() }) }) }),
        // flat shape
        fc.record({ traits: fc.record({ email: fc.string() }) }),
        // admin email in canonical shape
        fc.constantFrom(...adminSet).map((e) => ({ identity: { traits: { email: e } } })),
        // admin email in flat shape
        fc.constantFrom(...adminSet).map((e) => ({ traits: { email: e } })),
        // malformed: no traits
        fc.record({ identity: fc.record({}) }),
        // null
        fc.constant(null),
        // arbitrary object
        fc.object(),
        // admin email with case variants
        fc.constantFrom(...adminSet).map((e) => ({
          identity: { traits: { email: e.toUpperCase() } },
        })),
        // admin email with surrounding whitespace
        fc.constantFrom(...adminSet).map((e) => ({
          identity: { traits: { email: `  ${e}  ` } },
        })),
      ),
      (payload) => {
        const verdict = recoveryGateVerdict(payload, pred);
        // The invariant: if allowed, email must not be an admin subject.
        if (!verdict.refuse) {
          const identity = payload?.identity ?? payload;
          const email = identity?.traits?.email;
          // Must have a real string email
          if (typeof email !== 'string' || email.length === 0) {
            throw new Error(
              `INVARIANT VIOLATION (fail-closed): allowed without a real email. ` +
              `email=${JSON.stringify(email)}, payload=${JSON.stringify(payload)}`,
            );
          }
          // Must not be an admin
          if (pred(email)) {
            throw new Error(
              `INVARIANT VIOLATION (HIGH-3): admin subject allowed. ` +
              `email=${JSON.stringify(email)}, payload=${JSON.stringify(payload)}`,
            );
          }
        }
        return true;
      },
    ),
    { numRuns: 1000, seed: 42 },
  );
});

test('property: fail-closed on all missing/malformed payloads (500 runs)', () => {
  // Any payload that lacks a non-empty string email must refuse.
  const pred = makeAdminPredicate(['admin@example.com']);

  fc.assert(
    fc.property(
      fc.oneof(
        fc.constant(null),
        fc.constant(undefined),
        fc.constant({}),
        fc.record({ identity: fc.constant({}) }),
        fc.record({ identity: fc.record({ traits: fc.constant({}) }) }),
        fc.record({ identity: fc.record({ traits: fc.record({ email: fc.constant(null) }) }) }),
        fc.record({ identity: fc.record({ traits: fc.record({ email: fc.constant('') }) }) }),
        fc.record({ identity: fc.record({ traits: fc.record({ email: fc.integer() }) }) }),
        fc.record({ identity: fc.record({ traits: fc.record({ email: fc.boolean() }) }) }),
        fc.record({ identity: fc.record({ traits: fc.record({ email: fc.array(fc.string()) }) }) }),
      ),
      (payload) => {
        const verdict = recoveryGateVerdict(payload, pred);
        return verdict.refuse === true;
      },
    ),
    { numRuns: 500, seed: 123 },
  );
});

test('property: arbitrary isAdminSubject predicate — never allows what predicate claims is admin (1000 runs)', () => {
  // Generate both a payload and a random "admin set" to verify the gate delegates
  // correctly regardless of what the predicate considers admin.
  fc.assert(
    fc.property(
      fc.array(fc.emailAddress(), { minLength: 1, maxLength: 5 }),
      fc.emailAddress(),
      (adminEmails, targetEmail) => {
        const pred = makeAdminPredicate(adminEmails);
        const payload = { identity: { traits: { email: targetEmail } } };
        const verdict = recoveryGateVerdict(payload, pred);
        if (pred(targetEmail) && !verdict.refuse) {
          throw new Error(
            `INVARIANT VIOLATION: predicate says "${targetEmail}" is admin but gate returned allow. ` +
            `adminEmails=${JSON.stringify(adminEmails)}`,
          );
        }
        return true;
      },
    ),
    { numRuns: 1000, seed: 77 },
  );
});

// ---------------------------------------------------------------------------
// Whitespace-only email: explicit invariant gap documentation
// ---------------------------------------------------------------------------

test('whitespace-only email refuses (fail-closed — fixed)', () => {
  // The gate now checks: typeof email !== 'string' || email.trim().length === 0
  // A whitespace-only string ('   ') trims to '' (length 0) and is correctly refused.
  const p = { identity: { traits: { email: '   ' } } };
  const v = recoveryGateVerdict(p, isAdminSubject);

  // INVARIANT (fixed): whitespace-only email must be refused (fail-closed principle).
  assert.equal(v.refuse, true,
    'whitespace-only email must refuse — unidentifiable subject must not receive allow verdict');
  assertInvariant(p, v, 'whitespace-only fixed');
});

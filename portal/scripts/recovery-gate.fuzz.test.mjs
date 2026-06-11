// Property-based / adversarial fuzz harness for recoveryGateVerdict (CVP-P1).
//
// Run with: tsx --test scripts/recovery-gate.fuzz.test.mjs
//
// SECURITY INVARIANT (what an attacker wants to break):
//   recoveryGateVerdict NEVER returns { refuse: false } for an identity
//   whose IMMUTABLE id is on the OTHALA_ADMIN_IDS allowlist (admins must not
//   self-recover via email). It fails CLOSED (refuse: true) on
//   missing/malformed/ambiguous/unidentifiable payloads.
//
// In formal terms, for any input (payload, isAdminId):
//   verdict.refuse === false  =>  isAdminId(id) === false
//                                 AND id is a non-empty string.
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

const ADMIN_UUID = '11111111-1111-1111-1111-111111111111';
const OPS_UUID   = '33333333-3333-3333-3333-333333333333';
const OTHER_UUID = '22222222-2222-2222-2222-222222222222';

/** A simple isAdminId that treats a fixed set as admin. */
function makeAdminPredicate(adminIds) {
  const normalized = new Set(adminIds.map((id) => id.trim().toLowerCase()));
  return (id) => {
    if (typeof id !== 'string') return false;
    return normalized.has(id.trim().toLowerCase());
  };
}

const ADMIN_IDS = [ADMIN_UUID, OPS_UUID, 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'];
const isAdminId = makeAdminPredicate(ADMIN_IDS);

// Canonical jsonnet payload shape: { identity_id, groups, traits }
function kratosPayload(id) {
  return { identity_id: id, groups: [], traits: { email: 'user@example.com' } };
}

// Fallback shape (identity.id)
function legacyPayload(id) {
  return { identity: { id } };
}

// ---------------------------------------------------------------------------
// Core invariant assertion
// ---------------------------------------------------------------------------

/**
 * THE invariant: if verdict is "allow" (refuse===false), then:
 *   1. the id must be a non-empty string
 *   2. isAdminId(id) must be false
 *
 * A violation of either sub-clause is a security bug.
 */
function assertInvariant(payload, verdict, label) {
  if (!verdict.refuse) {
    const id = payload?.identity_id ?? payload?.identity?.id;
    assert.ok(
      typeof id === 'string' && id.length > 0,
      `${label}: allowed without a real id — fail-closed violation. id=${JSON.stringify(id)}`,
    );
    assert.ok(
      !isAdminId(id),
      `${label}: admin subject received ALLOW verdict — HIGH-3 violation. id=${JSON.stringify(id)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Explicit named cases (invariant-first)
// ---------------------------------------------------------------------------

test('null payload refuses (fail-closed)', () => {
  const v = recoveryGateVerdict(null, isAdminId);
  assert.equal(v.refuse, true, 'null payload must refuse');
  assertInvariant(null, v, 'null payload');
});

test('undefined payload refuses (fail-closed)', () => {
  const v = recoveryGateVerdict(undefined, isAdminId);
  assert.equal(v.refuse, true, 'undefined payload must refuse');
  assertInvariant(undefined, v, 'undefined payload');
});

test('empty object refuses (fail-closed)', () => {
  const v = recoveryGateVerdict({}, isAdminId);
  assert.equal(v.refuse, true, 'empty object must refuse');
  assertInvariant({}, v, 'empty object');
});

test('canonical admin UUID is refused (jsonnet shape)', () => {
  const p = kratosPayload(ADMIN_UUID);
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true, 'admin must be refused');
  assertInvariant(p, v, 'admin jsonnet shape');
});

test('admin UUID in UPPERCASE refuses (case-insensitive allowlist)', () => {
  const p = kratosPayload(ADMIN_UUID.toUpperCase());
  const v = recoveryGateVerdict(p, makeAdminPredicate([ADMIN_UUID]));
  assert.equal(v.refuse, true, 'upper-case admin UUID must refuse');
  assertInvariant(p, v, 'uppercase admin UUID');
});

test('admin UUID with leading/trailing whitespace refuses', () => {
  const p = kratosPayload(`  ${ADMIN_UUID}  `);
  const v = recoveryGateVerdict(p, makeAdminPredicate([ADMIN_UUID]));
  assert.equal(v.refuse, true, 'whitespace-padded admin UUID must refuse');
  assertInvariant(p, v, 'whitespace admin UUID');
});

test('admin UUID in legacy payload shape (identity.id) refuses', () => {
  const p = legacyPayload(ADMIN_UUID);
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true, 'legacy-shape admin must refuse');
  assertInvariant(p, v, 'legacy payload admin');
});

test('non-admin UUID is allowed (jsonnet shape)', () => {
  const p = kratosPayload(OTHER_UUID);
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, false, 'non-admin must be allowed');
  assertInvariant(p, v, 'non-admin jsonnet shape');
});

test('non-admin UUID is allowed (legacy shape)', () => {
  const p = legacyPayload(OTHER_UUID);
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, false, 'non-admin legacy must be allowed');
  assertInvariant(p, v, 'non-admin legacy shape');
});

test('missing identity_id refuses (fail-closed)', () => {
  const p = { groups: [], traits: { email: 'x@y.com' } };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'missing identity_id');
});

test('null identity_id refuses (fail-closed)', () => {
  const p = { identity_id: null };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'null identity_id');
});

test('empty string identity_id refuses (fail-closed)', () => {
  const p = { identity_id: '' };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'empty string identity_id');
});

test('whitespace-only identity_id refuses (fail-closed)', () => {
  const p = { identity_id: '   ' };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true, 'whitespace-only id must refuse — fail-closed');
  assertInvariant(p, v, 'whitespace-only identity_id');
});

test('numeric identity_id refuses (fail-closed)', () => {
  const p = { identity_id: 12345 };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'numeric identity_id');
});

test('boolean identity_id refuses (fail-closed)', () => {
  const p = { identity_id: true };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'boolean identity_id');
});

test('null-prototype payload does not crash or allow admin', () => {
  const p = Object.create(null);
  p.identity_id = ADMIN_UUID;
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true, 'null-prototype admin must refuse');
  assertInvariant(p, v, 'null-prototype payload');
});

test('identity_id takes precedence over identity.id when both present', () => {
  const p = {
    identity_id: ADMIN_UUID,  // admin
    identity: { id: OTHER_UUID }, // non-admin
  };
  const v = recoveryGateVerdict(p, isAdminId);
  assert.equal(v.refuse, true, 'identity_id takes precedence; admin must refuse');
  assertInvariant(p, v, 'precedence conflict');
});

// ---------------------------------------------------------------------------
// Property-based fuzzing (fast-check, 1000 runs)
// ---------------------------------------------------------------------------

test('property: NEVER allow an admin subject (1000 random payloads)', () => {
  const adminSet = [ADMIN_UUID, OPS_UUID, 'cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa'];
  const pred = makeAdminPredicate(adminSet);

  fc.assert(
    fc.property(
      fc.oneof(
        // canonical jsonnet shape with arbitrary uuid-like id
        fc.record({ identity_id: fc.string() }),
        // admin UUID in canonical shape
        fc.constantFrom(...adminSet).map((id) => ({ identity_id: id })),
        // admin UUID in legacy shape
        fc.constantFrom(...adminSet).map((id) => ({ identity: { id } })),
        // malformed: no id anywhere
        fc.constant({}),
        // null
        fc.constant(null),
        // arbitrary object
        fc.object(),
        // admin UUID with case variants
        fc.constantFrom(...adminSet).map((id) => ({ identity_id: id.toUpperCase() })),
        // admin UUID with surrounding whitespace
        fc.constantFrom(...adminSet).map((id) => ({ identity_id: `  ${id}  ` })),
      ),
      (payload) => {
        const verdict = recoveryGateVerdict(payload, pred);
        if (!verdict.refuse) {
          const id = payload?.identity_id ?? payload?.identity?.id;
          if (typeof id !== 'string' || id.length === 0) {
            throw new Error(
              `INVARIANT VIOLATION (fail-closed): allowed without a real id. ` +
              `id=${JSON.stringify(id)}, payload=${JSON.stringify(payload)}`,
            );
          }
          if (pred(id)) {
            throw new Error(
              `INVARIANT VIOLATION (HIGH-3): admin subject allowed. ` +
              `id=${JSON.stringify(id)}, payload=${JSON.stringify(payload)}`,
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
  const pred = makeAdminPredicate([ADMIN_UUID]);

  fc.assert(
    fc.property(
      fc.oneof(
        fc.constant(null),
        fc.constant(undefined),
        fc.constant({}),
        fc.record({ identity_id: fc.constant(null) }),
        fc.record({ identity_id: fc.constant('') }),
        fc.record({ identity_id: fc.integer() }),
        fc.record({ identity_id: fc.boolean() }),
        fc.record({ identity_id: fc.array(fc.string()) }),
        fc.record({ identity: fc.constant({}) }),
      ),
      (payload) => {
        const verdict = recoveryGateVerdict(payload, pred);
        return verdict.refuse === true;
      },
    ),
    { numRuns: 500, seed: 123 },
  );
});

test('property: arbitrary isAdminId predicate — never allows what predicate claims is admin (1000 runs)', () => {
  const hexSegment = (len) => fc.stringMatching(new RegExp(`^[0-9a-f]{${len}}$`));
  const uuidArb = fc.tuple(
    hexSegment(8),
    hexSegment(4),
    hexSegment(4),
    hexSegment(4),
    hexSegment(12),
  ).map(([a, b, c, d, e]) => `${a}-${b}-${c}-${d}-${e}`);

  fc.assert(
    fc.property(
      fc.array(uuidArb, { minLength: 1, maxLength: 5 }),
      uuidArb,
      (adminIds, targetId) => {
        const pred = makeAdminPredicate(adminIds);
        const payload = { identity_id: targetId };
        const verdict = recoveryGateVerdict(payload, pred);
        if (pred(targetId) && !verdict.refuse) {
          throw new Error(
            `INVARIANT VIOLATION: predicate says "${targetId}" is admin but gate returned allow. ` +
            `adminIds=${JSON.stringify(adminIds)}`,
          );
        }
        return true;
      },
    ),
    { numRuns: 1000, seed: 77 },
  );
});

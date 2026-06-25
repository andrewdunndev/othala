// Property-based / adversarial fuzz harness for recoveryGateVerdict (CVP-P1,
// updated ADR 0008).
//
// Run with: tsx --test scripts/recovery-gate.fuzz.test.mjs
//
// SECURITY INVARIANT (what an attacker wants to break):
//   recoveryGateVerdict NEVER returns { refuse: false } for a payload whose
//   `is_admin` field is boolean true. Admin recovery must always be refused.
//   It fails CLOSED (refuse: true) on missing/malformed/ambiguous payloads
//   and on any non-boolean is_admin value.
//
// In formal terms, for any input payload:
//   verdict.refuse === false  =>  payload.is_admin === false (boolean)
//                                 AND identity_id is a non-empty string.
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
const OTHER_UUID = '22222222-2222-2222-2222-222222222222';
const OPS_UUID   = '33333333-3333-3333-3333-333333333333';

// Canonical jsonnet payload shape: { identity_id, is_admin, groups, traits }
function adminPayload(id) {
  return { identity_id: id, is_admin: true, groups: ['admin'], traits: { email: 'admin@example.com' } };
}

function nonAdminPayload(id) {
  return { identity_id: id, is_admin: false, groups: [], traits: { email: 'user@example.com' } };
}

// Fallback shape (identity.id) — still accepted by the id-extraction path
function legacyPayload(id, is_admin) {
  return { identity: { id }, is_admin };
}

// ---------------------------------------------------------------------------
// Core invariant assertion
// ---------------------------------------------------------------------------

/**
 * THE invariant: if verdict is "allow" (refuse===false), then:
 *   1. identity_id (or identity.id) must be a non-empty string
 *   2. payload.is_admin must be boolean false (not true, not missing)
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
      payload?.is_admin !== true,
      `${label}: is_admin===true subject received ALLOW verdict — HIGH-3 violation.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Explicit named cases (invariant-first)
// ---------------------------------------------------------------------------

test('null payload refuses (fail-closed)', () => {
  const v = recoveryGateVerdict(null);
  assert.equal(v.refuse, true, 'null payload must refuse');
  assertInvariant(null, v, 'null payload');
});

test('undefined payload refuses (fail-closed)', () => {
  const v = recoveryGateVerdict(undefined);
  assert.equal(v.refuse, true, 'undefined payload must refuse');
  assertInvariant(undefined, v, 'undefined payload');
});

test('empty object refuses (fail-closed — no identity_id)', () => {
  const v = recoveryGateVerdict({});
  assert.equal(v.refuse, true, 'empty object must refuse (no identity_id)');
  assertInvariant({}, v, 'empty object');
});

test('is_admin===true is refused (admin payload, jsonnet shape)', () => {
  const p = adminPayload(ADMIN_UUID);
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'admin must be refused');
  assertInvariant(p, v, 'admin jsonnet shape');
});

test('is_admin===true is refused for OPS_UUID', () => {
  const p = adminPayload(OPS_UUID);
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'ops admin must be refused');
  assertInvariant(p, v, 'ops admin jsonnet shape');
});

test('is_admin===true in legacy shape (identity.id) refuses', () => {
  const p = legacyPayload(ADMIN_UUID, true);
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'legacy-shape admin must refuse');
  assertInvariant(p, v, 'legacy payload admin');
});

test('non-admin (is_admin===false) is allowed (jsonnet shape)', () => {
  const p = nonAdminPayload(OTHER_UUID);
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, false, 'non-admin must be allowed');
  assertInvariant(p, v, 'non-admin jsonnet shape');
});

test('non-admin (is_admin===false) is allowed (legacy shape)', () => {
  const p = legacyPayload(OTHER_UUID, false);
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, false, 'non-admin legacy must be allowed');
  assertInvariant(p, v, 'non-admin legacy shape');
});

test('missing identity_id refuses (fail-closed)', () => {
  const p = { is_admin: false, groups: [], traits: { email: 'x@y.com' } };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'missing identity_id');
});

test('null identity_id refuses (fail-closed)', () => {
  const p = { identity_id: null, is_admin: false };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'null identity_id');
});

test('empty string identity_id refuses (fail-closed)', () => {
  const p = { identity_id: '', is_admin: false };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'empty string identity_id');
});

test('whitespace-only identity_id refuses (fail-closed)', () => {
  const p = { identity_id: '   ', is_admin: false };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'whitespace-only id must refuse — fail-closed');
  assertInvariant(p, v, 'whitespace-only identity_id');
});

test('numeric identity_id refuses (fail-closed)', () => {
  const p = { identity_id: 12345, is_admin: false };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'numeric identity_id');
});

test('boolean identity_id refuses (fail-closed)', () => {
  const p = { identity_id: true, is_admin: false };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true);
  assertInvariant(p, v, 'boolean identity_id');
});

test('null-prototype payload does not crash or allow admin', () => {
  const p = Object.create(null);
  p.identity_id = ADMIN_UUID;
  p.is_admin = true;
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'null-prototype admin payload must refuse');
  assertInvariant(p, v, 'null-prototype payload');
});

test('identity_id takes precedence over identity.id when both present', () => {
  const p = {
    identity_id: ADMIN_UUID,   // admin
    identity: { id: OTHER_UUID }, // non-admin id (ignored for is_admin check)
    is_admin: true,
  };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'is_admin===true must refuse regardless of id source');
  assertInvariant(p, v, 'precedence conflict');
});

// ---------------------------------------------------------------------------
// Malformed is_admin (non-boolean) — fail-safe: refuse + log error
// ---------------------------------------------------------------------------

test('is_admin===string "true" refuses (non-boolean, fail-closed)', () => {
  const p = { identity_id: OTHER_UUID, is_admin: 'true' };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'string is_admin must refuse (non-boolean)');
  assertInvariant(p, v, 'string is_admin');
});

test('is_admin===1 refuses (non-boolean, fail-closed)', () => {
  const p = { identity_id: OTHER_UUID, is_admin: 1 };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'numeric is_admin must refuse (non-boolean)');
  assertInvariant(p, v, 'numeric is_admin');
});

test('is_admin===null refuses (non-boolean, fail-closed)', () => {
  const p = { identity_id: OTHER_UUID, is_admin: null };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'null is_admin must refuse (non-boolean)');
  assertInvariant(p, v, 'null is_admin');
});

test('missing is_admin refuses (non-boolean, fail-closed)', () => {
  const p = { identity_id: OTHER_UUID };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'missing is_admin must refuse (non-boolean)');
  assertInvariant(p, v, 'missing is_admin');
});

test('is_admin===0 refuses (non-boolean, fail-closed)', () => {
  const p = { identity_id: OTHER_UUID, is_admin: 0 };
  const v = recoveryGateVerdict(p);
  assert.equal(v.refuse, true, 'is_admin=0 must refuse (non-boolean)');
  assertInvariant(p, v, 'is_admin 0');
});

// ---------------------------------------------------------------------------
// Property-based fuzzing (fast-check, 1000 runs)
// ---------------------------------------------------------------------------

test('property: NEVER allow an is_admin===true subject (1000 random payloads)', () => {
  fc.assert(
    fc.property(
      fc.oneof(
        // canonical jsonnet shape with is_admin: true
        fc.record({ identity_id: fc.string(), is_admin: fc.constant(true) }),
        // legacy shape with is_admin: true
        fc.string().map((id) => ({ identity: { id }, is_admin: true })),
        // admin UUID, various field combinations
        fc.constantFrom(ADMIN_UUID, OPS_UUID).map((id) => ({
          identity_id: id,
          is_admin: true,
          groups: ['admin'],
          traits: { email: 'admin@example.com' },
        })),
        // malformed: no id anywhere (still must refuse)
        fc.constant({ is_admin: true }),
        // null
        fc.constant(null),
        // arbitrary object (may or may not have is_admin: true)
        fc.object(),
      ),
      (payload) => {
        const verdict = recoveryGateVerdict(payload);
        if (!verdict.refuse) {
          const id = payload?.identity_id ?? payload?.identity?.id;
          if (typeof id !== 'string' || id.length === 0) {
            throw new Error(
              `INVARIANT VIOLATION (fail-closed): allowed without a real id. ` +
              `id=${JSON.stringify(id)}, payload=${JSON.stringify(payload)}`,
            );
          }
          if (payload?.is_admin === true) {
            throw new Error(
              `INVARIANT VIOLATION (HIGH-3): is_admin===true subject allowed. ` +
              `payload=${JSON.stringify(payload)}`,
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
  fc.assert(
    fc.property(
      fc.oneof(
        fc.constant(null),
        fc.constant(undefined),
        fc.constant({}),
        // missing is_admin (non-boolean undefined)
        fc.record({ identity_id: fc.uuid() }),
        // malformed is_admin types
        fc.record({ identity_id: fc.uuid(), is_admin: fc.constant(null) }),
        fc.record({ identity_id: fc.uuid(), is_admin: fc.constant('true') }),
        fc.record({ identity_id: fc.uuid(), is_admin: fc.integer() }),
        // no id anywhere
        fc.record({ is_admin: fc.boolean() }).filter((p) => p.identity_id === undefined),
        fc.constant({ is_admin: false }),  // non-boolean? no — valid but no id
        // truly malformed id
        fc.record({ identity_id: fc.constant(null), is_admin: fc.boolean() }),
        fc.record({ identity_id: fc.constant(''), is_admin: fc.boolean() }),
      ),
      (payload) => {
        const verdict = recoveryGateVerdict(payload);
        // A payload with is_admin===false and a valid non-empty id is the ONLY
        // allow case. Everything else (malformed is_admin OR missing/malformed id)
        // must refuse.
        const id = payload?.identity_id ?? payload?.identity?.id;
        const hasValidId = typeof id === 'string' && id.trim().length > 0;
        const hasValidIsAdmin = typeof payload?.is_admin === 'boolean';

        if (hasValidId && hasValidIsAdmin && payload.is_admin === false) {
          // This is a valid allow payload; it may or may not refuse.
          return true;
        }
        // Everything else must refuse.
        return verdict.refuse === true;
      },
    ),
    { numRuns: 500, seed: 123 },
  );
});

test('property: is_admin===true always refuses regardless of identity_id (1000 runs)', () => {
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
      uuidArb,
      (targetId) => {
        const payload = { identity_id: targetId, is_admin: true };
        const verdict = recoveryGateVerdict(payload);
        if (!verdict.refuse) {
          throw new Error(
            `INVARIANT VIOLATION: is_admin===true but gate returned allow. ` +
            `targetId=${JSON.stringify(targetId)}`,
          );
        }
        return true;
      },
    ),
    { numRuns: 1000, seed: 77 },
  );
});

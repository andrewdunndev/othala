// The fail-closed PROPERTY TEST — the load-bearing guarantee of the whole
// access model: no path through the gate admits without an explicit binding.
//
// Run with: npx vitest run scripts/gate-property.test.mjs
//
// WHAT CHANGED, AND WHY. This file used to test `enforceAccessGate` with a
// generator whose whole pool was nine hardcoded lowercase literals, against an
// oracle that was a textual copy of the implementation. It therefore could not
// (a) exercise the path /api/forward-auth actually calls, (b) ever produce a
// case mismatch, or (c) fail when the implementation was wrong — only when it
// was DIFFERENT. All three are fixed here:
//
//   (a) The property section below drives `enforceGroupGate`/`hasGroup` — the
//       pair `portal/src/pages/api/forward-auth.ts` calls — and re-runs the
//       same laws against `enforceAccessGate` where they hold.
//   (b) The generator emits mixed-case and charset-violating names alongside
//       canonical ones, so a comparison that folds case is reachable.
//   (c) The oracle is gone. In its place are directional LAWS, each of which
//       is a statement about the gate that can be checked without knowing how
//       the gate is written. A law says "allowed IMPLIES x" or "y IMPLIES
//       denied"; none of them recomputes the decision.
//
// The invariant, for ALL (identity, required group):
//
//   enforceGroupGate(identity, group).allowed === true
//     IMPLIES identity != null
//         AND identity.state === 'active'
//         AND every stored group matches GROUP_RE
//         AND the stored groups contain `group` VERBATIM
//
// and, in the other direction, those four together imply allowed. Names are
// compared with no case folding and no coercion of any kind: there is ONE
// canonical form (GROUP_RE, portal/src/lib/access-groups.ts) and every
// boundary this codebase owns validates against it.
//
// MUTATION PROBE: reintroduce `.toLowerCase()` in gate.ts `hasGroup` and the
// "no case folding" law below goes RED. A suite that survives that mutation
// has not tested anything.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { enforceAccessGate, enforceGroupGate, hasGroup } from '../src/lib/gate.ts';
import { GROUP_RE } from '../src/lib/access-groups.ts';

// ─── fixtures ────────────────────────────────────────────────────────────────

/** Build a manifest fixture. accessGroups defaults to the prefix-free binding. */
function manifest(clientId, opts = {}) {
  return {
    clientId,
    clientName: opts.clientName ?? clientId,
    redirectUris: [],
    postLogoutRedirectUris: [],
    scopes: [],
    scope: '',
    audience: [],
    grantTypes: [],
    responseTypes: [],
    tokenEndpointAuthMethod: '',
    skipConsent: false,
    backchannelLogoutUri: '',
    backchannelLogoutSessionRequired: false,
    accessGroup: `access-${clientId}`,
    accessGroups: opts.accessGroups ?? [],
    roles: opts.roles ?? [],
    groupRoleMap: opts.groupRoleMap ?? {},
    emitGroupsClaim: null,
    skipAccessCheck: opts.skipAccessCheck ?? false,
    sourcePath: `${clientId}.yaml`,
  };
}

/** Build an identity fixture. `groups`==null models a failed lookup (null id). */
function identity(groups, state = 'active') {
  if (groups === null) return null;
  return {
    id: 'id-1',
    state,
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'tester', email: 'a@othala.test' },
    metadata_admin: { groups },
  };
}

// ─── §16 enumerated matrix (enforceAccessGate — the OIDC path) ──────────────

test('matrix: null id → DENY', () => {
  const m = manifest('photos', { accessGroups: ['memories'] });
  assert.equal(enforceAccessGate(identity(null), 'photos', m).allowed, false);
});

test('matrix: inactive identity in the bound group → DENY (state gate)', () => {
  const m = manifest('photos', { accessGroups: ['memories'] });
  const id = identity(['memories'], 'inactive');
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

test('matrix: active, NOT in the bound group → DENY', () => {
  const m = manifest('photos', { accessGroups: ['memories'] });
  const id = identity(['family']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

test('matrix: active in an UNBOUND group → DENY (group not in accessGroups)', () => {
  // User is in `access-photos` (the OLD prefix-derived name) but the manifest
  // binds `memories`. The prefix-based gate would ALLOW here; the new gate must
  // DENY — this case is the one that flips the matrix.
  const m = manifest('photos', { accessGroups: ['memories'] });
  const id = identity(['access-photos']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

test('matrix: active in a bound group → ALLOW', () => {
  const m = manifest('photos', { accessGroups: ['memories'] });
  const id = identity(['memories']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, true);
});

test('matrix: skipAccessCheck + active → ALLOW (membership bypassed)', () => {
  const m = manifest('photos', { accessGroups: [], skipAccessCheck: true });
  const id = identity(['anything']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, true);
});

test('matrix: skipAccessCheck + INACTIVE → DENY (state never bypassed)', () => {
  const m = manifest('photos', { accessGroups: [], skipAccessCheck: true });
  const id = identity(['anything'], 'inactive');
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

test('matrix: skipAccessCheck + a non-canonical stored group → DENY', () => {
  // The read-boundary refusal is a fact about the identity record, not about
  // this app's binding, so the escape hatch does not bypass it.
  const m = manifest('photos', { accessGroups: [], skipAccessCheck: true });
  const id = identity(['Anything']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

test('matrix: multi-group OR — access:[a,b], user has only b → ALLOW', () => {
  const m = manifest('photos', { accessGroups: ['admin-memories', 'memories'] });
  const id = identity(['memories']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, true);
});

test('matrix: groups:[] → DENY', () => {
  const m = manifest('photos', { accessGroups: ['memories'] });
  const id = identity([]);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

test('matrix: manifest with empty accessGroups, no skip → DENY (no implicit access)', () => {
  const m = manifest('photos', { accessGroups: [] });
  const id = identity(['memories']);
  assert.equal(enforceAccessGate(id, 'photos', m).allowed, false);
});

// A flat `access-`-prefixed name is an ordinary binding: the manifest binds
// `access-proxywatch`, the identity holds `access-proxywatch`, the gate ALLOWS. The
// gate compares bound names against identity groups verbatim
// (portal/src/lib/gate.ts: `accessGroups.some((g) => userGroups.includes(g))`)
// and derives nothing from clientId, so the prefix gets no special handling.
test('regression: access-proxywatch is a valid flat binding → ALLOW', () => {
  const m = manifest('proxywatch', { accessGroups: ['access-proxywatch'] });
  const id = identity(['access-proxywatch']);
  assert.equal(enforceAccessGate(id, 'proxywatch', m).allowed, true);
});

// ─── generators ─────────────────────────────────────────────────────────────
//
// Three pools, deliberately overlapping in their case folds so that a gate
// which folds case is DISTINGUISHABLE from one which does not.

/**
 * Names that satisfy GROUP_RE — the only names any owned boundary can write.
 * `trailing-` is in here on purpose: GROUP_RE permits a trailing hyphen, and a
 * fixture list that quietly assumed otherwise is how the old pool of nine tidy
 * literals stopped biting.
 */
const canonicalName = fc.constantFrom(
  'memories', 'admin-memories', 'family', 'access-photos', 'access-proxywatch',
  'friends', 'kids', 'admin', 'proxywatch', 'grafana-access',
  'trailing-',
);

/** Names a raw Kratos admin-API write can store and no owned boundary can. */
const nonCanonicalName = fc.constantFrom(
  'Memories', 'ACCESS-PROXYWATCH', 'Access-Photos', 'Family', 'aDmIn',
  'has space', 'under_score', '-leading', 'dotted.name', '2fa-required', '',
);

const anyName = fc.oneof(canonicalName, nonCanonicalName);

/** An identity's stored group list, or null for a failed lookup. */
const storedGroups = fc.option(fc.array(anyName, { maxLength: 5 }), { nil: null });
// NOT `undefined`: identity() defaults an omitted state to 'active', so a
// generated `undefined` would silently produce an ACTIVE identity. The missing
// -state case is covered explicitly below instead.
const anyState = fc.constantFrom('active', 'inactive', 'pending');

// ─── LAWS: enforceGroupGate — the path /api/forward-auth calls ───────────────

test('law: ALLOWED implies the stored list contains the required name VERBATIM', () => {
  fc.assert(
    fc.property(storedGroups, anyState, anyName, (groups, state, required) => {
      const id = identity(groups, state);
      if (!enforceGroupGate(id, required).allowed) return;
      assert.ok(
        (groups ?? []).includes(required),
        `allowed without a verbatim match: stored=${JSON.stringify(groups)} required=${JSON.stringify(required)}`,
      );
    }),
    { numRuns: 4000 },
  );
});

test('law: ALLOWED implies an identity, state==="active", and an all-canonical stored list', () => {
  fc.assert(
    fc.property(storedGroups, anyState, anyName, (groups, state, required) => {
      const id = identity(groups, state);
      if (!enforceGroupGate(id, required).allowed) return;
      assert.notEqual(id, null);
      assert.equal(id.state, 'active');
      assert.deepEqual((groups ?? []).filter((g) => !GROUP_RE.test(g)), []);
      assert.ok(GROUP_RE.test(required));
    }),
    { numRuns: 4000 },
  );
});

test('law: NO CASE FOLDING — a name differing only in case never matches', () => {
  // The mutation probe's target. Reintroduce `.toLowerCase()` in hasGroup and
  // this law fails on the first pair it generates.
  fc.assert(
    fc.property(canonicalName, (lower) => {
      const upper = lower.toUpperCase();
      assert.notEqual(lower, upper, 'fixture must actually differ in case');
      // Required name upper-cased: stored is canonical, the needle is not.
      assert.equal(enforceGroupGate(identity([lower]), upper).allowed, false);
      // Stored name upper-cased: the needle is canonical, the record is not.
      assert.equal(enforceGroupGate(identity([upper]), lower).allowed, false);
      // And directly at hasGroup, below the state/refusal checks.
      assert.equal(hasGroup(identity([lower]), upper), false);
      assert.equal(hasGroup(identity([upper]), lower), false);
    }),
    { numRuns: 200 },
  );
});

test('law: ANY non-canonical stored name implies DENY, whatever else is held', () => {
  fc.assert(
    fc.property(
      fc.array(canonicalName, { maxLength: 4 }),
      nonCanonicalName,
      canonicalName,
      (canon, bad, required) => {
        const id = identity([...canon, bad]);
        assert.equal(enforceGroupGate(id, required).allowed, false);
      },
    ),
    { numRuns: 2000 },
  );
});

test('law: a non-"active" state implies DENY, however well the groups match', () => {
  fc.assert(
    fc.property(canonicalName, fc.constantFrom('inactive', 'pending', ''), (g, state) => {
      assert.equal(enforceGroupGate(identity([g], state), g).allowed, false);
    }),
    { numRuns: 500 },
  );
});

test('law: a MISSING state field implies DENY (the field deleted, not defaulted)', () => {
  fc.assert(
    fc.property(canonicalName, (g) => {
      const id = identity([g]);
      delete id.state;
      assert.equal(enforceGroupGate(id, g).allowed, false);
    }),
    { numRuns: 200 },
  );
});

test('law: the gate is not vacuously closed — the three conditions together ALLOW', () => {
  fc.assert(
    fc.property(
      fc.array(canonicalName, { maxLength: 4 }),
      canonicalName,
      (others, required) => {
        const id = identity([...others, required]);
        assert.equal(enforceGroupGate(id, required).allowed, true);
      },
    ),
    { numRuns: 2000 },
  );
});

test('law: a null identity implies DENY for every required name', () => {
  fc.assert(
    fc.property(anyName, (required) => {
      assert.equal(enforceGroupGate(identity(null), required).allowed, false);
      assert.equal(enforceGroupGate(undefined, required).allowed, false);
    }),
    { numRuns: 200 },
  );
});

// ─── the same laws where they hold for enforceAccessGate (the OIDC path) ────

test('law: enforceAccessGate — ALLOWED without skip implies a verbatim binding match', () => {
  fc.assert(
    fc.property(
      storedGroups,
      anyState,
      fc.array(anyName, { maxLength: 4 }),
      (groups, state, accessGroups) => {
        const id = identity(groups, state);
        const m = manifest('photos', { accessGroups });
        if (!enforceAccessGate(id, 'photos', m).allowed) return;
        assert.ok(accessGroups.some((g) => (groups ?? []).includes(g)));
      },
    ),
    { numRuns: 4000 },
  );
});

test('law: enforceAccessGate — NO CASE FOLDING against the manifest binding', () => {
  fc.assert(
    fc.property(canonicalName, (lower) => {
      const upper = lower.toUpperCase();
      const m = manifest('photos', { accessGroups: [upper] });
      assert.equal(enforceAccessGate(identity([lower]), 'photos', m).allowed, false);
    }),
    { numRuns: 200 },
  );
});

test('law: enforceAccessGate — ALLOWED implies an all-canonical stored list', () => {
  fc.assert(
    fc.property(
      storedGroups,
      anyState,
      fc.array(anyName, { maxLength: 4 }),
      fc.boolean(),
      (groups, state, accessGroups, skipAccessCheck) => {
        const id = identity(groups, state);
        const m = manifest('photos', { accessGroups, skipAccessCheck });
        if (!enforceAccessGate(id, 'photos', m).allowed) return;
        assert.deepEqual((groups ?? []).filter((g) => !GROUP_RE.test(g)), []);
      },
    ),
    { numRuns: 4000 },
  );
});

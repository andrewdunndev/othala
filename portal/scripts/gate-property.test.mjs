// Invariant: no path through the gate admits without an explicit binding (fail closed).

import { test } from 'vitest';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { enforceAccessGate, enforceGroupGate, hasGroup } from '../src/lib/gate.ts';
import { GROUP_RE } from '../src/lib/access-groups.ts';
import { identity as buildIdentity } from '../src/lib/test-builders.ts';

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
    accessGroups: opts.accessGroups ?? [],
    roles: opts.roles ?? [],
    groupRoleMap: opts.groupRoleMap ?? {},
    emitGroupsClaim: null,
    skipAccessCheck: opts.skipAccessCheck ?? false,
    sourcePath: `${clientId}.yaml`,
  };
}

const identity = (groups, state = 'active') => (groups === null ? null : buildIdentity({ state, metadataAdmin: { groups } }));

const canonicalName = fc.constantFrom(
  'memories', 'admin-memories', 'family', 'access-photos', 'access-proxywatch',
  'friends', 'kids', 'admin', 'proxywatch', 'grafana-access',
  'trailing-',
);

const nonCanonicalName = fc.constantFrom(
  'Memories', 'ACCESS-PROXYWATCH', 'Access-Photos', 'Family', 'aDmIn',
  'has space', 'under_score', '-leading', 'dotted.name', '2fa-required', '',
);

const anyName = fc.oneof(canonicalName, nonCanonicalName);

const storedGroups = fc.option(fc.array(anyName, { maxLength: 5 }), { nil: null });
const anyState = fc.constantFrom('active', 'inactive', 'pending');

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
  fc.assert(
    fc.property(canonicalName, (lower) => {
      const upper = lower.toUpperCase();
      assert.notEqual(lower, upper, 'fixture must actually differ in case');
      assert.equal(enforceGroupGate(identity([lower]), upper).allowed, false);
      assert.equal(enforceGroupGate(identity([upper]), lower).allowed, false);
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

test('law: enforceAccessGate — ALLOWED without skip implies a verbatim binding match', () => {
  fc.assert(
    fc.property(
      storedGroups,
      anyState,
      fc.array(anyName, { maxLength: 4 }),
      (groups, state, accessGroups) => {
        const id = identity(groups, state);
        const m = manifest('photos', { accessGroups });
        if (!enforceAccessGate(id, m).allowed) return;
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
      assert.equal(enforceAccessGate(identity([lower]), m).allowed, false);
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
        if (!enforceAccessGate(id, m).allowed) return;
        assert.deepEqual((groups ?? []).filter((g) => !GROUP_RE.test(g)), []);
      },
    ),
    { numRuns: 4000 },
  );
});

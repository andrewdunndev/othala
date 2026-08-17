// Tests for the isSessionFresh() helper extracted in FIX-B from admin.ts.
//
// Run with: tsx --test scripts/admin-freshness.test.mjs
//
// Coverage:
//   - aal2 authentication_methods entry within window → true
//   - aal2 entry outside window → false
//   - multiple aal2 entries, most-recent within window → true
//   - multiple aal2 entries, most-recent outside window → false
//   - aal2 entry with Date object (SDK deserialization) → works
//   - no aal2 entries, falls back to authenticated_at within window → true
//   - no aal2 entries, falls back to authenticated_at outside window → false
//   - neither field present → null (fail-open)
//   - malformed completed_at entry skipped, falls back to authenticated_at
//   - non-aal2 entries are ignored, falls back to authenticated_at

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isSessionFresh } from '../src/lib/admin.ts';

const WINDOW_HOURS = 8;
const WINDOW_MS = WINDOW_HOURS * 60 * 60 * 1000;

/** ISO timestamp offset from now by delta ms (negative = in the past). */
function ts(deltaMs) {
  return new Date(Date.now() + deltaMs).toISOString();
}

// ── authentication_methods primary source ─────────────────────────────────────

test('FIX-B: aal2 method completed_at within window → true', () => {
  const session = {
    authentication_methods: [
      { method: 'passkey', aal: 'aal2', completed_at: ts(-(WINDOW_MS - 60_000)) },
    ],
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

test('FIX-B: aal2 method completed_at outside window → false', () => {
  const session = {
    authentication_methods: [
      { method: 'passkey', aal: 'aal2', completed_at: ts(-(WINDOW_MS + 60_000)) },
    ],
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), false);
});

test('FIX-B: multiple aal2 entries — most-recent within window → true', () => {
  const session = {
    authentication_methods: [
      { method: 'passkey', aal: 'aal2', completed_at: ts(-(WINDOW_MS + 3_600_000)) }, // old
      { method: 'passkey', aal: 'aal2', completed_at: ts(-(WINDOW_MS - 60_000)) },    // recent
    ],
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

test('FIX-B: multiple aal2 entries — most-recent outside window → false', () => {
  const session = {
    authentication_methods: [
      { method: 'passkey', aal: 'aal2', completed_at: ts(-(WINDOW_MS + 3_600_000)) }, // older
      { method: 'passkey', aal: 'aal2', completed_at: ts(-(WINDOW_MS + 60_000)) },    // most-recent but still outside
    ],
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), false);
});

test('FIX-B: aal2 entry completed_at as Date object (SDK-deserialized) within window → true', () => {
  const session = {
    authentication_methods: [
      { method: 'passkey', aal: 'aal2', completed_at: new Date(Date.now() - (WINDOW_MS - 60_000)) },
    ],
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

test('FIX-B: non-aal2 entries are ignored; falls back to authenticated_at within window', () => {
  const session = {
    authentication_methods: [
      { method: 'password', aal: 'aal1', completed_at: ts(-(WINDOW_MS - 60_000)) }, // aal1 only
    ],
    authenticated_at: ts(-(WINDOW_MS - 120_000)),
  };
  // aal2 entries: none → fall back to authenticated_at (within window) → true
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

// ── authenticated_at fallback ─────────────────────────────────────────────────

test('FIX-B: no authentication_methods array — falls back to authenticated_at within window → true', () => {
  const session = {
    authenticated_at: ts(-(WINDOW_MS - 60_000)),
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

test('FIX-B: no authentication_methods array — falls back to authenticated_at outside window → false', () => {
  const session = {
    authenticated_at: ts(-(WINDOW_MS + 60_000)),
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), false);
});

test('FIX-B: authenticated_at as Date object (SDK-deserialized) within window → true', () => {
  const session = {
    authenticated_at: new Date(Date.now() - (WINDOW_MS - 60_000)),
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

// ── fail-closed: neither source readable ───────────────────────────────────

test('FIX-B: neither authentication_methods nor authenticated_at → false (fail-closed)', () => {
  const session = {};
  assert.equal(isSessionFresh(session, WINDOW_HOURS), false);
});

test('FIX-B: empty authentication_methods array, no authenticated_at → false (fail-closed)', () => {
  const session = { authentication_methods: [] };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), false);
});

test('FIX-B: malformed completed_at entry skipped; falls back to authenticated_at → true', () => {
  const session = {
    authentication_methods: [
      { method: 'passkey', aal: 'aal2', completed_at: 'not-a-date' }, // malformed — skipped
    ],
    authenticated_at: ts(-(WINDOW_MS - 60_000)), // fallback — within window
  };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), true);
});

test('FIX-B: completely missing both sources → false (fail-closed)', () => {
  const session = { active: true, identity: { id: 'admin-1' } };
  assert.equal(isSessionFresh(session, WINDOW_HOURS), false);
});

// Tests for the non-canonical group REPAIR surface.
//
// Run with: tsx --test scripts/noncanonical-repair.test.mjs
//
// What this covers. refuseNonCanonical (src/lib/gate.ts) denies an identity
// holding any group that misses GROUP_RE (src/lib/access-groups.ts), at every
// app, on every request. src/pages/admin/users/[id].astro is the only surface
// that can repair such an identity, and it does so through planGroupSave —
// tested here as a pure function, plus source assertions binding the page to
// it (an .astro page cannot be imported into this harness, so the wiring is
// asserted against the file's bytes).
//
// The invariant under test is NOT "the group is preserved in the store" — no
// write path this codebase owns can re-write a non-canonical name, because
// updateIdentity (src/lib/admin-api.ts) hands every list to validateGroups
// (src/lib/metadata-admin.ts) and the same GROUP_RE rejects it. The invariant
// is that an unrelated save can never MUTATE those names as a side effect:
// keeping one refuses the save (nothing written, identity unchanged), and
// removing one takes an affirmative per-name tick.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { planGroupSave, nonCanonicalGroups } from '../src/lib/gate.ts';

const PAGE = fileURLToPath(new URL('../src/pages/admin/users/[id].astro', import.meta.url));
const pageSource = readFileSync(PAGE, 'utf8');

function identity(groups) {
  return {
    id: 'id-1',
    state: 'active',
    schema_id: 'family',
    schema_url: '',
    traits: { username: 'tester', email: 'a@othala.test' },
    metadata_admin: { groups },
  };
}

// ── round trip: an unrelated save cannot silently mutate the stored name ─────

test('an unrelated save with the name KEPT is refused, so the identity is unchanged', () => {
  // The operator edited only the display name. The checkbox sets can never
  // contain "Access-Grafana", so the submission carries the canonical groups
  // alone — exactly the shape that used to drop it.
  const stored = identity(['family', 'Access-Grafana']);
  const plan = planGroupSave(stored, ['family'], []);

  assert.notEqual(plan.refusal, null, 'a kept non-canonical group MUST refuse the save');
  assert.match(plan.refusal, /Access-Grafana/);
  assert.deepEqual(plan.kept, ['Access-Grafana']);
  assert.deepEqual(plan.removed, []);
  // Round trip: the stored state is untouched by planning a refused save.
  assert.deepEqual(nonCanonicalGroups(stored), ['Access-Grafana']);
  assert.deepEqual(stored.metadata_admin.groups, ['family', 'Access-Grafana']);
});

test('a submission that omits the clear field entirely removes nothing', () => {
  // An older render, or any form that never grew the row, submits no
  // clearNonCanonical values at all. Absence must PRESERVE.
  const plan = planGroupSave(identity(['family', 'has space']), ['family'], []);
  assert.deepEqual(plan.removed, []);
  assert.deepEqual(plan.kept, ['has space']);
  assert.notEqual(plan.refusal, null);
});

test('the refusal names EVERY kept group, not just the first', () => {
  const plan = planGroupSave(
    identity(['family', 'Access-Grafana', 'has space']),
    ['family'],
    [],
  );
  assert.match(plan.refusal, /Access-Grafana/);
  assert.match(plan.refusal, /has space/);
});

// ── explicit removal ─────────────────────────────────────────────────────────

test('an explicit tick removes the name and lets the save through', () => {
  const plan = planGroupSave(
    identity(['family', 'Access-Grafana']),
    ['family', 'memories'],
    ['Access-Grafana'],
  );
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.removed, ['Access-Grafana']);
  assert.deepEqual(plan.kept, []);
  assert.deepEqual(plan.groups, ['family', 'memories']);
});

test('clearing SOME of several still refuses on the rest', () => {
  const plan = planGroupSave(
    identity(['family', 'Access-Grafana', 'has space']),
    ['family'],
    ['Access-Grafana'],
  );
  assert.deepEqual(plan.removed, ['Access-Grafana']);
  assert.deepEqual(plan.kept, ['has space']);
  assert.notEqual(plan.refusal, null);
  assert.doesNotMatch(plan.refusal, /Access-Grafana/);
});

// ── repair surface, not a creation surface ───────────────────────────────────

test('a non-canonical name submitted through the checkbox fields is NOT written', () => {
  const plan = planGroupSave(identity(['family']), ['family', 'Access-Grafana'], []);
  assert.deepEqual(plan.groups, ['family']);
  assert.equal(plan.refusal, null, 'a hand-crafted submission is dropped, not a stored-state refusal');
});

test('a clear tick cannot strip a CANONICAL group', () => {
  const plan = planGroupSave(identity(['family', 'memories']), ['family', 'memories'], ['memories']);
  assert.deepEqual(plan.removed, []);
  assert.deepEqual(plan.groups, ['family', 'memories']);
});

test('a clear tick naming a group the identity does not hold is inert', () => {
  const plan = planGroupSave(identity(['family', 'Access-Grafana']), ['family'], ['Never-Stored']);
  assert.deepEqual(plan.removed, []);
  assert.deepEqual(plan.kept, ['Access-Grafana']);
  assert.notEqual(plan.refusal, null);
});

test('duplicate submitted names collapse', () => {
  const plan = planGroupSave(identity(['family']), ['family', 'family'], []);
  assert.deepEqual(plan.groups, ['family']);
});

test('a clean identity plans a plain save', () => {
  const plan = planGroupSave(identity(['family', 'memories']), ['family', 'memories'], []);
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.kept, []);
  assert.deepEqual(plan.removed, []);
});

test('a null identity has nothing to repair', () => {
  const plan = planGroupSave(null, ['family'], ['anything']);
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.removed, []);
  assert.deepEqual(plan.groups, ['family']);
});

// ── the page is actually wired to it ─────────────────────────────────────────
//
// These assert the bytes of [id].astro because the page cannot be imported
// here. They are what keeps the pure tests above from passing while the save
// path quietly goes back to composing submitted checkboxes.

test('the save path writes planGroupSave output, not the raw submitted lists', () => {
  assert.match(pageSource, /planGroupSave\(/, 'page must call planGroupSave');
  assert.match(
    pageSource,
    /normalizeGroupOrder\(groupPlan\.groups\)/,
    'the stored list must come from the plan',
  );
  assert.doesNotMatch(
    pageSource,
    /normalizeGroupOrder\(\[\.\.\.identityGroups, \.\.\.accessGroups\]\)/,
    'the old submitted-checkboxes-only composition must be gone',
  );
});

test('a refusal blocks the write by joining formErrors', () => {
  assert.match(
    pageSource,
    /if \(groupPlan\.refusal\) formErrors\.nonCanonicalGroups = groupPlan\.refusal;/,
  );
  // The existing guard that gates updateIdentity on an empty formErrors.
  assert.match(pageSource, /if \(Object\.keys\(formErrors\)\.length === 0\) \{/);
});

test('the edit form renders the stored non-canonical names with a removal control', () => {
  assert.match(pageSource, /const nonCanonical = nonCanonicalGroups\(identity\);/);
  assert.match(pageSource, /name="clearNonCanonical"/);
  assert.match(pageSource, /fd\.getAll\('clearNonCanonical'\)/);
});

test('the removal control is unchecked by default (removal is affirmative)', () => {
  const row = /<input type="checkbox" name="clearNonCanonical" value=\{g\} \/>/;
  assert.match(pageSource, row, 'the clear checkbox must carry no checked attribute');
});

test('the repair row rides the existing save form, under its CSRF token', () => {
  // The row adds a FIELD to the one save form rather than a second mutating
  // surface: no new action value, no new token, nothing for the POST handler's
  // CSRF branch to grow a case for. Slice the save <form> and prove the field
  // is inside it, next to csrfTokenSave.
  const openTag = '<form method="post" class="stack-lg" novalidate>';
  const open = pageSource.indexOf(openTag);
  assert.notEqual(open, -1, 'save form not found');
  const close = pageSource.indexOf('</form>', open);
  assert.notEqual(close, -1, 'save form never closes');
  const saveForm = pageSource.slice(open + openTag.length, close);

  assert.match(saveForm, /<input type="hidden" name="action" value="save" \/>/);
  assert.match(saveForm, /<input type="hidden" name="csrf_token" value=\{csrfTokenSave\} \/>/);
  assert.match(saveForm, /name="clearNonCanonical"/, 'the repair field must live inside the save form');
  assert.doesNotMatch(saveForm, /<form /, 'no nested form under the save form');

  // The handler's action-scoped set carries no verb THIS (repair-checkbox)
  // feature didn't put there: "save" stays on the identity-only branch. The
  // literal below is intentionally the full set (not just the repair-era
  // subset) so a future PR that adds a genuine new action-scoped verb updates
  // this list deliberately rather than this test silently going stale.
  assert.match(
    pageSource,
    /const actionScopedActions = new Set\(\['issue-recovery', 'send-invite-email', 'force-relogin', 'deactivate', 'reactivate', 'grant-admin', 'revoke-admin'\]\);/,
  );
});

test('the non-canonical names are rendered escaped, never via set:html', () => {
  // Astro escapes {expr} in both text and attribute position; the only way to
  // lose that on this page is an explicit set:html, which must not exist.
  assert.doesNotMatch(pageSource, /set:html/);
});

test('read mode files them under their own heading, not under access', () => {
  assert.match(pageSource, /unrecognised/);
  assert.match(pageSource, /const nonCanonicalSet = new Set\(nonCanonical\);/);
  assert.match(
    pageSource,
    /accessGroupMembership = groups\.filter\(\(g\) => !nonCanonicalSet\.has\(g\)/,
  );
});

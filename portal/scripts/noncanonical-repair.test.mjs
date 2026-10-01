// Invariant: non-canonical groups are repaired only through the explicit repair path.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { planGroupSave, nonCanonicalGroups } from '../src/lib/gate.ts';

const PAGE = fileURLToPath(new URL('../src/pages/admin/users/[id].astro', import.meta.url));
const pageSource = readFileSync(PAGE, 'utf8');
const LIB = fileURLToPath(new URL('../src/lib/admin-actions.ts', import.meta.url));
const libSource = readFileSync(LIB, 'utf8');

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

test('an unrelated save with the name KEPT is refused, so the identity is unchanged', () => {
  const stored = identity(['family', 'Access-Grafana']);
  const plan = planGroupSave(stored, ['family'], []);

  assert.notEqual(plan.refusal, null, 'a kept non-canonical group MUST refuse the save');
  assert.match(plan.refusal, /Access-Grafana/);
  assert.deepEqual(plan.kept, ['Access-Grafana']);
  assert.deepEqual(plan.removed, []);
  assert.deepEqual(nonCanonicalGroups(stored), ['Access-Grafana']);
  assert.deepEqual(stored.metadata_admin.groups, ['family', 'Access-Grafana']);
});

test('a submission that omits the clear field entirely removes nothing', () => {
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

test('saveAction writes planGroupSave output, not the raw submitted lists', () => {
  assert.match(libSource, /planGroupSave\(/, 'saveAction must call planGroupSave');
  assert.match(
    libSource,
    /normalizeGroupOrder\(groupPlan\.groups\)/,
    'the stored list must come from the plan',
  );
  assert.doesNotMatch(
    libSource,
    /normalizeGroupOrder\(\[\.\.\.identityGroups, \.\.\.accessGroups\]\)/,
    'the old submitted-checkboxes-only composition must be gone',
  );
});

test('a refusal blocks the write by returning formErrors instead of updating', () => {
  assert.match(
    libSource,
    /if \(groupPlan\.refusal\) formErrors\.nonCanonicalGroups = groupPlan\.refusal;/,
  );
  assert.match(libSource, /if \(Object\.keys\(formErrors\)\.length > 0\) \{\s*\n\s*return \{ formErrors, refetch: false \};/);
});

test('the person page lists every unrecognised stored name with its own removal form', () => {
  assert.match(pageSource, /const unrecognised = identity \? unrecognisedGroups\(identity, manifests\) : \[\];/);
  assert.match(pageSource, /<input type="hidden" name="group" value=\{g\} \/>/);
  assert.match(libSource, /fd\.getAll\('clearNonCanonical'\)/, 'saveAction must read the clear ticks');
  assert.match(libSource, /for \(const g of removing\) if \(!GROUP_RE\.test\(g\)\) fd\.append\('clearNonCanonical', g\);/);
});

test('removal is affirmative: nothing is removed unless the admin posts that name', () => {
  assert.match(libSource, /removeGroupsAction[\s\S]*remove: fd\.getAll\('group'\)/);
  assert.doesNotMatch(pageSource, /name="clearNonCanonical"|name="clearUnconfigured"/, 'the page names groups to remove, never pre-ticks them');
});

test('the removal form posts under its own CSRF token and the shared verifier', () => {
  assert.match(pageSource, /<input type="hidden" name="csrf_token" value=\{tok\('remove-groups'\)\} \/>/);
  assert.match(pageSource, /<input type="hidden" name="action" value="remove-groups" \/>/);
  assert.match(pageSource, /verifyToken\(String\(fd\.get\('csrf_token'\) \?\? ''\), adminId, tokenAction\)/);
  assert.match(pageSource, /const tokenAction = action === 'remove-credential' \? `remove-\$\{String\(fd\.get\('cred_type'\) \?\? ''\)\}` : action;/);
});

test('the non-canonical names are rendered escaped, never via set:html', () => {
  assert.doesNotMatch(pageSource, /set:html/);
});

test('they sit under their own heading, not in the apps section', () => {
  assert.match(pageSource, /<h2 id="h-groups">Unrecognised groups<\/h2>/);
  assert.match(pageSource, /unrecognisedGroups\(identity, manifests\)/);
});

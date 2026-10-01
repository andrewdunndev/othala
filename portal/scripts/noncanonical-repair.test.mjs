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

test('the edit form renders the stored non-canonical names with a removal control', () => {
  assert.match(pageSource, /const nonCanonical = nonCanonicalGroups\(identity\);/);
  assert.match(pageSource, /name="clearNonCanonical"/);
  assert.match(libSource, /fd\.getAll\('clearNonCanonical'\)/, 'saveAction must read the clear ticks');
});

test('the removal control is unchecked by default (removal is affirmative)', () => {
  const row = /<input type="checkbox" name="clearNonCanonical" value=\{g\} \/>/;
  assert.match(pageSource, row, 'the clear checkbox must carry no checked attribute');
});

test('the repair row rides the existing save form, under its CSRF token', () => {
  const openTag = '<form method="post" enctype="application/x-www-form-urlencoded" class="stack-lg" novalidate>';
  const open = pageSource.indexOf(openTag);
  assert.notEqual(open, -1, 'save form not found');
  const close = pageSource.indexOf('</form>', open);
  assert.notEqual(close, -1, 'save form never closes');
  const saveForm = pageSource.slice(open + openTag.length, close);

  assert.match(saveForm, /<input type="hidden" name="action" value="save" \/>/);
  assert.match(saveForm, /<input type="hidden" name="csrf_token" value=\{csrfTokenSave\} \/>/);
  assert.match(saveForm, /name="clearNonCanonical"/, 'the repair field must live inside the save form');
  assert.doesNotMatch(saveForm, /<form /, 'no nested form under the save form');

  assert.doesNotMatch(pageSource, /actionScopedActions/);
  assert.match(pageSource, /verifyToken\(String\(fd\.get\('csrf_token'\) \?\? ''\), adminIdentityId, tokenAction\)/);
  assert.match(pageSource, /const tokenAction = action === 'remove-credential' \? `remove-\$\{String\(fd\.get\('cred_type'\) \?\? ''\)\}` : action;/);
});

test('the non-canonical names are rendered escaped, never via set:html', () => {
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

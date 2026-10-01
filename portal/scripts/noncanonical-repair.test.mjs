// Invariant: non-canonical groups are repaired only through the explicit repair path.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { planGroupSave, nonCanonicalGroups } from '../src/lib/gate.ts';
import { identity as buildIdentity } from '../src/lib/test-builders.ts';

const PAGE = fileURLToPath(new URL('../src/pages/admin/users/[id].astro', import.meta.url));
const pageSource = readFileSync(PAGE, 'utf8');

const identity = (groups) => buildIdentity({ metadataAdmin: { groups } });

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

// Markup-only: no spec drives this page, so one source check stays.
test('the non-canonical names are rendered escaped, never via set:html', () => {
  assert.doesNotMatch(pageSource, /set:html/);
});

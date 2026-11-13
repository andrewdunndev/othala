// Invariants: the reference-check job runs a tagged reference, never a moving branch, since it executes with CI tokens;
// each toolchain version stated in more than one file agrees across them.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const read = (path) => readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), 'utf8');
const ci = read('.gitlab-ci.yml');

test('reference_ref is a release tag', () => {
  assert.match(ci, /^\s+reference_ref: v\d+\.\d+\.\d+$/m);
});

test('the deviation register parses and every entry carries a reason and an owner', () => {
  const entries = parse(readFileSync(fileURLToPath(new URL('../../.deviations.yaml', import.meta.url)), 'utf8'));
  assert.ok(Array.isArray(entries) && entries.length > 0);
  for (const e of entries) {
    for (const k of ['standard', 'assertion', 'reason', 'owner']) assert.ok(String(e[k] ?? '').trim() !== '', k);
  }
});

const major = (v) => Number(String(v).match(/\d+/)[0]);

test('the node major in mise.toml is the one the image, engines and @types/node state', () => {
  const mise = Number(read('mise.toml').match(/^node = "(\d+)/m)[1]);
  const images = [...read('portal/Containerfile').matchAll(/nodejs-(\d+)/g)].map((m) => Number(m[1]));
  assert.ok(images.length > 0, 'portal/Containerfile names a nodejs image');
  for (const n of images) assert.equal(n, mise);
  assert.equal(major(JSON.parse(read('portal/package.json')).engines.node), mise);
  for (const tree of ['portal', 'e2e', 'site']) {
    assert.equal(major(JSON.parse(read(`${tree}/package.json`)).devDependencies['@types/node']), mise, `${tree} @types/node`);
  }
});

test('the Playwright npm package and the e2e-tester base image are one version', () => {
  const pkg = JSON.parse(read('e2e/package.json')).devDependencies['@playwright/test'];
  const image = read('e2e/Containerfile').match(/^FROM mcr\.microsoft\.com\/playwright:v([\d.]+)-/m);
  assert.ok(image, 'e2e/Containerfile has a pinned playwright base');
  assert.equal(image[1], pkg);
});

test('render and portal pin the identical othala image line in the example and the overlay', () => {
  for (const [file, pattern] of [
    ['deploy/example/compose.yml', /^\s+image: (registry\.gitlab\.com\/dunn\.dev\/othala:\S+)$/gm],
    ['e2e/compose.e2e.yml', /^\s+image: (\$\{AUTH_REGISTRY\}:\$\{AUTH_VERSION\})$/gm],
  ]) {
    const lines = [...read(file).matchAll(pattern)].map((m) => m[1]);
    assert.equal(lines.length, 2, `${file}: render and othala`);
    assert.equal(lines[0], lines[1], file);
  }
});

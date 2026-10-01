// Invariant: the public mux never exposes admin-listener POST endpoints.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readdirSync, statSync } from 'node:fs';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagesDir = join(here, '..', 'src', 'pages');

const FORBIDDEN_ROUTES = new Set([
  '/admin/recovery-gate',
  '/admin/login-code-gate',
  '/admin/profile-gate',
  '/admin/second-factor-gate',
  '/admin/profile-sessions',
  '/admin/passkey-prune',
]);

const PAGE_EXT = /\.(astro|ts|js|mjs|md|mdx)$/;

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...walk(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

function routeForFile(file) {
  let rel = relative(pagesDir, file).split(sep).join('/');
  rel = rel.replace(PAGE_EXT, '');
  if (rel.endsWith('/index')) rel = rel.slice(0, -'/index'.length);
  if (rel === 'index') rel = '';
  return '/' + rel;
}

test('no src/pages/ file resolves to an admin-listener-only POST route', () => {
  const files = walk(pagesDir).filter((f) => PAGE_EXT.test(f));
  assert.ok(files.length > 0, 'expected to find page files under src/pages/');

  const offenders = [];
  for (const file of files) {
    const route = routeForFile(file);
    if (FORBIDDEN_ROUTES.has(route)) {
      offenders.push(`${relative(pagesDir, file)} -> ${route}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    'A src/pages/ file resolves to an admin-listener-only route (would expose ' +
      'the unauthenticated POST fan-out on the public port): ' +
      offenders.join(', '),
  );
});

test('the route-mapping helper actually maps the dangerous filenames', () => {
  assert.equal(routeForFile(join(pagesDir, 'admin', 'recovery-gate.ts')), '/admin/recovery-gate');
  assert.equal(
    routeForFile(join(pagesDir, 'admin', 'recovery-gate', 'index.astro')),
    '/admin/recovery-gate',
  );
  assert.equal(
    routeForFile(join(pagesDir, 'admin', 'recovery-gate.astro')),
    '/admin/recovery-gate',
  );
  assert.equal(
    routeForFile(join(pagesDir, 'admin', 'login-code-gate.astro')),
    '/admin/login-code-gate',
  );
  for (const r of ['/admin/recovery-gate', '/admin/login-code-gate']) {
    assert.ok(FORBIDDEN_ROUTES.has(r));
  }
});

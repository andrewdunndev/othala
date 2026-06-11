// Static guard: the public (Astro) mux must NOT expose the admin-listener
// POST endpoints.
//
// Run with: tsx --test scripts/public-mux-disjoint.test.mjs
//
// /admin/revoke-user, /admin/recovery-gate, and /admin/login-gate are served
// ONLY by the admin listener (src/server/listen.mjs), bearer-guarded and bound
// to the admin port. They are deliberately absent from src/pages/, so the
// public port never routes them.
//
// The risk this test fences off: a future `src/pages/admin/revoke-user.ts`
// (or .astro, or a revoke-user/index.* directory route) would make Astro
// serve POST /admin/revoke-user on the PUBLIC port — silently re-exposing
// the unauthenticated fan-out the listener guards with a bearer. A static
// filesystem check fails the build the moment such a file appears, long
// before it can ship.
//
// This is a pure fs/route-mapping check: it reads src/pages/ and derives the
// Astro route each file would serve, then asserts none of them is one of the
// admin-listener-only paths.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, statSync } from 'node:fs';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pagesDir = join(here, '..', 'src', 'pages');

// The admin-listener-only POST paths (mirror of ADMIN_POST_ROUTES in
// src/server/listen.mjs). No Astro page may resolve to any of these.
const FORBIDDEN_ROUTES = new Set(['/admin/revoke-user', '/admin/recovery-gate', '/admin/login-gate']);

// Astro page-file extensions that produce a route.
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

// Map a page FILE to the Astro ROUTE path it serves. Mirrors Astro's
// file-based routing for the cases relevant here:
//   pages/admin/revoke-user.ts          -> /admin/revoke-user
//   pages/admin/revoke-user/index.astro -> /admin/revoke-user
//   pages/admin/recovery-gate.astro     -> /admin/recovery-gate
// (Dynamic [param] segments can't statically equal a literal forbidden
// path, so they're left as-is; an exact-literal collision is what matters.)
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
  // Guards the guard: prove the mapping would CATCH the bad files, so a
  // future regression in routeForFile can't silently pass the suite.
  assert.equal(routeForFile(join(pagesDir, 'admin', 'revoke-user.ts')), '/admin/revoke-user');
  assert.equal(
    routeForFile(join(pagesDir, 'admin', 'revoke-user', 'index.astro')),
    '/admin/revoke-user',
  );
  assert.equal(
    routeForFile(join(pagesDir, 'admin', 'recovery-gate.astro')),
    '/admin/recovery-gate',
  );
  assert.equal(
    routeForFile(join(pagesDir, 'admin', 'login-gate.astro')),
    '/admin/login-gate',
  );
  for (const r of ['/admin/revoke-user', '/admin/recovery-gate', '/admin/login-gate']) {
    assert.ok(FORBIDDEN_ROUTES.has(r));
  }
});

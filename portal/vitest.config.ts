/**
 * Vitest configuration for the whole portal test suite.
 *
 * Scope: src/**\/*.test.ts (TypeScript-native unit tests) AND
 * scripts/*.test.mjs (integration-style tests against the built artefacts,
 * incl. the fast-check fuzz/property suites). One runner for both — the
 * former node --test + tsx harness over scripts/*.test.mjs was retired;
 * vitest handles TypeScript natively, so tsx is no longer a test dependency
 * (it remains a devDependency for `npm run lint:manifests`'s CLI runtime).
 *
 * Run: npx vitest run   (from portal/)
 *
 * Environment: node (not jsdom). DOMPurify uses isomorphic-dompurify which
 * works in Node without a DOM. Marked also runs fine in Node.
 */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'scripts/*.test.mjs'],
    // Run serially to avoid cross-test module-level state (rate-limiter Map,
    // process.env mutation in config.test.mjs/tiles.test.mjs).
    // (poolOptions was removed in Vitest 4; singleFork is now a top-level option.)
    pool: 'forks',
    singleFork: true,
  },
});

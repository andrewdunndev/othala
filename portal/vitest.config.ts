/**
 * Vitest configuration for portal/src/lib unit tests.
 *
 * Scope: src/lib/*.test.ts (TypeScript-native unit tests that import the
 * lib directly without going through the Astro build pipeline).
 *
 * These complement the existing scripts/*.test.mjs suite (Node --test +
 * tsx), which covers integration-style tests against the built artefacts.
 * The two harnesses run independently; vitest is faster for authoring new
 * lib tests because it handles TypeScript without a separate transpile step.
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
    include: ['src/lib/**/*.test.ts'],
    // Run serially to avoid cross-test module-level state (rate-limiter Map).
    // (poolOptions was removed in Vitest 4; singleFork is now a top-level option.)
    pool: 'forks',
    singleFork: true,
  },
});

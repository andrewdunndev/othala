import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'scripts/*.test.mjs'],
    // A forked worker per file keeps module state and process.env mutations from crossing files.
    pool: 'forks',
    // Expected-error stderr from passing tests ("kratos down") buried the failing line in CI; a failing test still prints its own.
    silent: 'passed-only',
  },
});

// Manifest lint CLI — standalone entry point for the manifest linter.
//
// Runs validateClients over every *.yaml manifest in MANIFEST_DIR (or a
// directory passed as the first CLI argument), then prints findings and exits
// non-zero if any BLOCK-class errors are present.
//
// Usage:
//   node dist/server/manifest-lint.mjs [<manifest-dir>]
//   MANIFEST_DIR=/etc/portal/manifests node dist/server/manifest-lint.mjs
//
// Exit codes:
//   0  — all manifests valid (no BLOCK-class errors)
//   1  — one or more manifests contain BLOCK-class errors
//   2  — directory not found or no manifests found (not an error, prints notice)
//
// Intended consumers:
//   - deployment CI: a pre-land manifest-lint gate (runs against the
//     operator's catalog directory via MANIFEST_DIR override).
//   - othala CI: `npm run lint:manifests` (validates e2e/manifests/).
//   - Operator: `node dist/server/manifest-lint.mjs /path/to/manifests`
//
// Built by:  npm run build:manifest-lint  (esbuild, same shape as registrar).
// Source:    src/server/manifest-lint-cli.ts

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseManifest, validateClients } from '../lib/manifests';

function manifestDir(): string {
  // CLI argument takes precedence over env var.
  return process.argv[2] ?? process.env.MANIFEST_DIR ?? '/etc/portal/manifests';
}

async function main(): Promise<void> {
  const dir = manifestDir();

  let files: string[];
  try {
    files = readdirSync(dir)
      .filter((f) => (f.endsWith('.yaml') || f.endsWith('.yml')) && f !== 'groups.yaml')
      .sort();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      console.warn(`[manifest-lint] directory not found: ${dir}`);
      process.exit(2);
    }
    throw err;
  }

  if (files.length === 0) {
    console.warn(`[manifest-lint] no *.yaml manifests found in ${dir}`);
    process.exit(2);
  }

  console.log(`[manifest-lint] linting ${files.length} manifest(s) in ${dir}`);

  const manifests = [];
  let parseErrors = 0;
  for (const f of files) {
    try {
      const text = readFileSync(join(dir, f), 'utf8');
      const m = parseManifest(text, f);
      manifests.push(m);
    } catch (err) {
      console.error(`[manifest-lint] PARSE ERROR in ${f}: ${err}`);
      parseErrors++;
    }
  }

  const errs = validateClients(manifests);

  if (errs.length === 0 && parseErrors === 0) {
    console.log(`[manifest-lint] OK — ${manifests.length} manifest(s) passed`);
    process.exit(0);
  }

  for (const e of errs) {
    console.error(`[manifest-lint] ERROR: ${e}`);
  }
  if (parseErrors > 0) {
    console.error(`[manifest-lint] ${parseErrors} parse error(s) above`);
  }
  console.error(
    `[manifest-lint] FAILED — ${errs.length} validation error(s), ${parseErrors} parse error(s)`,
  );
  process.exit(1);
}

main().catch((err) => {
  console.error('[manifest-lint] unexpected error:', err?.message ?? err);
  process.exit(1);
});

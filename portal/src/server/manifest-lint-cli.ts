// Manifest lint CLI: lints every apps/*.yaml under the content root in the first argument (or CONTENT_DIR), prints
// findings, exits 1 on a parse, validation or BLOCK error, 2 when no directory or manifests are found.
//   node dist/server/manifest-lint.mjs [<content-dir>]
// Built by `npm run build:manifest-lint` (esbuild, same shape as registrar). `config.mjs check` covers the whole tree.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { CONTENT_DIR } from '../lib/constants';
import { lintApps } from '../lib/content';

function main(): number {
  const dir = join(process.argv[2] ?? CONTENT_DIR, 'apps');
  if (!existsSync(dir)) {
    console.warn(`[manifest-lint] directory not found: ${dir}`);
    return 2;
  }
  const { manifests, errors, warnings } = lintApps(dir);
  if (manifests.length === 0 && errors.length === 0) {
    console.warn(`[manifest-lint] no *.yaml manifests found in ${dir}`);
    return 2;
  }
  console.log(`[manifest-lint] linted ${manifests.length} manifest(s) in ${dir}`);
  for (const w of warnings) console.warn(`[manifest-lint] WARN: ${w}`);
  for (const e of errors) console.error(`[manifest-lint] ERROR: ${e}`);
  if (errors.length > 0) {
    console.error(`[manifest-lint] FAILED: ${errors.length} error(s)`);
    return 1;
  }
  console.log(`[manifest-lint] OK: ${manifests.length} manifest(s) passed`);
  return 0;
}

process.exitCode = main();

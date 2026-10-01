// Manifest lint CLI: runs validateClients over every *.yaml in the first argument (or
// the golden manifest dir), prints findings, exits 1 on BLOCK-class errors, 2 when
// no directory or manifests are found.
//   node dist/server/manifest-lint.mjs [<manifest-dir>]
// Built by `npm run build:manifest-lint` (esbuild, same shape as registrar).

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseManifest, validateClients } from '../lib/manifests';
import { lintManifests } from '../lib/manifest-lint';
import { MANIFEST_DIR } from '../lib/constants';

function manifestDir(): string {
  return process.argv[2] ?? MANIFEST_DIR;
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

  // Warnings never fail the run. Group warnings need the live registry, so only requirement names are checked here.
  const requirementNames = (() => {
    try {
      return readdirSync(join(dir, 'requirements'))
        .filter((f) => f.endsWith('.md'))
        .map((f) => f.slice(0, -3));
    } catch {
      return [];
    }
  })();
  const referencedGroups = manifests.flatMap((m) => [...m.accessGroups, ...Object.keys(m.groupRoleMap)]);
  for (const w of lintManifests(manifests, referencedGroups, requirementNames)) {
    console.warn(`[manifest-lint] ${w.severity.toUpperCase()}: ${w.source}: ${w.message}`);
  }

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

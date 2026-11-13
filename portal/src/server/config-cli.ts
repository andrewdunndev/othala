// Config CLI, run from the portal image as a one-shot before Kratos, Hydra and Caddy start:
//   node dist/server/config.mjs render [--policy <dir>] [--content <dir>] [--out <dir>]
//   node dist/server/config.mjs check [--policy <dir>] [--content <dir>]
//   node dist/server/config.mjs gen-secrets [--content <dir>]
//   node dist/server/config.mjs check-ory --kratos <file> --hydra <file> --identity-schema <file> --jsonnet <file> [--policy <dir>]
// Values and secrets come from the environment. Exits 1 on a failed check or render, 2 on bad usage. A refused render keeps the last good output; a write that fails partway clears it.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { CONTENT_DIR, POLICY_DIR, RENDER_DIR } from '../lib/constants';
import { checkOry } from '../lib/contract';
import { lintApps } from '../lib/content';
import { clearRendered, generateSecrets, preflight, RenderError, render, writeRendered, type RenderedFile } from '../lib/render';

const USAGE =
  'usage: config.mjs render [--policy <dir>] [--content <dir>] [--out <dir>] | check [--policy <dir>] [--content <dir>] | gen-secrets [--content <dir>] | check-ory --kratos <file> --hydra <file> --identity-schema <file> --jsonnet <file> [--policy <dir>]';

function main(): number {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        policy: { type: 'string', default: POLICY_DIR },
        content: { type: 'string', default: CONTENT_DIR },
        out: { type: 'string', default: RENDER_DIR },
        kratos: { type: 'string' },
        hydra: { type: 'string' },
        'identity-schema': { type: 'string' },
        jsonnet: { type: 'string' },
      },
    });
  } catch (err) {
    console.error(`[othala-config] ${(err as Error).message}\n${USAGE}`);
    return 2;
  }
  const { positionals, values } = parsed;
  const policy = values.policy!;
  const content = values.content!;
  const out = values.out!;
  if (positionals.length !== 1) {
    console.error(USAGE);
    return 2;
  }

  switch (positionals[0]) {
    case 'check': {
      const errors = preflight(policy, content, process.env);
      for (const e of errors) console.error(`[othala-config] ${e}`);
      if (errors.length > 0) return 1;
      const apps = join(content, 'apps');
      for (const w of existsSync(apps) ? lintApps(apps).warnings : []) console.warn(`[othala-config] WARN: ${w}`);
      console.log(`[othala-config] check OK (${policy}, ${content})`);
      return 0;
    }
    case 'render': {
      let files: RenderedFile[];
      try {
        files = render(policy, content, process.env);
      } catch (err) {
        // A refusal is the operator's to fix, and the running stack keeps serving the last good render. Only a RenderError message is safe to print.
        const lines = err instanceof RenderError ? err.message.split('\n') : [`render failed: ${(err as NodeJS.ErrnoException).code ?? 'unexpected error'}`];
        for (const line of lines) console.error(`[othala-config] ${line}`);
        console.error('[othala-config] render refused; earlier output kept');
        return 1;
      }
      try {
        writeRendered(out, files);
        console.log(`[othala-config] rendered ${files.length} files from ${policy} and ${content} to ${out}`);
        return 0;
      } catch (err) {
        // A write that fails partway leaves old and new files mixed, so Kratos, Hydra and Caddy must refuse to boot on it.
        console.error(`[othala-config] render failed writing: ${(err as NodeJS.ErrnoException).code ?? 'unexpected error'}`);
        clearRendered(out);
        console.error('[othala-config] earlier output cleared');
        return 1;
      }
    }
    case 'check-ory': {
      if (!values.kratos || !values.hydra || !values['identity-schema'] || !values.jsonnet) {
        console.error(USAGE);
        return 2;
      }
      const violations = checkOry(policy, { kratos: values.kratos, hydra: values.hydra, identitySchema: values['identity-schema'], jsonnet: values.jsonnet });
      for (const v of violations) console.error(`[othala-config] ${v}`);
      if (violations.length > 0) return 1;
      console.log('[othala-config] check-ory OK');
      return 0;
    }
    case 'gen-secrets':
      process.stdout.write(generateSecrets(content));
      return 0;
    default:
      console.error(USAGE);
      return 2;
  }
}

process.exitCode = main();

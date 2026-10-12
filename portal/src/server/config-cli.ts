// Config CLI, run from the portal image as a one-shot before Kratos, Hydra and Caddy start:
//   node dist/server/config.mjs render [--policy <dir>] [--content <dir>] [--out <dir>]
//   node dist/server/config.mjs check [--policy <dir>] [--content <dir>]
//   node dist/server/config.mjs gen-secrets [--content <dir>]
// Values and secrets come from the environment. Exits 1 on a failed check or render, 2 on bad usage.

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { CONTENT_DIR, POLICY_DIR, RENDER_DIR } from '../lib/constants';
import { lintApps } from '../lib/content';
import { check, generateSecrets, render, RenderError, writeRendered } from '../lib/render';

const USAGE =
  'usage: config.mjs render [--policy <dir>] [--content <dir>] [--out <dir>] | check [--policy <dir>] [--content <dir>] | gen-secrets [--content <dir>]';

function main(): number {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        policy: { type: 'string', default: POLICY_DIR },
        content: { type: 'string', default: CONTENT_DIR },
        out: { type: 'string', default: RENDER_DIR },
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
      const errors = check(policy, content, process.env);
      for (const e of errors) console.error(`[othala-config] ${e}`);
      if (errors.length > 0) return 1;
      const apps = join(content, 'apps');
      for (const w of existsSync(apps) ? lintApps(apps).warnings : []) console.warn(`[othala-config] WARN: ${w}`);
      console.log(`[othala-config] check OK (${policy}, ${content})`);
      return 0;
    }
    case 'render': {
      try {
        const files = render(policy, content, process.env);
        writeRendered(out, files);
        console.log(`[othala-config] rendered ${files.length} files from ${policy} and ${content} to ${out}`);
        return 0;
      } catch (err) {
        if (!(err instanceof RenderError)) throw err;
        for (const line of err.message.split('\n')) console.error(`[othala-config] ${line}`);
        console.error('[othala-config] render refused; nothing written');
        return 1;
      }
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

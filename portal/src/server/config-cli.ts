// Ory config CLI, run from the portal image as a one-shot before Kratos and Hydra start:
//   node dist/server/config.mjs render [--policy <dir>] [--out <dir>]
//   node dist/server/config.mjs check [--policy <dir>]
//   node dist/server/config.mjs gen-secrets
// Values and secrets come from the environment. Exits 1 on a failed check or render, 2 on bad usage.

import { parseArgs } from 'node:util';
import { POLICY_DIR, RENDER_DIR } from '../lib/constants';
import { check, generateSecrets, render, RenderError, writeRendered } from '../lib/render';

const USAGE = 'usage: config.mjs render [--policy <dir>] [--out <dir>] | check [--policy <dir>] | gen-secrets';

function main(): number {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: { policy: { type: 'string', default: POLICY_DIR }, out: { type: 'string', default: RENDER_DIR } },
    });
  } catch (err) {
    console.error(`[othala-config] ${(err as Error).message}\n${USAGE}`);
    return 2;
  }
  const { positionals, values } = parsed;
  const policy = values.policy!;
  const out = values.out!;
  if (positionals.length !== 1) {
    console.error(USAGE);
    return 2;
  }

  switch (positionals[0]) {
    case 'check': {
      const errors = check(policy, process.env);
      for (const e of errors) console.error(`[othala-config] ${e}`);
      if (errors.length > 0) return 1;
      console.log(`[othala-config] check OK (${policy})`);
      return 0;
    }
    case 'render': {
      try {
        const files = render(policy, process.env);
        writeRendered(out, files);
        console.log(`[othala-config] rendered ${files.length} files from ${policy} to ${out}`);
        return 0;
      } catch (err) {
        if (!(err instanceof RenderError)) throw err;
        for (const line of err.message.split('\n')) console.error(`[othala-config] ${line}`);
        console.error('[othala-config] render refused; nothing written');
        return 1;
      }
    }
    case 'gen-secrets':
      process.stdout.write(generateSecrets());
      return 0;
    default:
      console.error(USAGE);
      return 2;
  }
}

process.exitCode = main();

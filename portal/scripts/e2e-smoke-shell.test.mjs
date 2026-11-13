// Invariant: the smoke's identity seeder emits valid JavaScript with and without a password, so a deny probe never runs against an empty subject.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const smoke = fileURLToPath(new URL('../../e2e/smoke.sh', import.meta.url));

function seederScript(...args) {
  // node_in is the pipe into the container; here it returns the script it would have run.
  const body = `OTHALA_APEX=othala.test\nnode_in() { cat; }\n${execFileSync('sed', ['-n', '/^mk_identity() {/,/^}/p', smoke], { encoding: 'utf8' })}\nmk_identity ${args.map((a) => `'${a}'`).join(' ')}\n`;
  return execFileSync('bash', ['-c', body], { encoding: 'utf8' });
}

function parses(js) {
  const dir = mkdtempSync(join(tmpdir(), 'smoke-seed-'));
  try {
    const file = join(dir, 'seed.cjs');
    writeFileSync(file, js);
    return spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('mk_identity without a password emits parseable JavaScript with no credentials', () => {
  const js = seederScript('inactive', "['grafana-access']", 'g2.inactive');
  const r = parses(js);
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!js.includes('credentials'));
});

test('mk_identity with a password emits parseable JavaScript carrying the password credential', () => {
  const js = seederScript('active', "['grafana-access']", 'g1.member', 'pw-123');
  const r = parses(js);
  assert.equal(r.status, 0, r.stderr);
  assert.match(js, /credentials:\{password:\{config:\{password:'pw-123'\}\}\}/);
});

test('the smoke file keeps the seeder defined once', () => {
  assert.equal((readFileSync(smoke, 'utf8').match(/^mk_identity\(\) \{/gm) ?? []).length, 1);
});

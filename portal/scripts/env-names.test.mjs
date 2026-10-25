// Invariant: the retired-name table and the known OTHALA_ set are disjoint, every retired name carries a fix, and the
// errors name the variable, never its value.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SECRETS } from '../src/lib/render.ts';
import { envNameErrors, KNOWN_OTHALA_NAMES, RETIRED_NAMES } from '../src/lib/env-names.ts';

test('no name is both known and retired, and every retired name names a fix', () => {
  for (const [name, fix] of Object.entries(RETIRED_NAMES)) {
    assert.equal(KNOWN_OTHALA_NAMES.includes(name), false, name);
    assert.match(fix, /^(delete|rename) it/, name);
  }
});

test('the tables are frozen', () => {
  assert.ok(Object.isFrozen(RETIRED_NAMES));
  assert.ok(Object.isFrozen(KNOWN_OTHALA_NAMES));
});

test('every retired name is an error with its fix; known and unprefixed names pass; unset is absent', () => {
  for (const name of Object.keys(RETIRED_NAMES)) {
    assert.deepEqual(envNameErrors({ [name]: 'secret-looking-value' }), [`${name} is retired: ${RETIRED_NAMES[name]}`]);
  }
  const known = Object.fromEntries(KNOWN_OTHALA_NAMES.map((n) => [n, 'v']));
  assert.deepEqual(envNameErrors({ ...known, PATH: '/bin', GRAFANA_CLIENT_SECRET: 'v', OTHALA_SITE_NAME: undefined }), []);
});

test('an unknown OTHALA_ name names itself and the known set, never the value', () => {
  const [error, ...rest] = envNameErrors({ OTHALA_INSTANCE: 'Value That Must Not Leak' });
  assert.deepEqual(rest, []);
  assert.equal(error, `OTHALA_INSTANCE is not an othala setting: delete it (othala reads ${KNOWN_OTHALA_NAMES.join(', ')})`);
});

const documented = new Set(
  readFileSync(fileURLToPath(new URL('../../.env.example', import.meta.url)), 'utf8')
    .split('\n')
    .map((l) => /^(?:# )?([A-Z<][A-Z0-9_<>]*)=/.exec(l)?.[1])
    .filter(Boolean),
);

test('.env.example documents every known setting, every required secret and every bind, and no retired or unknown OTHALA_ name', () => {
  const binds = ['KRATOS_ADMIN_BIND_HOST', 'HYDRA_ADMIN_BIND_HOST', 'PORTAL_ADMIN_BIND_HOST'];
  for (const name of [...KNOWN_OTHALA_NAMES, ...SECRETS, ...binds]) assert.ok(documented.has(name), `${name} undocumented`);
  for (const name of documented) {
    assert.ok(!Object.hasOwn(RETIRED_NAMES, name), `${name} is retired`);
    if (name.startsWith('OTHALA_')) assert.ok(KNOWN_OTHALA_NAMES.includes(name), `${name} unknown`);
  }
});

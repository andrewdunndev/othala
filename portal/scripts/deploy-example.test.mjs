// deploy/example is the shipped deployment e2e runs; these pin what e2e cannot see from inside it.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { check } from '../src/lib/render.ts';

const root = fileURLToPath(new URL('../../', import.meta.url));
const example = join(root, 'deploy/example');
const readYaml = (path) => parse(readFileSync(path, 'utf8'), { logLevel: 'error' });
const compose = readYaml(join(example, 'compose.yml'));
const env = Object.fromEntries(
  readFileSync(join(example, 'othala.env.example'), 'utf8')
    .split('\n')
    .filter((l) => /^[A-Z_][A-Z0-9_]*=/.test(l))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);

test('the example values and content pass check', () => {
  assert.deepEqual(check(root, join(example, 'content'), env), []);
});

test('each bind host is its service address on the internal network, and every pin to it agrees', () => {
  const binds = { kratos: 'KRATOS_ADMIN_BIND_HOST', hydra: 'HYDRA_ADMIN_BIND_HOST', othala: 'PORTAL_ADMIN_BIND_HOST' };
  for (const [svc, name] of Object.entries(binds)) {
    assert.equal(compose.services[svc].networks.internal.ipv4_address, env[name], svc);
  }
  for (const [svc, { extra_hosts = [] }] of Object.entries(compose.services)) {
    for (const pin of extra_hosts) {
      const [host, addr] = pin.split(':');
      assert.equal(addr, env[binds[host]], `${svc} pins ${host}`);
    }
  }
});

test('the e2e overlay re-pins no image the example pins', () => {
  const pinned = new Set(Object.values(compose.services).map((s) => s.image.split(/[:@]/)[0]));
  const overlay = readYaml(join(root, 'e2e/compose.e2e.yml'));
  for (const [svc, { image }] of Object.entries(overlay.services)) {
    if (image && !image.startsWith('${AUTH_REGISTRY}')) assert.ok(!pinned.has(image.split(/[:@]/)[0]), svc);
  }
});

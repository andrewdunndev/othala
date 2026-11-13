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

// A release commit bumps portal/package.json, renames the changelog's [Unreleased] heading to the version and
// moves the example's image tag, all together. Between releases all three still name the last release, with
// an [Unreleased] heading above it. So the rule holds on every commit: the example tag is the declared version.
const releaseHeading = /^## \[(\d+\.\d+\.\d+)\]/m;
const declaredVersion = (pkgText, changelogText) => {
  const pkg = JSON.parse(pkgText).version;
  const heading = changelogText.match(releaseHeading)?.[1];
  assert.equal(pkg, heading, 'package.json version is the newest changelog release heading');
  return pkg;
};
// A release tag names the tree it was cut from.
const tagNamesTree = (tag, version) => tag === undefined || tag === '' || tag === `v${version}`;
const exampleTag = (image) => image.split('@')[0].split(':').pop();

test('render and portal run one othala image', () => {
  const { render, othala } = compose.services;
  assert.equal(render.image, othala.image);
});

test('the example image tag is the version the tree declares', () => {
  const version = declaredVersion(
    readFileSync(join(root, 'portal/package.json'), 'utf8'),
    readFileSync(join(root, 'CHANGELOG.md'), 'utf8'),
  );
  assert.equal(exampleTag(compose.services.othala.image), `v${version}`);
  assert.ok(tagNamesTree(process.env.CI_COMMIT_TAG, version), `tag ${process.env.CI_COMMIT_TAG} is not v${version}`);
});

test('the version rule reads a released tree and an unreleased tree the same way', () => {
  const pkg = (version) => JSON.stringify({ version });
  const released = '# Changelog\n\n## [0.19.0] - 2026-12-01\n\n## [0.18.0] - 2026-11-11\n';
  const unreleased = '# Changelog\n\n## [Unreleased]\n\n### Added\n\n## [0.18.0] - 2026-11-11\n';
  assert.equal(declaredVersion(pkg('0.19.0'), released), '0.19.0');
  assert.equal(declaredVersion(pkg('0.18.0'), unreleased), '0.18.0');
  // a release commit that moved package.json and the heading but not the compose pin
  assert.notEqual(exampleTag('registry.example/othala:v0.18.0@sha256:abc'), `v${declaredVersion(pkg('0.19.0'), released)}`);
  // a tag pipeline: the tag must be the declared version; no tag means no claim
  assert.ok(tagNamesTree('v0.19.0', '0.19.0'));
  assert.ok(tagNamesTree(undefined, '0.19.0'));
  assert.ok(!tagNamesTree('v0.18.0', '0.19.0'));
  assert.ok(!tagNamesTree('0.19.0', '0.19.0'));
  // package.json bumped ahead of the changelog, or the changelog ahead of package.json
  assert.throws(() => declaredVersion(pkg('0.19.0'), unreleased));
  assert.throws(() => declaredVersion(pkg('0.18.0'), released));
});

test('the e2e overlay runs the example Ory flags, adding only the Kratos config layer', () => {
  const overlay = readYaml(join(root, 'e2e/compose.e2e.yml'));
  assert.equal(overlay.services.hydra.command, undefined);
  const added = overlay.services.kratos.command;
  const stripped = added.filter((arg, i) => arg !== '/etc/config/kratos.e2e.yml' && added[i + 1] !== '/etc/config/kratos.e2e.yml');
  assert.deepEqual(stripped, compose.services.kratos.command);
});

test('every service reading an owner-only rendered tree runs as the render uid', () => {
  const ownerOnly = new Set(['othala-kratos', 'othala-hydra']);
  const readers = Object.entries(compose.services).filter(([name, s]) =>
    name !== 'render' && (s.volumes ?? []).some((v) => ownerOnly.has(typeof v === 'string' ? v.split(':')[0] : v.source)),
  );
  assert.ok(readers.length >= 4);
  for (const [name, s] of readers) assert.equal(s.user, compose.services.render.user, `${name} cannot read 0600 files`);
});

test('startup order: render gates everything, Caddy waits only for render, the portal waits for healthy Ory', () => {
  const after = (svc) => Object.fromEntries(Object.entries(compose.services[svc].depends_on ?? {}).map(([k, v]) => [k, v.condition]));
  const done = 'service_completed_successfully';
  assert.deepEqual(after('caddy'), { render: done });
  assert.deepEqual(after('kratos-migrate'), { render: done, postgres: 'service_healthy' });
  assert.deepEqual(after('hydra-migrate'), { render: done, postgres: 'service_healthy' });
  assert.deepEqual(after('kratos'), { 'kratos-migrate': done });
  assert.deepEqual(after('hydra'), { 'hydra-migrate': done });
  assert.deepEqual(after('othala'), { kratos: 'service_healthy', hydra: 'service_healthy' });
});

test('Kratos and Hydra take no environment, so nothing overrides the rendered files unseen by check', () => {
  for (const svc of ['kratos', 'hydra', 'kratos-migrate', 'hydra-migrate']) {
    assert.ok(!('environment' in compose.services[svc]), `${svc} environment`);
    assert.ok(!('env_file' in compose.services[svc]), `${svc} env_file`);
  }
});

test('every service drops all capabilities', () => {
  for (const [name, s] of Object.entries(compose.services)) assert.deepEqual(s.cap_drop, ['ALL'], name);
});

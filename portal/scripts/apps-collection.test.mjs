// Cross-invariant tests for the apps Content Collection.
//
// Run with: node --test scripts/apps-collection.test.mjs
//
// The zod schema in src/content.config.ts already enforces the
// frontmatter shape at build time (validated by `astro check`):
// required fields, access_group regex, url() format, icon length,
// auth_kind enum, order int, disabled boolean. Filesystem
// constraints handle slug uniqueness (slugs ARE filenames) and
// non-empty directory.
//
// What zod + the filesystem can't enforce — and therefore what this
// suite covers — is the two cross-cuts:
//
//   1. access_group matches `access-<slug>` where <slug> is the
//      filename minus .md. Zod sees the regex on the field; it has
//      no view of the filename.
//
//   2. Every OIDC consumer in the apps registry has a matching
//      hydra/clients/<slug>.yaml. This is a cross-repo invariant
//      (registry lives in portal/, manifests in hydra/) that lies
//      outside any single zod schema.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const appsDir = join(here, '..', 'src', 'content', 'apps');

function readAllApps() {
  const files = readdirSync(appsDir).filter((f) => f.endsWith('.md')).sort();
  return files.map((f) => {
    const path = join(appsDir, f);
    const content = readFileSync(path, 'utf8');
    // Strip the frontmatter block bounded by --- markers.
    const m = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (!m) throw new Error(`${f}: no frontmatter block`);
    const frontmatter = parseYaml(m[1]);
    return {
      file: f,
      slug: f.replace(/\.md$/, ''),
      data: frontmatter,
    };
  });
}

test('apps collection: access_group matches access-<slug> convention', () => {
  const apps = readAllApps();
  for (const app of apps) {
    const expected = `access-${app.slug}`;
    assert.equal(
      app.data.access_group,
      expected,
      `${app.file}: access_group mismatch — file slug is "${app.slug}", access_group is "${app.data.access_group}" (expected "${expected}")`,
    );
  }
});

test('apps collection: every OIDC consumer has a corresponding hydra/clients yaml', () => {
  // The MD apps registry is canonical for "what apps exist." OIDC
  // consumers (auth_kind = oidc or oidc+ldap) must ALSO have a
  // hydra/clients/<slug>.yaml. Forward-auth apps have no yaml.
  const apps = readAllApps();
  const clientsDir = join(here, '..', '..', 'hydra', 'clients');
  let clientYamls = [];
  try {
    clientYamls = readdirSync(clientsDir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  } catch {
    // hydra/clients/ not in this checkout — skip
    return;
  }
  const clientSlugs = new Set(clientYamls.map((f) => f.replace(/\.ya?ml$/, '')));
  for (const app of apps) {
    const kind = app.data.auth_kind ?? 'oidc';
    if (kind === 'oidc' || kind === 'oidc+ldap') {
      assert.ok(
        clientSlugs.has(app.slug),
        `${app.file}: auth_kind="${kind}" but no hydra/clients/${app.slug}.yaml found`,
      );
    }
  }
});

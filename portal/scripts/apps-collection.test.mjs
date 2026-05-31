// Tests for the apps Content Collection frontmatter shape.
//
// Run with: node --test scripts/apps-collection.test.mjs
//
// We can't import the Astro Content Collection directly (depends on
// astro:content runtime). Instead, this test:
//
//   1. Walks src/content/apps/*.md
//   2. Parses YAML frontmatter
//   3. Asserts each entry has the required fields with the expected
//      shapes — matching the zod schema in src/content.config.ts
//
// Coverage focus (matches LB-9 in ARCHITECTURE.md):
//   - Every MD has the required frontmatter fields.
//   - access_group matches the access-<slug> convention where slug
//     is the filename minus .md.
//   - auth_kind is one of the allowed enums.
//   - icon length 1-3 chars.
//   - url is a fully-qualified URL.
//   - order is an integer.
//   - disabled is a boolean.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const appsDir = join(here, '..', 'src', 'content', 'apps');

const ALLOWED_AUTH_KINDS = ['oidc', 'forward_auth', 'ldap', 'oidc+ldap'];
const ACCESS_GROUP_RE = /^access-[a-z][a-z0-9-]*$/;
const URL_RE = /^https?:\/\/[^\s]+$/;
const ICON_RE = /^.{1,3}$/;

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

test('apps collection: directory is non-empty', () => {
  const apps = readAllApps();
  assert.ok(apps.length > 0, 'no apps found in src/content/apps/');
});

test('apps collection: every app has all required frontmatter fields', () => {
  const required = ['name', 'description', 'url', 'icon', 'access_group'];
  const apps = readAllApps();
  for (const app of apps) {
    for (const field of required) {
      assert.ok(
        app.data[field] !== undefined && app.data[field] !== null && app.data[field] !== '',
        `${app.file}: missing required field "${field}"`,
      );
    }
  }
});

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

test('apps collection: access_group regex (defense against typos)', () => {
  const apps = readAllApps();
  for (const app of apps) {
    assert.match(app.data.access_group, ACCESS_GROUP_RE, `${app.file}: access_group fails regex`);
  }
});

test('apps collection: url is fully-qualified', () => {
  const apps = readAllApps();
  for (const app of apps) {
    assert.match(app.data.url, URL_RE, `${app.file}: url not a fully-qualified https URL`);
  }
});

test('apps collection: icon is 1-3 chars', () => {
  const apps = readAllApps();
  for (const app of apps) {
    assert.match(String(app.data.icon), ICON_RE, `${app.file}: icon "${app.data.icon}" exceeds 3 chars`);
  }
});

test('apps collection: auth_kind is one of the allowed enums', () => {
  const apps = readAllApps();
  for (const app of apps) {
    const kind = app.data.auth_kind ?? 'oidc';
    assert.ok(
      ALLOWED_AUTH_KINDS.includes(kind),
      `${app.file}: auth_kind "${kind}" not in ${ALLOWED_AUTH_KINDS.join(', ')}`,
    );
  }
});

test('apps collection: order is an integer when present', () => {
  const apps = readAllApps();
  for (const app of apps) {
    if (app.data.order !== undefined) {
      assert.ok(
        Number.isInteger(app.data.order),
        `${app.file}: order "${app.data.order}" is not an integer`,
      );
    }
  }
});

test('apps collection: disabled is boolean when present', () => {
  const apps = readAllApps();
  for (const app of apps) {
    if (app.data.disabled !== undefined) {
      assert.equal(
        typeof app.data.disabled,
        'boolean',
        `${app.file}: disabled "${app.data.disabled}" is not a boolean`,
      );
    }
  }
});

test('apps collection: no duplicate slugs', () => {
  const apps = readAllApps();
  const slugs = apps.map((a) => a.slug);
  const seen = new Set();
  for (const s of slugs) {
    assert.ok(!seen.has(s), `duplicate slug: ${s}`);
    seen.add(s);
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

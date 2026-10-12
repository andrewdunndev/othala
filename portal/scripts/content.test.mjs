// Invariant: the content check passes the shipped example tree and refuses every entry outside the layout, an orphan
// or rejected sidecar, a bad groups.yaml, an unknown courier name and an invalid manifest, each naming the file and fix.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { clientSecretNames, contentErrors } from '../src/lib/content.ts';

const example = fileURLToPath(new URL('../../e2e/content', import.meta.url));
const COURIER = ['login_code.subject.gotmpl', 'recovery_code.subject.gotmpl'];
const APP = (id) =>
  `presentation:\n  name: ${id}\n  url: https://${id}.example.org\n  access: [family]\n` +
  `oidc:\n  client_id: ${id}\n  redirect_uris: [https://${id}.example.org/cb]\n  audience: [https://${id}.example.org]\n`;

function errorsFor(files, dirs = []) {
  const root = mkdtempSync(join(tmpdir(), 'othala-content-check-'));
  try {
    mkdirSync(join(root, 'apps'));
    for (const d of dirs) mkdirSync(join(root, d), { recursive: true });
    for (const [path, body] of Object.entries(files)) {
      mkdirSync(join(root, path, '..'), { recursive: true });
      writeFileSync(join(root, path), body);
    }
    return contentErrors(root, COURIER);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('the shipped example tree checks clean, and its confidential clients need secrets', () => {
  assert.deepEqual(contentErrors(example, COURIER), []);
  assert.deepEqual(clientSecretNames(example), ['AUDIOBOOKSHELF_CLIENT_SECRET', 'GRAFANA_CLIENT_SECRET', 'PROMPTDESK_CLIENT_SECRET']);
});

test('a full good tree checks clean, dot-entries skipped', () => {
  assert.deepEqual(
    errorsFor(
      {
        'groups.yaml': 'media:\n  title: Media\n  order: 1\n',
        'apps/wiki.yaml': APP('wiki'),
        'apps/wiki.md': '# Wiki\n',
        'apps/wiki.svg': '<svg xmlns="http://www.w3.org/2000/svg"/>',
        'apps/NOTICE': 'logos\n',
        'apps/requirements/vpn.md': '---\ntitle: VPN\n---\n',
        'courier/login_code.subject.gotmpl': 'x',
        '..data/anything': '',
        'apps/.gitkeep': '',
      },
      ['..2026_10_12'],
    ),
    [],
  );
});

test('the old flat layout is refused with the move that fixes it', () => {
  assert.deepEqual(errorsFor({ 'wiki.yaml': APP('wiki'), 'wiki.svg': '<svg/>', 'requirements/vpn.md': '', NOTICE: '' }), [
    'NOTICE: app content lives under apps/; move it to apps/NOTICE',
    'requirements: app content lives under apps/; move it to apps/requirements',
    'wiki.svg: app content lives under apps/; move it to apps/wiki.svg',
    'wiki.yaml: app content lives under apps/; move it to apps/wiki.yaml',
  ]);
  assert.deepEqual(errorsFor({ 'apps/groups.yaml': 'a: {}\n' }), ['apps/groups.yaml: groups.yaml lives at the content root; move it up one level']);
});

test('an unknown entry at the root or under apps/ is refused', () => {
  assert.deepEqual(errorsFor({ 'stray.txt': '' }), ['stray.txt: not part of the content layout (apps/, groups.yaml, courier/); delete it']);
  assert.deepEqual(errorsFor({ 'apps/notes.txt': '' }), [
    'apps/notes.txt: not part of the apps layout (<stem>.yaml, <stem>.md, <stem>.svg, requirements/, NOTICE); delete it',
  ]);
  assert.deepEqual(errorsFor({}, ['icons']), ['icons: not part of the content layout (apps/, groups.yaml, courier/); delete it']);
});

test('a missing tree or apps/ is refused', () => {
  assert.deepEqual(contentErrors('/nonexistent/othala', COURIER), ['/nonexistent/othala: content directory not found']);
  const root = mkdtempSync(join(tmpdir(), 'othala-content-noapps-'));
  try {
    assert.deepEqual(contentErrors(root, COURIER), ['apps: missing; the manifests live in apps/ under the content root']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a sidecar without a manifest, or a logo that is not an SVG, is refused', () => {
  assert.deepEqual(errorsFor({ 'apps/wiki.md': '', 'apps/wikki.svg': '<svg/>', 'apps/wiki.yaml': APP('wiki') }), [
    'apps/wikki.svg: no apps/wikki.yaml for this sidecar; rename it to match a manifest or delete it',
  ]);
  assert.deepEqual(errorsFor({ 'apps/wiki.yaml': APP('wiki'), 'apps/wiki.svg': '<html></html>' }), [
    'apps/wiki.svg does not open with an <svg> root',
  ]);
});

test('requirements are <name>.md slugs', () => {
  assert.deepEqual(errorsFor({ 'apps/requirements/Bad_Name.md': '', 'apps/requirements/vpn.txt': '' }), [
    'apps/requirements/Bad_Name.md: a requirement is <name>.md with a name matching /^[a-z][a-z0-9-]{0,39}$/',
    'apps/requirements/vpn.txt: a requirement is <name>.md with a name matching /^[a-z][a-z0-9-]{0,39}$/',
  ]);
});

test('groups.yaml must parse to a mapping of mappings', () => {
  assert.match(errorsFor({ 'groups.yaml': 'a: [unclosed\n' })[0], /^groups\.yaml: does not parse: /);
  assert.deepEqual(errorsFor({ 'groups.yaml': '- a\n' }), ['groups.yaml: must be a mapping of group name to { title, description, order }']);
  assert.deepEqual(errorsFor({ 'groups.yaml': 'media: Media\n' }), ['groups.yaml: media must be a mapping of title, description and order']);
});

test('a courier override must reuse a shipped name', () => {
  const fix = `an override is one of ${COURIER.join(', ')}`;
  assert.deepEqual(errorsFor({ 'courier/login.gotmpl': '', 'courier/login_code.subject.gotmpl': '' }), [
    `courier/login.gotmpl: no shipped template has this name; ${fix}`,
  ]);
  assert.deepEqual(errorsFor({}, ['courier/login_code.subject.gotmpl']), [`courier/login_code.subject.gotmpl: no shipped template has this name; ${fix}`]);
  assert.deepEqual(errorsFor({ courier: '' }), ['courier: must be a directory of <name>.gotmpl overrides']);
});

test('an invalid, unparseable, duplicated or retired-field manifest is refused', () => {
  assert.match(errorsFor({ 'apps/bad.yaml': ': x: [' })[0], /^apps\/bad\.yaml: does not parse: /);
  assert.ok(errorsFor({ 'apps/bad.yaml': APP('Bad') }).some((e) => e.startsWith('apps/bad.yaml: oidc.client_id "Bad" must match')));
  assert.deepEqual(errorsFor({ 'apps/a.yaml': APP('wiki'), 'apps/b.yaml': APP('wiki') }), [
    'apps/: client_id "wiki" is shared by a.yaml, b.yaml; give each its own',
  ]);
  assert.deepEqual(errorsFor({ 'apps/wiki.yaml': `${APP('wiki')}`.replace('  access: [family]\n', '  access: [family]\n  icon_slug: wiki\n') }), [
    'apps/wiki.yaml: presentation.icon_slug and icon_fallback are retired: drop the logo beside the manifest as <stem>.svg',
  ]);
});

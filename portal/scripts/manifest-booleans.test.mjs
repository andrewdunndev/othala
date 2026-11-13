// Invariant: a gate flag in a manifest is a real boolean or the file is rejected; a loose string never opens an app.

import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseManifest, loadClientManifests, invalidateManifestCache, setContentDir, droppedManifests } from '../src/lib/manifests.ts';
import { lintApps } from '../src/lib/content.ts';

const manifestWith = (where, key, value) => {
  const oidc = { client_id: 'wiki', scope: 'openid', audience: ['https://wiki.example.com'], redirect_uris: ['https://wiki.example.com/cb'] };
  const consent = {};
  if (where === 'oidc') oidc[key] = value;
  else consent[key] = value;
  const lines = (o) => Object.entries(o).map(([k, v]) => `  ${k}: ${JSON.stringify(v)}`).join('\n');
  return `oidc:\n${lines(oidc)}\npresentation:\n  access:\n    - wiki\nconsent:\n${lines(consent) || '  {}'}\n`.replace('consent:\n  {}', 'consent: {}');
};

const FLAGS = [
  ['consent', 'skip_access_check'],
  ['oidc', 'skip_consent'],
  ['oidc', 'backchannel_logout_session_required'],
  ['consent', 'emit_groups_claim'],
];

for (const [where, key] of FLAGS) {
  for (const bad of ['no', 'false', 'yes', 0, 1, null, [], {}]) {
    test(`${key}: ${JSON.stringify(bad)} is a manifest error`, () => {
      assert.throws(() => parseManifest(manifestWith(where, key, bad), 'wiki.yaml'), new RegExp(key));
    });
  }
  for (const good of [true, false]) {
    test(`${key}: ${good} parses`, () => {
      assert.doesNotThrow(() => parseManifest(manifestWith(where, key, good), 'wiki.yaml'));
    });
  }
}

test('an unquoted YAML 1.1 no is rejected, not read as skip', () => {
  const text = 'oidc:\n  client_id: wiki\n  scope: openid\npresentation:\n  access: [wiki]\nconsent:\n  skip_access_check: no\n';
  assert.throws(() => parseManifest(text, 'wiki.yaml'), /skip_access_check/);
});

test('presentation-only manifest: a non-boolean skip_access_check is rejected too', () => {
  const text = 'presentation:\n  name: Wiki\nconsent:\n  skip_access_check: "no"\n';
  assert.throws(() => parseManifest(text, 'wiki.yaml'), /skip_access_check/);
});

test('absent flags keep their defaults', () => {
  const m = parseManifest('oidc:\n  client_id: wiki\n  scope: openid\npresentation:\n  access: [wiki]\n', 'wiki.yaml');
  assert.equal(m.skipAccessCheck, false);
  assert.equal(m.skipConsent, false);
  assert.equal(m.backchannelLogoutSessionRequired, false);
  assert.equal(m.emitGroupsClaim, null);
});

test('the loader quarantines the file and manifest-lint reports it', () => {
  const root = mkdtempSync(join(tmpdir(), 'manifest-bool-'));
  const dir = join(root, 'apps');
  mkdirSync(dir);
  try {
    writeFileSync(join(dir, 'wiki.yaml'), manifestWith('consent', 'skip_access_check', 'no'));
    setContentDir(root);
    invalidateManifestCache();
    assert.deepEqual(loadClientManifests(), []);
    assert.equal(droppedManifests().length, 1);
    assert.match(droppedManifests()[0].reason, /skip_access_check/);
    const { errors } = lintApps(dir);
    assert.ok(errors.some((e) => /wiki\.yaml/.test(e) && /skip_access_check/.test(e)), errors.join('\n'));
  } finally {
    setContentDir(undefined);
    invalidateManifestCache();
    rmSync(root, { recursive: true, force: true });
  }
});

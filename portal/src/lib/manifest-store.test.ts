// Invariant: one bad manifest must not take the portal down.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { invalidateManifestCache, setManifestDir } from './manifests.js';
import {
  servingManifests,
  servingManifest,
  manifestHealth,
  _resetForTests,
} from './manifest-store.js';

const VALID_APP = `
oidc:
  client_id: proxywatch
  client_name: Proxywatch
  redirect_uris:
    - https://proxywatch.example.test/login/generic_oauth
  audience:
    - https://proxywatch.example.test
  scope: openid profile email groups
presentation:
  name: Proxywatch
  url: https://proxywatch.example.test
  access:
    - proxywatch-access
consent:
  roles:
    - name: viewer
      description: Read-only
      claim_emit:
        role: Viewer
  group_role_map:
    proxywatch-access: viewer
`;

const BROKEN_APP = VALID_APP.replace('proxywatch-access: viewer', 'proxywatch-access: editor');

const TILE_ONLY = `
presentation:
  name: Audiobookshelf
  url: https://audiobookshelf.example.test
  auth_kind: forward_auth
  access:
    - audiobookshelf-access
`;

let dir: string;
let logged: string[];

function write(name: string, body: string): void {
  writeFileSync(join(dir, name), body, 'utf8');
  invalidateManifestCache();
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'othala-manifest-store-'));
  setManifestDir(dir);
  invalidateManifestCache();
  _resetForTests();
  logged = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    logged.push(args.map(String).join(' '));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  setManifestDir(undefined);
  rmSync(dir, { recursive: true, force: true });
});

describe('servingManifests — healthy set', () => {
  it('loads the set and reports ok', () => {
    write('proxywatch.yaml', VALID_APP);

    const set = servingManifests();
    expect(set.map((m) => m.clientId)).toEqual(['proxywatch']);
    expect(manifestHealth().status).toBe('ok');
    expect(manifestHealth().error).toBeNull();
  });
});

describe('servingManifests — an invalid manifest', () => {
  it('is dropped while its valid sibling keeps serving, and health stays ok', () => {
    write('proxywatch.yaml', BROKEN_APP);
    write('other.yaml', VALID_APP.replaceAll('proxywatch', 'other'));

    expect(servingManifests().map((m) => m.clientId)).toEqual(['other']);
    expect(manifestHealth().status).toBe('ok');
  });

  it('resolves no client, so the gate denies rather than the page 500-ing', () => {
    write('proxywatch.yaml', BROKEN_APP);

    expect(servingManifest('proxywatch')).toBeUndefined();
  });
});

describe('servingManifests — the directory itself fails to load', () => {
  function breakDir(): void {
    const file = join(dir, 'not-a-dir');
    writeFileSync(file, '');
    setManifestDir(file);
    invalidateManifestCache();
  }

  it('keeps serving the last known good set, reports stale, names the cause, and recovers', () => {
    write('proxywatch.yaml', VALID_APP);
    expect(servingManifests()).toHaveLength(1);

    breakDir();
    expect(servingManifests().map((m) => m.clientId)).toEqual(['proxywatch']);
    const health = manifestHealth();
    expect(health.status).toBe('stale');
    expect(health.serving).toBe(1);
    expect(health.error).toContain('ENOTDIR');
    expect(logged.some((line) => line.includes('[portal:manifests] STALE'))).toBe(true);

    setManifestDir(dir);
    invalidateManifestCache();
    expect(servingManifests()).toHaveLength(1);
    expect(manifestHealth().status).toBe('ok');
    expect(logged.some((line) => line.includes('[portal:manifests] RECOVERED'))).toBe(true);
  });

  it('serves the empty set and reports unavailable on a cold start', () => {
    breakDir();

    expect(servingManifests()).toEqual([]);
    expect(manifestHealth().status).toBe('unavailable');
    expect(logged.some((line) => line.includes('[portal:manifests] UNAVAILABLE'))).toBe(true);
  });
});

describe('servingManifest — lookup rules match the strict loader', () => {
  it('is case-insensitive', () => {
    write('proxywatch.yaml', VALID_APP);
    expect(servingManifest('PROXYWATCH')?.clientId).toBe('proxywatch');
  });

  it('refuses presentation-only manifests', () => {
    write('audiobookshelf.yaml', TILE_ONLY);
    expect(servingManifests().map((m) => m.clientId)).toContain('audiobookshelf');
    expect(servingManifest('audiobookshelf')).toBeUndefined();
  });
});

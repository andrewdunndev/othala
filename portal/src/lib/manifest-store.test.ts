/**
 * manifest-store.test.ts — the B5 invariant: one bad manifest must not take the
 * portal down.
 *
 * These run against a REAL temp MANIFEST_DIR and the real loader, not a mock,
 * because the bug being guarded lives in the interaction between
 * loadClientManifests()'s pre-swap validation and its mtime-keyed cache — a
 * mocked loader would prove nothing about it.
 *
 * The break used here is an undeclared role in `group_role_map`, which is the
 * exact shape of the live risk that motivated the fix (a catalog change that
 * rewrote eight role maps at once). It is a SEMANTIC error, so unlike a YAML
 * syntax error it is set-wide and fatal in the strict loader.
 *
 * Covered:
 *   - a valid set loads and reports healthy;
 *   - breaking the set keeps the previous set being served, does not throw, and
 *     reports `stale` with the cause;
 *   - the failure is LOGGED (a silent stale-serve would be the worst outcome);
 *   - fixing the manifest recovers on the next call, with no restart;
 *   - a cold start onto a broken set serves the EMPTY set and reports
 *     `unavailable` — fail-closed, never a silent grant;
 *   - servingManifest() stays case-insensitive and refuses presentation-only
 *     manifests, matching the strict getClientManifest.
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { invalidateManifestCache } from './manifests.js';
import {
  servingManifests,
  servingManifest,
  servingAccessGroups,
  manifestHealth,
  _resetForTests,
} from './manifest-store.js';

/** A manifest that passes every validateClients rule. */
const VALID_APP = `
oidc:
  client_id: observe
  client_name: Observe
  redirect_uris:
    - https://observe.example.test/login/generic_oauth
  audience:
    - https://observe.example.test
  scope: openid profile email groups
presentation:
  name: Observe
  url: https://observe.example.test
  access:
    - observe-access
consent:
  roles:
    - name: viewer
      description: Read-only
      claim_emit:
        role: Viewer
  group_role_map:
    observe-access: viewer
`;

/**
 * The same manifest with group_role_map pointing at a role that is not
 * declared. validateClients rejects the WHOLE set for this, which is what makes
 * one bad file an estate-wide outage without the store in front of it.
 */
const BROKEN_APP = VALID_APP.replace('observe-access: viewer', 'observe-access: editor');

/** A presentation-only tile: a real access binding, no OIDC client. */
const TILE_ONLY = `
presentation:
  name: Gather
  url: https://gather.example.test
  auth_kind: forward_auth
  access:
    - gather-access
`;

let dir: string;
let logged: string[];

function write(name: string, body: string): void {
  writeFileSync(join(dir, name), body, 'utf8');
  // Both caches are mtime-keyed at second-or-better resolution; two writes
  // inside one tick can land on the same mtime. Invalidate explicitly so each
  // step of a test definitely re-reads from disk.
  invalidateManifestCache();
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'othala-manifest-store-'));
  process.env['MANIFEST_DIR'] = dir;
  invalidateManifestCache();
  _resetForTests();
  logged = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    logged.push(args.map(String).join(' '));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env['MANIFEST_DIR'];
  rmSync(dir, { recursive: true, force: true });
});

describe('servingManifests — healthy set', () => {
  it('loads the set and reports ok', () => {
    write('observe.yaml', VALID_APP);

    const set = servingManifests();
    expect(set.map((m) => m.clientId)).toEqual(['observe']);
    expect(manifestHealth().status).toBe('ok');
    expect(manifestHealth().error).toBeNull();
  });
});

describe('servingManifests — a manifest breaks under it', () => {
  it('keeps serving the last known good set instead of throwing', () => {
    write('observe.yaml', VALID_APP);
    const good = servingManifests();
    expect(good).toHaveLength(1);

    write('observe.yaml', BROKEN_APP);

    expect(() => servingManifests()).not.toThrow();
    const served = servingManifests();
    expect(served.map((m) => m.clientId)).toEqual(['observe']);
    // The role map that is actually served is the LAST GOOD one, not the
    // broken one now on disk.
    expect(served[0]?.groupRoleMap).toEqual({ 'observe-access': 'viewer' });
  });

  it('reports stale, names the cause, and logs it', () => {
    write('observe.yaml', VALID_APP);
    servingManifests();

    write('observe.yaml', BROKEN_APP);
    servingManifests();

    const health = manifestHealth();
    expect(health.status).toBe('stale');
    expect(health.serving).toBe(1);
    expect(health.error).toContain('editor');
    expect(health.failingSinceMs).not.toBeNull();

    // Loudly, on stderr, where journald picks it up. A silent fallback would
    // leave an operator reading a stale catalog as the live one.
    expect(logged.some((line) => line.includes('[portal:manifests] STALE'))).toBe(true);
  });

  it('recovers on the next call once the manifest is fixed — no restart', () => {
    write('observe.yaml', VALID_APP);
    servingManifests();
    write('observe.yaml', BROKEN_APP);
    servingManifests();
    expect(manifestHealth().status).toBe('stale');

    // A different, still-valid set: the role is renamed in BOTH the declaration
    // and the map, so this one validates.
    write('observe.yaml', VALID_APP.replaceAll('viewer', 'reader'));

    const set = servingManifests();
    expect(set[0]?.groupRoleMap).toEqual({ 'observe-access': 'reader' });
    expect(manifestHealth().status).toBe('ok');
    expect(logged.some((line) => line.includes('[portal:manifests] RECOVERED'))).toBe(true);
  });
});

describe('servingManifests — cold start onto a broken set', () => {
  it('serves the empty set and reports unavailable', () => {
    write('observe.yaml', BROKEN_APP);

    expect(servingManifests()).toEqual([]);

    const health = manifestHealth();
    expect(health.status).toBe('unavailable');
    expect(health.serving).toBe(0);
    expect(logged.some((line) => line.includes('[portal:manifests] UNAVAILABLE'))).toBe(true);
  });

  it('resolves no client, so the gate denies rather than the page 500-ing', () => {
    write('observe.yaml', BROKEN_APP);

    expect(servingManifest('observe')).toBeUndefined();
    expect(servingAccessGroups()).toEqual([]);
  });
});

describe('servingManifest — lookup rules match the strict loader', () => {
  it('is case-insensitive', () => {
    write('observe.yaml', VALID_APP);
    expect(servingManifest('OBSERVE')?.clientId).toBe('observe');
  });

  it('refuses presentation-only manifests', () => {
    write('gather.yaml', TILE_ONLY);
    // The tile is in the catalog…
    expect(servingManifests().map((m) => m.clientId)).toContain('gather');
    // …but it registers no Hydra client, so no OAuth2 request may resolve it.
    expect(servingManifest('gather')).toBeUndefined();
  });
});

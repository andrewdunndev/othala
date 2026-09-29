/**
 * group-registry.test.ts — a group's TYPE comes from its BINDING, never its name.
 *
 * group-registry.ts answers the one question the whole access model rests on:
 * "what kind of group is this?". /auth/settings, admin/groups and both admin
 * user surfaces render off its answer, and the manifest lint checks references
 * against it. It had no test of any kind. Three things it must get right:
 *
 *   BINDING BEATS NAME. A group used to be typed by matching `access-*`, which
 *     overloaded a naming convention as a runtime discriminator. That inference
 *     is retired (see the group-registry.ts header). The tests below feed the
 *     builder groups whose NAME says one thing and whose BINDING says another,
 *     in BOTH directions, and assert the binding wins every time.
 *
 *   EVERY auth_kind COUNTS (B4). The loader used to drop presentation-only
 *     manifests, so every forward_auth / external tile's access group was
 *     invisible to the registry. Invisible meant no checkbox in the
 *     identity-edit form, and admin/users/[id].astro rewrites
 *     metadata_admin.groups wholesale from the rendered boxes — so every save
 *     silently DROPPED those groups. The completeness assertions here are
 *     written against a HARDCODED expected set, never against a loop over the
 *     manifests that were actually loaded: such a loop passes vacuously when a
 *     whole class of manifest disappears upstream, which is exactly how B4 hid.
 *
 *   ENTRY IS EXPLICIT. The converged model: entry comes from holding
 *     `<svc>-access`, for everyone including admins; role comes from
 *     additionally holding `<svc>-admin`. Nothing is derived from anything
 *     else. So `<svc>-admin` appears ONLY as a group_role_map key, and the
 *     registry must type it `role` and NOT `access` — an identity holding only
 *     `<svc>-admin` has no entry binding for the gate to satisfy. If a future
 *     edit re-derives access from an admin binding, the fixtures below (which
 *     mirror the live catalog shape) go red.
 *
 * Fixtures are real manifest YAML driven through the real parser and the real
 * on-disk loader, not hand-built objects, because the invariant lives in the
 * seam between the loader and the registry — that seam is where B4 lived.
 *
 * Run: npx vitest run src/lib/group-registry.test.ts   (from portal/)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// config.ts reads OTHALA_IDENTITY_GROUPS ONCE, at module load, into an exported
// const — so it has to be set before the import graph below is evaluated.
// vi.hoisted runs above the imports; a beforeEach would be far too late.
vi.hoisted(() => {
  process.env['OTHALA_IDENTITY_GROUPS'] = 'admin,housemates';
});

import {
  parseManifest,
  loadClientManifests,
  invalidateManifestCache,
  knownAccessGroups,
  type ClientManifest,
} from './manifests.js';
import {
  buildGroupRegistry,
  getGroupRegistry,
  isAccessGroup,
  isIdentityGroup,
  knownGroupNames,
  namesOfKind,
  type GroupRegistry,
} from './group-registry.js';

// ── fixtures ────────────────────────────────────────────────────────────────
//
// House shape: `presentation.access:` names ONLY `<svc>-access`;
// `<svc>-admin` exists solely as a group_role_map key.

/** auth_kind: oidc — a real Hydra client, admin role mapped separately. */
const GRAFANA = `
presentation:
  name: Grafana
  url: https://grafana.example.test
  auth_kind: oidc
  access:
    - grafana-access
oidc:
  client_id: grafana
  client_name: Grafana
  redirect_uris:
    - https://grafana.example.test/sso/callback
  audience:
    - https://grafana.example.test
  scope: openid profile email groups
consent:
  roles:
    - name: admin
      description: Full administration
      claim_emit:
        role: Administrator
    - name: user
      description: Ordinary member
      claim_emit:
        role: User
  group_role_map:
    grafana-admin: admin
    grafana-access: user
`;

/** auth_kind: oidc, plural binding. */
const PROMPTDESK = `
presentation:
  name: Promptdesk
  url: https://promptdesk.example.test
  auth_kind: oidc
  access:
    - promptdesk-access
oidc:
  client_id: promptdesk
  client_name: Promptdesk
  redirect_uris:
    - https://promptdesk.example.test/oauth/callback
  audience:
    - https://promptdesk.example.test
  scope: openid profile email groups
consent:
  roles:
    - name: admin
      description: Full administration
      claim_emit:
        role: Administrator
    - name: user
      description: Ordinary member
      claim_emit:
        role: User
  group_role_map:
    promptdesk-admin: admin
    promptdesk-access: user
`;

/**
 * auth_kind: forward_auth — presentation-only, and written with the SINGULAR
 * `access_group:` compat shim, which is how most forward_auth tiles are
 * written. The reverse proxy gates this app on the group named here; if the
 * registry cannot see it, the admin UI cannot grant it.
 */
const PROXYWATCH = `
presentation:
  name: Proxywatch
  url: https://proxywatch.example.test
  auth_kind: forward_auth
  access_group: proxywatch-access
`;

/** Two forward_auth tiles sharing ONE access group. */
const FETCHER = `
presentation:
  name: Usenet downloader
  url: https://downloads.example.test/fetcher
  auth_kind: forward_auth
  access_group: downloads-usenet-access
`;

const SERIES = `
presentation:
  name: Series manager
  url: https://downloads.example.test/series
  auth_kind: forward_auth
  access_group: downloads-usenet-access
`;

/** auth_kind: forward_auth — presentation-only, plural binding. */
const FILEDROP = `
presentation:
  name: Filedrop
  url: https://filedrop.example.test
  auth_kind: forward_auth
  access:
    - filedrop-access
`;

/** auth_kind: external — someone else's auth, but still OUR access binding. */
const AUDIOBOOKSHELF = `
presentation:
  name: Audiobookshelf
  url: https://audiobookshelf.example.test
  auth_kind: external
  access:
    - audiobookshelf-access
`;

/**
 * auth_kind: external with NO access binding at all, allowed only because it
 * declares skip_access_check. It must contribute NOTHING to the registry:
 * absence of a binding is absence, and there is no implicit
 * `access-<clientId>` to invent (othala primitive #5).
 */
const STATUSPAGE = `
presentation:
  name: Status
  url: https://status.example.test
  auth_kind: external
consent:
  skip_access_check: true
`;

/**
 * The name-versus-binding fixture, carrying BOTH directions in one manifest:
 *
 *   `photo-club`   — a name with no access-ish shape whatsoever, bound in
 *                    `presentation.access:`. Name-based typing would have
 *                    called it an identity group. It is an ACCESS group.
 *   `access-legacy` — a name that reads exactly like the retired `access-*`
 *                    convention, whose ONLY binding is a role binding.
 *                    Name-based typing would have called it an access group.
 *                    It is a ROLE group, and grants no entry.
 */
const ARCHIVE = `
presentation:
  name: Archive
  url: https://archive.example.test
  auth_kind: oidc
  access:
    - photo-club
oidc:
  client_id: archive
  client_name: Archive
  redirect_uris:
    - https://archive.example.test/callback
  audience:
    - https://archive.example.test
  scope: openid profile email groups
consent:
  roles:
    - name: curator
      description: Curates the collection
      claim_emit:
        role: Curator
  group_role_map:
    access-legacy: curator
`;

/** The whole fixture catalog, by filename — one manifest of every auth_kind. */
const CATALOG: Record<string, string> = {
  'audiobookshelf.yaml': AUDIOBOOKSHELF,
  'fetcher.yaml': FETCHER,
  'filedrop.yaml': FILEDROP,
  'grafana.yaml': GRAFANA,
  'promptdesk.yaml': PROMPTDESK,
  'proxywatch.yaml': PROXYWATCH,
  'series.yaml': SERIES,
  'statuspage.yaml': STATUSPAGE,
};

/**
 * Every access group the catalog binds, sorted, HARDCODED.
 *
 * Deliberately not derived from CATALOG: this list is what makes the
 * completeness tests non-vacuous. Four of the six entries come from manifests
 * that register no OIDC client at all (proxywatch / fetcher+series / filedrop /
 * audiobookshelf — forward_auth, forward_auth, forward_auth, external). If any upstream
 * filter ever drops presentation-only manifests again, this list is what
 * notices. statuspage contributes nothing: it declares no binding.
 */
const EXPECTED_ACCESS = [
  'audiobookshelf-access',
  'downloads-usenet-access',
  'filedrop-access',
  'grafana-access',
  'promptdesk-access',
  'proxywatch-access',
];

/**
 * Every group the catalog binds to a ROLE, sorted, hardcoded.
 * `<svc>-access` appears here as well as above — it is both the entry binding
 * and the key that maps an ordinary member to the `user` role. `<svc>-admin`
 * appears ONLY here, which is the converged model stated as data.
 */
const EXPECTED_ROLE = ['grafana-access', 'grafana-admin', 'promptdesk-access', 'promptdesk-admin'];

// ── helpers ─────────────────────────────────────────────────────────────────

function parse(file: string, body: string): ClientManifest {
  return parseManifest(body, file);
}

function accessFor(reg: GroupRegistry, name: string): string[] {
  return reg.get(name)?.accessFor ?? [];
}

let dir: string;

function write(name: string, body: string): void {
  writeFileSync(join(dir, name), body, 'utf8');
  // The loader's cache is mtime-keyed at second-or-better resolution, so two
  // writes inside one tick can land on the same mtime. Invalidate explicitly
  // so every step of a test definitely re-reads from disk.
  invalidateManifestCache();
}

function writeCatalog(): void {
  for (const [file, body] of Object.entries(CATALOG)) write(file, body);
}

// ═══════════════════════════════════════════════════════════════════════════
// buildGroupRegistry — the pure derivation
// ═══════════════════════════════════════════════════════════════════════════

describe('buildGroupRegistry — type comes from the binding, not the name', () => {
  it('types a group with no access-ish name as access when a manifest binds it', () => {
    const reg = buildGroupRegistry([parse('archive.yaml', ARCHIVE)], []);

    // Name-based typing (`/^access-/`) would have missed this entirely.
    expect(isAccessGroup(reg, 'photo-club')).toBe(true);
    expect(reg.get('photo-club')?.kinds).toEqual(new Set(['access']));
    expect(reg.get('photo-club')?.accessFor).toEqual(['archive']);
  });

  it('types a group NAMED like the retired access- convention as role when that is its only binding', () => {
    const reg = buildGroupRegistry([parse('archive.yaml', ARCHIVE)], []);

    // Name-based typing would have called this an access group and granted
    // entry on it. Its only binding is a role binding, so it grants none.
    expect(reg.get('access-legacy')?.kinds).toEqual(new Set(['role']));
    expect(isAccessGroup(reg, 'access-legacy')).toBe(false);
    expect(reg.get('access-legacy')?.accessFor).toEqual([]);
    expect(reg.get('access-legacy')?.roleFor).toEqual(['archive']);
  });

  it('does not let <svc>-admin become an access group (entry stays explicit)', () => {
    const reg = buildGroupRegistry([parse('grafana.yaml', GRAFANA)], []);

    // Entry: grafana-access, held by everyone who may enter, admins included.
    expect(isAccessGroup(reg, 'grafana-access')).toBe(true);
    expect(reg.get('grafana-access')?.kinds).toEqual(new Set(['access', 'role']));

    // Role: grafana-admin, and role ONLY. Holding it grants no entry, and
    // nothing derives entry from it. An identity holding only grafana-admin is
    // misconfigured, not privileged.
    expect(reg.get('grafana-admin')?.kinds).toEqual(new Set(['role']));
    expect(isAccessGroup(reg, 'grafana-admin')).toBe(false);
    expect(reg.get('grafana-admin')?.accessFor).toEqual([]);
    expect(reg.get('grafana-admin')?.roleFor).toEqual(['grafana']);
  });

  it('unions the kinds when one group carries several bindings', () => {
    // `housemates` is a configured identity group that an app also binds for
    // access. It is both; neither binding erases the other.
    const bound = `
presentation:
  name: Photos
  url: https://photos.example.test
  auth_kind: forward_auth
  access:
    - housemates
`;
    const reg = buildGroupRegistry([parse('photos.yaml', bound)], ['admin', 'housemates']);

    expect(reg.get('housemates')?.kinds).toEqual(new Set(['identity', 'access']));
    expect(isIdentityGroup(reg, 'housemates')).toBe(true);
    expect(isAccessGroup(reg, 'housemates')).toBe(true);

    // …while a configured identity group nothing binds stays identity-only.
    expect(reg.get('admin')?.kinds).toEqual(new Set(['identity']));
    expect(isAccessGroup(reg, 'admin')).toBe(false);
  });

  it('records every app that binds a shared group, in load order, without duplicates', () => {
    const reg = buildGroupRegistry(
      [parse('fetcher.yaml', FETCHER), parse('series.yaml', SERIES)],
      [],
    );

    expect(reg.get('downloads-usenet-access')?.accessFor).toEqual(['fetcher', 'series']);
    expect(reg.get('downloads-usenet-access')?.kinds).toEqual(new Set(['access']));
  });

  it('invents nothing for a manifest with no binding at all', () => {
    const reg = buildGroupRegistry([parse('statuspage.yaml', STATUSPAGE)], []);

    // No implicit access-<clientId>: absence of a binding is absence.
    expect(reg.size).toBe(0);
    expect(isAccessGroup(reg, 'statuspage-access')).toBe(false);
    expect(isAccessGroup(reg, 'access-statuspage')).toBe(false);
    expect(knownGroupNames(reg).size).toBe(0);
  });

  it('reports an unbound name as unknown rather than guessing its kind', () => {
    const reg = buildGroupRegistry([parse('grafana.yaml', GRAFANA)], ['admin']);

    // A typo'd group is what the lint has to catch. It must be absent, not
    // silently typed by the shape of its name.
    expect(reg.has('grafana-acess')).toBe(false);
    expect(isAccessGroup(reg, 'grafana-acess')).toBe(false);
    expect(isIdentityGroup(reg, 'grafana-acess')).toBe(false);
    expect(knownGroupNames(reg).has('grafana-acess')).toBe(false);
  });

  it('knownGroupNames covers every bound name, of every kind', () => {
    const set = Object.entries(CATALOG).map(([file, body]) => parse(file, body));
    const reg = buildGroupRegistry(set, ['admin', 'housemates']);

    expect(Array.from(knownGroupNames(reg)).sort()).toEqual(
      [...new Set([...EXPECTED_ACCESS, ...EXPECTED_ROLE, 'admin', 'housemates'])].sort(),
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// getGroupRegistry — over the real on-disk catalog
// ═══════════════════════════════════════════════════════════════════════════

describe('getGroupRegistry — completeness over the real loader', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'othala-group-registry-'));
    process.env['MANIFEST_DIR'] = dir;
    invalidateManifestCache();
    // The serving store logs stale/unavailable states to stderr; that is its
    // own suite's business, and here it is only noise.
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env['MANIFEST_DIR'];
    rmSync(dir, { recursive: true, force: true });
  });

  it('sees every manifest of every auth_kind — nothing is filtered upstream', () => {
    writeCatalog();

    // Guard the guard: if the loader silently dropped a class of manifest, the
    // assertions below would agree with a registry that had lost the same
    // class. This is the check that refuses to agree.
    expect(loadClientManifests().map((m) => m.clientId).sort()).toEqual([
      'audiobookshelf',
      'fetcher',
      'filedrop',
      'grafana',
      'promptdesk',
      'proxywatch',
      'series',
      'statuspage',
    ]);

    const reg = getGroupRegistry();
    expect(namesOfKind(reg, 'access')).toEqual(EXPECTED_ACCESS);
    expect(namesOfKind(reg, 'role')).toEqual(EXPECTED_ROLE);
  });

  it('B4: a presentation-only tile’s access group is grantable, not invisible', () => {
    writeCatalog();
    const reg = getGroupRegistry();

    // forward_auth (singular shim), forward_auth (shared), forward_auth (plural), external.
    // Every one of these registers no OIDC client, and every one of them is a
    // group the reverse proxy really gates on — so every one must be visible
    // here or the admin UI drops it on the next identity save.
    for (const group of [
      'proxywatch-access',
      'downloads-usenet-access',
      'filedrop-access',
      'audiobookshelf-access',
    ]) {
      expect(isAccessGroup(reg, group), `${group} must be an access group`).toBe(true);
      expect(knownAccessGroups(), `${group} must be grantable in the admin UI`).toContain(group);
    }

    // And the two views agree exactly — the registry and knownAccessGroups()
    // read the same `presentation.access:` binding the gate reads.
    expect(knownAccessGroups()).toEqual(EXPECTED_ACCESS);
    expect(namesOfKind(reg, 'access')).toEqual(knownAccessGroups());
  });

  it('carries the configured identity groups through without typing them access', () => {
    writeCatalog();
    const reg = getGroupRegistry();

    expect(isIdentityGroup(reg, 'housemates')).toBe(true);
    expect(isAccessGroup(reg, 'housemates')).toBe(false);
    expect(isIdentityGroup(reg, 'admin')).toBe(true);
    expect(isAccessGroup(reg, 'admin')).toBe(false);
  });

  it('memoizes on the manifest set and rebuilds when the catalog turns over', () => {
    writeCatalog();
    const first = getGroupRegistry();
    expect(getGroupRegistry()).toBe(first);

    // A second access group added to an existing binding.
    write('grafana.yaml', GRAFANA.replace('    - grafana-access\n', '    - grafana-access\n    - grafana-guest\n'));

    const second = getGroupRegistry();
    expect(second).not.toBe(first);
    expect(isAccessGroup(second, 'grafana-guest')).toBe(true);
    expect(accessFor(second, 'grafana-guest')).toEqual(['grafana']);
  });

  it('never throws when the catalog breaks, and keeps serving the last good registry', () => {
    writeCatalog();
    const good = getGroupRegistry();
    expect(isAccessGroup(good, 'grafana-access')).toBe(true);

    // A group_role_map pointing at an undeclared role: a SEMANTIC error, which
    // the strict loader treats as fatal for the WHOLE set.
    write('grafana.yaml', GRAFANA.replace('grafana-access: user', 'grafana-access: editor'));

    expect(() => getGroupRegistry()).not.toThrow();
    const after = getGroupRegistry();

    // The serving store holds one array reference steady through an outage, so
    // the memo stays warm rather than thrashing — and the admin surfaces keep
    // rendering the groups they were rendering a moment ago.
    expect(after).toBe(good);
    expect(namesOfKind(after, 'access')).toEqual(EXPECTED_ACCESS);
  });

  it('grants nothing when there is no catalog to read', () => {
    // Empty manifest dir: fail-closed. Identity groups survive (they are env,
    // not catalog), but no access binding exists for anyone to satisfy.
    const reg = getGroupRegistry();

    expect(namesOfKind(reg, 'access')).toEqual([]);
    expect(namesOfKind(reg, 'role')).toEqual([]);
    expect(isIdentityGroup(reg, 'housemates')).toBe(true);
  });
});

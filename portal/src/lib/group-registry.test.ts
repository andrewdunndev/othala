// Invariant: a group's type comes from its binding, never its name.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

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

const PROXYWATCH = `
presentation:
  name: Proxywatch
  url: https://proxywatch.example.test
  auth_kind: forward_auth
  access_group: proxywatch-access
`;

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

const FILEDROP = `
presentation:
  name: Filedrop
  url: https://filedrop.example.test
  auth_kind: forward_auth
  access:
    - filedrop-access
`;

const AUDIOBOOKSHELF = `
presentation:
  name: Audiobookshelf
  url: https://audiobookshelf.example.test
  auth_kind: external
  access:
    - audiobookshelf-access
`;

const STATUSPAGE = `
presentation:
  name: Status
  url: https://status.example.test
  auth_kind: external
consent:
  skip_access_check: true
`;

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

const EXPECTED_ACCESS = [
  'audiobookshelf-access',
  'downloads-usenet-access',
  'filedrop-access',
  'grafana-access',
  'promptdesk-access',
  'proxywatch-access',
];

const EXPECTED_ROLE = ['grafana-access', 'grafana-admin', 'promptdesk-access', 'promptdesk-admin'];

function parse(file: string, body: string): ClientManifest {
  return parseManifest(body, file);
}

function accessFor(reg: GroupRegistry, name: string): string[] {
  return reg.get(name)?.accessFor ?? [];
}

let dir: string;

function write(name: string, body: string): void {
  writeFileSync(join(dir, name), body, 'utf8');
  invalidateManifestCache();
}

function writeCatalog(): void {
  for (const [file, body] of Object.entries(CATALOG)) write(file, body);
}

describe('buildGroupRegistry — type comes from the binding, not the name', () => {
  it('types a group with no access-ish name as access when a manifest binds it', () => {
    const reg = buildGroupRegistry([parse('archive.yaml', ARCHIVE)], []);

    expect(isAccessGroup(reg, 'photo-club')).toBe(true);
    expect(reg.get('photo-club')?.kinds).toEqual(new Set(['access']));
    expect(reg.get('photo-club')?.accessFor).toEqual(['archive']);
  });

  it('types a group NAMED like the retired access- convention as role when that is its only binding', () => {
    const reg = buildGroupRegistry([parse('archive.yaml', ARCHIVE)], []);

    expect(reg.get('access-legacy')?.kinds).toEqual(new Set(['role']));
    expect(isAccessGroup(reg, 'access-legacy')).toBe(false);
    expect(reg.get('access-legacy')?.accessFor).toEqual([]);
    expect(reg.get('access-legacy')?.roleFor).toEqual(['archive']);
  });

  it('does not let <svc>-admin become an access group (entry stays explicit)', () => {
    const reg = buildGroupRegistry([parse('grafana.yaml', GRAFANA)], []);

    expect(isAccessGroup(reg, 'grafana-access')).toBe(true);
    expect(reg.get('grafana-access')?.kinds).toEqual(new Set(['access', 'role']));

    expect(reg.get('grafana-admin')?.kinds).toEqual(new Set(['role']));
    expect(isAccessGroup(reg, 'grafana-admin')).toBe(false);
    expect(reg.get('grafana-admin')?.accessFor).toEqual([]);
    expect(reg.get('grafana-admin')?.roleFor).toEqual(['grafana']);
  });

  it('unions the kinds when one group carries several bindings', () => {
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

    expect(reg.size).toBe(0);
    expect(isAccessGroup(reg, 'statuspage-access')).toBe(false);
    expect(isAccessGroup(reg, 'access-statuspage')).toBe(false);
    expect(knownGroupNames(reg).size).toBe(0);
  });

  it('reports an unbound name as unknown rather than guessing its kind', () => {
    const reg = buildGroupRegistry([parse('grafana.yaml', GRAFANA)], ['admin']);

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

describe('getGroupRegistry — completeness over the real loader', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'othala-group-registry-'));
    process.env['MANIFEST_DIR'] = dir;
    invalidateManifestCache();
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

    for (const group of [
      'proxywatch-access',
      'downloads-usenet-access',
      'filedrop-access',
      'audiobookshelf-access',
    ]) {
      expect(isAccessGroup(reg, group), `${group} must be an access group`).toBe(true);
      expect(knownAccessGroups(), `${group} must be grantable in the admin UI`).toContain(group);
    }

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

    write('grafana.yaml', GRAFANA.replace('grafana-access: user', 'grafana-access: editor'));

    expect(() => getGroupRegistry()).not.toThrow();
    const after = getGroupRegistry();

    expect(after).toBe(good);
    expect(namesOfKind(after, 'access')).toEqual(EXPECTED_ACCESS);
  });

  it('grants nothing when there is no catalog to read', () => {
    const reg = getGroupRegistry();

    expect(namesOfKind(reg, 'access')).toEqual([]);
    expect(namesOfKind(reg, 'role')).toEqual([]);
    expect(isIdentityGroup(reg, 'housemates')).toBe(true);
  });
});

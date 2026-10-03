// Invariant: a group's type comes from its binding, never its name.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  parseManifest,
  loadClientManifests,
  invalidateManifestCache,
  setManifestDir,
  type ClientManifest,
} from './manifests.js';
import {
  buildGroupRegistry,
  isAccessGroup,
  isIdentityGroup,
  knownGroupNames,
  type GroupKind,
  type GroupRegistry,
} from './group-registry.js';
import { servingManifests } from './manifest-store.js';
import { IDENTITY_GROUPS } from './constants.js';

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
  access: [proxywatch-access]
`;

const FETCHER = `
presentation:
  name: Usenet downloader
  url: https://downloads.example.test/fetcher
  auth_kind: forward_auth
  access: [downloads-usenet-access]
`;

const SERIES = `
presentation:
  name: Series manager
  url: https://downloads.example.test/series
  auth_kind: forward_auth
  access: [downloads-usenet-access]
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
    access-curators: curator
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

function namesOfKind(reg: GroupRegistry, kind: GroupKind): string[] {
  return [...reg.values()].filter((e) => e.kinds.has(kind)).map((e) => e.name).sort();
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
  });

  it('types a group NAMED like the retired access- convention as role when that is its only binding', () => {
    const reg = buildGroupRegistry([parse('archive.yaml', ARCHIVE)], []);

    expect(reg.get('access-curators')?.kinds).toEqual(new Set(['role']));
    expect(isAccessGroup(reg, 'access-curators')).toBe(false);
  });

  it('does not let <svc>-admin become an access group (entry stays explicit)', () => {
    const reg = buildGroupRegistry([parse('grafana.yaml', GRAFANA)], []);

    expect(isAccessGroup(reg, 'grafana-access')).toBe(true);
    expect(reg.get('grafana-access')?.kinds).toEqual(new Set(['access', 'role']));

    expect(reg.get('grafana-admin')?.kinds).toEqual(new Set(['role']));
    expect(isAccessGroup(reg, 'grafana-admin')).toBe(false);
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

  it('types a group several apps bind once, as access', () => {
    const reg = buildGroupRegistry(
      [parse('fetcher.yaml', FETCHER), parse('series.yaml', SERIES)],
      [],
    );

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

describe('buildGroupRegistry — completeness over the real loader', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'othala-group-registry-'));
    setManifestDir(dir);
    invalidateManifestCache();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
    setManifestDir(undefined);
    rmSync(dir, { recursive: true, force: true });
  });

  const servingRegistry = () => buildGroupRegistry(servingManifests(), IDENTITY_GROUPS);

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

    const reg = servingRegistry();
    expect(namesOfKind(reg, 'access')).toEqual(EXPECTED_ACCESS);
    expect(namesOfKind(reg, 'role')).toEqual(EXPECTED_ROLE);
  });

  it('carries the fixed identity groups through without typing them access', () => {
    writeCatalog();
    const reg = servingRegistry();

    expect(isIdentityGroup(reg, 'everyone')).toBe(true);
    expect(isAccessGroup(reg, 'everyone')).toBe(false);
  });
});

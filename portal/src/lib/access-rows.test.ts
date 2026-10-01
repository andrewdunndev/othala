// Invariant: the level an admin picks for an app round-trips through storage (groups and role overrides) unchanged.

import { describe, expect, it } from 'vitest';
import {
  accessToStorage,
  choicesFromForm,
  currentLevel,
  isOpenToEveryone,
  isTopLevel,
  levelsFor,
  type AccessStored,
} from './access-rows';
import type { ClientManifest } from './manifests';

const role = (name: string, description = `${name} role`) => ({ name, description, claimEmit: {} });

const grafana = {
  clientId: 'grafana',
  accessGroups: ['grafana-access'],
  roles: [role('admin'), role('editor'), role('viewer')],
  groupRoleMap: { 'grafana-admin': 'admin' },
  skipAccessCheck: false,
} as unknown as ClientManifest;

const proxywatch = {
  clientId: 'proxywatch',
  accessGroups: ['proxywatch-access'],
  roles: [],
  groupRoleMap: {},
  skipAccessCheck: false,
} as unknown as ClientManifest;

const statuspage = {
  clientId: 'statuspage',
  accessGroups: ['everyone'],
  roles: [],
  groupRoleMap: {},
  skipAccessCheck: false,
} as unknown as ClientManifest;

const MANIFESTS = [grafana, proxywatch, statuspage];
const stored = (groups: string[], roles: Record<string, string> = {}): AccessStored => ({ groups, roles });

/** Apply a choice, then read the level back the way the page does. */
function roundTrip(m: ClientManifest, level: string, from: AccessStored): string {
  const next = accessToStorage(MANIFESTS, { [m.clientId]: level }, from);
  return currentLevel(m, { groups: next.groups, roles: next.roles });
}

describe('levels', () => {
  it('runs least to most privilege and carries role descriptions as hints', () => {
    expect(levelsFor(grafana).map((l) => l.value)).toEqual(['viewer', 'editor', 'admin']);
    expect(levelsFor(grafana)[0]).toEqual({ value: 'viewer', label: 'Viewer', hint: 'viewer role' });
  });

  it('offers Can use for an app without roles', () => {
    expect(levelsFor(proxywatch)).toEqual([{ value: 'use', label: 'Can use', hint: '' }]);
  });

  it('knows open apps and the top level', () => {
    expect(isOpenToEveryone(statuspage)).toBe(true);
    expect(isOpenToEveryone(grafana)).toBe(false);
    expect(isTopLevel(grafana, 'admin')).toBe(true);
    expect(isTopLevel(grafana, 'editor')).toBe(false);
    expect(isTopLevel(proxywatch, 'use')).toBe(false);
  });
});

describe('currentLevel', () => {
  it('is none without the access group', () => {
    expect(currentLevel(grafana, { groups: ['everyone'] })).toBe('none');
  });

  it('is the lowest level for the access group alone', () => {
    expect(currentLevel(grafana, { groups: ['grafana-access'] })).toBe('viewer');
  });

  it('reads a mapped group and an override', () => {
    expect(currentLevel(grafana, { groups: ['grafana-access', 'grafana-admin'] })).toBe('admin');
    expect(currentLevel(grafana, { groups: ['grafana-access'], roles: { grafana: 'editor' } })).toBe('editor');
  });
});

describe('accessToStorage', () => {
  it('stores the lowest level as the access group alone', () => {
    const next = accessToStorage(MANIFESTS, { grafana: 'viewer' }, stored(['everyone']));
    expect(next.groups.sort()).toEqual(['everyone', 'grafana-access']);
    expect(next.roles).toEqual({});
  });

  it('stores a mapped level as access group plus role group', () => {
    const next = accessToStorage(MANIFESTS, { grafana: 'admin' }, stored(['everyone']));
    expect(next.groups.sort()).toEqual(['everyone', 'grafana-access', 'grafana-admin']);
    expect(next.roles).toEqual({});
  });

  it('stores an unmapped level as a role override', () => {
    const next = accessToStorage(MANIFESTS, { grafana: 'editor' }, stored(['everyone']));
    expect(next.groups.sort()).toEqual(['everyone', 'grafana-access']);
    expect(next.roles).toEqual({ grafana: 'editor' });
  });

  it('removes the groups and the override for No access', () => {
    const next = accessToStorage(MANIFESTS, { grafana: 'none' }, stored(['everyone', 'grafana-access', 'grafana-admin'], { grafana: 'editor' }));
    expect(next.groups).toEqual(['everyone']);
    expect(next.roles).toEqual({});
  });

  it('clears a contradicting override and the old role group when the level moves', () => {
    const down = accessToStorage(MANIFESTS, { grafana: 'viewer' }, stored(['grafana-access', 'grafana-admin'], { grafana: 'editor' }));
    expect(down.groups).toEqual(['grafana-access']);
    expect(down.roles).toEqual({});
  });

  it('round-trips every level of every editable app', () => {
    for (const level of ['none', 'viewer', 'editor', 'admin']) {
      expect(roundTrip(grafana, level, stored(['everyone']))).toBe(level);
      expect(roundTrip(grafana, level, stored(['everyone', 'grafana-access', 'grafana-admin'], { grafana: 'editor' }))).toBe(level);
    }
    expect(roundTrip(proxywatch, 'use', stored([]))).toBe('use');
    expect(roundTrip(proxywatch, 'none', stored(['proxywatch-access']))).toBe('none');
  });

  it('leaves an unchanged app and unrelated groups alone', () => {
    const from = stored(['everyone', 'garden', 'grafana-access'], { grafana: 'editor' });
    const next = accessToStorage(MANIFESTS, { grafana: 'editor', proxywatch: 'use' }, from);
    expect(next.groups.sort()).toEqual(['everyone', 'garden', 'grafana-access', 'proxywatch-access']);
    expect(next.roles).toEqual({ grafana: 'editor' });
  });

  it('keeps a group another app still relies on', () => {
    const shared = { ...proxywatch, clientId: 'other', accessGroups: ['grafana-access'] } as unknown as ClientManifest;
    const next = accessToStorage([grafana, shared], { grafana: 'none' }, stored(['grafana-access']));
    expect(next.groups).toEqual(['grafana-access']);
    expect(next.unmet).toEqual([{ clientId: 'grafana', group: 'grafana-access', sharedWith: ['other'] }]);
  });

  it('writes an explicit entry-level override when a shared role group would outrank it', () => {
    const other = {
      ...proxywatch,
      clientId: 'other',
      accessGroups: ['other-access'],
      groupRoleMap: { 'grafana-admin': 'use' },
    } as unknown as ClientManifest;
    const from = stored(['grafana-access', 'grafana-admin', 'other-access']);
    const next = accessToStorage([grafana, other], { grafana: 'viewer' }, from);
    expect(next.groups).toContain('grafana-admin');
    expect(next.roles).toEqual({ grafana: 'viewer' });
    expect(next.unmet).toEqual([]);
    expect(currentLevel(grafana, next)).toBe('viewer');
  });

  it('ignores open apps, unknown apps and unknown levels', () => {
    const from = stored(['everyone', 'grafana-access']);
    const next = accessToStorage(MANIFESTS, { statuspage: 'use', nothing: 'use', grafana: 'owner' }, from);
    expect(next).toEqual({ groups: ['everyone', 'grafana-access'], roles: {}, unmet: [] });
  });
});

describe('choicesFromForm', () => {
  it('reads level fields by client id', () => {
    const fd = new FormData();
    fd.set('level:grafana', 'editor');
    fd.set('level:proxywatch', 'none');
    fd.set('displayName', 'x');
    expect(choicesFromForm(fd)).toEqual({ grafana: 'editor', proxywatch: 'none' });
  });
});

describe('currentLevel follows the consent resolver, never group naming', () => {
  const wiki = {
    clientId: 'wiki',
    accessGroups: ['wiki-access'],
    roles: [role('admin'), role('editor'), role('reader')],
    groupRoleMap: { 'wiki-admin': 'admin', 'wiki-edit': 'editor' },
    skipAccessCheck: false,
  } as unknown as ClientManifest;

  it('lets an override win over the group map, and ignores an empty or malformed override', () => {
    const groups = ['wiki-access', 'wiki-admin'];
    expect(currentLevel(wiki, { groups, roles: { wiki: 'reader' } })).toBe('reader');
    expect(currentLevel(wiki, { groups, roles: {} })).toBe('admin');
    expect(currentLevel(wiki, { groups, roles: { wiki: 5 as unknown as string } })).toBe('admin');
    expect(currentLevel(wiki, { groups, roles: { wiki: 'nonsense' } })).toBe('admin');
  });

  it('gives the highest-ranked mapped role whatever order the groups are stored in', () => {
    const set = ['wiki-access', 'wiki-edit', 'wiki-admin'];
    const orders = [set, [...set].reverse(), [set[1], set[2], set[0]], [set[2], set[0], set[1]]];
    for (const groups of orders) expect(currentLevel(wiki, { groups })).toBe('admin');
  });

  it('falls to the lowest level when access holds no mapped role, and to none without the access group', () => {
    expect(currentLevel(wiki, { groups: ['wiki-access'] })).toBe('reader');
    expect(currentLevel(wiki, { groups: ['wiki-admin'] })).toBe('none');
  });

  it('treats a roleless app as Can use only for people in its group', () => {
    expect(currentLevel(proxywatch, { groups: ['proxywatch-access'] })).toBe('use');
    expect(currentLevel(proxywatch, { groups: [] })).toBe('none');
  });
});

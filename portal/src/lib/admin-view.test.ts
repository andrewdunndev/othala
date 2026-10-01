// Invariant: the admin lists speak in people, apps and levels, and filter by what a person can actually use.

import { describe, expect, it } from 'vitest';
import {
  attentionItems,
  emailIsVerified,
  joinApps,
  personName,
  personRows,
  rowMatches,
  showOptions,
  unrecognisedGroups,
} from './admin-view';
import type { ClientManifest } from './manifests';
import { identity } from './test-builders';

const role = (name: string) => ({ name, description: '', claimEmit: {} });
const grafana = {
  clientId: 'grafana', clientName: 'Grafana', sourcePath: 'grafana.yaml', accessGroups: ['grafana-access'],
  roles: [role('admin'), role('viewer')], groupRoleMap: { 'grafana-admin': 'admin' }, skipAccessCheck: false,
} as unknown as ClientManifest;
const statuspage = {
  clientId: 'statuspage', clientName: 'Status page', sourcePath: 'statuspage.yaml', accessGroups: ['everyone'],
  roles: [], groupRoleMap: {}, skipAccessCheck: false,
} as unknown as ClientManifest;
const apps = joinApps([grafana, statuspage], []);

const person = (username: string, groups: string[], extra: Record<string, unknown> = {}) =>
  identity({ id: username, username, metadataAdmin: { groups, ...extra } });

describe('joinApps', () => {
  it('names an app by its manifest when no tile matches, with the file stem as slug', () => {
    expect(apps.map((a) => [a.slug, a.name])).toEqual([['grafana', 'Grafana'], ['statuspage', 'Status page']]);
  });
});

describe('personRows', () => {
  const rows = personRows(
    [
      person('zed', ['everyone']),
      identity({ id: 'amy', username: 'amy', displayName: 'Amy Park', state: 'inactive', metadataAdmin: { groups: ['everyone', 'grafana-access', 'grafana-admin'], admin: true } }),
    ],
    apps,
  );

  it('sorts by name and shows display name over username', () => {
    expect(rows.map((r) => r.name)).toEqual(['Amy Park', 'zed']);
    expect(personName(identity({ username: 'q.r' }))).toBe('q.r');
  });

  it('chips the apps they can use, marking the top level, open apps included', () => {
    expect(rows[0].chips).toEqual([{ name: 'Grafana', top: true }, { name: 'Status page', top: false }]);
    expect(rows[1].chips).toEqual([{ name: 'Status page', top: false }]);
  });

  it('badges admin and sign-in off', () => {
    expect([rows[0].admin, rows[0].off, rows[1].admin, rows[1].off]).toEqual([true, true, false, false]);
  });

  it('reads email verification from the trait address only', () => {
    expect(emailIsVerified(identity({ verified: true }))).toBe(true);
    expect(emailIsVerified(identity({ verified: false }))).toBe(false);
  });
});

describe('rowMatches', () => {
  const [amy, zed] = personRows(
    [
      identity({ id: 'amy', username: 'amy', displayName: 'Amy Park', metadataAdmin: { groups: ['grafana-access'], admin: true } }),
      identity({ id: 'zed', username: 'zed', state: 'inactive', metadataAdmin: { groups: [] } }),
    ],
    joinApps([grafana], []),
  );

  it('searches name, username and email', () => {
    expect(rowMatches(amy, 'park', 'all')).toBe(true);
    expect(rowMatches(amy, 'zed@', 'all')).toBe(false);
    expect(rowMatches(zed, 'ZED@OTHALA', 'all')).toBe(true);
  });

  it('shows admins, people without apps, sign-in off and per-app users', () => {
    expect([amy, zed].map((r) => rowMatches(r, '', 'admins'))).toEqual([true, false]);
    expect([amy, zed].map((r) => rowMatches(r, '', 'noapps'))).toEqual([false, true]);
    expect([amy, zed].map((r) => rowMatches(r, '', 'off'))).toEqual([false, true]);
    expect([amy, zed].map((r) => rowMatches(r, '', 'app:grafana'))).toEqual([true, false]);
    expect(rowMatches(zed, '', 'nonsense')).toBe(true);
  });

  it('offers one Can use option per app after the fixed ones', () => {
    expect(showOptions(apps).map((o) => o.label)).toEqual(['Everyone', 'Household admins', 'No apps yet', 'Sign-in off', 'Can use Grafana', 'Can use Status page']);
  });
});

describe('unrecognised groups and attention', () => {
  it('flags groups no app binds and invalid names, never role groups or household groups', () => {
    const i = person('a', ['everyone', 'admin', 'grafana-access', 'grafana-admin', 'garden', 'Bad Name']);
    expect(unrecognisedGroups(i, [grafana])).toEqual(['garden', 'Bad Name']);
  });

  it('lists people with no apps and people with a stray group, and nothing when all is well', () => {
    const rows = personRows([identity({ id: 'n', username: 'nobody', metadataAdmin: { groups: ['garden'] } })], [apps[0]]);
    expect(attentionItems(rows).map((a) => a.text)).toEqual(['Has no apps yet', 'Has a group no app uses']);
    expect(attentionItems(personRows([person('ok', ['grafana-access'])], [apps[0]]))).toEqual([]);
  });
});

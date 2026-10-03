// Invariant: the admin lists speak in people, apps and levels, and filter by what a person can actually use.

import { describe, expect, it } from 'vitest';
import {
  attentionItems,
  describeTtl,
  emailIsVerified,
  joinApps,
  personLimits,
  personName,
  personRows,
  removalBlock,
  rowMatches,
  showOptions,
  signInMethods,
  suggestUsername,
  unrecognisedGroups,
} from './admin-view';
import type { ClientManifest } from './manifests';
import { asAdmin, identity, withCredential, withLookupSecret, withPasskey, withTotp, withWebauthnKey, manifest } from './test-builders';
import { parseIdentity } from './identity-facts';

const role = (name: string) => ({ name, description: '', claimEmit: {} });
const grafana = {
  clientId: 'grafana', clientName: 'Grafana', sourcePath: 'grafana.yaml', accessGroups: ['grafana-access'],
  roles: [role('admin'), role('viewer')], groupRoleMap: { 'grafana-admin': 'admin' }, skipAccessCheck: false,
} as unknown as ClientManifest;
const statuspage = {
  clientId: 'statuspage', clientName: 'Status page', sourcePath: 'statuspage.yaml', accessGroups: [],
  roles: [], groupRoleMap: {}, skipAccessCheck: true,
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

  it('chips the apps they were given, marking the top level, never open apps', () => {
    expect(rows[0].chips).toEqual([{ name: 'Grafana', top: true }]);
    expect(rows[1].chips).toEqual([]);
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
    const i = person('a', ['everyone', 'grafana-access', 'grafana-admin', 'garden', 'Bad Name']);
    expect(unrecognisedGroups(i, [grafana])).toEqual(['garden', 'Bad Name']);
  });

  it('lists people with no apps and people with a stray group, and nothing when all is well', () => {
    const rows = personRows([identity({ id: 'n', username: 'nobody', metadataAdmin: { groups: ['garden'] } })], [apps[0]]);
    expect(attentionItems(rows).map((a) => a.text)).toEqual(['Has no apps yet', 'Belongs to a group no app uses']);
    expect(attentionItems(rows).find((a) => a.text.startsWith('Belongs to a group'))?.anchor).toBe('groups');
    expect(attentionItems(personRows([person('ok', ['grafana-access'])], [apps[0]]))).toEqual([]);
  });
});

describe('suggestUsername', () => {
  it('joins the words of a name with dots, dropping accents and punctuation', () => {
    expect(suggestUsername('Robin K. Rivera', 'x@example.test')).toBe('robin.k.rivera');
    expect(suggestUsername('Zoë Núñez', 'x@example.test')).toBe('zoe.nunez');
  });

  it('falls back to the email local part for one word, and to nothing when that does not fit', () => {
    expect(suggestUsername('Robin', 'robin.k@example.test')).toBe('robin.k');
    expect(suggestUsername('Robin', 'robin@example.test')).toBe('');
    expect(suggestUsername('', '')).toBe('');
  });
});

describe('describeTtl', () => {
  it('says hours and minutes in words and leaves other durations alone', () => {
    expect([describeTtl('24h'), describeTtl('1h'), describeTtl('30m'), describeTtl('2d')]).toEqual(['24 hours', '1 hour', '30 minutes', '2d']);
  });
});

describe('signInMethods', () => {
  const status = (i: ReturnType<typeof identity>) => Object.fromEntries(signInMethods(i).map((m) => [m.label, m.value]));

  it('reads the account page words from the stored credentials', () => {
    const i = withLookupSecret(withTotp(identity()));
    expect(status(i)).toMatchObject({ Password: 'Set', 'Authenticator app': 'Set', 'Backup codes': 'Saved' });
  });

  it('counts passkeys and security keys and says None when absent', () => {
    expect(status(withPasskey(identity()))).toMatchObject({ Passkeys: '1' });
    expect(status(identity())).toMatchObject({ Passkeys: 'None', 'Authenticator app': 'Not set', 'Backup codes': 'Not saved' });
  });
});

describe('sign-in status agrees with the second-factor rule', () => {
  const status = (i: ReturnType<typeof identity>) => Object.fromEntries(signInMethods(i).map((m) => [m.label, m.value]));

  it('does not count an empty webauthn entry as a security key', () => {
    const i = withCredential(identity(), 'webauthn', {});
    expect(status(i)).toMatchObject({ 'Security keys': 'None' });
    expect(parseIdentity(i).hasSecondFactor).toBe(false);
  });

  it('counts a security key and an authenticator app exactly when parseIdentity counts a second factor', () => {
    const key = withWebauthnKey(identity());
    expect(status(key)).toMatchObject({ 'Security keys': '1', 'Authenticator app': 'Not set' });
    expect(parseIdentity(key).hasSecondFactor).toBe(true);
    const app = withTotp(identity());
    expect(status(app)).toMatchObject({ 'Authenticator app': 'Set' });
    expect(parseIdentity(app).hasSecondFactor).toBe(true);
    expect(status(withCredential(identity(), 'totp', {}))).toMatchObject({ 'Authenticator app': 'Not set' });
  });
});

describe('personLimits', () => {
  const o = { first: 'Eli', isSelf: false, lastAdmin: false };

  it('gives the reason for a person with no second factor instead of a grant', () => {
    expect(personLimits(identity(), o).grant).toMatch(/authenticator app or security key first/);
    expect(personLimits(withTotp(identity()), o).grant).toBeNull();
  });

  it('refuses revoking and turning off the last admin, and turning off your own sign-in', () => {
    const last = personLimits(asAdmin(withTotp(identity())), { ...o, isSelf: true, lastAdmin: true });
    expect(last.revoke).toMatch(/only household admin/);
    expect(last.deactivate).toMatch(/own sign-in/);
    const other = personLimits(asAdmin(withTotp(identity())), { ...o, lastAdmin: true });
    expect(other.revoke).toMatch(/Eli is the only household admin/);
    expect(other.deactivate).toMatch(/only household admin/);
    expect(personLimits(asAdmin(withTotp(identity())), o)).toMatchObject({ revoke: null, deactivate: null });
  });
});

describe('removalBlock', () => {
  it('blocks removing an admin\'s last second factor and allows it when another remains or for a non-admin', () => {
    const admin = asAdmin(withTotp(identity()));
    expect(removalBlock(admin, 'totp', false, [])).toMatch(/at least one/);
    expect(removalBlock(withWebauthnKey(admin), 'totp', false, [])).toBeNull();
    expect(removalBlock(withTotp(identity()), 'totp', false, [])).toBeNull();
    expect(removalBlock(withTotp(identity()), 'totp', true, [])).toMatch(/at least one/);
  });

  it('blocks removing the last second factor of someone with an elevated app role', () => {
    const wiki = manifest('wiki', ['admin', 'user'], { 'wiki-admin': 'admin' }, ['family']);
    const elevated = withTotp(identity({ metadataAdmin: { groups: ['family', 'wiki-admin'] } }));
    expect(removalBlock(elevated, 'totp', false, [wiki])).toMatch(/at least one/);
    expect(removalBlock(withWebauthnKey(elevated), 'totp', false, [wiki])).toBeNull();
    expect(removalBlock(withTotp(identity({ metadataAdmin: { groups: ['family'] } })), 'totp', false, [wiki])).toBeNull();
  });
});

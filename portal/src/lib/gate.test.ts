// Invariant: a denial outranks a step-up, and step-up follows enrolled second factors, the admin marker and elevated
// roles only.

import { describe, it, expect } from 'vitest';
import { decideAccess, needsStepUp, holdsElevatedRole } from './gate';
import type { ClientManifest } from './manifests';
import type { Identity } from './types';
import { asAdmin, identity as buildIdentity, withCredential, withLookupSecret, withPasskey, withTotp, withWebauthnKey, manifest } from './test-builders';

const APPLY: Record<string, (i: Identity) => Identity> = {
  password: (i) => i,
  passkey: withPasskey,
  totp: withTotp,
  webauthn: (i) => withWebauthnKey(i),
  lookup_secret: withLookupSecret,
  'webauthn-schema-only': (i) => i,
  'webauthn-no-keys': (i) => withCredential(i, 'webauthn', { credentials: [] }),
  'webauthn-passwordless-only': (i) => withWebauthnKey(i, { passwordless: true }),
  'totp-no-url': (i) => withCredential(i, 'totp', {}),
};

function identity(types: string[], admin?: boolean): Identity {
  const base = buildIdentity({
    id: 'id-1',
    password: types.includes('password'),
    ...(admin === undefined ? {} : { metadataAdmin: { admin } }),
  });
  return types.reduce((i, t) => APPLY[t](i), base);
}

describe('needsStepUp', () => {
  const cases: Array<[string, string | undefined, string[], boolean | undefined, boolean]> = [
    ['aal1 + totp', 'aal1', ['password', 'totp'], undefined, true],
    ['aal1 + webauthn', 'aal1', ['passkey', 'webauthn'], undefined, true],
    ['missing aal + totp', undefined, ['totp'], undefined, true],
    ['aal1 admin-marked, no second factor', 'aal1', ['password'], true, true],
    ['aal1 passkey only', 'aal1', ['passkey'], undefined, false],
    ['aal1 password only', 'aal1', ['password'], undefined, false],
    ['aal1 lookup_secret only', 'aal1', ['lookup_secret'], undefined, false],
    ['aal1 password + schema webauthn entry, no keys', 'aal1', ['password', 'webauthn-schema-only'], undefined, false],
    ['aal1 password + emptied webauthn entry', 'aal1', ['password', 'webauthn-no-keys'], undefined, false],
    ['aal1 passwordless webauthn key only', 'aal1', ['password', 'webauthn-passwordless-only'], undefined, false],
    ['aal1 totp entry without a totp_url', 'aal1', ['password', 'totp-no-url'], undefined, false],
    ['aal1 admin marker false', 'aal1', ['password'], false, false],
    ['aal2 + totp', 'aal2', ['totp'], undefined, false],
    ['aal2 admin-marked', 'aal2', ['totp'], true, false],
  ];

  it.each(cases)('%s', (_name, aal, types, admin, expected) => {
    const session = aal === undefined ? {} : { authenticator_assurance_level: aal as 'aal1' | 'aal2' };
    expect(needsStepUp(session, identity(types, admin))).toBe(expected);
  });

  it('null session with a second factor steps up', () => {
    expect(needsStepUp(null, identity(['totp']))).toBe(true);
  });

  it('null identity never steps up (the gate denies it elsewhere)', () => {
    expect(needsStepUp({ authenticator_assurance_level: 'aal1' }, null)).toBe(false);
  });
});

const x = manifest('x', ['admin', 'user'], { 'x-admin': 'admin', 'x-access': 'user' }, ['x-access']);

describe('holdsElevatedRole', () => {
  const listen = manifest('listen', ['admin', 'user', 'guest'], { 'listen-admin': 'admin', 'listen-access': 'user' }, ['listen-access']);
  const grafana = manifest('grafana', ['admin', 'editor', 'viewer'], { 'grafana-admin': 'admin', 'grafana-access': 'viewer' }, ['grafana-access']);
  const held = (manifests: ClientManifest[], groups: string[], roles?: Record<string, string>) =>
    holdsElevatedRole(buildIdentity({ metadataAdmin: { groups, ...(roles ? { roles } : {}) } }), manifests);

  it('a role above the entry role holds elevation', () => {
    expect(held([x], ['x-admin'])).toBe(true);
    expect(held([listen], ['listen-admin'])).toBe(true);
  });
  it('the entry role and below do not', () => {
    expect(held([x], ['x-access'])).toBe(false);
    expect(held([listen], ['listen-access'])).toBe(false);
    expect(held([x, listen], [])).toBe(false);
    expect(holdsElevatedRole(null, [x])).toBe(false);
  });
  it('an override resolves through the same ranking', () => {
    expect(held([grafana], ['grafana-access'], { grafana: 'editor' })).toBe(true);
    expect(held([grafana], ['grafana-admin'], { grafana: 'viewer' })).toBe(false);
  });
  it('an override naming an undeclared role is not elevated, whatever the groups map', () => {
    expect(held([grafana], ['grafana-access', 'grafana-admin'], { grafana: 'reader' })).toBe(false);
  });
  it('the entry role is the lowest-ranked mapped access group', () => {
    const m = manifest('m', ['admin', 'editor', 'viewer'], { 'm-edit': 'editor', 'm-view': 'viewer' }, ['m-edit', 'm-view']);
    expect(held([m], ['m-edit'])).toBe(true);
    expect(held([m], ['m-view'])).toBe(false);
  });
  it('without a mapped access group the entry role is the last declared', () => {
    const m = manifest('m', ['admin', 'editor', 'viewer'], {}, ['m-access']);
    expect(held([m], ['m-access'], { m: 'editor' })).toBe(true);
    expect(held([m], ['m-access'], { m: 'viewer' })).toBe(false);
  });
  it('a manifest without roles is never elevated', () => {
    expect(held([manifest('y', [], {}, ['y-access'])], ['y-access'])).toBe(false);
  });
});

describe('decideAccess', () => {
  const member = (groups = ['x-access']) => buildIdentity({ metadataAdmin: { groups } });
  const aal1 = { authenticator_assurance_level: 'aal1' as const };
  const aal2 = { authenticator_assurance_level: 'aal2' as const };
  const cases: Array<[string, Identity | null, Parameters<typeof decideAccess>[1], Parameters<typeof decideAccess>[2], string]> = [
    ['app: member at aal1', member(), { app: x }, aal1, 'allow'],
    ['app: not in an access group', member([]), { app: x }, aal1, 'deny'],
    ['app: inactive identity', { ...member(), state: 'inactive' }, { app: x }, aal1, 'deny'],
    ['app: identity lookup failed', null, { app: x }, aal1, 'deny'],
    ['app: no manifest', member(), { app: undefined }, aal1, 'deny'],
    ['app: second factor at aal1', withTotp(member()), { app: x }, aal1, 'stepUp'],
    ['app: second factor at aal2', withTotp(member()), { app: x }, aal2, 'allow'],
    ['app: admin marker at aal1', asAdmin(member()), { app: x }, aal1, 'stepUp'],
    ['app: elevated role at aal1', member(['x-access', 'x-admin']), { app: x }, aal1, 'stepUp'],
    ['app: denial outranks step-up', withTotp(member([])), { app: x }, aal1, 'deny'],
    ['group: member at aal1', member(), { group: 'x-access' }, aal1, 'allow'],
    ['group: not a member', member(), { group: 'y-access' }, aal1, 'deny'],
    ['group: non-canonical stored group', member(['x-access', 'Bad Name']), { group: 'x-access' }, aal1, 'deny'],
    ['group: second factor at aal1', withTotp(member()), { group: 'x-access' }, aal1, 'stepUp'],
    ['admin: marker, aal2, fresh', asAdmin(member()), 'admin', { ...aal2, fresh: true }, 'allow'],
    ['admin: no marker', member(), 'admin', { ...aal2, fresh: true }, 'deny'],
    ['admin: stale aal2', asAdmin(member()), 'admin', { ...aal2, fresh: false }, 'stepUp'],
    ['admin: freshness unknown', asAdmin(member()), 'admin', aal2, 'stepUp'],
    ['admin: aal1', asAdmin(member()), 'admin', { ...aal1, fresh: true }, 'stepUp'],
    ['admin: session rules settle without an identity', null, 'admin', aal1, 'stepUp'],
    ['emailed code: admin account', asAdmin(member()), 'emailed-code', null, 'deny'],
    ['emailed code: member', withTotp(member()), 'emailed-code', null, 'allow'],
    ['emailed code: no identity to refuse', null, 'emailed-code', null, 'allow'],
  ];

  it.each(cases)('%s', (_name, i, target, session, expected) => {
    expect(Object.keys(decideAccess(i, target, session, [x]))).toEqual([expected]);
  });
});

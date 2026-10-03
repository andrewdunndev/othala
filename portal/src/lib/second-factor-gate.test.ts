import { describe, it, expect } from 'vitest';
import { secondFactorChangeVerdict, SECOND_FACTOR_KEEP, SECOND_FACTOR_UNAVAILABLE } from './second-factor-gate';
import type { Identity } from './types';
import { asAdmin, identity, manifest, withCredential, withLookupSecret, withPasskey, withTotp, withWebauthnKey } from './test-builders';

const KEEP = { refuse: true, text: SECOND_FACTOR_KEEP };
const UNAVAILABLE = { refuse: true, text: SECOND_FACTOR_UNAVAILABLE };
const ALLOW = { refuse: false };

const key = (i: Identity) => withWebauthnKey(i);
const passwordlessKey = (i: Identity) => withWebauthnKey(i, { passwordless: true });

function build(...steps: Array<(i: Identity) => Identity>): Identity {
  return steps.reduce((i, step) => step(i), identity());
}

describe('secondFactorChangeVerdict — admin', () => {
  const cases: Array<[string, Identity, 'totp' | 'webauthn', object]> = [
    ['totp only, totp change (unlink)', build(asAdmin, withTotp), 'totp', KEEP],
    ['totp + backup codes + passkey, totp change', build(asAdmin, withTotp, withLookupSecret, withPasskey), 'totp', KEEP],
    ['totp + passwordless key, totp change', build(asAdmin, withTotp, passwordlessKey), 'totp', KEEP],
    ['totp + key, totp change', build(asAdmin, withTotp, key), 'totp', ALLOW],
    ['key only, totp change (link)', build(asAdmin, key), 'totp', ALLOW],
    ['totp + key, webauthn change', build(asAdmin, withTotp, key), 'webauthn', ALLOW],
    ['two keys, webauthn change', build(asAdmin, key, key), 'webauthn', ALLOW],
    ['one key, webauthn change (removal possible)', build(asAdmin, key), 'webauthn', KEEP],
    ['one key + passwordless key, webauthn change', build(asAdmin, key, passwordlessKey), 'webauthn', KEEP],
    ['totp only, webauthn change (add)', build(asAdmin, withTotp), 'webauthn', ALLOW],
    ['no second factor, totp change (link)', build(asAdmin), 'totp', ALLOW],
    ['no second factor, webauthn change', build(asAdmin, passwordlessKey), 'webauthn', ALLOW],
  ];
  it.each(cases)('%s', (_name, stored, method, expected) => {
    expect(secondFactorChangeVerdict(stored, method)).toEqual(expected);
  });
});

describe('secondFactorChangeVerdict — member', () => {
  it.each(['totp', 'webauthn'])('allows removing the last second factor (%s)', (method) => {
    expect(secondFactorChangeVerdict(build(withTotp), method)).toEqual(ALLOW);
    expect(secondFactorChangeVerdict(build(key), method)).toEqual(ALLOW);
  });

  it('allows a member whose read carried no credential configs', () => {
    expect(secondFactorChangeVerdict({ ...build(withTotp), credentials: undefined }, 'totp')).toEqual(ALLOW);
  });
});

describe('secondFactorChangeVerdict — elevated member', () => {
  const manifests = [manifest('x', ['admin', 'user'], { 'x-admin': 'admin', 'x-access': 'user' }, ['x-access'])];
  const elevated = (i: Identity): Identity => ({ ...i, metadata_admin: { groups: ['x-admin'] } });
  const verdict = (stored: Identity, method: string) => secondFactorChangeVerdict(stored, method, manifests);

  it('keeps the only totp', () => {
    expect(verdict(build(elevated, withTotp), 'totp')).toEqual(KEEP);
  });

  it('allows dropping totp when a key remains', () => {
    expect(verdict(build(elevated, withTotp, key), 'totp')).toEqual(ALLOW);
  });

  it('refuses when the read carried no credential configs', () => {
    expect(verdict({ ...build(elevated, withTotp), credentials: undefined }, 'totp')).toEqual(UNAVAILABLE);
  });

  it('leaves an entry-level member alone', () => {
    const member = (i: Identity): Identity => ({ ...i, metadata_admin: { groups: ['x-access'] } });
    expect(verdict(build(member, withTotp), 'totp')).toEqual(ALLOW);
  });
});

describe('secondFactorChangeVerdict — fails closed', () => {
  it('refuses a missing identity or an unknown method', () => {
    expect(secondFactorChangeVerdict(null, 'totp')).toEqual(UNAVAILABLE);
    expect(secondFactorChangeVerdict(undefined, 'webauthn')).toEqual(UNAVAILABLE);
    expect(secondFactorChangeVerdict(build(asAdmin, withTotp), 'password')).toEqual(UNAVAILABLE);
    expect(secondFactorChangeVerdict(build(withTotp), '')).toEqual(UNAVAILABLE);
  });

  it('refuses an admin whose read carried no credentials', () => {
    expect(secondFactorChangeVerdict({ ...build(asAdmin, withTotp), credentials: undefined }, 'totp')).toEqual(UNAVAILABLE);
  });

  it('refuses an admin whose totp or webauthn entry came back without config', () => {
    const noConfig = (type: string) => (i: Identity): Identity => {
      const { config: _c, ...entry } = i.credentials![type]!;
      return { ...i, credentials: { ...i.credentials, [type]: entry } as Identity['credentials'] };
    };
    expect(secondFactorChangeVerdict(build(asAdmin, withTotp, key, noConfig('totp')), 'webauthn')).toEqual(UNAVAILABLE);
    expect(secondFactorChangeVerdict(build(asAdmin, withTotp, noConfig('webauthn')), 'totp')).toEqual(UNAVAILABLE);
  });

  it('treats a totp entry without a totp_url as not enrolled', () => {
    const stale = build(asAdmin, key, (i) => withCredential(i, 'totp', {}));
    expect(secondFactorChangeVerdict(stale, 'totp')).toEqual(ALLOW);
    expect(secondFactorChangeVerdict(stale, 'webauthn')).toEqual(KEEP);
  });
});

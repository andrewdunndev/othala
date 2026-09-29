import { describe, it, expect } from 'vitest';
import { needsStepUp, hasSecondFactor } from './step-up';
import type { Identity } from './types';
import { identity as buildIdentity, withCredential, withLookupSecret, withPasskey, withTotp, withWebauthnKey } from './test-builders';

// Credential variants over the builder's admin-API identity, which always
// carries the schema's password and webauthn entries (identifiers, no keys).
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

describe('hasSecondFactor', () => {
  it('reads an identity with no credentials map as none', () => {
    expect(hasSecondFactor({ ...identity([]), credentials: undefined })).toBe(false);
  });
});

// Invariant: only a strict boolean true admin marker confers admin, and a second factor is what Kratos counts.

import { describe, it, expect } from 'vitest';
import { parseIdentity } from './identity-facts.js';
import type { Identity } from './types.js';
import { asAdmin, identity, whoamiIdentity, withCredential, withPasskey, withTotp, withWebauthnKey } from './test-builders.js';

function makeIdentity(metadataAdmin?: Record<string, unknown>): Identity {
  return identity({ metadataAdmin: metadataAdmin as Identity['metadata_admin'] });
}

describe('parseIdentity isAdmin — marker present and true', () => {
  it('returns true when metadata_admin.admin === true (boolean)', () => {
    const identity = makeIdentity({ admin: true });
    expect(parseIdentity(identity).isAdmin).toBe(true);
  });

  it('returns true with other metadata_admin fields present alongside admin:true', () => {
    const identity = makeIdentity({ groups: ['admin'], roles: { myapp: 'editor' }, admin: true });
    expect(parseIdentity(identity).isAdmin).toBe(true);
  });
});

describe('parseIdentity isAdmin — marker absent', () => {
  it('returns false when metadata_admin is undefined', () => {
    const identity = makeIdentity(undefined);
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when metadata_admin is an empty object (no admin key)', () => {
    const identity = makeIdentity({});
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when metadata_admin has groups but no admin key', () => {
    const identity = makeIdentity({ groups: ['admin', 'family'] });
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });
});

describe('parseIdentity isAdmin — marker wrong value (fail-closed strict equality)', () => {
  it('returns false when admin is boolean false', () => {
    const identity = makeIdentity({ admin: false });
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when admin is string "true" (not boolean)', () => {
    const identity = makeIdentity({ admin: 'true' } as Record<string, unknown>);
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when admin is number 1 (not boolean)', () => {
    const identity = makeIdentity({ admin: 1 } as Record<string, unknown>);
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when admin is null', () => {
    const identity = makeIdentity({ admin: null } as Record<string, unknown>);
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when admin is 0 (falsy number)', () => {
    const identity = makeIdentity({ admin: 0 } as Record<string, unknown>);
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when admin is an object (not boolean)', () => {
    const identity = makeIdentity({ admin: { value: true } } as Record<string, unknown>);
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });
});

describe('parseIdentity isAdmin — null/undefined identity (fail-closed)', () => {
  it('returns false for null identity', () => {
    expect(parseIdentity(null).isAdmin).toBe(false);
  });

  it('returns false for undefined identity', () => {
    expect(parseIdentity(undefined).isAdmin).toBe(false);
  });
});

describe('parseIdentity isAdmin — malformed metadata_admin', () => {
  it('returns false when metadata_admin is an array (not an object)', () => {
    const identity = { ...makeIdentity(), metadata_admin: [{ admin: true }] as unknown as Identity['metadata_admin'] };
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });

  it('returns false when metadata_admin is a string', () => {
    const identity = { ...makeIdentity(), metadata_admin: 'admin' as unknown as Identity['metadata_admin'] };
    expect(parseIdentity(identity).isAdmin).toBe(false);
  });
});


describe('parseIdentity credentials', () => {
  const bare = identity({ password: false });
  const cases: Array<[string, Identity, Record<string, unknown>]> = [
    ['password only', identity(), { authenticator: false, securityKeys: 0, hasSecondFactor: false, firstFactorKey: true }],
    ['schema entries only', bare, { securityKeys: 0, hasSecondFactor: false, firstFactorKey: false }],
    ['authenticator app', withTotp(bare), { authenticator: true, hasSecondFactor: true, firstFactorKey: false }],
    ['totp entry without a url', withCredential(bare, 'totp', {}), { authenticator: false, hasSecondFactor: false }],
    ['totp entry with an empty url', withCredential(bare, 'totp', { totp_url: '' }), { authenticator: false, hasSecondFactor: false }],
    ['security key', withWebauthnKey(bare), { securityKeys: 1, hasSecondFactor: true, firstFactorKey: false }],
    ['passwordless webauthn key', withWebauthnKey(bare, { passwordless: true }), { securityKeys: 0, hasSecondFactor: false, firstFactorKey: true }],
    ['passkey', withPasskey(bare), { hasSecondFactor: false, firstFactorKey: true }],
    ['whoami identity (credentials not read)', whoamiIdentity(asAdmin(withTotp(bare))), { isAdmin: false, hasSecondFactor: false, firstFactorKey: true }],
  ];

  it.each(cases)('%s', (_name, i, want) => {
    expect(parseIdentity(i)).toMatchObject(want);
  });

  it('reads groups as stored, keeping only strings', () => {
    expect(parseIdentity(makeIdentity({ groups: ['family', 'Bad Name', 3, null] })).groups).toEqual(['family', 'Bad Name']);
    expect(parseIdentity(makeIdentity({ groups: 'family' })).groups).toEqual([]);
    expect(parseIdentity(null)).toMatchObject({ state: undefined, groups: [], hasSecondFactor: false });
  });
});

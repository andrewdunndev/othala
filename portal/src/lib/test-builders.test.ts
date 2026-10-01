import { describe, it, expect } from 'vitest';
import { INCLUDED_CREDENTIALS } from './admin-api';
import { identity, session, withTotp, withWebauthnKey, withPasskey, withLookupSecret, asAdmin, whoamiIdentity } from './test-builders';
import { parseIdentity } from './identity-facts';

describe('identity builder defaults', () => {
  it('carries the schema webauthn entry with identifiers and no keys', () => {
    const webauthn = identity().credentials?.webauthn;
    expect(webauthn?.identifiers).toEqual(['ada.lovelace']);
    expect(webauthn?.config).toEqual({});
  });

  it('returns config for every requested credential type and none for the rest', () => {
    const creds = withLookupSecret(withPasskey(withTotp(identity()))).credentials ?? {};
    for (const t of INCLUDED_CREDENTIALS) expect(creds[t]?.config, t).toBeDefined();
    for (const [t, c] of Object.entries(creds)) {
      if (!(INCLUDED_CREDENTIALS as string[]).includes(t)) expect(c.config, t).toBeUndefined();
    }
  });

  it('holds no second factor until one is added', () => {
    expect(parseIdentity(identity()).hasSecondFactor).toBe(false);
    expect(parseIdentity(withTotp(identity())).hasSecondFactor).toBe(true);
    expect(parseIdentity(withWebauthnKey(identity())).hasSecondFactor).toBe(true);
    expect(parseIdentity(withWebauthnKey(identity(), { passwordless: true })).hasSecondFactor).toBe(false);
  });

  it('asAdmin keeps existing metadata_admin fields', () => {
    expect(asAdmin(identity({ metadataAdmin: { groups: ['family'] } })).metadata_admin).toEqual({ groups: ['family'], admin: true });
  });
});

describe('session builder defaults', () => {
  it('embeds the whoami identity without credentials or metadata_admin', () => {
    const s = session();
    expect(s.identity?.credentials).toBeUndefined();
    expect(s.identity?.metadata_admin).toBeUndefined();
    expect(whoamiIdentity(asAdmin(identity())).metadata_admin).toBeUndefined();
  });

  it('records methods in step-up order', () => {
    const s = session('aal2', ['password', 'totp']);
    expect(s.authentication_methods?.map((m) => [m.method, m.aal])).toEqual([
      ['password', 'aal1'],
      ['totp', 'aal2'],
    ]);
  });
});

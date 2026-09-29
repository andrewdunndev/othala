// Typed builders for Kratos and Hydra shapes in unit tests.
//
// Defaults reproduce what Kratos v26.2.0 and Hydra return to the portal, so a
// fixture starts realistic and a test states only what it varies. Kratos
// source references are paths in ory/kratos at v26.2.0.

import type {
  IdentityCredentials,
  OAuth2Client,
  OAuth2ConsentRequest,
  OAuth2LoginRequest,
  OAuth2LogoutRequest,
  SessionAuthenticationMethod,
} from '@ory/client-fetch';
import type { AAL, Identity, Session } from './types';

const STAMP = new Date('2026-01-01T00:00:00Z');

type Credentials = NonNullable<Identity['credentials']>;
type Traits = { username: string; email: string; recoveryEmail?: string; displayName?: string };

function cred(type: string, identifiers: string[], config?: object, version = 0): IdentityCredentials {
  return {
    type: type as IdentityCredentials['type'],
    identifiers,
    ...(config === undefined ? {} : { config }),
    version,
    created_at: STAMP,
    updated_at: STAMP,
  };
}

export interface IdentityOptions {
  id?: string;
  username?: string;
  email?: string;
  recoveryEmail?: string;
  displayName?: string;
  schemaId?: string;
  state?: 'active' | 'inactive';
  /** false: the password entry carries identifiers only (no password set). */
  password?: boolean;
  verified?: boolean;
  metadataAdmin?: Identity['metadata_admin'];
}

/**
 * An identity as the admin API returns it from getIdentity (credentials
 * included for the types admin-api.ts requests).
 *
 * The schema marks username as a password and webauthn identifier and email
 * as a password and code identifier, so every identity carries all three
 * entries whether or not the member enrolled anything
 * (identity/extension_credentials.go:35-52, :66-122). An entry stored without
 * config is persisted as {} (persistence/sql/identity/persister_identity.go:302)
 * and returned as {} when requested; a type not requested comes back without
 * config (identity/identity.go:479-483). 'code' is not requested.
 */
export function identity(opts: IdentityOptions = {}): Identity {
  const id = opts.id ?? 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const username = opts.username ?? 'ada.lovelace';
  const email = opts.email ?? `${username}@othala.test`;
  const schemaId = opts.schemaId ?? 'family';
  const traits: Traits = { username, email };
  if (opts.recoveryEmail !== undefined) traits.recoveryEmail = opts.recoveryEmail;
  if (opts.displayName !== undefined) traits.displayName = opts.displayName;

  const verified = opts.verified ?? true;
  const addresses = [email, ...(opts.recoveryEmail === undefined ? [] : [opts.recoveryEmail])];

  return {
    id,
    schema_id: schemaId,
    schema_url: `http://kratos:4433/schemas/${Buffer.from(schemaId).toString('base64url')}`,
    state: opts.state ?? 'active',
    state_changed_at: STAMP,
    traits,
    verifiable_addresses: addresses.map((value) => ({
      value,
      via: 'email' as const,
      verified,
      status: verified ? 'completed' : 'pending',
      ...(verified ? { verified_at: STAMP } : {}),
      created_at: STAMP,
      updated_at: STAMP,
    })),
    recovery_addresses: addresses.map((value) => ({ id: `ra-${value}`, value, via: 'email' as const, created_at: STAMP, updated_at: STAMP })),
    credentials: {
      password: cred(
        'password',
        [username, email],
        opts.password === false ? {} : { hashed_password: '$argon2id$v=19$m=65536,t=1,p=2$c2FsdA$aGFzaA' },
      ),
      webauthn: cred('webauthn', [username], {}),
      code: cred('code', [email], undefined, 1),
    },
    ...(opts.metadataAdmin === undefined ? {} : { metadata_admin: opts.metadataAdmin }),
    created_at: STAMP,
    updated_at: STAMP,
  };
}

/** Replace (or add) one credential entry. For variants the helpers below do not cover. */
export function withCredential(i: Identity, type: string, config: object, identifiers?: string[]): Identity {
  const prior = i.credentials?.[type];
  return {
    ...i,
    credentials: {
      ...i.credentials,
      [type]: cred(type, identifiers ?? prior?.identifiers ?? [i.id], config, prior?.version ?? 0),
    } as Credentials,
  };
}

/** TOTP enrolled via settings: identifier is the identity id (selfservice/strategy/totp/settings.go:205). */
export function withTotp(i: Identity): Identity {
  return withCredential(i, 'totp', { totp_url: `otpauth://totp/othala:${String(i.traits?.username ?? '')}?secret=JBSWY3DPEHPK3PXP&issuer=othala` }, [i.id]);
}

function webauthnKey(n: number, passwordless: boolean): object {
  // identity/credentials_webauthn.go:139-150; byte fields marshal as base64.
  return {
    id: Buffer.from(`key-${n}`).toString('base64'),
    public_key: 'cHVibGljLWtleQ==',
    attestation_type: 'none',
    authenticator: { aaguid: 'AAAAAAAAAAAAAAAAAAAAAA==', sign_count: 0, clone_warning: false },
    display_name: `key ${n}`,
    added_at: STAMP.toISOString(),
    is_passwordless: passwordless,
  };
}

type WebauthnConfig = { credentials?: object[]; user_handle?: string };

/** A security key on the schema's webauthn entry; identifiers stay the username. */
export function withWebauthnKey(i: Identity, { passwordless = false }: { passwordless?: boolean } = {}): Identity {
  const prior = (i.credentials?.webauthn?.config ?? {}) as WebauthnConfig;
  const keys = prior.credentials ?? [];
  return withCredential(i, 'webauthn', {
    credentials: [...keys, webauthnKey(keys.length + 1, passwordless)],
    user_handle: Buffer.from(i.id).toString('base64'),
  });
}

/** A passkey: identifier is the WebAuthn user handle (selfservice/strategy/passkey/passkey_registration.go:184). */
export function withPasskey(i: Identity): Identity {
  const handle = Buffer.from(i.id).toString('base64');
  return withCredential(i, 'passkey', { credentials: [webauthnKey(1, true)], user_handle: handle }, [handle]);
}

/** Backup codes: identifier is the identity id (selfservice/strategy/lookup/settings.go:304). */
export function withLookupSecret(i: Identity): Identity {
  return withCredential(i, 'lookup_secret', { recovery_codes: [{ code: 'aaaa-bbbb' }, { code: 'cccc-dddd' }] }, [i.id]);
}

export function asAdmin(i: Identity): Identity {
  return { ...i, metadata_admin: { ...i.metadata_admin, admin: true } };
}

/** The identity as /sessions/whoami embeds it: no credentials, no metadata_admin (identity/identity.go:361-370). */
export function whoamiIdentity(i: Identity): Identity {
  const { credentials: _c, metadata_admin: _m, ...rest } = i;
  return rest;
}

type MethodName = NonNullable<SessionAuthenticationMethod['method']>;

/**
 * A /sessions/whoami session (session/session.go:76-127). A method given by
 * name completes now; the first counts as aal1 and later ones as aal2, the
 * order of a step-up.
 */
export function session(
  aal: AAL = 'aal1',
  methods: Array<MethodName | SessionAuthenticationMethod> = ['password'],
  overrides: Partial<Session> = {},
): Session {
  const now = new Date();
  return {
    id: 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
    active: true,
    expires_at: new Date(now.getTime() + 24 * 60 * 60 * 1000),
    authenticated_at: now,
    issued_at: now,
    authenticator_assurance_level: aal,
    authentication_methods: methods.map((m, n) =>
      typeof m === 'string' ? { method: m, aal: n === 0 ? 'aal1' : 'aal2', completed_at: now } : m,
    ),
    identity: whoamiIdentity(identity()),
    devices: [],
    ...overrides,
  };
}

export function oauth2Client(overrides: Partial<OAuth2Client> = {}): OAuth2Client {
  return { client_id: 'grafana', client_name: 'Grafana', skip_consent: false, ...overrides };
}

export function oauth2LoginRequest(overrides: Partial<OAuth2LoginRequest> = {}): OAuth2LoginRequest {
  return {
    challenge: 'lc',
    client: oauth2Client(),
    request_url: 'https://grafana.othala.test/login/generic_oauth',
    requested_scope: ['openid', 'email', 'profile'],
    requested_access_token_audience: [],
    skip: false,
    subject: '',
    ...overrides,
  };
}

export function oauth2ConsentRequest(overrides: Partial<OAuth2ConsentRequest> = {}): OAuth2ConsentRequest {
  return {
    challenge: 'cc',
    client: oauth2Client(),
    login_challenge: 'lc',
    request_url: 'https://grafana.othala.test/login/generic_oauth',
    requested_scope: ['openid', 'email', 'profile'],
    requested_access_token_audience: [],
    skip: false,
    subject: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    ...overrides,
  };
}

export function oauth2LogoutRequest(overrides: Partial<OAuth2LogoutRequest> = {}): OAuth2LogoutRequest {
  return {
    challenge: 'gc',
    client: oauth2Client(),
    request_url: 'https://sso.othala.test/oauth2/sessions/logout',
    rp_initiated: true,
    sid: 'bbbbbbbb-cccc-dddd-eeee-ffffffffffff',
    subject: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    ...overrides,
  };
}

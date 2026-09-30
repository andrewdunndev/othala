// Invariant: builders reproduce Kratos v26.2.0 and Hydra shapes; tests state only what they vary.

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
  password?: boolean;
  verified?: boolean;
  metadataAdmin?: Identity['metadata_admin'];
}

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

export function withTotp(i: Identity): Identity {
  return withCredential(i, 'totp', { totp_url: `otpauth://totp/othala:${String(i.traits?.username ?? '')}?secret=JBSWY3DPEHPK3PXP&issuer=othala` }, [i.id]);
}

function webauthnKey(n: number, passwordless: boolean): object {
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

export function withWebauthnKey(i: Identity, { passwordless = false }: { passwordless?: boolean } = {}): Identity {
  const prior = (i.credentials?.webauthn?.config ?? {}) as WebauthnConfig;
  const keys = prior.credentials ?? [];
  return withCredential(i, 'webauthn', {
    credentials: [...keys, webauthnKey(keys.length + 1, passwordless)],
    user_handle: Buffer.from(i.id).toString('base64'),
  });
}

export function withPasskey(i: Identity): Identity {
  const handle = Buffer.from(i.id).toString('base64');
  return withCredential(i, 'passkey', { credentials: [webauthnKey(1, true)], user_handle: handle }, [handle]);
}

export function withLookupSecret(i: Identity): Identity {
  return withCredential(i, 'lookup_secret', { recovery_codes: [{ code: 'aaaa-bbbb' }, { code: 'cccc-dddd' }] }, [i.id]);
}

export function asAdmin(i: Identity): Identity {
  return { ...i, metadata_admin: { ...i.metadata_admin, admin: true } };
}

export function whoamiIdentity(i: Identity): Identity {
  const { credentials: _c, metadata_admin: _m, ...rest } = i;
  return rest;
}

type MethodName = NonNullable<SessionAuthenticationMethod['method']>;

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

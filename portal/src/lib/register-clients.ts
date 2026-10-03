// In-app OIDC client registration, the TS successor to util/apply-clients.sh. Each manifest's `oidc:` block (never
// `consent:`) is pushed to Hydra as a typed OAuth2Client body via OAuth2Api, with the secret from
// `<CLIENT_ID_UPPER>_CLIENT_SECRET` in env (never hardcoded; a missing one is a hard error unless allowMissingSecret).
// Idempotent: getOAuth2Client decides create (404) versus update (200).

import {
  Configuration,
  OAuth2Api,
  ResponseError,
  type OAuth2Client,
} from '@ory/client-fetch';
import {
  oidcClientManifests,
  assertManifestsValid,
  CLIENT_ID_ENV_STEM_RE,
  type ClientManifest,
} from './manifests';
import { HYDRA_ADMIN_URL } from './constants';
import { timeoutFetch } from './ory-fetch';
import { clientSecretEnv } from './config';

/** The slice of OAuth2Api the registrar needs, so tests can inject a stub. */
export interface OAuth2ClientApi {
  getOAuth2Client(req: { id: string }): Promise<OAuth2Client>;
  createOAuth2Client(req: { oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
  setOAuth2Client(req: { id: string; oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
}

export interface RegisterOptions {
  /** Stub for tests; defaults to a real OAuth2Api on the Hydra admin URL. */
  api?: OAuth2ClientApi;
  /** Per-client secret source; defaults to the process environment. */
  env?: Record<string, string | undefined>;
  /** Skip the validateClients lint; default false so a bad manifest set cannot half-register. */
  skipValidation?: boolean;
  /** Tolerate a missing `<SLUG>_CLIENT_SECRET` and register without it (dry-run); default false is a hard error. */
  allowMissingSecret?: boolean;
}

export interface RegisterResult {
  clientId: string;
  action: 'created' | 'updated';
}

/**
 * Env var name for a client's secret, e.g. grafana -> GRAFANA_CLIENT_SECRET. Throws if `clientId` is not a valid
 * POSIX env-var stem (a hyphenated id gives an unresolvable name); validateClients rule 1a rejects it at load, so this
 * is defence in depth for callers that skip validation. Fail loud, never silently sanitize.
 */
export function secretEnvVar(clientId: string): string {
  if (!CLIENT_ID_ENV_STEM_RE.test(clientId)) {
    const wouldBe = `${clientId.toUpperCase()}_CLIENT_SECRET`;
    throw new Error(
      `client_id ${JSON.stringify(clientId)} is not a valid POSIX env-var stem ` +
        `(^[A-Za-z_][A-Za-z0-9_]*$). The registrar would derive ` +
        `${JSON.stringify(wouldBe)} which is not a valid shell variable and will ` +
        `never resolve. Rename the client_id to use only letters, digits, and ` +
        `underscores (manifest-lint rule 1a catches this at load time).`,
    );
  }
  return `${clientId.toUpperCase()}_CLIENT_SECRET`;
}

function defaultApi(): OAuth2ClientApi {
  return new OAuth2Api(new Configuration({ basePath: HYDRA_ADMIN_URL, fetchApi: timeoutFetch() })) as unknown as OAuth2ClientApi;
}

/** Build the Hydra OAuth2Client body from a manifest + secret: only `oidc:` fields, optional ones omitted when empty, the secret as a typed field. */
export function buildClientBody(
  m: ClientManifest,
  secret: string | undefined,
): OAuth2Client {
  const body: OAuth2Client = {
    client_id: m.clientId,
  };
  if (m.clientName) body.client_name = m.clientName;
  if (m.grantTypes.length > 0) body.grant_types = m.grantTypes;
  if (m.responseTypes.length > 0) body.response_types = m.responseTypes;
  if (m.scope) body.scope = m.scope;
  if (m.redirectUris.length > 0) body.redirect_uris = m.redirectUris;
  if (m.postLogoutRedirectUris.length > 0) {
    body.post_logout_redirect_uris = m.postLogoutRedirectUris;
  }
  if (m.audience.length > 0) body.audience = m.audience;
  if (m.tokenEndpointAuthMethod) {
    body.token_endpoint_auth_method = m.tokenEndpointAuthMethod;
  }
  if (m.skipConsent) body.skip_consent = true;
  if (m.backchannelLogoutUri) body.backchannel_logout_uri = m.backchannelLogoutUri;
  if (m.backchannelLogoutSessionRequired) {
    body.backchannel_logout_session_required = true;
  }
  if (secret) body.client_secret = secret;
  return body;
}

/** Resolve a per-client secret from env. */
function resolveSecret(
  m: ClientManifest,
  env: Record<string, string | undefined>,
  allowMissing: boolean,
): string | undefined {
  const name = secretEnvVar(m.clientId);
  const secret = env[name];
  if (!secret) {
    if (allowMissing) return undefined;
    throw new Error(`${name} not set in environment for client ${m.clientId}`);
  }
  return secret;
}

/** True iff the SDK error is an HTTP 404 (client does not exist yet). */
function isNotFound(err: unknown): boolean {
  return err instanceof ResponseError && err.response?.status === 404;
}

/** Register (create or update) one client in Hydra; exposed for tests and targeted re-apply. */
export async function registerClient(
  api: OAuth2ClientApi,
  m: ClientManifest,
  secret: string | undefined,
): Promise<RegisterResult> {
  const body = buildClientBody(m, secret);

  let exists = false;
  try {
    await api.getOAuth2Client({ id: m.clientId });
    exists = true;
  } catch (err) {
    if (!isNotFound(err)) throw err;
    exists = false;
  }

  if (exists) {
    await api.setOAuth2Client({ id: m.clientId, oAuth2Client: body });
    return { clientId: m.clientId, action: 'updated' };
  }
  await api.createOAuth2Client({ oAuth2Client: body });
  return { clientId: m.clientId, action: 'created' };
}

/**
 * Run validateClients (unless skipValidation), then register every manifest idempotently, returning the per-client
 * actions. Create-or-update only, never deletes, so a decommissioned client survives until removed by hand.
 */
export async function registerAllClients(
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  // Narrow through oidcClientManifests: presentation-only tiles have no client or secret, so an unfiltered set would
  // throw at boot and on every SIGHUP (swallowed by registrar.ts), leaving Hydra with zero clients.
  const manifests = oidcClientManifests();
  return registerManifests(manifests, opts);
}

/** Register an explicit manifest set, without the on-disk loader (for callers and tests). */
export async function registerManifests(
  manifests: ClientManifest[],
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  const env = opts.env ?? clientSecretEnv();
  const api = opts.api ?? defaultApi();

  if (!opts.skipValidation) {
    assertManifestsValid(manifests);
  }

  const results: RegisterResult[] = [];
  for (const m of manifests) {
    const secret = resolveSecret(m, env, Boolean(opts.allowMissingSecret));
    results.push(await registerClient(api, m, secret));
  }
  return results;
}

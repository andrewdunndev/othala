// In-app OIDC client registration — the TS successor to util/apply-clients.sh.
//
// CU2 item 2. apply-clients.sh read the per-app <slug>.yaml manifests, extracted the
// `oidc:` block, injects a per-client secret from the environment, and
// POST/PUTs each client to Hydra's admin API (/admin/clients). This module
// does the same through the C1 @ory/client-fetch OAuth2Api with a TYPED
// body — no `yq -j` string concatenation, no shell interpolation of the
// secret into a JSON string.
//
// Field mapping (manifest oidc: → Hydra OAuth2Client), matching exactly
// what apply-clients.sh forwarded (it sent the whole `oidc:` mapping
// verbatim plus `client_secret`):
//
//   client_id                        -> client_id
//   client_name                      -> client_name
//   grant_types                      -> grant_types
//   response_types                   -> response_types
//   scope (space-joined string)      -> scope
//   redirect_uris                    -> redirect_uris
//   post_logout_redirect_uris        -> post_logout_redirect_uris
//   audience                         -> audience
//   token_endpoint_auth_method       -> token_endpoint_auth_method
//   skip_consent                     -> skip_consent
//   backchannel_logout_uri           -> backchannel_logout_uri
//   backchannel_logout_session_required -> backchannel_logout_session_required
//   <SLUG>_CLIENT_SECRET (env)       -> client_secret
//
// Anything under `consent:` is NEVER forwarded — same namespace boundary
// the shell enforced (it extracted `.oidc` only).
//
// Idempotency: getOAuth2Client(client_id) decides create vs update. A 404
// (ResponseError) means "create" (POST/createOAuth2Client); a 200 means
// "update" (PUT/setOAuth2Client). This mirrors the shell's HTTP-status
// branch.
//
// Secrets: read from process.env per client, named `<CLIENT_ID_UPPER>_CLIENT_SECRET`
// — the same convention apply-clients.sh used (KEEP_CLIENT_SECRET,
// LLM_CLIENT_SECRET, …). Those are the `*_oidc_client_secret` sops keys the
// iac apply target exports into the container env. Never hardcoded, never
// derived; a missing secret is a hard error (unless allowMissingSecret is
// set for dry-run/diff workflows).

import {
  Configuration,
  OAuth2Api,
  ResponseError,
  type OAuth2Client,
} from '@ory/client-fetch';
import {
  loadClientManifests,
  assertManifestsValid,
  type ClientManifest,
} from './manifests';

/**
 * Minimal slice of the OAuth2Api the registrar needs. Declaring it here
 * lets the unit tests inject a stub without standing up a live Hydra, and
 * documents exactly which SDK calls cross the wire.
 */
export interface OAuth2ClientApi {
  getOAuth2Client(req: { id: string }): Promise<OAuth2Client>;
  createOAuth2Client(req: { oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
  setOAuth2Client(req: { id: string; oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
}

export interface RegisterOptions {
  /**
   * Inject a stub/mock for unit tests. Defaults to a real OAuth2Api bound
   * to HYDRA_ADMIN_URL (+ optional HYDRA_ADMIN_TOKEN bearer), matching
   * admin.ts's oauth2Api() construction.
   */
  api?: OAuth2ClientApi;
  /**
   * Source of per-client secrets. Defaults to process.env. Injectable so
   * tests don't have to mutate the global environment.
   */
  env?: Record<string, string | undefined>;
  /**
   * Skip the validateClients lint before registering. Default false — the
   * registrar refuses to push a manifest set that fails the lint, so a bad
   * audience or undeclared role can't half-register. Tests that exercise
   * field-mapping on a single crafted manifest set this true.
   */
  skipValidation?: boolean;
  /**
   * When true, a missing `<SLUG>_CLIENT_SECRET` is tolerated and the
   * client is registered without a secret in the body (dry-run / diff
   * posture, like apply-clients.sh DRY_RUN=1). Default false: a missing
   * secret is a hard error, matching the shell's non-dry-run branch.
   */
  allowMissingSecret?: boolean;
}

export interface RegisterResult {
  clientId: string;
  action: 'created' | 'updated';
}

/** Env var name carrying a client's secret, e.g. keep -> KEEP_CLIENT_SECRET. */
export function secretEnvVar(clientId: string): string {
  return `${clientId.toUpperCase()}_CLIENT_SECRET`;
}

function hydraAdminBase(): string {
  return process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445';
}

function defaultApi(): OAuth2ClientApi {
  const token = process.env.HYDRA_ADMIN_TOKEN ?? '';
  return new OAuth2Api(
    new Configuration({
      basePath: hydraAdminBase(),
      ...(token ? { accessToken: token } : {}),
    }),
  ) as unknown as OAuth2ClientApi;
}

/**
 * Build the Hydra OAuth2Client body from a parsed manifest + secret.
 *
 * Only `oidc:`-derived fields are set; the `consent:` block never reaches
 * Hydra. Optional fields are omitted when empty so the body matches what
 * apply-clients.sh produced (it forwarded only the keys present in the
 * yaml). The secret is set as a typed field, not concatenated into a JSON
 * string — the injection-safety requirement.
 */
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

/** Resolve a per-client secret from the env, applying the apply-clients.sh policy. */
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

/**
 * Register (create or update) a single client in Hydra. Exposed for the
 * tests and for targeted re-apply; registerAllClients drives the full set.
 */
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
 * Register every client from the loaded manifest set against Hydra.
 *
 * Runs the full validateClients lint first (unless skipValidation), then
 * registers each client idempotently. Returns the per-client action list.
 *
 * DORMANT until the E1 cutover: nothing invokes this yet. Client
 * registration stays shell-driven via util/apply-clients.sh; this is NOT
 * yet the live successor and apply-clients.sh is NOT superseded. E1 wires
 * the in-app path and flips the cutover.
 */
export async function registerAllClients(
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  const manifests = loadClientManifests();
  return registerManifests(manifests, opts);
}

/**
 * Register an explicit manifest set. Split out from registerAllClients so
 * callers (and tests) can register a crafted set without touching the
 * on-disk loader.
 */
export async function registerManifests(
  manifests: ClientManifest[],
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  const env = opts.env ?? process.env;
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

import type { OAuth2Client } from '@ory/client-fetch';
import {
  oidcClientManifests,
  CLIENT_ID_RE,
  type ClientManifest,
} from './manifests';
import { hydraAdmin, isNotFound } from './ory-fetch';
import { clientSecretEnv } from './config';

export interface OAuth2ClientApi {
  getOAuth2Client(req: { id: string }): Promise<OAuth2Client>;
  createOAuth2Client(req: { oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
  setOAuth2Client(req: { id: string; oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
}

export interface RegisterOptions {
  api?: OAuth2ClientApi;
  env?: Record<string, string | undefined>;
}

export interface RegisterResult {
  clientId: string;
  action: 'created' | 'updated';
}

/** Throws rather than sanitizing, so a malformed id never names a variable that cannot resolve. */
export function secretEnvVar(clientId: string): string {
  if (!CLIENT_ID_RE.test(clientId)) {
    throw new Error(`client_id ${JSON.stringify(clientId)} must match ${CLIENT_ID_RE}.`);
  }
  return `${clientId.toUpperCase()}_CLIENT_SECRET`;
}

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

function resolveSecret(
  m: ClientManifest,
  env: Record<string, string | undefined>,
): string | undefined {
  if (m.tokenEndpointAuthMethod === 'none') return undefined;
  const name = secretEnvVar(m.clientId);
  const secret = env[name];
  if (!secret) throw new Error(`${name} not set in environment for client ${m.clientId}`);
  return secret;
}

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

/** Never deletes: a decommissioned client stays in Hydra until removed by hand. */
export async function registerAllClients(
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  // Presentation-only tiles have no client or secret; unfiltered, every boot would throw and leave Hydra with no clients.
  const manifests = oidcClientManifests();
  return registerManifests(manifests, opts);
}

export async function registerManifests(
  manifests: ClientManifest[],
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  const env = opts.env ?? clientSecretEnv();
  const api = opts.api ?? (hydraAdmin() as unknown as OAuth2ClientApi);

  const results: RegisterResult[] = [];
  const failed: string[] = [];
  for (const m of manifests) {
    try {
      results.push(await registerClient(api, m, resolveSecret(m, env)));
    } catch (err) {
      failed.push(`${m.clientId} (${err instanceof Error ? err.message : String(err)})`);
    }
  }
  if (failed.length > 0) {
    throw new Error(`registration failed for ${failed.length} client(s): ${failed.join('; ')}`);
  }
  return results;
}

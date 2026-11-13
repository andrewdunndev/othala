import { createHash } from 'node:crypto';
import type { JsonPatch, OAuth2Client } from '@ory/client-fetch';
import {
  droppedManifests,
  loadClientManifests,
  needsClientSecret,
  oidcClientManifests,
  secretEnvVar,
  type ClientManifest,
} from './manifests';
import { hydraAdmin, isNotFound } from './ory-fetch';
import { clientSecretEnv } from './config';
import { listIdentities } from './admin-api';
import { nextPageToken } from './revoke';

export interface OAuth2ClientApi {
  getOAuth2Client(req: { id: string }): Promise<OAuth2Client>;
  createOAuth2Client(req: { oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
  setOAuth2Client(req: { id: string; oAuth2Client: OAuth2Client }): Promise<OAuth2Client>;
  revokeOAuth2ConsentSessions(req: { subject: string; client: string }): Promise<unknown>;
  listOAuth2ClientsRaw(req: { pageSize: number; pageToken?: string }): Promise<{ value(): Promise<OAuth2Client[]>; raw: { headers: Headers } }>;
  patchOAuth2Client(req: { id: string; jsonPatch: JsonPatch[] }): Promise<unknown>;
}

export interface RegisterOptions {
  api?: OAuth2ClientApi;
  env?: Record<string, string | undefined>;
  /** Every identity id; Hydra revokes consent per subject. Defaults to the Kratos admin list. */
  subjects?: () => Promise<string[]>;
}

/** What othala keeps in a Hydra client's metadata: its mark, the access fingerprint last applied, and whether the app is retired. */
interface OthalaMark {
  fingerprint?: string;
  retired?: boolean;
}

function markOf(c: OAuth2Client | undefined): OthalaMark | undefined {
  const m = (c?.metadata as { othala?: unknown } | null | undefined)?.othala;
  return m && typeof m === 'object' ? (m as OthalaMark) : undefined;
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

/**
 * A digest of what decides who an app lets in and what its tokens say: the access groups and gate flag, the group role
 * map, the roles (rank order and claim_emit), the groups claim switch and the scopes. Names, URIs and descriptions are
 * not access, so editing them does not end grants.
 */
export function accessFingerprint(m: ClientManifest): string {
  const access = {
    accessGroups: [...m.accessGroups].sort(),
    skipAccessCheck: m.skipAccessCheck,
    groupRoleMap: m.groupRoleMap,
    roles: m.roles.map((r) => ({ name: r.name, claimEmit: r.claimEmit })),
    emitGroupsClaim: m.emitGroupsClaim,
    scopes: [...m.scopes].sort(),
  };
  return createHash('sha256').update(canonical(access)).digest('hex');
}

type RevokeClient = (clientId: string) => Promise<void>;

/** Ends one client's consent sessions, and so its access and refresh tokens, for every identity. */
function clientRevoker(api: OAuth2ClientApi, subjects: () => Promise<string[]>): RevokeClient {
  return async (clientId) => {
    for (const subject of await subjects()) {
      try {
        await api.revokeOAuth2ConsentSessions({ subject, client: clientId });
      } catch (err) {
        if (!isNotFound(err)) throw err;
      }
    }
  };
}

export interface RegisterResult {
  clientId: string;
  action: 'created' | 'updated';
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
  if (!needsClientSecret(m)) return undefined;
  const name = secretEnvVar(m.clientId);
  const secret = env[name];
  if (!secret) throw new Error(`${name} not set in environment for client ${m.clientId}`);
  return secret;
}

export async function registerClient(
  api: OAuth2ClientApi,
  m: ClientManifest,
  secret: string | undefined,
  revoke: RevokeClient,
): Promise<RegisterResult> {
  const body = buildClientBody(m, secret);
  const fingerprint = accessFingerprint(m);

  let existing: OAuth2Client | undefined;
  try {
    existing = await api.getOAuth2Client({ id: m.clientId });
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }

  if (existing) {
    // A client with no stored fingerprint predates this check: it is baselined, not revoked. Revoking first and storing
    // the new fingerprint after means a failed revoke is retried on the next reconcile.
    const stored = markOf(existing)?.fingerprint;
    if (stored !== undefined && stored !== fingerprint) await revoke(m.clientId);
    body.metadata = { ...(existing.metadata as object | null), othala: { fingerprint } };
    await api.setOAuth2Client({ id: m.clientId, oAuth2Client: body });
    return { clientId: m.clientId, action: 'updated' };
  }
  body.metadata = { othala: { fingerprint } };
  await api.createOAuth2Client({ oAuth2Client: body });
  return { clientId: m.clientId, action: 'created' };
}

/** Never deletes: a decommissioned client stays in Hydra until removed by hand. */
export async function registerAllClients(
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  // Presentation-only tiles have no client or secret; unfiltered, every boot would throw and leave Hydra with no clients.
  const manifests = oidcClientManifests();
  const results = await registerManifests(manifests, opts);
  await retireAbsentClients(opts);
  return results;
}

/** Every manifest, only when the load is complete: none quarantined, the directory readable, at least one served. Otherwise null. */
function completeManifestSet(): ClientManifest[] | null {
  try {
    const all = loadClientManifests();
    return all.length > 0 && droppedManifests().length === 0 ? all : null;
  } catch {
    return null;
  }
}

/**
 * A client othala registered whose manifest is gone from a complete load has its grants ended once and is marked retired.
 * An incomplete load (quarantined file, unreadable directory, nothing served) proves nothing is absent, so it does nothing.
 */
async function retireAbsentClients(opts: RegisterOptions): Promise<void> {
  const present = completeManifestSet();
  if (!present) return;
  const api = opts.api ?? (hydraAdmin() as unknown as OAuth2ClientApi);
  const revoke = clientRevoker(api, opts.subjects ?? (async () => (await listIdentities()).map((i) => i.id)));
  const served = new Set(present.map((m) => m.clientId.toLowerCase()));
  const failed: string[] = [];
  let pageToken: string | undefined;
  do {
    const page = await api.listOAuth2ClientsRaw({ pageSize: 250, pageToken });
    for (const c of await page.value()) {
      const mark = markOf(c);
      if (!c.client_id || !mark || mark.retired || served.has(c.client_id.toLowerCase())) continue;
      try {
        await revoke(c.client_id);
        const metadata = { ...(c.metadata as object | null), othala: { ...mark, retired: true } };
        await api.patchOAuth2Client({ id: c.client_id, jsonPatch: [{ op: 'add', path: '/metadata', value: metadata }] });
      } catch (err) {
        failed.push(`${c.client_id} (${err instanceof Error ? err.message : String(err)})`);
      }
    }
    pageToken = nextPageToken(page.raw.headers);
  } while (pageToken);
  if (failed.length > 0) throw new Error(`retiring failed for ${failed.length} client(s): ${failed.join('; ')}`);
}

export async function registerManifests(
  manifests: ClientManifest[],
  opts: RegisterOptions = {},
): Promise<RegisterResult[]> {
  const env = opts.env ?? clientSecretEnv();
  const api = opts.api ?? (hydraAdmin() as unknown as OAuth2ClientApi);
  const revoke = clientRevoker(api, opts.subjects ?? (async () => (await listIdentities()).map((i) => i.id)));

  const results: RegisterResult[] = [];
  const failed: string[] = [];
  for (const m of manifests) {
    try {
      results.push(await registerClient(api, m, resolveSecret(m, env), revoke));
    } catch (err) {
      failed.push(`${m.clientId} (${err instanceof Error ? err.message : String(err)})`);
    }
  }
  if (failed.length > 0) {
    throw new Error(`registration failed for ${failed.length} client(s): ${failed.join('; ')}`);
  }
  return results;
}

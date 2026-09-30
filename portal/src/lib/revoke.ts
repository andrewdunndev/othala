// revokeSubject: the in-process revocation fan-out for admin force-logout, self-service sign-out-everywhere and
// deactivate, via the typed Ory SDK. Order is fixed: (1) deactivate only: Kratos state -> inactive, before 2;
// (2) Kratos sessions revoke, where 404 (no sessions) is success and continues; (3) Hydra login sessions, by sid then by subject;
// (4) Hydra consent sessions. A real failure throws a RevokeError naming the dependency and next action.

import {
  Configuration,
  IdentityApi,
  OAuth2Api,
  ResponseError,
  type JsonPatch,
} from '@ory/client-fetch';

/** Which upstream dependency a revoke step failed against. */
export type RevokeDependency = 'kratos-admin' | 'hydra-admin';

/** Prescriptive revoke failure: names the dependency and next action; the raw cause is for server logs only. */
export class RevokeError extends Error {
  readonly dependency: RevokeDependency;
  readonly step: string;
  override readonly cause?: unknown;
  constructor(dependency: RevokeDependency, step: string, nextAction: string, cause?: unknown) {
    super(`revoke step "${step}" failed against ${dependency}: ${nextAction}`);
    this.name = 'RevokeError';
    this.dependency = dependency;
    this.step = step;
    this.cause = cause;
  }
}

/** True for an HTTP 404; Kratos returns it from DELETE .../sessions when the subject has no active sessions. */
function isNotFound(err: unknown): boolean {
  return err instanceof ResponseError && err.response?.status === 404;
}

/** The portal-side revoke fan-out clients + the trigger flavour. */
export interface RevokeDeps {
  identityApi: IdentityApi;
  oauth2Api: OAuth2Api;
}

export interface RevokeOptions {
  /** deactivate trigger: run step 1 (state -> inactive) before step 2. */
  deactivate?: boolean;
}

/** Per-step outcome for the UI. */
export interface RevokeResult {
  subject: string;
  deactivated: boolean;
  kratosSessionsRevoked: boolean;
  hydraLoginRevoked: boolean;
  hydraConsentRevoked: boolean;
}

function kratosAdminBase(): string {
  return process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';
}

function hydraAdminBase(): string {
  return process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445';
}

function buildIdentityApi(): IdentityApi {
  const token = process.env.KRATOS_ADMIN_TOKEN ?? '';
  return new IdentityApi(
    new Configuration({
      basePath: kratosAdminBase(),
      ...(token ? { accessToken: token } : {}),
    }),
  );
}

function buildOAuth2Api(): OAuth2Api {
  const token = process.env.HYDRA_ADMIN_TOKEN ?? '';
  return new OAuth2Api(
    new Configuration({
      basePath: hydraAdminBase(),
      ...(token ? { accessToken: token } : {}),
    }),
  );
}

/** Resolve injected deps, defaulting to the live SDK clients. */
function resolveDeps(deps: Partial<RevokeDeps> = {}): RevokeDeps {
  return {
    identityApi: deps.identityApi ?? buildIdentityApi(),
    oauth2Api: deps.oauth2Api ?? buildOAuth2Api(),
  };
}

/** Distinct login-session ids named by the subject's consent rows, following the Link rel=next pages. */
async function listLoginSessionIds(oauth2Api: OAuth2Api, subject: string): Promise<string[]> {
  const sids = new Set<string>();
  let pageToken: string | undefined;
  do {
    const res = await oauth2Api.listOAuth2ConsentSessionsRaw({ subject, pageSize: 250, pageToken });
    for (const row of await res.value()) {
      const sid = row.consent_request?.login_session_id;
      if (sid) sids.add(sid);
    }
    const next = /<([^>]*)>\s*;\s*rel="?next"?/.exec(res.raw.headers.get('link') ?? '');
    pageToken = next ? (new URL(next[1], 'http://hydra').searchParams.get('page_token') ?? undefined) : undefined;
  } while (pageToken);
  return [...sids];
}

/** Run the fan-out for one subject (Kratos identity id); steps 1-4 abort on the first failure. */
export async function revokeSubject(
  subject: string,
  options: RevokeOptions = {},
  deps: Partial<RevokeDeps> = {},
): Promise<RevokeResult> {
  const d = resolveDeps(deps);
  const result: RevokeResult = {
    subject,
    deactivated: false,
    kratosSessionsRevoked: false,
    hydraLoginRevoked: false,
    hydraConsentRevoked: false,
  };

  // Step 1 (deactivate only): flip state first so a session re-minted in the race window is for an inactive identity.
  if (options.deactivate) {
    const patch: Array<JsonPatch> = [{ op: 'replace', path: '/state', value: 'inactive' }];
    try {
      await d.identityApi.patchIdentity({ id: subject, jsonPatch: patch });
      result.deactivated = true;
    } catch (err) {
      throw new RevokeError(
        'kratos-admin',
        'state->inactive',
        'Could not mark the identity inactive. Verify KRATOS_ADMIN_URL reachability and that the identity id exists, then retry the deactivate.',
        err,
      );
    }
  }

  // Step 2: a 404 means no active sessions, which counts as revoked; only a real failure aborts.
  try {
    await d.identityApi.deleteIdentitySessions({ id: subject });
    result.kratosSessionsRevoked = true;
  } catch (err) {
    if (isNotFound(err)) {
      result.kratosSessionsRevoked = true; // no active sessions == nothing to revoke
    } else {
      throw new RevokeError(
        'kratos-admin',
        'delete-sessions',
        'Could not revoke the subject\'s Kratos sessions; fan-out ABORTED (the subject may still hold a live session). Verify KRATOS_ADMIN_URL, then re-run the revoke.',
        err,
      );
    }
  }

  // Step 3: Hydra login-session revoke. Each session the subject's consent rows name is revoked by its own sid so Hydra
  // posts the back-channel logout token to that session's clients; the {subject} delete then sweeps sessions with no
  // row. Per-sid must precede step 4, which deletes the rows Hydra selects those clients from.
  let phase = 'list-consent-sessions';
  try {
    for (const sid of await listLoginSessionIds(d.oauth2Api, subject)) {
      phase = 'revoke-login-sessions';
      await d.oauth2Api.revokeOAuth2LoginSessions({ sid });
    }
    phase = 'revoke-login-sessions';
    await d.oauth2Api.revokeOAuth2LoginSessions({ subject });
    result.hydraLoginRevoked = true;
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      phase,
      'Kratos sessions are cut, but Hydra still remembers the login (remembered login still open — a fresh token could skip-login). Verify HYDRA_ADMIN_URL, then re-run the revoke (it is idempotent).',
      err,
    );
  }

  // Step 4: Hydra consent-session revoke.
  try {
    await d.oauth2Api.revokeOAuth2ConsentSessions({ subject, all: true });
    result.hydraConsentRevoked = true;
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      'revoke-consent-sessions',
      'Login sessions are cut, but Hydra consent + associated access tokens persist. Verify HYDRA_ADMIN_URL, then re-run the revoke (it is idempotent).',
      err,
    );
  }

  return result;
}

/**
 * Step 4 alone: revoke the subject's Hydra consent sessions for every client, used when an admin narrows groups,
 * roles or the admin marker so old grants and refresh tokens stop working. Login sessions are left alone.
 */
export async function revokeConsentSessions(
  subject: string,
  deps: Partial<Pick<RevokeDeps, 'oauth2Api'>> = {},
): Promise<void> {
  const oauth2Api = deps.oauth2Api ?? buildOAuth2Api();
  try {
    await oauth2Api.revokeOAuth2ConsentSessions({ subject, all: true });
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      'revoke-consent-sessions',
      'Hydra consent + associated tokens persist. Verify HYDRA_ADMIN_URL, then use Force re-login on this identity.',
      err,
    );
  }
}

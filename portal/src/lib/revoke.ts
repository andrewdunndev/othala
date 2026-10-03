// Session revocation over the typed Ory SDK. A failed step throws a RevokeError naming the dependency and next action.

import {
  Configuration,
  IdentityApi,
  OAuth2Api,
  ResponseError,
  type JsonPatch,
} from '@ory/client-fetch';
import { HYDRA_ADMIN_URL, KRATOS_ADMIN_URL } from './constants';
import { timeoutFetch } from './ory-fetch';

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

function buildIdentityApi(): IdentityApi {
  return new IdentityApi(new Configuration({ basePath: KRATOS_ADMIN_URL, fetchApi: timeoutFetch() }));
}

function buildOAuth2Api(): OAuth2Api {
  return new OAuth2Api(new Configuration({ basePath: HYDRA_ADMIN_URL, fetchApi: timeoutFetch() }));
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

/** Run the fan-out for one subject (Kratos identity id), aborting on the first failure. */
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

  // Inactive first, so a session re-minted in the race window belongs to an inactive identity.
  if (options.deactivate) {
    const patch: Array<JsonPatch> = [{ op: 'replace', path: '/state', value: 'inactive' }];
    try {
      await d.identityApi.patchIdentity({ id: subject, jsonPatch: patch });
      result.deactivated = true;
    } catch (err) {
      throw new RevokeError(
        'kratos-admin',
        'state->inactive',
        'Could not mark the identity inactive. Verify Kratos admin reachability and that the identity id exists, then retry the deactivate.',
        err,
      );
    }
  }

  try {
    await d.identityApi.deleteIdentitySessions({ id: subject });
  } catch (err) {
    if (!isNotFound(err)) {
      throw new RevokeError(
        'kratos-admin',
        'delete-sessions',
        'Could not revoke the subject\'s Kratos sessions; fan-out ABORTED (the subject may still hold a live session). Verify the Kratos admin API, then re-run the revoke.',
        err,
      );
    }
  }
  result.kratosSessionsRevoked = true;

  await revokeHydraSessions(subject, d);
  result.hydraLoginRevoked = true;
  result.hydraConsentRevoked = true;
  return result;
}

/** End the subject's Hydra login sessions on every device, then its consent sessions and their tokens. */
export async function revokeHydraSessions(
  subject: string,
  deps: Partial<Pick<RevokeDeps, 'oauth2Api'>> = {},
): Promise<void> {
  const oauth2Api = deps.oauth2Api ?? buildOAuth2Api();
  // Only a per-sid revoke posts back-channel logout, and Hydra picks its clients from the consent rows the last step deletes.
  let phase = 'list-consent-sessions';
  try {
    for (const sid of await listLoginSessionIds(oauth2Api, subject)) {
      phase = 'revoke-login-sessions';
      await oauth2Api.revokeOAuth2LoginSessions({ sid });
    }
    phase = 'revoke-login-sessions';
    await oauth2Api.revokeOAuth2LoginSessions({ subject });
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      phase,
      'Hydra still remembers the login. Verify the Hydra admin API, then sign them out everywhere.',
      err,
    );
  }

  try {
    await oauth2Api.revokeOAuth2ConsentSessions({ subject, all: true });
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      'revoke-consent-sessions',
      'App sign-ins are ended, but app access and its tokens persist. Verify the Hydra admin API, then sign them out everywhere.',
      err,
    );
  }
}

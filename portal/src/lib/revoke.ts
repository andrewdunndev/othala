import type { IdentityApi, JsonPatch, OAuth2Api } from '@ory/client-fetch';
import { hydraAdmin, isNotFound, kratosAdmin } from './ory-fetch';

export type RevokeDependency = 'kratos-admin' | 'hydra-admin';

export const DEACTIVATE_STEP = 'state->inactive';

/** The message is safe to show; the raw cause is for server logs only. */
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

export interface RevokeDeps {
  identityApi: IdentityApi;
  oauth2Api: OAuth2Api;
}

export interface RevokeOptions {
  deactivate?: boolean;
}

export interface RevokeResult {
  subject: string;
  deactivated: boolean;
  kratosSessionsRevoked: boolean;
  hydraLoginRevoked: boolean;
  hydraConsentRevoked: boolean;
}

function resolveDeps(deps: Partial<RevokeDeps> = {}): RevokeDeps {
  return {
    identityApi: deps.identityApi ?? kratosAdmin(),
    oauth2Api: deps.oauth2Api ?? hydraAdmin(),
  };
}

/** The page token of a Hydra list response's `rel="next"` Link header, if any. */
export function nextPageToken(headers: Headers): string | undefined {
  const next = /<([^>]*)>\s*;\s*rel="?next"?/.exec(headers.get('link') ?? '');
  return next ? (new URL(next[1], 'http://hydra').searchParams.get('page_token') ?? undefined) : undefined;
}

async function listLoginSessionIds(oauth2Api: OAuth2Api, subject: string): Promise<string[]> {
  const sids = new Set<string>();
  let pageToken: string | undefined;
  do {
    const res = await oauth2Api.listOAuth2ConsentSessionsRaw({ subject, pageSize: 250, pageToken });
    for (const row of await res.value()) {
      const sid = row.consent_request?.login_session_id;
      if (sid) sids.add(sid);
    }
    pageToken = nextPageToken(res.raw.headers);
  } while (pageToken);
  return [...sids];
}

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
        DEACTIVATE_STEP,
        'Could not mark the identity inactive. Verify Kratos admin reachability and that the identity id exists, then retry the deactivate.',
        err,
      );
    }
  }

  try {
    await d.identityApi.deleteIdentitySessions({ id: subject });
  } catch (err) {
    // Kratos answers 404 when the subject has no active sessions.
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

export async function revokeHydraSessions(
  subject: string,
  deps: Partial<Pick<RevokeDeps, 'oauth2Api'>> = {},
): Promise<void> {
  const oauth2Api = deps.oauth2Api ?? hydraAdmin();
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
      'Hydra still remembers the login. Verify the Hydra admin API, then try again.',
      err,
    );
  }

  try {
    await oauth2Api.revokeOAuth2ConsentSessions({ subject, all: true });
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      'revoke-consent-sessions',
      'App sign-ins are ended, but app access and its tokens persist. Verify the Hydra admin API, then try again.',
      err,
    );
  }
}

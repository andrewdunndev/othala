// revokeSubject — the in-process revocation fan-out (CU3 / B1).
//
// One function, called by all three revocation triggers:
//
//   - admin force-logout      (admin "revoke user")        -> steps 2-6
//   - user "sign out everywhere" (self-service settings)   -> steps 2-6
//   - deactivate              (admin deactivate-identity)  -> step 1 THEN 2-6
//
// The fan-out is in-process here, calling the Kratos + Hydra admin APIs
// directly through the typed Ory SDK (@ory/client-fetch). No
// string-interpolated admin URLs.
//
// FAN-OUT ORDER (do not reorder; steps 1-2 are the hard cut):
//
//   1. Kratos state -> inactive  (deactivate trigger ONLY; MUST precede 2)
//      PATCH /admin/identities/{id} [{op:replace,path:/state,value:inactive}]
//   2. Kratos sessions revoke    DELETE /admin/identities/{id}/sessions
//      A REAL failure (Kratos unreachable / 5xx) ABORTS the fan-out. But a
//      404 ("no active sessions") is the SUCCESS postcondition, not a failure
//      — tolerate it and CONTINUE: a subject with no live Kratos session can
//      still hold a remembered Hydra login / live access tokens, which is the
//      very case "sign out everywhere" must cut.
//   3. Hydra login-session revoke   revokeOAuth2LoginSessions({subject})
//      Cuts the remembered login so a remembered subject cannot
//      skip-login a fresh token. Idempotent.
//   4. Hydra consent-session revoke revokeOAuth2ConsentSessions({subject,all})
//      Invalidates granted consent + associated access tokens. Idempotent.
//
// There is no in-process identity cache to invalidate: the hot login/consent
// path always fetches a fresh identity (oauth2-handlers -> admin-api.getIdentity),
// so a revoked/deactivated subject fails the gate's state-check on the next
// fetch — revocation is correct without a cache.
//
// Prescriptive errors: an upstream failure on steps 1-4 throws a
// RevokeError naming WHICH dependency failed (hydra-admin / kratos-admin)
// and WHAT to do next. Raw upstream errors are never surfaced to callers.

import {
  Configuration,
  IdentityApi,
  OAuth2Api,
  ResponseError,
  type JsonPatch,
} from '@ory/client-fetch';

/** Which upstream dependency a revoke step failed against. */
export type RevokeDependency = 'kratos-admin' | 'hydra-admin';

/**
 * Prescriptive revoke failure. Names the dependency and the operator's
 * next action; never leaks the raw upstream error to the caller's surface
 * (the raw cause is attached for server-side logging only).
 */
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

/**
 * True iff the SDK error is an HTTP 404. Kratos returns 404 from
 * DELETE /admin/identities/{id}/sessions when the subject has NO active
 * sessions — "nothing to revoke", the success postcondition, not a failure.
 */
function isNotFound(err: unknown): boolean {
  return err instanceof ResponseError && err.response?.status === 404;
}

/** The portal-side revoke fan-out clients + the trigger flavour. */
export interface RevokeDeps {
  identityApi: IdentityApi;
  oauth2Api: OAuth2Api;
}

export interface RevokeOptions {
  /**
   * deactivate trigger: run step 1 (state -> inactive) before step 2.
   * admin force-logout + sign-out-everywhere leave this false.
   */
  deactivate?: boolean;
}

/** Per-step outcome, returned so the UI can report what landed. */
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

/**
/** Resolve injected deps, defaulting to the live SDK clients + helpers. */
function resolveDeps(deps: Partial<RevokeDeps> = {}): RevokeDeps {
  return {
    identityApi: deps.identityApi ?? buildIdentityApi(),
    oauth2Api: deps.oauth2Api ?? buildOAuth2Api(),
  };
}

/**
 * Run the revocation fan-out for one subject (the Kratos identity id).
 *
 * Steps 1-4 are the hard cut and throw a prescriptive RevokeError on the
 * first failure (the cut aborts — earlier steps already landed).
 */
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

  // ── Step 1 (deactivate trigger ONLY): Kratos state -> inactive ──────────
  // MUST precede step 2: flip state first so a session re-minted in the
  // race window is itself for an inactive identity (the gate then denies).
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

  // ── Step 2 (all triggers): Kratos sessions revoke. ─────────────────────
  // A 404 means the subject has no active sessions (Kratos v26 returns 404,
  // not 204, in that case): nothing to revoke == revoked. Tolerate it and
  // continue to the Hydra cut. Only a REAL failure aborts the fan-out.
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

  // ── Step 3 (all triggers): Hydra login-session revoke. Idempotent. ──────
  try {
    await d.oauth2Api.revokeOAuth2LoginSessions({ subject });
    result.hydraLoginRevoked = true;
  } catch (err) {
    throw new RevokeError(
      'hydra-admin',
      'revoke-login-sessions',
      'Kratos sessions are cut, but Hydra still remembers the login (remembered login still open — a fresh token could skip-login). Verify HYDRA_ADMIN_URL, then re-run the revoke (it is idempotent).',
      err,
    );
  }

  // ── Step 4 (all triggers): Hydra consent-session revoke. Idempotent. ────
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
 * Revoke only the subject's Hydra consent sessions, for every client
 * (step 4 on its own). Used when an admin narrows a subject's groups, roles
 * or admin marker: the grants and refresh tokens issued under the old access
 * stop working, and the next sign-in re-runs consent against the new record.
 * Kratos and Hydra login sessions are left alone. Idempotent.
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

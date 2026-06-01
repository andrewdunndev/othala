// OAuth2 challenge handlers (CU1 item 1), ported from consent/handlers.go.
//
// These are the Hydra login/consent/logout challenge providers — the role the
// Go consent service plays at urls.{login,consent,logout}. They are distinct
// from src/pages/auth/{login,consent,logout}.astro, which render the Kratos
// browser-flow human UI. The new routes live at /oauth2/{login,consent,logout}
// (see src/pages/oauth2/*).
//
// Each handler takes a Web Request and returns a Web Response (302 redirect or
// an error status). The logic is framework-agnostic so the Astro routes are
// thin wrappers and the handlers can be exercised directly in contract tests
// with stubbed dependencies (see Deps).
//
// Flow mirrors the Go service:
//   login   -> resolve subject (skip-remembered or whoami), gate, accept/reject
//   consent -> re-gate, build id_token claims, accept with consent session
//   logout  -> accept (Kratos session invalidation is the portal's job)
//
// SDK usage: we reuse the class-based @ory/client-fetch OAuth2Api (the same
// surface admin.ts drives for listOAuth2Clients) and the C1 admin-api
// getIdentity / kratos getSession helpers, rather than re-hand-rolling fetch.

import { Configuration, OAuth2Api } from '@ory/client-fetch';
import type {
  OAuth2ConsentRequest,
  OAuth2LoginRequest,
  OAuth2LogoutRequest,
} from '@ory/client-fetch';
import type { Identity, Session } from './types';
import { getIdentity as defaultGetIdentity } from './admin-api';
import { getSession as defaultGetSession } from './kratos';
import { enforceAccessGate, type GateResult } from './gate';
import { buildIDTokenClaims } from './claims';

// loginRememberFor / consentRememberFor: same windows as the Go service
// (consent/handlers.go) so Hydra's remembered decisions expire on the same
// cadence regardless of which provider answers the challenge.
const LOGIN_REMEMBER_FOR = 86400; // 24h
const CONSENT_REMEMBER_FOR = 3600; // 1h

function hydraAdminBase(): string {
  return process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445';
}

function defaultOAuth2Api(): OAuth2Api {
  const token = process.env.HYDRA_ADMIN_TOKEN ?? '';
  return new OAuth2Api(
    new Configuration({
      basePath: hydraAdminBase(),
      ...(token ? { accessToken: token } : {}),
    }),
  );
}

/**
 * The login-UI base the no-session path bounces to. Production points at the
 * portal's own Kratos browser-flow login page.
 */
function loginUIBase(): string {
  return process.env.PORTAL_LOGIN_URL ?? '/auth/login';
}

/**
 * Injectable dependencies. Production wiring uses the real SDK + C1 helpers;
 * contract tests pass stubs. All optional so callers override only what they
 * need.
 */
export interface Deps {
  oauth2?: Pick<
    OAuth2Api,
    | 'getOAuth2LoginRequest'
    | 'acceptOAuth2LoginRequest'
    | 'rejectOAuth2LoginRequest'
    | 'getOAuth2ConsentRequest'
    | 'acceptOAuth2ConsentRequest'
    | 'rejectOAuth2ConsentRequest'
    | 'getOAuth2LogoutRequest'
    | 'acceptOAuth2LogoutRequest'
  >;
  getIdentity?: (id: string) => Promise<Identity>;
  getSession?: (cookie?: string) => Promise<Session | null>;
  gate?: (identity: Identity | null, clientId: string) => GateResult;
  buildClaims?: (identity: Identity | null) => Record<string, unknown>;
}

function resolve(deps: Deps): Required<Deps> {
  return {
    oauth2: deps.oauth2 ?? defaultOAuth2Api(),
    getIdentity: deps.getIdentity ?? defaultGetIdentity,
    getSession: deps.getSession ?? defaultGetSession,
    gate: deps.gate ?? ((identity, clientId) => enforceAccessGate(identity, clientId)),
    buildClaims: deps.buildClaims ?? buildIDTokenClaims,
  };
}

/** 302 redirect helper. */
function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

/**
 * Build the relative return_to path for the Kratos login bounce (CU1 item 5,
 * hardening). ALWAYS a server-side RELATIVE path — no scheme/host — so it can
 * never redirect the browser cross-origin even if the challenge value is
 * attacker-influenced (it is URL-encoded regardless).
 */
export function buildLoginReturnTo(challenge: string): string {
  const qs = new URLSearchParams({ login_challenge: challenge });
  return `/oauth2/login?${qs.toString()}`;
}

/** Fetch an identity, returning null on any lookup failure (fail-closed). */
async function safeGetIdentity(
  d: Required<Deps>,
  subject: string,
): Promise<Identity | null> {
  try {
    return await d.getIdentity(subject);
  } catch {
    return null;
  }
}

/** Handle GET /oauth2/login?login_challenge=... */
export async function handleLogin(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);
  const challenge = new URL(req.url).searchParams.get('login_challenge');
  if (!challenge) {
    return new Response('missing login_challenge', { status: 400 });
  }

  let login: OAuth2LoginRequest;
  try {
    login = await d.oauth2.getOAuth2LoginRequest({ loginChallenge: challenge });
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  const clientId = login.client?.client_id ?? '';

  // Resolve the authenticated subject.
  let subject: string;
  let remember = false;
  let acr: string | undefined;

  if (login.skip) {
    // Hydra already remembers this subject. Honor it; the gate still fires.
    subject = login.subject;
  } else {
    let session: Session | null;
    try {
      session = await d.getSession(req.headers.get('cookie') ?? undefined);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
    if (!session?.active || !session.identity) {
      // Not authenticated — bounce to the (relative) login UI with a relative
      // return_to so we come back here after Kratos mints a session.
      const returnTo = buildLoginReturnTo(challenge);
      const loginURL = `${loginUIBase()}?return_to=${encodeURIComponent(returnTo)}`;
      return redirect(loginURL);
    }
    subject = session.identity.id;
    remember = true;
    acr = session.authenticator_assurance_level ?? undefined;
  }

  // Enforce the access gate (state + group), fail-closed on lookup failure.
  const identity = await safeGetIdentity(d, subject);
  const result = d.gate(identity, clientId);
  if (!result.allowed) {
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2LoginRequest({
        loginChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: result.reason,
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
  }

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2LoginRequest({
      loginChallenge: challenge,
      acceptOAuth2LoginRequest: {
        subject,
        ...(remember ? { remember: true, remember_for: LOGIN_REMEMBER_FOR } : {}),
        ...(acr ? { acr } : {}),
      },
    });
    return redirect(redirect_to);
  } catch {
    return new Response('upstream error', { status: 502 });
  }
}

/** Handle GET /oauth2/consent?consent_challenge=... */
export async function handleConsent(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);
  const challenge = new URL(req.url).searchParams.get('consent_challenge');
  if (!challenge) {
    return new Response('missing consent_challenge', { status: 400 });
  }

  let consent: OAuth2ConsentRequest;
  try {
    consent = await d.oauth2.getOAuth2ConsentRequest({ consentChallenge: challenge });
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  const subject = consent.subject ?? '';
  const clientId = consent.client?.client_id ?? '';

  // Re-enforce the access gate at consent time (state + group), fail-closed.
  // Consent must gate even when login was remembered (skip), and the consent
  // challenge always fires for skip_consent clients.
  const identity = await safeGetIdentity(d, subject);
  const result = d.gate(identity, clientId);
  if (!result.allowed) {
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2ConsentRequest({
        consentChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: result.reason,
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
  }

  // identity is non-null here: the gate denies on a null identity.
  const idTokenClaims = d.buildClaims(identity);

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2ConsentRequest({
      consentChallenge: challenge,
      acceptOAuth2ConsentRequest: {
        grant_scope: consent.requested_scope,
        grant_access_token_audience: consent.requested_access_token_audience,
        remember: true,
        remember_for: CONSENT_REMEMBER_FOR,
        session: {
          id_token: idTokenClaims,
          access_token: {},
        },
      },
    });
    return redirect(redirect_to);
  } catch {
    return new Response('upstream error', { status: 502 });
  }
}

/** Handle GET /oauth2/logout?logout_challenge=... */
export async function handleLogout(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);
  const challenge = new URL(req.url).searchParams.get('logout_challenge');
  if (!challenge) {
    return new Response('missing logout_challenge', { status: 400 });
  }

  let _logout: OAuth2LogoutRequest;
  try {
    _logout = await d.oauth2.getOAuth2LogoutRequest({ logoutChallenge: challenge });
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2LogoutRequest({
      logoutChallenge: challenge,
    });
    return redirect(redirect_to);
  } catch {
    return new Response('upstream error', { status: 502 });
  }
}

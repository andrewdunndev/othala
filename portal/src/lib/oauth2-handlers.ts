import { Configuration, OAuth2Api } from '@ory/client-fetch';
import type {
  OAuth2ConsentRequest,
  OAuth2LoginRequest,
  OAuth2LogoutRequest,
} from '@ory/client-fetch';
import type { Identity, Session } from './types';
import { getIdentity as defaultGetIdentity, revokeSession as defaultRevokeSession } from './admin-api';
import { getSession as defaultGetSession } from './kratos';
import { decideAccess, enforceAccessGate } from './gate';
import { composeIDTokenClaims } from './claims';
import type { ClientManifest } from './manifests';
import { servingManifest } from './manifest-store';
import { verifyToken, CSRFError } from './csrf';
import { publicUrl } from './config';
import { HYDRA_ADMIN_URL } from './constants';
import { timeoutFetch } from './ory-fetch';

// Hydra remembers a sign-in as long as the Kratos session lives, so a later app sign-out still reaches handleLogout.
const KRATOS_SESSION_LIFESPAN = 2_592_000; // Kratos session.lifespan, 720h

export function loginRememberFor(session: Session, now: number = Date.now()): number {
  const expires = session.expires_at ? new Date(session.expires_at).getTime() : NaN;
  if (!Number.isFinite(expires)) return KRATOS_SESSION_LIFESPAN;
  return Math.max(1, Math.ceil((expires - now) / 1000));
}

export function defaultOAuth2Api(): OAuth2Api {
  return new OAuth2Api(new Configuration({ basePath: HYDRA_ADMIN_URL, fetchApi: timeoutFetch() }));
}

const LOGIN_UI_BASE = '/auth/login';
const CONSENT_UI_BASE = '/auth/consent';

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
    | 'revokeOAuth2LoginSessions'
  >;
  getIdentity?: (id: string) => Promise<Identity>;
  getSession?: (cookie?: string) => Promise<Session | null>;
  revokeSession?: (sessionId: string) => Promise<void>;
  /** The serving default never throws, so an invalid manifest set denies entry instead of failing every challenge. */
  manifest?: (clientId: string) => ClientManifest | undefined;
}

function resolve(deps: Deps): Required<Deps> {
  return {
    oauth2: deps.oauth2 ?? defaultOAuth2Api(),
    getIdentity: deps.getIdentity ?? defaultGetIdentity,
    getSession: deps.getSession ?? defaultGetSession,
    revokeSession: deps.revokeSession ?? defaultRevokeSession,
    manifest: deps.manifest ?? ((clientId) => servingManifest(clientId)),
  };
}

/** Logs the error text only, never cookies, challenges or tokens. */
export function upstream(step: string, err: unknown): void {
  console.error('[portal] upstream failure', { step, error: String(err) });
}

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

/** Relative path only, so the login bounce cannot redirect cross-origin. */
export function buildLoginReturnTo(challenge: string): string {
  const qs = new URLSearchParams({ login_challenge: challenge });
  return `/oauth2/login?${qs.toString()}`;
}

async function safeGetIdentity(
  d: Required<Deps>,
  subject: string,
): Promise<Identity | null> {
  try {
    return await d.getIdentity(subject);
  } catch (err) {
    upstream('getIdentity', err);
    return null;
  }
}

// Hydra exposes no requested_at, so a sign-in this recent satisfies prompt=login and stops the refresh looping back.
const FRESH_LOGIN_WINDOW_S = 30;

export function freshnessVerdict(
  requestUrl: string,
  session: Pick<Session, 'authenticated_at'>,
  now: number = Date.now(),
): 'ok' | 'refresh' | 'login_required' {
  let params: URLSearchParams;
  try {
    params = new URL(requestUrl).searchParams;
  } catch {
    return 'ok';
  }
  const prompt = (params.get('prompt') ?? '').split(' ');
  const rawMaxAge = params.get('max_age') ?? '';
  const maxAge = /^\d+$/.test(rawMaxAge) ? Number(rawMaxAge) : undefined;
  if (!prompt.includes('login') && maxAge === undefined) return 'ok';
  const limit = prompt.includes('login') ? FRESH_LOGIN_WINDOW_S : Math.max(maxAge ?? 0, FRESH_LOGIN_WINDOW_S);
  const age = (now - new Date(session.authenticated_at ?? NaN).getTime()) / 1000;
  if (age <= limit) return 'ok';
  return prompt.includes('none') ? 'login_required' : 'refresh';
}

function loginBounce(challenge: string, query = ''): Response {
  return redirect(`${LOGIN_UI_BASE}?${query}return_to=${encodeURIComponent(buildLoginReturnTo(challenge))}`);
}

async function rejectLogin(d: Required<Deps>, challenge: string, error: string, status_code: number): Promise<Response> {
  try {
    const { redirect_to } = await d.oauth2.rejectOAuth2LoginRequest({
      loginChallenge: challenge,
      rejectOAuth2Request: { error, error_description: error, status_code },
    });
    return redirect(redirect_to);
  } catch (err) {
    upstream('rejectOAuth2LoginRequest', err);
    return new Response('upstream error', { status: 502 });
  }
}

export async function handleLogin(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);
  const challenge = new URL(req.url).searchParams.get('login_challenge');
  if (!challenge) {
    return new Response('missing login_challenge', { status: 400 });
  }

  let login: OAuth2LoginRequest;
  try {
    login = await d.oauth2.getOAuth2LoginRequest({ loginChallenge: challenge });
  } catch (err) {
    upstream('getOAuth2LoginRequest', err);
    return new Response('upstream error', { status: 502 });
  }

  const clientId = login.client?.client_id ?? '';

  let session: Session | null;
  try {
    session = await d.getSession(req.headers.get('cookie') ?? undefined);
  } catch (err) {
    upstream('getSession', err);
    return new Response('upstream error', { status: 502 });
  }
  // Hydra remembers this subject but Kratos is the authority: a skip needs a live Kratos session for the same subject.
  if (login.skip && session?.active && session.identity && session.identity.id !== login.subject) {
    // A different user's live session: end that one Hydra login session so Hydra re-issues without skip; never a subject-wide revoke.
    if (!login.session_id) return new Response('upstream error', { status: 502 });
    try {
      await d.oauth2.revokeOAuth2LoginSessions({ sid: login.session_id });
    } catch (err) {
      upstream('revokeOAuth2LoginSessions', err);
      return new Response('upstream error', { status: 502 });
    }
    return redirect(login.request_url);
  }
  if (!session?.active || !session.identity) return loginBounce(challenge);
  const subject = session.identity.id;
  const acr = session.authenticator_assurance_level ?? undefined;

  const identity = await safeGetIdentity(d, subject);
  const access = decideAccess(identity, { app: d.manifest(clientId) }, session);
  if ('deny' in access) {
    // Log the real reason server-side; send Hydra an opaque error_description so RPs learn no group names or identity state.
    console.warn('[oauth2/login] access denied', { clientId, subject, reason: access.deny });
    return rejectLogin(d, challenge, 'access_denied', 403);
  }

  const freshness = freshnessVerdict(login.request_url, session);
  if (freshness === 'login_required') return rejectLogin(d, challenge, freshness, 400);
  if (freshness === 'refresh') return loginBounce(challenge, 'refresh=true&');

  if ('stepUp' in access) return loginBounce(challenge, 'aal=aal2&');

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2LoginRequest({
      loginChallenge: challenge,
      acceptOAuth2LoginRequest: {
        subject,
        remember: true,
        remember_for: loginRememberFor(session),
        // Hydra keeps its cookie on a remembered login unless asked to renew it.
        ...(login.skip ? { extend_session_lifespan: true } : {}),
        ...(acr ? { acr } : {}),
      },
    });
    return redirect(redirect_to);
  } catch (err) {
    upstream('acceptOAuth2LoginRequest', err);
    return new Response('upstream error', { status: 502 });
  }
}

export async function acceptConsentRequest(
  challenge: string,
  consent: OAuth2ConsentRequest,
  identity: Identity,
  d: Required<Deps>,
  clientId: string,
): Promise<Response> {
  const manifest = d.manifest(clientId);
  const idTokenClaims = composeIDTokenClaims(identity, manifest, consent.requested_scope);
  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2ConsentRequest({
      consentChallenge: challenge,
      acceptOAuth2ConsentRequest: {
        grant_scope: consent.requested_scope,
        grant_access_token_audience: consent.requested_access_token_audience,
        // Not remembered, so every authorize passes the gate again.
        remember: false,
        session: {
          id_token: idTokenClaims,
          access_token: {},
        },
      },
    });
    return redirect(redirect_to);
  } catch (err) {
    upstream('acceptOAuth2ConsentRequest', err);
    return new Response('upstream error', { status: 502 });
  }
}

export async function handleConsent(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);
  const challenge = new URL(req.url).searchParams.get('consent_challenge');
  if (!challenge) {
    return new Response('missing consent_challenge', { status: 400 });
  }

  let consent: OAuth2ConsentRequest;
  try {
    consent = await d.oauth2.getOAuth2ConsentRequest({ consentChallenge: challenge });
  } catch (err) {
    upstream('getOAuth2ConsentRequest', err);
    return new Response('upstream error', { status: 502 });
  }

  const subject = consent.subject ?? '';
  const clientId = consent.client?.client_id ?? '';

  // Re-gate at consent time (state + group), fail-closed; it must gate even when login was remembered.
  const identity = await safeGetIdentity(d, subject);
  const consentManifest = d.manifest(clientId);
  const result = enforceAccessGate(identity, clientId, consentManifest);
  if (!result.allowed) {
    console.warn('[oauth2/consent] access denied', { clientId, subject, reason: result.reason });
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2ConsentRequest({
        consentChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: 'access_denied',
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch (err) {
      upstream('rejectOAuth2ConsentRequest', err);
      return new Response('upstream error', { status: 502 });
    }
  }

  // The manifest's skip_consent survives client re-registration; the gate above denied a null identity.
  if (consent.skip || consentManifest?.skipConsent) {
    return acceptConsentRequest(challenge, consent, identity!, d, clientId);
  }

  const qs = new URLSearchParams({ consent_challenge: challenge });
  return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
}

export async function handleConsentPost(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);

  let body: URLSearchParams;
  try {
    const text = await req.text();
    body = new URLSearchParams(text);
  } catch {
    return new Response('bad request body', { status: 400 });
  }

  const challenge = body.get('consent_challenge');
  if (!challenge) {
    return new Response('missing consent_challenge', { status: 400 });
  }

  const action = body.get('action');
  if (action !== 'allow' && action !== 'deny') {
    return new Response('invalid action', { status: 400 });
  }

  // Re-fetch: the challenge is single-use, so a stale post is inert.
  let consent: OAuth2ConsentRequest;
  try {
    consent = await d.oauth2.getOAuth2ConsentRequest({ consentChallenge: challenge });
  } catch (err) {
    upstream('getOAuth2ConsentRequest', err);
    return new Response('upstream error', { status: 502 });
  }

  let session: Session | null;
  try {
    session = await d.getSession(req.headers.get('cookie') ?? undefined);
  } catch (err) {
    upstream('getSession', err);
    return new Response('upstream error', { status: 502 });
  }

  if (!session?.active || !session.identity) {
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2ConsentRequest({
        consentChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: 'no active session',
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch (err) {
      upstream('rejectOAuth2ConsentRequest', err);
      return new Response('upstream error', { status: 502 });
    }
  }

  // The CSRF token is scoped to 'consent', so one minted for another action cannot be replayed here.
  const csrfToken = body.get('csrf_token');
  try {
    verifyToken(csrfToken, session.identity.id, 'consent');
  } catch (err) {
    if (err instanceof CSRFError) {
      return new Response('CSRF token invalid', { status: 400 });
    }
    return new Response('server error', { status: 500 });
  }

  if (session.identity.id !== consent.subject) {
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2ConsentRequest({
        consentChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: 'session subject mismatch',
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch (err) {
      upstream('rejectOAuth2ConsentRequest', err);
      // Reject failed after the nonce was consumed: back to the grant screen for a fresh token.
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
    }
  }

  if (action === 'deny') {
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2ConsentRequest({
        consentChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: 'user denied access',
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch (err) {
      upstream('rejectOAuth2ConsentRequest', err);
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
    }
  }

  const clientId = consent.client?.client_id ?? '';
  const identity = await safeGetIdentity(d, consent.subject ?? '');
  const allowManifest = d.manifest(clientId);
  const result = enforceAccessGate(identity, clientId, allowManifest);
  if (!result.allowed) {
    console.warn('[oauth2/consent/post] access denied', { clientId, subject: consent.subject, reason: result.reason });
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2ConsentRequest({
        consentChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: 'access_denied',
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch (err) {
      upstream('rejectOAuth2ConsentRequest', err);
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
    }
  }

  // The nonce is spent, so a 502 from Hydra redirects to the grant screen for a fresh token.
  const allowResponse = await acceptConsentRequest(challenge, consent, identity!, d, clientId);
  if (allowResponse.status === 502) {
    const qs = new URLSearchParams({ consent_challenge: challenge });
    return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
  }
  return allowResponse;
}

export async function handleLogout(req: Request, deps: Deps = {}): Promise<Response> {
  const d = resolve(deps);
  const challenge = new URL(req.url).searchParams.get('logout_challenge');
  if (!challenge) {
    return new Response('missing logout_challenge', { status: 400 });
  }

  let _logout: OAuth2LogoutRequest;
  try {
    _logout = await d.oauth2.getOAuth2LogoutRequest({ logoutChallenge: challenge });
  } catch (err) {
    upstream('getOAuth2LogoutRequest', err);
    return new Response('upstream error', { status: 502 });
  }

  // A logout that Hydra did not initiate for the RP is the portal's own.
  if (_logout.rp_initiated === false) {
    return redirect(`${publicUrl}/auth/logout`);
  }

  // Subject binding (logout-CSRF hardening): a live session for a different identity is refused; no live session proceeds.
  const logoutSubject = _logout.subject;
  {
    let session: Session | null;
    try {
      session = await d.getSession(req.headers.get('cookie') ?? undefined);
    } catch (err) {
      upstream('getSession', err);
      return redirect(`${publicUrl}/auth/error?reason=auth-unreachable`);
    }
    if (logoutSubject && session?.active && session.identity && session.identity.id !== logoutSubject) {
      return redirect(`${publicUrl}/`);
    }
    // Revoke before Hydra forgets the login: accepting after a failed revoke lets the next authorize sign straight back in.
    if (session?.active && session.identity) {
      try {
        if (!session.id) throw new Error('session without id');
        await d.revokeSession(session.id);
      } catch (e) {
        console.warn('[oauth2/logout] session revoke failed', { subject: logoutSubject, error: String(e) });
        return redirect(`${publicUrl}/auth/error?reason=auth-unreachable`);
      }
    }
  }

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2LogoutRequest({
      logoutChallenge: challenge,
    });
    return redirect(redirect_to);
  } catch (err) {
    upstream('acceptOAuth2LogoutRequest', err);
    return new Response('upstream error', { status: 502 });
  }
}

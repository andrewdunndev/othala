// Hydra login/consent/logout challenge providers at /oauth2/{login,consent,logout} (not the Kratos UI pages in
// src/pages/auth/). Each handler takes a Web Request and returns a Web Response, so routes stay thin and tests inject Deps.
// login: resolve subject (remembered or whoami), gate, accept/reject; consent: re-gate, build claims, accept;
// logout: revoke the subject's live Kratos session, then accept.

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

// Hydra remembers a sign-in as long as the Kratos session lives so a later app sign-out still reaches handleLogout;
// the fallback is the Kratos session.lifespan (720h).
const KRATOS_SESSION_LIFESPAN = 2_592_000; // 30 days

/** Seconds until the Kratos session expires; the configured lifespan when unknown. */
export function loginRememberFor(session: Session, now: number = Date.now()): number {
  const expires = session.expires_at ? new Date(session.expires_at).getTime() : NaN;
  if (!Number.isFinite(expires)) return KRATOS_SESSION_LIFESPAN;
  return Math.max(1, Math.ceil((expires - now) / 1000));
}

export function defaultOAuth2Api(): OAuth2Api {
  return new OAuth2Api(new Configuration({ basePath: HYDRA_ADMIN_URL }));
}

/** Login-UI base for the no-session bounce (the portal's Kratos login page). */
const LOGIN_UI_BASE = '/auth/login';

/** Consent grant-screen base. */
const CONSENT_UI_BASE = '/auth/consent';

/** Injectable dependencies; tests pass stubs for what they need. */
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
  /** Revoke one Kratos session by id (logout). */
  revokeSession?: (sessionId: string) => Promise<void>;
  /** Resolve a client manifest. Defaults to the SERVING loader (manifest-store.ts), which never throws, so an invalid
   * manifest set denies entry instead of 500ing every challenge; undefined is fail-closed at the gate. */
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

/** 302 redirect. */
function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

/** Relative return_to path for the Kratos login bounce: never a scheme or host, so it cannot redirect cross-origin. */
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
  let acr: string | undefined;
  let liveSession: Session;

  if (login.skip) {
    // Hydra remembers this subject but Kratos is the authority: honor the skip only with a live Kratos session for
    // the same subject; otherwise force interactive login.
    let session: Session | null;
    try {
      session = await d.getSession(req.headers.get('cookie') ?? undefined);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
    if (session?.active && session.identity && session.identity.id !== login.subject) {
      // A different user's live session: end that one Hydra login session so Hydra re-issues without skip; never a subject-wide revoke.
      if (!login.session_id) return new Response('upstream error', { status: 502 });
      try {
        await d.oauth2.revokeOAuth2LoginSessions({ sid: login.session_id });
      } catch {
        return new Response('upstream error', { status: 502 });
      }
      return redirect(login.request_url);
    }
    if (!session?.active || !session.identity) {
      const returnTo = buildLoginReturnTo(challenge);
      const loginURL = `${LOGIN_UI_BASE}?return_to=${encodeURIComponent(returnTo)}`;
      return redirect(loginURL);
    }
    subject = login.subject;
    liveSession = session;
    acr = session.authenticator_assurance_level ?? undefined;
  } else {
    let session: Session | null;
    try {
      session = await d.getSession(req.headers.get('cookie') ?? undefined);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
    if (!session?.active || !session.identity) {
      // Not authenticated: bounce to the login UI with a relative return_to.
      const returnTo = buildLoginReturnTo(challenge);
      const loginURL = `${LOGIN_UI_BASE}?return_to=${encodeURIComponent(returnTo)}`;
      return redirect(loginURL);
    }
    subject = session.identity.id;
    liveSession = session;
    acr = session.authenticator_assurance_level ?? undefined;
  }

  // The access policy (gate.ts): state + group, fail-closed on lookup failure, then step-up.
  const identity = await safeGetIdentity(d, subject);
  const access = decideAccess(identity, { app: d.manifest(clientId) }, liveSession);
  if ('deny' in access) {
    // Log the real reason server-side; send Hydra an opaque error_description so RPs learn no group names or identity state.
    console.warn('[oauth2/login] access denied', { clientId, subject, reason: access.deny });
    try {
      const { redirect_to } = await d.oauth2.rejectOAuth2LoginRequest({
        loginChallenge: challenge,
        rejectOAuth2Request: {
          error: 'access_denied',
          error_description: 'access_denied',
          status_code: 403,
        },
      });
      return redirect(redirect_to);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
  }

  // Second-factor step-up: accounts with totp/webauthn, the admin marker, or a role above an app's entry role, complete aal2 first; Kratos returns to this challenge.
  if ('stepUp' in access) {
    const returnTo = buildLoginReturnTo(challenge);
    return redirect(`${LOGIN_UI_BASE}?aal=aal2&return_to=${encodeURIComponent(returnTo)}`);
  }

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2LoginRequest({
      loginChallenge: challenge,
      acceptOAuth2LoginRequest: {
        subject,
        remember: true,
        remember_for: loginRememberFor(liveSession),
        // Hydra keeps its cookie on a remembered login unless asked to renew it.
        ...(login.skip ? { extend_session_lifespan: true } : {}),
        ...(acr ? { acr } : {}),
      },
    });
    return redirect(redirect_to);
  } catch {
    return new Response('upstream error', { status: 502 });
  }
}

/**
 * Accept a consent request with full claims; shared by the skip auto-accept in handleConsent and the POST in
 * /oauth2/consent.ts. Consent is not remembered, so every authorize passes the gate again. Callers have passed the
 * gate, so identity is non-null; `clientId` resolves the manifest for claims.
 */
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
        remember: false,
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

  // Re-gate at consent time (state + group), fail-closed; it must gate even when login was remembered.
  const identity = await safeGetIdentity(d, subject);
  const consentManifest = d.manifest(clientId);
  const result = enforceAccessGate(identity, clientId, consentManifest);
  if (!result.allowed) {
    // Log the real reason server-side; send an opaque error_description.
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
    } catch {
      return new Response('upstream error', { status: 502 });
    }
  }

  // SKIP PATH: the manifest's skip_consent (the operator's pre-consent record, which survives client re-registration)
  // or Hydra's consent.skip auto-accepts with no grant UI. Identity is non-null: the gate denies null above.
  if (consent.skip || consentManifest?.skipConsent) {
    return acceptConsentRequest(challenge, consent, identity!, d, clientId);
  }

  // PROMPT PATH: redirect to /auth/consent; its POST to /oauth2/consent completes the challenge.
  const qs = new URLSearchParams({ consent_challenge: challenge });
  return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
}

/**
 * Handle POST /oauth2/consent (Allow/Deny from /auth/consent.astro). Verifies the signed, consent-scoped CSRF token
 * (CSRFError returns 400, fail-closed), re-fetches the challenge from Hydra (single-use, so stale posts are inert),
 * and requires the Kratos session's identity.id to equal consent.subject, else access_denied.
 */
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

  // Re-fetch from Hydra: single-use integrity, binds to the subject.
  let consent: OAuth2ConsentRequest;
  try {
    consent = await d.oauth2.getOAuth2ConsentRequest({ consentChallenge: challenge });
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  // Resolve the Kratos session and assert subject match.
  let session: Session | null;
  try {
    session = await d.getSession(req.headers.get('cookie') ?? undefined);
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  if (!session?.active || !session.identity) {
    // No active session: cannot consent for anyone.
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
    } catch {
      return new Response('upstream error', { status: 502 });
    }
  }

  // CSRF: the token is scoped to 'consent', so one minted for another action cannot be replayed here.
  const csrfToken = body.get('csrf_token');
  try {
    verifyToken(csrfToken, session.identity.id, 'consent');
  } catch (err) {
    if (err instanceof CSRFError) {
      return new Response('CSRF token invalid', { status: 400 });
    }
    return new Response('server error', { status: 500 });
  }

  // Subject-mismatch guard: the posting session must be the challenge's subject.
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
    } catch {
      // Reject failed after the nonce was consumed: back to the grant screen for a fresh token.
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
    }
  }

  // Deny path.
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
    } catch {
      // Reject failed after the nonce was consumed: back to the grant screen for a fresh token.
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${CONSENT_UI_BASE}?${qs.toString()}`);
    }
  }

  // Allow path: re-gate before accepting.
  const clientId = consent.client?.client_id ?? '';
  const identity = await safeGetIdentity(d, consent.subject ?? '');
  const allowManifest = d.manifest(clientId);
  const result = enforceAccessGate(identity, clientId, allowManifest);
  if (!result.allowed) {
    // Log the real reason server-side; send an opaque error_description.
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
    } catch {
      // Reject failed after the nonce was consumed: back to the grant screen for a fresh token.
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
    } catch {
      return redirect(`${publicUrl}/auth/error?reason=auth-unreachable`);
    }
    if (logoutSubject && session?.active && session.identity && session.identity.id !== logoutSubject) {
      // Live session is a different user's: refuse to auto-accept and redirect home.
      return redirect(`${publicUrl}/`);
    }
    // The live session is the subject's: revoke it before Hydra forgets the login; a failed revoke must not accept,
    // or the next authorize would sign straight back in.
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
  } catch {
    return new Response('upstream error', { status: 502 });
  }
}

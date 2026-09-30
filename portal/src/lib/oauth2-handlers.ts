// OAuth2 challenge handlers (CU1 item 1).
//
// These are the Hydra login/consent/logout challenge providers. They are
// distinct from src/pages/auth/{login,consent,logout}.astro, which render the
// Kratos browser-flow human UI. The routes live at
// /oauth2/{login,consent,logout} (see src/pages/oauth2/*).
//
// Each handler takes a Web Request and returns a Web Response (302 redirect or
// an error status). The logic is framework-agnostic so the Astro routes are
// thin wrappers and the handlers can be exercised directly in contract tests
// with stubbed dependencies (see Deps).
//
// Flow mirrors the Go service:
//   login   -> resolve subject (skip-remembered or whoami), gate, accept/reject
//   consent -> re-gate, build id_token claims, accept with consent session
//   logout  -> revoke the subject's live Kratos session, then accept
//
// SDK usage: we reuse the class-based @ory/client-fetch OAuth2Api and the
// C1 admin-api getIdentity / kratos getSession helpers, rather than
// re-hand-rolling fetch.

import { Configuration, OAuth2Api } from '@ory/client-fetch';
import type {
  OAuth2ConsentRequest,
  OAuth2LoginRequest,
  OAuth2LogoutRequest,
} from '@ory/client-fetch';
import type { Identity, Session } from './types';
import { getIdentity as defaultGetIdentity, revokeSession as defaultRevokeSession } from './admin-api';
import { getSession as defaultGetSession } from './kratos';
import { enforceAccessGate, type GateResult } from './gate';
import { composeIDTokenClaims } from './claims';
import type { ClientManifest } from './manifests';
import { servingManifest } from './manifest-store';
import { verifyToken, CSRFError } from './csrf';
import { needsStepUp } from './step-up';

// Hydra remembers an app sign-in for as long as the Kratos session lives, so
// a later app sign-out still reaches handleLogout and ends that session.
// Hydra v26.2.0 sets its login cookie Max-Age to remember_for when > 0 and
// clamps the stored expiry to ttl.authentication_session (default 720h)
// (consent/strategy_default.go:441-489). The fallback is the Kratos
// session.lifespan (kratos/kratos.yml, 720h).
const KRATOS_SESSION_LIFESPAN = 2_592_000; // 30 days

/** Seconds until the Kratos session expires; the configured lifespan when unknown. */
export function loginRememberFor(session: Session, now: number = Date.now()): number {
  const expires = session.expires_at ? new Date(session.expires_at).getTime() : NaN;
  if (!Number.isFinite(expires)) return KRATOS_SESSION_LIFESPAN;
  return Math.max(1, Math.ceil((expires - now) / 1000));
}

// CONSENT_REMEMBER_FOR_SKIP: 1 hour — matches Go consentRememberFor (3600).
// Used on the skip auto-accept path (all current skip_consent:true clients).
// Go comment: "Trusted clients all skip_consent anyway, so remember is
// mostly belt and suspenders. Short window keeps blast radius small if a
// group changes mid-session."
const CONSENT_REMEMBER_FOR_SKIP = 3600; // 1h — matches Go consentRememberFor

// CONSENT_REMEMBER_FOR_PROMPT: 30 days (2 592 000 s).
// Used on the interactive Allow POST path only. Goal: a prompted client
// asks ONCE PER USER, then is silent on subsequent logins (coordinator
// decision 2). Matches the login memory (the Kratos session, 30 d) and aligns
// with Hydra's refresh_token TTL (720 h / 30 d). NOT applied on the
// skip path — skip path uses CONSENT_REMEMBER_FOR_SKIP to match Go.
const CONSENT_REMEMBER_FOR_PROMPT = 2_592_000; // 30 days

function hydraAdminBase(): string {
  return process.env.HYDRA_ADMIN_URL ?? 'http://hydra:4445';
}

export function defaultOAuth2Api(): OAuth2Api {
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
 * The consent grant-screen base. Production points at /auth/consent (the
 * Astro page that renders the Allow / Deny UI). Overridable via
 * PORTAL_CONSENT_URL for test / lab environments.
 */
function consentUIBase(): string {
  return process.env.PORTAL_CONSENT_URL ?? '/auth/consent';
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
    | 'revokeOAuth2LoginSessions'
  >;
  getIdentity?: (id: string) => Promise<Identity>;
  getSession?: (cookie?: string) => Promise<Session | null>;
  /** Revoke one Kratos session by id (logout). Resolves when the session is gone. */
  revokeSession?: (sessionId: string) => Promise<void>;
  gate?: (identity: Identity | null, clientId: string, manifest?: ClientManifest) => GateResult;
  /**
   * Resolve a client manifest by clientId. Used for claims injection (A3) and
   * gate (C). Defaults to the SERVING loader (lib/manifest-store.ts), which
   * never throws: a manifest set that fails to validate must deny entry, not
   * 500 every login and consent challenge in the estate at once. An undefined
   * result is fail-closed at the gate.
   */
  manifest?: (clientId: string) => ClientManifest | undefined;
}

function resolve(deps: Deps): Required<Deps> {
  return {
    oauth2: deps.oauth2 ?? defaultOAuth2Api(),
    getIdentity: deps.getIdentity ?? defaultGetIdentity,
    getSession: deps.getSession ?? defaultGetSession,
    revokeSession: deps.revokeSession ?? defaultRevokeSession,
    gate: deps.gate ?? ((identity, clientId, manifest) => enforceAccessGate(identity, clientId, manifest)),
    manifest: deps.manifest ?? ((clientId) => servingManifest(clientId)),
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
  let acr: string | undefined;
  let liveSession: Session;

  if (login.skip) {
    // Hydra remembers this subject, but Kratos is the authentication authority.
    // Do NOT silently re-SSO on a remembered Hydra login when the Kratos session
    // is gone (e.g. the user logged out). Re-verify a live Kratos session whose
    // subject matches before honoring the skip; otherwise force interactive login.
    let session: Session | null;
    try {
      session = await d.getSession(req.headers.get('cookie') ?? undefined);
    } catch {
      return new Response('upstream error', { status: 502 });
    }
    if (session?.active && session.identity && session.identity.id !== login.subject) {
      // A different user's live session: Hydra's remembered login is someone
      // else's. End that one login session and let Hydra re-issue the
      // challenge without skip. Never fall back to a subject-wide revoke.
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
      const loginURL = `${loginUIBase()}?return_to=${encodeURIComponent(returnTo)}`;
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
      // Not authenticated — bounce to the (relative) login UI with a relative
      // return_to so we come back here after Kratos mints a session.
      const returnTo = buildLoginReturnTo(challenge);
      const loginURL = `${loginUIBase()}?return_to=${encodeURIComponent(returnTo)}`;
      return redirect(loginURL);
    }
    subject = session.identity.id;
    liveSession = session;
    acr = session.authenticator_assurance_level ?? undefined;
  }

  // Enforce the access gate (state + group), fail-closed on lookup failure.
  const identity = await safeGetIdentity(d, subject);
  const loginManifest = d.manifest(clientId);
  const result = d.gate(identity, clientId, loginManifest);
  if (!result.allowed) {
    // Log the real denial reason server-side for operator observability, then
    // send an opaque error_description to the client (Hydra forwards it into
    // the RP redirect) to avoid leaking internal group names or identity state
    // distinguishers to relying parties.
    console.warn('[oauth2/login] access denied', { clientId, subject, reason: result.reason });
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

  // Second-factor step-up: an account with totp/webauthn, or the admin marker,
  // completes aal2 before any app sign-in is accepted. Kratos returns to this
  // challenge afterwards and the aal2 session is accepted with acr aal2.
  if (needsStepUp(liveSession, identity)) {
    const returnTo = buildLoginReturnTo(challenge);
    return redirect(`${loginUIBase()}?aal=aal2&return_to=${encodeURIComponent(returnTo)}`);
  }

  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2LoginRequest({
      loginChallenge: challenge,
      acceptOAuth2LoginRequest: {
        subject,
        remember: true,
        remember_for: loginRememberFor(liveSession),
        // On a remembered login Hydra keeps its cookie unless asked to renew it.
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
 * Accept a consent request with full claims and remember=true.
 *
 * Extracted so both the skip=true auto-accept path in handleConsent AND the
 * POST handler in /oauth2/consent.ts share one call site (DRY). The identity
 * is non-null here — callers must have already passed the gate (which denies
 * on null identity).
 *
 * rememberFor: callers pass CONSENT_REMEMBER_FOR_SKIP (3600, matches Go) for
 * the skip auto-accept path, and CONSENT_REMEMBER_FOR_PROMPT (30d) for the
 * interactive Allow POST path. Default is CONSENT_REMEMBER_FOR_SKIP (skip
 * path is the common case for all current skip_consent:true clients).
 *
 * clientId: threaded in to resolve the client manifest for claims injection
 * (A3: composeIDTokenClaims applies emit_groups + lookupRole deepMergeClaims).
 */
export async function acceptConsentRequest(
  challenge: string,
  consent: OAuth2ConsentRequest,
  identity: Identity,
  d: Required<Deps>,
  clientId: string,
  rememberFor: number = CONSENT_REMEMBER_FOR_SKIP,
): Promise<Response> {
  const manifest = d.manifest(clientId);
  const idTokenClaims = composeIDTokenClaims(identity, manifest, consent.requested_scope);
  try {
    const { redirect_to } = await d.oauth2.acceptOAuth2ConsentRequest({
      consentChallenge: challenge,
      acceptOAuth2ConsentRequest: {
        grant_scope: consent.requested_scope,
        grant_access_token_audience: consent.requested_access_token_audience,
        remember: true,
        remember_for: rememberFor,
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

  // Re-enforce the access gate at consent time (state + group), fail-closed.
  // Consent must gate even when login was remembered (skip), and the consent
  // challenge always fires for skip_consent clients.
  const identity = await safeGetIdentity(d, subject);
  const consentManifest = d.manifest(clientId);
  const result = d.gate(identity, clientId, consentManifest);
  if (!result.allowed) {
    // Log the real denial reason server-side; send an opaque error_description
    // to the client to avoid leaking internal group names / identity state.
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

  // SKIP PATH (load-bearing):
  // curated IdP — the operator pre-consents at manifest-authoring time, so a
  // skip_consent:true client auto-accepts with NO grant UI ("never prompts").
  //
  // Honor the MANIFEST skip_consent (authoritative, operator-authored) OR
  // Hydra's remember-based `consent.skip` when set. Why the manifest flag is
  // authoritative (vs Hydra's client field, which OSS Hydra v26.2.0 does not
  // auto-skip on): the manifest is the operator's pre-consent record and
  // survives a client re-registration that resets Hydra's own field. Identity is
  // non-null here (gate denies on null above). remember_for =
  // CONSENT_REMEMBER_FOR_SKIP (3600).
  if (consent.skip || consentManifest?.skipConsent) {
    return acceptConsentRequest(challenge, consent, identity!, d, clientId, CONSENT_REMEMBER_FOR_SKIP);
  }

  // PROMPT PATH:
  // When consent.skip === false the user has NOT previously granted consent for
  // this client (or the grant expired). Redirect to the grant screen. The
  // browser renders /auth/consent, the user clicks Allow / Deny, and the form
  // POSTs to /oauth2/consent which completes the challenge.
  const qs = new URLSearchParams({ consent_challenge: challenge });
  return redirect(`${consentUIBase()}?${qs.toString()}`);
}

/**
 * Handle POST /oauth2/consent — Allow/Deny from the grant screen.
 *
 * Called by the <form method="POST" action="/oauth2/consent"> in
 * /auth/consent.astro. Validates signed CSRF token (verifyToken) + subject-
 * match, then either accepts (with full claims + remember=true) or rejects
 * the consent challenge.
 *
 * Integrity model:
 *   - Signed CSRF token: csrf_token is verified via verifyToken(token, identityId)
 *     from csrf.ts — same mechanism as the admin pages. Fail-closed: CSRFError
 *     returns 400. The token is emitted as a hidden input in consent.astro and
 *     tied to the session's identity.id.
 *   - The consent_challenge is re-fetched from Hydra on every POST. Hydra
 *     single-use challenges prevent replay: a challenge that has already been
 *     accepted/rejected returns an error, so old form submissions are inert.
 *   - The current Kratos session's identity.id MUST equal consent.subject.
 *     A mismatch means a different user's browser session is trying to
 *     consent on someone else's challenge — reject with access_denied.
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

  // Re-fetch the consent request from Hydra (single-use integrity — validates
  // the challenge is still open and binds to the correct subject).
  let consent: OAuth2ConsentRequest;
  try {
    consent = await d.oauth2.getOAuth2ConsentRequest({ consentChallenge: challenge });
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  // Resolve the current Kratos session and assert subject match.
  let session: Session | null;
  try {
    session = await d.getSession(req.headers.get('cookie') ?? undefined);
  } catch {
    return new Response('upstream error', { status: 502 });
  }

  if (!session?.active || !session.identity) {
    // No active session — cannot safely consent on behalf of any user.
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

  // CSRF verification (D1): verify the signed CSRF token emitted by consent.astro.
  // The token is action-scoped to 'consent' (FIX-E): a token minted for any other
  // action (e.g. 'force-relogin', 'deactivate') cannot be replayed here.
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
      // Hydra reject failed after CSRF nonce was consumed. Redirect back to
      // the grant screen so the user gets a fresh token and can retry.
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${consentUIBase()}?${qs.toString()}`);
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
      // Hydra reject failed after CSRF nonce was consumed. Redirect back to
      // the grant screen so the user gets a fresh token and can retry.
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${consentUIBase()}?${qs.toString()}`);
    }
  }

  // Allow path — re-enforce the access gate before accepting.
  const clientId = consent.client?.client_id ?? '';
  const identity = await safeGetIdentity(d, consent.subject ?? '');
  const allowManifest = d.manifest(clientId);
  const result = d.gate(identity, clientId, allowManifest);
  if (!result.allowed) {
    // Log the real denial reason server-side; send an opaque error_description
    // to the client to avoid leaking internal group names / identity state.
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
      // Hydra reject failed after CSRF nonce was consumed. Redirect back to
      // the grant screen so the user gets a fresh token and can retry.
      const qs = new URLSearchParams({ consent_challenge: challenge });
      return redirect(`${consentUIBase()}?${qs.toString()}`);
    }
  }

  // identity is non-null here: gate denies on null identity above.
  // remember_for = CONSENT_REMEMBER_FOR_PROMPT (30d) for the interactive Allow path.
  // acceptConsentRequest has its own try/catch; on Hydra failure it returns 502.
  // The CSRF nonce was already consumed above, so on accept failure redirect back
  // to the grant screen for a fresh token rather than stranding the user.
  const allowResponse = await acceptConsentRequest(challenge, consent, identity!, d, clientId, CONSENT_REMEMBER_FOR_PROMPT);
  if (allowResponse.status === 502) {
    const qs = new URLSearchParams({ consent_challenge: challenge });
    return redirect(`${consentUIBase()}?${qs.toString()}`);
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
    return redirect(`${process.env.OTHALA_PUBLIC_URL ?? ''}/auth/logout`);
  }

  // FIX-F: subject-binding defence-in-depth (logout-CSRF hardening).
  // If a live Kratos session is present, its identity must match the logout
  // subject. A mismatch means a cross-user forced-logout attempt — refuse it.
  // If there is no live session the logout proceeds (the session is already gone
  // or the browser has no cookie, both of which are expected on a legitimate
  // logout flow initiated by Hydra post-revocation).
  const logoutSubject = _logout.subject;
  {
    let session: Session | null;
    try {
      session = await d.getSession(req.headers.get('cookie') ?? undefined);
    } catch {
      return redirect(`${process.env.OTHALA_PUBLIC_URL ?? ''}/auth/error?reason=auth-unreachable`);
    }
    if (logoutSubject && session?.active && session.identity && session.identity.id !== logoutSubject) {
      // Live session belongs to a DIFFERENT user than the logout subject.
      // Refuse to auto-accept — redirect to the portal home instead.
      const publicUrlBase = process.env.OTHALA_PUBLIC_URL ?? '';
      return redirect(`${publicUrlBase}/`);
    }
    // The live session is the subject's: signing out of an app ends the SSO
    // session, so revoke it before Hydra forgets the login. A failed revoke
    // must not accept, or the next authorize would sign straight back in.
    if (session?.active && session.identity) {
      try {
        if (!session.id) throw new Error('session without id');
        await d.revokeSession(session.id);
      } catch (e) {
        console.warn('[oauth2/logout] session revoke failed', { subject: logoutSubject, error: String(e) });
        const publicUrlBase = process.env.OTHALA_PUBLIC_URL ?? '';
        return redirect(`${publicUrlBase}/auth/error?reason=auth-unreachable`);
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

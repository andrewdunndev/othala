// Kratos public-API client used by Astro SSR pages.
//
// All flow GETs forward the user's incoming Cookie header so Kratos
// can read the anti-CSRF cookie set when the flow was created. Without
// that cookie the flow lookup returns 403.
//
// KRATOS_PUBLIC_URL resolution order:
//   1. process.env.KRATOS_PUBLIC_URL (compose / quadlet env)
//   2. http://localhost:4433 (local dev / test fallback)

import { Configuration, FrontendApi, ResponseError } from '@ory/client-fetch';
import type {
  FlowResult,
  LoginFlow,
  RecoveryFlow,
  RegistrationFlow,
  Session,
  SettingsFlow,
  VerificationFlow,
} from './types';

export function kratosBase(): string {
  return process.env.KRATOS_PUBLIC_URL ?? 'http://localhost:4433';
}

const HEALTH_TIMEOUT_MS = 2000;

function frontendApi(): FrontendApi {
  return new FrontendApi(
    new Configuration({
      basePath: kratosBase(),
    }),
  );
}

/**
 * GET /sessions/whoami
 *
 * Returns the active session or null if the cookie is absent/invalid/expired.
 * Throws on network failure or unexpected status (caller may catch to render
 * the infra-down state).
 */
export async function getSession(cookie?: string): Promise<Session | null> {
  try {
    const session = await frontendApi().toSession({ cookie });
    return session as unknown as Session;
  } catch (e) {
    if (e instanceof ResponseError && (e.response.status === 401 || e.response.status === 403)) {
      return null;
    }
    throw e;
  }
}

/**
 * Light health check used by the three-state landing.
 *
 * Hits a public endpoint with a 2s timeout. /health/alive is unauthenticated
 * on Kratos public; if Caddy proxies /admin/health/* through to Kratos we'd
 * hit that, but we keep this on the public surface to honour "no admin port
 * on the public internet."
 */
export async function isReachable(): Promise<boolean> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), HEALTH_TIMEOUT_MS);
  try {
    const res = await fetch(`${kratosBase()}/health/alive`, {
      signal: ctl.signal,
      redirect: 'manual',
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

// Generic flow fetcher over the SDK. Wraps the five get*Flow SDK methods into
// the FlowResult discriminated union the Astro pages depend on.
//
// Status mapping (preserved from the hand-rolled getFlow):
//   410 / 404 / 403 → { kind: 'gone' }   (expired, not-found, CSRF mismatch)
//   401             → { kind: 'unauthorized' }
//   2xx             → { kind: 'ok', flow }
//
// The SDK deserialises `expires_at` / `issued_at` as Date objects; the portal
// renderer treats those fields as opaque strings and never parses them, so the
// cast to the hand-maintained flow types is safe at the use-sites.
async function wrapFlowResult<T>(call: () => Promise<T>): Promise<FlowResult<T>> {
  try {
    const flow = await call();
    return { kind: 'ok', flow };
  } catch (e) {
    if (e instanceof ResponseError) {
      const s = e.response.status;
      if (s === 410 || s === 404 || s === 403) return { kind: 'gone' };
      if (s === 401) return { kind: 'unauthorized' };
    }
    throw e;
  }
}

export function getLoginFlow(flowId: string, cookie?: string): Promise<FlowResult<LoginFlow>> {
  return wrapFlowResult(() =>
    frontendApi()
      .getLoginFlow({ id: flowId, cookie })
      .then((f) => f as unknown as LoginFlow),
  );
}

export function getRegistrationFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<RegistrationFlow>> {
  return wrapFlowResult(() =>
    frontendApi()
      .getRegistrationFlow({ id: flowId, cookie })
      .then((f) => f as unknown as RegistrationFlow),
  );
}

export function getSettingsFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<SettingsFlow>> {
  return wrapFlowResult(() =>
    frontendApi()
      .getSettingsFlow({ id: flowId, cookie })
      .then((f) => f as unknown as SettingsFlow),
  );
}

export function getRecoveryFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<RecoveryFlow>> {
  return wrapFlowResult(() =>
    frontendApi()
      .getRecoveryFlow({ id: flowId, cookie })
      .then((f) => f as unknown as RecoveryFlow),
  );
}

export function getVerificationFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<VerificationFlow>> {
  return wrapFlowResult(() =>
    frontendApi()
      .getVerificationFlow({ id: flowId, cookie })
      .then((f) => f as unknown as VerificationFlow),
  );
}

/**
 * URL builders for Kratos browser-flow initiators. Pages redirect to these
 * when no flow ID is present (or the flow is gone).
 *
 * These MUST be browser-relative (same-origin), NOT kratosBase(): kratosBase()
 * is the SERVER-side Kratos URL (e.g. http://kratos:4433 inside the pod),
 * which the browser cannot resolve. The portal and Kratos's public API are the
 * same public origin (Caddy routes /self-service/* to Kratos), so a relative
 * path resolves correctly in the browser regardless of the deployment's
 * internal hostnames.
 */
export const browserFlows = {
  login(opts: { aal?: 'aal1' | 'aal2'; refresh?: boolean; returnTo?: string } = {}): string {
    const p = new URLSearchParams();
    if (opts.aal) p.set('aal', opts.aal);
    if (opts.refresh) p.set('refresh', 'true');
    if (opts.returnTo) p.set('return_to', opts.returnTo);
    const qs = p.toString();
    return `/self-service/login/browser${qs ? `?${qs}` : ''}`;
  },
  registration(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/registration/browser${qs}`;
  },
  settings(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/settings/browser${qs}`;
  },
  recovery(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/recovery/browser${qs}`;
  },
  verification(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/verification/browser${qs}`;
  },
  logout(returnTo?: string): string {
    // Browser logout endpoint returns 303 to a logout-with-token URL; the
    // typical pattern is to first GET /self-service/logout/browser to pick
    // up the token, then POST it. Astro pages render the form; the JSON
    // version is /self-service/logout/browser.
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/logout/browser${qs}`;
  },
};

/**
 * GET /self-service/logout/browser — returns { logout_url, logout_token }.
 * Pages render a button posting to logout_url to complete the logout.
 *
 * The SDK's LogoutFlow has exactly { logout_url, logout_token } — same
 * shape as LogoutInfo. LogoutInfo is kept as an alias for callers.
 */
export interface LogoutInfo {
  logout_url: string;
  logout_token: string;
}

export async function getLogoutInfo(cookie?: string): Promise<LogoutInfo | null> {
  try {
    const flow = await frontendApi().createBrowserLogoutFlow({ cookie });
    return flow as LogoutInfo;
  } catch (e) {
    if (e instanceof ResponseError && (e.response.status === 401 || e.response.status === 403)) {
      return null;
    }
    throw e;
  }
}

/**
 * D1: drive Kratos's OWN self-service recovery flow, server-side, for a
 * single address — the Kratos-native email delivery path for the
 * admin-triggered invite email. Kratos's courier sends the code; this adds
 * zero new mail machinery to the portal (nodemailer/mailer.ts is untouched).
 *
 * Uses the API flow type (`/self-service/recovery/api`), not the browser
 * flow: an API-flow submission needs no anti-CSRF cookie ("Sending the
 * anti-csrf token is only required for browser login flows" — the Ory SDK's
 * UpdateRecoveryFlowWithCodeMethod doc comment), so this is a clean two-call
 * server-to-server sequence with no cookie jar to thread through. The CSRF
 * hazard Kratos's own docs warn about ("MUST NOT use this endpoint in
 * server-side browser applications") is about handing an API flow to an
 * untrusted BROWSER; here the flow id is minted and redeemed inside this one
 * server-side call and never reaches a browser, so it does not apply.
 *
 * Bare fetch, not the @ory/client-fetch SDK: every SDK method throws
 * ResponseError on any non-2xx, but Kratos v26.2.x returns HTTP 400 for this
 * exact submission once the flow has moved past `choose_method` — a normal
 * state transition (the body is still the valid re-rendered flow), not a
 * failure. This is the same quirk e2e/playwright/tests/j-recovery-flow.spec.ts
 * and k-email-code-login.spec.ts already work around by treating
 * {200, 400, 422} as the single "accepted" outcome — mirrored here so
 * production and the e2e suite agree on what "sent" means.
 *
 * What success here does NOT prove: that the email left the SMTP relay.
 * Kratos queues courier messages and dispatches them on its own worker,
 * decoupled from this request/response — identical to the guarantee an
 * ordinary "Forgot access?" recovery already gives a member today. A
 * misconfigured OTHALA_SMTP_CONNECTION_URI on the Kratos side fails silently
 * from here (see D1 in DECISIONS.md and the admin-panel notice copy).
 *
 * Throws on a genuine failure (Kratos unreachable, malformed flow response,
 * or a status outside the accepted set). Never logs `email` — the caller
 * (portal/src/pages/admin/users/[id].astro) is responsible for keeping the
 * address out of server logs on both the success and error paths.
 */
export async function sendInviteRecoveryEmail(email: string): Promise<void> {
  const base = kratosBase();

  const initResp = await fetch(`${base}/self-service/recovery/api`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!initResp.ok) {
    throw new Error(`recovery flow init failed: HTTP ${initResp.status}`);
  }
  const flow = (await initResp.json()) as { id?: string };
  if (!flow.id) {
    throw new Error('recovery flow init returned no flow id');
  }

  const submitResp = await fetch(
    `${base}/self-service/recovery?flow=${encodeURIComponent(flow.id)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ method: 'code', email }),
    },
  );
  // 200 / 422 — standard re-render (code sent). 400 — Kratos v26
  // choose_method -> sent_email "flow state mismatch", which is STILL the
  // success path (see the function doc comment above). Anything else is a
  // real failure: Kratos down, the flow expired before we could submit, etc.
  if (submitResp.status !== 200 && submitResp.status !== 400 && submitResp.status !== 422) {
    throw new Error(`recovery email submit failed: HTTP ${submitResp.status}`);
  }
}

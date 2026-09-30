// Kratos public-API client for Astro SSR pages. Flow GETs forward the user's
// Cookie header so Kratos can read the anti-CSRF cookie (else 403).
// KRATOS_PUBLIC_URL defaults to http://localhost:4433.

import { Configuration, FrontendApi, ResponseError } from '@ory/client-fetch';
import type {
  FlowResult,
  LoginFlow,
  RecoveryFlow,
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
 * GET /sessions/whoami. Null when the cookie is absent, invalid or expired;
 * throws on network failure or an unexpected status.
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

/** Health check for the three-state landing: public /health/alive, 2s timeout. */
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

// Wraps the get*Flow SDK calls into the FlowResult union the pages use:
// 410/404/403 -> gone, 401 -> unauthorized, 2xx -> ok. The SDK's Date fields
// are never parsed by the renderer, so the casts to our flow types are safe.
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
 * URL builders for Kratos browser-flow initiators, redirected to when no flow
 * ID is present or the flow is gone. Browser-relative, NOT kratosBase(): that
 * is the server-side address, which the browser cannot resolve.
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
    // The endpoint 303s to a logout-with-token URL; see getLogoutInfo for the token.
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/logout/browser${qs}`;
  },
};

/** GET /self-service/logout/browser: the logout_url and logout_token for a sign-out POST. */
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
 * Drive Kratos's own recovery flow server-side for one address, so Kratos's
 * courier sends the invite email. Uses the API flow (no anti-CSRF cookie
 * needed); the flow id never reaches a browser.
 *
 * Bare fetch, not the SDK: the SDK throws on any non-2xx, but Kratos v26 answers
 * 400 for this submission once the flow has left `choose_method`, with a valid
 * body. {200, 400, 422} is the accepted set, as in the e2e recovery specs.
 *
 * Success does not prove the email left the SMTP relay; Kratos dispatches
 * courier messages on its own worker. Throws on a genuine failure. Never logs
 * `email`; the caller keeps the address out of server logs.
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
  // 400 is Kratos v26's "flow state mismatch" after choose_method: still success.
  // Anything else is a real failure.
  if (submitResp.status !== 200 && submitResp.status !== 400 && submitResp.status !== 422) {
    throw new Error(`recovery email submit failed: HTTP ${submitResp.status}`);
  }
}

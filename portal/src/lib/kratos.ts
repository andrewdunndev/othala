// Kratos public-API client used by Astro SSR pages.
//
// All flow GETs forward the user's incoming Cookie header so Kratos
// can read the anti-CSRF cookie set when the flow was created. Without
// that cookie the flow lookup returns 403.
//
// KRATOS_PUBLIC_URL resolution order:
//   1. process.env.KRATOS_PUBLIC_URL (compose / quadlet env)
//   2. http://localhost:4433 (local dev / test fallback)

import type {
  FlowResult,
  LoginFlow,
  RecoveryFlow,
  RegistrationFlow,
  Session,
  SettingsFlow,
  VerificationFlow,
} from './types';

function kratosBase(): string {
  return process.env.KRATOS_PUBLIC_URL ?? 'http://localhost:4433';
}

const HEALTH_TIMEOUT_MS = 2000;

interface FetchOpts {
  cookie?: string;
  signal?: AbortSignal;
}

function withCookie(opts: FetchOpts): HeadersInit {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (opts.cookie) headers['Cookie'] = opts.cookie;
  return headers;
}

/**
 * GET /sessions/whoami
 *
 * Returns the active session or null if the cookie is absent/invalid/expired.
 * Throws on network failure or unexpected status (caller may catch to render
 * the infra-down state).
 */
export async function getSession(cookie?: string): Promise<Session | null> {
  const res = await fetch(`${kratosBase()}/sessions/whoami`, {
    headers: withCookie({ cookie }),
    redirect: 'manual',
  });
  if (res.status === 401 || res.status === 403) return null;
  if (!res.ok) throw new Error(`whoami: ${res.status}`);
  return (await res.json()) as Session;
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

// Kratos self-service flows are browser-mediated; the SDK follows redirects + throws on non-2xx, we need 303s opaque + flow-state discrimination.
async function getFlow<T>(path: string, flowId: string, cookie?: string): Promise<FlowResult<T>> {
  const url = `${kratosBase()}${path}?id=${encodeURIComponent(flowId)}`;
  const res = await fetch(url, {
    headers: withCookie({ cookie }),
    redirect: 'manual',
  });
  if (res.status === 410 || res.status === 404 || res.status === 403) {
    // 410 Gone: flow expired. 404: not found. 403: CSRF cookie mismatch.
    // All three resolve the same way: start a fresh flow.
    return { kind: 'gone' };
  }
  if (res.status === 401) return { kind: 'unauthorized' };
  if (!res.ok) throw new Error(`flow ${path}: ${res.status}`);
  const flow = (await res.json()) as T;
  return { kind: 'ok', flow };
}

export function getLoginFlow(flowId: string, cookie?: string): Promise<FlowResult<LoginFlow>> {
  return getFlow<LoginFlow>('/self-service/login/flows', flowId, cookie);
}

export function getRegistrationFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<RegistrationFlow>> {
  return getFlow<RegistrationFlow>('/self-service/registration/flows', flowId, cookie);
}

export function getSettingsFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<SettingsFlow>> {
  return getFlow<SettingsFlow>('/self-service/settings/flows', flowId, cookie);
}

export function getRecoveryFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<RecoveryFlow>> {
  return getFlow<RecoveryFlow>('/self-service/recovery/flows', flowId, cookie);
}

export function getVerificationFlow(
  flowId: string,
  cookie?: string,
): Promise<FlowResult<VerificationFlow>> {
  return getFlow<VerificationFlow>('/self-service/verification/flows', flowId, cookie);
}

/**
 * URL builders for Kratos browser-flow initiators. Pages redirect to these
 * when no flow ID is present (or the flow is gone).
 */
export const browserFlows = {
  login(opts: { aal?: 'aal1' | 'aal2'; refresh?: boolean; returnTo?: string } = {}): string {
    const p = new URLSearchParams();
    if (opts.aal) p.set('aal', opts.aal);
    if (opts.refresh) p.set('refresh', 'true');
    if (opts.returnTo) p.set('return_to', opts.returnTo);
    const qs = p.toString();
    return `${kratosBase()}/self-service/login/browser${qs ? `?${qs}` : ''}`;
  },
  registration(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${kratosBase()}/self-service/registration/browser${qs}`;
  },
  settings(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${kratosBase()}/self-service/settings/browser${qs}`;
  },
  recovery(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${kratosBase()}/self-service/recovery/browser${qs}`;
  },
  verification(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${kratosBase()}/self-service/verification/browser${qs}`;
  },
  logout(returnTo?: string): string {
    // Browser logout endpoint returns 303 to a logout-with-token URL; the
    // typical pattern is to first GET /self-service/logout/browser to pick
    // up the token, then POST it. Astro pages render the form; the JSON
    // version is /self-service/logout/browser.
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `${kratosBase()}/self-service/logout/browser${qs}`;
  },
};

/**
 * GET /self-service/logout/browser — returns { logout_url, logout_token }.
 * Pages render a button posting to logout_url to complete the logout.
 */
export interface LogoutInfo {
  logout_url: string;
  logout_token: string;
}

export async function getLogoutInfo(cookie?: string): Promise<LogoutInfo | null> {
  const res = await fetch(`${kratosBase()}/self-service/logout/browser`, {
    headers: withCookie({ cookie }),
    redirect: 'manual',
  });
  if (res.status === 401 || res.status === 403) return null;
  if (!res.ok) throw new Error(`logout info: ${res.status}`);
  return (await res.json()) as LogoutInfo;
}

export { kratosBase };

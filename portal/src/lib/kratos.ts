// Flow GETs forward the user's Cookie header: without its anti-CSRF cookie Kratos answers 403.

import { Configuration, FrontendApi, ResponseError } from '@ory/client-fetch';
import { KRATOS_PUBLIC_URL } from './constants';
import { timeoutFetch } from './ory-fetch';
import type {
  FlowResult,
  LoginFlow,
  RecoveryFlow,
  Session,
  SettingsFlow,
  VerificationFlow,
} from './types';

export function kratosBase(): string {
  return KRATOS_PUBLIC_URL;
}

const HEALTH_TIMEOUT_MS = 2000;

function frontendApi(): FrontendApi {
  return new FrontendApi(
    new Configuration({
      basePath: kratosBase(),
      fetchApi: timeoutFetch(),
    }),
  );
}

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

const ERROR_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function getFlowError(id: string): Promise<{ id?: unknown; code?: unknown } | null> {
  if (!ERROR_ID.test(id)) return null;
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), HEALTH_TIMEOUT_MS);
  try {
    const res = await fetch(`${kratosBase()}/self-service/errors?id=${encodeURIComponent(id)}`, {
      signal: ctl.signal,
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { error?: { id?: unknown; code?: unknown } };
    return body?.error ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// The renderer never reads the SDK's Date fields, so casting to our flow types is safe.
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

// Browser-relative: kratosBase() is a server-side address the browser cannot resolve.
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
  /** `email` rides in the initiating URL, which Kratos keeps as the flow's request_url, so the verification page can prefill it. */
  verification(returnTo?: string, email?: string): string {
    const p = new URLSearchParams();
    if (returnTo) p.set('return_to', returnTo);
    if (email) p.set('email', email);
    const qs = p.toString();
    return `/self-service/verification/browser${qs ? `?${qs}` : ''}`;
  },
  logout(returnTo?: string): string {
    const qs = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : '';
    return `/self-service/logout/browser${qs}`;
  },
};

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

/** Runs Kratos's API recovery flow so its courier sends the invite. Never logs the address. */
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
  // Kratos answers 400 once the flow has left choose_method, which the SDK would throw on.
  if (submitResp.status !== 200 && submitResp.status !== 400 && submitResp.status !== 422) {
    throw new Error(`recovery email submit failed: HTTP ${submitResp.status}`);
  }
}

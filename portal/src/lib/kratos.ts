// Flow GETs forward the user's Cookie header: without its anti-CSRF cookie Kratos answers 403.

import { Configuration, FrontendApi, ResponseError } from '@ory/client-fetch';
import { KRATOS_PUBLIC_URL } from './constants';
import { UUID_RE } from './uuid';
import { timeoutFetch } from './ory-fetch';
import type {
  FlowResult,
  LoginFlow,
  RecoveryFlow,
  Session,
  SettingsFlow,
  VerificationFlow,
} from './types';

function frontendApi(timeoutMs?: number): FrontendApi {
  return new FrontendApi(
    new Configuration({
      basePath: KRATOS_PUBLIC_URL,
      fetchApi: timeoutFetch(timeoutMs),
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

// The error page must stay quick when Kratos is down, so this read gives up sooner than the flow getters.
const ERROR_PAGE_TIMEOUT_MS = 2000;

export async function getFlowError(id: string): Promise<{ id?: unknown; code?: unknown } | null> {
  const flowErrorId = id.toLowerCase();
  if (!UUID_RE.test(flowErrorId)) return null;
  try {
    const flowError = await frontendApi(ERROR_PAGE_TIMEOUT_MS).getFlowError({ id: flowErrorId });
    return (flowError.error as { id?: unknown; code?: unknown } | undefined) ?? null;
  } catch {
    return null;
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

// Browser-relative: KRATOS_PUBLIC_URL is a server-side address the browser cannot resolve.
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

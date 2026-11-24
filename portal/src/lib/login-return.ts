// An app sign-in's return (/oauth2/login?login_challenge=...) across a login flow Kratos will no longer run. Kratos
// answers a POST to a flow the session already satisfies (not a refresh, requested AAL at or below the session's) with
// a bare 303 to default_browser_return_url, before any strategy and without the flow's return_to. So a flow is not
// offered once spent, and the return is also kept in a short cookie for the POST that still reaches Kratos, which the
// landing sends back to /oauth2/login, where the app's gate (skip_step_up included) decides.
// __Host-: no sibling subdomain can plant one, and Path=/ reaches the landing and the login page.

import type { LoginFlow, Session } from './types';

export const LOGIN_RETURN_COOKIE = '__Host-othala_login_return';
const MAX_AGE_S = 300;
const RETURN_RE = /^\/oauth2\/login\?login_challenge=[A-Za-z0-9._~*+%-]+$/;
const MAX_LEN = 3000;

export function isLoginReturn(path: string): boolean {
  return path.length <= MAX_LEN && RETURN_RE.test(path);
}

/** A flow's return_to as a relative /oauth2/login return, whether it is stored relative or absolute on `origin`. */
export function loginReturnOf(returnTo: string | undefined, origin: string): string | undefined {
  if (!returnTo) return undefined;
  if (isLoginReturn(returnTo)) return returnTo;
  try {
    const u = new URL(returnTo);
    const path = u.pathname + u.search;
    return u.origin === new URL(origin).origin && isLoginReturn(path) ? path : undefined;
  } catch {
    return undefined;
  }
}

/** True when Kratos would answer any POST to `flow` with the bare 303: a live session already at the flow's AAL. */
export function flowSpent(
  flow: Pick<LoginFlow, 'refresh' | 'requested_aal'>,
  session: Pick<Session, 'active' | 'authenticator_assurance_level'> | null | undefined,
): boolean {
  if (flow.refresh || !session?.active) return false;
  return flow.requested_aal !== 'aal2' || session.authenticator_assurance_level === 'aal2';
}

/** Set-Cookie keeping `path`; empty when it is not a relative /oauth2/login return. */
export function keepLoginReturn(path: string): string[] {
  if (!isLoginReturn(path)) return [];
  return [`${LOGIN_RETURN_COOKIE}=${encodeURIComponent(path)}; Path=/; Max-Age=${MAX_AGE_S}; HttpOnly; Secure; SameSite=Lax`];
}

export function clearLoginReturn(): string {
  return `${LOGIN_RETURN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

/** The kept return from a Cookie header, or undefined when there is none or it is not a relative /oauth2/login path. */
export function readLoginReturn(cookie: string | null | undefined): string | undefined {
  for (const part of (cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0 || part.slice(0, i).trim() !== LOGIN_RETURN_COOKIE) continue;
    try {
      const value = decodeURIComponent(part.slice(i + 1).trim());
      return isLoginReturn(value) ? value : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

// A login flow the session already satisfies is spent. Kratos answers a POST to such a flow (not a refresh, requested
// AAL at or below the session's) with a bare 303 to default_browser_return_url, before any strategy and without the
// flow's return_to. So the login page never offers one: it continues to the flow's /oauth2/login return, where the
// app's gate (skip_step_up included) decides, or to the landing.

import type { LoginFlow, Session } from './types';

const RETURN_RE = /^\/oauth2\/login\?login_challenge=[A-Za-z0-9._~*+%-]+$/;
const MAX_LEN = 3000;

const isLoginReturn = (path: string): boolean => path.length <= MAX_LEN && RETURN_RE.test(path);

/** True when Kratos would answer any POST to `flow` with the bare 303: a live session already at the flow's AAL. */
export function flowSpent(
  flow: Pick<LoginFlow, 'refresh' | 'requested_aal'>,
  session: Pick<Session, 'active' | 'authenticator_assurance_level'> | null | undefined,
): boolean {
  if (flow.refresh || !session?.active) return false;
  return flow.requested_aal !== 'aal2' || session.authenticator_assurance_level === 'aal2';
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

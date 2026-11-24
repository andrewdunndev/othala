// A login flow the session already satisfies is spent. Kratos answers a POST to such a flow (not a refresh, requested
// AAL at or below the session's) with a bare 303 to default_browser_return_url, before any strategy and without the
// flow's return_to. So the login page never offers one: it continues to the flow's /oauth2/login return, where the
// app's gate (skip_step_up included) decides, or to the landing.

import type { LoginFlow, Session } from './types';

/** True when Kratos would answer any POST to `flow` with the bare 303: a live session already at the flow's AAL. */
export function flowSpent(
  flow: Pick<LoginFlow, 'refresh' | 'requested_aal'>,
  session: Pick<Session, 'active' | 'authenticator_assurance_level'> | null | undefined,
): boolean {
  if (flow.refresh || !session?.active) return false;
  return flow.requested_aal !== 'aal2' || session.authenticator_assurance_level === 'aal2';
}

/**
 * A flow's return_to as a relative /oauth2/login?login_challenge=... path on `origin`, or undefined. Kratos reports the
 * return_to query value of the flow's request URL, so it may be relative or absolute and the challenge may be long.
 */
export function loginReturnOf(returnTo: string | undefined, origin: string): string | undefined {
  if (!returnTo) return undefined;
  try {
    const base = new URL(origin);
    const u = new URL(returnTo, base);
    const challenge = u.searchParams.get('login_challenge');
    if (u.origin !== base.origin || u.pathname !== '/oauth2/login' || !challenge) return undefined;
    return `/oauth2/login?${new URLSearchParams({ login_challenge: challenge }).toString()}`;
  } catch {
    return undefined;
  }
}

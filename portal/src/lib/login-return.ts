// The OAuth return of an app sign-in in progress, kept in a cookie beside the Kratos flow. Kratos answers a login POST it
// will not run (the session already holds the flow's AAL) with a bare 303 to default_browser_return_url, which drops the
// flow's return_to; the landing and the login page read this cookie so the sign-in goes back to /oauth2/login.
// __Host-: no sibling subdomain can plant one, and Path=/ reaches the landing and the login page.

export const LOGIN_RETURN_COOKIE = '__Host-othala_login_return';
// Shorter than Hydra's login request lifespan, so a kept return never outlives its challenge by much.
const MAX_AGE_S = 600;
const RETURN_RE = /^\/oauth2\/login\?login_challenge=[A-Za-z0-9._~*+%-]+$/;
const MAX_LEN = 3000;

export function isLoginReturn(path: string): boolean {
  return path.length <= MAX_LEN && RETURN_RE.test(path);
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

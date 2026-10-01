// The actions an error page offers, by what went wrong and who is looking. A hiccup gets Try again; a refusal gets a way
// home; Sign in appears only for someone who is signed out.

export interface StatusAction {
  href: string;
  label: string;
  primary: boolean;
}

/** Errors worth retrying as they are: the service was busy or away, not the person's doing. */
export const isTransient = (status: number): boolean => status === 429 || status >= 500;

/** Refusals that signing in again cannot fix: the app is wrong, or the person cancelled. */
const NO_SIGN_IN = new Set(["app-misconfigured", "sign-in-cancelled"]);

export function statusActions(status: number, signedIn: boolean, retryHref: string, reason?: string): StatusAction[] {
  if (isTransient(status)) {
    const retry = { href: retryHref, label: 'Try again', primary: true };
    // When Try again already goes home, a second Go home would say the same thing twice.
    return retryHref === '/' ? [retry] : [retry, { href: '/', label: 'Go home', primary: false }];
  }
  if (status === 410) {
    return [{ href: '/auth/login', label: 'Start again', primary: true }, { href: '/', label: 'Go home', primary: false }];
  }
  if (status === 401 && !signedIn) {
    return [{ href: '/auth/login', label: 'Sign in', primary: true }, { href: '/', label: 'Go home', primary: false }];
  }
  const home = { href: '/', label: 'Go home', primary: true };
  if (reason && NO_SIGN_IN.has(reason)) return [home];
  return signedIn ? [home] : [home, { href: '/auth/login', label: 'Sign in', primary: false }];
}

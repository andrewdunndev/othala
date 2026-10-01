// The actions an error page offers, by what went wrong and who is looking. A hiccup gets Try again; a refusal gets a way
// home; Sign in appears only for someone who is signed out.

export interface StatusAction {
  href: string;
  label: string;
  primary: boolean;
}

/** Errors worth retrying as they are: the service was busy or away, not the person's doing. */
export const isTransient = (status: number): boolean => status === 429 || status >= 500;

export function statusActions(status: number, signedIn: boolean, retryHref: string): StatusAction[] {
  if (isTransient(status)) {
    const retry = { href: retryHref, label: 'Try again', primary: true };
    // When Try again already goes home, a second Go home would say the same thing twice.
    return retryHref === '/' ? [retry] : [retry, { href: '/', label: 'Go home', primary: false }];
  }
  if (status === 401 && !signedIn) {
    return [{ href: '/auth/login', label: 'Sign in', primary: true }, { href: '/', label: 'Go home', primary: false }];
  }
  const home = { href: '/', label: 'Go home', primary: true };
  return signedIn ? [home] : [home, { href: '/auth/login', label: 'Sign in', primary: false }];
}

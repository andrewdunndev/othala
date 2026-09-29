// Sign-out gate for /auth/logout.
//
// Ending a session is a state change, so it rides the same per-request token
// as every other portal form: a GET only renders the confirm form, and only a
// POST carrying a token minted for this identity's sign-out proceeds.

import { signToken, verifyToken, CSRFError } from './csrf';

export const LOGOUT_ACTION = 'logout';

/** Mint the token the sign-out form carries. */
export function signLogoutToken(identityId: string): string {
  return signToken(identityId, LOGOUT_ACTION);
}

/**
 * True only for a POST whose token was minted for this identity's sign-out.
 * Any token failure answers false (fails closed); the caller re-renders the
 * confirm form rather than ending the session.
 */
export function logoutAuthorized(
  method: string,
  presented: FormDataEntryValue | null | undefined,
  identityId: string,
): boolean {
  if (method.toUpperCase() !== 'POST') return false;
  if (typeof presented !== 'string' || !presented) return false;
  try {
    verifyToken(presented, identityId, LOGOUT_ACTION);
    return true;
  } catch (err) {
    if (err instanceof CSRFError) return false;
    throw err;
  }
}

/**
 * A tokenless sign-out is only honoured when the browser says the request
 * came from this portal: an Origin equal to `ownOrigin`, or no Origin and a
 * Referer on `ownOrigin`.
 */
export function sameOriginRequest(
  origin: string | null,
  referer: string | null,
  ownOrigin: string,
): boolean {
  if (origin !== null) return origin === ownOrigin;
  if (!referer) return false;
  try {
    return new URL(referer).origin === ownOrigin;
  } catch {
    return false;
  }
}

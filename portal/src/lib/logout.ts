import { signToken, verifyToken, CSRFError } from './csrf';
import { revokeHydraSessions, RevokeError } from './revoke';

export const LOGOUT_ACTION = 'logout';

export function signLogoutToken(identityId: string): string {
  return signToken(identityId, LOGOUT_ACTION);
}

/** Sign-out is a state change, so only a POST carrying this identity's sign-out token proceeds. */
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

export async function endAppSignIns(identityId: string): Promise<boolean> {
  try {
    await revokeHydraSessions(identityId);
    return true;
  } catch (err) {
    const step = err instanceof RevokeError ? err.step : 'unknown';
    console.warn(`[othala/logout] could not end app sign-ins (step ${step}); signing out of the portal anyway.`);
    return false;
  }
}

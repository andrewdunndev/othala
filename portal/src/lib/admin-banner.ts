// The one result line the person page shows after an action, in household words. Pure, so each outcome's wording and
// tone are testable. The setup-link outcome has its own card and is not described here.

import type { ActionResult } from './admin-actions';

export type BannerTone = 'success' | 'warning' | 'danger';
export interface Banner {
  tone: BannerTone;
  text: string;
}

const CREDENTIALS: Record<string, string> = {
  totp: 'the authenticator app',
  webauthn: 'the security keys',
  lookup_secret: 'the backup codes',
};

/** What a successful save said it saved, by the action that ran. */
const SAVED: Record<string, string> = {
  'save-access': 'Access saved.',
  'save-household': 'Household saved.',
  'save-profile': 'Profile saved.',
  'remove-groups': 'Group removed.',
};

export function bannerFor(result: ActionResult, action: string, who: string): Banner | null {
  switch (result.kind) {
    case 'updated':
      return {
        tone: 'success',
        text: result.removed.length > 0 ? `${SAVED[action] ?? 'Saved.'} Removed ${result.removed.join(', ')}.` : (SAVED[action] ?? 'Saved.'),
      };
    case 'deactivated':
      return { tone: 'warning', text: `Sign-in is off for ${who}. Their devices were signed out.` };
    case 'reactivated':
      return { tone: 'success', text: `Sign-in is back on for ${who}. They will need to sign in again.` };
    case 'admin-granted':
      return { tone: 'success', text: `${who} is now a household admin.` };
    case 'admin-revoked':
      return { tone: 'warning', text: `${who} is no longer a household admin.` };
    case 'revoked':
      return { tone: 'success', text: `${who} is signed out everywhere.` };
    case 'credential-removed':
      return { tone: 'warning', text: `Removed ${CREDENTIALS[result.credType] ?? result.credType}. Send a setup link so ${who} can set it up again.` };
    case 'email-verified':
      return { tone: 'success', text: `${who}'s email is marked as verified.` };
    case 'prerequisites-saved':
      return { tone: 'success', text: 'Prerequisites saved.' };
    case 'avatar-saved':
      return { tone: 'success', text: result.removed ? 'Picture removed.' : 'Picture saved.' };
    case 'error':
      return { tone: 'danger', text: result.message };
    case 'recovery':
      return null;
  }
}

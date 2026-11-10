// House-voice confirmations for the settings page. Kratos reports one generic "saved" for every method, so the page
// script keys the action the person took (the submitter's name, or `method:<value>`) to the sentence shown in the card.
import { AVATAR_REFUSALS } from './avatar';

export const FLASH: Record<string, string> = {
  'method:totp': 'Authenticator app added.',
  totp_unlink: 'Authenticator app removed.',
  totp_replace: 'Old app removed. Scan the new code below, then enter the code your app shows.',
  passkey_rename: 'Name saved.',
  passkey_remove: 'Passkey removed.',
  webauthn_remove: 'Security key removed.',
  passkey_register_trigger: 'Passkey added.',
  webauthn_register_trigger: 'Security key added.',
  'method:password': 'Password changed. Your other devices are signed out.',
  'method:profile': 'Profile saved.',
  lookup_secret_regenerate: 'New backup codes ready. Save them now.',
  lookup_secret_confirm: 'Backup codes saved.',
  lookup_secret_disable: 'Backup codes turned off.',
};

/** Removals after which a lost device may still be signed in somewhere: the saved line offers to sign out everywhere. */
export const LOST_KEYS = new Set(['passkey_remove', 'webauthn_remove', 'totp_unlink']);

export const flashKey = (name: string, value: string): string => (name === 'method' ? `method:${value}` : name);

/** Kratos messages worth saying in the house voice, by message id. Anything else passes through. */
const MESSAGES: Record<number, string> = {
  1050001: 'Saved.',
  1060001: "You're signed in with your setup code. Add a passkey now so signing in takes one tap.",
  4000008: "That code didn't work. Codes change every 30 seconds, so try the one showing now.",
};
export const messageText = (m: { id: number; text: string }): string => MESSAGES[m.id] ?? m.text;

/** A setup key in groups of four, easier to read aloud and to type. */
export const groupKey = (s: string): string => s.replace(/\s+/g, '').replace(/(.{4})(?=.)/g, '$1 ');

/** Why a rename did not land, as the sentence under that passkey's row. */
export const RENAME_ERRORS: Record<string, string> = {
  name: 'Give the passkey a name of up to 40 characters.',
  unknown: 'That passkey is no longer on your account.',
  csrf: 'That page was out of date. Try again.',
  busy: 'Could not save the name. Try again in a moment.',
};

export const RENAME_ERROR_COOKIE = 'othala_rename_error';

/** The sentence a picture change leaves in the Picture card, by the code the POST left in the cookie. */
export const AVATAR_FLASH: Record<string, { tone: 'success' | 'danger'; text: string }> = {
  set: { tone: 'success', text: 'Picture saved. Apps pick it up the next time you sign in to them.' },
  removed: { tone: 'success', text: 'Picture removed.' },
  empty: { tone: 'danger', text: AVATAR_REFUSALS.empty },
  'too-large': { tone: 'danger', text: AVATAR_REFUSALS['too-large'] },
  type: { tone: 'danger', text: AVATAR_REFUSALS.type },
  csrf: { tone: 'danger', text: 'That page was out of date. Try again.' },
  busy: { tone: 'danger', text: 'Could not save the picture. Try again in a moment.' },
};

export const AVATAR_FLASH_COOKIE = 'othala_avatar_flash';

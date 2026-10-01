// Invariant: the settings page's house-voice sentences cover every action it offers, and key and message helpers are exact.

import { describe, it, expect } from 'vitest';
import { FLASH, flashKey, groupKey, messageText, RENAME_ERRORS } from './settings-flash';

describe('settings flash', () => {
  it('keys a method submit by its value and any other submit by its name', () => {
    expect(flashKey('method', 'totp')).toBe('method:totp');
    expect(flashKey('passkey_remove', 'ab')).toBe('passkey_remove');
    expect(FLASH[flashKey('method', 'totp')]).toBe('Authenticator app added.');
  });

  it('says every enrollment and removal in its own words', () => {
    for (const k of ['totp_unlink', 'passkey_remove', 'webauthn_remove', 'passkey_register_trigger', 'webauthn_register_trigger', 'lookup_secret_disable']) {
      expect(FLASH[k], k).toBeTruthy();
    }
    expect(new Set(Object.values(FLASH)).size).toBe(Object.keys(FLASH).length);
  });

  it('rewords the refused-code and saved messages, and passes others through', () => {
    expect(messageText({ id: 4000008, text: 'The provided authentication code is invalid, please try again.' })).toMatch(/didn't work/);
    expect(messageText({ id: 1050001, text: 'Your changes have been saved!' })).toBe('Saved.');
    expect(messageText({ id: 1, text: 'as is' })).toBe('as is');
  });

  it('groups a setup key in fours without a trailing space', () => {
    expect(groupKey('JBSWY3DPEHPK3PXP')).toBe('JBSW Y3DP EHPK 3PXP');
    expect(groupKey('JBSWY3DPE')).toBe('JBSW Y3DP E');
    expect(groupKey('JBSW Y3DP')).toBe('JBSW Y3DP');
  });

  it('has a sentence for every rename refusal', () => {
    expect(Object.keys(RENAME_ERRORS).sort()).toEqual(['busy', 'csrf', 'name', 'unknown']);
  });
});

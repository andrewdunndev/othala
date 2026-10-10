// Invariant: the settings view model reads each recorded fixture state the way the page presents it.

import { describe, it, expect } from 'vitest';
import { splitCodes, credentialItems, totpView, lookupView, securityStatus, passwordPanelOpen, keyOnlyKeeper, emailVerified, formatAdded } from './settings-view';
import { devSettings, isDevSettingsState } from './settings-fixtures';

const nodesOf = (s: Parameters<typeof devSettings>[0]) => devSettings(s).flow.ui.nodes;

describe('settings view over the fixtures', () => {
  it('rejects anything that is not a fixture state', () => {
    expect(isDevSettingsState('nope')).toBe(false);
    expect(isDevSettingsState(null)).toBe(false);
  });

  it('a fresh account has nothing enrolled and offers a QR', () => {
    const n = nodesOf('fresh');
    expect(securityStatus(n, { emailVerified: true })).toMatchObject({ passkeys: 0, securityKeys: 0, twoStep: false, backupCodes: false });
    const t = totpView(n);
    expect(t.enrolled).toBe(false);
    expect(t.qr?.src).toMatch(/^data:image\/svg/);
    expect(t.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(t.codeInput?.name).toBe('totp_code');
    expect(t.save?.value).toBe('totp');
  });

  it('lists passkeys and keys with dates, applying stored names over Kratos\'s "unnamed"', () => {
    const n = nodesOf('enrolled');
    const keys = credentialItems(n, 'webauthn_remove');
    expect(keys).toHaveLength(1);
    expect(keys[0].name).toBe('Keyring key');
    const plain = credentialItems(n, 'passkey_remove');
    expect(plain.map((p) => p.name)).toEqual([null, null, 'iCloud Keychain']);
    expect(formatAdded(plain[0].addedAt)).toBe('12 Jun 2026');
    const named = credentialItems(n, 'passkey_remove', { [plain[1].id]: 'Pixel phone' });
    expect(named.map((p) => p.name)).toEqual([null, 'Pixel phone', 'iCloud Keychain']);
  });

  it('the enrolled account reads two-step on with backup codes saved', () => {
    const n = nodesOf('enrolled');
    expect(securityStatus(n, { emailVerified: true })).toMatchObject({ passkeys: 3, securityKeys: 1, twoStep: true, backupCodes: true, emailUnverified: false });
    expect(totpView(n).enrolled).toBe(true);
    expect(lookupView(n).enrolled).toBe(true);
  });

  it('a wrong code keeps the QR and carries the error on the code input', () => {
    const t = totpView(nodesOf('totp-wrong-code'));
    expect(t.qr).not.toBeNull();
    expect(t.codeMessages[0]?.type).toBe('error');
  });

  it('success enrols the app without saved backup codes', () => {
    const d = devSettings('success');
    expect(d.flow.state).toBe('success');
    const s = securityStatus(d.flow.ui.nodes, { emailVerified: true });
    expect(s.twoStep).toBe(true);
    expect(s.backupCodes).toBe(false);
  });

  it('keyOnlyKeeper holds only for a keeper with exactly one key and no app', () => {
    const enrolled = nodesOf('enrolled');
    const keyOnly = enrolled.filter((n) => n.group !== 'totp');
    expect(keyOnlyKeeper(keyOnly, true)).toBe(true);
    expect(keyOnlyKeeper(keyOnly, false)).toBe(false);
    expect(keyOnlyKeeper(enrolled, true)).toBe(false);
    expect(keyOnlyKeeper(nodesOf('fresh'), true)).toBe(false);
    expect(keyOnlyKeeper(keyOnly.filter((n) => n.group !== 'webauthn'), true)).toBe(false);
  });

  it('flags an unverified email only when the address is known unverified', () => {
    expect(emailVerified({ traits: { email: 'A@x.test' }, verifiable_addresses: [{ value: 'a@x.test', verified: false }] })).toBe(false);
    expect(emailVerified({ traits: { email: 'a@x.test' }, verifiable_addresses: [{ value: 'a@x.test', verified: true }] })).toBe(true);
    expect(emailVerified({ traits: { email: 'a@x.test' }, verifiable_addresses: [] })).toBeNull();
    expect(securityStatus([], { emailVerified: false }).emailUnverified).toBe(true);
    expect(securityStatus([], { emailVerified: null }).emailUnverified).toBe(false);
  });

  it('reads backup codes one by one from the revealed and the new-codes states', () => {
    for (const st of ['codes-reveal', 'codes-new'] as const) {
      const l = lookupView(nodesOf(st));
      expect(l.list).toHaveLength(12);
      expect(l.list.every((c) => c.code && !c.used)).toBe(true);
    }
    expect(securityStatus(nodesOf('codes-new'), { emailVerified: true }).backupCodes).toBe(false);
  });

  it('splits the comma-joined text when the per-code messages are absent, and marks used codes', () => {
    expect(splitCodes('aaaa-bbbb, cccc-dddd, used')).toEqual([
      { code: 'aaaa-bbbb', used: false }, { code: 'cccc-dddd', used: false }, { code: 'used', used: true },
    ]);
    expect(splitCodes('x', { secrets: [{ context: { secret: 'one' } }, { context: {} }] })).toEqual([{ code: 'one', used: false }, { code: '', used: true }]);
  });
});

describe('passwordPanelOpen', () => {
  it('opens with no password yet, and for a refusal; otherwise stays collapsed', () => {
    const nodes = nodesOf('fresh');
    expect(passwordPanelOpen(nodes, false)).toBe(true);
    expect(passwordPanelOpen(nodes, true)).toBe(false);
    const refused = nodes.map((n) => (n.group === 'password' ? { ...n, messages: [{ id: 1, text: 'no', type: 'error' as const }] } : n));
    expect(passwordPanelOpen(refused, true)).toBe(true);
  });
});

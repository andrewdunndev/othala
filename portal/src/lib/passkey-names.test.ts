// Invariant: a passkey name is written only for a credential the signed-in identity owns, as a targeted patch that
// leaves every other metadata_admin key alone; stale names are pruned, display reads fall back cleanly.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  applyRename,
  cleanPasskeyName,
  ownsPasskey,
  passkeyCredentialIds,
  pruneNames,
  readPasskeyNames,
  renameVerdict,
} from './passkey-names';
import { validateMetadataAdmin, MetadataAdminError } from './metadata-admin';
import type { Identity } from './types';

const b64 = (hex: string) => Buffer.from(hex, 'hex').toString('base64');
const MINE = 'a1b2c3d4e5f60718';
const OTHER = '0f0e0d0c0b0a0908';

function identityWith(ids: string[]): Identity {
  return {
    id: 'me-id',
    traits: { username: 'sam', email: 'sam@example.test' },
    credentials: { passkey: { type: 'passkey', config: { credentials: ids.map((id) => ({ id: b64(id) })) } } },
  } as unknown as Identity;
}

describe('passkey names', () => {
  it('cleans names: trims, collapses whitespace, strips controls, bounds the length', () => {
    expect(cleanPasskeyName('  Work   laptop ')).toBe('Work laptop');
    expect(cleanPasskeyName('a\u0000b\nc')).toBe('a b c');
    expect(cleanPasskeyName('')).toBeNull();
    expect(cleanPasskeyName('   ')).toBeNull();
    expect(cleanPasskeyName('x'.repeat(41))).toBeNull();
    expect(cleanPasskeyName('x'.repeat(40))).toBe('x'.repeat(40));
    expect(cleanPasskeyName(7)).toBeNull();
  });

  it('reads stored names tolerantly, dropping bad keys and values', () => {
    expect(readPasskeyNames({ passkeyNames: { [MINE]: 'Phone', 'not hex': 'x', [OTHER]: 5 } })).toEqual({ [MINE]: 'Phone' });
    expect(readPasskeyNames(undefined)).toEqual({});
    expect(readPasskeyNames({ passkeyNames: ['a'] })).toEqual({});
  });

  it('lists credential ids as the hex a passkey_remove node carries', () => {
    expect(passkeyCredentialIds(identityWith([MINE, OTHER]))).toEqual([MINE, OTHER]);
    expect(passkeyCredentialIds({ id: 'x' } as unknown as Identity)).toEqual([]);
  });

  it('ownership: only the identity\'s own credential ids', () => {
    const me = identityWith([MINE]);
    expect(ownsPasskey(me, MINE)).toBe(true);
    expect(ownsPasskey(me, OTHER)).toBe(false);
    expect(ownsPasskey(me, '')).toBe(false);
    expect(ownsPasskey(me, `${MINE}/../x`)).toBe(false);
    expect(ownsPasskey(identityWith([]), MINE)).toBe(false);
  });

  it('prunes only names whose credential is gone', () => {
    expect(pruneNames({ [MINE]: 'Phone', [OTHER]: 'Old' }, [MINE])).toEqual({ [MINE]: 'Phone' });
    expect(pruneNames({ [MINE]: 'Phone' }, [MINE, OTHER])).toBeNull();
    expect(pruneNames({}, [])).toBeNull();
    expect(pruneNames({ [MINE]: 'Phone' }, [])).toEqual({});
  });

  it('rename verdicts: malformed 400, foreign 403, unusable name 400, else ok', () => {
    const me = identityWith([MINE]);
    expect(renameVerdict(me, undefined, 'x')).toMatchObject({ ok: false, status: 400 });
    expect(renameVerdict(me, 'ZZ', 'x')).toMatchObject({ ok: false, status: 400 });
    expect(renameVerdict(me, OTHER, 'x')).toMatchObject({ ok: false, status: 403 });
    expect(renameVerdict(me, MINE, '  ')).toMatchObject({ ok: false, status: 400 });
    expect(renameVerdict(me, MINE, ' Pixel ')).toEqual({ ok: true, name: 'Pixel' });
  });
});

describe('applyRename', () => {
  const patch = vi.fn(async () => {});
  beforeEach(() => patch.mockClear());

  it('writes for an owned credential, with the cleaned name', async () => {
    const v = await applyRename(identityWith([MINE]), MINE, ' Pixel  phone ', patch);
    expect(v.ok).toBe(true);
    expect(patch).toHaveBeenCalledExactlyOnceWith('me-id', MINE, 'Pixel phone');
  });

  it('never writes for a credential another identity owns', async () => {
    const v = await applyRename(identityWith([MINE]), OTHER, 'Mine now', patch);
    expect(v).toMatchObject({ ok: false, status: 403 });
    expect(patch).not.toHaveBeenCalled();
  });

  it('never writes for a malformed id or empty name', async () => {
    await applyRename(identityWith([MINE]), '../metadata_admin', 'x', patch);
    await applyRename(identityWith([MINE]), MINE, '', patch);
    expect(patch).not.toHaveBeenCalled();
  });
});

describe('metadata_admin accepts passkeyNames', () => {
  it('validates the map and rejects a bad id or name', () => {
    expect(validateMetadataAdmin({ passkeyNames: { [MINE]: 'Phone' } }).passkeyNames).toEqual({ [MINE]: 'Phone' });
    expect(() => validateMetadataAdmin({ passkeyNames: { 'x y': 'Phone' } })).toThrow(MetadataAdminError);
    expect(() => validateMetadataAdmin({ passkeyNames: { [MINE]: '' } })).toThrow(MetadataAdminError);
    expect(() => validateMetadataAdmin({ passkeyNames: [] })).toThrow(MetadataAdminError);
  });
});

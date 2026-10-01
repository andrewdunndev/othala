// Invariant: passkey names are written and pruned with targeted JSON patches on metadata_admin.passkeyNames only,
// never a full-record update.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { getIdentity, patchIdentity, updateIdentity } = vi.hoisted(() => ({
  getIdentity: vi.fn(),
  patchIdentity: vi.fn(async () => ({})),
  updateIdentity: vi.fn(),
}));

vi.mock('@ory/client-fetch', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@ory/client-fetch')>();
  class IdentityApi {
    getIdentity = getIdentity;
    patchIdentity = patchIdentity;
    updateIdentity = updateIdentity;
  }
  return { ...actual, IdentityApi };
});

import { patchPasskeyName, prunePasskeyNames } from './admin-api';

const A = 'aa11';
const B = 'bb22';
const b64 = (h: string) => Buffer.from(h, 'hex').toString('base64');

beforeEach(() => {
  getIdentity.mockReset();
  patchIdentity.mockClear();
  updateIdentity.mockClear();
});

describe('patchPasskeyName', () => {
  it('creates metadata_admin when absent', async () => {
    getIdentity.mockResolvedValue({ metadata_admin: null });
    await patchPasskeyName('i', A, 'Phone');
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'add', path: '/metadata_admin', value: { passkeyNames: { [A]: 'Phone' } } }] });
  });

  it('creates the map beside existing keys without touching them', async () => {
    getIdentity.mockResolvedValue({ metadata_admin: { groups: ['everyone'], admin: true } });
    await patchPasskeyName('i', A, 'Phone');
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'add', path: '/metadata_admin/passkeyNames', value: { [A]: 'Phone' } }] });
  });

  it('sets one member of an existing map', async () => {
    getIdentity.mockResolvedValue({ metadata_admin: { passkeyNames: { [B]: 'Old' } } });
    await patchPasskeyName('i', A, 'Phone');
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'add', path: `/metadata_admin/passkeyNames/${A}`, value: 'Phone' }] });
    expect(updateIdentity).not.toHaveBeenCalled();
  });

  it('refuses a name or id the validator rejects, before any write', async () => {
    await expect(patchPasskeyName('i', '../x', 'Phone')).rejects.toThrow();
    await expect(patchPasskeyName('i', A, '')).rejects.toThrow();
    expect(patchIdentity).not.toHaveBeenCalled();
  });
});

describe('prunePasskeyNames', () => {
  const withCreds = (ids: string[], names: Record<string, string>) => ({
    metadata_admin: { groups: ['everyone'], passkeyNames: names },
    credentials: { passkey: { config: { credentials: ids.map((id) => ({ id: b64(id) })) } } },
  });

  it('drops names of removed credentials and keeps the rest', async () => {
    getIdentity.mockResolvedValue(withCreds([A], { [A]: 'Phone', [B]: 'Gone' }));
    expect(await prunePasskeyNames('i')).toBe(1);
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'replace', path: '/metadata_admin/passkeyNames', value: { [A]: 'Phone' } }] });
  });

  it('removes the key when no name survives', async () => {
    getIdentity.mockResolvedValue(withCreds([], { [B]: 'Gone' }));
    await prunePasskeyNames('i');
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'remove', path: '/metadata_admin/passkeyNames' }] });
  });

  it('writes nothing when every name is current', async () => {
    getIdentity.mockResolvedValue(withCreds([A, B], { [A]: 'Phone' }));
    expect(await prunePasskeyNames('i')).toBe(0);
    expect(patchIdentity).not.toHaveBeenCalled();
  });
});

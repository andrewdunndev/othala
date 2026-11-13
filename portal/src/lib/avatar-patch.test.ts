// Invariant: the picture is written and removed with targeted JSON patches on metadata_admin.avatar only.

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

import { patchAvatar } from './admin-api';
import { avatarOf } from './test-builders';

const a = avatarOf('png', 1);
const b = avatarOf('png', 2);

beforeEach(() => {
  getIdentity.mockReset();
  patchIdentity.mockClear();
  updateIdentity.mockClear();
});

describe('patchAvatar', () => {
  it('creates metadata_admin when absent', async () => {
    getIdentity.mockResolvedValue({ metadata_admin: null });
    await patchAvatar('i', a);
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'add', path: '/metadata_admin', value: { avatar: a } }] });
  });

  it('writes the key beside existing ones with one targeted op, new or already set', async () => {
    getIdentity.mockResolvedValue({ metadata_admin: { groups: ['everyone'] } });
    await patchAvatar('i', a);
    expect(patchIdentity).toHaveBeenLastCalledWith({ id: 'i', jsonPatch: [{ op: 'add', path: '/metadata_admin/avatar', value: a }] });
    getIdentity.mockResolvedValue({ metadata_admin: { groups: ['everyone'], avatar: a } });
    await patchAvatar('i', b);
    const sent = (patchIdentity.mock.lastCall as unknown as [{ jsonPatch: unknown[] }])[0].jsonPatch;
    expect(sent).toEqual([expect.objectContaining({ path: '/metadata_admin/avatar', value: b })]);
    expect(updateIdentity).not.toHaveBeenCalled();
  });

  it('removes only a present key, and never does a full update', async () => {
    getIdentity.mockResolvedValue({ metadata_admin: { avatar: a } });
    await patchAvatar('i', null);
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'remove', path: '/metadata_admin/avatar' }] });
    patchIdentity.mockClear();
    getIdentity.mockResolvedValue({ metadata_admin: { groups: [] } });
    await patchAvatar('i', null);
    getIdentity.mockResolvedValue({ metadata_admin: null });
    await patchAvatar('i', null);
    expect(patchIdentity).not.toHaveBeenCalled();
    expect(updateIdentity).not.toHaveBeenCalled();
  });

  it('refuses a value that is not a valid picture before any call', async () => {
    await expect(patchAvatar('i', { ...a, type: 'image/svg+xml' } as never)).rejects.toThrow(/avatar/);
    expect(getIdentity).not.toHaveBeenCalled();
  });
});

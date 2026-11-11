// The one form handler behind both pictures editors (a member's settings card, an admin's user page): a `remove` field
// clears the picture, an `avatar` file sets it. The same refusals apply to both.

import { patchAvatar } from './admin-api';
import { AVATAR_MAX_BYTES, parseAvatarBytes, type AvatarRefusal } from './avatar';

export type AvatarEdit = { ok: true; change: 'set' | 'removed' } | { ok: false; code: AvatarRefusal };

export async function applyAvatarForm(fd: FormData, identityId: string): Promise<AvatarEdit> {
  if (fd.get('remove') === '1') {
    await patchAvatar(identityId, null);
    return { ok: true, change: 'removed' };
  }
  const file = fd.get('avatar');
  if (typeof file === 'string' || file === null) return { ok: false, code: 'empty' };
  if (file.size > AVATAR_MAX_BYTES) return { ok: false, code: 'too-large' };
  const parsed = parseAvatarBytes(new Uint8Array(await file.arrayBuffer()));
  if (!parsed.ok) return { ok: false, code: parsed.code };
  await patchAvatar(identityId, parsed.avatar);
  return { ok: true, change: 'set' };
}

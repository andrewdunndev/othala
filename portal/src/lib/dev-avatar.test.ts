import { describe, expect, it } from 'vitest';
import { DEV_AVATAR, DEV_AVATAR_SRC } from './dev-avatar';
import { avatarProblem } from './avatar';
import { AVATAR_MAX_BYTES } from './avatar-limits';

describe('dev placeholder picture', () => {
  it('passes the same validation as a stored picture', () => {
    expect(avatarProblem(DEV_AVATAR)).toBeNull();
    expect(DEV_AVATAR.type).toBe('image/png');
    expect(Buffer.from(DEV_AVATAR.data, 'base64').length).toBeLessThan(AVATAR_MAX_BYTES);
  });
  it('is shown as a data URL', () => {
    expect(DEV_AVATAR_SRC.startsWith('data:image/png;base64,')).toBe(true);
  });
});

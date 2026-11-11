import { describe, expect, it } from 'vitest';
import { DEV_SETTINGS_STATES, devSettings } from './settings-fixtures';
import { AVATAR_FLASH } from './settings-flash';

describe('settings fixtures', () => {
  it('builds every state with no duplicate names', () => {
    expect(new Set(DEV_SETTINGS_STATES).size).toBe(DEV_SETTINGS_STATES.length);
    for (const s of DEV_SETTINGS_STATES) expect(devSettings(s).flow.id).toBe(`dev-flow-${s}`);
  });

  it('has a picture state for every flash the route emits', () => {
    for (const code of Object.keys(AVATAR_FLASH)) expect(devSettings(`picture-${code}`).avatarFlash).toBe(code);
  });

  it('shows the picture for plain and error states and none after a removal', () => {
    expect(devSettings('picture-has').avatar).toBe(true);
    expect(devSettings('picture-none').avatar).toBe(false);
    expect(devSettings('picture-removed').avatar).toBe(false);
    expect(devSettings('picture-too-large').avatar).toBe(true);
  });
});

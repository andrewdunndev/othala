// Invariant: every action outcome reads as one plain line, and a failure is never worded as success.

import { describe, expect, it } from 'vitest';
import { bannerFor } from './admin-banner';
import type { ActionResult } from './admin-actions';

const say = (r: ActionResult, action = '') => bannerFor(r, action, 'Robin');

describe('bannerFor', () => {
  it('names what a save saved and any group it removed', () => {
    expect(say({ kind: 'updated', removed: [] }, 'save-access')).toEqual({ tone: 'success', text: 'Access saved.' });
    expect(say({ kind: 'updated', removed: ['garden'] }, 'remove-groups')?.text).toBe('Group removed. Removed garden.');
  });

  it('warns for sign-in off and admin removal, and confirms their reversals', () => {
    expect(say({ kind: 'deactivated', username: 'a.b' })?.tone).toBe('warning');
    expect(say({ kind: 'admin-revoked', username: 'a.b' })?.tone).toBe('warning');
    expect(say({ kind: 'reactivated', username: 'a.b' })?.tone).toBe('success');
    expect(say({ kind: 'admin-granted', username: 'a.b' })?.text).toBe('Robin is now a household admin.');
  });

  it('shows an error as danger with its own message, and leaves the setup link to its card', () => {
    expect(say({ kind: 'error', message: 'Nope.' })).toEqual({ tone: 'danger', text: 'Nope.' });
    expect(say({ kind: 'recovery', url: 'u', code: 'c', expiresAt: 'x' })).toBeNull();
  });
});

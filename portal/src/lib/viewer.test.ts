import { describe, it, expect } from 'vitest';
import { devViewer } from './viewer';

describe('devViewer', () => {
  it('stands in for a session only in dev and only for the two known values', () => {
    expect(devViewer(true, 'member')).toEqual({ identityId: 'dev-mock', isAdmin: false });
    expect(devViewer(true, 'admin')).toEqual({ identityId: 'dev-mock', isAdmin: true });
    expect(devViewer(true, 'root')).toBeNull();
    expect(devViewer(true, null)).toBeNull();
    expect(devViewer(false, 'admin')).toBeNull();
  });
});

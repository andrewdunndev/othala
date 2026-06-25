/**
 * admin-auth.test.ts — unit tests for the admin authority marker (ADR 0008).
 *
 * Coverage:
 *   isAdminMarker:
 *   - marker true (boolean) → admin
 *   - marker absent (undefined metadata_admin) → not admin
 *   - marker absent (empty object) → not admin
 *   - marker false → not admin
 *   - marker string "true" (wrong type) → not admin (strict equality)
 *   - marker number 1 (wrong type) → not admin
 *   - marker null → not admin
 *   - null identity → not admin
 *   - undefined identity → not admin
 *   - malformed metadata_admin (array) → not admin
 *   - metadata_admin with extra keys and admin:true → admin
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect } from 'vitest';
import { isAdminMarker } from './admin-auth.js';
import type { Identity } from './types.js';

// ── Minimal Identity fixture builder ─────────────────────────────────────────

function makeIdentity(metadataAdmin?: Record<string, unknown>): Identity {
  return {
    id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    schema_id: 'family',
    schema_url: 'http://kratos:4434/schemas/family',
    state: 'active',
    traits: { username: 'testuser', email: 'test@example.com' },
    metadata_admin: metadataAdmin as Identity['metadata_admin'],
  };
}

// ── isAdminMarker ─────────────────────────────────────────────────────────────

describe('isAdminMarker — marker present and true', () => {
  it('returns true when metadata_admin.admin === true (boolean)', () => {
    const identity = makeIdentity({ admin: true });
    expect(isAdminMarker(identity)).toBe(true);
  });

  it('returns true with other metadata_admin fields present alongside admin:true', () => {
    const identity = makeIdentity({ groups: ['admin'], roles: { myapp: 'editor' }, admin: true });
    expect(isAdminMarker(identity)).toBe(true);
  });
});

describe('isAdminMarker — marker absent', () => {
  it('returns false when metadata_admin is undefined', () => {
    const identity = makeIdentity(undefined);
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when metadata_admin is an empty object (no admin key)', () => {
    const identity = makeIdentity({});
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when metadata_admin has groups but no admin key', () => {
    const identity = makeIdentity({ groups: ['admin', 'family'] });
    expect(isAdminMarker(identity)).toBe(false);
  });
});

describe('isAdminMarker — marker wrong value (fail-closed strict equality)', () => {
  it('returns false when admin is boolean false', () => {
    const identity = makeIdentity({ admin: false });
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when admin is string "true" (not boolean)', () => {
    const identity = makeIdentity({ admin: 'true' } as Record<string, unknown>);
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when admin is number 1 (not boolean)', () => {
    const identity = makeIdentity({ admin: 1 } as Record<string, unknown>);
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when admin is null', () => {
    const identity = makeIdentity({ admin: null } as Record<string, unknown>);
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when admin is 0 (falsy number)', () => {
    const identity = makeIdentity({ admin: 0 } as Record<string, unknown>);
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when admin is an object (not boolean)', () => {
    const identity = makeIdentity({ admin: { value: true } } as Record<string, unknown>);
    expect(isAdminMarker(identity)).toBe(false);
  });
});

describe('isAdminMarker — null/undefined identity (fail-closed)', () => {
  it('returns false for null identity', () => {
    expect(isAdminMarker(null)).toBe(false);
  });

  it('returns false for undefined identity', () => {
    expect(isAdminMarker(undefined)).toBe(false);
  });
});

describe('isAdminMarker — malformed metadata_admin', () => {
  it('returns false when metadata_admin is an array (not an object)', () => {
    // Force a structurally invalid shape to test the guard.
    const identity = { ...makeIdentity(), metadata_admin: [{ admin: true }] as unknown as Identity['metadata_admin'] };
    expect(isAdminMarker(identity)).toBe(false);
  });

  it('returns false when metadata_admin is a string', () => {
    const identity = { ...makeIdentity(), metadata_admin: 'admin' as unknown as Identity['metadata_admin'] };
    expect(isAdminMarker(identity)).toBe(false);
  });
});


// Invariant: marking an email verified patches the email trait's own address and nothing else, never via a PUT body.

import { beforeEach, describe, expect, it, vi } from 'vitest';

// Kratos v26's admin PATCH admits only add, remove and replace (oryx/jsonx/patch.go opAllowList); anything else is a 400.
const { getIdentity, patchIdentity } = vi.hoisted(() => ({
  getIdentity: vi.fn(),
  patchIdentity: vi.fn(async ({ jsonPatch }: { jsonPatch: Array<{ op: string }> }) => {
    const bad = jsonPatch.find((p) => !['add', 'remove', 'replace'].includes(p.op));
    if (bad) throw new Error(`unsupported operation: ${bad.op}`);
    return {};
  }),
}));

vi.mock('@ory/client-fetch', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@ory/client-fetch')>();
  class IdentityApi {
    getIdentity = getIdentity;
    patchIdentity = patchIdentity;
  }
  return { ...actual, IdentityApi };
});

import { emailVerifiedPatch, markEmailVerified } from './admin-api';

const addr = (value: string, verified: boolean, via = 'email') => ({ value, via, verified, status: verified ? 'completed' : 'pending' });
const vouched = (value: string) => ({ value, via: 'email', verified: true, status: 'completed' });

describe('emailVerifiedPatch', () => {
  it('replaces the trait address entry by index, matching case-insensitively', () => {
    const out = emailVerifiedPatch({
      traits: { email: 'Robin@Example.test' },
      verifiable_addresses: [addr('other@example.test', false), addr('robin@example.test', false)] as never,
    });
    expect(out).toEqual([{ op: 'replace', path: '/verifiable_addresses/1', value: vouched('robin@example.test') }]);
  });

  it('appends the trait address when others exist but not it', () => {
    const out = emailVerifiedPatch({ traits: { email: 'a@example.test' }, verifiable_addresses: [addr('r@example.test', false)] as never });
    expect(out).toEqual([{ op: 'add', path: '/verifiable_addresses/-', value: vouched('a@example.test') }]);
  });

  it('creates the list when none is declared', () => {
    const out = emailVerifiedPatch({ traits: { email: 'a@example.test' }, verifiable_addresses: undefined });
    expect(out).toEqual([{ op: 'add', path: '/verifiable_addresses', value: [vouched('a@example.test')] }]);
  });
});

describe('markEmailVerified', () => {
  beforeEach(() => {
    getIdentity.mockReset();
    patchIdentity.mockClear();
  });

  it('patches with ops Kratos admits when the stored email is the one the admin saw', async () => {
    getIdentity.mockResolvedValue({ traits: { email: 'a@example.test' }, verifiable_addresses: [addr('a@example.test', false)] });
    await expect(markEmailVerified('i', 'a@example.test')).resolves.toBe(true);
    expect(patchIdentity).toHaveBeenCalledWith({ id: 'i', jsonPatch: [{ op: 'replace', path: '/verifiable_addresses/0', value: vouched('a@example.test') }] });
  });

  it('writes nothing when the stored email changed since the page rendered', async () => {
    getIdentity.mockResolvedValue({ traits: { email: 'new@example.test' }, verifiable_addresses: [addr('new@example.test', false)] });
    await expect(markEmailVerified('i', 'old@example.test')).resolves.toBe(false);
    await expect(markEmailVerified('i', '')).resolves.toBe(false);
    expect(patchIdentity).not.toHaveBeenCalled();
  });
});

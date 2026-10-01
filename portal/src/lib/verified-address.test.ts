// Invariant: marking an email verified patches the email trait's own address and nothing else, never via a PUT body.

import { describe, expect, it } from 'vitest';
import { emailVerifiedPatch } from './admin-api';

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

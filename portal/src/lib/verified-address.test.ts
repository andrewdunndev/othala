// Invariant: marking an email verified changes the email trait's own address and nothing else.

import { describe, expect, it } from 'vitest';
import { addressesWithEmailVerified } from './admin-api';

const addr = (value: string, verified: boolean, via = 'email') => ({ value, via, verified, status: verified ? 'completed' : 'pending' });

describe('addressesWithEmailVerified', () => {
  it('verifies the trait address, matching case-insensitively', () => {
    const out = addressesWithEmailVerified({
      traits: { email: 'Ashley@Example.test' },
      verifiable_addresses: [addr('ashley@example.test', false)] as never,
    });
    expect(out).toEqual([{ value: 'ashley@example.test', via: 'email', verified: true, status: 'completed' }]);
  });

  it('carries every other address through unchanged', () => {
    const out = addressesWithEmailVerified({
      traits: { email: 'a@example.test' },
      verifiable_addresses: [addr('a@example.test', false), addr('recovery@example.test', false)] as never,
    });
    expect(out[1]).toEqual({ value: 'recovery@example.test', via: 'email', verified: false, status: 'pending' });
  });

  it('adds the trait address when none is declared', () => {
    const out = addressesWithEmailVerified({ traits: { email: 'a@example.test' }, verifiable_addresses: undefined });
    expect(out).toEqual([{ value: 'a@example.test', via: 'email', verified: true, status: 'completed' }]);
  });
});

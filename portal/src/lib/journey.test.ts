import { describe, it, expect } from 'vitest';
import { journeyText, noticeClass, recoverySpecs, verificationSpecs } from './journey';
import { nodeLabel, specKey } from './nodes';
import { REASON_MAP, DEFAULT_ENTRY } from './error-reasons';

describe('journeyText', () => {
  it('rewrites known Kratos messages to say what to do next', () => {
    expect(journeyText({ id: 4060006, text: 'The recovery code is invalid or has already been used.' })).toMatch(/ask for a new one/);
    expect(journeyText({ id: 4000006, text: 'x' })).toMatch(/passkey/);
  });
  it('passes an unknown message through unchanged', () => {
    expect(journeyText({ id: 1, text: 'Something odd.' })).toBe('Something odd.');
  });
});

describe('noticeClass', () => {
  it('maps message types to notice variants', () => {
    expect(noticeClass('error')).toContain('notice-danger');
    expect(noticeClass('success')).toContain('notice-success');
    expect(noticeClass('info')).toContain('notice-warning');
  });
});

describe('node specs', () => {
  it('keys buttons apart from inputs of the same name', () => {
    expect(specKey({ name: 'email', type: 'email' })).toBe('email');
    expect(specKey({ name: 'email', type: 'submit' })).toBe('button:email');
  });
  it('puts the portal label ahead of Kratos, and falls back for unknown nodes', () => {
    expect(nodeLabel({ label: 'Verify code' }, 'Continue', 'x')).toBe('Verify code');
    expect(nodeLabel(undefined, 'Continue', 'x')).toBe('Continue');
    expect(nodeLabel(undefined, undefined, 'fallback')).toBe('fallback');
  });
  it('makes the recovery code step numeric and one-time-code, with a resend that skips validation', () => {
    const s = recoverySpecs('sent');
    expect(s.code).toMatchObject({ inputmode: 'numeric', autocomplete: 'one-time-code' });
    expect(s['button:method'].label).toBe('Verify code');
    expect(s['button:email'].formnovalidate).toBe(true);
    expect(verificationSpecs('sent')['button:method'].label).toBe('Verify email');
  });
});

describe('error reasons', () => {
  it('every known reason says what to do next and carries no jargon', () => {
    for (const e of [...Object.values(REASON_MAP), DEFAULT_ENTRY]) {
      expect(e.message).toMatch(/\b(try|sign in|contact|ask|go|use)\b/i);
      expect(e.message).not.toMatch(/dependency|resource|substrate|Kratos|OAuth/i);
    }
  });
});

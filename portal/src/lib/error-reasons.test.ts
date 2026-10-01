import { describe, it, expect } from 'vitest';
import { resolveReason, resolveError, kratosReason, REASON_MAP, DEFAULT_ENTRY } from './error-reasons.js';

describe('resolveReason', () => {
  it('shows a known reason with its entry', () => {
    expect(resolveReason('not-admin')).toEqual({ entry: REASON_MAP['not-admin'], reason: 'not-admin' });
  });

  it.each(['<b>hello</b>', 'anything at all', '', 'constructor', '__proto__', 'toString'])(
    'shows no reason text for %j',
    (raw) => {
      const r = resolveReason(raw);
      expect(r.reason).toBeUndefined();
      expect(r.entry).toBe(DEFAULT_ENTRY);
    },
  );

  it('shows no reason text when the parameter is absent', () => {
    expect(resolveReason(null)).toEqual({ entry: DEFAULT_ENTRY });
  });
});

describe('resolveError', () => {
  const q = (s: string) => new URLSearchParams(s);
  it('maps a Hydra error to a next step and never shows its description', () => {
    expect(resolveError(q('error=invalid_client&error_description=<b>x</b>')).reason).toBe('app-misconfigured');
    expect(resolveError(q('error=access_denied')).reason).toBe('sign-in-cancelled');
    expect(resolveError(q('error=login_required')).reason).toBe('flow-expired');
  });
  it('maps a looked-up Kratos error, and falls back to the generic entry', () => {
    expect(resolveError(q('id=x'), kratosReason({ id: 'self_service_flow_expired', code: 410 })).reason).toBe('flow-expired');
    expect(kratosReason({ code: 403 })).toBe('flow-expired');
    expect(kratosReason({ id: 'constructor' })).toBeUndefined();
    expect(resolveError(q('error=constructor')).entry).toBe(DEFAULT_ENTRY);
  });
  it('lets our own reason win', () => {
    expect(resolveError(q('reason=not-admin&error=invalid_client')).reason).toBe('not-admin');
  });
});

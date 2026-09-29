import { describe, it, expect } from 'vitest';
import { resolveReason, REASON_MAP, DEFAULT_ENTRY } from './error-reasons.js';

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

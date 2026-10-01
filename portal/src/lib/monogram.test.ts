import { describe, it, expect } from 'vitest';
import { monogram } from './monogram';

describe('monogram', () => {
  it('takes word initials, not the first two letters', () => {
    expect(monogram('New app')).toBe('NA');
    expect(monogram('photo-sync box extra')).toBe('PS');
  });
  it('uses one letter for a one-word name and survives empty input', () => {
    expect(monogram('Grafana')).toBe('G');
    expect(monogram('')).toBe('?');
  });
});

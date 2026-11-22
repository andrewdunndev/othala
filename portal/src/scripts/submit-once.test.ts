import { describe, expect, it } from 'vitest';
import { createSubmitOnce } from './submit-once';

describe('createSubmitOnce', () => {
  it('lets the first submit through and refuses the rest', () => {
    const g = createSubmitOnce();
    const form = {};
    expect(g.allow(form)).toBe(true);
    expect(g.allow(form)).toBe(false);
    expect(g.allow(form)).toBe(false);
  });

  it('tracks forms independently', () => {
    const g = createSubmitOnce();
    expect(g.allow({})).toBe(true);
    expect(g.allow({})).toBe(true);
  });

  it('re-arms a form after a bfcache restore', () => {
    const g = createSubmitOnce();
    const form = {};
    g.allow(form);
    g.rearm(form);
    expect(g.allow(form)).toBe(true);
  });
});

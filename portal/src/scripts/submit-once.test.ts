import { describe, expect, it } from 'vitest';
import { createSubmitOnce, guardSubmits } from './submit-once';

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

describe('guardSubmits', () => {
  // A document stand-in that dispatches capture listeners before bubbling ones, as the DOM does.
  function fakeDoc() {
    const capture: Array<(e: Event) => void> = [];
    const bubble: Array<(e: Event) => void> = [];
    return {
      addEventListener(_t: 'submit', h: (e: Event) => void, c = false) {
        (c ? capture : bubble).push(h);
      },
      submit(form: object) {
        const e = new Event('submit', { cancelable: true });
        Object.defineProperty(e, 'target', { value: form });
        for (const h of [...capture, ...bubble]) h(e);
        return e;
      },
    };
  }

  it('cancels the repeat before a bubbling router listener acts on it', () => {
    const doc = fakeDoc();
    const posted: object[] = [];
    // Registered first, like the Astro router: posts whatever has not been cancelled.
    doc.addEventListener('submit', (e) => {
      if (!e.defaultPrevented) posted.push(e.target as object);
    }, false);
    guardSubmits(doc, createSubmitOnce(), () => true);
    const form = {};
    doc.submit(form);
    doc.submit(form);
    expect(posted).toEqual([form]);
  });

  it('leaves other forms alone', () => {
    const doc = fakeDoc();
    guardSubmits(doc, createSubmitOnce(), () => false);
    const form = {};
    expect(doc.submit(form).defaultPrevented).toBe(false);
    expect(doc.submit(form).defaultPrevented).toBe(false);
  });
});

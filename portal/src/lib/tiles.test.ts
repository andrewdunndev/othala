/**
 * tiles.test.ts — DOMPurify sanitization regression test.
 *
 * Covers `sanitizeEducationMarkdown()` (tiles.ts), the exact
 * marked + DOMPurify composition parseTile() runs over an operator-supplied
 * `<slug>.md` before `set:html` injection on the /apps/<slug> detail page,
 * with both the `html` and `svg` USE_PROFILES on (inline diagrams have to
 * survive, which widens what the sanitizer has to get right).
 *
 * The hostile-input corpus below asserts a property, not a snapshot:
 * nothing executable survives sanitization. Each case's `forbidden` patterns
 * are markers of live script/handler/URL-scheme survival, not a copy of one
 * library's exact output — a sanitizer-internal minor bump (e.g. a changed
 * attribute allowlist ordering) does not fail these; a script, event
 * handler or javascript:/data: scheme reaching the output does.
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect } from 'vitest';
import { sanitizeEducationMarkdown } from './tiles';

describe('tiles.ts: marked + DOMPurify sanitization', () => {
  it('strips onerror from img tags (XSS via education markdown)', () => {
    const out = sanitizeEducationMarkdown('<img src=x onerror="alert(1)">');
    expect(out, 'onerror attribute must be removed by DOMPurify').not.toContain('onerror');
    expect(out, 'img element itself should survive (src scrubbed)').toContain('<img');
  });

  it('strips <script> tags entirely', () => {
    const out = sanitizeEducationMarkdown('Before\n<script>alert("xss")</script>\nAfter');
    expect(out, '<script> must be stripped').not.toContain('<script');
    expect(out, 'alert payload must not appear in output').not.toContain('alert');
    expect(out, 'prose before script must survive').toContain('Before');
    expect(out, 'prose after script must survive').toContain('After');
  });

  it('strips javascript: hrefs (href injection)', () => {
    const out = sanitizeEducationMarkdown('[click me](javascript:alert(1))');
    expect(out, 'javascript: href must be stripped').not.toContain('javascript:');
  });

  it('preserves safe inline SVG (cat-explainer diagrams — USE_PROFILES svg:true)', () => {
    const out = sanitizeEducationMarkdown(
      '<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>',
    );
    expect(out, 'safe SVG must survive sanitization').toContain('<svg');
    expect(out, 'circle element must survive').toContain('<circle');
  });

  it('preserves normal markdown prose intact', () => {
    const out = sanitizeEducationMarkdown('## Title\n\nA paragraph with **bold** and _italic_ text.');
    expect(out, 'heading must be rendered').toContain('<h2');
    expect(out, 'strong must be rendered').toContain('<strong>');
    expect(out, 'em must be rendered').toContain('<em>');
    expect(out, 'text content must survive').toContain('bold');
  });

  it('sanitizes onclick on arbitrary elements', () => {
    const out = sanitizeEducationMarkdown('<p onclick="stealCookies()">Click me</p>');
    expect(out, 'onclick must be stripped').not.toContain('onclick');
    expect(out, 'paragraph text should survive').toContain('Click me');
  });
});

interface HostileCase {
  category: string;
  name: string;
  raw: string;
  /** Patterns marking live-script/handler/scheme survival — must NOT match. */
  forbidden: RegExp[];
  /** Benign markers that must still be present (prose/element survival). */
  mustContain?: RegExp[];
}

const MARK = 'xss_marker_9f2c';

const hostileCorpus: HostileCase[] = [
  {
    category: 'script',
    name: 'script tag carrying a payload',
    raw: `<script>window.${MARK}=1</script>`,
    forbidden: [/<script/i, new RegExp(MARK)],
  },
  {
    category: 'script',
    name: 'remote script tag inside markdown prose',
    raw: `Before\n\n<script src="//evil.example/x.js">window.${MARK}=1</script>\n\nAfter`,
    forbidden: [/<script/i, /evil\.example/i, new RegExp(MARK)],
    mustContain: [/Before/, /After/],
  },
  {
    category: 'event-handler',
    name: 'onload on svg root',
    raw: `<svg onload="window.${MARK}=1"><circle r="1"/></svg>`,
    forbidden: [/onload/i, new RegExp(MARK)],
  },
  {
    category: 'event-handler',
    name: 'onclick on a paragraph',
    raw: `<p onclick="window.${MARK}=1">click</p>`,
    forbidden: [/onclick/i, new RegExp(MARK)],
  },
  {
    category: 'javascript-url',
    name: 'javascript: markdown link',
    raw: `[click](javascript:window.${MARK}=1)`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'javascript-url',
    name: 'javascript: href with tab obfuscation',
    raw: `<a href="java\tscript:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'data-url',
    name: 'data:text/html anchor smuggling a script',
    raw: `<a href="data:text/html,<script>window.${MARK}=1</script>">click</a>`,
    forbidden: [/data:text\/html/i, /<script/i, new RegExp(MARK)],
  },
  {
    category: 'data-url',
    name: 'data: SVG payload via object',
    raw: `<object data="data:image/svg+xml,<svg onload=window.${MARK}=1>"></object>`,
    forbidden: [/<object/i, /data:image\/svg/i, new RegExp(MARK)],
  },
  {
    category: 'svg-foreignobject',
    name: 'foreignObject smuggling an HTML event handler',
    raw: `<svg><foreignObject><img src=x onerror="window.${MARK}=1"></foreignObject></svg>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'svg-use-xlink',
    name: 'use href targeting javascript:',
    raw: `<svg><use href="javascript:window.${MARK}=1"/></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-use-xlink',
    name: 'use xlink:href targeting javascript:',
    raw: `<svg><use xlink:href="javascript:window.${MARK}=1"/></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-animate-set',
    name: 'animate mutating an anchor href to javascript:',
    raw: `<svg><a><animate attributeName="href" values="javascript:window.${MARK}=1"/><text>click</text></a></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-animate-set',
    name: 'set mutating an anchor href to javascript:',
    raw: `<svg><a><set attributeName="href" to="javascript:window.${MARK}=1"/><text>click</text></a></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    // No shipped browser executes a javascript: scheme reached via a CSS
    // url() value (that was an IE-only behavior); DOMPurify's html profile
    // accordingly passes the `style` attribute's text through unparsed.
    // The enforceable property here is containment: a hostile style value
    // must not escape into a new element or handler outside the attribute.
    category: 'style-css-url',
    name: 'style attribute css url() does not escape into new markup',
    raw: `<div style="background:url(javascript:window.${MARK}=1)">x</div>`,
    forbidden: [/<script/i, /\bon\w+\s*=/i],
    mustContain: [/<div/, />x<\/div>/],
  },
  {
    category: 'style-css-url',
    name: 'style tag css url() javascript scheme',
    raw: `<style>body{background:url("javascript:window.${MARK}=1")}</style>x`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'mxss',
    name: 'style/img namespace-mutation payload',
    raw: `<svg><p><style><img src="</style><img src=x onerror=window.${MARK}=1//">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'namespace-confusion',
    name: 'math/mglyph namespace-confusion payload',
    raw: `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=window.${MARK}=1>"></mglyph></table></mtext></math>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'form button formaction javascript:',
    raw: `<form><button formaction="javascript:window.${MARK}=1">go</button></form>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'meta refresh to javascript:',
    raw: `<meta http-equiv="refresh" content="0;url=javascript:window.${MARK}=1">`,
    forbidden: [/<meta/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'base href hijack',
    raw: `<base href="javascript:window.${MARK}=1//">`,
    forbidden: [/<base/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'iframe javascript: src',
    raw: `<iframe src="javascript:window.${MARK}=1"></iframe>`,
    forbidden: [/<iframe/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'embed javascript: src',
    raw: `<embed src="javascript:window.${MARK}=1">`,
    forbidden: [/<embed/i, /javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'template-noscript',
    name: 'noscript-closing nesting escape',
    raw: `<noscript><p title="</noscript><img src=x onerror=window.${MARK}=1>">x</noscript>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'template-noscript',
    name: 'template smuggling a script',
    raw: `<template><script>window.${MARK}=1</script></template>`,
    forbidden: [/<script/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'case-obfuscated event-handler attribute',
    raw: `<img src=x OnErRor="window.${MARK}=1">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'decimal-entity-obfuscated javascript scheme',
    raw: `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'hex-entity-obfuscated javascript scheme',
    raw: `<a href="&#x6A;avascript:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'non-breaking-space obfuscated scheme',
    raw: `<a href="java script:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'raw HTML block between markdown prose',
    raw: `# Title\n\nSome prose.\n\n<script>window.${MARK}=1</script>\n\nMore prose.`,
    forbidden: [/<script/i, new RegExp(MARK)],
    mustContain: [/Title/, /More prose/],
  },
];

describe('tiles.ts: hostile-input corpus (othala#11) — nothing executable survives', () => {
  for (const c of hostileCorpus) {
    it(`[${c.category}] ${c.name}`, () => {
      const out = sanitizeEducationMarkdown(c.raw);
      for (const pattern of c.forbidden) {
        expect(out, `${c.category}/${c.name}: forbidden pattern ${pattern} found in "${out}"`).not.toMatch(
          pattern,
        );
      }
      for (const pattern of c.mustContain ?? []) {
        expect(out, `${c.category}/${c.name}: expected benign content ${pattern} missing from "${out}"`).toMatch(
          pattern,
        );
      }
    });
  }
});

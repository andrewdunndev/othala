/**
 * tiles.test.ts — DOMPurify sanitization regression test.
 *
 * Coverage: the marked + DOMPurify composition in tiles.ts parseTile().
 *
 * Background (feat/passkey-first-login):
 *   Before this fix, the raw `marked.parse()` output was passed to
 *   `set:html` in Astro without sanitization. An operator-supplied
 *   `<slug>.md` could embed arbitrary HTML (including onerror handlers)
 *   that would execute in the browser.
 *
 *   Fix: tiles.ts now runs:
 *     DOMPurify.sanitize(marked.parse(raw), { USE_PROFILES: { html: true, svg: true } })
 *
 * This test replicates that composition directly and asserts:
 *   1. `onerror` event handler is stripped from the sanitized output.
 *   2. `<script>` tags are stripped.
 *   3. Safe inline SVG content survives (the USE_PROFILES: {svg:true} branch).
 *   4. Normal markdown prose round-trips intact.
 *
 * NOTE: This test mirrors the tiles.ts code path exactly. If the
 * sanitization call in parseTile() is changed, update this test to match.
 * The real tiles.ts function is not exported in a test-friendly form (it
 * reads from MANIFEST_DIR and the filesystem), so we replicate the
 * composition here and document that linkage explicitly.
 *
 * Run: npx vitest run   (from portal/)
 */

import { describe, it, expect } from 'vitest';
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';

/** Mirrors the sanitize call in tiles.ts parseTile(). */
function sanitizeMarkdown(raw: string): string {
  const html = marked.parse(raw, { async: false }) as string;
  return DOMPurify.sanitize(html, { USE_PROFILES: { html: true, svg: true } });
}

describe('tiles.ts: marked + DOMPurify sanitization', () => {
  it('strips onerror from img tags (XSS via education markdown)', () => {
    const raw = '<img src=x onerror="alert(1)">';
    const out = sanitizeMarkdown(raw);
    expect(out, 'onerror attribute must be removed by DOMPurify').not.toContain('onerror');
    expect(out, 'img element itself should survive (src scrubbed)').toContain('<img');
  });

  it('strips <script> tags entirely', () => {
    const raw = 'Before\n<script>alert("xss")</script>\nAfter';
    const out = sanitizeMarkdown(raw);
    expect(out, '<script> must be stripped').not.toContain('<script');
    expect(out, 'alert payload must not appear in output').not.toContain('alert');
    expect(out, 'prose before script must survive').toContain('Before');
    expect(out, 'prose after script must survive').toContain('After');
  });

  it('strips javascript: hrefs (href injection)', () => {
    const raw = '[click me](javascript:alert(1))';
    const out = sanitizeMarkdown(raw);
    // DOMPurify removes javascript: URIs from href attributes.
    expect(out, 'javascript: href must be stripped').not.toContain('javascript:');
  });

  it('preserves safe inline SVG (cat-explainer diagrams — USE_PROFILES svg:true)', () => {
    const raw = '<svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>';
    const out = sanitizeMarkdown(raw);
    expect(out, 'safe SVG must survive sanitization').toContain('<svg');
    expect(out, 'circle element must survive').toContain('<circle');
  });

  it('preserves normal markdown prose intact', () => {
    const raw = '## Title\n\nA paragraph with **bold** and _italic_ text.';
    const out = sanitizeMarkdown(raw);
    expect(out, 'heading must be rendered').toContain('<h2');
    expect(out, 'strong must be rendered').toContain('<strong>');
    expect(out, 'em must be rendered').toContain('<em>');
    expect(out, 'text content must survive').toContain('bold');
  });

  it('sanitizes onclick on arbitrary elements', () => {
    const raw = '<p onclick="stealCookies()">Click me</p>';
    const out = sanitizeMarkdown(raw);
    expect(out, 'onclick must be stripped').not.toContain('onclick');
    expect(out, 'paragraph text should survive').toContain('Click me');
  });
});

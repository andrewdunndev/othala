import { marked } from 'marked';

/** Strip a leading scaffold TODO HTML comment (added to KEEP-REWRITE
 *  files) and any YAML frontmatter, so neither reaches the page. The
 *  TODO stays in the source file for the coordinator; it never renders. */
function stripLeading(raw: string): string {
  let body = raw.replace(/^\s*<!--\s*TODO\(site-rewrite\)[\s\S]*?-->\s*/, '');
  const fm = body.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n([\s\S]*)$/);
  if (fm) body = fm[1];
  return body;
}

/** Render a doc's markdown to HTML, rewriting intra-repo `.md` links
 *  to their site URLs using the basename→href map. Anchors preserved.
 *  Unknown `.md` targets are left as-is (they are the flagged dead
 *  links). */
export function renderMarkdown(raw: string, linkMap: Record<string, string>): string {
  const body = stripLeading(raw);
  let html = marked.parse(body, { async: false }) as string;
  html = html.replace(/href="([^"]*?\.md)(#[^"]*)?"/g, (m, path, anchor) => {
    const base = path.split('/').pop();
    const target = linkMap[base];
    return target ? `href="${target}${anchor || ''}"` : m;
  });
  return html;
}

/** First real prose paragraph of a doc, for section-index card blurbs.
 *  Skips the H1, blockquote callouts, and status lines. Trimmed to a
 *  reasonable card length. */
export function cardBlurb(raw: string): string {
  const body = stripLeading(raw);
  const lines = body.split(/\r?\n/);
  const buf: string[] = [];
  for (const line of lines) {
    const t = line.trim();
    if (buf.length === 0) {
      if (t === '' || t.startsWith('#') || t.startsWith('>') || t.startsWith('---')) continue;
      if (/^(status|date|updated|scope|reviewer)\b/i.test(t)) continue;
    }
    if (t === '' && buf.length > 0) break;
    buf.push(t);
  }
  let text = buf.join(' ').replace(/[*`_]/g, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
  if (text.length > 180) text = text.slice(0, 177).replace(/\s+\S*$/, '') + '…';
  return text;
}

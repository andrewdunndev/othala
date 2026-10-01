// A text input must never share a form with a destructive submit: Enter in the input would press the first submit in
// tree order, which used to be a Remove. Destructive buttons point at their own hidden form (`form="..."`).
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const TEXTY = /<input\b(?![^>]*type="(?:hidden|checkbox|radio|submit|button)")[^>]*>/g;
const DESTRUCTIVE = /<button\b[^>]*type="submit"[^>]*>/g;
const destructive = (tag: string) =>
  /(_remove|_unlink|_disable)|value="remove"|button-danger|\.unlink\.name|lookupOff\.name|name=\{removeName\}/.test(tag);

function forms(src: string): string[] {
  return [...src.matchAll(/<form\b[\s\S]*?<\/form>/g)].map((m) => m[0]);
}

describe('settings forms', () => {
  const sources = { 'settings.astro': read('../pages/auth/settings.astro'), 'CredentialRows.astro': read('../components/settings/CredentialRows.astro') };

  it('finds the method forms', () => {
    expect(forms(sources['settings.astro']).length).toBeGreaterThan(8);
  });

  it('no form holds both a text input and an in-form destructive submit', () => {
    for (const [file, src] of Object.entries(sources)) {
      for (const f of forms(src)) {
        const hasText = (f.match(TEXTY) ?? []).some((t) => !/\bform=/.test(t));
        const bad = (f.match(DESTRUCTIVE) ?? []).filter((b) => destructive(b) && !/\bform=/.test(b));
        expect(hasText && bad.length > 0, `${file}: ${bad[0] ?? ''}`).toBe(false);
      }
    }
  });

  it('every destructive submit outside a form block points at its own form', () => {
    const credentials = sources['CredentialRows.astro'];
    const removes = (credentials.match(DESTRUCTIVE) ?? []).filter(destructive);
    expect(removes.length).toBeGreaterThan(0);
    for (const b of removes) expect(b).toMatch(/\bform=/);
  });

  it('every disclosure checkbox belongs to the inert #disclosures form, never the form around it', () => {
    let seen = 0;
    for (const [file, src] of Object.entries(sources)) {
      for (const tag of src.match(/<input\b[^>]*type="checkbox"[^>]*>/g) ?? []) {
        if (!/\bdisclose\b/.test(tag)) continue;
        seen++;
        expect(tag, `${file}: ${tag}`).toMatch(/\bform="disclosures"/);
      }
    }
    expect(seen).toBeGreaterThan(6);
    expect(sources['settings.astro']).toMatch(/<form id="disclosures"[^>]*hidden><\/form>/);
  });

  it('e2e specs reach a disclosure toggle by its class, since the script swaps each label for a button', () => {
    const enhance = read('../scripts/settings-enhance.ts');
    expect(enhance).toMatch(/b\.className = label\.className/);
    expect(enhance).toMatch(/label\.replaceWith\(b\)/);
    const dir = join(process.cwd(), '..', 'e2e', 'playwright', 'tests');
    const specs = readdirSync(dir).filter((f) => f.endsWith('.ts'));
    expect(specs.length).toBeGreaterThan(10);
    for (const f of specs) {
      const hit = readFileSync(join(dir, f), 'utf8').match(/label\.(?:lbl-\w+|toggle-label)\b/);
      expect(hit?.[0], `${f} selects a disclosure label the script replaces; use the class alone`).toBeUndefined();
    }
  });
});

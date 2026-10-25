import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const pages = fileURLToPath(new URL('.', import.meta.url));
const src = join(pages, '..');

function astroFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? astroFiles(join(dir, e.name)) : e.name.endsWith('.astro') ? [join(dir, e.name)] : [],
  );
}

describe('error pages', () => {
  it.each(['404.astro', '500.astro', 'auth/error.astro'])('%s renders through StatusPage', (page) => {
    expect(readFileSync(join(pages, page), 'utf8')).toMatch(/<StatusPage[\s>]/);
  });

  it('StatusPage is the only template that emits the error reason marker', () => {
    const emitters = astroFiles(src)
      .filter((f) => readFileSync(f, 'utf8').includes('data-reason'))
      .map((f) => relative(src, f));
    expect(emitters).toEqual(['components/StatusPage.astro']);
  });
});

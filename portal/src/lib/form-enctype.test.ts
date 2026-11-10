// Astro's ClientRouter re-sends same-origin form posts as multipart/form-data unless the form names its enctype, and
// Kratos (Go ParseForm) reads only urlencoded bodies, so a multipart post arrives with every field empty. A file upload
// to a portal route is the one multipart form, and it opts out of the router with data-astro-reload.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('..', import.meta.url));
function astroFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? astroFiles(p) : p.endsWith('.astro') ? [p] : [];
  });
}

export function postFormsMissingEnctype(src: string): string[] {
  return [...src.matchAll(/<form\b[^>]*>/g)]
    .map((m) => m[0])
    .filter((t) => /\bmethod="post"/i.test(t))
    .filter((t) => !/\benctype="application\/x-www-form-urlencoded"/.test(t))
    .filter((t) => !(/\benctype="multipart\/form-data"/.test(t) && /\bdata-astro-reload\b/.test(t)));
}

describe('form enctype', () => {
  it('every POST form names enctype=application/x-www-form-urlencoded, data-astro-reload or not', () => {
    const files = astroFiles(root);
    expect(files.length).toBeGreaterThan(10);
    const bad = files.flatMap((f) => postFormsMissingEnctype(readFileSync(f, 'utf8')).map((t) => `${f}: ${t}`));
    expect(bad).toEqual([]);
  });

  it('detects a form without it', () => {
    expect(postFormsMissingEnctype('<form method="POST" action="/x" data-astro-reload>')).toHaveLength(1);
    expect(postFormsMissingEnctype('<form method="post" enctype="multipart/form-data">')).toHaveLength(1);
    expect(postFormsMissingEnctype('<form method="post" enctype="multipart/form-data" data-astro-reload>')).toHaveLength(0);
  });
});

// Filename↔access_group cross-cut, factored out of content.config.ts so it
// is unit-testable without pulling in the `astro:content` virtual module
// (which only resolves inside an Astro build). content.config.ts's zod
// superRefine calls these; scripts/content-config-superrefine.test.mjs
// exercises them directly.

/** Filename → slug, matching astro/loaders glob's default (basename minus extension). */
export function slugFromEntry(entry: string): string {
  const base = entry.split('/').pop() ?? entry;
  return base.replace(/\.[^.]+$/, '');
}

/** The access group a tile with this slug must declare: `access-<slug>`. */
export function expectedAccessGroup(slug: string): string {
  return `access-${slug}`;
}

/**
 * Validate the filename↔access_group cross-cut. Returns an error message
 * when access_group does not equal `access-<slug>`, or null when it
 * matches. Fail-closed on a missing slug (the loader always injects one;
 * an absent slug means a loader regression, not a clean tile).
 */
export function accessGroupMismatch(
  slug: string | undefined,
  accessGroup: string,
): string | null {
  if (typeof slug !== 'string' || slug.length === 0) {
    return 'internal: slug was not injected by the loader; cannot verify access_group matches the filename';
  }
  const expected = expectedAccessGroup(slug);
  if (accessGroup !== expected) {
    return `access_group "${accessGroup}" does not match the filename slug "${slug}" (expected "${expected}")`;
  }
  return null;
}

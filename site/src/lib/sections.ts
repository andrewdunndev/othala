// Single source of truth for othala.dunn.dev: what pages exist, in
// what section, in what order, and which source file backs each one.
// Consumed by Layout.astro (header nav + section sidebar) and by the
// dynamic [...slug].astro route (which reads each `file` and renders
// it through marked). Adding a doc page = adding one row here + moving
// the markdown under src/content/docs/.
//
// The site carries the Guides (content-collection-backed, below) plus
// a standalone Architecture overview at src/pages/architecture.astro —
// hand-authored rather than markdown. `extraNav` is how it reaches the header nav without a
// `Section` entry of its own. Operational runbooks live in the
// repository (docs/), not on the public site.

export interface SectionPage {
  href: string;
  label: string;
  /** Path under src/content/docs/ that backs this page. Omitted for the
   *  section Overview (rendered as a card grid) and for external index
   *  entries (which link off-site and generate no doc page). */
  file?: string;
  /** True when `href` points off-site. No doc page is generated; the entry
   *  renders as an overview/sidebar link. */
  external?: boolean;
  /** Overview-card description for entries without a `file` (external
   *  links). File-backed pages derive their blurb from the source. */
  blurb?: string;
  /** Optional sub-heading the sidebar groups this page under. */
  group?: string;
}

export interface Section {
  href: string;
  label: string;
  lede: string;
  pages: SectionPage[];
}

export const sections: Section[] = [
  {
    href: '/guides/',
    label: 'Guides',
    lede: 'The integration commitments that keep an Ory deployment durable across upgrades, how applications are connected over OIDC, how requests are denied, and how the substrate is hardened.',
    pages: [
      { href: '/guides/',                       label: 'Overview' },
      { href: '/guides/per-app-oidc/',          label: 'Per-app OIDC',           file: 'guides/per-app-oidc.md' },
      { href: '/guides/error-handling/',        label: 'Error handling',         file: 'guides/error-handling.md' },
      { href: '/guides/hardening/',             label: 'Hardening',              file: 'guides/hardening.md' },
    ],
  },
];

/** Top-level nav entries that are not content-collection sections.
 *  Layout.astro renders these ahead of the `sections`-derived entries,
 *  so a standalone page (Architecture) is reachable from every page's
 *  header nav without inventing a `Section` with no doc pages. */
export const extraNav: { href: string; label: string }[] = [
  { href: '/architecture/', label: 'Architecture' },
];

/** Pick the section that owns a URL path (drives sidebar rendering). */
export function sectionForPath(path: string): Section | null {
  const cleaned = path.replace(/\/$/, '') || '/';
  for (const s of sections) {
    const sectionHref = s.href.replace(/\/$/, '');
    if (cleaned === sectionHref || cleaned.startsWith(sectionHref + '/')) return s;
  }
  return null;
}

/** Map every published doc's source basename → its site URL, so
 *  intra-repo Markdown links (`[hardening](hardening.md)`,
 *  `docs/per-app-oidc.md`) rewrite to working site links at render
 *  time. Basenames not in the map (repo-only docs, off-site paths)
 *  are left untouched — those links resolve
 *  against the repository, not the site. */
export function docLinkMap(): Record<string, string> {
  const map: Record<string, string> = {};
  for (const s of sections) {
    for (const p of s.pages) {
      if (!p.file) continue;
      const base = p.file.split('/').pop()!;
      map[base] = p.href;
    }
  }
  return map;
}

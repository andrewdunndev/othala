// Single source of truth for othala.dunn.dev: what pages exist, in
// what section, in what order, and which source file backs each one.
// Consumed by Layout.astro (header nav + section sidebar) and by the
// dynamic [...slug].astro route (which reads each `file` and renders
// it through marked). Adding a doc page = adding one row here + moving
// the markdown under src/content/docs/.
//
// The site carries the two timeless surfaces: adopter-facing Guides and
// a Decisions index that links OUT to the repo-canonical ADRs. Operational
// runbooks and dated research live in the repository (docs/), not on the
// public site.

export interface SectionPage {
  href: string;
  label: string;
  /** Path under src/content/docs/ that backs this page. Omitted for the
   *  section Overview (rendered as a card grid) and for external index
   *  entries (which link off-site and generate no doc page). */
  file?: string;
  /** True when `href` points off-site (e.g. an ADR on gitlab.com). No
   *  doc page is generated; the entry renders as an overview/sidebar link. */
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

const ADR = 'https://gitlab.com/dunn.dev/othala/-/blob/main/docs/adr';

export const sections: Section[] = [
  {
    href: '/guides/',
    label: 'Guides',
    lede: 'Operational and adopter-facing guides: the integration commitments that keep the stack durable, how to wire an app to Othala over OIDC, how requests are denied, how to run it securely, and what a family member sees when they sign in.',
    pages: [
      { href: '/guides/',                       label: 'Overview' },
      { href: '/guides/golden-path/',           label: 'Golden path',            file: 'guides/golden-path.md' },
      { href: '/guides/per-app-oidc/',          label: 'Per-app OIDC',           file: 'guides/per-app-oidc.md' },
      { href: '/guides/error-handling/',        label: 'Error handling',         file: 'guides/error-handling.md' },
      { href: '/guides/hardening/',             label: 'Hardening',              file: 'guides/hardening.md' },
      { href: '/guides/family-help/',           label: 'Family help',            file: 'guides/family-help.md' },
      { href: '/guides/contribution-strategy/', label: 'Contribution strategy',  file: 'guides/contribution-strategy.md' },
    ],
  },
  {
    href: '/decisions/',
    label: 'Decisions',
    lede: 'Architecture Decision Records — the choices that shaped Othala and are not obvious from the code alone. The records live in the repository and describe the system as deployed; each card links to the canonical ADR on gitlab.com.',
    pages: [
      { href: '/decisions/', label: 'Overview' },
      { href: `${ADR}/01-auth-substrate-ory.md`,             external: true, label: '01 · Auth substrate: Ory',       blurb: 'Six substrates evaluated; Ory wins on BYO-UI, single-binary, Apache-2. Substrate is Kratos + Hydra; the LDAP bridge was never deployed and is retired.' },
      { href: `${ADR}/02-custom-portal-oidc-registrar.md`,   external: true, label: '02 · Custom portal + registrar', blurb: 'Consent folded into the portal; client registration is a typed TypeScript registrar — create/update-only, never deletes — reconciled on SIGHUP.' },
      { href: `${ADR}/03-proxy-originated-mtls.md`,          external: true, label: '03 · Proxy-originated mTLS',     blurb: 'Apps talk plain HTTP; a sidecar holds the cert. The dag admin-proxy was reverted (2026-07-01) to a network-isolated direct hop; the pattern survives on the inference path.' },
      { href: `${ADR}/04-identity-linking-on-username.md`,   external: true, label: '04 · Identity linking',          blurb: 'The durable OIDC subject is the Kratos identity UUID; username is the human migration on-ramp and is user-mutable; email is never a configured link key.' },
      { href: `${ADR}/05-passkey-first-auth.md`,             external: true, label: '05 · Passkey-first auth',        blurb: 'Three tiers: passkey primary, email one-time-code as a full-login secondary, password demoted to a tertiary recovery on-ramp.' },
      { href: `${ADR}/06-two-pki.md`,                        external: true, label: '06 · Two-PKI',                  blurb: 'Two never-chained roots estate-wide. dag is single-PKI (Let’s Encrypt edge only) as deployed; the live step-ca consumer is the inference metering hop.' },
      { href: `${ADR}/07-three-layer-naming.md`,             external: true, label: '07 · Three-layer naming',        blurb: 'Othala (OSS project) / dag.dunn.dev (the instance) / kratos+hydra (Ory functional names) — used consistently, never conflated.' },
      { href: `${ADR}/08-admin-authority-model.md`,          external: true, label: '08 · Admin authority model',     blurb: 'Live admin grant/revoke via admin-managed metadata + AAL2 step-up, retiring the env allowlist; the Ory-native admin plane is the bootstrap floor. Two honest gaps recorded.' },
      { href: `${ADR}/09-capability-group-access-model.md`,  external: true, label: '09 · Capability-group access',    blurb: 'access-<svc> / admin-<svc> / root capability groups with path-selective forward-auth and set-union claims; legacy cohorts persist pending migration. The roster stays in the instance.' },
      { href: `${ADR}/10-first-party-skip-consent.md`,       external: true, label: '10 · First-party skip-consent',   blurb: 'skip_consent per first-party client so the household never sees a consent screen; a documented threat-model acceptance, revisited at the first banking-tier client.' },
      { href: `${ADR}/README.md`, external: true, label: 'Format & full index', group: 'Meta', blurb: 'The MADR-lite format, the status conventions, and the full index of decision records in the repository.' },
    ],
  },
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
 *  intra-repo Markdown links (`[golden path](golden-path.md)`,
 *  `docs/per-app-oidc.md`) rewrite to working site links at render
 *  time. Basenames not in the map (repo-only docs, external ADRs,
 *  storr-internal paths) are left untouched — those links resolve
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

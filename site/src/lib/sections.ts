// Single source of truth for othala.dunn.dev: what pages exist, in
// what section, in what order, and which source file backs each one.
// Consumed by Layout.astro (header nav + section sidebar) and by the
// dynamic [...slug].astro route (which reads each `file` and renders
// it through marked). Adding a doc page = adding one row here + moving
// the markdown under src/content/docs/.
//
// The site carries the two timeless surfaces: the Guides that describe how
// this instance is wired, and a Decisions index that links OUT to the
// repo-canonical ADRs. Operational runbooks and dated research live in the
// repository (docs/), not on the public site.
//
// The Decisions cards below are a THIRD hand-maintained copy of the ADR
// index (the others are docs/adr/README.md and the files themselves). Every
// docs/adr/NN-*.md must have a card here, and no ADR edit lands without its
// card updated in the same commit. Card blurbs are discipline, not a gate:
// scripts/check-purity.sh checks that each card's number resolves to a file,
// and nothing checks that a blurb is still true.

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
    lede: 'How this instance is actually wired: the integration commitments that keep it durable across Ory upgrades, how apps are connected over OIDC, how requests are denied, how it is hardened, and what a family member sees when they sign in.',
    pages: [
      { href: '/guides/',                       label: 'Overview' },
      { href: '/guides/golden-path/',           label: 'Golden path',            file: 'guides/golden-path.md' },
      { href: '/guides/per-app-oidc/',          label: 'Per-app OIDC',           file: 'guides/per-app-oidc.md' },
      { href: '/guides/error-handling/',        label: 'Error handling',         file: 'guides/error-handling.md' },
      { href: '/guides/hardening/',             label: 'Hardening',              file: 'guides/hardening.md' },
      { href: '/guides/family-help/',           label: 'Family help',            file: 'guides/family-help.md' },
    ],
  },
  {
    href: '/decisions/',
    label: 'Decisions',
    lede: 'Architecture Decision Records — the choices that shaped Othala and are not obvious from the code alone. The records live in the repository and describe the system as deployed; each card links to the canonical ADR on gitlab.com.',
    pages: [
      { href: '/decisions/', label: 'Overview' },
      { href: `${ADR}/01-auth-substrate-ory.md`,             external: true, label: '01 · Auth substrate: Ory',        blurb: 'Six substrates evaluated; Ory wins on BYO-UI, single-binary, Apache-2. The substrate is Kratos + Hydra and a custom portal. A service authenticates one of three ways: OIDC, a service-local password, or forward-auth. No LDAP server and no LDAP bridge is deployed.' },
      { href: `${ADR}/02-custom-portal-oidc-registrar.md`,   external: true, label: '02 · Custom portal + registrar',   blurb: 'Consent folded into the portal; client registration is a typed TypeScript registrar (create/update-only, never deletes) reconciled on boot and on SIGHUP. A decommissioned service leaves a ghost registration until an operator removes it by hand.' },
      { href: `${ADR}/03-proxy-originated-mtls.md`,          external: true, label: '03 · Proxy-originated mTLS',      blurb: 'Application code speaks plain HTTP and never loads a certificate; where a real TLS boundary exists, a Caddy sidecar holds the cert. The dag Kratos-admin hop needs no boundary and has none: network isolation is the load-bearing control there.' },
      { href: `${ADR}/04-identity-linking-on-username.md`,   external: true, label: '04 · Identity linking',           blurb: 'The durable OIDC subject is the Kratos identity UUID; username is the one-time migration and first-link key and stays user-mutable; email is never a configured link key. Mealie is the sole username-forever consumer.' },
      { href: `${ADR}/05-passkey-first-auth.md`,             external: true, label: '05 · Passkey-first auth',         blurb: 'Three tiers: passkey primary everywhere, email one-time-code as a full-login secondary ranked above password, and password as the tertiary recovery on-ramp and the credential the seeded floor identities carry.' },
      { href: `${ADR}/06-two-pki.md`,                        external: true, label: '06 · Two-PKI',                    blurb: 'Two never-chained roots estate-wide: Let’s Encrypt for everything browser- and device-facing, a self-hosted step-ca root for internal mesh identities. dag is single-PKI as deployed; the live step-ca consumer is the inference metering hop.' },
      { href: `${ADR}/07-three-layer-naming.md`,             external: true, label: '07 · Three-layer naming',         blurb: 'Othala (the OSS project) / dag.dunn.dev (this deployment) / kratos+hydra (Ory’s functional component names), used consistently and never conflated, because which layer a name belongs to decides which file owns a change.' },
      { href: `${ADR}/08-admin-authority-model.md`,          external: true, label: '08 · Admin authority model',      blurb: 'Day-to-day admin is the metadata_admin.admin marker: admin-API-writable only, read fresh on every request, AAL2-gated server-side. The floor is the Ory-native admin plane with a dedicated break-glass identity. One honest gap recorded, with its re-litigation trigger.' },
      { href: `${ADR}/09-capability-group-access-model.md`,  external: true, label: '09 · Access model',               blurb: 'Exactly two groups per service. Entry comes from holding <svc>-access, always, for everyone including admins; <svc>-admin grants role only and admits nobody on its own. No estate-wide root, no cohorts, nothing derived from anything else.' },
      { href: `${ADR}/10-first-party-skip-consent.md`,       external: true, label: '10 · First-party skip-consent',   blurb: 'skip_consent per first-party client so the household never sees a consent screen. No client uses the consent screen today, so the per-client flag is a deliberate tripwire; the accepted threat is stated, and the first banking-tier client re-opens it.' },
      { href: `${ADR}/11-hardening-tuning.md`,               external: true, label: '11 · Hardening tuning',           blurb: 'The deliberate deviations from Ory defaults (flow and session lifetimes, hash cost, credential-change AAL), plus the PKCE posture and the reasons not to flip it on the strength of a client that is not deployed.' },
      { href: `${ADR}/12-oidc-client-topology.md`,           external: true, label: '12 · OIDC client topology',       blurb: 'Hydra redirects challenge flows to portal-owned /oauth2/{login,consent,logout} routes, which the fronting proxy must match before any wider wildcard or every login breaks silently. The CORS allowlist as deployed is a single origin.' },
      { href: `${ADR}/13-vendored-config-contract.md`,       external: true, label: '13 · Vendored-config contract',   blurb: 'Four config files here are byte-canonical for production; the deploy plane vendors them verbatim and enforces the match. The edit direction is one-way, and the ADR pointers inside them are what make these numbers permanent.' },
      { href: `${ADR}/14-enrollment-out-of-band.md`,         external: true, label: '14 · Enrollment',                 blurb: 'No self-service registration. An admin creates the identity with no credential and hands over a one-time link and code by chat; the recipient sets up their own credentials in their own browser. No password ever transits a channel.' },
      { href: `${ADR}/15-forward-auth-gate-aal1.md`,         external: true, label: '15 · Forward-auth gate + aal1',   blurb: 'Apps that cannot speak OIDC are gated by Caddy forward_auth calling the portal with a required group. 401 means only “no usable session”; everything else is a fail-closed 403. This gate is why session.whoami must stay aal1.' },
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

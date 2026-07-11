// Single source of truth for othala.dunn.dev: what pages exist, in
// what section, in what order, and which source file backs each one.
// Consumed by Layout.astro (header nav + section sidebar) and by the
// dynamic [...slug].astro route (which reads each `file` and renders
// it through marked). Adding a doc page = adding one row here + moving
// the markdown under src/content/docs/.
//
// `disposition` records how each source file was handled when the docs
// site was scaffolded (MOVE = lifted as-is; KEEP-REWRITE = lifted with
// a TODO header for a later prose pass). It is documentation only; the
// site does not branch on it.

export type Disposition = 'MOVE' | 'KEEP-REWRITE';

export interface SectionPage {
  href: string;
  label: string;
  /** Path under src/content/docs/ that backs this page. Omitted for
   *  the section Overview (rendered as a card grid). */
  file?: string;
  /** Optional sub-heading the sidebar groups this page under. */
  group?: string;
  disposition?: Disposition;
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
    lede: 'Operational and adopter-facing guides: the integration commitments that keep the stack durable, how to wire an app to Othala over OIDC, how requests are denied, how to run it securely, and what a family member sees when they sign in.',
    pages: [
      { href: '/guides/',                     label: 'Overview' },
      { href: '/guides/golden-path/',         label: 'Golden path',          file: 'guides/golden-path.md',          disposition: 'MOVE' },
      { href: '/guides/per-app-oidc/',        label: 'Per-app OIDC',         file: 'guides/per-app-oidc.md',         disposition: 'KEEP-REWRITE' },
      { href: '/guides/error-handling/',      label: 'Error handling',       file: 'guides/error-handling.md',       disposition: 'MOVE' },
      { href: '/guides/hardening/',           label: 'Hardening',            file: 'guides/hardening.md',            disposition: 'KEEP-REWRITE' },
      { href: '/guides/family-help/',         label: 'Family help',          file: 'guides/family-help.md',          disposition: 'MOVE' },
      { href: '/guides/contribution-strategy/', label: 'Contribution strategy', file: 'guides/contribution-strategy.md', disposition: 'MOVE' },
    ],
  },
  {
    href: '/decisions/',
    label: 'Decisions',
    lede: 'Architecture Decision Records — the choices that shaped Othala and are not obvious from the code alone: what was decided, why the alternatives were real, and what follows.',
    pages: [
      { href: '/decisions/',                            label: 'Overview' },
      { href: '/decisions/0001-auth-substrate-ory/',            label: '0001 · Auth substrate: Ory',            file: 'decisions/0001-auth-substrate-ory.md',            disposition: 'MOVE' },
      { href: '/decisions/0002-custom-portal-oidc-registrar/',  label: '0002 · Custom portal + registrar',      file: 'decisions/0002-custom-portal-oidc-registrar.md',  disposition: 'MOVE' },
      { href: '/decisions/0003-proxy-originated-mtls/',         label: '0003 · Proxy-originated mTLS',          file: 'decisions/0003-proxy-originated-mtls.md',         disposition: 'KEEP-REWRITE' },
      { href: '/decisions/0004-identity-linking-on-username/',  label: '0004 · Identity linking',               file: 'decisions/0004-identity-linking-on-username.md',  disposition: 'KEEP-REWRITE' },
      { href: '/decisions/0005-passkey-first-auth/',            label: '0005 · Passkey-first auth',             file: 'decisions/0005-passkey-first-auth.md',            disposition: 'KEEP-REWRITE' },
      { href: '/decisions/0006-two-pki/',                       label: '0006 · Two-PKI',                        file: 'decisions/0006-two-pki.md',                       disposition: 'KEEP-REWRITE' },
      { href: '/decisions/0007-three-layer-naming/',            label: '0007 · Three-layer naming',             file: 'decisions/0007-three-layer-naming.md',            disposition: 'KEEP-REWRITE' },
      { href: '/decisions/0008-admin-authority-model/',         label: '0008 · Admin authority model',          file: 'decisions/0008-admin-authority-model.md',         disposition: 'MOVE' },
      { href: '/decisions/0009-capability-group-access-model/', label: '0009 · Capability-group access',        file: 'decisions/0009-capability-group-access-model.md', disposition: 'KEEP-REWRITE' },
      { href: '/decisions/0010-first-party-skip-consent/',      label: '0010 · First-party skip-consent',       file: 'decisions/0010-first-party-skip-consent.md',      disposition: 'KEEP-REWRITE' },
      { href: '/decisions/format/',       label: 'ADR format',   file: 'decisions/README.md',        group: 'Meta', disposition: 'MOVE' },
      { href: '/decisions/0000-template/', label: 'Template',    file: 'decisions/0000-template.md', group: 'Meta', disposition: 'MOVE' },
    ],
  },
  {
    href: '/runbooks/',
    label: 'Runbooks',
    lede: 'Break-glass and steady-state operational procedures for running an Othala instance: admin recovery, credential rotation, recovery-email deliverability, lost-device eviction, and Postgres backup/restore.',
    pages: [
      { href: '/runbooks/',                  label: 'Overview' },
      { href: '/runbooks/admin-recovery/',   label: 'Admin recovery',        file: 'runbooks/admin-recovery.md',   disposition: 'MOVE' },
      { href: '/runbooks/lost-device/',      label: 'Lost or stolen device', file: 'runbooks/lost-device.md',      disposition: 'KEEP-REWRITE' },
      { href: '/runbooks/cookie-rotation/',  label: 'Cookie / cipher rotation', file: 'runbooks/cookie-rotation.md', disposition: 'MOVE' },
      { href: '/runbooks/secrets-rotation/', label: 'secrets.system rotation', file: 'runbooks/secrets-rotation.md', disposition: 'MOVE' },
      { href: '/runbooks/email-recovery/',   label: 'Email recovery',        file: 'runbooks/email-recovery.md',   disposition: 'MOVE' },
      { href: '/runbooks/postgres-backup/',  label: 'Postgres backup',       file: 'runbooks/postgres-backup.md',  disposition: 'MOVE' },
    ],
  },
  {
    href: '/research/',
    label: 'Research',
    lede: 'Research and audit artifacts behind the design: the Ory ecosystem survey, an OIDC/identity standards-alignment audit, and the QEMU end-to-end CI harness that proves the stack.',
    pages: [
      { href: '/research/',                              label: 'Overview' },
      { href: '/research/ory-ecosystem-survey/',         label: 'Ory ecosystem survey',       file: 'research/ory-ecosystem-survey.md',         disposition: 'MOVE' },
      { href: '/research/oidc-standards-audit-2026-06-20/', label: 'OIDC standards audit',    file: 'research/oidc-standards-audit-2026-06-20.md', disposition: 'MOVE' },
      { href: '/research/qemu-ci-lab/',                  label: 'QEMU CI lab',                file: 'research/qemu-ci-lab.md',                  disposition: 'KEEP-REWRITE' },
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
 *  intra-repo Markdown links (`[0002](0002-...md)`, `../decision.md`,
 *  `docs/per-app-oidc.md`) rewrite to working site links at render
 *  time. Basenames not in the map (CUT docs, storr-internal
 *  campaigns/* paths) are left untouched and 404 — those are the
 *  dead links the KEEP-REWRITE headers call out. */
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

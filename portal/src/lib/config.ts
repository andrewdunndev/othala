// Othala portal env-config module.
//
// Reads and normalises every OTHALA_* var the portal itself consumes.
// Vars that belong to Ory service config (OTHALA_APEX, OTHALA_WEBAUTHN,
// OTHALA_SMTP, …) are injected at the YAML layer via ${ENV} substitution
// and are NOT present here.
//
// Required-no-default strategy
// ─────────────────────────────
// Some vars have no sensible production default. When NODE_ENV === 'production'
// and such a var is absent the accessor THROWS at module load so the problem
// is caught at startup, not buried in a rendered page. In development / test
// it returns a safe local default instead.
//
// Neutral-default strategy
// ─────────────────────────
// Vars that carry display text or schema identifiers all ship a generic
// default. The default is described inline so operators know exactly what
// they get if they omit the var.
//
// Usage
// ─────
//   import { publicUrl, siteName, instanceName, adminContact,
//            defaultSchemaId, defaultGroup, identityGroups } from '../lib/config';
//
//   // or for consumers that only need one value and want tree-shaking:
//   import { siteName } from '../lib/config';  // depth-relative per file

// ── helpers ──────────────────────────────────────────────────────────────────

function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

/**
 * Reads an env var. In production, throws if absent. In dev/test, returns
 * `devDefault` with a console.warn so developers notice the gap without a
 * hard crash.
 */
function requiredVar(name: string, devDefault: string): string {
  const val = process.env[name];
  if (val !== undefined && val.trim() !== '') return val.trim();
  if (isProduction()) {
    throw new Error(
      `[othala/config] Required env var ${name} is not set. ` +
        `Set it in the deployment environment and restart.`,
    );
  }
  // dev / test: warn loudly but keep going
  console.warn(
    `[othala/config] ${name} is not set; using dev default "${devDefault}". ` +
      `This would throw in production.`,
  );
  return devDefault;
}

/**
 * Reads an env var and returns `fallback` when absent or blank.
 * No throw in any environment — callers rely on the neutral default.
 */
function optionalVar(name: string, fallback: string): string {
  const val = process.env[name];
  return val !== undefined && val.trim() !== '' ? val.trim() : fallback;
}

// ── OTHALA_PUBLIC_URL ─────────────────────────────────────────────────────────
//
// The public FQDN/issuer of this Othala instance. Consumers use it to build
// absolute redirect URLs, canonical links, and email hrefs. Must not carry a
// trailing slash.
//
// Required-no-default in production.
// Dev/test default: 'http://localhost:4321' (Astro dev port).

export const publicUrl: string = requiredVar(
  'OTHALA_PUBLIC_URL',
  'http://localhost:4321',
).replace(/\/+$/, ''); // strip trailing slash regardless of source

// ── OTHALA_SITE_NAME ──────────────────────────────────────────────────────────
//
// Human-readable brand name shown in page titles, headers, and footers.
//
// Neutral default: 'Othala' (the project name; operators override for their
// instance, e.g. 'Acme SSO').

export const siteName: string = optionalVar('OTHALA_SITE_NAME', 'Othala');

// ── OTHALA_ADMIN_CONTACT ──────────────────────────────────────────────────────
//
// Human-readable contact hint shown to locked-out users on error/recovery
// screens. Ops teams set this to an email address or help-desk URL.
//
// Neutral default: 'your administrator'.

export const adminContact: string = optionalVar(
  'OTHALA_ADMIN_CONTACT',
  'your administrator',
);

// ── OTHALA_INSTANCE_NAME ──────────────────────────────────────────────────────
//
// Display name used for TOTP issuer labels, WebAuthn RP display name, and
// SMTP From headers. May differ from siteName (e.g. siteName = 'Acme Portal',
// instanceName = 'Acme SSO').
//
// Default: falls back to OTHALA_SITE_NAME (resolved value, not raw env) so
// operators who set only OTHALA_SITE_NAME get a consistent brand with zero
// extra config.

export const instanceName: string =
  process.env.OTHALA_INSTANCE_NAME?.trim() || siteName;

// ── OTHALA_SMTP_CONNECTION_URI ────────────────────────────────────────────────
//
// The SINGLE source of truth for the courier SMTP connection, shared by both
// Kratos (kratos/kratos.yml `courier.smtp.connection_uri`) and the portal's
// contact-form mailer (lib/mailer.ts). One URI, one relay — the contact form
// provably uses the exact same outbound path as recovery/verification mail.
//
// Form:  smtps://USER:PASS@host:465   (implicit TLS, recommended)
//        smtp://USER:PASS@host:587     (STARTTLS)
// The USER/PASS are URL-encoded; the portal mailer URL-decodes them.
//
// Required-no-default in production (no working SMTP ⇒ the form can't deliver).
// Dev/test default points at the lab catcher so `npm run dev` and the e2e gate
// have a working relay without secrets. (The e2e mailpit listens on :1025.)

// A required image-config parameter (the app sends mail). Exposed
// explicitly and set wherever the othala image runs — including the
// register-clients one-shot, which shares the image + this config contract
// even though it doesn't itself send mail (same pattern as OTHALA_PUBLIC_URL).
export const smtpConnectionUri: string = requiredVar(
  'OTHALA_SMTP_CONNECTION_URI',
  'smtp://lab:lab@localhost:1025',
);

// ── OTHALA_CONTACT_RECIPIENT ──────────────────────────────────────────────────
//
// Where the dashboard contact/request form delivers. A single email address
// (the operator's inbox). Must be set explicitly — admin authority is the
// metadata_admin.admin marker, so no admin email list exists to
// serve as a fallback here.
//
// Fail-loud in production when unset.

function resolveContactRecipient(): string {
  const explicit = process.env.OTHALA_CONTACT_RECIPIENT?.trim();
  if (explicit) return explicit;
  if (isProduction()) {
    throw new Error(
      '[othala/config] No contact recipient: set OTHALA_CONTACT_RECIPIENT so ' +
        'the dashboard request form has somewhere to deliver.',
    );
  }
  console.warn(
    '[othala/config] OTHALA_CONTACT_RECIPIENT is not set; ' +
      'using dev default "admin@localhost". This would throw in production.',
  );
  return 'admin@localhost';
}

export const contactRecipient: string = resolveContactRecipient();

// From address for portal-originated mail (the contact form). Reuses the
// Kratos courier From address so all instance mail shares one envelope sender.
// Neutral default keeps dev/test working without config.
export const smtpFromAddress: string = optionalVar(
  'OTHALA_SMTP_FROM_ADDRESS',
  'noreply@localhost',
);

// ── OTHALA_DEFAULT_SCHEMA_ID ──────────────────────────────────────────────────
//
// Kratos schema_id assigned to identities created by the portal (admin
// create-identity flow, CLI bootstrap, etc.). Must match a schema listed in
// the Kratos identity schema config.
//
// Neutral default: 'default'.

export const defaultSchemaId: string = optionalVar(
  'OTHALA_DEFAULT_SCHEMA_ID',
  'default',
);

// ── OTHALA_DEFAULT_GROUP ──────────────────────────────────────────────────────
//
// The fallback access group applied to any manifest tile whose
// `presentation.access_group` field is absent. Every tile in Othala gates on
// group membership — there is no ungated/bypass concept. When an operator
// omits `access_group` from a manifest the tile becomes visible to members of
// this group rather than to nobody.
//
// Operators override this per instance (e.g. `OTHALA_DEFAULT_GROUP=family`).
// The default group is automatically appended to the identityGroups list (see
// OTHALA_IDENTITY_GROUPS below) so it appears in the admin UI group selector.
// Membership is NOT auto-assigned to new identities — adding a user to the
// default group remains an explicit admin act.
//
// Neutral default: 'everyone' — an OSS-portable name that makes the intent
// clear without conflicting with any identity-group convention.

export const defaultGroup: string = optionalVar(
  'OTHALA_DEFAULT_GROUP',
  'everyone',
).toLowerCase();

// ── OTHALA_IDENTITY_GROUPS ────────────────────────────────────────────────────
//
// Comma-separated ORDERED list of identity groups available for assignment in
// the admin UI. The 'admin' group is RESERVED and always first; it is
// automatically prepended if the operator omits it or places it elsewhere,
// preserving the invariant that admin authority gates are always first in any
// rendered group selector.
//
// The value of OTHALA_DEFAULT_GROUP is appended (deduplicated) so the default
// group always appears in the selector without requiring the operator to list
// it explicitly.
//
// Example:  OTHALA_IDENTITY_GROUPS=admin,family,friends,work
// Neutral default: ['admin', 'everyone'] — admin plus the default group;
// operators extend as needed.
//
// WHAT THIS LIST IS, AND WHAT IT IS NOT — three different things share the
// word "group" here, and conflating them has produced wrong docs before.
//
// 1. THIS list (env) is a TYPE declaration plus selector options. It names
//    which groups count as `identity` groups rather than app-access groups —
//    read by group-registry.ts and manifests.ts `knownIdentityGroups` for
//    classification, by access.ts (IDENTITY_GROUP_ORDER → normalizeGroupOrder)
//    for a stable stored order that is cosmetic only, and by the admin UI to
//    render the identity-group checkboxes. It authorizes nothing on its own.
//
// 2. `metadata_admin.groups` ON AN IDENTITY IS ENTRY AUTHORIZATION. It is
//    NOT display-only. `identityGroups(identity)` in gate.ts (same exported
//    name as the constant below, a different function) is the reader, and it
//    feeds `enforceGroupGate` for the /api/forward-auth edge gate and
//    `enforceAccessGate` for the OIDC login and consent challenges — both of
//    which also refuse an identity carrying any stored group outside
//    GROUP_RE (access-groups.ts), via gate.ts `refuseNonCanonical`, above the
//    `skip_access_check` hatch. The same array also drives tile visibility
//    (tiles.ts `userCanSeeTile`) and role resolution (claims.ts `lookupRole`).
//    Adding a name to that array admits a person; removing one locks them out.
//
// 3. Admin authority is neither: it is the `metadata_admin.admin` marker read
//    by admin-auth.ts `isAdminMarker`, writable only through the Kratos admin API.
//    It is not a group and does not appear in `metadata_admin.groups`. A bare
//    'admin' string prepended to the list below is a NAME in a selector; it
//    confers no portal authority.

function parseIdentityGroups(): string[] {
  const raw = process.env.OTHALA_IDENTITY_GROUPS ?? '';
  const parsed = raw
    .split(',')
    .map((g) => g.trim().toLowerCase())
    .filter(Boolean);

  // 'admin' is always first; deduplicate without losing order.
  const base = ['admin', ...parsed.filter((g) => g !== 'admin')];
  const withDefault = base.includes(defaultGroup)
    ? base
    : [...base, defaultGroup];
  return withDefault;
}

export const identityGroups: string[] = parseIdentityGroups();

// ── OTHALA_ADMIN_FRESHNESS_HOURS ──────────────────────────────────────────────
//
// A session-age window in hours. Parsed here, but NOT enforced by any gate:
// nothing outside this file reads `adminFreshnessHours`.
//
// The portal's only freshness computation is `isSessionFresh` in lib/admin.ts,
// whose docblock records the decision — "this function is NOT wired into the
// requireAdminSession gate" — and flags that its timestamp semantics "should be
// validated against a live Kratos session before wiring isSessionFresh into any
// gate". Do not describe this var as active until that wiring lands.
//
// What requireAdminSession actually enforces is the SP-3 trinity:
// active session, `session.authenticator_assurance_level === 'aal2'` (anything
// else redirects to the Kratos step-up login flow with aal=aal2 & refresh=true),
// and the metadata_admin.admin marker read fresh from the admin API. There is
// no session-age check. See site/src/content/docs/guides/hardening.md §7, which
// carries the same statement for operators.
//
// Default: 8 (hours) when unset, blank, or not a non-negative integer.

function parseAdminFreshnessHours(): number {
  const raw = process.env.OTHALA_ADMIN_FRESHNESS_HOURS;
  if (raw === undefined || raw.trim() === '') return 8;
  const n = parseInt(raw.trim(), 10);
  if (!Number.isFinite(n) || n < 0) {
    console.warn(
      `[othala/config] OTHALA_ADMIN_FRESHNESS_HOURS="${raw}" is not a valid non-negative integer; ` +
        'using default 8.',
    );
    return 8;
  }
  return n;
}

export const adminFreshnessHours: number = parseAdminFreshnessHours();

// ── aggregate export for consumers that want the full config object ───────────
//
// Named individual exports above are the primary API and are tree-shakeable.
// This object is a convenience for logging/debug and template-level spread.

export const config = {
  publicUrl,
  siteName,
  adminContact,
  instanceName,
  defaultSchemaId,
  defaultGroup,
  identityGroups,
  contactRecipient,
  smtpFromAddress,
  adminFreshnessHours,
  // smtpConnectionUri intentionally OMITTED from the debug/log object: it
  // carries the SMTP password. Consumers import it by name when they need it.
} as const;

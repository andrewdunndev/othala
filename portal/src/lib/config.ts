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
// (the operator's inbox). When unset it falls back to the FIRST entry of
// OTHALA_ADMIN_SUBJECTS (the admin allowlist) — the people who can actually
// action a request — so a minimal deployment needs no extra config.
//
// Fail-loud in production only if BOTH are empty (nowhere to send).

function firstAdminSubject(): string {
  const raw = process.env.OTHALA_ADMIN_SUBJECTS ?? '';
  for (const part of raw.split(',')) {
    const email = part.trim();
    if (email) return email;
  }
  return '';
}

function resolveContactRecipient(): string {
  const explicit = process.env.OTHALA_CONTACT_RECIPIENT?.trim();
  if (explicit) return explicit;
  const admin = firstAdminSubject();
  if (admin) return admin;
  if (isProduction()) {
    throw new Error(
      '[othala/config] No contact recipient: set OTHALA_CONTACT_RECIPIENT or ' +
        'OTHALA_ADMIN_SUBJECTS so the dashboard request form has somewhere to deliver.',
    );
  }
  console.warn(
    '[othala/config] No OTHALA_CONTACT_RECIPIENT / OTHALA_ADMIN_SUBJECTS; ' +
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
// NOTE: group membership in metadata_admin.groups is DISPLAY-ONLY (CU3/B2).
//       Admin authority is the OTHALA_ADMIN_SUBJECTS allowlist in admin-auth.ts,
//       not this list.

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
  // smtpConnectionUri intentionally OMITTED from the debug/log object: it
  // carries the SMTP password. Consumers import it by name when they need it.
} as const;

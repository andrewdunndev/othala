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
//            defaultSchemaId, identityGroups } from '../lib/config';
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

// ── OTHALA_IDENTITY_GROUPS ────────────────────────────────────────────────────
//
// Comma-separated ORDERED list of identity groups available for assignment in
// the admin UI. The 'admin' group is RESERVED and always first; it is
// automatically prepended if the operator omits it or places it elsewhere,
// preserving the invariant that admin authority gates are always first in any
// rendered group selector.
//
// Example:  OTHALA_IDENTITY_GROUPS=admin,family,friends,work
// Neutral default: ['admin'] — single group; operators extend as needed.
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
  const groups = ['admin', ...parsed.filter((g) => g !== 'admin')];
  return groups.length > 1 ? groups : ['admin'];
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
  identityGroups,
} as const;

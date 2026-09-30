// Portal env config: every OTHALA_* var the portal consumes. Ory service vars are injected at the YAML layer.
// A required var throws at load in production and takes a dev default elsewhere; the rest ship neutral defaults.

// ── helpers ──────────────────────────────────────────────────────────────────

function isProduction(): boolean {
  return process.env.NODE_ENV === 'production';
}

/** Reads an env var; in production throws if absent, in dev/test warns and returns `devDefault`. */
function requiredVar(name: string, devDefault: string): string {
  const val = process.env[name];
  if (val !== undefined && val.trim() !== '') return val.trim();
  if (isProduction()) {
    throw new Error(
      `[othala/config] Required env var ${name} is not set. ` +
        `Set it in the deployment environment and restart.`,
    );
  }
  console.warn(
    `[othala/config] ${name} is not set; using dev default "${devDefault}". ` +
      `This would throw in production.`,
  );
  return devDefault;
}

/** Reads an env var, `fallback` when absent or blank. */
function optionalVar(name: string, fallback: string): string {
  const val = process.env[name];
  return val !== undefined && val.trim() !== '' ? val.trim() : fallback;
}

// ── OTHALA_PUBLIC_URL ── public issuer URL, no trailing slash; required in production.
export const publicUrl: string = requiredVar(
  'OTHALA_PUBLIC_URL',
  'http://localhost:4321',
).replace(/\/+$/, ''); // strip trailing slash regardless of source

// ── OTHALA_APEX ── registrable parent domain: the Kratos cookie domain and the WebAuthn RP id; required in production.
export const apex: string = requiredVar('OTHALA_APEX', 'localhost');

// ── OTHALA_SITE_NAME ── brand name in titles, headers and footers.
export const siteName: string = optionalVar('OTHALA_SITE_NAME', 'Othala');

// ── OTHALA_ADMIN_CONTACT ── contact hint on error/recovery screens (email or help-desk URL).
export const adminContact: string = optionalVar(
  'OTHALA_ADMIN_CONTACT',
  'your administrator',
);

// ── OTHALA_INSTANCE_NAME ── TOTP issuer, WebAuthn RP name and SMTP From name; falls back to siteName.
export const instanceName: string =
  process.env.OTHALA_INSTANCE_NAME?.trim() || siteName;

// ── OTHALA_SMTP_CONNECTION_URI ── one SMTP URI shared by Kratos courier and lib/mailer.ts
// (smtps://USER:PASS@host:465 or smtp://...:587, URL-encoded credentials); required in production.
export const smtpConnectionUri: string = requiredVar(
  'OTHALA_SMTP_CONNECTION_URI',
  'smtp://lab:lab@localhost:1025',
);

// ── OTHALA_CONTACT_RECIPIENT ── where the contact/request form delivers; required in production.
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

// ── OTHALA_SMTP_FROM_ADDRESS ── From: address for portal mail; defaults to noreply@<OTHALA_APEX>.
export const smtpFromAddress: string = optionalVar(
  'OTHALA_SMTP_FROM_ADDRESS',
  `noreply@${apex}`,
);

// ── OTHALA_DEFAULT_GROUP ── default identity group, appended to identityGroups; membership is never auto-assigned.
export const defaultGroup: string = optionalVar(
  'OTHALA_DEFAULT_GROUP',
  'everyone',
).toLowerCase();

// ── OTHALA_IDENTITY_GROUPS ── ordered identity groups offered in the admin UI; 'admin' is always first and
// the default group is appended. The list only classifies and offers groups. Entry authorization is
// `metadata_admin.groups` on the identity (gate.ts); admin authority is the `metadata_admin.admin` marker
// (admin-auth.ts), so 'admin' in this list confers nothing.
function parseIdentityGroups(): string[] {
  const raw = process.env.OTHALA_IDENTITY_GROUPS ?? '';
  const parsed = raw
    .split(',')
    .map((g) => g.trim().toLowerCase())
    .filter(Boolean);

  const base = ['admin', ...parsed.filter((g) => g !== 'admin')];
  const withDefault = base.includes(defaultGroup)
    ? base
    : [...base, defaultGroup];
  return withDefault;
}

export const identityGroups: string[] = parseIdentityGroups();

// ── OTHALA_ADMIN_FRESHNESS_HOURS ── session-age window for the requireAdminSession step-up; default 1.
function parseAdminFreshnessHours(): number {
  const raw = process.env.OTHALA_ADMIN_FRESHNESS_HOURS;
  if (raw === undefined || raw.trim() === '') return 1;
  const n = parseInt(raw.trim(), 10);
  if (!Number.isFinite(n) || n < 0) {
    console.warn(
      `[othala/config] OTHALA_ADMIN_FRESHNESS_HOURS="${raw}" is not a valid non-negative integer; ` +
        'using default 1.',
    );
    return 1;
  }
  return n;
}

export const adminFreshnessHours: number = parseAdminFreshnessHours();

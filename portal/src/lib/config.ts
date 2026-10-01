// Portal env config: the only module that reads production env (plain-Node listen.mjs and otel.mjs cannot import TS).
// A required var throws at load in production and takes a dev default elsewhere. Fixed topology lives in constants.ts.

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

// ── OTHALA_PUBLIC_URL ── public issuer URL, no trailing slash; required in production.
export const publicUrl: string = requiredVar(
  'OTHALA_PUBLIC_URL',
  'http://localhost:4321',
).replace(/\/+$/, ''); // strip trailing slash regardless of source

// ── OTHALA_APEX ── registrable parent domain: the Kratos cookie domain and the WebAuthn RP id; required in production.
export const apex: string = requiredVar('OTHALA_APEX', 'localhost');

// ── OTHALA_INSTANCE_NAME ── brand name, TOTP issuer, WebAuthn RP name and SMTP From name; required in production.
export const instanceName: string = requiredVar('OTHALA_INSTANCE_NAME', 'Othala');

// ── OTHALA_SMTP_CONNECTION_URI ── one SMTP URI shared by Kratos courier and lib/mailer.ts
// (smtps://USER:PASS@host:465 or smtp://...:587, URL-encoded credentials); required in production.
export const smtpConnectionUri: string = requiredVar(
  'OTHALA_SMTP_CONNECTION_URI',
  'smtp://lab:lab@localhost:1025',
);

// ── OTHALA_CONTACT_RECIPIENT ── where the contact/request form delivers; required in production.
export const contactRecipient: string = requiredVar('OTHALA_CONTACT_RECIPIENT', 'admin@localhost');

// From: address for portal mail; always noreply@<OTHALA_APEX>, matching the kratos.yml courier.
export const smtpFromAddress: string = `noreply@${apex}`;

// ── Secrets ── read lazily so a missing one fails closed at use; production also requires both at load.
/** The value of secret `name`, or undefined when unset or blank. */
export function secret(name: 'CSRF_SECRET' | 'RECOVERY_GATE_SECRET'): string | undefined {
  const val = process.env[name];
  return val !== undefined && val.trim() !== '' ? val : undefined;
}

if (isProduction()) {
  for (const name of ['CSRF_SECRET', 'RECOVERY_GATE_SECRET'] as const) {
    if (secret(name) === undefined) {
      throw new Error(`[othala/config] Required env var ${name} is not set. Set it in the deployment environment and restart.`);
    }
  }
}

// ── <SLUG>_CLIENT_SECRET ── per-app OIDC secrets named by each manifest's client_id; the registrar resolves them here.
export function clientSecretEnv(): Record<string, string | undefined> {
  return process.env;
}

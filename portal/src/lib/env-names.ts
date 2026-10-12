// The env names othala answers to. An unknown OTHALA_* name or a retired name is an error that names the fix, so a
// deployment env cannot carry a setting that silently does nothing. Reads no environment; callers pass it in.

/** Every OTHALA_* name othala reads. Secrets, binds and `<SLUG>_CLIENT_SECRET` sit outside the prefix. */
export const KNOWN_OTHALA_NAMES: readonly string[] = Object.freeze([
  'OTHALA_PUBLIC_URL',
  'OTHALA_APEX',
  'OTHALA_INSTANCE_NAME',
  'OTHALA_CONTACT_RECIPIENT',
  'OTHALA_SMTP_CONNECTION_URI',
  'OTHALA_OTLP_ENDPOINT',
  'OTHALA_DEV_MOCK_GROUPS',
]);

const FIXED_TOPOLOGY = 'delete it; service hosts and ports are fixed (kratos:4433, kratos:4434, hydra:4445, othala:4431)';

/** Retired name to the fix an operator applies. */
export const RETIRED_NAMES: Readonly<Record<string, string>> = Object.freeze({
  OTHALA_DEFAULT_SCHEMA_ID: 'delete it; the identity schema is fixed',
  OTHALA_WEBAUTHN_RP_ID: 'delete it; the WebAuthn RP id is OTHALA_APEX',
  OTHALA_WEBAUTHN_RP_ORIGINS: 'delete it; the WebAuthn origin is OTHALA_PUBLIC_URL',
  OTHALA_SMTP_FROM_ADDRESS: 'delete it; mail comes from noreply@<OTHALA_APEX>',
  OTHALA_SITE_NAME: 'rename it OTHALA_INSTANCE_NAME',
  OTHALA_ADMIN_CONTACT: 'delete it; the dashboard names no contact',
  OTHALA_DEFAULT_GROUP: 'delete it; the default group is fixed at everyone',
  OTHALA_IDENTITY_GROUPS: 'delete it; identity groups are fixed',
  OTHALA_ADMIN_FRESHNESS_HOURS: 'delete it; the admin step-up window is fixed at 1h',
  OTHALA_HIBP_ENABLED: 'delete it; the breach check is always on',
  OTHALA_PASSWORD_MIN_LENGTH: 'delete it; the password minimum is fixed',
  OTHALA_CORS_ALLOWED_ORIGINS: 'delete it; Hydra allows OTHALA_PUBLIC_URL',
  OTHALA_PUBLIC_HOST: 'delete it; the edge uses OTHALA_PUBLIC_URL',
  OTHALA_OTLP_PROVIDER: 'delete it; set OTHALA_OTLP_ENDPOINT',
  OTHALA_OTLP_ENVIRONMENT: 'delete it; set OTHALA_OTLP_ENDPOINT',
  OTHALA_ADMIN_ENDPOINT_BEARER: 'delete it; the admin console replaced the bearer endpoint',
  OTLP_INGEST_TOKEN: 'delete it; set OTHALA_OTLP_ENDPOINT',
  KRATOS_PUBLIC_URL: FIXED_TOPOLOGY,
  HYDRA_PUBLIC_URL: FIXED_TOPOLOGY,
  KRATOS_ADMIN_URL: FIXED_TOPOLOGY,
  HYDRA_ADMIN_URL: FIXED_TOPOLOGY,
  KRATOS_ADMIN_TOKEN: 'delete it; the admin APIs take no bearer',
  HYDRA_ADMIN_TOKEN: 'delete it; the admin APIs take no bearer',
  KRATOS_PG_HOST: FIXED_TOPOLOGY,
  HYDRA_PG_HOST: FIXED_TOPOLOGY,
  KRATOS_ADMIN_HOST: FIXED_TOPOLOGY,
  CONSENT_HOST: FIXED_TOPOLOGY,
  PORTAL_LOGIN_URL: 'delete it; the login route is fixed',
  PORTAL_CONSENT_URL: 'delete it; the consent route is fixed',
  HYDRA_PAIRWISE_SALT: 'delete it; subjects are public',
  MANIFEST_DIR: 'delete it; content mounts at /etc/othala (CONTENT_DIR under astro dev)',
});

/** One error per retired or unknown name present in `env`, sorted by name; names only, never values. */
export function envNameErrors(env: Record<string, string | undefined>): string[] {
  const known = new Set(KNOWN_OTHALA_NAMES);
  const errors: string[] = [];
  for (const name of Object.keys(env).filter((n) => env[n] !== undefined).sort()) {
    if (Object.hasOwn(RETIRED_NAMES, name)) errors.push(`${name} is retired: ${RETIRED_NAMES[name]}`);
    else if (name.startsWith('OTHALA_') && !known.has(name)) {
      errors.push(`${name} is not an othala setting: delete it (othala reads ${KNOWN_OTHALA_NAMES.join(', ')})`);
    }
  }
  return errors;
}

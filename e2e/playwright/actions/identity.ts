/**
 * identity.ts — Kratos identity seed helpers (Kratos Admin API).
 *
 * Creates test identities via POST /admin/identities on the Kratos admin
 * endpoint (kratosAdminURL = http://kratos:4434 inside the compose net).
 *
 * BCRYPT SEEDING — Kratos v26.2.0 finding (documented in browser-test.mjs):
 *   Setting credentials.password.config.password (plaintext) in an admin
 *   identity POST is a no-op — Kratos ignores it. The password MUST be
 *   pre-hashed. This module uses a fixed bcrypt hash for the shared test
 *   password 'othala-testpass-2026' (cost 10, generated offline):
 *
 *     $ htpasswd -bnBC 10 '' othala-testpass-2026 | tr -d ':\n'
 *     $2y$10$6cMlVk/QqGweMGJ/gEDgQuu0B9o.sYwvVLDG6YBcXIDq9Z5yCBXPG
 *
 *   The hash is a compile-time constant here. On the carmine VM, the
 *   same constant is used — no runtime bcrypt library needed in the test
 *   runner (avoids the native module / compilation dependency).
 *
 *   Verification: `htpasswd -v` or any bcrypt checker:
 *     echo 'othala-testpass-2026' | bcrypt-verify '$2y$10$...'
 *
 * Identity schema: 'family' (the project's canonical schema_id).
 * Both MEMBER and ADMIN are seeded via this action in the fixtures before
 * any spec runs; the identities persist for the lifetime of the compose run.
 */

// Uses globalThis.fetch (Node 18+ / the playwright runner environment).

// Fixed bcrypt hash for 'othala-testpass-2026', cost=10.
// Generated with: htpasswd -bnBC 10 '' othala-testpass-2026 | tr -d ':\n'
// This is a public test fixture — NOT a production credential.
export const TEST_PASSWORD = 'othala-testpass-2026';
export const TEST_PASSWORD_BCRYPT =
  '$2y$10$6cMlVk/QqGweMGJ/gEDgQuu0B9o.sYwvVLDG6YBcXIDq9Z5yCBXPG';

export interface SeedOptions {
  email: string;
  username: string;
  displayName: string;
  /** metadata_admin.groups — controls access-keep group membership */
  groups: string[];
  kratosAdminURL: string;
}

export interface SeedResult {
  id: string;
  email: string;
}

/**
 * createIdentityWithPassword — POST a new Kratos identity with a bcrypt
 * hashed_password credential via the Kratos admin API.
 *
 * The Kratos admin API does NOT require authentication in the default
 * compose setup (the admin port 4434 is internal-only, not edge-exposed).
 *
 * Idempotency: if an identity with this email already exists (409), the
 * function returns the existing identity's id by doing a GET /admin/identities
 * with identifier_id filter. On any other error it throws.
 */
export async function createIdentityWithPassword(opts: SeedOptions): Promise<SeedResult> {
  const body = {
    schema_id: 'family',
    state: 'active',
    traits: {
      username: opts.username,
      email: opts.email,
      displayName: opts.displayName,
    },
    metadata_admin: {
      groups: opts.groups,
    },
    credentials: {
      password: {
        config: {
          hashed_password: TEST_PASSWORD_BCRYPT,
        },
      },
    },
  };

  const resp = await fetch(`${opts.kratosAdminURL}/admin/identities`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (resp.ok) {
    const data = (await resp.json()) as { id: string };
    return { id: data.id, email: opts.email };
  }

  if (resp.status === 409) {
    // Conflict: identity already exists. Look it up by credentials identifier.
    const listResp = await fetch(
      `${opts.kratosAdminURL}/admin/identities?credentials_identifier=${encodeURIComponent(opts.email)}`,
    );
    if (listResp.ok) {
      const list = (await listResp.json()) as Array<{ id: string }>;
      if (list.length > 0) {
        return { id: list[0].id, email: opts.email };
      }
    }
    throw new Error(`createIdentity 409 but lookup returned empty for ${opts.email}`);
  }

  const text = await resp.text().catch(() => '');
  throw new Error(
    `createIdentity failed for ${opts.email}: HTTP ${resp.status} — ${text.slice(0, 400)}`,
  );
}

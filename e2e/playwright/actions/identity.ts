/**
 * Kratos identity seed helpers (admin API). Admin-API plaintext passwords are ignored,
 * so identities carry a fixed bcrypt hash of TEST_PASSWORD (cost 10, generated offline).
 */

export const TEST_PASSWORD = 'othala-testpass-2026';
export const TEST_PASSWORD_BCRYPT =
  '$2b$10$6cMlVk/QqGweMGJ/gEDgQuu0B9o.sYwvVLDG6YBcXIDq9Z5yCBXPG';

export interface SeedOptions {
  email: string;
  username: string;
  displayName: string;
  /** metadata_admin.groups — controls access-<app> group membership */
  groups: string[];
  isAdmin?: boolean;
  kratosAdminURL: string;
}

export interface SeedResult {
  id: string;
  email: string;
}

export async function createIdentityWithPassword(opts: SeedOptions): Promise<SeedResult> {
  return seedIdentity(opts, true);
}

/** An identity with no password and no passkey: it can only sign in by emailed code. */
export async function createIdentityCodeOnly(opts: SeedOptions): Promise<SeedResult> {
  return seedIdentity(opts, false);
}

async function seedIdentity(opts: SeedOptions, withPassword: boolean): Promise<SeedResult> {
  const body = {
    schema_id: 'family',
    state: 'active',
    traits: {
      username: opts.username,
      email: opts.email,
      displayName: opts.displayName,
    },
    metadata_admin: {
      ...(opts.isAdmin === true ? { admin: true } : {}),
      groups: opts.groups,
    },
    ...(withPassword ? { credentials: { password: { config: { password: TEST_PASSWORD } } } } : {}),
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

/** Read an identity from the Kratos admin API (ground truth for "the effect"). */
export async function readIdentity(
  kratosAdminURL: string,
  id: string,
  credentials: string[] = [],
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> {
  const query = credentials.map((c) => `include_credential=${c}`).join('&');
  const resp = await fetch(`${kratosAdminURL}/admin/identities/${id}${query ? `?${query}` : ''}`);
  if (!resp.ok) throw new Error(`admin API identity read: HTTP ${resp.status} for ${id}`);
  return resp.json();
}

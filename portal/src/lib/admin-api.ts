// Kratos admin API wrappers for /admin/* SSR pages, via the Ory SDK IdentityApi. The admin port (http://kratos:4434)
// has no auth; network isolation is the gate, and KRATOS_ADMIN_TOKEN, if set, is forwarded as a bearer.
// The state flip uses RFC 6902 JSON-Patch. Non-2xx surfaces as a ResponseError for callers to render.

import {
  Configuration,
  IdentityApi,
  ResponseError,
  type CreateIdentityBody,
  type UpdateIdentityBody,
  type DeleteIdentityCredentialsTypeEnum,
  type GetIdentityIncludeCredentialEnum,
  type Session,
} from '@ory/client-fetch';
import type { Identity } from './types';
import { validateMetadataAdmin } from './metadata-admin';
import { revokeSubject } from './revoke';
import { defaultSchemaId } from './config';

function adminBase(): string {
  return process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';
}

function adminToken(): string {
  return process.env.KRATOS_ADMIN_TOKEN ?? '';
}

// The SDK sends the bearer on every request when `accessToken` is set, so configure it only when a token exists.
function identityApi(): IdentityApi {
  const token = adminToken();
  return new IdentityApi(
    new Configuration({
      basePath: adminBase(),
      ...(token ? { accessToken: token } : {}),
    }),
  );
}

export interface IdentityTraits {
  username: string;
  email: string;
  displayName?: string;
  recoveryEmail?: string;
}

export interface MetadataAdmin {
  groups?: string[];
  /** Per-app role overrides, keyed by client_id. */
  roles?: Record<string, string>;
  /**
   * Admin authority marker. Strict boolean; only set via the
   * Kratos admin API. Use patchAdminMarker for targeted grant/revoke so
   * groups/roles are never clobbered.
   */
  /**
   * Prerequisites the admin has marked set up for this person (names defined under requirements/ in MANIFEST_DIR).
   * Written only by patchPrerequisites, a targeted patch, so a groups/roles save never clobbers it.
   */
  prerequisites?: string[];
  admin?: boolean;
}

export interface CreateIdentityInput {
  traits: IdentityTraits;
  metadataAdmin: MetadataAdmin;
  schemaId?: string;
}

export interface UpdateIdentityInput {
  traits: IdentityTraits;
  metadataAdmin: MetadataAdmin;
}

// per_page=250 is the family-scale ceiling; the Link-header pagination is deliberately not followed.
export async function listIdentities(): Promise<Identity[]> {
  return identityApi().listIdentities({ perPage: 250 });
}

// Credential types the admin API returns. 'lookup_secret' must be included or backup codes are never fetched (the
// admin page keys its badge on it and updateIdentity would drop it on a PUT round-trip).
export const INCLUDED_CREDENTIALS: GetIdentityIncludeCredentialEnum[] = ['password', 'webauthn', 'passkey', 'totp', 'lookup_secret'];

export async function getIdentity(id: string): Promise<Identity> {
  return identityApi().getIdentity({
    id,
    includeCredential: INCLUDED_CREDENTIALS,
  });
}

export async function createIdentity(input: CreateIdentityInput): Promise<Identity> {
  // J1: enforce the metadata_admin shape here; the Kratos schema validates only `traits`, so a typo would be stored.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const createIdentityBody: CreateIdentityBody = {
    schema_id: input.schemaId ?? defaultSchemaId,
    traits: input.traits,
    metadata_admin: validated,
  };
  return identityApi().createIdentity({ createIdentityBody });
}

/** Replace traits + metadata_admin via PUT (simpler than JSON-Patch when both are written together). */
export async function updateIdentity(id: string, input: UpdateIdentityInput): Promise<Identity> {
  // J1: same metadata_admin enforcement as createIdentity.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const api = identityApi();
  const current = await api.getIdentity({
    id,
    includeCredential: INCLUDED_CREDENTIALS,
  });
  const updateIdentityBody: UpdateIdentityBody = {
    schema_id: current.schema_id,
    state: current.state ?? 'active',
    traits: input.traits,
    metadata_admin: validated,
  };
  return api.updateIdentity({ id, updateIdentityBody });
}

export async function deleteIdentity(id: string): Promise<void> {
  await identityApi().deleteIdentity({ id });
}

/** Revoke one Kratos session by id; a 404 (already gone) is success, anything else throws. */
export async function revokeSession(id: string): Promise<void> {
  try {
    await identityApi().disableSession({ id });
  } catch (e) {
    if (e instanceof ResponseError && e.response.status === 404) return;
    throw e;
  }
}

/** Active Kratos sessions of an identity. A 404 means it has none left. */
export async function listSessions(id: string): Promise<Session[]> {
  try {
    return await identityApi().listIdentitySessions({ id, active: true, perPage: 1000 });
  } catch (e) {
    if (e instanceof ResponseError && e.response.status === 404) return [];
    throw e;
  }
}

/** Mark the identity inactive AND run the full revocation fan-out (revokeSubject with deactivate:true); a Kratos-sessions failure aborts with a RevokeError. */
export async function deactivateIdentity(id: string): Promise<void> {
  await revokeSubject(id, { deactivate: true });
}

/** Restore an inactive identity to active. No revokeSubject: the fan-out ran at deactivate and the user signs in fresh. */
export async function reactivateIdentity(id: string): Promise<void> {
  const patch = [{ op: 'replace' as const, path: '/state', value: 'active' }];
  await identityApi().patchIdentity({ id, jsonPatch: patch });
}

/**
 * Targeted JSON-Patch of the `metadata_admin.admin` marker, leaving groups and roles untouched. Grant sets admin=true
 * (an add of /metadata_admin when absent, else add/replace of the key); revoke removes the key and treats an absent
 * one as success. No validateMetadataAdmin: only one boolean key is touched.
 */
export async function patchAdminMarker(id: string, grant: boolean): Promise<void> {
  const api = identityApi();
  if (grant) {
    // Kratos does not auto-vivify /metadata_admin, so pre-fetch to choose the ops.
    const current = await api.getIdentity({ id });
    const hasMeta = current.metadata_admin != null && typeof current.metadata_admin === 'object';
    const patch: Array<{ op: 'add' | 'replace' | 'remove'; path: string; value?: unknown }> = [];
    if (!hasMeta) {
      patch.push({ op: 'add', path: '/metadata_admin', value: { admin: true } });
    } else {
      // metadata_admin exists: add or replace the key.
      const meta = current.metadata_admin as Record<string, unknown>;
      if ('admin' in meta) {
        patch.push({ op: 'replace', path: '/metadata_admin/admin', value: true });
      } else {
        patch.push({ op: 'add', path: '/metadata_admin/admin', value: true });
      }
    }
    await api.patchIdentity({ id, jsonPatch: patch });
  } else {
    // Kratos may error on removing a missing path, so check first.
    const current = await api.getIdentity({ id });
    const meta = current.metadata_admin as Record<string, unknown> | undefined;
    if (!meta || !('admin' in meta)) {
      // Already absent.
      return;
    }
    await api.patchIdentity({ id, jsonPatch: [{ op: 'remove', path: '/metadata_admin/admin' }] });
  }
}


/**
 * Targeted JSON-Patch of `metadata_admin.prerequisites`, leaving groups, roles and the admin marker untouched. The list
 * is validated by validateMetadataAdmin (a duplicate throws) and written whole (add when absent, else replace); an empty
 * list removes the key.
 */
export async function patchPrerequisites(id: string, names: string[]): Promise<void> {
  const prerequisites = validateMetadataAdmin({ prerequisites: names }).prerequisites ?? [];
  const api = identityApi();
  const current = await api.getIdentity({ id });
  const meta = current.metadata_admin as Record<string, unknown> | null | undefined;
  const hasMeta = meta != null && typeof meta === 'object';
  const hasKey = hasMeta && 'prerequisites' in meta;
  type Op = { op: 'add' | 'replace' | 'remove'; path: string; value?: unknown };
  let patch: Op[];
  if (prerequisites.length === 0) {
    if (!hasKey) return;
    patch = [{ op: 'remove', path: '/metadata_admin/prerequisites' }];
  } else if (!hasMeta) {
    patch = [{ op: 'add', path: '/metadata_admin', value: { prerequisites } }];
  } else {
    patch = [{ op: hasKey ? 'replace' : 'add', path: '/metadata_admin/prerequisites', value: prerequisites }];
  }
  await api.patchIdentity({ id, jsonPatch: patch });
}

/**
 * Credential types admin eviction may delete. `password` is excluded: Kratos rejects DELETE on it and it is not a
 * lost-device factor. `passkey` is excluded because Kratos v26.2.0 deleteIdentityCredentials 400s on it; passkeys are
 * removed per credential at /auth/settings (p-eviction.spec.ts P3). Included: webauthn, totp and lookup_secret.
 */
export const EVICTABLE_CREDENTIAL_TYPES = new Set<string>([
  'webauthn',
  'totp',
  'lookup_secret',
]);

/**
 * Delete ALL credentials of `type` (DELETE /admin/identities/{id}/credentials/{type}): Kratos has no per-instance
 * removal, so the user re-enrolls via the recovery URL from the same admin action. Not valid for passkey. A 404 (type
 * not enrolled) is success; other non-2xx statuses throw.
 */
export async function deleteCredential(
  identityId: string,
  type: string,
): Promise<void> {
  // Only eviction-relevant types (Kratos rejects password).
  if (!EVICTABLE_CREDENTIAL_TYPES.has(type)) {
    throw new Error(`deleteCredential: '${type}' is not an evictable credential type`);
  }
  try {
    await identityApi().deleteIdentityCredentials({
      id: identityId,
      type: type as DeleteIdentityCredentialsTypeEnum,
    });
  } catch (err: unknown) {
    // 404: type not present, nothing to evict.
    if (
      err != null &&
      typeof err === 'object' &&
      'response' in err &&
      (err as { response: { status: number } }).response?.status === 404
    ) {
      return;
    }
    throw err;
  }
}

export interface RecoveryLink {
  recovery_link: string;
  /** The short numeric code Kratos generates (used alongside recovery_link). */
  recovery_code: string;
  expires_at: string;
}

/** One-shot recovery code + link the admin shares out-of-band (createRecoveryCodeForIdentity). The SDK returns `expires_at` as a Date; coerce to a string. */
export async function getRecoveryLink(id: string, expiresIn = '1h'): Promise<RecoveryLink> {
  const link = await identityApi().createRecoveryCodeForIdentity({
    createRecoveryCodeForIdentityBody: { identity_id: id, expires_in: expiresIn },
  });
  return {
    recovery_link: link.recovery_link,
    recovery_code: link.recovery_code,
    expires_at: link.expires_at instanceof Date ? link.expires_at.toISOString() : String(link.expires_at ?? ''),
  };
}

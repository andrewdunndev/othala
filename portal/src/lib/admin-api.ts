// Kratos admin API wrappers used by /admin/* SSR pages.
//
// The portal runs on the host in the same pod network as Kratos, so the
// admin port (4434) is reachable directly at `http://kratos:4434`. The
// admin port has no auth in default Kratos posture; network isolation
// is the gate. KRATOS_ADMIN_TOKEN is reserved for a future Oathkeeper
// (or equivalent) interposer; if set, it's forwarded as Authorization
// Bearer. If unset, the Authorization header is omitted.
//
// Calls go through the Ory SDK's IdentityApi (`@ory/client-fetch`,
// fetch-native). JSON-Patch is still used for the state flip in
// deactivateIdentity because Kratos's PATCH endpoint expects RFC 6902
// patches, not partial documents. The SDK surfaces a ResponseError on
// non-2xx; callers catch and render an error notice.

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

// Behaviour-preserving auth: the SDK injects the bearer on every request
// when `accessToken` is configured. The legacy raw-fetch code only added
// Authorization when KRATOS_ADMIN_TOKEN was set, so guard the option:
// configure accessToken only when a token is present.
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

// per_page=250 is the family-scale ceiling for listIdentities. H9 from
// the adversarial review: the Kratos identities endpoint paginates via
// Link header; this call does NOT follow it. At family scale (5-25
// identities) this is fine and the truncation never bites.
//
// If the estate ever grows bot/service identities, mirror the
// pagination loop pattern and follow `next` Link headers until exhausted.
// Today it is deliberately unimplemented.
export async function listIdentities(): Promise<Identity[]> {
  return identityApi().listIdentities({ perPage: 250 });
}

// Credential types whose config the admin API returns. 'lookup_secret' must be
// included or the backup-codes credential is never fetched: the admin user page
// keys its badge on it, and updateIdentity would drop it on a PUT round-trip.
export const INCLUDED_CREDENTIALS: GetIdentityIncludeCredentialEnum[] = ['password', 'webauthn', 'passkey', 'totp', 'lookup_secret'];

export async function getIdentity(id: string): Promise<Identity> {
  return identityApi().getIdentity({
    id,
    includeCredential: INCLUDED_CREDENTIALS,
  });
}

export async function createIdentity(input: CreateIdentityInput): Promise<Identity> {
  // J1: enforce metadata_admin shape at the application layer. Kratos's
  // identity-schema only validates `traits`; metadata_admin is opaque to
  // the schema validator. A typo (grupos instead of groups) would
  // otherwise be silently accepted and stored.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const createIdentityBody: CreateIdentityBody = {
    schema_id: input.schemaId ?? defaultSchemaId,
    traits: input.traits,
    metadata_admin: validated,
  };
  return identityApi().createIdentity({ createIdentityBody });
}

/**
 * Replace traits + metadata_admin via PUT (Kratos accepts a full identity
 * body). PATCH/JSON-Patch is the alternative; PUT is simpler when both
 * blocks are written together, which is the admin-UI common case.
 */
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

/**
 * Revoke one Kratos session by id (DELETE /admin/sessions/{id}). A 404 means
 * the session is already gone, which is the postcondition; anything else throws.
 */
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

/**
 * Mark the identity inactive AND run the full revocation fan-out.
 *
 * deactivate is the only trigger that runs step 1 (state -> inactive)
 * before the rest; revokeSubject({deactivate:true}) does step 1 then 2-4:
 * Kratos sessions, Hydra login + consent revoke. A step 2 failure aborts
 * (prescriptive RevokeError). This completes the old patch+delete-sessions pair, which left
 * the Hydra remembered login and the granted consent open after a "deactivate".
 */
export async function deactivateIdentity(id: string): Promise<void> {
  await revokeSubject(id, { deactivate: true });
}

/**
 * Restore an inactive identity to active state.
 *
 * This is the inverse of deactivateIdentity. Unlike deactivate, reactivate
 * does NOT need a revocation fan-out: the sessions and consent grants were
 * already cleared when the identity was deactivated. The user will need to
 * log in fresh after reactivation — that is the correct postcondition.
 *
 * No revokeSubject call here: the fan-out ran at deactivate time and the
 * identity has had no live sessions since. Calling it again would be a no-op
 * (Kratos 404 on delete-sessions) and would add unnecessary Hydra churn.
 */
export async function reactivateIdentity(id: string): Promise<void> {
  const patch = [{ op: 'replace' as const, path: '/state', value: 'active' }];
  await identityApi().patchIdentity({ id, jsonPatch: patch });
}

/**
 * Targeted patch of the `metadata_admin.admin` marker.
 *
 * Uses JSON Patch (RFC 6902) against the Kratos PATCH endpoint so groups
 * and roles are never touched. Grant sets admin=true; revoke removes the key.
 *
 * The Kratos PATCH body must include the full path under /metadata_admin.
 * If metadata_admin is absent entirely, Kratos rejects a /metadata_admin/admin
 * add directly; we first add /metadata_admin as {} then add the key. Grant
 * therefore sends a two-op patch that is idempotent on repeated calls (add
 * with test-or-add semantics). Revoke sends a single remove op; a 404-style
 * "path not found" error from Kratos is treated as success (already absent).
 *
 * This does NOT call validateMetadataAdmin because we only touch a single
 * boolean key — the other fields are untouched by the patch.
 */
export async function patchAdminMarker(id: string, grant: boolean): Promise<void> {
  const api = identityApi();
  if (grant) {
    // Ensure metadata_admin exists, then set admin=true. Use a two-op patch:
    // first add /metadata_admin if missing (the Kratos SDK patchIdentity call
    // accepts a standard RFC 6902 array). If the path already exists the add
    // for /metadata_admin will conflict, so we use a conditional approach:
    // just send add for /metadata_admin/admin and rely on Kratos creating
    // intermediate nodes. In practice, Kratos does NOT auto-vivify; we do a
    // pre-fetch to decide which ops to send.
    const current = await api.getIdentity({ id });
    const hasMeta = current.metadata_admin != null && typeof current.metadata_admin === 'object';
    const patch: Array<{ op: 'add' | 'replace' | 'remove'; path: string; value?: unknown }> = [];
    if (!hasMeta) {
      patch.push({ op: 'add', path: '/metadata_admin', value: { admin: true } });
    } else {
      // metadata_admin exists — add or replace the admin key.
      const meta = current.metadata_admin as Record<string, unknown>;
      if ('admin' in meta) {
        patch.push({ op: 'replace', path: '/metadata_admin/admin', value: true });
      } else {
        patch.push({ op: 'add', path: '/metadata_admin/admin', value: true });
      }
    }
    await api.patchIdentity({ id, jsonPatch: patch });
  } else {
    // Remove the admin key. If metadata_admin or admin is absent this is a
    // no-op at the semantic level; Kratos may return an error for a remove on
    // a missing path, so we check first.
    const current = await api.getIdentity({ id });
    const meta = current.metadata_admin as Record<string, unknown> | undefined;
    if (!meta || !('admin' in meta)) {
      // Already absent — nothing to do.
      return;
    }
    await api.patchIdentity({ id, jsonPatch: [{ op: 'remove', path: '/metadata_admin/admin' }] });
  }
}

// ── Credential eviction ───────────────────────────────────────────────────────

/**
 * Allowed credential types for admin eviction via the portal UI.
 *
 * `password` is intentionally excluded: Kratos rejects DELETE on password and
 * it is not a lost-device eviction factor (the attacker can't enrol a new
 * password without knowing the current one and we do not expose that surface).
 *
 * `passkey` is excluded too, but for a different reason: Kratos v26.2.0
 * identity/handler.go deleteIdentityCredentials has no passkey case and
 * unconditionally 400s ("Credentials type passkey cannot be deleted.",
 * confirmed against the pinned tag and master — see issue #10). The
 * canonical passkey eviction is self-service per-credential removal at
 * /auth/settings (proven by e2e/playwright/tests/p-eviction.spec.ts P3).
 *
 * Eviction-relevant types: webauthn (a possession factor a thief could have
 * enrolled), totp and lookup_secret (codes stored on or extracted from a
 * lost device).
 */
export const EVICTABLE_CREDENTIAL_TYPES = new Set<string>([
  'webauthn',
  'totp',
  'lookup_secret',
]);

/**
 * Delete ALL credentials of `type` for an identity.
 *
 * This is the lost-device eviction primitive. Kratos does not expose per-instance
 * removal on the admin API — the unit of deletion is the credential type.
 * Removing the type evicts every registered credential of that kind; the
 * legitimate user re-enrolls via the recovery/enrollment URL issued in the
 * same admin action. NOT valid for passkey — see EVICTABLE_CREDENTIAL_TYPES.
 *
 * 404 from Kratos is treated as success (type not enrolled — nothing to evict).
 * All other non-2xx statuses propagate as errors to the caller.
 *
 * Endpoint: DELETE /admin/identities/{id}/credentials/{type}
 *
 * NOTE: The exact endpoint shape and 404 behaviour need live gate validation
 * against the deployed Kratos version. Confirm via the e2e harness or manual
 * curl before relying in production.
 */
export async function deleteCredential(
  identityId: string,
  type: string,
): Promise<void> {
  // Only allow eviction-relevant types (not password — Kratos rejects it).
  if (!EVICTABLE_CREDENTIAL_TYPES.has(type)) {
    throw new Error(`deleteCredential: '${type}' is not an evictable credential type`);
  }
  try {
    await identityApi().deleteIdentityCredentials({
      id: identityId,
      type: type as DeleteIdentityCredentialsTypeEnum,
    });
  } catch (err: unknown) {
    // Tolerate 404: type not present is a no-op for eviction purposes.
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

/**
 * One-shot recovery code + link the admin shares out-of-band.
 *
 * Uses `createRecoveryCodeForIdentity` (POST /admin/recovery/code, Kratos
 * v26.2.0+). The response includes both a `recovery_link` (URL to the
 * recovery UI with an empty code field) and a `recovery_code` (the
 * short numeric code Kratos emails or the admin can share directly).
 *
 * The SDK deserialises `expires_at` as a Date object. Guard the coercion:
 * call toISOString() only when the value is actually a Date, fall back to
 * String() for any other wire shape so the caller always gets a string.
 */
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

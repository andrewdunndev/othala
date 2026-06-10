// Kratos admin API wrappers used by /admin/* SSR pages.
//
// The portal runs on carmine in the same pod network as Kratos, so the
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
  type CreateIdentityBody,
  type UpdateIdentityBody,
  type DeleteIdentityCredentialsTypeEnum,
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
// pagination loop pattern from gitlab.com/dunn.dev/kratos-ldap and
// follow `next` Link headers until exhausted. Today it's deliberately
// unimplemented.
export async function listIdentities(): Promise<Identity[]> {
  return identityApi().listIdentities({ perPage: 250 });
}

export async function getIdentity(id: string): Promise<Identity> {
  return identityApi().getIdentity({
    id,
    // 'lookup_secret' must be included or the backup-codes credential is never
    // fetched: the admin user page keyed the badge on it and would always show
    // "not enrolled" without this entry.
    includeCredential: ['password', 'webauthn', 'passkey', 'totp', 'lookup_secret'],
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
    // Keep consistent with getIdentity: 'lookup_secret' must be present so
    // updateIdentity preserves the current backup-codes credential rather
    // than losing it on a PUT round-trip.
    includeCredential: ['password', 'webauthn', 'passkey', 'totp', 'lookup_secret'],
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
 * Mark the identity inactive AND run the full revocation fan-out.
 *
 * deactivate is the only trigger that runs step 1 (state -> inactive)
 * before the rest; revokeSubject({deactivate:true}) does step 1 then 2-5:
 * Kratos sessions, Hydra login + consent revoke, best-effort LDAP bind-cache
 * flush. Step 2 failure aborts (prescriptive RevokeError); step 5 is
 * best-effort. This completes the old patch+delete-sessions pair, which left
 * the Hydra 24h login window and the granted consent open after a "deactivate".
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

// ── Credential eviction ───────────────────────────────────────────────────────

/**
 * Allowed credential types for admin eviction via the portal UI.
 *
 * `password` is intentionally excluded: Kratos rejects DELETE on password and
 * it is not a lost-device eviction factor (the attacker can't enrol a new
 * password without knowing the current one and we do not expose that surface).
 *
 * Eviction-relevant types: passkey and webauthn (possession factors a thief
 * could have enrolled), totp and lookup_secret (codes stored on or extracted
 * from a lost device).
 */
export const EVICTABLE_CREDENTIAL_TYPES = new Set<string>([
  'passkey',
  'webauthn',
  'totp',
  'lookup_secret',
]);

/**
 * Delete ALL credentials of `type` for an identity.
 *
 * This is the lost-device eviction primitive. Kratos does not expose per-instance
 * passkey removal on the admin API — the unit of deletion is the credential type.
 * Removing the type evicts every registered credential of that kind; the
 * legitimate user re-enrolls via the recovery/enrollment URL issued in the
 * same admin action.
 *
 * 404 from Kratos is treated as success (type not enrolled — nothing to evict).
 * All other non-2xx statuses propagate as errors to the caller.
 *
 * Endpoint: DELETE /admin/identities/{id}/credentials/{type}
 *
 * NOTE: The exact endpoint shape and 404 behaviour need live gate validation
 * against the deployed Kratos version. Confirm via `make dag-e2e` or manual
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
  expires_at: string;
}

/** One-shot enrollment / recovery URL the admin shares out-of-band. */
export async function getRecoveryLink(id: string, expiresIn = '1h'): Promise<RecoveryLink> {
  const link = await identityApi().createRecoveryLinkForIdentity({
    createRecoveryLinkForIdentityBody: { identity_id: id, expires_in: expiresIn },
  });
  // The SDK types expires_at as optional; the portal contract (and an
  // existing test) treats it as a present string. Coerce at the boundary.
  return {
    recovery_link: link.recovery_link,
    expires_at: String(link.expires_at ?? ''),
  };
}

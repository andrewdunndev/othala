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
  type JsonPatch,
} from '@ory/client-fetch';
import type { Identity } from './types';
import { validateMetadataAdmin } from './metadata-admin';

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
// pagination loop pattern in ldap-bridge/kratos/client.go:166-220 and
// follow `next` Link headers until exhausted. Today it's deliberately
// unimplemented.
export async function listIdentities(): Promise<Identity[]> {
  return identityApi().listIdentities({ perPage: 250 });
}

export async function getIdentity(id: string): Promise<Identity> {
  return identityApi().getIdentity({
    id,
    includeCredential: ['password', 'webauthn', 'passkey', 'totp'],
  });
}

export async function createIdentity(input: CreateIdentityInput): Promise<Identity> {
  // J1: enforce metadata_admin shape at the application layer. Kratos's
  // identity-schema only validates `traits`; metadata_admin is opaque to
  // the schema validator. A typo (grupos instead of groups) would
  // otherwise be silently accepted and stored.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const createIdentityBody: CreateIdentityBody = {
    schema_id: input.schemaId ?? 'family',
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
    includeCredential: ['password', 'webauthn', 'passkey', 'totp'],
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

/** Mark the identity inactive without removing it; revokes existing sessions. */
export async function deactivateIdentity(id: string): Promise<void> {
  const api = identityApi();
  const patchIdentityBody: Array<JsonPatch> = [
    { op: 'replace', path: '/state', value: 'inactive' },
  ];
  await api.patchIdentity({ id, patchIdentityBody });
  // Session revocation is the second half of deactivation. If it fails
  // (500, network error, etc.) and we don't await it, the identity stays
  // in a half-deactivated state — marked inactive but still holding
  // active sessions. Awaiting surfaces the failure so the caller can
  // re-run / alert.
  await api.deleteIdentitySessions({ id });
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

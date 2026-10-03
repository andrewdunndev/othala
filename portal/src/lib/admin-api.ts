// The Kratos admin port has no auth; network isolation is the gate.

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
import { passkeyCredentialIds, pruneNames, readPasskeyNames } from './passkey-names';
import { revokeSubject } from './revoke';
import { KRATOS_ADMIN_URL } from './constants';
import { timeoutFetch } from './ory-fetch';

function identityApi(): IdentityApi {
  return new IdentityApi(new Configuration({ basePath: KRATOS_ADMIN_URL, fetchApi: timeoutFetch() }));
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
  prerequisites?: string[];
  passkeyNames?: Record<string, string>;
  admin?: boolean;
}

export interface CreateIdentityInput {
  traits: IdentityTraits;
  metadataAdmin: MetadataAdmin;
}

export interface UpdateIdentityInput {
  traits: IdentityTraits;
  metadataAdmin: MetadataAdmin;
}

// One page of 250 is the family-scale ceiling; later pages are not fetched.
export async function listIdentities(): Promise<Identity[]> {
  return identityApi().listIdentities({ perPage: 250 });
}

// Without lookup_secret, backup codes are never fetched and a PUT round-trip would drop them.
export const INCLUDED_CREDENTIALS: GetIdentityIncludeCredentialEnum[] = ['password', 'webauthn', 'passkey', 'totp', 'lookup_secret'];

export async function getIdentity(id: string): Promise<Identity> {
  return identityApi().getIdentity({
    id,
    includeCredential: INCLUDED_CREDENTIALS,
  });
}

export async function createIdentity(input: CreateIdentityInput): Promise<Identity> {
  // The Kratos schema validates only traits, so a typo in metadata_admin would be stored.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  // No schema_id: Kratos applies default_schema_id. The SDK types the field as required, hence the cast.
  const createIdentityBody = {
    traits: input.traits,
    metadata_admin: validated,
    // Kratos keeps a pre-declared address that matches the trait, so the person is verified without a mail round trip.
    verifiable_addresses: [
      {
        value: input.traits.email.toLowerCase(),
        via: 'email',
        verified: true,
        status: 'completed',
      },
    ],
  } as CreateIdentityBody;
  return identityApi().createIdentity({ createIdentityBody });
}

export async function updateIdentity(id: string, input: UpdateIdentityInput): Promise<Identity> {
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

export async function revokeSession(id: string): Promise<void> {
  try {
    await identityApi().disableSession({ id });
  } catch (e) {
    if (e instanceof ResponseError && e.response.status === 404) return;
    throw e;
  }
}

export async function listSessions(id: string): Promise<Session[]> {
  try {
    return await identityApi().listIdentitySessions({ id, active: true, perPage: 1000 });
  } catch (e) {
    if (e instanceof ResponseError && e.response.status === 404) return [];
    throw e;
  }
}

export async function deactivateIdentity(id: string): Promise<void> {
  await revokeSubject(id, { deactivate: true });
}

export async function reactivateIdentity(id: string): Promise<void> {
  const patch = [{ op: 'replace' as const, path: '/state', value: 'active' }];
  await identityApi().patchIdentity({ id, jsonPatch: patch });
}

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
      return;
    }
    await api.patchIdentity({ id, jsonPatch: [{ op: 'remove', path: '/metadata_admin/admin' }] });
  }
}

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

type PatchOp = { op: 'add' | 'replace' | 'remove'; path: string; value?: unknown };

export async function patchPasskeyName(id: string, credentialId: string, name: string): Promise<void> {
  const names = validateMetadataAdmin({ passkeyNames: { [credentialId]: name } }).passkeyNames ?? {};
  const api = identityApi();
  const current = await api.getIdentity({ id });
  const meta = current.metadata_admin as Record<string, unknown> | null | undefined;
  let patch: PatchOp[];
  if (meta == null || typeof meta !== 'object') {
    patch = [{ op: 'add', path: '/metadata_admin', value: { passkeyNames: names } }];
  } else if (!('passkeyNames' in meta)) {
    patch = [{ op: 'add', path: '/metadata_admin/passkeyNames', value: names }];
  } else {
    patch = [{ op: 'add', path: `/metadata_admin/passkeyNames/${credentialId}`, value: names[credentialId] }];
  }
  await api.patchIdentity({ id, jsonPatch: patch });
}

export async function prunePasskeyNames(id: string): Promise<number> {
  const api = identityApi();
  const current = await api.getIdentity({ id, includeCredential: INCLUDED_CREDENTIALS });
  const names = readPasskeyNames(current.metadata_admin);
  const kept = pruneNames(names, passkeyCredentialIds(current as unknown as Identity));
  if (kept === null) return 0;
  const patch: PatchOp[] =
    Object.keys(kept).length === 0
      ? [{ op: 'remove', path: '/metadata_admin/passkeyNames' }]
      : [{ op: 'replace', path: '/metadata_admin/passkeyNames', value: kept }];
  await api.patchIdentity({ id, jsonPatch: patch });
  return Object.keys(names).length - Object.keys(kept).length;
}

// Kratos refuses to admin-delete password and passkey credentials.
export const EVICTABLE_CREDENTIAL_TYPES = new Set<string>([
  'webauthn',
  'totp',
  'lookup_secret',
]);

/** Kratos has no per-instance removal: this deletes every credential of the type. */
export async function deleteCredential(
  identityId: string,
  type: string,
): Promise<void> {
  if (!EVICTABLE_CREDENTIAL_TYPES.has(type)) {
    throw new Error(`deleteCredential: '${type}' is not an evictable credential type`);
  }
  try {
    await identityApi().deleteIdentityCredentials({
      id: identityId,
      type: type as DeleteIdentityCredentialsTypeEnum,
    });
  } catch (err: unknown) {
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
  recovery_code: string;
  expires_at: string;
}

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

export interface AddressPayload {
  value: string;
  via: string;
  verified: boolean;
  status: string;
}

/** Kratos's PUT drops verifiable_addresses, so vouching goes through PATCH. */
export function emailVerifiedPatch(
  identity: Pick<Identity, 'traits' | 'verifiable_addresses'>,
): Array<{ op: 'add' | 'replace'; path: string; value: unknown }> {
  const email = String((identity.traits as { email?: unknown } | undefined)?.email ?? '').toLowerCase();
  const existing = identity.verifiable_addresses ?? [];
  const own = existing.findIndex((a) => String(a.via) === 'email' && a.value.toLowerCase() === email);
  const vouched: AddressPayload = { value: email, via: 'email', verified: true, status: 'completed' };
  if (own === -1) {
    return [
      existing.length
        ? { op: 'add', path: '/verifiable_addresses/-', value: vouched }
        : { op: 'add', path: '/verifiable_addresses', value: [vouched] },
    ];
  }
  return [{ op: 'replace', path: `/verifiable_addresses/${own}`, value: vouched }];
}

/** Kratos keeps a verifiable address only while it equals the email trait, so an email changed after this read never ends up verified. */
export async function markEmailVerified(id: string, displayed: string): Promise<boolean> {
  const api = identityApi();
  const current = await api.getIdentity({ id });
  if (!displayed || current.traits?.email !== displayed) return false;
  await api.patchIdentity({ id, jsonPatch: emailVerifiedPatch(current) as never });
  return true;
}

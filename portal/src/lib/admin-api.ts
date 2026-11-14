// The Kratos admin port has no auth; network isolation is the gate.

import type {
  CreateIdentityBody,
  UpdateIdentityBody,
  DeleteIdentityCredentialsTypeEnum,
  GetIdentityIncludeCredentialEnum,
  Session,
} from '@ory/client-fetch';
import type { Identity } from './types';
import { validateMetadataAdmin } from './metadata-admin';
import { readAvatar, type Avatar } from './avatar';
import { passkeyCredentialIds, pruneNames, readPasskeyNames } from './passkey-names';
import { pageTokens, revokeSubject } from './revoke';
import { readGrantsMarker, type GrantsMarker } from './grant-reconcile';
import { isNotFound, kratosAdmin } from './ory-fetch';

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
  avatar?: Avatar;
  /** The credential fingerprint the last grant revoke covered (see grant-reconcile.ts). */
  grants_revoked?: { fp: string; at: string };
}

export interface CreateIdentityInput {
  traits: IdentityTraits;
  metadataAdmin: MetadataAdmin;
}

export interface UpdateIdentityInput {
  traits: IdentityTraits;
  /** What the caller edits. Every other mark is carried from the identity read inside the update. */
  metadataAdmin: Pick<MetadataAdmin, 'groups' | 'roles'>;
}

/** Every identity: callers count and revoke across the whole set, so a page is never the end of it. */
export async function listIdentities(): Promise<Identity[]> {
  const api = kratosAdmin();
  const all: Identity[] = [];
  const next = pageTokens();
  let pageToken: string | undefined;
  do {
    const page = await api.listIdentitiesRaw({ pageSize: 250, pageToken });
    all.push(...(await page.value()));
    pageToken = next(page.raw.headers);
  } while (pageToken);
  return all;
}

// Without lookup_secret, backup codes are never fetched and a PUT round-trip would drop them.
export const INCLUDED_CREDENTIALS: GetIdentityIncludeCredentialEnum[] = ['password', 'webauthn', 'passkey', 'totp', 'lookup_secret'];

export async function getIdentity(id: string): Promise<Identity> {
  return kratosAdmin().getIdentity({
    id,
    includeCredential: INCLUDED_CREDENTIALS,
  });
}

/** Every identity with the five settings credential types included, fully paginated: the sweep's one read. */
export async function listIdentitiesWithCredentials(): Promise<Identity[]> {
  const api = kratosAdmin();
  const all: Identity[] = [];
  const next = pageTokens();
  let pageToken: string | undefined;
  do {
    const page = await api.listIdentitiesRaw({ pageSize: 250, pageToken, includeCredential: INCLUDED_CREDENTIALS });
    all.push(...(await page.value()));
    pageToken = next(page.raw.headers);
  } while (pageToken);
  return all;
}

export async function getIdentityWithoutCredentials(id: string): Promise<Identity> {
  return kratosAdmin().getIdentity({ id });
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
  return kratosAdmin().createIdentity({ createIdentityBody });
}

export async function updateIdentity(id: string, input: UpdateIdentityInput): Promise<Identity> {
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const api = kratosAdmin();
  const current = await api.getIdentity({
    id,
    includeCredential: INCLUDED_CREDENTIALS,
  });
  const held = current.metadata_admin as MetadataAdmin | null | undefined;
  // The marks no whole-form save edits come from this read, never the caller's earlier one, so a revoke that landed in between is not undone.
  const carried = validateMetadataAdmin({
    ...(held?.admin === true ? { admin: true } : {}),
    ...(held?.prerequisites?.length ? { prerequisites: held.prerequisites } : {}),
    ...(held?.passkeyNames && Object.keys(held.passkeyNames).length ? { passkeyNames: held.passkeyNames } : {}),
    avatar: readAvatar(held),
    grants_revoked: readGrantsMarker(held),
  });
  const updateIdentityBody: UpdateIdentityBody = {
    schema_id: current.schema_id,
    state: current.state ?? 'active',
    traits: input.traits,
    metadata_admin: { ...carried, ...validated },
  };
  return api.updateIdentity({ id, updateIdentityBody });
}

export async function deleteIdentity(id: string): Promise<void> {
  await kratosAdmin().deleteIdentity({ id });
}

export async function revokeSession(id: string): Promise<void> {
  try {
    await kratosAdmin().disableSession({ id });
  } catch (e) {
    if (isNotFound(e)) return;
    throw e;
  }
}

export async function listSessions(id: string): Promise<Session[]> {
  try {
    return await kratosAdmin().listIdentitySessions({ id, active: true, perPage: 1000 });
  } catch (e) {
    if (isNotFound(e)) return [];
    throw e;
  }
}

export async function deactivateIdentity(id: string): Promise<void> {
  await revokeSubject(id, { deactivate: true });
}

export async function reactivateIdentity(id: string): Promise<void> {
  const patch = [{ op: 'replace' as const, path: '/state', value: 'active' }];
  await kratosAdmin().patchIdentity({ id, jsonPatch: patch });
}

type PatchOp = { op: 'add' | 'replace' | 'remove'; path: string; value?: unknown };

const pointerSegment = (segment: string) => segment.replace(/~/g, '~0').replace(/\//g, '~1');
const nest = (path: string[], value: unknown): unknown => path.reduceRight<unknown>((inner, key) => ({ [key]: inner }), value);

/**
 * One targeted write under metadata_admin: set `path` to `value`, or remove it with null. Targeted so no other key is
 * rewritten and a concurrent change to one is not lost. Kratos does not create a missing parent, so the add lands at the
 * first segment that is absent, carrying the rest nested; an add onto an existing member replaces it (RFC 6902).
 */
async function patchMetadataKey(id: string, path: string[], value: unknown | null): Promise<void> {
  const api = kratosAdmin();
  const current = await api.getIdentity({ id });
  const hasMeta = current.metadata_admin != null && typeof current.metadata_admin === 'object';
  let node: unknown = current.metadata_admin;
  let present = 0;
  while (hasMeta && present < path.length && node != null && typeof node === 'object' && Object.hasOwn(node, path[present])) {
    node = (node as Record<string, unknown>)[path[present]];
    present++;
  }
  const pointer = (segments: string[]) => ['/metadata_admin', ...segments.map(pointerSegment)].join('/');
  let patch: PatchOp[];
  if (value === null) {
    if (!hasMeta || present < path.length) return;
    patch = [{ op: 'remove', path: pointer(path) }];
  } else if (!hasMeta) {
    patch = [{ op: 'add', path: '/metadata_admin', value: nest(path, value) }];
  } else {
    const depth = Math.min(present + 1, path.length);
    patch = [{ op: 'add', path: pointer(path.slice(0, depth)), value: nest(path.slice(depth), value) }];
  }
  await api.patchIdentity({ id, jsonPatch: patch });
}

export async function patchAdminMarker(id: string, grant: boolean): Promise<void> {
  await patchMetadataKey(id, ['admin'], grant ? true : null);
}

/** Records the fingerprint a revoke covered: one JSON Patch add on /metadata_admin/grants_revoked. */
export async function patchGrantsRevoked(id: string, marker: GrantsMarker): Promise<void> {
  await patchMetadataKey(id, ['grants_revoked'], validateMetadataAdmin({ grants_revoked: marker }).grants_revoked!);
}

export async function patchPrerequisites(id: string, names: string[]): Promise<void> {
  const prerequisites = validateMetadataAdmin({ prerequisites: names }).prerequisites ?? [];
  await patchMetadataKey(id, ['prerequisites'], prerequisites.length === 0 ? null : prerequisites);
}

export async function patchPasskeyName(id: string, credentialId: string, name: string): Promise<void> {
  const names = validateMetadataAdmin({ passkeyNames: { [credentialId]: name } }).passkeyNames ?? {};
  await patchMetadataKey(id, ['passkeyNames', credentialId], names[credentialId]);
}

export async function prunePasskeyNames(id: string): Promise<number> {
  const api = kratosAdmin();
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
    await kratosAdmin().deleteIdentityCredentials({
      id: identityId,
      type: type as DeleteIdentityCredentialsTypeEnum,
    });
  } catch (err: unknown) {
    if (isNotFound(err)) return;
    throw err;
  }
}

export interface RecoveryLink {
  recovery_link: string;
  recovery_code: string;
  expires_at: string;
}

export async function getRecoveryLink(id: string, expiresIn = '1h'): Promise<RecoveryLink> {
  const link = await kratosAdmin().createRecoveryCodeForIdentity({
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
  const api = kratosAdmin();
  const current = await api.getIdentity({ id });
  if (!displayed || current.traits?.email !== displayed) return false;
  await api.patchIdentity({ id, jsonPatch: emailVerifiedPatch(current) as never });
  return true;
}

/** Sets the picture, or removes it with null. */
export async function patchAvatar(id: string, avatar: Avatar | null): Promise<void> {
  await patchMetadataKey(id, ['avatar'], avatar === null ? null : validateMetadataAdmin({ avatar }).avatar!);
}

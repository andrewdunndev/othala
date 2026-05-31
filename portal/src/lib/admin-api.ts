// Kratos admin API wrappers used by /admin/* SSR pages.
//
// The portal runs on carmine in the same pod network as Kratos, so the
// admin port (4434) is reachable directly at `http://kratos:4434`. The
// admin port has no auth in default Kratos posture; network isolation
// is the gate. KRATOS_ADMIN_TOKEN is reserved for a future Oathkeeper
// (or equivalent) interposer; if set, it's forwarded as Authorization
// Bearer. If unset, the Authorization header is omitted.
//
// All functions throw on non-2xx with the response body folded into the
// message; callers catch and render an error notice. JSON-Patch is used
// for trait/metadata updates because Kratos's PATCH endpoint expects RFC
// 6902 patches, not partial documents.

import type { Identity } from './types';
import { validateMetadataAdmin } from './metadata-admin';

function adminBase(): string {
  return process.env.KRATOS_ADMIN_URL ?? 'http://kratos:4434';
}

function adminToken(): string {
  return process.env.KRATOS_ADMIN_TOKEN ?? '';
}

function authHeaders(extra: Record<string, string> = {}): HeadersInit {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...extra,
  };
  const token = adminToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function ok(res: Response, label: string): Promise<void> {
  if (res.ok) return;
  let body = '';
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }
  throw new Error(`${label}: ${res.status} ${body.slice(0, 240)}`);
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
  const res = await fetch(`${adminBase()}/admin/identities?per_page=250`, {
    headers: authHeaders(),
  });
  await ok(res, 'listIdentities');
  return (await res.json()) as Identity[];
}

export async function getIdentity(id: string): Promise<Identity> {
  const url =
    `${adminBase()}/admin/identities/${encodeURIComponent(id)}` +
    `?include_credential=password,webauthn,passkey,totp`;
  const res = await fetch(url, { headers: authHeaders() });
  await ok(res, 'getIdentity');
  return (await res.json()) as Identity;
}

export async function createIdentity(input: CreateIdentityInput): Promise<Identity> {
  // J1: enforce metadata_admin shape at the application layer. Kratos's
  // identity-schema only validates `traits`; metadata_admin is opaque to
  // the schema validator. A typo (grupos instead of groups) would
  // otherwise be silently accepted and stored.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const res = await fetch(`${adminBase()}/admin/identities`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      schema_id: input.schemaId ?? 'family',
      traits: input.traits,
      metadata_admin: validated,
    }),
  });
  await ok(res, 'createIdentity');
  return (await res.json()) as Identity;
}

/**
 * Replace traits + metadata_admin via PUT (Kratos accepts a full identity
 * body). PATCH/JSON-Patch is the alternative; PUT is simpler when both
 * blocks are written together, which is the admin-UI common case.
 */
export async function updateIdentity(id: string, input: UpdateIdentityInput): Promise<Identity> {
  // J1: same metadata_admin enforcement as createIdentity.
  const validated = validateMetadataAdmin(input.metadataAdmin);
  const current = await getIdentity(id);
  const res = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      schema_id: current.schema_id,
      state: current.state ?? 'active',
      traits: input.traits,
      metadata_admin: validated,
    }),
  });
  await ok(res, 'updateIdentity');
  return (await res.json()) as Identity;
}

export async function deleteIdentity(id: string): Promise<void> {
  const res = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  await ok(res, 'deleteIdentity');
}

/** Mark the identity inactive without removing it; revokes existing sessions. */
export async function deactivateIdentity(id: string): Promise<void> {
  const res = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: authHeaders({ 'Content-Type': 'application/json-patch+json' }),
    body: JSON.stringify([{ op: 'replace', path: '/state', value: 'inactive' }]),
  });
  await ok(res, 'deactivateIdentity');
  // Session revocation is the second half of deactivation. If it fails
  // (500, network error, etc.) and we don't check, the identity stays in
  // a half-deactivated state — marked inactive but still holding active
  // sessions. Surface the failure so the caller can re-run / alert.
  const sessRes = await fetch(`${adminBase()}/admin/identities/${encodeURIComponent(id)}/sessions`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  await ok(sessRes, 'deleteIdentitySessions');
}

export interface RecoveryLink {
  recovery_link: string;
  expires_at: string;
}

/** One-shot enrollment / recovery URL the admin shares out-of-band. */
export async function getRecoveryLink(id: string, expiresIn = '1h'): Promise<RecoveryLink> {
  const res = await fetch(`${adminBase()}/admin/recovery/link`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ identity_id: id, expires_in: expiresIn }),
  });
  await ok(res, 'getRecoveryLink');
  return (await res.json()) as RecoveryLink;
}

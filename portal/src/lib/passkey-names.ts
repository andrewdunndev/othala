// Passkey names. Kratos v26.2.0 passkey settings take no name, so a person's names live in the identity's
// metadata_admin.passkeyNames as { credential_id: name }, keyed by the lowercase-hex credential id the settings flow
// carries in each passkey_remove node. Written only by the rename route (targeted JSON patch) and pruned by the
// settings.after.passkey hook; display falls back to "Passkey" plus the added date.

import type { Identity } from './types';

export const PASSKEY_NAME_MAX = 40;
export const CREDENTIAL_ID_RE = /^[0-9a-f]{2,512}$/;

export type PasskeyNames = Record<string, string>;

/** Trim, collapse whitespace and drop control characters; null for an empty or over-long result. */
export function cleanPasskeyName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const name = raw.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (name.length === 0 || [...name].length > PASSKEY_NAME_MAX) return null;
  return name;
}

/** The stored names, tolerant of a missing or malformed value; entries with a bad key or name are dropped. */
export function readPasskeyNames(meta: unknown): PasskeyNames {
  const raw = (meta as { passkeyNames?: unknown } | null | undefined)?.passkeyNames;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: PasskeyNames = {};
  for (const [id, name] of Object.entries(raw as Record<string, unknown>)) {
    const clean = cleanPasskeyName(name);
    if (CREDENTIAL_ID_RE.test(id) && clean) out[id] = clean;
  }
  return out;
}

/** The identity's passkey credential ids as lowercase hex, the form of a passkey_remove node value. */
export function passkeyCredentialIds(identity: Identity | null | undefined): string[] {
  const config = (identity?.credentials as Record<string, { config?: unknown }> | undefined)?.passkey?.config as
    | { credentials?: Array<{ id?: unknown }> }
    | undefined;
  const out: string[] = [];
  for (const c of config?.credentials ?? []) {
    if (typeof c?.id === 'string' && c.id.length > 0) out.push(Buffer.from(c.id, 'base64').toString('hex'));
  }
  return out;
}

/** True when `credentialId` is one of this identity's own passkeys. */
export function ownsPasskey(identity: Identity | null | undefined, credentialId: string): boolean {
  return CREDENTIAL_ID_RE.test(credentialId) && passkeyCredentialIds(identity).includes(credentialId);
}

/** The names that remain once ids no longer on the identity are dropped, or null when nothing is stale. */
export function pruneNames(names: PasskeyNames, currentIds: readonly string[]): PasskeyNames | null {
  const kept: PasskeyNames = {};
  let dropped = false;
  for (const [id, name] of Object.entries(names)) {
    if (currentIds.includes(id)) kept[id] = name;
    else dropped = true;
  }
  return dropped ? kept : null;
}

export type RenameVerdict =
  | { ok: true; name: string }
  | { ok: false; status: 400 | 403; error: string; code: 'unknown' | 'name' };

/** Validate a rename: a well-formed id the session's identity owns, and a usable name. */
export function renameVerdict(identity: Identity, credentialId: unknown, rawName: unknown): RenameVerdict {
  if (typeof credentialId !== 'string' || !CREDENTIAL_ID_RE.test(credentialId)) {
    return { ok: false, status: 400, error: 'Unknown passkey.', code: 'unknown' };
  }
  if (!ownsPasskey(identity, credentialId)) {
    return { ok: false, status: 403, error: 'Unknown passkey.', code: 'unknown' };
  }
  const name = cleanPasskeyName(rawName);
  if (!name) {
    return { ok: false, status: 400, error: `Give the passkey a name of up to ${PASSKEY_NAME_MAX} characters.`, code: 'name' };
  }
  return { ok: true, name };
}

/** Validate a rename and, only when the identity owns the passkey, write it through `patch`. */
export async function applyRename(
  identity: Identity,
  credentialId: unknown,
  rawName: unknown,
  patch: (identityId: string, credentialId: string, name: string) => Promise<void>,
): Promise<RenameVerdict> {
  const verdict = renameVerdict(identity, credentialId, rawName);
  if (verdict.ok) await patch(identity.id, credentialId as string, verdict.name);
  return verdict;
}

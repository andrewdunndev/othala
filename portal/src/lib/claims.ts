// ID-token claim construction. A missing claim is omitted, never null.

import type { Identity } from './types';
import type { ClientManifest } from './manifests';
import { shouldEmitGroups } from './manifests';
import { avatarPath, readAvatar } from './avatar';
import { publicUrl } from './config';

type Claims = Record<string, unknown>;

function stringTrait(traits: unknown, key: string): string | undefined {
  if (!traits || typeof traits !== 'object') return undefined;
  const v = (traits as Record<string, unknown>)[key];
  return typeof v === 'string' && v !== '' ? v : undefined;
}

function extractGroups(meta: unknown): string[] | undefined {
  if (!meta || typeof meta !== 'object') return undefined;
  const raw = (meta as Record<string, unknown>).groups;
  if (!Array.isArray(raw)) return undefined;
  return raw.filter((g): g is string => typeof g === 'string');
}

/** email_verified: the flag of the entry holding the email trait's own address (case-insensitive); no match is false, no addresses omits the claim. */
function emailVerified(identity: Identity, email: string): boolean | undefined {
  const addrs = identity.verifiable_addresses;
  if (!Array.isArray(addrs) || addrs.length === 0) return undefined;
  const want = email.toLowerCase();
  const own = addrs.find((a) => typeof a.value === 'string' && a.value.toLowerCase() === want);
  return own?.verified === true;
}

export function buildIDTokenClaims(identity: Identity | null | undefined): Claims {
  const claims: Claims = {};
  if (!identity) return claims;

  const traits = identity.traits;

  const email = stringTrait(traits, 'email');
  if (email !== undefined) {
    claims.email = email;
    const verified = emailVerified(identity, email);
    if (verified !== undefined) {
      claims.email_verified = verified;
    }
  }

  const username = stringTrait(traits, 'username');
  if (username !== undefined) {
    claims.preferred_username = username;
  }

  const displayName = stringTrait(traits, 'displayName');
  if (displayName !== undefined) {
    claims.name = displayName;
  } else if (username !== undefined) {
    claims.name = username;
  }

  const groups = extractGroups(identity.metadata_admin);
  if (groups !== undefined) {
    claims.groups = groups;
  }

  const avatar = readAvatar(identity.metadata_admin);
  if (avatar !== undefined && identity.id) {
    claims.picture = `${publicUrl}${avatarPath(identity.id, avatar)}`;
  }

  return claims;
}

/**
 * The app role: a metadataAdmin.roles[clientId] override naming a declared role, else the highest-ranked role any
 * stored group maps to (index 0 is highest), so the result depends on the group set, not its order. An override naming
 * a role the manifest no longer declares resolves to the lowest declared role: a person someone chose to hold back never
 * regains what a group maps to. A role never grants entry. Roles declared in ascending order silently downgrade, the safe
 * direction.
 */
export function lookupRole(
  manifest: ClientManifest | undefined | null,
  metadataAdmin: unknown,
): { roleName: string; claimEmit: Record<string, unknown> } | null {
  if (!manifest || manifest.roles.length === 0) return null;

  const meta = metadataAdmin as Record<string, unknown> | null | undefined;

  const overrides = meta?.roles;
  if (overrides && typeof overrides === 'object' && !Array.isArray(overrides)) {
    const overrideMap = overrides as Record<string, unknown>;
    const overrideName = overrideMap[manifest.clientId.toLowerCase()];
    if (typeof overrideName === 'string' && overrideName !== '') {
      const role = manifest.roles.find((r) => r.name === overrideName);
      const resolved = role ?? manifest.roles[manifest.roles.length - 1];
      return { roleName: resolved.name, claimEmit: shallowCopyClaimEmit(resolved.claimEmit) };
    }
  }

  const rawGroups = meta?.groups;
  const groups: string[] = Array.isArray(rawGroups)
    ? rawGroups.filter((g): g is string => typeof g === 'string')
    : [];

  let bestIndex = -1;
  for (const g of groups) {
    const roleName = manifest.groupRoleMap[g];
    if (!roleName) continue;
    // findIndex for the rank; a duplicated role name resolves to its first declaration.
    const index = manifest.roles.findIndex((r) => r.name === roleName);
    if (index === -1) continue;
    if (bestIndex === -1 || index < bestIndex) bestIndex = index;
  }

  if (bestIndex !== -1) {
    const role = manifest.roles[bestIndex];
    return { roleName: role.name, claimEmit: shallowCopyClaimEmit(role.claimEmit) };
  }

  return null;
}

function shallowCopyClaimEmit(ce: Record<string, unknown> | null): Record<string, unknown> {
  if (!ce) return {};
  return { ...ce };
}

/** Merge two arrays, dst order first then new src elements; identity for primitives, JSON.stringify for objects. */
function unionArrays(a: unknown[], b: unknown[]): unknown[] {
  const out: unknown[] = [];
  const seen = new Set<string>();
  for (const el of [...a, ...b]) {
    const key =
      typeof el === 'object' && el !== null
        ? JSON.stringify(el)
        : `${typeof el}:${String(el)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(el);
  }
  return out;
}

/**
 * Merge src into dst in place. Arrays are UNIONed (a role's claim_emit adds to the real groups array, never
 * shadows it); objects recurse; other conflicts take src.
 */
export function deepMergeClaims(
  dst: Record<string, unknown>,
  src: Record<string, unknown>,
): void {
  if (!dst || !src) return;
  for (const [k, sv] of Object.entries(src)) {
    // Skip prototype-pollution keys: recursing on dst["__proto__"] would write onto Object.prototype.
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    // Own-property check so inherited keys do not count as already in dst.
    if (!Object.prototype.hasOwnProperty.call(dst, k)) {
      dst[k] = sv;
      continue;
    }
    const dv = dst[k];
    if (
      dv !== null && typeof dv === 'object' && !Array.isArray(dv) &&
      sv !== null && typeof sv === 'object' && !Array.isArray(sv)
    ) {
      deepMergeClaims(dv as Record<string, unknown>, sv as Record<string, unknown>);
      continue;
    }
    if (Array.isArray(dv) && Array.isArray(sv)) {
      dst[k] = unionArrays(dv, sv);
      continue;
    }
    dst[k] = sv;
  }
}

/** Map from OIDC scope token to the claim keys it covers (OIDC Core §5.4). */
const SCOPE_CLAIMS: Record<string, string[]> = {
  email: ['email', 'email_verified'],
  profile: ['name', 'preferred_username', 'picture'],
  groups: ['groups'],
};

/** The ID-token claims for a consent; `sub` is Hydra's. Scope filtering runs last, so claim_emit cannot bypass it. */
export function composeIDTokenClaims(
  identity: Identity | null | undefined,
  manifest: ClientManifest | undefined | null,
  requestedScope: readonly string[],
): Record<string, unknown> {
  const claims = buildIDTokenClaims(identity) as Record<string, unknown>;

  if (manifest && !shouldEmitGroups(manifest)) {
    delete claims.groups;
  }

  // An app learns only the stored groups its own manifest binds; the role's claim_emit is merged below.
  if (Array.isArray(claims.groups)) {
    const bound = manifest ? new Set([...manifest.accessGroups, ...Object.keys(manifest.groupRoleMap)]) : new Set<string>();
    const kept = (claims.groups as string[]).filter((g) => bound.has(g));
    if (kept.length > 0) claims.groups = kept;
    else delete claims.groups;
  }

  if (identity) {
    const result = lookupRole(manifest, identity.metadata_admin);
    if (result) {
      deepMergeClaims(claims, result.claimEmit);
    }
  }

  for (const [scope, keys] of Object.entries(SCOPE_CLAIMS)) {
    if (!requestedScope.includes(scope)) {
      for (const k of keys) delete claims[k];
    }
  }

  return claims;
}

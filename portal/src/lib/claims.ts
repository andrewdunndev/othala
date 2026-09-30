// ID-token claim construction, ported from consent/claims.go and consent/manifest.go. Divergences from Go: array
// UNION in deepMergeClaims, highest-role-wins in lookupRole, and emailVerified reading only the email trait's own address.
// Missing claims are omitted, never null. composeIDTokenClaims order: build identity claims, drop groups when the
// manifest suppresses them, keep only the groups it binds, merge the role's claim_emit, then drop claims whose scope was not granted.

import type { Identity } from './types';
import type { ClientManifest } from './manifests';
import { shouldEmitGroups } from './manifests';

type Claims = Record<string, unknown>;

/** A trait value coerced to a non-empty string, or undefined. */
function stringTrait(traits: unknown, key: string): string | undefined {
  if (!traits || typeof traits !== 'object') return undefined;
  const v = (traits as Record<string, unknown>)[key];
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/** Read metadata_admin.groups tolerating any-shaped metadata. */
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

/** Build ID-token claims from a Kratos identity (BuildIDTokenClaims in claims.go). */
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

  return claims;
}

/**
 * Resolve the app role: (1) an override in metadataAdmin.roles[clientId] naming a declared role wins (an undeclared
 * name falls through); (2) otherwise the HIGHEST-RANKED declared role over every stored group mapped through
 * groupRoleMap, rank being index in manifest.roles (0 highest), so the result depends on the group SET, not its order
 * (admins hold both `<svc>-access` and `<svc>-admin`); (3) null. Role never grants entry (manifest.accessGroups does).
 * Rank is a convention (roles declared in descending privilege); ascending order silently downgrades, the safe
 * direction. Undeclared mapped roles are blocked at load (validateClients); the `index === -1` skip is defence in depth.
 * Returns a shallow copy of claimEmit.
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
      if (role) {
        return { roleName: role.name, claimEmit: shallowCopyClaimEmit(role.claimEmit) };
      }
      // Override names an undeclared role: fall through to the groups walk.
    }
  }

  // Highest-ranked declared role over the whole group set, not the first match.
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
    // Undeclared mapped role: skip (defence in depth, see above).
    if (index === -1) continue;
    if (bestIndex === -1 || index < bestIndex) bestIndex = index;
  }

  if (bestIndex !== -1) {
    const role = manifest.roles[bestIndex];
    return { roleName: role.name, claimEmit: shallowCopyClaimEmit(role.claimEmit) };
  }

  return null;
}

/** Shallow-copy a claimEmit map. */
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
  profile: ['name', 'preferred_username'],
  groups: ['groups'],
};

/**
 * The emission sequence acceptConsentRequest calls: identity claims, drop groups if the manifest suppresses them,
 * keep only the groups the manifest binds, merge the role's claim_emit (arrays unioned), then, when requestedScope is given, drop claims whose scope
 * (OIDC Core §5.4) was not granted. Omitting requestedScope emits everything. `sub` is Hydra's.
 */
export function composeIDTokenClaims(
  identity: Identity | null | undefined,
  manifest: ClientManifest | undefined | null,
  requestedScope?: string[],
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

  // Scope-gate (OIDC Core §5.4); skipped when requestedScope is omitted.
  if (requestedScope) {
    for (const [scope, keys] of Object.entries(SCOPE_CLAIMS)) {
      if (!requestedScope.includes(scope)) {
        for (const k of keys) delete claims[k];
      }
    }
  }

  return claims;
}

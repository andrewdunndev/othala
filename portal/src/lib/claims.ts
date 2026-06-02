// ID-token claim construction (CU1 item 3, CU2 claims injection).
//
// Direct port of consent/claims.go BuildIDTokenClaims, deepMergeClaims,
// and consent/manifest.go LookupRole, with IDENTICAL semantics.
//
// BuildIDTokenClaims mapping against the family identity schema
// (traits: username, email, displayName?):
//
//   email              = traits.email                            (if present)
//   email_verified     = verifiable_addresses[email].verified    (if any record)
//   preferred_username = traits.username                         (if present)
//   name               = traits.displayName, fallback traits.username
//   groups             = metadata_admin.groups (string array)    (if present)
//
// Anything missing is omitted rather than emitted as null (apps tolerate
// missing fields better than null).
//
// composeIDTokenClaims implements the 3-step emission sequence from
// consent/handlers.go (~lines 208–223):
//   1. buildIDTokenClaims (pure identity claims, including groups)
//   2. if manifest && !shouldEmitGroups(manifest): delete groups claim
//   3. lookupRole; if found: deepMergeClaims(claims, claimEmit)

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

/**
 * email_verified from verifiable_addresses: the entry matching the email
 * trait, else the first entry. Returns undefined when there are no addresses
 * (so the claim is omitted), matching emailVerified() in claims.go.
 */
function emailVerified(identity: Identity, email: string): boolean | undefined {
  const addrs = identity.verifiable_addresses;
  if (!Array.isArray(addrs) || addrs.length === 0) return undefined;
  for (const a of addrs) {
    if (a.value === email) return a.verified;
  }
  return addrs[0].verified;
}

/**
 * Build the ID-token claims from a Kratos identity. Identical mapping to
 * BuildIDTokenClaims in claims.go.
 */
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
 * lookupRole — full port of consent/manifest.go Manifest.LookupRole.
 *
 * Resolution order (matches Go exactly):
 *   1. Override: metadataAdmin.roles[clientId.toLowerCase()] — if the named
 *      role IS declared in manifest.roles, that role wins. If the override
 *      names an UNDECLARED role, fall through to step 2 (typo-tolerance,
 *      matching Go's "Fall through to derivation rather than emit nothing").
 *   2. Groups walk: metadataAdmin.groups in stored order; first match in
 *      manifest.groupRoleMap whose mapped role IS in manifest.roles wins.
 *   3. null — no role resolved.
 *
 * Returns a shallow copy of claimEmit (mirroring Go copyClaimEmit) so
 * callers can deepMergeClaims without aliasing the manifest's storage.
 */
export function lookupRole(
  manifest: ClientManifest | undefined | null,
  metadataAdmin: unknown,
): { roleName: string; claimEmit: Record<string, unknown> } | null {
  if (!manifest || manifest.roles.length === 0) return null;

  const meta = metadataAdmin as Record<string, unknown> | null | undefined;

  // Step 1: override check.
  const overrides = meta?.roles;
  if (overrides && typeof overrides === 'object' && !Array.isArray(overrides)) {
    const overrideMap = overrides as Record<string, unknown>;
    const overrideName = overrideMap[manifest.clientId.toLowerCase()];
    if (typeof overrideName === 'string' && overrideName !== '') {
      const role = manifest.roles.find((r) => r.name === overrideName);
      if (role) {
        return { roleName: role.name, claimEmit: shallowCopyClaimEmit(role.claimEmit) };
      }
      // Override names an undeclared role: fall through to groups walk
      // (typo-tolerance — Go comment: "Fall through to derivation rather
      // than emit nothing").
    }
  }

  // Step 2: groups walk in the identity's stored metadata_admin.groups array
  // order (not the group_role_map key order). Stored order is normalized at
  // admin-form save time by normalizeGroupOrder in access.ts.
  const rawGroups = meta?.groups;
  const groups: string[] = Array.isArray(rawGroups)
    ? rawGroups.filter((g): g is string => typeof g === 'string')
    : [];

  for (const g of groups) {
    const roleName = manifest.groupRoleMap[g];
    if (!roleName) continue;
    const role = manifest.roles.find((r) => r.name === roleName);
    if (role) {
      return { roleName: role.name, claimEmit: shallowCopyClaimEmit(role.claimEmit) };
    }
  }

  // Step 3: no match.
  return null;
}

/** Shallow-copy a claimEmit map (mirrors Go copyClaimEmit). */
function shallowCopyClaimEmit(ce: Record<string, unknown> | null): Record<string, unknown> {
  if (!ce) return {};
  return { ...ce };
}

/**
 * deepMergeClaims — full port of consent/claims.go deepMergeClaims.
 *
 * Merges src into dst in-place. Conflict semantics (identical to Go):
 *   - Missing key in dst: copy src[k] into dst[k].
 *   - Both values are objects (Record<string,unknown>): recurse.
 *   - Any other conflict (scalar, array, type mismatch): src wins
 *     wholesale. Arrays are last-write-wins, NOT union — matching Go.
 *   - Nil/undefined dst or src: no-op (mirrors Go nil check).
 */
export function deepMergeClaims(
  dst: Record<string, unknown>,
  src: Record<string, unknown>,
): void {
  if (!dst || !src) return;
  for (const [k, sv] of Object.entries(src)) {
    const dv = dst[k];
    if (!(k in dst)) {
      dst[k] = sv;
      continue;
    }
    if (
      dv !== null && typeof dv === 'object' && !Array.isArray(dv) &&
      sv !== null && typeof sv === 'object' && !Array.isArray(sv)
    ) {
      deepMergeClaims(dv as Record<string, unknown>, sv as Record<string, unknown>);
      continue;
    }
    // Scalar, array, or type mismatch: src wins.
    dst[k] = sv;
  }
}

/**
 * composeIDTokenClaims — the 3-step emission sequence from
 * consent/handlers.go. The function acceptConsentRequest calls this
 * instead of buildIDTokenClaims directly.
 *
 * Order matches Go handlers.go ~lines 208-223:
 *   1. buildIDTokenClaims(identity) — pure identity claims
 *   2. if manifest && !shouldEmitGroups(manifest): delete groups claim
 *   3. lookupRole(manifest, identity.metadata_admin); if found:
 *      deepMergeClaims(claims, role.claimEmit)
 *
 * A missing manifest (nil-check in Go: `if cfg.Manifest != nil`) is
 * handled by lookupRole returning null and shouldEmitGroups not being
 * called — base claims only, groups emitted by default.
 */
export function composeIDTokenClaims(
  identity: Identity | null | undefined,
  manifest: ClientManifest | undefined | null,
): Record<string, unknown> {
  const claims = buildIDTokenClaims(identity) as Record<string, unknown>;

  if (manifest && !shouldEmitGroups(manifest)) {
    delete claims.groups;
  }

  if (identity) {
    const result = lookupRole(manifest, identity.metadata_admin);
    if (result) {
      deepMergeClaims(claims, result.claimEmit);
    }
  }

  return claims;
}

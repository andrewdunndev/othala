// ID-token claim construction (CU1 item 3, CU2 claims injection).
//
// Direct port of consent/claims.go BuildIDTokenClaims, deepMergeClaims,
// and consent/manifest.go LookupRole, with IDENTICAL semantics except
// where noted. Two divergences are noted at their definitions: the array
// UNION in deepMergeClaims, and the highest-role-wins group walk in
// lookupRole (Go took the first stored-order match).
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
// composeIDTokenClaims implements the 4-step emission sequence from
// consent/handlers.go (~lines 208–223):
//   1. buildIDTokenClaims (pure identity claims, including groups)
//   2. if manifest && !shouldEmitGroups(manifest): delete groups claim
//   3. lookupRole; if found: deepMergeClaims(claims, claimEmit)
//   4. if requestedScope provided: delete claims whose required scope is absent

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
 * lookupRole — port of consent/manifest.go Manifest.LookupRole, with ONE
 * deliberate divergence in step 2 (highest role wins, not first stored match).
 *
 * Resolution order:
 *   1. Override: metadataAdmin.roles[clientId.toLowerCase()] — if the named
 *      role IS declared in manifest.roles, that role wins. If the override
 *      names an UNDECLARED role, fall through to step 2 (typo-tolerance,
 *      matching Go's "Fall through to derivation rather than emit nothing").
 *   2. Groups walk: every group in metadataAdmin.groups is mapped through
 *      manifest.groupRoleMap; of the roles that ARE declared in
 *      manifest.roles, the HIGHEST-RANKED one wins. Rank is position in
 *      manifest.roles (index 0 highest) — see RANK below.
 *   3. null — no role resolved.
 *
 * WHY step 2 is no longer first-stored-match
 * ------------------------------------------
 * Under the converged access model an admin holds BOTH `<svc>-access` and
 * `<svc>-admin` explicitly — entry comes from `<svc>-access` for everyone,
 * admins included, and admin-implies-access is abolished. So a single
 * identity now routinely carries two groups that BOTH map to a role, and the
 * old "first match in metadata_admin.groups order" rule made the effective
 * role depend on array order.
 *
 * That order is not a safe input. `normalizeGroupOrder` (access.ts) sorts
 * non-identity groups alphabetically, which puts `cinema-access` BEFORE
 * `cinema-admin` — a first-match walk hands every admin the `user` role. And
 * metadata_admin.groups is written through the Kratos admin API, which makes
 * no ordering promise at all for identities touched outside the admin form.
 *
 * This resolver is therefore order-independent: the same group SET yields the
 * same role in any permutation. `normalizeGroupOrder` is now cosmetic (stable
 * display / stable diffs); it is NOT what makes role resolution deterministic.
 *
 * ENFORCERS (what actually holds this together, so nothing here is folklore)
 * -------------------------------------------------------------------------
 * - ENTRY is not decided here at all. It is `manifest.accessGroups` — sourced
 *   from `presentation.access:` by parseAccessGroups (access-groups.ts, called
 *   from parseManifest in manifests.ts) — and checked with OR-semantics by
 *   enforceAccessGate (gate.ts) and computeEffectiveAccess (access.ts). This
 *   function only decides ROLE. A role mapping never grants entry.
 * - "Every role named in group_role_map is declared in roles[]" is enforced at
 *   load time: validateClients (manifests.ts) BLOCKs the reload, and
 *   lintManifests (manifest-lint.ts) reports it. The `index === -1` skip below
 *   is defence-in-depth for a manifest that reached us anyway.
 * - RANK = declaration order in `consent.roles` is a CONVENTION, enforced by
 *   nobody. Every manifest in the deployed catalog and the e2e fixtures
 *   declares roles in descending privilege (admin, user; admin, user, guest;
 *   admin, editor, viewer), and this resolver reads that order rather than
 *   hardcoding the name "admin" — role names are manifest-authored strings and
 *   name-based inference is exactly what group-registry.ts retired. A manifest
 *   that lists roles in ASCENDING privilege gets a downgrade, which is the
 *   fail-safe direction, but it is silent. If that ever needs to stop being a
 *   convention, the place to enforce it is manifest-lint.ts.
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

  // Step 2: groups walk. Map EVERY stored group through groupRoleMap and keep
  // the highest-ranked declared role, rather than stopping at the first match.
  // Rank is the role's index in manifest.roles (0 = highest); see the RANK note
  // in the doc comment. Because the winner is the minimum index over the set of
  // matched roles, the result is a pure function of the group SET — stored
  // order cannot change it. Admins hold both `<svc>-access` and `<svc>-admin`,
  // so this is a live path, not a hypothetical.
  const rawGroups = meta?.groups;
  const groups: string[] = Array.isArray(rawGroups)
    ? rawGroups.filter((g): g is string => typeof g === 'string')
    : [];

  let bestIndex = -1;
  for (const g of groups) {
    const roleName = manifest.groupRoleMap[g];
    if (!roleName) continue;
    // findIndex, not find: we need the rank, and it returns the FIRST
    // declaration of a duplicated role name, so a malformed manifest still
    // resolves deterministically.
    const index = manifest.roles.findIndex((r) => r.name === roleName);
    // Mapped role is not declared: skip it (validateClients should already have
    // blocked this manifest at load — see ENFORCERS above).
    if (index === -1) continue;
    if (bestIndex === -1 || index < bestIndex) bestIndex = index;
  }

  if (bestIndex !== -1) {
    const role = manifest.roles[bestIndex];
    return { roleName: role.name, claimEmit: shallowCopyClaimEmit(role.claimEmit) };
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
 * unionArrays — merge two arrays preserving dst order and appending any
 * elements of src not already present. Deduplication uses strict identity for
 * primitives and JSON.stringify for objects/arrays, which is sufficient for
 * the real case (string arrays in groups claims). Order is dst-first, then
 * new elements from src in their original src order.
 */
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
 * deepMergeClaims — port of consent/claims.go deepMergeClaims with one
 * intentional divergence: arrays are UNIONed (order-preserving, deduped)
 * rather than last-write-wins. This honours the de-facto SCIM `groups`
 * convention — a role's claim_emit contributes additively to the user's
 * real membership array, never shadows it.
 *
 * Merges src into dst in-place. Conflict semantics:
 *   - Missing key in dst: copy src[k] into dst[k].
 *   - Both values are objects (Record<string,unknown>): recurse.
 *   - Both values are arrays: dst[k] = unionArrays(dst[k], src[k]).
 *   - Any other conflict (scalar, type mismatch): src wins wholesale.
 *   - Nil/undefined dst or src: no-op (mirrors Go nil check).
 */
export function deepMergeClaims(
  dst: Record<string, unknown>,
  src: Record<string, unknown>,
): void {
  if (!dst || !src) return;
  for (const [k, sv] of Object.entries(src)) {
    // Guard against prototype-pollution via __proto__, constructor, and prototype.
    // Object.entries() returns __proto__ as a plain string key when present in a
    // parsed JSON object, but dst["__proto__"] resolves to Object.prototype via
    // the special accessor — the recursive branch would then write onto
    // Object.prototype, polluting the entire process. constructor and prototype
    // are analogous vectors (e.g. src.constructor.prototype mutations).
    // Explicitly skipping all three is the safest defence.
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    // Use own-property semantics so that inherited keys (e.g. from a polluted
    // prototype) don't create a false "key already in dst" match and cause us
    // to recurse into the prototype chain.
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
    // Array union: preserve dst membership, append additive src elements.
    if (Array.isArray(dv) && Array.isArray(sv)) {
      dst[k] = unionArrays(dv, sv);
      continue;
    }
    // Scalar or type mismatch: src wins.
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
 * composeIDTokenClaims — the 4-step emission sequence from
 * consent/handlers.go. The function acceptConsentRequest calls this
 * instead of buildIDTokenClaims directly.
 *
 * Order matches Go handlers.go ~lines 208-223, plus step 4:
 *   1. buildIDTokenClaims(identity) — pure identity claims
 *   2. if manifest && !shouldEmitGroups(manifest): delete groups claim
 *   3. lookupRole(manifest, identity.metadata_admin); if found:
 *      deepMergeClaims(claims, role.claimEmit) — array keys are unioned,
 *      so a role's groups are additive (H1 fix)
 *   4. if requestedScope provided: delete any claim whose required scope
 *      is absent (OIDC Core §5.4 scope-gate, H2 fix)
 *
 * @param requestedScope - the granted scope tokens from the consent request.
 *   When provided, only claims covered by a listed scope are emitted.
 *   When omitted (undefined), all claims are emitted — this preserves
 *   backward-compat for callers that do not (yet) thread scope through.
 *   `sub` is set by Hydra, not here; it is never touched.
 *
 * A missing manifest (nil-check in Go: `if cfg.Manifest != nil`) is
 * handled by lookupRole returning null and shouldEmitGroups not being
 * called — base claims only, groups emitted by default.
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

  if (identity) {
    const result = lookupRole(manifest, identity.metadata_admin);
    if (result) {
      deepMergeClaims(claims, result.claimEmit);
    }
  }

  // Step 4: scope-gate (OIDC Core §5.4). Only applied when requestedScope
  // is provided — omitting it emits everything (back-compat).
  if (requestedScope) {
    for (const [scope, keys] of Object.entries(SCOPE_CLAIMS)) {
      if (!requestedScope.includes(scope)) {
        for (const k of keys) delete claims[k];
      }
    }
  }

  return claims;
}

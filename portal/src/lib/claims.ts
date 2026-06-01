// ID-token claim construction (CU1 item 3).
//
// Direct port of consent/claims.go BuildIDTokenClaims, with IDENTICAL
// mapping against the family identity schema
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

import type { Identity } from './types';

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

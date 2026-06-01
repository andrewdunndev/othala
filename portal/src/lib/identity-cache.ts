// In-process identity cache (DAG CU3 — revoke step 5 target).
//
// The Go consent service held a short-TTL in-process identity cache so the
// hot login/consent path didn't re-fetch metadata_admin from Kratos on
// every challenge. The TS portal carries the same cache so the revoke
// fan-out has a concrete thing to invalidate (step 5): after a revoke, a
// stale cached identity must not let a just-cut subject pass the gate.
//
// Scope: process-local, single-pod. carmine runs one portal process; if
// the portal ever scales horizontally, swap this for a shared store and
// fan invalidation across replicas (out of scope at family scale).

import type { Identity } from './types';

interface Entry {
  identity: Identity;
  expiresAt: number;
}

const TTL_MS = 30_000;
const cache = new Map<string, Entry>();

/** Read a cached identity by subject id, or undefined if missing/expired. */
export function getCachedIdentity(subject: string, now = Date.now()): Identity | undefined {
  const entry = cache.get(subject);
  if (!entry) return undefined;
  if (entry.expiresAt <= now) {
    cache.delete(subject);
    return undefined;
  }
  return entry.identity;
}

/** Store an identity under its subject id with the default TTL. */
export function setCachedIdentity(subject: string, identity: Identity, now = Date.now()): void {
  cache.set(subject, { identity, expiresAt: now + TTL_MS });
}

/**
 * Invalidate the cached identity for a subject (revoke fan-out step 5).
 * Idempotent: invalidating an absent subject is a no-op.
 */
export function invalidateIdentity(subject: string): void {
  cache.delete(subject);
}

/** Test/diagnostic helper: drop every cached identity. */
export function clearIdentityCache(): void {
  cache.clear();
}

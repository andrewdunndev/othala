// Serving-path manifest access — what keeps one bad manifest from taking the
// portal down.
//
// Two tiers read the manifest set, and they want opposite failure behaviour:
//
//   STRICT   The registrar (lib/register-clients.ts) and the lint CLI
//            (server/manifest-lint-cli.ts) call lib/manifests.ts directly and
//            MUST throw on an invalid set. A half-valid catalog must never
//            reach Hydra, and the lint's whole job is a non-zero exit.
//
//   SERVING  Every request path — the /oauth2/* challenge handlers, the admin
//            UI, and the group registry behind /auth/settings — calls THIS
//            module, which never throws.
//
// Why the split has to exist: loadClientManifests() validates the whole set and
// throws on any finding, so ONE semantic error — an undeclared role in
// group_role_map, an empty audience, an empty access binding, a duplicate
// client_id — 500s every OIDC login in the estate and the entire admin UI at
// once, including the surface the operator would use to diagnose it. A YAML
// syntax error is per-file isolated (manifests.ts loadOne warns and skips); a
// semantic error is set-wide and fatal. That asymmetry is the whole bug.
//
// loadClientManifests() already restores its prior cache before throwing, but
// that cache is only ever RETURNED when the manifest directory's mtime is
// unchanged — and the edit that broke the set changed the mtime. So the prior
// cache was preserved and never reachable. This module holds the last known
// good set OUTSIDE that mtime check, where it can actually be served. It also
// survives invalidateManifestCache() (the SIGHUP path, registrar.ts), which
// nulls manifests.ts's cache before reconciling and would otherwise destroy the
// last good state at exactly the wrong moment.
//
// Behaviour when a load fails:
//
//   - Serve the last known good set, unchanged, for as long as loading keeps
//     failing. That set was serving traffic seconds earlier.
//   - With no last known good set (a cold start onto a broken catalog) serve
//     the EMPTY set. Empty is fail-closed everywhere it lands: gate.ts denies a
//     client whose manifest is missing, and the admin UI renders zero apps.
//     Serving nothing never grants anything.
//   - Log to stderr, where journald picks it up. Grep the portal unit's journal
//     for `[portal:manifests]`. The first failure, and any change in the error
//     text, log in full; after that a one-line reminder repeats on an interval
//     so a long outage keeps leaving a trail instead of scrolling away.
//   - Retry on EVERY call. Recovery needs no restart and no SIGHUP: the first
//     request after the manifest is fixed loads cleanly and logs RECOVERED.
//
// Staleness is never silent. manifestHealth() drives a banner on the admin
// surfaces so nobody reads a stale app list as the live one.

import { loadClientManifests, type ClientManifest } from './manifests';
import { identityGroups as envIdentityGroups } from './config';

/** Log tag; matches the `[portal:registrar]` convention in server/registrar.ts. */
const TAG = '[portal:manifests]';

/** How often the "still broken" reminder repeats while a failure persists. */
const REMINDER_MS = 60 * 1000;

/**
 * The set served when a load fails and there is no last known good set.
 * A module-level constant, not a fresh `[]` per call, so callers that memoize
 * on array identity (group-registry.ts getGroupRegistry) keep their memo warm
 * through an outage instead of rebuilding on every request.
 */
const EMPTY: ClientManifest[] = [];

/**
 * `ok`          — the last load succeeded; what is served matches disk.
 * `stale`       — loading is failing; serving the last known good set, which
 *                 may not match what is on disk.
 * `unavailable` — loading is failing and there is nothing good to fall back
 *                 to; serving zero apps, so every gated app denies entry.
 */
export type ManifestStatus = 'ok' | 'stale' | 'unavailable';

export interface ManifestHealth {
  status: ManifestStatus;
  /** The load/validation failure verbatim, for the operator; null when `ok`. */
  error: string | null;
  /** Epoch ms of the first failure in the current run; null when `ok`. */
  failingSinceMs: number | null;
  /** How many manifests are actually being served right now. */
  serving: number;
}

let lastGood: ClientManifest[] | null = null;

interface Failure {
  message: string;
  sinceMs: number;
  lastLoggedMs: number;
}

let failure: Failure | null = null;

/**
 * The manifest set to serve this request. Never throws.
 *
 * On success the set is recorded as the last known good and returned. On
 * failure the last known good set is returned (or the empty set if there is
 * none) and the failure is logged — see the module header for the logging
 * cadence.
 */
export function servingManifests(): ClientManifest[] {
  let set: ClientManifest[];
  try {
    set = loadClientManifests();
  } catch (err) {
    noteFailure(err);
    return lastGood ?? EMPTY;
  }
  noteSuccess(set.length);
  lastGood = set;
  return set;
}

/**
 * Resolve one OIDC client manifest by client_id from the served set, or
 * undefined. The serving-path counterpart of manifests.ts getClientManifest,
 * with the same two rules:
 *
 *   - case-insensitive (Go Manifest.Client lowercases the id);
 *   - presentation-only manifests are NOT resolvable, because they register no
 *     Hydra client and no OAuth2 request can legitimately name one.
 *
 * The /oauth2/* challenge handlers resolve through here so a broken catalog
 * denies entry instead of 500-ing every login at once. An undefined result is
 * fail-closed at the gate: gate.ts enforceAccessGate has no binding to satisfy
 * without a manifest.
 */
export function servingManifest(clientId: string): ClientManifest | undefined {
  const key = clientId.toLowerCase();
  return servingManifests().find(
    (m) => !m.presentationOnly && m.clientId.toLowerCase() === key,
  );
}

/**
 * Identity groups across the served set: OTHALA_IDENTITY_GROUPS plus every
 * group_role_map key any manifest references, sorted.
 *
 * Same derivation as manifests.ts knownIdentityGroups(), over the served set
 * instead of the strict load — that function throws, and the admin UI is
 * precisely the surface that must stay up when a manifest breaks.
 */
export function servingIdentityGroups(): string[] {
  const set = new Set<string>(envIdentityGroups);
  for (const m of servingManifests()) {
    for (const g of Object.keys(m.groupRoleMap)) set.add(g);
  }
  return Array.from(set).sort();
}

/**
 * Access groups across the served set: every group any manifest's
 * `presentation.access:` binding names, sorted.
 *
 * Same derivation as manifests.ts knownAccessGroups(), over the served set.
 */
export function servingAccessGroups(): string[] {
  const set = new Set<string>();
  for (const m of servingManifests()) {
    for (const g of m.accessGroups) set.add(g);
  }
  return Array.from(set).sort();
}

/**
 * Current health of the served set, for the admin banner.
 *
 * Refreshes the state first (a cached load, so it is cheap) so the answer never
 * depends on whether the caller happened to load manifests earlier in the same
 * render. Call it in any order relative to servingManifests().
 */
export function manifestHealth(): ManifestHealth {
  servingManifests();
  if (failure === null) {
    return {
      status: 'ok',
      error: null,
      failingSinceMs: null,
      serving: lastGood?.length ?? 0,
    };
  }
  return {
    status: lastGood === null ? 'unavailable' : 'stale',
    error: failure.message,
    failingSinceMs: failure.sinceMs,
    serving: lastGood?.length ?? 0,
  };
}

/** Drop the last known good set and the failure state. Tests only. */
export function _resetForTests(): void {
  lastGood = null;
  failure = null;
}

// ── failure bookkeeping + logging ───────────────────────────────────────────

function noteFailure(err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  const now = Date.now();

  if (failure === null) {
    failure = { message, sinceMs: now, lastLoggedMs: now };
    logFull(message);
    return;
  }

  // A different error means the operator is mid-fix and has reached a new
  // problem: log it in full rather than swallowing it into the reminder.
  if (failure.message !== message) {
    failure = { message, sinceMs: failure.sinceMs, lastLoggedMs: now };
    logFull(message);
    return;
  }

  if (now - failure.lastLoggedMs >= REMINDER_MS) {
    const brokenForMs = now - failure.sinceMs;
    failure.lastLoggedMs = now;
    console.error(
      `${TAG} STILL BROKEN after ${Math.round(brokenForMs / 1000)}s — ` +
        `serving ${lastGood?.length ?? 0} app(s) ` +
        `${lastGood === null ? '(nothing to fall back to)' : 'from the last known good set'}. ` +
        `Cause: ${message}`,
    );
  }
}

function logFull(message: string): void {
  if (lastGood === null) {
    console.error(
      `${TAG} UNAVAILABLE — the manifest set failed to load and there is no last known ` +
        `good set to fall back to. Serving ZERO apps: every OIDC login is denied and the ` +
        `admin app list is empty. Fix the manifest directory; the portal recovers on the ` +
        `next request, no restart needed. Cause: ${message}`,
    );
    return;
  }
  console.error(
    `${TAG} STALE — the manifest set failed to load. Serving the last known good set ` +
      `(${lastGood.length} app(s)), which no longer matches what is on disk. ` +
      `Fix the manifest directory; the portal recovers on the next request, no restart ` +
      `needed. Cause: ${message}`,
  );
}

function noteSuccess(count: number): void {
  if (failure === null) return;
  const brokenForMs = Date.now() - failure.sinceMs;
  failure = null;
  console.error(
    `${TAG} RECOVERED — the manifest set loaded cleanly after ${Math.round(brokenForMs / 1000)}s ` +
      `broken; serving ${count} app(s).`,
  );
}

// Serving-path manifest access. STRICT callers (registrar, lint CLI) use manifests.ts directly and must throw on an
// invalid set; SERVING callers (/oauth2/* handlers, admin UI, group registry) use this module, which never throws.
// loadClientManifests() throws on any set-wide semantic error, which would 500 every login and the admin UI. This
// module holds the last known good set outside manifests.ts's mtime check (the breaking edit changed the mtime) and
// across invalidateManifestCache() (SIGHUP). On failure it serves that set, or the EMPTY set on a cold start (fail-closed:
// gate.ts denies a missing manifest); logs `[portal:manifests]` in full on the first failure or a changed error, then a
// periodic reminder; and retries on every call, so a fixed manifest logs RECOVERED with no restart.
// manifestHealth() drives the admin banner so a stale list is never read as live.

import { loadClientManifests, type ClientManifest } from './manifests';

/** Log tag, as `[portal:registrar]` in server/registrar.ts. */
const TAG = '[portal:manifests]';

/** How often the "still broken" reminder repeats while a failure persists. */
const REMINDER_MS = 60 * 1000;

/** Set served with no last known good; a shared constant so identity-memoizing callers (group-registry.ts) stay warm through an outage. */
const EMPTY: ClientManifest[] = [];

/** `ok`: matches disk. `stale`: loading fails, serving the last known good set. `unavailable`: loading fails with nothing to fall back to, so zero apps and every gated app denies. */
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

/** The manifest set to serve this request; never throws. Records success as last known good; on failure returns it (or the empty set) and logs. */
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
 * One OIDC client manifest by client_id from the served set, as manifests.ts getClientManifest (case-insensitive;
 * presentation-only tiles never resolve). A broken catalog denies at the gate instead of 500ing; undefined is fail-closed.
 */
export function servingManifest(clientId: string): ClientManifest | undefined {
  const key = clientId.toLowerCase();
  return servingManifests().find(
    (m) => !m.presentationOnly && m.clientId.toLowerCase() === key,
  );
}

/** Sorted access groups named by any served manifest's `presentation.access:`; as knownAccessGroups() over the served set. */
export function servingAccessGroups(): string[] {
  const set = new Set<string>();
  for (const m of servingManifests()) {
    for (const g of m.accessGroups) set.add(g);
  }
  return Array.from(set).sort();
}

/** Health of the served set for the admin banner; refreshes first (cached, cheap) so call order does not matter. */
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

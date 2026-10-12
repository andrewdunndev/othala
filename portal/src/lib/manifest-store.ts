// Serving-path manifest access, which never throws. Per-file problems are quarantined in manifests.ts; this covers
// a directory that cannot be read, which would otherwise 500 every login. It keeps the last known good set across mtime checks and SIGHUP, serves the EMPTY set on a cold start
// (fail-closed), logs `[portal:manifests]` on the first or changed failure, and retries each call so a fix logs
// RECOVERED. manifestHealth() drives the admin banner.

import { droppedManifests, loadClientManifests, type ClientManifest, type Dropped } from './manifests';

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
  /** The load failure verbatim, for the operator; null when `ok`. */
  error: string | null;
  /** Epoch ms of the first failure in the current run; null when `ok`. */
  failingSinceMs: number | null;
  /** How many manifests are actually being served right now. */
  serving: number;
  /** Files the loader dropped (unparseable or invalid manifests), each with its reason; the rest keep serving. */
  dropped: Dropped[];
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
 * One OIDC client manifest by client_id from the served set, case-insensitive. Presentation-only tiles never resolve,
 * so an OAuth2 request cannot bind a client_id to an unregistered tile. A broken catalog denies at the gate instead of
 * 500ing; undefined is fail-closed.
 */
export function servingManifest(clientId: string): ClientManifest | undefined {
  const key = clientId.toLowerCase();
  return servingManifests().find(
    (m) => !m.presentationOnly && m.clientId.toLowerCase() === key,
  );
}

/** Health of the served set for the admin banner; refreshes first (cached, cheap) so call order does not matter. */
export function manifestHealth(): ManifestHealth {
  servingManifests();
  const dropped = failure === null ? droppedManifests() : [];
  if (failure === null) {
    return {
      status: 'ok',
      error: null,
      failingSinceMs: null,
      serving: lastGood?.length ?? 0,
      dropped,
    };
  }
  return {
    status: lastGood === null ? 'unavailable' : 'stale',
    error: failure.message,
    failingSinceMs: failure.sinceMs,
    serving: lastGood?.length ?? 0,
    dropped,
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
        `admin app list is empty. Fix apps/ under /etc/othala; the portal recovers on the ` +
        `next request, no restart needed. Cause: ${message}`,
    );
    return;
  }
  console.error(
    `${TAG} STALE — the manifest set failed to load. Serving the last known good set ` +
      `(${lastGood.length} app(s)), which no longer matches what is on disk. ` +
      `Fix apps/ under /etc/othala; the portal recovers on the next request, no restart ` +
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

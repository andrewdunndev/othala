// In-process OIDC client reconciler, run on boot (retrying with capped backoff until a cold Hydra answers) and on
// SIGHUP (drops the manifest cache, re-registers all clients); both are wired in listen.ts. It never crashes the
// listeners: errors are logged and the portal keeps serving. `register` is injectable for tests.
import { registerAllClients, type RegisterOptions } from '../lib/register-clients';
import { invalidateManifestCache } from '../lib/manifests';

/** Signature of the injectable register function (matches registerAllClients). */
type RegisterFn = (opts?: RegisterOptions) => Promise<{ clientId: string; action: string }[]>;

// Single-flight guard. A call during a pass queues exactly one rerun, so a SIGHUP
// that lands mid-pass is not lost and many of them still cost one extra pass.
let reconciling = false;
let rerunPending = false;
let lastOk = true;

/** False once a pass has failed and until a later pass succeeds; read by /readyz. */
export const lastReconcileOk = (): boolean => lastOk;

/**
 * Run one reconcile pass: load manifests, register every client, log results.
 *
 * Single-flight: if already running, queues one rerun and returns. On error:
 * logs loudly (unless `logFailure` is false, for a caller that logs its own) and RE-THROWS so reconcileOnBoot can retry.
 * `finally` resets the guard, then runs the queued rerun.
 *
 * @param register Injectable register function (defaults to registerAllClients).
 */
export async function reconcileClients(register: RegisterFn = registerAllClients, logFailure = true): Promise<void> {
  if (reconciling) {
    console.warn('[portal:registrar] reconcile already in-flight — queued one rerun');
    rerunPending = true;
    return;
  }
  reconciling = true;
  try {
    const results = await register();
    for (const r of results) {
      console.log(`[portal:registrar] ${r.action} ${r.clientId}`);
    }
    console.log(`[portal:registrar] reconcile complete — ${results.length} client(s) processed`);
    lastOk = true;
  } catch (err) {
    lastOk = false;
    if (logFailure) console.error('[portal:registrar] reconcile FAILED — continuing to serve:', err);
    throw err;
  } finally {
    reconciling = false;
    if (rerunPending) {
      rerunPending = false;
      await reconcileClients(register).catch(() => {});
    }
  }
}

/**
 * Boot reconcile. Hydra may still be starting, or recovering its database, when the portal binds its
 * listeners, so a failed pass retries with doubling backoff capped at `maxDelayMs` until one succeeds; the
 * listeners serve throughout and /readyz reports 503 until it does. A failure is logged once per backoff step,
 * so a long outage costs a handful of lines, not one per retry. Only a pass of its own ends the loop.
 *
 * @param register  Injectable register function (defaults to registerAllClients).
 * @param baseDelayMs  First retry delay in ms (default 2000).
 * @param maxDelayMs  Ceiling for the retry delay in ms (default 60000).
 */
export async function reconcileOnBoot(
  register: RegisterFn = registerAllClients,
  baseDelayMs = 2000,
  maxDelayMs = 60_000,
): Promise<void> {
  let delay = baseDelayMs;
  let attemptLogged = 0;
  let failureLogged = 0;
  for (let attempt = 1; ; attempt++) {
    if (delay !== attemptLogged) {
      attemptLogged = delay;
      console.log(`[portal:registrar] boot reconcile attempt ${attempt}`);
    }
    // Wait out a pass already running (a SIGHUP) without queueing a rerun behind it: only a pass of our own ends the loop.
    if (reconciling) {
      await new Promise((resolve) => setTimeout(resolve, baseDelayMs));
      continue;
    }
    try {
      await reconcileClients(register, false);
      return;
    } catch (err) {
      if (delay !== failureLogged) {
        failureLogged = delay;
        const at = delay >= maxDelayMs ? ' (the longest wait; logged no more until it succeeds)' : '';
        console.warn(
          `[portal:registrar] reconcile failed: ${(err as Error).message} — retrying in ${delay}ms${at}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, maxDelayMs);
    }
  }
}

/**
 * SIGHUP reload handler. Invalidates the manifest cache so the next load
 * re-reads from disk, then runs a reconcile pass. Errors are swallowed
 * (already logged by reconcileClients); the portal continues serving.
 *
 * @param register  Injectable register function (defaults to registerAllClients).
 */
export async function reloadOnSighup(register: RegisterFn = registerAllClients): Promise<void> {
  console.log('[portal:registrar] SIGHUP — reloading manifest cache and reconciling clients');
  invalidateManifestCache();
  try {
    await reconcileClients(register);
  } catch {
    // Already logged loudly by reconcileClients — serve on.
  }
}

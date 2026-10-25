// In-process OIDC client reconciler, run on boot (bounded retry+backoff for a
// cold Hydra) and on SIGHUP (drops the manifest cache, re-registers all
// clients); both are wired in listen.ts. It never crashes the listeners: errors
// are logged and the portal keeps serving. `register` is injectable for tests.
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
 * logs loudly and RE-THROWS so reconcileOnBoot can apply its retry logic.
 * `finally` resets the guard, then runs the queued rerun.
 *
 * @param register Injectable register function (defaults to registerAllClients).
 */
export async function reconcileClients(register: RegisterFn = registerAllClients): Promise<void> {
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
    console.error('[portal:registrar] reconcile FAILED — continuing to serve:', err);
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
 * Bounded-retry boot reconcile. Hydra may still be starting when the portal
 * binds its listeners, so we retry with linear backoff up to `attempts` times.
 *
 * After the last attempt, logs a clear operator message and RETURNS without
 * throwing — the portal must not crash its listeners due to Hydra
 * unavailability at boot. An operator can SIGHUP to retry once Hydra is up.
 *
 * @param register  Injectable register function (defaults to registerAllClients).
 * @param attempts  Maximum attempts before giving up (default 5).
 * @param baseDelayMs  Delay multiplier in ms (attempt × baseDelayMs, default 2000).
 */
export async function reconcileOnBoot(
  register: RegisterFn = registerAllClients,
  attempts = 5,
  baseDelayMs = 2000,
): Promise<void> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      console.log(`[portal:registrar] boot reconcile attempt ${attempt}/${attempts}`);
      await reconcileClients(register);
      return; // success — done
    } catch {
      if (attempt < attempts) {
        const delay = baseDelayMs * attempt;
        console.warn(
          `[portal:registrar] attempt ${attempt} failed — retrying in ${delay}ms`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  // All attempts exhausted — log prominently and return (never throw).
  console.error(
    `[portal:registrar] boot reconcile gave up after ${attempts} attempt(s) — ` +
      'serving anyway — fix Hydra and SIGHUP to retry',
  );
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

// In-process OIDC client reconciler — driven by boot reconcile + SIGHUP.
//
// Called on BOOT (reconcileOnBoot) and on SIGHUP (reloadOnSighup), both wired
// in src/server/listen.mjs. The reconciler is resilient: it never crashes the
// portal listeners regardless of Hydra availability.
//
// Boot reconcile: bounded retry+backoff so a cold start with Hydra still
// initialising still succeeds after a few attempts. After the retry budget is
// exhausted the portal logs a clear operator notice and keeps serving (an
// operator can SIGHUP to retry once Hydra is ready).
//
// SIGHUP reconcile: drops the manifest cache (so the next load re-reads from
// disk), then re-registers all clients. Errors are swallowed and logged
// loudly — the portal continues serving on SIGHUP errors too.
//
// Injectable `register` parameter (defaults to registerAllClients) lets the
// test suite pass a stub without importing a live Hydra SDK.
import { registerAllClients, type RegisterOptions } from '../lib/register-clients';
import { invalidateManifestCache } from '../lib/manifests';

/** Signature of the injectable register function (matches registerAllClients). */
type RegisterFn = (opts?: RegisterOptions) => Promise<{ clientId: string; action: string }[]>;

// Module-level single-flight guard. A second call while one is in-flight
// warns and returns immediately — prevents queued SIGHUPs from piling up.
let reconciling = false;

/**
 * Run one reconcile pass: load manifests, register every client, log results.
 *
 * Single-flight: if already running, warns and returns without calling
 * `register` again. On error: logs loudly and RE-THROWS so reconcileOnBoot
 * can apply its retry logic. `finally` always resets the guard.
 *
 * @param register Injectable register function (defaults to registerAllClients).
 */
export async function reconcileClients(register: RegisterFn = registerAllClients): Promise<void> {
  if (reconciling) {
    console.warn('[portal:registrar] reconcile already in-flight — skipping concurrent call');
    return;
  }
  reconciling = true;
  try {
    const results = await register();
    for (const r of results) {
      console.log(`[portal:registrar] ${r.action} ${r.clientId}`);
    }
    console.log(`[portal:registrar] reconcile complete — ${results.length} client(s) processed`);
  } catch (err) {
    console.error('[portal:registrar] reconcile FAILED — continuing to serve:', err);
    throw err;
  } finally {
    reconciling = false;
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

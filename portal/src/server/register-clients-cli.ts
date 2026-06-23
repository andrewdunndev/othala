// One-shot CLI wrapper around the in-app OIDC client registrar.
//
// This is the e2e/deploy entrypoint for the registrar that otherwise lives
// only as a library (src/lib/register-clients.ts -> registerAllClients).
// Registration is a deliberate one-shot step — never on app boot or route:
//
//   - In production, the deploy repo's `just dag-reload-clients <host>`
//     invokes this bundle as a --rm one-shot on the internal network
//     (the only network that can reach Hydra's admin port).
//     The registrar also runs on app boot via the SIGHUP-driven reconcile.
//     See DEPLOY.md "Client registration".
//   - In the e2e harness, `compose run --rm register-clients` invokes THIS
//     module on the same othala image to prove the in-app registrar
//     registers every `oidc:` manifest in MANIFEST_DIR against Hydra admin.
//
// Bundled to dist/server/register-clients.mjs by `npm run
// build:register-clients` (esbuild, same shape as admin-runtime). Reads
// HYDRA_ADMIN_URL + MANIFEST_DIR + per-client <SLUG>_CLIENT_SECRET from the
// environment (the registrar's defaults). Exits non-zero on any failure so
// the e2e gate sees a red.

import { registerAllClients } from '../lib/register-clients';

async function main(): Promise<void> {
  const results = await registerAllClients();
  for (const r of results) {
    console.log(`[register-clients] ${r.action} ${r.clientId}`);
  }
  console.log(`[register-clients] ${results.length} client(s) registered`);
}

main().catch((err) => {
  console.error('[register-clients] failed:', err?.message ?? err);
  process.exit(1);
});

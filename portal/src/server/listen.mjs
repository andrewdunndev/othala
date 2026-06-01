// Dual-listener (D-listener) — CU1 item 4.
//
// Two in-process HTTP listeners, bound separately:
//
//   PUBLIC port (PORT, default 4321, bound on HOST default 0.0.0.0)
//     Serves the Astro SSR `handler` (the @astrojs/node middleware-mode
//     handler): the OAuth2 challenge providers (/oauth2/{login,consent,
//     logout}) AND the family UI + /auth/* + /admin/* pages. This is the
//     only handler exposed to the network. The SSR entry is imported LAZILY
//     so this module's pure admin mux can be unit-tested without a prior
//     `astro build`.
//
//   ADMIN port (ADMIN_PORT, default 4431, bound on ADMIN_HOST default
//     127.0.0.1 — loopback / pod-only)
//     A SEPARATE http.createServer with its own tiny mux. Today it serves
//     only /healthz and /readyz (placeholders); revoke + recovery-gate land
//     here in CU3. It NEVER delegates to the Astro `handler`, so no public
//     route and no challenge provider is reachable on the admin port — and
//     the public handler never sees admin paths. The two muxes are disjoint.
//
// Run with:  node ./dist/server/listen.mjs   (after `npm run build`, which
// copies this file next to the built dist/server/entry.mjs).

import http from 'node:http';

const PORT = Number(process.env.PORT ?? 4321);
const HOST = process.env.HOST ?? '0.0.0.0';
const ADMIN_PORT = Number(process.env.ADMIN_PORT ?? 4431);
const ADMIN_HOST = process.env.ADMIN_HOST ?? '127.0.0.1';

/** Routes the admin mux explicitly serves. Disjoint from the public routes. */
export const ADMIN_ROUTES = new Set(['/healthz', '/readyz']);

/** Report whether a request is an admin route (pure; test helper). */
export function isAdminRoute(method, url) {
  const path = (url ?? '/').split('?')[0];
  return method === 'GET' && ADMIN_ROUTES.has(path);
}

/** Handle one admin-port request. Writes to res; never touches the SSR handler. */
export function handleAdminRequest(req, res) {
  if (isAdminRoute(req.method, req.url)) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  // Anything that is not an admin route (including every public/challenge
  // path) is not found on the admin port. CU3 adds revoke + recovery-gate
  // here only.
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
}

/** Build the admin server (no socket bound until .listen). */
export function createAdminServer() {
  return http.createServer(handleAdminRequest);
}

/** Build the public server, lazily importing the built Astro SSR handler. */
export async function createPublicServer() {
  // The standalone entry.mjs auto-binds its OWN server on import unless this
  // is set: @astrojs/node's start() is a no-op when ASTRO_NODE_AUTOSTART is
  // "disabled". We want only this module to bind sockets (public + admin), so
  // disable the adapter's auto-start and drive the exported `handler` directly.
  process.env.ASTRO_NODE_AUTOSTART = 'disabled';
  const { handler: ssrHandler } = await import('./entry.mjs');
  return http.createServer((req, res) => {
    ssrHandler(req, res, (err) => {
      // `next` for unmatched routes / errors: the middleware handler did not
      // produce a response. Emit a plain 404/500 rather than hanging.
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('internal server error');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
    });
  });
}

// Bind both listeners only when run as the entrypoint (not when imported by
// tests, which exercise the pure admin mux above).
if (import.meta.url === `file://${process.argv[1]}`) {
  const publicServer = await createPublicServer();
  publicServer.listen(PORT, HOST, () => {
    console.log(`[portal] public listener on http://${HOST}:${PORT}`);
  });

  const adminServer = createAdminServer();
  adminServer.listen(ADMIN_PORT, ADMIN_HOST, () => {
    console.log(`[portal] admin listener on http://${ADMIN_HOST}:${ADMIN_PORT}`);
  });
}

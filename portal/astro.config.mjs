import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import tailwindcss from '@tailwindcss/vite';

// Astro 6: Node standalone SSR for the carmine deployment.
//
// `output: 'server'` ships SSR-by-default. Pages opt OUT of SSR with
// `export const prerender = true`. Static assets and prerendered HTML
// land in `dist/client/`; the SSR build emits `dist/server/entry.mjs`.
//
// D-listener (CU1 item 4): standalone mode's entry.mjs EXPORTS a Node
// `handler` (the adapter declares exports ['handler','startServer','options'])
// but also AUTO-BINDS its own server on import. `src/server/listen.mjs`
// (copied into dist by the build) sets ASTRO_NODE_AUTOSTART=disabled before
// importing entry.mjs — which makes the adapter's start() a no-op — then
// serves the exported `handler` on the PUBLIC port and stands up a SEPARATE
// loopback-only ADMIN port (http.createServer) in the same process. Only
// listen.mjs binds sockets. The admin port never delegates to `handler`, so
// the two muxes stay disjoint. (Middleware mode would also export a bare
// handler; standalone is kept because the rest of the build/runtime tooling
// already targets it and the autostart switch is a clean, documented hook.)
//
// We do NOT use Astro's Sessions API. Identity sessions live in the
// Kratos cookie on `.dunn.dev`, not in any Astro-managed store.

// Derive the public URL for build-time config from the same env var the
// runtime lib/config.ts uses. Needed for `site` (canonical URL, affects
// sitemaps and metadata) and `security.allowedDomains` (trustProxy host
// validation — see note below).
const PUBLIC_URL = process.env.OTHALA_PUBLIC_URL ?? 'http://localhost:4321';

// Parse hostname for security.allowedDomains. With trustProxy: true the
// node adapter resolves the incoming request's host from X-Forwarded-Host
// (if present) or the Host header, then validates it against allowedDomains.
// An empty allowedDomains list causes validateHost/validateForwardedHeaders to
// always return undefined, which makes hostname fall back to "localhost:PORT".
// That mismatch means url.origin !== Origin header even on legitimate
// same-origin POSTs → Astro's checkOrigin middleware fires 403 on every form
// POST, including the app's own consent/admin flows. Setting allowedDomains to
// the public hostname fixes the reverse-proxy origin check while keeping CSRF
// protection active for genuinely cross-origin requests.
//
// The pattern `{}` (empty object) means "any hostname is allowed" and is the
// safe default for deployments where the hostname is not known at build time.
// Operators who want to lock down to a specific hostname override
// OTHALA_PUBLIC_URL at build time.
let allowedDomains = [{}];
try {
  const publicHostname = new URL(PUBLIC_URL).hostname;
  if (publicHostname && publicHostname !== 'localhost') {
    allowedDomains = [{ hostname: publicHostname }];
  }
} catch {
  // Malformed PUBLIC_URL — fall through to the permissive default.
}

export default defineConfig({
  output: 'server',
  // trustProxy: Caddy sets X-Forwarded-For; with trustProxy the adapter
  // resolves ctx.clientAddress from XFF rather than the raw TCP socket
  // (which is always the Caddy container IP, collapsing all users to one
  // rate-limit bucket).
  adapter: node({ mode: 'standalone', trustProxy: true }),
  integrations: [],
  // Build-time bake: same var as the runtime OTHALA_PUBLIC_URL export in $lib/config.
  site: PUBLIC_URL,
  security: {
    // See allowedDomains comment above. Required for checkOrigin to work
    // correctly behind a reverse proxy when trustProxy is true.
    allowedDomains,
  },
  vite: {
    plugins: [tailwindcss()],
  },
});

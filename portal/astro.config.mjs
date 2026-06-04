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

export default defineConfig({
  output: 'server',
  // trustProxy: Caddy sets X-Forwarded-For; with trustProxy the adapter
  // resolves ctx.clientAddress from XFF rather than the raw TCP socket
  // (which is always the Caddy container IP, collapsing all users to one
  // rate-limit bucket).
  adapter: node({ mode: 'standalone', trustProxy: true }),
  integrations: [],
  // Build-time bake: same var as the runtime OTHALA_PUBLIC_URL export in $lib/config.
  site: process.env.OTHALA_PUBLIC_URL ?? 'http://localhost:4321',
  vite: {
    plugins: [tailwindcss()],
  },
});

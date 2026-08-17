import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import tailwindcss from '@tailwindcss/vite';

// Astro 6: Node standalone SSR — the portal ships as a container that serves
// itself, with no separate web server in front of the Node process.
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

// Build-time `site` (canonical URL — affects sitemaps and metadata) reads the
// same env var the runtime lib/config.ts uses. It is host-specific by nature,
// but it does NOT gate any security control: a default-localhost `site` baked
// into an OSS image only mislabels canonical metadata, which the runtime can't
// fix anyway. The SECURITY-bearing host resolution (allowedDomains) is host-
// AGNOSTIC — see below — so the published image carries no baked host.
const PUBLIC_URL = process.env.OTHALA_PUBLIC_URL ?? 'http://localhost:4321';

// security.allowedDomains — HOST-AGNOSTIC by design. We pass a single empty
// pattern `[{}]`, which matchPattern() treats as a match-anything wildcard
// (an undefined hostname/protocol/port/pathname each short-circuits to true,
// see @astrojs/internal-helpers matchHostname/matchPattern). This makes the
// node adapter (trustProxy:true) TRUST whatever host Caddy forwards in
// X-Forwarded-Host and resolve `Astro.url.origin` to it.
//
// Crucially, the `{}` wildcard does NOT disable the origin check. Astro's
// checkOrigin middleware (astro/dist/core/app/middlewares.js) compares
// `request.headers.get('origin') === url.origin` on every unsafe POST. With
// the wildcard, `url.origin` is the real forwarded host, so:
//   - a same-origin browser POST (Origin == forwarded host) PASSES, and
//   - a forged cross-origin POST (Origin == http://evil.example) is 403'd,
// because Origin != url.origin. No build-time host, no runtime host config:
// the wildcard accepts whatever Caddy forwards while checkOrigin still
// enforces Origin == Host. Empirically verified against the live e2e stack
// (E/F/H same-origin specs pass; forged-Origin POST → 403).
//
// NOTE: an EMPTY list `[]` is NOT equivalent — validateHost/
// validateForwardedHeaders bail when allowedDomains.length === 0, the host
// falls back to "localhost", and every legitimate same-origin POST then 403s.
// The list must contain the wildcard entry.
const allowedDomains = [{}];

export default defineConfig({
  output: 'server',
  // trustProxy: Caddy sets X-Forwarded-For; with trustProxy the adapter
  // resolves ctx.clientAddress from XFF rather than the raw TCP socket
  // (which is always the Caddy container IP, collapsing all users to one
  // rate-limit bucket).
  // DOS-3: default bodySizeLimit is 1 GiB; cap at 256 KiB (262144 bytes) so a
  // flood of large POST bodies cannot exhaust heap before rate-limiting fires.
  adapter: node({ mode: 'standalone', trustProxy: true, bodySizeLimit: 262144 }),
  integrations: [],
  // Canonical URL for metadata/sitemaps only (no security weight). Defaults to
  // localhost for a bare/OSS build; operators who care about canonical links
  // set OTHALA_PUBLIC_URL at build time, but it is not required.
  site: PUBLIC_URL,
  security: {
    // Host-agnostic wildcard — see the allowedDomains comment above. Keeps
    // checkOrigin meaningful behind a trustProxy reverse proxy WITHOUT baking
    // any host into the image.
    allowedDomains,
  },
  vite: {
    plugins: [tailwindcss()],
  },
});

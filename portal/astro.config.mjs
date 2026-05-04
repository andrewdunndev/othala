import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import tailwindcss from '@tailwindcss/vite';

// Astro 6: Node standalone SSR for the carmine deployment.
//
// `output: 'server'` ships SSR-by-default. Pages opt OUT of SSR with
// `export const prerender = true`. Static assets and prerendered HTML
// land in `dist/client/`; the SSR entrypoint is `dist/server/entry.mjs`
// which a small Node process serves on the configured port.
//
// We do NOT use Astro's Sessions API. Identity sessions live in the
// Kratos cookie on `.dunn.dev`, not in any Astro-managed store.

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  integrations: [],
  site: 'https://home.dunn.dev',
  vite: {
    plugins: [tailwindcss()],
  },
});

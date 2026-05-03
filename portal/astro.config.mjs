import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import tailwind from '@astrojs/tailwind';

// Astro 6 dropped the Cloudflare Pages target. We use the Workers adapter
// with static-asset support; functionally near-identical for our shape.
//
// Output mode: hybrid. Per-page prerender flag is REQUIRED on every route
// in hybrid mode (no inheritance) — see adversarial-review.md.

export default defineConfig({
  output: 'hybrid',
  adapter: cloudflare({
    mode: 'directory',
    runtime: {
      mode: 'local',
      type: 'workers',
    },
  }),
  integrations: [tailwind()],
  site: 'https://home.dunn.dev',
  vite: {
    define: {
      // Build-time constants
      __KRATOS_PUBLIC_URL__: JSON.stringify(process.env.KRATOS_PUBLIC_URL || 'https://auth.dunn.dev'),
    },
  },
});

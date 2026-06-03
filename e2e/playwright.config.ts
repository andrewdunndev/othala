import { defineConfig, devices } from '@playwright/test';

/**
 * Othala browser e2e — Playwright config.
 *
 * The compose `browser` profile manages the full stack (postgres → kratos →
 * hydra → othala → caddy). Playwright does NOT manage the web server; the
 * compose playwright service waits for caddy/othala to be healthy before
 * this process starts.
 *
 * baseURL is the Caddy edge alias inside the compose net: auth.othala.test.
 * The playwright container is ON that net, so http:// (no TLS) works fine.
 *
 * Output dir: /out (mounted from ./browser-out on the host, matches the
 * volume in compose.yml so screenshots are available as CI artifacts).
 */
export default defineConfig({
  testDir: './playwright/tests',
  outputDir: '/out',
  timeout: 60_000,
  retries: 0,
  workers: 1,          // serial: tests share seeded identities, keep order deterministic
  reporter: [['list'], ['html', { outputFolder: '/out/html-report', open: 'never' }]],

  use: {
    baseURL: process.env.BASE ?? 'http://auth.othala.test',
    // Browser context carries cookies across navigations automatically.
    // The JSON-API login action (actions/login.ts) returns the session via
    // Set-Cookie; we use a storageState pattern per identity in the fixtures.
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    video: 'off',
    trace: 'off',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});

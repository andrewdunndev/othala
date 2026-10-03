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
  outputDir: '/out/test-results',   // sibling of the html-report dir below (Playwright forbids nesting)
  timeout: 60_000,
  forbidOnly: true,
  retries: 1,          // upstream uses 2 in CI; 1 absorbs first-attempt flakiness from a freshly-started compose stack
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
      use: {
        ...devices['Desktop Chrome'],
        // channel: 'chromium' forces the full Chromium binary instead of the
        // default headless-shell — the shell ignores
        // --unsafely-treat-insecure-origin-as-secure entirely (playwright#22944),
        // which silently defeated the flag below.
        channel: 'chromium',
        launchOptions: {
          // Blink's [SecureContext] gate blocks navigator.credentials on
          // plaintext http:// origins (the e2e edge is deliberately not
          // TLS'd — see e2e/caddy.Caddyfile); this allowlists it for WebAuthn.
          args: ['--unsafely-treat-insecure-origin-as-secure=http://auth.othala.test'],
        },
      },
    },
  ],
});

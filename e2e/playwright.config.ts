import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { defineConfig, devices } from '@playwright/test';

// SPKI pins of the edge's internal CA (read-only volume): Chromium treats a pinned chain as valid, so
// WebAuthn sees a clean secure context.
const ca = '/caddy/caddy/pki/authorities/local/';
const spki = ['root', 'intermediate']
  .map((n) => createHash('sha256')
    .update(new X509Certificate(readFileSync(ca + n + '.crt')).publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64'))
  .join(',');

/**
 * Othala browser e2e — Playwright config.
 *
 * The compose `browser` profile manages the full stack (postgres → kratos →
 * hydra → othala → caddy). Playwright does NOT manage the web server; the
 * compose playwright service waits for caddy/othala to be healthy before
 * this process starts.
 *
 * baseURL is the Caddy edge alias inside the compose net: auth.othala.test.
 * The edge serves a Caddy internal CA, trusted via the SPKI pins above.
 *
 * Output dir: /out (mounted from ./browser-out on the host, matches the
 * volume in compose.e2e.yml so screenshots are available as CI artifacts).
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
    baseURL: process.env.BASE ?? 'https://auth.othala.test',
    // Browser context carries cookies across navigations automatically.
    // The JSON-API login action (actions/login.ts) returns the session via
    // Set-Cookie; we use a storageState pattern per identity in the fixtures.
    screenshot: 'only-on-failure',
    video: 'off',
    trace: 'off',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // The full Chromium binary: the default headless-shell ignores the SPKI flag below.
        channel: 'chromium',
        launchOptions: {
          args: ['--ignore-certificate-errors-spki-list=' + spki],
        },
      },
    },
  ],
});

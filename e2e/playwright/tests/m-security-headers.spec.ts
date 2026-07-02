/**
 * M — Security response headers + self-hosted fonts (no external requests).
 *
 * Coverage gaps addressed by this spec:
 *
 *   M1–M5 (per-route header checks):
 *     The middleware.ts `applySecurityHeaders()` function added in the
 *     feat/passkey-first-login branch must emit these headers on EVERY
 *     response — 2xx, 3xx, 4xx, 5xx. This spec probes five representative
 *     URLs (login, settings, admin, portal root, and a 404) with a raw
 *     `request.get()` call (maxRedirects: 0) so redirects are NOT followed;
 *     the headers on the FIRST response are checked.
 *
 *     Required headers:
 *       x-frame-options: DENY
 *       x-content-type-options: nosniff
 *       referrer-policy: same-origin
 *       content-security-policy: contains "frame-ancestors 'none'"
 *
 *     NOTE: script-src is intentionally absent from the CSP (deferred; see
 *     middleware.ts CSP note + docs/hardening.md §2). Do NOT assert it.
 *
 *   M6 (self-hosted fonts guard):
 *     IBM Plex fonts moved from Google CDN to local /fonts/. The auth pages
 *     must make NO requests to fonts.googleapis.com, fonts.gstatic.com, or
 *     any other external (non-same-origin) host. This test navigates
 *     /auth/login, collects all outbound requests via page.on('request'),
 *     and asserts every URL is same-origin.
 *
 * These tests PASS on the current feat/passkey-first-login branch.
 *
 * Live-stack requirements:
 *   - othala + caddy + kratos compose services healthy.
 *   - Playwright container on the compose net (auth.othala.test reachable).
 */

import { test, expect } from '../fixtures';

// Headers to assert on every probed route.
const REQUIRED_HEADERS: Array<[string, string | RegExp]> = [
  ['x-frame-options', 'DENY'],
  ['x-content-type-options', 'nosniff'],
  // no-referrer → same-origin (work item #5): no-referrer suppressed the
  // Origin header on same-origin form-POST navigations, 403ing every admin
  // mutation via Astro's checkOrigin. same-origin still sends no referrer
  // cross-origin (the original privacy intent), restoring Origin same-origin.
  ['referrer-policy', 'same-origin'],
  // CSP must contain frame-ancestors 'none' — script-src intentionally absent.
  ['content-security-policy', /frame-ancestors\s+'none'/],
  // CSP must include form-action 'self' (Kratos forms POST to same origin).
  ['content-security-policy', /form-action\s+'self'/],
  // HSTS: 2-year max-age; IdP is HTTPS-only behind Caddy.
  ['strict-transport-security', /max-age=63072000/],
];

// Routes to probe. maxRedirects:0 so we read headers from the FIRST response.
// /auth/settings and /admin will redirect unauthenticated requests — that's
// fine; the headers must be present on the 3xx response itself.
const PROBE_ROUTES = [
  '/auth/login',
  '/auth/settings',
  '/admin',
  '/',
  '/this-path-does-not-exist-404-check',
];

test.describe('M — Security response headers', () => {
  for (const route of PROBE_ROUTES) {
    test(`M-headers: ${route} carries all required security headers`, async ({
      page,
      baseURL,
    }) => {
      const url = `${baseURL}${route}`;
      const resp = await page.context().request.get(url, { maxRedirects: 0 });

      const headers = resp.headers();
      console.log(`[M] ${route} status=${resp.status()} headers=`, headers);

      for (const [name, expected] of REQUIRED_HEADERS) {
        const value = headers[name] ?? '';
        if (typeof expected === 'string') {
          expect(
            value,
            `${route}: expected header "${name}: ${expected}" but got "${value}"`,
          ).toBe(expected);
        } else {
          expect(
            value,
            `${route}: header "${name}" must match ${expected} but got "${value}"`,
          ).toMatch(expected);
        }
      }
    });
  }

  // M6 — self-hosted fonts guard.
  // Navigate /auth/login, collect all resource URLs, assert none are external.
  test('M6 — /auth/login makes no external (non-same-origin) requests (self-hosted fonts)', async ({
    page,
    baseURL,
  }) => {
    const origin = new URL(baseURL).origin; // e.g. http://auth.othala.test
    const externalRequests: string[] = [];

    page.on('request', (req) => {
      const u = req.url();
      try {
        const reqOrigin = new URL(u).origin;
        if (reqOrigin !== origin) {
          externalRequests.push(u);
        }
      } catch {
        // data: / blob: / chrome-extension: — ignore
      }
    });

    await page.goto(`${baseURL}/auth/login`, { waitUntil: 'networkidle' });

    if (externalRequests.length > 0) {
      console.error('[M6] External requests detected:', externalRequests);
    }

    expect(
      externalRequests,
      `M6: /auth/login must make no external requests — found: ${JSON.stringify(externalRequests)}`,
    ).toHaveLength(0);

    console.log('[M6] PASS — all requests are same-origin; no external fonts/CDN calls');
  });
});

// M — security response headers are present and fonts are self-hosted (no external requests).

import { test, expect } from '../fixtures';

const REQUIRED_HEADERS: Array<[string, string | RegExp]> = [
  ['x-frame-options', 'DENY'],
  ['x-content-type-options', 'nosniff'],
  ['referrer-policy', 'same-origin'],
  ['content-security-policy', /frame-ancestors\s+'none'/],
  ['content-security-policy', /form-action\s+'self'/],
  ['strict-transport-security', /max-age=63072000/],
];

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
